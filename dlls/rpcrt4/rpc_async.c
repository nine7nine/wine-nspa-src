/*
 * Asynchronous Call Support Functions
 *
 * Copyright 2007 Robert Shearman (for CodeWeavers)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include <stdarg.h>

#include "rpc.h"
#include "rpcndr.h"
#include "rpcasync.h"

#include "wine/debug.h"

#include "rpc_binding.h"
#include "rpc_message.h"
#include "ndr_stubless.h"

WINE_DEFAULT_DEBUG_CHANNEL(rpc);

#define RPC_ASYNC_SIGNATURE 0x43595341

/* Async call state machine, encoded in the (otherwise unused) Lock field
 * of RPC_ASYNC_STATE.  Wine's RpcAsyncInitializeHandle initialises Lock
 * to 0, and the upstream MSDN-documented contract for that field is
 * "private, set to 0 by RpcAsyncInitializeHandle" — so it is the right
 * place for our terminal-status word.  Updated only via Interlocked*
 * primitives so RpcAsyncGetCallStatus is wait-free. */
#define ASYNC_STATE_PENDING    0
#define ASYNC_STATE_COMPLETED  1
#define ASYNC_STATE_CANCELLED  2

static inline BOOL valid_async_handle(PRPC_ASYNC_STATE pAsync)
{
    return pAsync->Signature == RPC_ASYNC_SIGNATURE;
}

/***********************************************************************
 *           RpcAsyncInitializeHandle [RPCRT4.@]
 *
 * Initialises an asynchronous state so it can be used in other asynchronous
 * functions and for use in asynchronous calls.
 *
 * PARAMS
 *  pAsync [I] Asynchronous state to initialise.
 *  Size   [I] Size of the memory pointed to by pAsync.
 *
 * RETURNS
 *  Success: RPC_S_OK.
 *  Failure: Any error code.
 */
RPC_STATUS WINAPI RpcAsyncInitializeHandle(PRPC_ASYNC_STATE pAsync, unsigned int Size)
{
    TRACE("(%p, %d)\n", pAsync, Size);

    if (Size != sizeof(*pAsync))
    {
        ERR("invalid Size %d\n", Size);
        return ERROR_INVALID_PARAMETER;
    }

    pAsync->Size = sizeof(*pAsync);
    pAsync->Signature = RPC_ASYNC_SIGNATURE;
    pAsync->Lock = 0;
    pAsync->Flags = 0;
    pAsync->StubInfo = NULL;
    pAsync->RuntimeInfo = NULL;
    memset(pAsync->Reserved, 0, sizeof(*pAsync) - FIELD_OFFSET(RPC_ASYNC_STATE, Reserved));

    return RPC_S_OK;
}

/***********************************************************************
 *           RpcAsyncGetCallStatus [RPCRT4.@]
 *
 * Retrieves the current status of the asynchronous call taking place.
 *
 * PARAMS
 *  pAsync [I] Asynchronous state to initialise.
 *
 * RETURNS
 *  RPC_S_OK - The call was successfully completed.
 *  RPC_S_INVALID_ASYNC_HANDLE - The asynchronous structure is not valid.
 *  RPC_S_ASYNC_CALL_PENDING - The call is still in progress and has not been completed.
 *  Any other error code - The call failed.
 */
RPC_STATUS WINAPI RpcAsyncGetCallStatus(PRPC_ASYNC_STATE pAsync)
{
    LONG s;

    TRACE("(%p)\n", pAsync);

    if (!valid_async_handle(pAsync))
        return RPC_S_INVALID_ASYNC_HANDLE;

    s = InterlockedCompareExchange(&pAsync->Lock, 0, 0);
    switch (s)
    {
    case ASYNC_STATE_PENDING:    return RPC_S_ASYNC_CALL_PENDING;
    case ASYNC_STATE_COMPLETED:  return RPC_S_OK;
    case ASYNC_STATE_CANCELLED:  return RPC_S_CALL_CANCELLED;
    default:
        ERR("unexpected Lock state %ld\n", s);
        return RPC_S_INTERNAL_ERROR;
    }
}

/***********************************************************************
 *           RpcAsyncCompleteCall [RPCRT4.@]
 *
 * Completes a client or server asynchronous call.
 *
 * PARAMS
 *  pAsync [I] Asynchronous state to initialise.
 *  Reply  [I] The return value of the asynchronous function.
 *
 * RETURNS
 *  Success: RPC_S_OK.
 *  Failure: Any error code.
 */
RPC_STATUS WINAPI RpcAsyncCompleteCall(PRPC_ASYNC_STATE pAsync, void *Reply)
{
    struct async_call_data *data;
    RPC_STATUS status;
    LONG prev;

    TRACE("(%p, %p)\n", pAsync, Reply);

    if (!valid_async_handle(pAsync))
        return RPC_S_INVALID_ASYNC_HANDLE;

    /* Transition Lock from PENDING → COMPLETED.  If we lose the race to
     * a concurrent RpcAsyncCancelCall (state already CANCELLED), report
     * cancellation and leave the entry alone — the cancel path is
     * responsible for its own cleanup notifier. */
    prev = InterlockedCompareExchange(&pAsync->Lock,
                                      ASYNC_STATE_COMPLETED,
                                      ASYNC_STATE_PENDING);
    if (prev == ASYNC_STATE_CANCELLED)
        return RPC_S_CALL_CANCELLED;
    if (prev != ASYNC_STATE_PENDING)
    {
        ERR("RpcAsyncCompleteCall on a handle in unexpected state %ld\n", prev);
        return RPC_S_INVALID_ASYNC_HANDLE;
    }

    TRACE("pAsync %p, pAsync->StubInfo %p\n", pAsync, pAsync->StubInfo);

    data = pAsync->StubInfo;
    if (data->pStubMsg->IsClient)
        status = NdrpCompleteAsyncClientCall(pAsync, Reply);
    else
        status = NdrpCompleteAsyncServerCall(pAsync, Reply);

    return status;
}

/***********************************************************************
 *           RpcAsyncAbortCall [RPCRT4.@]
 *
 * Aborts the asynchronous server call taking place.
 *
 * PARAMS
 *  pAsync        [I] Asynchronous server state to abort.
 *  ExceptionCode [I] Exception code to return to the client in a fault packet.
 *
 * RETURNS
 *  Success: RPC_S_OK.
 *  Failure: Any error code.
 */
RPC_STATUS WINAPI RpcAsyncAbortCall(PRPC_ASYNC_STATE pAsync, ULONG ExceptionCode)
{
    /* Server-side abort: the server stub uses this to send a fault PDU
     * back to the client with the given exception code.  Wine's server-
     * side async stub implementation in NdrpCompleteAsyncServerCall
     * doesn't yet wire fault-PDU emission per the FIXME at
     * rpc_message.c:1971; without that, marking the abort here is the
     * best we can do.  Reflects the intent in the Lock state machine
     * so server code that observes state transitions sees a terminal
     * state. */
    TRACE("(%p, %ld/0x%lx)\n", pAsync, ExceptionCode, ExceptionCode);

    if (!valid_async_handle(pAsync))
        return RPC_S_INVALID_ASYNC_HANDLE;

    InterlockedCompareExchange(&pAsync->Lock,
                               ASYNC_STATE_CANCELLED,
                               ASYNC_STATE_PENDING);
    /* TODO: wire fault PDU emission once NdrpCompleteAsyncServerCall
     * supports it. */
    return RPC_S_OK;
}

/***********************************************************************
 *           RpcAsyncCancelCall [RPCRT4.@]
 *
 * Cancels the asynchronous client call taking place.
 *
 * PARAMS
 *  pAsync        [I] Asynchronous client state to abort.
 *  fAbortCall    [I] If TRUE, then send a cancel to the server, otherwise
 *                    just wait for the call to complete.
 *
 * RETURNS
 *  Success: RPC_S_OK.
 *  Failure: Any error code.
 */
RPC_STATUS WINAPI RpcAsyncCancelCall(PRPC_ASYNC_STATE pAsync, BOOL fAbortCall)
{
    struct async_call_data *data;
    LONG prev;

    TRACE("(%p, %s)\n", pAsync, fAbortCall ? "TRUE" : "FALSE");

    if (!valid_async_handle(pAsync))
        return RPC_S_INVALID_ASYNC_HANDLE;

    /* Race with RpcAsyncCompleteCall — if the call already completed
     * naturally, just return success (the user wanted termination, the
     * call is terminated). */
    prev = InterlockedCompareExchange(&pAsync->Lock,
                                      ASYNC_STATE_CANCELLED,
                                      ASYNC_STATE_PENDING);
    if (prev != ASYNC_STATE_PENDING)
        return RPC_S_OK;

    /* Wake the connection's blocking I/O so async_notifier_proc returns
     * promptly.  conn->ops->cancel_call is the existing transport-vtable
     * entry — for ncacn_ip_tcp/http it sets cancel_event; for ncalrpc/
     * ncacn_np it issues NtCancelIoFileEx. */
    data = pAsync->StubInfo;
    if (data && data->pStubMsg && data->pStubMsg->RpcMsg &&
        data->pStubMsg->RpcMsg->ReservedForRuntime)
    {
        RpcConnection *conn = data->pStubMsg->RpcMsg->ReservedForRuntime;
        if (conn->ops->cancel_call) conn->ops->cancel_call(conn);
    }

    /* fAbortCall=TRUE additionally requests an explicit cancel PDU to
     * the server.  Wine doesn't currently emit those PDUs (the cancel
     * path stays purely client-side); the I/O cancellation above is the
     * best-effort behaviour upstream apps already get from the TCP cancel
     * path's existing cancel_event mechanism.  Filed as TODO. */
    return RPC_S_OK;
}
