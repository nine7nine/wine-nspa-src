/*
 * NSPA Phase 2.B — default I/O timeout helper for rpcrt4 transports.
 *
 * Stock Wine's rpcrt4 calls WaitForSingleObject(event, INFINITE) on every
 * client-side overlapped I/O wait (NtReadFile / NtWriteFile event wait,
 * TCP send wait).  If the peer dies between request-send and response-
 * receive, the caller hangs forever — no Wine app calls
 * RpcMgmtSetComTimeout, so there's no application-level escape.
 *
 * This helper returns a configurable default that bounds the wait.  Used
 * in place of bare INFINITE at the three client-side hang-prone call
 * sites in rpc_transport.c:
 *
 *   rpcrt4_conn_np_read           (line 396)
 *   rpcrt4_conn_np_write          (line 417)
 *   rpcrt4_sock_wait_for_send     (line 1101)
 *
 * Server-side listener loops (rpcrt4_protseq_*_wait_for_new_connection,
 * etc.) keep INFINITE — those are intentionally long-running and have
 * cancel-event escape paths.
 *
 * See nspa/docs/rpc-fast-and-solid-plan.md.
 */

#ifndef __WINE_RPCRT4_NSPA_TIMEOUTS_H
#define __WINE_RPCRT4_NSPA_TIMEOUTS_H

#include <windef.h>

/* One-time init.  Called from rpcrt4's DllMain at DLL_PROCESS_ATTACH,
 * before any RT thread can observe the cached value.  Reads
 * NSPA_RPC_TIMEOUT_MS once; never called again.  Anything else
 * (DLL_THREAD_ATTACH, dynamic loads) does not re-read env. */
extern void nspa_rpc_io_init(void);

/* Default I/O wait timeout for client-side rpcrt4 transport calls.
 *
 * Resolution table (set once by nspa_rpc_io_init):
 *   NSPA_RPC_TIMEOUT_MS unset / invalid : 30000    (30 s)
 *   NSPA_RPC_TIMEOUT_MS=0               : INFINITE (kill switch)
 *   NSPA_RPC_TIMEOUT_MS=N               : N milliseconds
 *
 * RT-safety properties:
 *   - Hot path = single volatile load.  No syscall, no lock, no
 *     env-var lookup, no allocation, no conditional state probe.
 *   - Pre-init: the cached value carries a compile-time default
 *     (30 s), so even pre-init reads return a sane value.
 *   - Const-after-init: only the DllMain init writes the cell;
 *     RT readers only ever read.  No cacheline bouncing in steady
 *     state. */
extern DWORD nspa_rpc_io_timeout_ms(void);

#endif /* __WINE_RPCRT4_NSPA_TIMEOUTS_H */
