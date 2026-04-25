/*
 * NSPA RPC Phase 1.A — irpcss bypass entrypoints.
 *
 * Replaces the four irpcss_* RPC calls in dlls/combase/rpc.c with direct
 * wineserver requests when the NSPA_RPC_BYPASS gate is enabled.
 *
 * See nspa/docs/rpc-fast-and-solid-plan.md.  Server-side state lives in
 * server/nspa/rpc_state.c and is keyed on the registering process; the
 * wineserver event loop's single-threaded dispatch provides the
 * concurrency discipline that rpcss does today via a CRITICAL_SECTION.
 */

#include <stdarg.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <winerror.h>
#include <objidl.h>

#include "wine/server.h"
#include "wine/debug.h"

#include "rpc_bypass.h"

WINE_DEFAULT_DEBUG_CHANNEL(ole);


/* Gate state values for irpcss_gate.
 *   0 = unread (not yet probed env)
 *   1 = disabled
 *   2 = enabled */
static LONG irpcss_gate;

static LONG read_bypass_mask(void)
{
    WCHAR buf[16];
    DWORD len = GetEnvironmentVariableW( L"NSPA_RPC_BYPASS", buf, ARRAY_SIZE(buf) );
    if (!len || len >= ARRAY_SIZE(buf)) return 0;
    return wcstoul( buf, NULL, 0 );
}

int nspa_rpc_bypass_irpcss(void)
{
    LONG g = InterlockedCompareExchange( &irpcss_gate, 0, 0 );
    if (g) return g == 2;
    g = (read_bypass_mask() & 1) ? 2 : 1;
    InterlockedCompareExchange( &irpcss_gate, g, 0 );
    return g == 2;
}


/* Map a wineserver NTSTATUS to the HRESULT that the legacy rpcss path
 * would have returned for the same condition.  Lets dlls/combase/rpc.c's
 * callers stay unaware of the bypass. */
static HRESULT hresult_from_server_status( unsigned int status )
{
    switch (status)
    {
    case 0:                           return S_OK;
    case STATUS_NO_MEMORY:            return E_OUTOFMEMORY;
    case STATUS_NOT_FOUND:            return E_NOINTERFACE;
    case STATUS_BUFFER_TOO_SMALL:     return E_OUTOFMEMORY;
    default:
        WARN( "unexpected server status %#x\n", status );
        return E_FAIL;
    }
}


HRESULT nspa_irpcss_register_class_factory( REFCLSID clsid, DWORD flags,
                                            MInterfacePointer *object,
                                            unsigned int *cookie )
{
    unsigned int status;
    SIZE_T blob_size = 0;

    if (object) blob_size = FIELD_OFFSET( MInterfacePointer, abData[object->ulCntData] );

    SERVER_START_REQ( nspa_register_class_factory )
    {
        memcpy( &req->clsid_lo, clsid, sizeof(*clsid) );
        req->flags = flags;
        if (blob_size) wine_server_add_data( req, object, blob_size );
        status = wine_server_call( req );
        if (!status) *cookie = reply->cookie;
    }
    SERVER_END_REQ;

    return hresult_from_server_status( status );
}


HRESULT nspa_irpcss_revoke_class_factory( unsigned int cookie )
{
    unsigned int status;

    SERVER_START_REQ( nspa_revoke_class_factory )
    {
        req->cookie = cookie;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;

    return hresult_from_server_status( status );
}


HRESULT nspa_irpcss_get_class_factory( REFCLSID clsid, PMInterfacePointer *object )
{
    /* MInterfacePointer is variable-size.  We don't know the registered
     * blob's size up front, so allocate an initial buffer and grow on
     * STATUS_BUFFER_TOO_SMALL.  Typical OOP COM stub-info fits in a few
     * hundred bytes; 1024 covers the overwhelming majority of cases in a
     * single call. */
    DWORD buf_size = 1024;
    PMInterfacePointer buf;
    unsigned int status;
    data_size_t reply_size = 0;

    *object = NULL;

    for (;;)
    {
        if (!(buf = CoTaskMemAlloc( buf_size )))
            return E_OUTOFMEMORY;

        SERVER_START_REQ( nspa_get_class_factory )
        {
            memcpy( &req->clsid_lo, clsid, sizeof(*clsid) );
            wine_server_set_reply( req, buf, buf_size );
            status = wine_server_call( req );
            reply_size = wine_server_reply_size( reply );
        }
        SERVER_END_REQ;

        if (status != STATUS_BUFFER_TOO_SMALL) break;

        CoTaskMemFree( buf );
        buf_size *= 2;
        if (buf_size > 64 * 1024) return E_OUTOFMEMORY;  /* sanity */
    }

    if (status || !reply_size)
    {
        CoTaskMemFree( buf );
        return hresult_from_server_status( status );
    }

    *object = buf;
    return S_OK;
}


HRESULT nspa_irpcss_alloc_thread_seq_id( DWORD *id )
{
    unsigned int status;

    SERVER_START_REQ( nspa_alloc_thread_seq_id )
    {
        status = wine_server_call( req );
        if (!status) *id = reply->seq_id;
    }
    SERVER_END_REQ;

    return hresult_from_server_status( status );
}
