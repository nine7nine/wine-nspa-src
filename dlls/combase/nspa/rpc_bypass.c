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

    TRACE( "nspa-bypass register %s flags %#lx obj %p\n",
           debugstr_guid(clsid), flags, object );

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

    TRACE( "nspa-bypass revoke cookie %u\n", cookie );

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

    TRACE( "nspa-bypass get %s\n", debugstr_guid(clsid) );

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

    TRACE( "nspa-bypass alloc_thread_seq_id\n" );

    SERVER_START_REQ( nspa_alloc_thread_seq_id )
    {
        status = wine_server_call( req );
        if (!status) *id = reply->seq_id;
    }
    SERVER_END_REQ;

    return hresult_from_server_status( status );
}


/* ════════════════════════════════════════════════════════════════════════
 *   Phase 1.B — irot (Running Object Table) bypass entrypoints
 * ════════════════════════════════════════════════════════════════════════ */

#define NSPA_BYPASS_BIT_IROT  2u   /* bit 1 (mask 2) of NSPA_RPC_BYPASS */

/* Reuse the same gate-state machine as irpcss; separate bit, separate
 * memoised flag.  Read once on first call (per-bit memoisation). */
static LONG irot_gate;

int nspa_rpc_bypass_irot(void)
{
    LONG g = InterlockedCompareExchange( &irot_gate, 0, 0 );
    if (g) return g == 2;
    g = (read_bypass_mask() & NSPA_BYPASS_BIT_IROT) ? 2 : 1;
    InterlockedCompareExchange( &irot_gate, g, 0 );
    return g == 2;
}


/* irot status mapper — match the HRESULTs that rpcss's IrotXxx
 * methods would have returned for the same condition.
 *   - is_running uses S_FALSE for "not running" (success code).
 *   - get_object / get_time_of_last_change use MK_E_UNAVAILABLE.
 *   - revoke / note_change_time use E_INVALIDARG for unknown cookies.
 * Each entrypoint maps STATUS_NOT_FOUND to its caller-expected
 * HRESULT explicitly.  hresult_from_server_status() handles the
 * rest. */


HRESULT nspa_irot_register( const MonikerComparisonData *moniker_data,
                            const InterfaceData *object,
                            const InterfaceData *moniker,
                            const FILETIME *time, DWORD flags,
                            IrotCookie *cookie,
                            IrotContextHandle *ctxt_handle )
{
    unsigned int status;
    SIZE_T md_size = FIELD_OFFSET( MonikerComparisonData, abData[moniker_data->ulCntData] );
    SIZE_T ob_size = FIELD_OFFSET( InterfaceData,         abData[object->ulCntData] );
    SIZE_T mk_size = FIELD_OFFSET( InterfaceData,         abData[moniker->ulCntData] );
    int already_registered = 0;

    TRACE( "nspa-bypass irot_register flags %#lx\n", flags );

    SERVER_START_REQ( nspa_irot_register )
    {
        req->moniker_data_len = (unsigned int)md_size;
        req->object_len       = (unsigned int)ob_size;
        req->moniker_len      = (unsigned int)mk_size;
        req->flags            = flags;
        req->time             = ((unsigned __int64)time->dwHighDateTime << 32) | time->dwLowDateTime;
        wine_server_add_data( req, moniker_data, md_size );
        wine_server_add_data( req, object,       ob_size );
        wine_server_add_data( req, moniker,      mk_size );
        status = wine_server_call( req );
        if (!status)
        {
            *cookie = reply->cookie;
            already_registered = reply->already_registered;
        }
    }
    SERVER_END_REQ;

    /* The bypass model has no RPC context handle — the wineserver-side
     * cleanup-on-process-exit replaces it.  Hand the caller a non-NULL
     * sentinel (the cookie cast to a pointer) so it can later pass us
     * "something" for revoke; we ignore it on revoke. */
    if (!status && ctxt_handle) *ctxt_handle = (IrotContextHandle)(ULONG_PTR)*cookie;

    if (status) return hresult_from_server_status( status );
    return already_registered ? MK_S_MONIKERALREADYREGISTERED : S_OK;
}


HRESULT nspa_irot_revoke( IrotCookie cookie, IrotContextHandle *ctxt_handle,
                          PInterfaceData *object, PInterfaceData *moniker )
{
    unsigned int status;
    DWORD buf_size = 1024;
    void *buf;
    unsigned int object_len = 0, moniker_len = 0;

    TRACE( "nspa-bypass irot_revoke cookie %lu\n", (unsigned long)cookie );

    *object  = NULL;
    *moniker = NULL;

    for (;;)
    {
        if (!(buf = CoTaskMemAlloc( buf_size ))) return E_OUTOFMEMORY;

        SERVER_START_REQ( nspa_irot_revoke )
        {
            req->cookie = cookie;
            wine_server_set_reply( req, buf, buf_size );
            status = wine_server_call( req );
            if (!status)
            {
                object_len  = reply->object_len;
                moniker_len = reply->moniker_len;
            }
        }
        SERVER_END_REQ;

        if (status != STATUS_BUFFER_TOO_SMALL) break;

        CoTaskMemFree( buf );
        buf_size *= 2;
        if (buf_size > 256 * 1024) return E_OUTOFMEMORY;
    }

    if (status == STATUS_NOT_FOUND)
    {
        CoTaskMemFree( buf );
        return E_INVALIDARG;
    }
    if (status)
    {
        CoTaskMemFree( buf );
        return hresult_from_server_status( status );
    }

    /* The buffer contains [object bytes | moniker bytes].  Hand back
     * pointers to MIDL_user_allocate'd copies, matching the rpcss
     * IrotRevoke contract — caller is expected to MIDL_user_free both. */
    if (object_len)
    {
        if (!(*object = CoTaskMemAlloc( object_len )))
        {
            CoTaskMemFree( buf );
            return E_OUTOFMEMORY;
        }
        memcpy( *object, buf, object_len );
    }
    if (moniker_len)
    {
        if (!(*moniker = CoTaskMemAlloc( moniker_len )))
        {
            CoTaskMemFree( *object );
            *object = NULL;
            CoTaskMemFree( buf );
            return E_OUTOFMEMORY;
        }
        memcpy( *moniker, (unsigned char *)buf + object_len, moniker_len );
    }

    CoTaskMemFree( buf );
    if (ctxt_handle) *ctxt_handle = NULL;
    return S_OK;
}


HRESULT nspa_irot_is_running( const MonikerComparisonData *moniker_data )
{
    unsigned int status;
    SIZE_T md_size = FIELD_OFFSET( MonikerComparisonData, abData[moniker_data->ulCntData] );

    TRACE( "nspa-bypass irot_is_running\n" );

    SERVER_START_REQ( nspa_irot_is_running )
    {
        wine_server_add_data( req, moniker_data, md_size );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;

    if (status == STATUS_NOT_FOUND) return S_FALSE;
    if (!status) return S_OK;
    return hresult_from_server_status( status );
}


HRESULT nspa_irot_get_object( const MonikerComparisonData *moniker_data,
                              PInterfaceData *obj, IrotCookie *cookie )
{
    unsigned int status;
    SIZE_T md_size = FIELD_OFFSET( MonikerComparisonData, abData[moniker_data->ulCntData] );
    DWORD buf_size = 1024;
    void *buf;
    data_size_t reply_size = 0;
    unsigned int got_cookie = 0;

    TRACE( "nspa-bypass irot_get_object\n" );

    *obj    = NULL;
    *cookie = 0;

    for (;;)
    {
        if (!(buf = CoTaskMemAlloc( buf_size ))) return E_OUTOFMEMORY;

        SERVER_START_REQ( nspa_irot_get_object )
        {
            wine_server_add_data( req, moniker_data, md_size );
            wine_server_set_reply( req, buf, buf_size );
            status = wine_server_call( req );
            reply_size = wine_server_reply_size( reply );
            if (!status) got_cookie = reply->cookie;
        }
        SERVER_END_REQ;

        if (status != STATUS_BUFFER_TOO_SMALL) break;

        CoTaskMemFree( buf );
        buf_size *= 2;
        if (buf_size > 64 * 1024) return E_OUTOFMEMORY;
    }

    if (status == STATUS_NOT_FOUND)
    {
        CoTaskMemFree( buf );
        return MK_E_UNAVAILABLE;
    }
    if (status)
    {
        CoTaskMemFree( buf );
        return hresult_from_server_status( status );
    }

    *cookie = got_cookie;
    if (!reply_size)
    {
        CoTaskMemFree( buf );
        return S_OK;
    }
    *obj = buf;   /* hand the buffer over directly; caller MIDL_user_free's it */
    return S_OK;
}


HRESULT nspa_irot_note_change_time( IrotCookie cookie, const FILETIME *time )
{
    unsigned int status;

    TRACE( "nspa-bypass irot_note_change_time cookie %lu\n", (unsigned long)cookie );

    SERVER_START_REQ( nspa_irot_note_change_time )
    {
        req->cookie = cookie;
        req->time   = ((unsigned __int64)time->dwHighDateTime << 32) | time->dwLowDateTime;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;

    if (status == STATUS_NOT_FOUND) return E_INVALIDARG;
    return hresult_from_server_status( status );
}


HRESULT nspa_irot_get_time_of_last_change( const MonikerComparisonData *moniker_data,
                                           FILETIME *time )
{
    unsigned int status;
    SIZE_T md_size = FIELD_OFFSET( MonikerComparisonData, abData[moniker_data->ulCntData] );
    unsigned __int64 packed = 0;

    TRACE( "nspa-bypass irot_get_time_of_last_change\n" );

    SERVER_START_REQ( nspa_irot_get_time_of_last_change )
    {
        wine_server_add_data( req, moniker_data, md_size );
        status = wine_server_call( req );
        if (!status) packed = reply->time;
    }
    SERVER_END_REQ;

    if (status == STATUS_NOT_FOUND) return MK_E_UNAVAILABLE;
    if (status) return hresult_from_server_status( status );

    time->dwLowDateTime  = (DWORD)(packed & 0xffffffffu);
    time->dwHighDateTime = (DWORD)(packed >> 32);
    return S_OK;
}


HRESULT nspa_irot_enum_running( PInterfaceList *list )
{
    unsigned int status;
    DWORD buf_size = 4096;
    void *buf;
    data_size_t reply_size = 0;
    unsigned int count = 0;
    PInterfaceList out;
    SIZE_T list_alloc;
    unsigned int i;
    const unsigned char *p, *end;

    TRACE( "nspa-bypass irot_enum_running\n" );

    *list = NULL;

    for (;;)
    {
        if (!(buf = CoTaskMemAlloc( buf_size ))) return E_OUTOFMEMORY;

        SERVER_START_REQ( nspa_irot_enum_running )
        {
            wine_server_set_reply( req, buf, buf_size );
            status = wine_server_call( req );
            reply_size = wine_server_reply_size( reply );
            if (!status) count = reply->count;
        }
        SERVER_END_REQ;

        if (status != STATUS_BUFFER_TOO_SMALL) break;

        CoTaskMemFree( buf );
        buf_size *= 2;
        if (buf_size > 1024 * 1024) return E_OUTOFMEMORY;
    }

    if (status)
    {
        CoTaskMemFree( buf );
        return hresult_from_server_status( status );
    }

    /* Build the InterfaceList: { ULONG size; PInterfaceData interfaces[]; }
     * The pointer array is followed in memory (per the rpcss convention)
     * by the InterfaceData blobs themselves, all in a single allocation. */
    list_alloc = FIELD_OFFSET( InterfaceList, interfaces[count] ) + reply_size;
    if (!(out = CoTaskMemAlloc( list_alloc )))
    {
        CoTaskMemFree( buf );
        return E_OUTOFMEMORY;
    }
    out->size = count;

    p   = (const unsigned char *)buf;
    end = p + reply_size;
    {
        unsigned char *dst = (unsigned char *)&out->interfaces[count];
        for (i = 0; i < count; i++)
        {
            unsigned int sz;
            if ((SIZE_T)(end - p) < sizeof(sz)) break;
            memcpy( &sz, p, sizeof(sz) );
            p += sizeof(sz);
            if ((SIZE_T)(end - p) < sz) break;
            out->interfaces[i] = (PInterfaceData)dst;
            memcpy( dst, p, sz );
            dst += sz;
            p   += sz;
        }
    }

    CoTaskMemFree( buf );
    *list = out;
    return S_OK;
}
