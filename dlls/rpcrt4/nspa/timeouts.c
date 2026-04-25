/*
 * NSPA Phase 2.B — default I/O timeout helper for rpcrt4 transports.
 *
 * RT-safe by construction:
 *
 *   - g_io_timeout_ms carries a compile-time default (30 s), so the
 *     cell is valid for any reader from t=0 — there's no "uninitialised"
 *     window even if the helper is called before init somehow.
 *
 *   - nspa_rpc_io_init() runs exactly once, at DLL_PROCESS_ATTACH,
 *     before any thread other than DllMain's caller exists.  It is
 *     a single-writer init: read env → maybe override → store.
 *
 *   - nspa_rpc_io_timeout_ms() is a single volatile read.  No
 *     syscalls, no locks, no env-var lookup, no allocation, no
 *     conditional state probe.  RT readers see a steady cacheline
 *     after init (read-only, shared, no bouncing).
 *
 * See nspa/docs/rpc-fast-and-solid-plan.md.
 */

#include <stdarg.h>
#include <stdlib.h>

#include <windef.h>
#include <winbase.h>

#include "timeouts.h"


#define NSPA_RPC_DEFAULT_TIMEOUT_MS  30000u   /* 30 s */


/* The single cached value.  Written once by nspa_rpc_io_init() at
 * DLL_PROCESS_ATTACH; read forever after by RT threads.  volatile
 * suppresses compiler reorders / load elision; on x86/x86_64 a
 * plain aligned 32-bit load IS already atomic, so no explicit
 * memory barrier is needed for the hot path. */
static volatile DWORD g_io_timeout_ms = NSPA_RPC_DEFAULT_TIMEOUT_MS;


void nspa_rpc_io_init(void)
{
    WCHAR buf[16];
    DWORD len = GetEnvironmentVariableW( L"NSPA_RPC_TIMEOUT_MS", buf, ARRAY_SIZE(buf) );
    DWORD v = NSPA_RPC_DEFAULT_TIMEOUT_MS;

    if (len && len < ARRAY_SIZE(buf))
    {
        unsigned long parsed = wcstoul( buf, NULL, 0 );
        v = (parsed == 0) ? INFINITE : (DWORD)parsed;
    }

    /* Single store at DLL_PROCESS_ATTACH — no contending writer, no
     * RT reader yet.  After this point the cell is effectively const. */
    g_io_timeout_ms = v;
}


DWORD nspa_rpc_io_timeout_ms(void)
{
    return g_io_timeout_ms;
}
