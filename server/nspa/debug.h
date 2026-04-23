/*
 * NSPA debug/trace macros — wineserver side.
 *
 * Mirrors dlls/ntdll/unix/nspa/debug.h (client-side) with two-layer
 * gating: a compile-time NSPA_DEBUG switch and a runtime cached env
 * check.  Wineserver is single-threaded, so a plain `static int cache`
 * suffices — no atomics needed.
 */

#ifndef __WINE_SERVER_NSPA_DEBUG_H
#define __WINE_SERVER_NSPA_DEBUG_H

#include <stdlib.h>
#include <stdio.h>

#ifndef NSPA_DEBUG
#define NSPA_DEBUG 1
#endif

#if NSPA_DEBUG

#define NSPA_TRACE_ENABLED_FN(name) \
    static inline int nspa_trace_##name##_enabled(void) { \
        static int cache = -1; \
        if (cache < 0) cache = getenv( "NSPA_" #name ) ? 1 : 0; \
        return cache; \
    }

NSPA_TRACE_ENABLED_FN(LF_TRACE_SRV)
NSPA_TRACE_ENABLED_FN(POST_DEBUG)

#define NSPA_TRACE(name, ...) \
    do { if (nspa_trace_##name##_enabled()) fprintf( stderr, __VA_ARGS__ ); } while (0)

#else /* !NSPA_DEBUG */

#define NSPA_TRACE(name, ...) ((void)0)

#endif /* NSPA_DEBUG */

#endif /* __WINE_SERVER_NSPA_DEBUG_H */
