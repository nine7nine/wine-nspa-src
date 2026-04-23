/*
 * NSPA debug/trace macros — client-side (ntdll, win32u).
 *
 * Two-layer gating:
 *
 *   1. Compile-time: NSPA_DEBUG defaults to 1; pass -DNSPA_DEBUG=0 to a
 *      release build and every NSPA_TRACE call compiles away to nothing.
 *
 *   2. Runtime: the first NSPA_TRACE call for a given env name does a
 *      single getenv() and caches the result in a TU-local static bool.
 *      Every subsequent call is a relaxed atomic load + conditional
 *      branch; when the env is unset (the default for production runs)
 *      the cost is a load + a not-taken branch, no syscall.
 *
 * Usage:
 *
 *   #include "nspa/debug.h"
 *   NSPA_TRACE(LF_TRACE, "NSPA-LF mint h=%p fd=%d\n", h, fd);
 *
 * The macro stamps out a per-env helper function at first use via the
 * NSPA_TRACE_ENABLED_FN expansion below.  Because the helper is
 * `static inline`, each translation unit that calls it gets its own
 * private cache — independent and lock-free.
 */

#ifndef __WINE_NSPA_DEBUG_H
#define __WINE_NSPA_DEBUG_H

#include <stdlib.h>
#include <stdio.h>

#ifndef NSPA_DEBUG
#define NSPA_DEBUG 1
#endif

#if NSPA_DEBUG

#define NSPA_TRACE_ENABLED_FN(name) \
    static inline int nspa_trace_##name##_enabled(void) { \
        static int cache = -1; \
        int v = __atomic_load_n( &cache, __ATOMIC_RELAXED ); \
        if (v < 0) { \
            v = getenv( "NSPA_" #name ) ? 1 : 0; \
            __atomic_store_n( &cache, v, __ATOMIC_RELAXED ); \
        } \
        return v; \
    }

/* Register the env names currently used.  Adding a new trace channel
 * means adding a line here; unused channels impose no runtime cost. */
NSPA_TRACE_ENABLED_FN(LF_TRACE)
NSPA_TRACE_ENABLED_FN(LF_TRACE_SRV)
NSPA_TRACE_ENABLED_FN(SEND_DIAG)
NSPA_TRACE_ENABLED_FN(POST_DEBUG)

#define NSPA_TRACE(name, ...) \
    do { if (nspa_trace_##name##_enabled()) fprintf( stderr, __VA_ARGS__ ); } while (0)

#else /* !NSPA_DEBUG */

#define NSPA_TRACE(name, ...) ((void)0)

#endif /* NSPA_DEBUG */

#endif /* __WINE_NSPA_DEBUG_H */
