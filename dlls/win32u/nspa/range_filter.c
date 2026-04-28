/*
 * NSPA empty-PEEK shortcut — client-side filter-vs-range check.
 *
 * Reads the per-class deliverable msg-id range published by the server in
 * nspa_queue_bypass_shm_t::nspa_msg_ranges[].  See protocol.def for the
 * data structure and ordering invariant; see server/nspa/range_publish.c
 * for the writer.
 *
 * Race-window override (conservative): if the published range is the
 * empty sentinel (min > max) BUT the caller is invoking us because the
 * legacy QS bit is set, return FALSE (don't trust the empty sentinel —
 * server is mid-update or the bit is set for a non-msg_list reason such
 * as quit_message / NSPA ring posts).  The caller then falls through to
 * the existing wake-bit logic, RPCs, and gets the right answer.
 */

#if 0
#pragma makedep unix
#endif

#include <stdint.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "winternl.h"
#include "../win32u_private.h"

/* T2 ships gated default-OFF; T3 flips polarity post-validation.  Set
 * NSPA_RANGE_FILTER=1 to enable for A/B testing in this phase. */
static int nspa_range_filter_enabled( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv( "NSPA_RANGE_FILTER" );
        cached = (v && *v == '1');
    }
    return cached;
}

/* Bound seqlock retry to avoid pathological spin if a writer is somehow
 * stuck mid-update.  The publisher is wineserver-single-threaded so
 * sustained writer churn is not expected; treat exhaustion as
 * "uncertain — RPC". */
#define NSPA_RANGE_SEQLOCK_RETRY_BUDGET  16

BOOL nspa_post_range_excludes_filter( const nspa_queue_bypass_shm_t *bypass,
                                      UINT first, UINT last )
{
    const volatile nspa_msg_range_t *range;
    unsigned int v0, v1, min, max;
    unsigned int retries = 0;

    if (!bypass) return FALSE;
    if (!nspa_range_filter_enabled()) return FALSE;
    range = &bypass->nspa_msg_ranges[NSPA_RANGE_CLASS_POST];

    /* Seqlock retry-read of (min, max). */
    for (;;)
    {
        v0 = __atomic_load_n( &range->version, __ATOMIC_ACQUIRE );
        if (v0 & 1u)
        {
            /* writer mid-update */
            if (++retries > NSPA_RANGE_SEQLOCK_RETRY_BUDGET) return FALSE;
            continue;
        }
        min = __atomic_load_n( &range->min_msg, __ATOMIC_RELAXED );
        max = __atomic_load_n( &range->max_msg, __ATOMIC_RELAXED );
        __atomic_thread_fence( __ATOMIC_ACQUIRE );
        v1 = __atomic_load_n( &range->version, __ATOMIC_ACQUIRE );
        if (v1 == v0) break;
        if (++retries > NSPA_RANGE_SEQLOCK_RETRY_BUDGET) return FALSE;
    }

    /* Sentinel: class empty.  Caller invoked us because a wake bit is
     * set, so this is either a mid-update race window or a non-msg_list
     * source (quit_message, NSPA ring).  Conservative: don't shortcut. */
    if (min > max) return FALSE;

    /* Range non-empty: filter [first, last] excludes the queue range
     * iff filter is entirely below min OR entirely above max. */
    return (last < min) || (first > max);
}
