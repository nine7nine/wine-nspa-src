/*
 * NSPA empty-PEEK shortcut — per-class deliverable msg-id range publisher
 * (server side).
 *
 * Cheap policy: enqueue widens (min, max) to cover the new msg id;
 * dequeue resets to sentinel only when the list is empty.  Range may
 * stay wider than the actual list contents post-dequeue — that's a
 * false-positive overlap (unnecessary RPC), not a correctness bug.
 *
 * Wineserver is single-threaded for request handlers, so the seqlock
 * `version` field exists only for cross-process readers — odd =
 * mid-update, even = stable.  Pattern mirrors nspa_hook_cache_rebuild
 * in server/nspa/hook_cache.c.
 */

#include "config.h"

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winuser.h"

#include "../object.h"
#include "../thread.h"
#include "../user.h"
#include "range_publish.h"

static inline void publish_seqlock_begin( nspa_msg_range_t *range, unsigned int *v_out )
{
    unsigned int v = range->version;
    /* odd version = writer mid-update; readers retry */
    __atomic_store_n( &range->version, v + 1, __ATOMIC_RELEASE );
    __atomic_thread_fence( __ATOMIC_ACQ_REL );
    *v_out = v;
}

static inline void publish_seqlock_end( nspa_msg_range_t *range, unsigned int v )
{
    /* even version = stable; pair with reader's acquire-load on version */
    __atomic_thread_fence( __ATOMIC_ACQ_REL );
    __atomic_store_n( &range->version, v + 2, __ATOMIC_RELEASE );
}

void nspa_post_range_publish_widen( nspa_queue_bypass_shm_t *shm, unsigned int msg_id )
{
    nspa_msg_range_t *range;
    unsigned int v, min, max;

    if (!shm) return;

    range = (nspa_msg_range_t *)&shm->nspa_msg_ranges[NSPA_RANGE_CLASS_POST];

    publish_seqlock_begin( range, &v );

    /* Cheap widen: extend (min, max) to cover msg_id.  Sentinel-empty
     * (min=~0u, max=0) widens correctly: any new msg_id will satisfy
     * msg_id < ~0u and msg_id > 0 (for msg_id > 0) so the range becomes
     * [msg_id, msg_id] — a non-empty range covering only the new id. */
    min = range->min_msg;
    max = range->max_msg;
    if (msg_id < min) min = msg_id;
    if (msg_id > max) max = msg_id;
    range->min_msg = min;
    range->max_msg = max;

    publish_seqlock_end( range, v );
}

void nspa_post_range_publish_empty( nspa_queue_bypass_shm_t *shm )
{
    nspa_msg_range_t *range;
    unsigned int v;

    if (!shm) return;

    range = (nspa_msg_range_t *)&shm->nspa_msg_ranges[NSPA_RANGE_CLASS_POST];

    publish_seqlock_begin( range, &v );

    range->min_msg = ~0u;
    range->max_msg = 0;

    publish_seqlock_end( range, v );
}
