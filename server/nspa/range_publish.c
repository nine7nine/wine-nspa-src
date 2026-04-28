/*
 * NSPA empty-PEEK shortcut — per-class deliverable msg-id range publisher
 * (server side).  T0 STUB: structural plumbing only; T1 fills in the
 * publish logic at the queue.c seams.
 *
 * Cheap-policy spec (T1 implementation target):
 *   nspa_post_range_publish(queue, new_msg)        — enqueue path: widen
 *     range to include new_msg under seqlock.  No list walk.
 *   nspa_post_range_publish_check_empty(queue)     — dequeue path: if
 *     queue->msg_list[POST_MESSAGE] is empty, reset to sentinel
 *     (min=~0u, max=0).  Otherwise no-op (range may stay wider than the
 *     actual post-dequeue contents — false-positive overlap → unnecessary
 *     RPC, no correctness regression).
 *
 * Both helpers must run BEFORE the corresponding set_queue_bits /
 * clear_queue_bits call so the published range is at-least-as-fresh as
 * the wake bit.  See protocol.def design comment.
 *
 * Wineserver is single-threaded for request handlers, so the seqlock
 * version field exists only for cross-process readers.
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

void nspa_post_range_publish( struct msg_queue *queue, unsigned int new_msg )
{
    /* T0 stub — wired in T1. */
    (void)queue;
    (void)new_msg;
}

void nspa_post_range_publish_check_empty( struct msg_queue *queue )
{
    /* T0 stub — wired in T1. */
    (void)queue;
}
