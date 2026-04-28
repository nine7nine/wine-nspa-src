/*
 * NSPA empty-PEEK shortcut — per-class deliverable msg-id range publisher.
 *
 * See protocol.def comment block above nspa_msg_range_t for design and
 * ordering invariant.  This header is the server-side seam exposed to
 * queue.c at every legacy POST-list mutation site.
 */

#ifndef __WINE_SERVER_NSPA_RANGE_PUBLISH_H
#define __WINE_SERVER_NSPA_RANGE_PUBLISH_H

#include "../object.h"
#include "../thread.h"
#include "../user.h"

/* Recompute and publish the POST-class min/max msg-id range for the
 * given queue.  Cheap-policy: enqueue path widens via (min, max); dequeue
 * path resets to empty sentinel only when the legacy POST list is empty.
 *
 * Must be called BEFORE set_queue_bits(QS_POSTMESSAGE) on enqueue and
 * BEFORE clear_queue_bits(QS_POSTMESSAGE) on dequeue, so cross-process
 * readers always see range at-least-as-fresh as the wake bit.
 *
 * No-op when the queue's bypass shm is not allocated. */
void nspa_post_range_publish( struct msg_queue *queue, unsigned int new_msg );
void nspa_post_range_publish_check_empty( struct msg_queue *queue );

#endif /* __WINE_SERVER_NSPA_RANGE_PUBLISH_H */
