/*
 * NSPA empty-PEEK shortcut — per-class deliverable msg-id range publisher.
 *
 * See protocol.def comment block above nspa_msg_range_t for design and
 * ordering invariant.  This header is the server-side seam exposed to
 * queue.c at every legacy POST-list mutation site.
 */

#ifndef __WINE_SERVER_NSPA_RANGE_PUBLISH_H
#define __WINE_SERVER_NSPA_RANGE_PUBLISH_H

#include "wine/server_protocol.h"  /* nspa_queue_bypass_shm_t */

/* Cheap-policy publisher.  Both helpers are no-ops when shm is NULL.
 *
 * Ordering invariant: caller must invoke widen() AFTER list_add_tail and
 * BEFORE set_queue_bits(QS_POSTMESSAGE).  Caller must invoke empty()
 * AFTER list_remove (when the list is now empty) and BEFORE
 * clear_queue_bits(QS_POSTMESSAGE).  This guarantees cross-process
 * readers see range at-least-as-fresh as the wake bit; the residual
 * empty-sentinel-vs-bit-set race is handled by the client-side
 * race-window override.
 */
extern void nspa_post_range_publish_widen( nspa_queue_bypass_shm_t *shm, unsigned int msg_id );
extern void nspa_post_range_publish_empty( nspa_queue_bypass_shm_t *shm );

#endif /* __WINE_SERVER_NSPA_RANGE_PUBLISH_H */
