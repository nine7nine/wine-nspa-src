/*
 * NSPA msg-ring v2 Phase A — redraw_window push ring (server side).
 *
 * Client appends to nspa_queue_bypass_shm_t::nspa_redraw_ring; server
 * drains lazily on the next request handler dispatched from this
 * queue.  SPSC: queue-owning thread is sole producer, wineserver main
 * thread is sole consumer.
 */
#ifndef __WINE_SERVER_NSPA_REDRAW_RING_H
#define __WINE_SERVER_NSPA_REDRAW_RING_H

struct thread;

/* Drain any pending redraw entries from `thread`'s queue ring.
 * No-op when the queue's bypass shm isn't allocated.  Called from
 * server/request.c request-dispatch entry. */
extern void nspa_redraw_ring_drain( struct thread *thread );

#endif /* __WINE_SERVER_NSPA_REDRAW_RING_H */
