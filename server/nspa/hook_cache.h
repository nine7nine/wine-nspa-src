/*
 * NSPA Tier 2 hook cache — wineserver side.  Public declarations.
 *
 * Maintains the per-(queue, hook id) snapshot in
 * nspa_queue_bypass_shm_t::nspa_hook_chains[].  See server/protocol.def
 * for the shmem layout.  Server is the sole writer; clients read with
 * a seqlock retry (T2.3).
 */
#ifndef __WINE_SERVER_NSPA_HOOK_CACHE_H
#define __WINE_SERVER_NSPA_HOOK_CACHE_H

struct thread;
struct desktop;

/* Rebuild the per-queue cache for one (thread, index) pair.  No-op
 * when the queue's bypass shm isn't allocated.  Sets the chain's
 * `overflowed` flag (forcing the client back to the legacy
 * start_hook_chain RPC trio) on cap exceeded, any global hook firing
 * for this queue at this index, any out-of-context WINEVENT entry, or
 * module string-pool exhaustion. */
extern void nspa_hook_cache_rebuild( struct thread *thread, int index );

/* Rebuild for every queue on `desktop` that is affected by a change to
 * the global hook table at `index`.  Iterates desktop->threads; mirrors
 * the existing add_queue_hook_count loop in add_hook(). */
extern void nspa_hook_cache_rebuild_global( struct desktop *desktop, int index );

#endif /* __WINE_SERVER_NSPA_HOOK_CACHE_H */
