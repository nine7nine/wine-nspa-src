/*
 * NSPA per-process server-side io_uring.
 *
 * One io_uring per Wine process (owned by the gamma channel dispatcher
 * pthread).  Used to async-complete handlers that wrap blocking syscalls
 * (openat on cold-cache files, network mounts, realpath, readlink, ...)
 * so the dispatcher returns to RECV immediately, with the CQE drained
 * inline on the same RT thread when the ntsync aggregate-wait fires on
 * the eventfd source.
 *
 * Lifecycle is bound to the process: init from nspa_shmem_channel_init,
 * shutdown from nspa_shmem_channel_destroy.  Every Wine process either
 * has both (channel + uring) or neither (legacy socket IPC fallback).
 *
 * RT discipline:
 *   - Single submitter: the dispatcher pthread.  Pre-allocated pending
 *     pool with O(1) freelist alloc/free, no malloc on the hot path.
 *   - All SQEs SHOULD set IOSQE_ASYNC (default in nspa_uring_get_sqe)
 *     so the syscall runs in a kernel worker, not inline in
 *     io_uring_enter — keeps the dispatcher off blocking syscalls.
 *   - Init/shutdown happen at process lifecycle boundaries (not RT
 *     critical), so io_uring_queue_init_params / queue_exit syscalls
 *     are acceptable there.
 *
 * Phase 2 (initial landing) provides the infrastructure but no
 * submitters.  Phase 3 (dispatcher restructure) consumes
 * nspa_uring_get_eventfd in NTSYNC_IOC_AGGREGATE_WAIT.  Phase 4 ports
 * the create_file handler to use nspa_uring_get_sqe / submit / drain.
 *
 * See wine/nspa/docs/aggregate-wait-and-async-completion.md (§5).
 */
#ifndef __WINE_SERVER_NSPA_URING_H
#define __WINE_SERVER_NSPA_URING_H

/* Caller is expected to have already included "config.h" (Wine convention).
 * We rely on HAVE_LIBURING_H being defined or not. */

#include <stddef.h>     /* NULL — used by !HAVE_LIBURING_H fallback stubs */

#ifdef HAVE_LIBURING_H
#include <liburing.h>
#endif

struct nspa_uring_pending;
struct thread;
struct request_shm;

/* CQE callback signature.  ctx is whatever the submitter passed via
 * nspa_uring_pending_alloc; result is cqe->res (negative errno on
 * failure, positive value or 0 on success — kernel convention).
 *
 * The callback runs in dispatcher pthread context, with whatever locks
 * the dispatcher loop is holding around nspa_uring_drain.  Phase 4
 * conventions: the dispatcher takes pi_mutex_lock(&global_lock) before
 * draining so per-thread state mutations are race-free. */
typedef void (*nspa_uring_callback_fn)(void *ctx, int result);

#ifdef HAVE_LIBURING_H

/* Pool size: 64 in-flight ops per ring.  Matches the SQ ring size and
 * aligns with NTSYNC_AGG_MAX (one SQE in flight per aggregate-wait
 * iteration is a hard ceiling on dispatcher throughput, but Phase 4 is
 * one-handler-at-a-time so the realistic concurrency is much smaller). */
#define NSPA_URING_RING_SIZE  64

/* Per-pending-op state.  The pool is an array; the freelist threads
 * through ->next.  next == NULL when allocated and in flight. */
struct nspa_uring_pending
{
    nspa_uring_callback_fn       callback;
    void                        *ctx;
    struct nspa_uring_pending   *next;        /* freelist link, NULL when in flight */
};

struct nspa_uring_instance
{
    struct io_uring              ring;
    int                          ring_fd;     /* cached ring->ring_fd */
    int                          eventfd;     /* registered with ring; -1 if init failed */
    int                          active;      /* 1 if init succeeded, 0 otherwise */

    struct nspa_uring_pending    pool[NSPA_URING_RING_SIZE];
    struct nspa_uring_pending   *free_head;
    unsigned int                 inflight;
};

/* ---------------------------------------------------------------- */
/* Lifecycle (called from nspa_shmem_channel_init / _destroy)        */

/* Initialise the per-process ring + eventfd + pending pool.  Returns 0
 * on success, negative on failure.  Failure is non-fatal — caller
 * leaves u->active = 0 and async-completing handlers fall back to
 * synchronous behaviour. */
extern int  nspa_uring_instance_init( struct nspa_uring_instance *u );

/* Tear down the ring + eventfd.  Idempotent.  Caller is responsible
 * for ensuring no submitter thread is still using the instance —
 * after this returns, every nspa_uring_* function on this instance
 * is a no-op. */
extern void nspa_uring_instance_shutdown( struct nspa_uring_instance *u );

/* ---------------------------------------------------------------- */
/* Hot path (dispatcher-pthread-only — single-issuer)                */

/* Drain available CQEs.  For each one, invokes its callback.
 * Bounded: drains all currently-ready CQEs but never blocks.  Safe
 * to call when nothing is in flight (returns immediately). */
extern void nspa_uring_drain( struct nspa_uring_instance *u );

/* Allocate a pending tracking entry from the pool.  Returns NULL if
 * the pool is full (caller should fall back to synchronous handling).
 * The callback is invoked from nspa_uring_drain when the corresponding
 * CQE is processed. */
extern struct nspa_uring_pending *nspa_uring_pending_alloc(
    struct nspa_uring_instance *u, nspa_uring_callback_fn cb, void *ctx );

/* Return a pending entry to the pool.  Called by the drain code after
 * the callback runs; also useful in error paths where the SQE could
 * not be submitted. */
extern void nspa_uring_pending_free(
    struct nspa_uring_instance *u, struct nspa_uring_pending *p );

/* Acquire a fresh SQE.  RT-safe: returns immediately, never blocks.
 * The SQE has IOSQE_ASYNC pre-set so the syscall runs in a kernel
 * worker thread — keeps the (RT-priority) dispatcher off blocking
 * syscalls.  Caller fills the rest of the SQE then calls _submit().
 * Returns NULL if the SQ ring is full (rare; implies > NSPA_URING_RING_SIZE
 * unsubmitted ops queued — caller should submit and retry). */
extern struct io_uring_sqe *nspa_uring_get_sqe( struct nspa_uring_instance *u );

/* Submit any queued SQEs.  Returns the number submitted (>= 0) or
 * negative errno on failure. */
extern int  nspa_uring_submit( struct nspa_uring_instance *u );

/* Return the eventfd registered with the ring, or -1 if the instance
 * is inactive.  Used by Phase 3 dispatcher to pass to
 * NTSYNC_IOC_AGGREGATE_WAIT as an FD source — the eventfd fires when
 * io_uring posts CQEs. */
extern int  nspa_uring_get_eventfd( struct nspa_uring_instance *u );

/* ---------------------------------------------------------------- */
/* Phase 4: deferred-reply helpers (called from request handlers     */
/* that submit to the ring + their CQE callbacks).                   */

/* Mark this thread's reply as deferred — the request handler is
 * about to (or has just) submitted an io_uring SQE and the CQE
 * callback will own the reply path.  call_req_handler_shm sees
 * the flag and skips send_reply_shm; the dispatcher likewise skips
 * NTSYNC_IOC_CHANNEL_REPLY.  Both will be issued by signal_reply
 * below when the CQE arrives. */
extern void nspa_uring_defer_reply( struct thread *thread );

/* Complete a deferred reply from a CQE callback.  Saves/restores
 * `current` around send_reply_shm + nspa_shmem_channel_reply, clears
 * the deferred flag.  Caller is responsible for filling the reply
 * payload in request_shm->u.reply BEFORE calling this. */
extern void nspa_uring_signal_reply( struct thread *thread,
                                     struct request_shm *request_shm,
                                     unsigned int data_size,
                                     int channel_fd,
                                     unsigned long long entry_id );

#else  /* !HAVE_LIBURING_H */

/* Fallback when liburing is not available at build time.  The instance
 * is a stub with active = 0 and all functions no-op. */
struct nspa_uring_instance
{
    int active;   /* always 0 in this build */
};

static inline int  nspa_uring_instance_init( struct nspa_uring_instance *u )
{
    if (u) u->active = 0;
    return -1;
}
static inline void nspa_uring_instance_shutdown( struct nspa_uring_instance *u ) { (void)u; }
static inline void nspa_uring_drain( struct nspa_uring_instance *u ) { (void)u; }
static inline struct nspa_uring_pending *nspa_uring_pending_alloc(
    struct nspa_uring_instance *u, nspa_uring_callback_fn cb, void *ctx )
{ (void)u; (void)cb; (void)ctx; return NULL; }
static inline void nspa_uring_pending_free(
    struct nspa_uring_instance *u, struct nspa_uring_pending *p )
{ (void)u; (void)p; }
static inline int nspa_uring_get_eventfd( struct nspa_uring_instance *u ) { (void)u; return -1; }

#endif /* HAVE_LIBURING_H */

#endif /* __WINE_SERVER_NSPA_URING_H */
