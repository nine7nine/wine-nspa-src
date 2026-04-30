/*
 * NSPA per-process server-side io_uring — Phase 2 of patch 1010 series.
 *
 * Provides a per-process io_uring (one ring per Wine client process)
 * for use by async-completing wineserver handlers.  This Phase 2
 * landing introduces the infrastructure but no submitters yet —
 * Phase 3 (dispatcher restructure) and Phase 4 (create_file handler)
 * are layered on top.
 *
 * See server/nspa/uring.h for API and design rationale, and
 * wine/nspa/docs/aggregate-wait-and-async-completion.md (§5) for the
 * userspace integration plan.
 *
 * Copyright 2026 Wine-NSPA
 */

#include "config.h"

#ifdef HAVE_LIBURING_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/eventfd.h>

#include <liburing.h>

#include "uring.h"

/* Pool init: thread the array through ->next, head -> [0] -> [1] -> ... -> [N-1] -> NULL. */
static void pool_init( struct nspa_uring_instance *u )
{
    unsigned int i;

    for (i = 0; i < NSPA_URING_RING_SIZE - 1; i++)
        u->pool[i].next = &u->pool[i + 1];
    u->pool[NSPA_URING_RING_SIZE - 1].next = NULL;
    u->free_head = &u->pool[0];
    u->inflight = 0;
}

int nspa_uring_instance_init( struct nspa_uring_instance *u )
{
    struct io_uring_params params;
    int ret;

    if (!u) return -EINVAL;

    memset( u, 0, sizeof(*u) );
    u->ring_fd = -1;
    u->eventfd = -1;
    u->active  = 0;

    /* Try the modern flag set first (matches client-side ntdll/io_uring.c).
     * COOP_TASKRUN: completions processed in submitter context — RT-safe.
     * SINGLE_ISSUER pinned to the dispatcher pthread is *not* set: the
     * ring is created on the main thread (process_init) but submitters
     * run on the dispatcher.  Plain init keeps both threads valid as
     * issuers (functionally we only submit from one, but the kernel
     * doesn't care without SINGLE_ISSUER). */
    memset( &params, 0, sizeof(params) );
    params.flags = IORING_SETUP_COOP_TASKRUN;
    ret = io_uring_queue_init_params( NSPA_URING_RING_SIZE, &u->ring, &params );
    if (ret < 0)
    {
        memset( &params, 0, sizeof(params) );
        ret = io_uring_queue_init_params( NSPA_URING_RING_SIZE, &u->ring, &params );
    }
    if (ret < 0)
    {
        /* Non-fatal — caller leaves u->active = 0 and falls back. */
        static int warned;
        if (!warned)
        {
            warned = 1;
            fprintf( stderr, "wine: NSPA RT:server-uring: unavailable (%s) — async handlers fall back to sync\n",
                     strerror( -ret ) );
        }
        return ret;
    }
    u->ring_fd = u->ring.ring_fd;

    /* eventfd for CQE notification.  Phase 3 hands this to ntsync's
     * NTSYNC_IOC_AGGREGATE_WAIT so the dispatcher wakes on CQE arrival
     * atomically with channel-RECV readiness. */
    u->eventfd = eventfd( 0, EFD_NONBLOCK | EFD_CLOEXEC );
    if (u->eventfd < 0)
    {
        ret = -errno;
        fprintf( stderr, "wine: NSPA RT:server-uring: eventfd() failed (%s)\n",
                 strerror( errno ) );
        io_uring_queue_exit( &u->ring );
        u->ring_fd = -1;
        return ret;
    }

    if (io_uring_register_eventfd( &u->ring, u->eventfd ) < 0)
    {
        ret = -errno;
        fprintf( stderr, "wine: NSPA RT:server-uring: register_eventfd failed (%s)\n",
                 strerror( errno ) );
        close( u->eventfd );
        u->eventfd = -1;
        io_uring_queue_exit( &u->ring );
        u->ring_fd = -1;
        return ret;
    }

    pool_init( u );
    u->active = 1;

    /* One-time banner — matches client-side announcement style. */
    {
        static int once;
        if (!once)
        {
            once = 1;
            fprintf( stderr, "wine: NSPA RT:server-uring: per-process ring active "
                     "(sq=%u cq=%u flags=0x%x efd=%d) — async handlers available\n",
                     params.sq_entries, params.cq_entries, params.flags, u->eventfd );
        }
    }
    return 0;
}

void nspa_uring_instance_shutdown( struct nspa_uring_instance *u )
{
    if (!u || !u->active) return;

    /* Caller is responsible for ensuring no submitter is still running.
     * For Phase 2 there are no submitters; Phase 3+ require dispatcher
     * exit before this is called. */
    if (u->eventfd >= 0)
    {
        close( u->eventfd );
        u->eventfd = -1;
    }
    io_uring_queue_exit( &u->ring );
    u->ring_fd = -1;
    u->active  = 0;
    /* Pool is statically embedded — nothing to free. */
}

/* ------------------------------------------------------------------ */

void nspa_uring_drain( struct nspa_uring_instance *u )
{
    struct io_uring_cqe *cqe;
    unsigned int head;
    unsigned int count = 0;

    if (!u || !u->active) return;

    /* io_uring_for_each_cqe walks ready CQEs without blocking.  Process
     * each, invoke its callback, then advance the CQ ring head. */
    io_uring_for_each_cqe( &u->ring, head, cqe )
    {
        struct nspa_uring_pending *p = io_uring_cqe_get_data( cqe );

        if (p && p->callback)
            p->callback( p->ctx, cqe->res );
        if (p)
            nspa_uring_pending_free( u, p );
        count++;
    }
    if (count)
        io_uring_cq_advance( &u->ring, count );
}

struct nspa_uring_pending *nspa_uring_pending_alloc(
    struct nspa_uring_instance *u, nspa_uring_callback_fn cb, void *ctx )
{
    struct nspa_uring_pending *p;

    if (!u || !u->active) return NULL;

    p = u->free_head;
    if (!p) return NULL;            /* pool exhausted */
    u->free_head = p->next;
    p->next     = NULL;             /* mark in flight */
    p->callback = cb;
    p->ctx      = ctx;
    u->inflight++;
    return p;
}

void nspa_uring_pending_free(
    struct nspa_uring_instance *u, struct nspa_uring_pending *p )
{
    if (!u || !p) return;
    p->callback = NULL;
    p->ctx      = NULL;
    p->next     = u->free_head;
    u->free_head = p;
    if (u->inflight)
        u->inflight--;
}

struct io_uring_sqe *nspa_uring_get_sqe( struct nspa_uring_instance *u )
{
    struct io_uring_sqe *sqe;

    if (!u || !u->active) return NULL;
    sqe = io_uring_get_sqe( &u->ring );
    if (!sqe) return NULL;

    /* RT-safety default: IOSQE_ASYNC forces submission to a kernel worker
     * thread, so the syscall doesn't run inline in io_uring_enter and
     * block the (RT-priority) dispatcher pthread.  Caller may clear this
     * if a known-fast op is being submitted; default-on is the safe
     * stance for handler authors. */
    sqe->flags |= IOSQE_ASYNC;
    return sqe;
}

int nspa_uring_submit( struct nspa_uring_instance *u )
{
    if (!u || !u->active) return -EINVAL;
    return io_uring_submit( &u->ring );
}

int nspa_uring_get_eventfd( struct nspa_uring_instance *u )
{
    if (!u || !u->active) return -1;
    return u->eventfd;
}

#endif /* HAVE_LIBURING_H */
