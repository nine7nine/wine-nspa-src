/*
 * NSPA local-file async close queue — implementation.
 *
 * Phase 3 first real consumer of the sched infrastructure.  See
 * lf_close_queue.h for the NT-semantic preservation contract.
 *
 * Design:
 *
 *   Producer (NtClose):
 *     - tries push(); on success, returns immediately
 *     - on failure (queue full or gate off), falls through to inline close
 *
 *   Drain (sched thread, async callback):
 *     - takes the lock, splices the pending list onto a local list,
 *       releases the lock, then closes outside the lock so producers
 *       are not blocked on slow close()/RPC
 *
 *   Pre-flush (LF allocator):
 *     - synchronous drain on caller thread; same splice-then-close
 *       pattern outside the lock
 *
 * Concurrency:
 *   - pi_mutex around the linked list keeps push/drain/flush serialized
 *   - The actual close()/RPC work happens outside the lock so the lock
 *     hold time stays microseconds
 *   - drain_pending atomic prevents redundant async submissions when the
 *     sched thread is already draining
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdlib.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winbase.h"
#include "wine/list.h"
#include "wine/server.h"
#include "wine/debug.h"

#include "../unix_private.h"

#include <rtpi.h>

#include "sched_helpers.h"
#include "lf_close_queue.h"

WINE_DEFAULT_DEBUG_CHANNEL(file);

/* Queue capacity.  64 was chosen as a balance between batching benefit
 * (deeper = more amortization) and FD-exhaustion risk (deeper = longer
 * lingering FDs).  Tunable later if profiling motivates. */
#define NSPA_LF_CLOSE_QUEUE_CAP 64

struct close_entry
{
    struct list  entry;
    HANDLE       server_handle;   /* 0 if not lazy-promoted */
    int          unix_fd;         /* -1 if none */
};

static DEFINE_PI_MUTEX( queue_lock, 0 );
static struct list queue_pending = LIST_INIT( queue_pending );
static unsigned int queue_count;          /* protected by queue_lock */
static volatile int drain_armed;          /* atomic — 1 while async drain is queued or in flight */

static void close_entry_perform( struct close_entry *e )
{
    /* Both close() and the close_handle RPC may block briefly; do them
     * outside the queue_lock.  Failure is best-effort: NtClose already
     * returned success to the app; we have nothing to report. */
    if (e->unix_fd >= 0) close( e->unix_fd );

    if (e->server_handle)
    {
        SERVER_START_REQ( close_handle )
        {
            req->handle = wine_server_obj_handle( e->server_handle );
            wine_server_call( req );
        }
        SERVER_END_REQ;
    }

    free( e );
}

/* Async callback running on the sched thread.  Snapshot the pending
 * list under the lock, release, then close everything.  This bounds the
 * lock hold time to a few list-pointer assignments. */
static void drain_async_cb( void *arg )
{
    struct list snapshot = LIST_INIT( snapshot );
    struct close_entry *e, *next;

    (void)arg;

    pi_mutex_lock( &queue_lock );
    /* Splice the entire pending list onto our local snapshot. */
    LIST_FOR_EACH_ENTRY_SAFE( e, next, &queue_pending, struct close_entry, entry )
    {
        list_remove( &e->entry );
        list_add_tail( &snapshot, &e->entry );
    }
    queue_count = 0;
    /* Mark drain as no longer armed BEFORE releasing the lock, so a
     * push that happens after we release re-arms a fresh drain.  Use
     * release ordering so the "queue is empty + I will arm again"
     * publication happens before any subsequent push observes it. */
    __atomic_store_n( &drain_armed, 0, __ATOMIC_RELEASE );
    pi_mutex_unlock( &queue_lock );

    /* Perform the actual closes outside the lock.  Any new push that
     * arrives during this loop goes into a fresh batch + arms a new
     * async submission. */
    LIST_FOR_EACH_ENTRY_SAFE( e, next, &snapshot, struct close_entry, entry )
    {
        list_remove( &e->entry );
        close_entry_perform( e );
    }
}

BOOL nspa_lf_close_queue_push( HANDLE server_handle, int unix_fd )
{
    struct close_entry *e;
    int need_arm = 0;

    if (!nspa_sched_enabled()) return FALSE;
    if (!server_handle && unix_fd < 0) return TRUE;     /* nothing to do */

    /* Check current depth without holding the lock first — fast bailout
     * for the common full-queue case.  Re-check under the lock below. */
    if (__atomic_load_n( &queue_count, __ATOMIC_ACQUIRE ) >= NSPA_LF_CLOSE_QUEUE_CAP)
        return FALSE;

    if (!(e = malloc( sizeof(*e) ))) return FALSE;      /* caller falls back to inline */
    e->server_handle = server_handle;
    e->unix_fd       = unix_fd;

    pi_mutex_lock( &queue_lock );
    if (queue_count >= NSPA_LF_CLOSE_QUEUE_CAP)
    {
        pi_mutex_unlock( &queue_lock );
        free( e );
        return FALSE;
    }
    list_add_tail( &queue_pending, &e->entry );
    __atomic_store_n( &queue_count, queue_count + 1, __ATOMIC_RELEASE );

    /* Arm a single async drain per batch.  If a drain is already in
     * flight or queued, our push will be picked up by the splice it
     * does at start. */
    if (!__atomic_exchange_n( &drain_armed, 1, __ATOMIC_ACQ_REL ))
        need_arm = 1;
    pi_mutex_unlock( &queue_lock );

    if (need_arm)
    {
        if (nspa_sched_submit_async( drain_async_cb, NULL ))
        {
            /* Sched submission failed.  Don't leave drain_armed set —
             * otherwise no future push can arm a fresh drain.  Roll
             * back the flag and synchronously flush so this entry
             * isn't lost. */
            __atomic_store_n( &drain_armed, 0, __ATOMIC_RELEASE );
            ERR( "sched submit failed; flushing inline\n" );
            nspa_lf_close_queue_flush();
        }
    }
    return TRUE;
}

void nspa_lf_close_queue_flush( void )
{
    struct list snapshot = LIST_INIT( snapshot );
    struct close_entry *e, *next;

    if (__atomic_load_n( &queue_count, __ATOMIC_ACQUIRE ) == 0) return;

    pi_mutex_lock( &queue_lock );
    LIST_FOR_EACH_ENTRY_SAFE( e, next, &queue_pending, struct close_entry, entry )
    {
        list_remove( &e->entry );
        list_add_tail( &snapshot, &e->entry );
    }
    queue_count = 0;
    /* Don't clear drain_armed — if an async drain is already queued,
     * let it run (it will find an empty queue and exit cheaply).  This
     * avoids a race where we clear the flag, an arm hasn't happened
     * yet, and we lose the next batch.  Worst case: one wasted async
     * dispatch into an empty queue. */
    pi_mutex_unlock( &queue_lock );

    LIST_FOR_EACH_ENTRY_SAFE( e, next, &snapshot, struct close_entry, entry )
    {
        list_remove( &e->entry );
        close_entry_perform( e );
    }
}

unsigned int nspa_lf_close_queue_pending( void )
{
    return __atomic_load_n( &queue_count, __ATOMIC_ACQUIRE );
}
