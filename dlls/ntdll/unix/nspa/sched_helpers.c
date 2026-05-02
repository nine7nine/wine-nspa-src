/*
 * NSPA sched helpers — implementation.
 *
 * Phase 2.5: env gate read-once for NSPA_USE_SCHED_THREAD.
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

#include <pthread.h>
#include <sched.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"
#include "wine/unixlib.h"

#include "../unix_private.h"

#include "sched_helpers.h"

WINE_DEFAULT_DEBUG_CHANNEL(sched);

/* Cached value: 0 = unknown, 1 = explicitly OFF, 2 = ON.  Three states
 * so a concurrent first call can't re-read the env (cheap monotonic
 * transition, no lock needed since the env is process-wide constant). */
static int nspa_sched_enabled_cached;

BOOL nspa_sched_enabled(void)
{
    int v = __atomic_load_n( &nspa_sched_enabled_cached, __ATOMIC_ACQUIRE );
    if (!v)
    {
        /* Default ON since 2026-05-02 night — Phase 3 LF close queue
         * shipped + Ableton-validated.  Set NSPA_USE_SCHED_THREAD=0 to
         * force OFF (kept as an env switch for diagnostic A/B). */
        const char *env = getenv( "NSPA_USE_SCHED_THREAD" );
        v = (env && env[0] == '0' && env[1] == 0) ? 1 : 2;
        __atomic_store_n( &nspa_sched_enabled_cached, v, __ATOMIC_RELEASE );
    }
    return v == 2;
}

int nspa_sched_submit_async( void (*cb)( void *arg ), void *arg )
{
    /* Adapt to ntdll_sched_async signature: it takes async_callback which
     * is `void (*)(void *private)`.  Same type — pass through. */
    NTSTATUS status = ntdll_sched_async( (async_callback)cb, arg );
    return status != STATUS_SUCCESS;
}

/* ============================================================
 * NSPA Phase 3 multi-class: RT sched instance lazy spawn
 * ============================================================
 *
 * Lazy-spawn an RT-class sched thread on first
 * ntdll_sched_register_*_class(NTDLL_SCHED_CLASS_RT, ...) call.
 * Thread runs SCHED_FIFO at NSPA_RT_PRIO-1 (one priority below the
 * NSPA_RT_PRIO ceiling — same priority class as the local_timer +
 * wm_timer dispatchers it's intended to replace).
 *
 * Available iff:
 *   - sched is enabled (NSPA_USE_SCHED_THREAD), AND
 *   - NSPA RT promotion is configured (nspa_rt_prio_base >= 1, so
 *     prio_base - 1 is a valid SCHED_FIFO priority)
 *
 * If unavailable, get_rt_instance() returns NULL and consumers see
 * STATUS_NOT_SUPPORTED — they then fall back to their own pthread
 * (existing path).  No silent-degrade-to-SCHED_OTHER, since RT
 * consumers chose RT for a reason. */

static pthread_once_t  rt_init_once = PTHREAD_ONCE_INIT;
static struct sched_instance *rt_inst;
static int rt_unavailable;     /* set by rt_init_once if NSPA RT not configured */

static void *rt_thread_main( void *arg )
{
    struct sched_instance *inst = arg;
    pthread_setname_np( pthread_self(), "wine-sched-rt" );
    sched_run_inst( inst );
    return NULL;
}

static void rt_init_once_fn( void )
{
    pthread_attr_t attr;
    struct sched_param param;
    pthread_t tid;
    int err, prio;

    if (!nspa_sched_enabled())
    {
        rt_unavailable = 1;
        return;
    }
    if (nspa_rt_prio_base < 1)
    {
        /* NSPA_RT_PRIO not set or too low to derive a useful sched
         * thread priority.  RT-class registrations will return
         * STATUS_NOT_SUPPORTED; caller falls back. */
        rt_unavailable = 1;
        return;
    }
    prio = nspa_rt_prio_base - 1;

    if (!(rt_inst = sched_instance_alloc()))
    {
        ERR( "RT sched instance alloc failed\n" );
        rt_unavailable = 1;
        return;
    }

    /* Spawn the thread with explicit SCHED_FIFO attrs.  pthread_create
     * with INHERIT_SCHED + the sched policy in attr is the cleanest
     * way to land at the right priority without a window where the
     * thread runs at SCHED_OTHER. */
    pthread_attr_init( &attr );
    pthread_attr_setinheritsched( &attr, PTHREAD_EXPLICIT_SCHED );
    pthread_attr_setschedpolicy( &attr, SCHED_FIFO );
    param.sched_priority = prio;
    pthread_attr_setschedparam( &attr, &param );

    err = pthread_create( &tid, &attr, rt_thread_main, rt_inst );
    pthread_attr_destroy( &attr );

    if (err)
    {
        /* Common failure: caller lacks CAP_SYS_NICE/RLIMIT_RTPRIO for
         * SCHED_FIFO at this priority.  Retry with default attrs +
         * pthread_setschedparam from inside the thread — same as the
         * existing local_timer/wm_timer dispatchers' graceful path. */
        WARN( "pthread_create with SCHED_FIFO failed (err=%d); falling back to default attr\n", err );
        if ((err = pthread_create( &tid, NULL, rt_thread_main, rt_inst )))
        {
            ERR( "pthread_create plain also failed (err=%d) — RT class unavailable\n", err );
            free( rt_inst );
            rt_inst = NULL;
            rt_unavailable = 1;
            return;
        }
        /* Best-effort priority bump from outside (non-fatal). */
        if (pthread_setschedparam( tid, SCHED_FIFO, &param ))
            WARN( "post-create SCHED_FIFO promotion also failed; RT thread runs SCHED_OTHER\n" );
    }
    pthread_detach( tid );
}

struct sched_instance *nspa_sched_get_rt_instance( void )
{
    pthread_once( &rt_init_once, rt_init_once_fn );
    if (rt_unavailable) return NULL;
    return rt_inst;
}

BOOL nspa_sched_rt_available( void )
{
    return nspa_sched_get_rt_instance() != NULL;
}
