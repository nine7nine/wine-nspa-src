/*
 * NSPA periodic observability sampler — implementation.
 *
 * Consumer #2 of the sched API.  Validates register_timer + cancel +
 * the modular collector registration pattern.
 *
 * Lifecycle:
 *   nspa_sched_obs_init()  → at sched_run entry
 *     ├─ check NSPA_SCHED_OBS_INTERVAL_MS env (off by default)
 *     ├─ open /dev/shm/nspa-obs.<pid> (truncate)
 *     ├─ ntdll_sched_register_timer(initial)
 *     └─ atexit(obs_atexit)
 *
 *   tick callback (sched thread):
 *     ├─ truncate file + rewind
 *     ├─ invoke each registered collector
 *     ├─ fflush
 *     └─ ntdll_sched_register_timer(next interval)  // re-arm
 *
 *   obs_atexit (process exit):
 *     ├─ ntdll_sched_cancel(current handle)  // best-effort
 *     ├─ final tick (synchronous; no re-arm)
 *     └─ fclose
 *
 * Race notes:
 *   - obs_handle is read by atexit on the calling thread, written by
 *     the sched-thread timer callback.  Use atomic load/store for the
 *     pointer.  Worst case: cancel finds STATUS_NOT_FOUND because the
 *     callback fired between our load and the cancel call — final
 *     tick still runs.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/unixlib.h"

#include "sched_helpers.h"
#include "sched_obs.h"
#include "lf_close_queue.h"

#define NSPA_SCHED_OBS_MAX_COLLECTORS 16

static nspa_obs_collector_t collectors[ NSPA_SCHED_OBS_MAX_COLLECTORS ];
static unsigned int collector_count;
/* No locking needed for `collectors[]`: registration is expected at
 * static-init time (well before sched starts).  The sampler reads the
 * snapshot view at each tick.  If a real consumer needs late
 * registration, switch to atomic CAS-based append. */

static FILE *obs_file;
static LONGLONG obs_interval_ns;
static volatile sched_handle_t obs_handle;     /* atomic for atexit/race */
static int obs_active;                          /* set after first arm */

static void obs_dump_locked( void )
{
    unsigned int i;

    if (!obs_file) return;

    /* Truncate to keep the file at exactly one snapshot. */
    if (fseek( obs_file, 0, SEEK_SET ) != 0) return;
    /* ftruncate failure is non-fatal — old content lingers but new
     * write overwrites the leading bytes; consumers should look at
     * the most-recent snapshot terminator if length-sensitive. */
    (void)ftruncate( fileno( obs_file ), 0 );

    fprintf( obs_file, "# NSPA observability snapshot pid=%d\n", (int)getpid() );

    for (i = 0; i < collector_count; i++)
    {
        if (collectors[i]) collectors[i]( obs_file );
    }

    fflush( obs_file );
}

static void obs_arm_locked( void );

/* Sched-thread callback.  Re-arms self on each tick. */
static void obs_tick_cb( void *arg )
{
    (void)arg;
    obs_dump_locked();
    /* Clear the handle BEFORE re-arming so an atexit that races sees
     * either the old (stale) handle or the new one — never a half-
     * updated state.  cancel of a stale handle returns STATUS_NOT_FOUND
     * harmlessly. */
    __atomic_store_n( &obs_handle, NULL, __ATOMIC_RELEASE );
    obs_arm_locked();
}

static void obs_arm_locked( void )
{
    LARGE_INTEGER t;
    sched_handle_t h = NULL;

    /* Negative = relative timeout in NT 100ns units. */
    t.QuadPart = -(obs_interval_ns / 100);
    if (ntdll_sched_register_timer( &t, obs_tick_cb, NULL, &h ) == STATUS_SUCCESS)
        __atomic_store_n( &obs_handle, h, __ATOMIC_RELEASE );
    /* Else: failed to schedule.  No retry; obs effectively stops.
     * atexit will still do a final dump. */
}

static void obs_atexit( void )
{
    sched_handle_t h;

    /* Cancel current pending timer registration if any.  Best-effort:
     * if the timer fired right before this call, cancel returns
     * STATUS_NOT_FOUND.  Either way, do a final synchronous dump. */
    h = __atomic_exchange_n( &obs_handle, NULL, __ATOMIC_ACQ_REL );
    if (h) ntdll_sched_cancel( h );

    obs_dump_locked();

    if (obs_file)
    {
        fclose( obs_file );
        obs_file = NULL;
    }
}

void nspa_sched_obs_register_collector( nspa_obs_collector_t cb )
{
    unsigned int i;

    if (!cb) return;
    /* Idempotent: skip duplicate registration. */
    for (i = 0; i < collector_count; i++)
        if (collectors[i] == cb) return;
    if (collector_count >= NSPA_SCHED_OBS_MAX_COLLECTORS) return;
    collectors[ collector_count++ ] = cb;
}

/* Built-in collector: lf_close_queue depth — exercises the
 * cross-subsystem wiring within ntdll. */
static void collect_lf_close_queue( FILE *out )
{
    fprintf( out, "lf_close_queue.pending %u\n", nspa_lf_close_queue_pending() );
}

void nspa_sched_obs_init( void )
{
    const char *env;
    int interval_ms;
    char path[ 64 ];

    if (!nspa_sched_enabled()) return;

    env = getenv( "NSPA_SCHED_OBS_INTERVAL_MS" );
    if (!env) return;                       /* default OFF */
    interval_ms = atoi( env );
    if (interval_ms <= 0) return;

    snprintf( path, sizeof(path), "/dev/shm/nspa-obs.%d", (int)getpid() );
    obs_file = fopen( path, "w" );
    if (!obs_file) return;                  /* nothing to do without a sink */

    obs_interval_ns = (LONGLONG)interval_ms * 1000000LL;

    /* Register built-in collectors.  Future PE-migrated services can
     * call nspa_sched_obs_register_collector() at static-init time to
     * plug their stats in. */
    nspa_sched_obs_register_collector( collect_lf_close_queue );

    obs_active = 1;
    obs_arm_locked();

    atexit( obs_atexit );
}
