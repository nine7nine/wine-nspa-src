/*
 * NSPA RT sched-class validation probe — implementation.
 *
 * Periodic RT-class timer that re-arms itself, measures wakeup jitter
 * vs the expected fire time, exposes counters via the OBS collector
 * pattern.  Used to validate the RT class end-to-end before wm_timer
 * (or other production RT consumers) migrates.
 *
 * Concurrency:
 *   - rt_probe_cb runs on the RT sched thread (SCHED_FIFO at
 *     NSPA_RT_PRIO-1).  Updates atomic counters, re-arms itself.
 *   - Obs collector runs on the DEFAULT sched thread (SCHED_OTHER).
 *     Reads atomic counters; no lock needed.
 *   - The handle is updated by rt_probe_cb (RT thread) on every
 *     re-arm and read by atexit on the caller thread.  Use a small
 *     pi_mutex around it; ABA-safe cancel makes contents safe under
 *     torn read either way.
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
#include <time.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"
#include "wine/unixlib.h"

#include <rtpi.h>

#include "sched_helpers.h"
#include "sched_obs.h"
#include "sched_rt_probe.h"

WINE_DEFAULT_DEBUG_CHANNEL(sched);

/* Cadence chosen to be modest: probe shouldn't be a stress test, just
 * a periodic validate.  100ms keeps the rate low enough to be invisible
 * in any audio/perf measurement. */
#define RT_PROBE_INTERVAL_NS  (100LL * 1000000LL)

static volatile unsigned long rt_probe_fires;
static volatile long          rt_probe_jitter_last_us;
static volatile long          rt_probe_jitter_max_us;
static long long              rt_probe_expected_ns;
static sched_handle_t         rt_probe_handle;
static DEFINE_PI_MUTEX( rt_probe_handle_lock, 0 );
static int                    rt_probe_active;

static long long mono_now_ns( void )
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* Timer callback: runs on the RT sched thread.  Records jitter,
 * bumps fire count, re-arms by registering the next interval. */
static void rt_probe_cb( void *arg )
{
    long long now = mono_now_ns();
    long jitter = (long)((now - rt_probe_expected_ns) / 1000);   /* µs */
    long curr_max;

    (void)arg;

    if (jitter < 0) jitter = -jitter;

    __atomic_add_fetch( &rt_probe_fires, 1, __ATOMIC_RELAXED );
    __atomic_store_n( &rt_probe_jitter_last_us, jitter, __ATOMIC_RELAXED );

    curr_max = __atomic_load_n( &rt_probe_jitter_max_us, __ATOMIC_RELAXED );
    if (jitter > curr_max)
    {
        /* Single-writer (rt_probe_cb runs on one thread): plain store
         * is correct; we only relax-store to publish to readers. */
        __atomic_store_n( &rt_probe_jitter_max_us, jitter, __ATOMIC_RELAXED );
    }

    /* Re-arm for next interval.  Clear the stored handle BEFORE
     * arming so an atexit racing with the boundary sees a coherent
     * value (gen-checked cancel of stale = harmless NOT_FOUND). */
    pi_mutex_lock( &rt_probe_handle_lock );
    rt_probe_handle = SCHED_HANDLE_NULL;
    pi_mutex_unlock( &rt_probe_handle_lock );

    {
        LARGE_INTEGER t;
        sched_handle_t h = SCHED_HANDLE_NULL;
        NTSTATUS status;
        t.QuadPart = -(RT_PROBE_INTERVAL_NS / 100);
        rt_probe_expected_ns = now + RT_PROBE_INTERVAL_NS;
        status = ntdll_sched_register_timer_class( NTDLL_SCHED_CLASS_RT, &t,
                                                   rt_probe_cb, NULL, &h );
        if (status == STATUS_SUCCESS)
        {
            pi_mutex_lock( &rt_probe_handle_lock );
            rt_probe_handle = h;
            pi_mutex_unlock( &rt_probe_handle_lock );
        }
        else
        {
            WARN( "rt probe re-arm failed status=%#x — probe stops\n", (unsigned int)status );
        }
    }
}

static void rt_probe_collector( FILE *out )
{
    fprintf( out, "rt_probe.alive %d\n", nspa_sched_rt_available() ? 1 : 0 );
    fprintf( out, "rt_probe.fires %lu\n",
             __atomic_load_n( &rt_probe_fires, __ATOMIC_RELAXED ) );
    fprintf( out, "rt_probe.jitter_last_us %ld\n",
             __atomic_load_n( &rt_probe_jitter_last_us, __ATOMIC_RELAXED ) );
    fprintf( out, "rt_probe.jitter_max_us %ld\n",
             __atomic_load_n( &rt_probe_jitter_max_us, __ATOMIC_RELAXED ) );
}

static void rt_probe_atexit( void )
{
    sched_handle_t h;

    pi_mutex_lock( &rt_probe_handle_lock );
    h = rt_probe_handle;
    rt_probe_handle = SCHED_HANDLE_NULL;
    pi_mutex_unlock( &rt_probe_handle_lock );

    if (h.priv) ntdll_sched_cancel( h );
    /* Counters intentionally not dumped here — the OBS sampler's
     * own atexit handler does a final flush which picks up our
     * collector on its way out. */
}

void nspa_sched_rt_probe_init( void )
{
    LARGE_INTEGER t;
    sched_handle_t h = SCHED_HANDLE_NULL;
    NTSTATUS status;

    if (!getenv( "NSPA_SCHED_RT_PROBE" )) return;

    if (!nspa_sched_rt_available())
    {
        ERR( "NSPA_SCHED_RT_PROBE set but NSPA RT class unavailable "
             "(NSPA_USE_SCHED_THREAD off, or NSPA_RT_PRIO not configured)\n" );
        return;
    }

    nspa_sched_obs_register_collector( rt_probe_collector );

    /* Initial arm.  Counters start at 0; first fire records jitter
     * vs the expected_ns we set right before the register call. */
    t.QuadPart = -(RT_PROBE_INTERVAL_NS / 100);
    rt_probe_expected_ns = mono_now_ns() + RT_PROBE_INTERVAL_NS;
    status = ntdll_sched_register_timer_class( NTDLL_SCHED_CLASS_RT, &t,
                                               rt_probe_cb, NULL, &h );
    if (status != STATUS_SUCCESS)
    {
        ERR( "rt probe initial register failed status=%#x\n", (unsigned int)status );
        return;
    }
    pi_mutex_lock( &rt_probe_handle_lock );
    rt_probe_handle = h;
    pi_mutex_unlock( &rt_probe_handle_lock );

    rt_probe_active = 1;
    atexit( rt_probe_atexit );
}
