/*
 * NSPA RT scheduling — wineserver side.
 *
 * Extracted from server/thread.c.
 *
 * SCHED_FIFO/RR support for the NT realtime band [16..31], gated on
 * NSPA_RT_PRIO at wineserver startup.  Mirrors the client-side block
 * now in dlls/ntdll/unix/nspa/rt.c; keeps upstream server/thread.c
 * free of RT-specific statics.
 */

#include "config.h"

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winbase.h"
#include "ddk/wdm.h"

#include "../thread.h"
#include "../process.h"
#include "rt.h"

/* NSPA RT: SCHED_FIFO/RR support for the NT realtime band [16..31].
 * Gated on NSPA_RT_PRIO being set at wineserver startup. When unset,
 * nspa_rt_prio_base stays -1 and the RT path is dormant, leaving the
 * existing nice-based behavior unchanged.
 */
#ifndef SCHED_RESET_ON_FORK
# define SCHED_RESET_ON_FORK 0x40000000
#endif

int nspa_rt_policy = SCHED_FIFO;  /* parsed from NSPA_RT_POLICY; applies to NT [16..30] only */
int nspa_rt_prio_base = -1;          /* parsed from NSPA_RT_PRIO; -1 = RT disabled */

/* NSPA RT v1.1: wineserver main thread scheduling class. Shmem dispatcher
 * threads (v1.5) also use these and self-promote at startup — they cannot
 * rely on pthread inheritance because SCHED_RESET_ON_FORK applies to
 * clone()/pthread_create() too, not just fork(), so pthreads spawned by an
 * RT-promoted parent start fresh as SCHED_OTHER. */
int nspa_srv_rt_policy = SCHED_FIFO;  /* parsed from NSPA_SRV_RT_POLICY */
int nspa_srv_rt_prio   = -1;          /* parsed from NSPA_SRV_RT_PRIO or derived; -1 = disabled */

/* NSPA RT v1.2: transient flag set by DECL_HANDLER(set_thread_info) when the
 * client has already applied the sched class via ntdll Tier 1 or v1.2 cross-
 * thread map. apply_thread_priority() reads it and skips both the RT promote
 * path AND the maybe_demote path, preventing Tier 2 from clobbering the
 * client's work. Safe as a static because wineserver dispatches under
 * global_lock — one DECL_HANDLER runs at a time. */
int nspa_rt_skip_apply;

/* Map an NT priority in [1..31] to a SCHED_FIFO priority, with NSPA_RT_PRIO
 * as the ceiling (NT 31 = TIME_CRITICAL maps to exactly NSPA_RT_PRIO).
 * Lower NT bands fall linearly below the ceiling, preserving the Win32
 * relative spacing. */
int nspa_rt_map_prio( int nt_band )
{
    int fifo = nspa_rt_prio_base - (HIGH_PRIORITY - nt_band);
    int fmin = sched_get_priority_min( SCHED_FIFO );
    int fmax = sched_get_priority_max( SCHED_FIFO ) - 1;  /* reserve 99 for kernel */
    if (fifo < fmin) fifo = fmin;
    if (fifo > fmax) fifo = fmax;
    return fifo;
}

/* Choose scheduling policy based on NT band: TIME_CRITICAL (NT 31) is always
 * SCHED_FIFO (strict priority ordering required for audio callbacks and
 * similar run-until-block workloads). Lower RT band (NT 16..30) uses the
 * NSPA_RT_POLICY env var choice (FF or RR). */
static int nspa_rt_policy_for_band( int nt_band )
{
    if (nt_band >= HIGH_PRIORITY) return SCHED_FIFO;
    return nspa_rt_policy;
}

/* Apply NSPA RT scheduling to a unix tid. Idempotent. */
void nspa_rt_apply( int unix_tid, int nt_band )
{
    struct sched_param param = { .sched_priority = nspa_rt_map_prio( nt_band ) };
    int policy = nspa_rt_policy_for_band( nt_band );

    if (sched_setscheduler( unix_tid, policy | SCHED_RESET_ON_FORK, &param ) == -1)
    {
        static int warned;
        if (debug_level || !warned++)
            fprintf( stderr, "wine: NSPA RT:Threads: sched_setscheduler(tid=%d, prio=%d) failed: %s\n",
                     unix_tid, param.sched_priority, strerror(errno) );
    }
    else if (debug_level > 1)
    {
        const char *pname = policy == SCHED_FIFO ? "FF" : policy == SCHED_RR ? "RR" : "?";
        fprintf( stderr, "wine: NSPA RT:Threads: tid=%d nt_band=%d -> %s/%d\n",
                 unix_tid, nt_band, pname, param.sched_priority );
    }
}

/* If a thread was previously RT-promoted but is now dropping into the nice
 * band, reset its scheduling class to SCHED_OTHER before falling through to
 * the setpriority() path. Cheap: one sched_getscheduler() on the common path,
 * one sched_setscheduler() only on actual transitions. */
void nspa_rt_maybe_demote( int unix_tid )
{
    int cur = sched_getscheduler( unix_tid );
    if (cur == SCHED_FIFO || cur == SCHED_RR)
    {
        struct sched_param zero = {0};
        sched_setscheduler( unix_tid, SCHED_OTHER, &zero );
    }
}

/* Parse NSPA_RT_POLICY / NSPA_RT_PRIO. Called once from init_threading(). */
void nspa_rt_init(void)
{
    const char *policy_env = getenv( "NSPA_RT_POLICY" );
    const char *prio_env   = getenv( "NSPA_RT_PRIO" );
    int fmin, fmax, val;

    if (!prio_env || !*prio_env) return;  /* RT dormant */

    fmin = sched_get_priority_min( SCHED_FIFO );
    fmax = sched_get_priority_max( SCHED_FIFO );
    if (fmin < 0 || fmax < 0) return;

    val = atoi( prio_env );
    if (val < fmin || val >= fmax)
    {
        fprintf( stderr, "wine: NSPA RT:Threads: NSPA_RT_PRIO=%d out of range [%d..%d); RT disabled\n",
                 val, fmin, fmax );
        return;
    }
    nspa_rt_prio_base = val;

    if (policy_env)
    {
        if      (!strcmp( policy_env, "FF" )) nspa_rt_policy = SCHED_FIFO;
        else if (!strcmp( policy_env, "RR" )) nspa_rt_policy = SCHED_RR;
        /* TS = conservative mode: only TIME_CRITICAL (NT 31) gets promoted to
         * SCHED_FIFO; lower RT band (NT 16..30) falls through to the upstream
         * nice-based path. Useful for users who want audio RT without forcing
         * every realtime-class thread to SCHED_FIFO. */
        else if (!strcmp( policy_env, "TS" )) nspa_rt_policy = SCHED_OTHER;
        else fprintf( stderr, "wine: NSPA RT:Threads: NSPA_RT_POLICY=%s unrecognized (expected FF, RR, or TS), using FF\n",
                      policy_env );
    }

    /* Print RT status unconditionally so users can see v1 is active without
     * needing WINEDEBUG. One line, stderr. */
    {
        const char *pname = nspa_rt_policy == SCHED_FIFO  ? "FF" :
                            nspa_rt_policy == SCHED_RR    ? "RR" :
                            nspa_rt_policy == SCHED_OTHER ? "TS" : "?";
        fprintf( stderr, "wine: NSPA RT:Threads: lower_band=%s ceiling=%d "
                         "(NT 31->FF %d, NT 24->%d, NT 16->%d)\n",
                 pname, nspa_rt_prio_base,
                 nspa_rt_map_prio( HIGH_PRIORITY ),
                 nspa_rt_map_prio( 24 ),
                 nspa_rt_map_prio( LOW_REALTIME_PRIORITY ) );
    }

    fprintf( stderr, "wine: NSPA RT:CS-PI: critical section priority inheritance enabled (FUTEX_LOCK_PI)\n" );

    /* NTSync dependency: RT mode requires /dev/ntsync for correct wait
     * paths.  Without it, ALL sync waits serialize through the wineserver
     * global_lock, causing priority inversion and potential deadlocks
     * under heavy threading (e.g. Ableton Live).
     *
     * Note: get_inproc_device_fd() caches the fd on first call — if ntsync
     * is loaded AFTER the wineserver starts, it will never be used.
     * Ensure ntsync is in /etc/modules-load.d/ for autoload at boot. */
    if (access( "/dev/ntsync", F_OK ) != 0)
    {
        fprintf( stderr, "\n"
                 "wine: *** NSPA RT:NTSync: CRITICAL — /dev/ntsync is NOT available ***\n"
                 "wine: *** All sync waits will serialize through wineserver (deadlock risk!) ***\n"
                 "wine: *** Fix: sudo modprobe ntsync && echo ntsync | sudo tee /etc/modules-load.d/ntsync.conf ***\n"
                 "\n" );
    }
    else
    {
        fprintf( stderr, "wine: NSPA RT:NTSync: /dev/ntsync available — kernel-direct sync active\n" );
    }

    /* NSPA RT v1.1: optionally promote wineserver itself to RT, at a priority
     * BELOW the audio callback band so audio callbacks always preempt the
     * server. Shmem dispatcher threads (v1.5) inherit via pthread default
     * PTHREAD_INHERIT_SCHED and will come along at the same priority.
     *
     * Default derivation: ceiling - 16 (just below NT 16 at ceiling - 15).
     * Override via NSPA_SRV_RT_PRIO (integer) + NSPA_SRV_RT_POLICY (FF|RR).
     * Gated on NSPA_RT_PRIO being set (since we only reach here if it is). */
    {
        const char *srv_pol_env  = getenv( "NSPA_SRV_RT_POLICY" );
        const char *srv_prio_env = getenv( "NSPA_SRV_RT_PRIO" );
        int audio_fifo = nspa_rt_map_prio( HIGH_PRIORITY );
        struct sched_param param;

        /* Derive wineserver priority: explicit env override or ceiling - 16.
         * NT 16 (lowest RT band) maps to ceiling - 15, so ceiling - 16 places
         * wineserver just below the entire RT thread band. */
        if (srv_prio_env && *srv_prio_env)
        {
            int val = atoi( srv_prio_env );
            if (val < 1 || val >= fmax)
            {
                fprintf( stderr, "wine: NSPA RT:Server: NSPA_SRV_RT_PRIO=%d out of range [1..%d); "
                                 "wineserver stays SCHED_OTHER\n", val, fmax );
                return;
            }
            if (val >= nspa_rt_map_prio( LOW_REALTIME_PRIORITY ))
                fprintf( stderr, "wine: NSPA RT:Server: NSPA_SRV_RT_PRIO=%d overlaps RT thread band [%d..%d]; "
                                 "wineserver may preempt RT threads\n",
                         val, nspa_rt_map_prio( LOW_REALTIME_PRIORITY ), audio_fifo );
            nspa_srv_rt_prio = val;
        }
        else
        {
            nspa_srv_rt_prio = nspa_rt_prio_base - 16;
            if (nspa_srv_rt_prio < 1) nspa_srv_rt_prio = 1;
        }

        if (srv_pol_env)
        {
            if      (!strcmp( srv_pol_env, "FF" )) nspa_srv_rt_policy = SCHED_FIFO;
            else if (!strcmp( srv_pol_env, "RR" )) nspa_srv_rt_policy = SCHED_RR;
            else fprintf( stderr, "wine: NSPA RT:Server: NSPA_SRV_RT_POLICY=%s unrecognized "
                                  "(expected FF or RR), using FF\n", srv_pol_env );
        }

        /* SCHED_RESET_ON_FORK is safe here: shmem dispatcher pthreads are
         * created with PTHREAD_EXPLICIT_SCHED in create_thread() so their
         * class is set explicitly, not inherited — reset-on-fork doesn't
         * affect them. Any actual fork() (e.g. future wineserver helpers)
         * will have its child correctly demoted to SCHED_OTHER. */
        param.sched_priority = nspa_srv_rt_prio;
        if (sched_setscheduler( 0, nspa_srv_rt_policy | SCHED_RESET_ON_FORK, &param ) == -1)
        {
            fprintf( stderr, "wine: NSPA RT:Server: sched_setscheduler(%s/%d) "
                             "failed: %s (wineserver stays at current policy)\n",
                     nspa_srv_rt_policy == SCHED_FIFO ? "FF" : "RR",
                     nspa_srv_rt_prio, strerror(errno) );
            nspa_srv_rt_prio = -1;  /* mark disabled so dispatchers don't try */
        }
        else
        {
            fprintf( stderr, "wine: NSPA RT:Server: wineserver promoted to %s/%d "
                             "(audio ceiling=%d, gap=%d)\n",
                     nspa_srv_rt_policy == SCHED_FIFO ? "FF" : "RR",
                     nspa_srv_rt_prio, audio_fifo, audio_fifo - nspa_srv_rt_prio );
        }
    }
}
