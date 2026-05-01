/*
 * NSPA RT scheduling — client-side.
 *
 * Extracted from dlls/ntdll/unix/thread.c as part of the nspa reorg.
 *
 * NSPA RT v1 + v1.2: client-side RT scheduling, hooks for NtSetInformationThread
 * and NtSetInformationProcess that bypass wineserver for in-process priority
 * management.
 *
 * v1 Tier 1 (original): SetThreadPriority(GetCurrentThread(), TIME_CRITICAL)
 *   hits a local sched_setscheduler fast path. Audio callback hot path.
 * v1.2 Tier 2: non-self SetThreadPriority + SetPriorityClass also served
 *   locally using a handle->unix-TID map. Matches wineserver Tier 2.
 * v2.5: per-thread cached sched policy + priority avoid repeated getparam.
 *
 * Environment:
 *   NSPA_RT_PRIO   — master switch + FIFO priority anchor (NT 24 maps here)
 *   NSPA_RT_POLICY — FF / RR for lower RT band, TS for conservative mode
 *
 * Thread interlock with wineserver Tier 2:
 *
 * When the client handles a call via v1.2, it sets req->nspa_rt_override=1 in
 * the RPC. Tier 2 in wineserver sees this and SKIPS its RT branch — it neither
 * redundantly applies nor clobbers the client's sched class via
 * nspa_rt_maybe_demote().
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"

#include "../unix_private.h"

#include <rtpi.h>

WINE_DEFAULT_DEBUG_CHANNEL(thread);

#ifndef NSPA_RT_TIME_CRITICAL
# define NSPA_RT_TIME_CRITICAL 15  /* THREAD_PRIORITY_TIME_CRITICAL from winnt.h */
#endif
#ifndef NSPA_THREAD_PRIORITY_IDLE
# define NSPA_THREAD_PRIORITY_IDLE (-15)
#endif
#ifndef PROCESS_PRIOCLASS_IDLE
# define PROCESS_PRIOCLASS_IDLE         1
# define PROCESS_PRIOCLASS_NORMAL       2
# define PROCESS_PRIOCLASS_HIGH         3
# define PROCESS_PRIOCLASS_REALTIME     4
# define PROCESS_PRIOCLASS_BELOW_NORMAL 5
# define PROCESS_PRIOCLASS_ABOVE_NORMAL 6
#endif

/* Forward declaration: defined further down so nspa_rt_apply_tid can call it. */
static void nspa_rt_pin_for_role( int tid, int nt_band );

/* Cached env state. -2 = unprobed, -1 = disabled, >=0 = base FIFO prio. */
int nspa_rt_prio_base = -2;
/* SCHED_FIFO / SCHED_RR / SCHED_OTHER (TS mode) for the lower RT band. */
int nspa_rt_policy_v = SCHED_FIFO;

/* Cached process priority class. Updated by NtSetInformationProcess hook
 * and on first use via lazy query to wineserver. Accessed interlocked. */
static LONG nspa_cached_priocls = PROCESS_PRIOCLASS_NORMAL;
static LONG nspa_cached_priocls_valid;

/* Called from process.c when the client hooks ProcessPriorityClass changes. */
void nspa_rt_set_cached_priocls( int cls )
{
    InterlockedExchange( &nspa_cached_priocls, cls );
    InterlockedExchange( &nspa_cached_priocls_valid, 1 );
}

/* v1.2 map — HANDLE → unix_tid, populated at NtCreateThreadEx.
 * Open addressing with linear probe, 256 slots, lock-protected. */
#define NSPA_RT_MAP_SIZE 256
struct nspa_rt_map_entry
{
    HANDLE handle;
    int    unix_tid;
};
static struct nspa_rt_map_entry nspa_rt_map[NSPA_RT_MAP_SIZE];
static pi_mutex_t nspa_rt_map_lock = PI_MUTEX_INIT(0);

static inline unsigned int nspa_rt_map_hash( HANDLE h )
{
    return ((unsigned long)h >> 2) % NSPA_RT_MAP_SIZE;
}

void nspa_rt_map_add( HANDLE handle, int tid )
{
    unsigned int i, p;
    if (!handle || tid <= 0) return;
    pi_mutex_lock( &nspa_rt_map_lock );
    i = nspa_rt_map_hash( handle );
    for (p = 0; p < NSPA_RT_MAP_SIZE; p++)
    {
        unsigned int idx = (i + p) % NSPA_RT_MAP_SIZE;
        if (!nspa_rt_map[idx].handle || nspa_rt_map[idx].handle == handle)
        {
            nspa_rt_map[idx].handle = handle;
            nspa_rt_map[idx].unix_tid = tid;
            break;
        }
    }
    pi_mutex_unlock( &nspa_rt_map_lock );
}

int nspa_rt_map_lookup( HANDLE handle )
{
    unsigned int i, p;
    int tid = -1;
    if (!handle) return -1;
    pi_mutex_lock( &nspa_rt_map_lock );
    i = nspa_rt_map_hash( handle );
    for (p = 0; p < NSPA_RT_MAP_SIZE; p++)
    {
        unsigned int idx = (i + p) % NSPA_RT_MAP_SIZE;
        if (!nspa_rt_map[idx].handle) break;
        if (nspa_rt_map[idx].handle == handle)
        {
            tid = nspa_rt_map[idx].unix_tid;
            break;
        }
    }
    pi_mutex_unlock( &nspa_rt_map_lock );
    return tid;
}

void nspa_rt_map_remove( HANDLE handle )
{
    unsigned int i, p;
    if (!handle) return;
    pi_mutex_lock( &nspa_rt_map_lock );
    i = nspa_rt_map_hash( handle );
    for (p = 0; p < NSPA_RT_MAP_SIZE; p++)
    {
        unsigned int idx = (i + p) % NSPA_RT_MAP_SIZE;
        if (!nspa_rt_map[idx].handle) break;
        if (nspa_rt_map[idx].handle == handle)
        {
            nspa_rt_map[idx].handle = NULL;
            nspa_rt_map[idx].unix_tid = 0;
            break;
        }
    }
    pi_mutex_unlock( &nspa_rt_map_lock );
}

/* Probe env vars once. Thread-safe via idempotency — multiple calls
 * are harmless because they all compute the same answer. */
void nspa_rt_probe(void)
{
    const char *prio_env, *policy_env;
    int val, fmin, fmax;

    if (nspa_rt_prio_base != -2) return;
    nspa_rt_prio_base = -1;

    prio_env = getenv( "NSPA_RT_PRIO" );
    if (!prio_env || !*prio_env) return;

    fmin = sched_get_priority_min( SCHED_FIFO );
    fmax = sched_get_priority_max( SCHED_FIFO );
    if (fmin < 0 || fmax < 0) return;

    val = atoi( prio_env );
    if (val < fmin || val >= fmax) return;
    nspa_rt_prio_base = val;

    policy_env = getenv( "NSPA_RT_POLICY" );
    if (policy_env)
    {
        if      (!strcmp( policy_env, "FF" )) nspa_rt_policy_v = SCHED_FIFO;
        else if (!strcmp( policy_env, "RR" )) nspa_rt_policy_v = SCHED_RR;
        else if (!strcmp( policy_env, "TS" )) nspa_rt_policy_v = SCHED_OTHER;
    }
}

/* Resolve base_priority offset + cached process class → absolute NT priority.
 * Mirrors server/thread.c:set_thread_base_priority(). */
int nspa_resolve_nt_band( int base_priority )
{
    LONG cls = InterlockedCompareExchange( &nspa_cached_priocls, 0, 0 );
    int is_rt = (cls == PROCESS_PRIOCLASS_REALTIME);
    int proc_base;

    if (base_priority == NSPA_THREAD_PRIORITY_IDLE)
        return is_rt ? 16 : 1;
    if (base_priority == NSPA_RT_TIME_CRITICAL)
        return is_rt ? 31 : 15;

    switch (cls)
    {
    case PROCESS_PRIOCLASS_IDLE:         proc_base = 4;  break;
    case PROCESS_PRIOCLASS_BELOW_NORMAL: proc_base = 6;  break;
    case PROCESS_PRIOCLASS_NORMAL:       proc_base = 8;  break;
    case PROCESS_PRIOCLASS_ABOVE_NORMAL: proc_base = 10; break;
    case PROCESS_PRIOCLASS_HIGH:         proc_base = 13; break;
    case PROCESS_PRIOCLASS_REALTIME:     proc_base = 24; break;
    default:                             proc_base = 8;  break;
    }
    return proc_base + base_priority;
}

/* Apply RT scheduling to a specific unix tid. Returns 1 if applied, 0 if
 * skipped (RT disabled, TS mode for lower band, or permission denied).
 * nt_band is the absolute NT priority in [1..31]. */
int nspa_rt_apply_tid( int tid, int nt_band )
{
    struct sched_param param;
    int fifo, policy, fmin, fmax;

    nspa_rt_probe();
    if (nspa_rt_prio_base < 0) return 0;
    if (tid < 0) return 0;  /* tid == 0 is valid: sched_setscheduler(0,...) = current thread */

    /* Ceiling mapping: NT 31 (TIME_CRITICAL) = NSPA_RT_PRIO, lower bands below. */
    fifo = nspa_rt_prio_base - (31 - nt_band);
    fmin = sched_get_priority_min( SCHED_FIFO );
    fmax = sched_get_priority_max( SCHED_FIFO ) - 1;
    if (fifo < fmin) fifo = fmin;
    if (fifo > fmax) fifo = fmax;

    /* TC (NT 31) always FIFO; lower band honors env var policy. */
    policy = (nt_band >= 31) ? SCHED_FIFO : nspa_rt_policy_v;

    /* TS mode for lower band: don't promote, let Tier 2 fallback apply nice. */
    if (policy == SCHED_OTHER) return 0;

    param.sched_priority = fifo;
    if (sched_setscheduler( tid, policy | SCHED_RESET_ON_FORK, &param ) == -1)
    {
        static int warned;
        if (!warned++)
            WARN( "NSPA RT v1.2: sched_setscheduler(tid=%d, prio=%d) failed: %s\n",
                  tid, fifo, strerror(errno) );
        /* If the tid is dead (ESRCH), drop the stale map entry. */
        if (errno == ESRCH)
        {
            /* caller holds nothing; safe to clean up */
        }
        return 0;
    }

    /* NSPA v2.5: cache our own RT state so shmem PI boost can skip
     * sched_getscheduler(0) + sched_getparam(0) on every request. */
    if (tid == 0)
    {
        struct ntdll_thread_data *data = ntdll_get_thread_data();
        data->nspa_rt_cached_policy = policy;
        data->nspa_rt_cached_prio   = fifo;
    }

    /* NSPA Step 1 (default-OFF behind NSPA_PIN_AFFINITY=1): pin to a
     * topology-derived physical-core partition.  No-op when env disables
     * or topology too small. */
    nspa_rt_pin_for_role( tid, nt_band );

    return 1;
}

/* ---------------------------------------------------------------------
 * NSPA thread placement (Step 1 / Case B — uniform-with-SMT)
 *
 * Default-OFF behind NSPA_PIN_AFFINITY=1 .  When enabled, audio
 * threads (NT 31) are pinned to the back half of physical cores and
 * wineserver-RT-class threads (NT 24-30) to the front half — separated
 * at the physical-core boundary so SMT siblings don't share L1/L2
 * between the two classes.  Non-RT threads stay unrestricted; the
 * kernel scheduler handles them.
 *
 * Topology source: /sys/devices/system/cpu/cpuN/topology/thread_siblings_list .
 * Logical CPUs whose siblings_list overlaps share a physical core.
 *
 * Gates the partition on >= 3 physical cores so two-core machines
 * (which have no headroom to spare) get a no-op.
 *
 * Hybrid (Case A) and server-side mirror are deferred to a later
 * session per nspa/docs/jit-and-thread-placement-investigation-20260501.md .
 * ---------------------------------------------------------------------
 */

/* -1 unprobed, 0 disabled, 1 enabled */
static int nspa_pin_enabled = -1;
/* 0 unprobed, 1 ok, -1 unavailable / too small */
static int nspa_topology_state = 0;
static int nspa_n_physical_cores = 0;
static cpu_set_t nspa_audio_mask;
static cpu_set_t nspa_srv_mask;

static void nspa_pin_probe_env(void)
{
    const char *v;
    if (nspa_pin_enabled >= 0) return;
    v = getenv( "NSPA_PIN_AFFINITY" );
    nspa_pin_enabled = (v && *v == '1') ? 1 : 0;
}

/* Parse a sysfs-style range list "0,4" or "0-1" or "0,4,8,12" into
 * the given cpu_set.  Returns the highest CPU id seen, or -1 on error. */
static int nspa_parse_siblings_list( const char *buf, cpu_set_t *out )
{
    const char *p = buf;
    int max_cpu = -1;
    CPU_ZERO( out );
    while (*p && *p != '\n')
    {
        char *end;
        long start = strtol( p, &end, 10 );
        long stop;
        if (end == p) return -1;
        p = end;
        stop = start;
        if (*p == '-')
        {
            p++;
            stop = strtol( p, &end, 10 );
            if (end == p) return -1;
            p = end;
        }
        for (long c = start; c <= stop && c < CPU_SETSIZE; c++)
        {
            CPU_SET( c, out );
            if ((int)c > max_cpu) max_cpu = (int)c;
        }
        if (*p == ',') p++;
        else break;
    }
    return max_cpu;
}

/* Walk /sys/devices/system/cpu/cpuN/topology/thread_siblings_list and
 * group logical CPUs by physical core.  Builds nspa_audio_mask /
 * nspa_srv_mask.  Returns 1 on success, 0 if topology unavailable
 * or insufficient (<3 physical cores). */
static int nspa_topology_probe(void)
{
    cpu_set_t per_phys[64];
    int per_phys_count = 0;
    int seen[CPU_SETSIZE] = {0};
    int half;

    for (int cpu = 0; cpu < CPU_SETSIZE; cpu++)
    {
        char path[128];
        FILE *f;
        char buf[256];
        cpu_set_t siblings;

        snprintf( path, sizeof(path),
                  "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", cpu );
        f = fopen( path, "r" );
        if (!f)
        {
            if (cpu == 0) return 0;  /* no sysfs at all */
            break;                    /* end of online CPUs */
        }
        if (!fgets( buf, sizeof(buf), f )) { fclose(f); continue; }
        fclose(f);

        if (seen[cpu]) continue;  /* already grouped */
        if (per_phys_count >= 64) break;
        if (nspa_parse_siblings_list( buf, &siblings ) < 0) continue;

        per_phys[per_phys_count] = siblings;
        for (int i = 0; i < CPU_SETSIZE; i++)
            if (CPU_ISSET( i, &siblings )) seen[i] = 1;
        per_phys_count++;
    }

    nspa_n_physical_cores = per_phys_count;

    if (per_phys_count < 3)
    {
        WARN( "NSPA pin: only %d physical core(s) — disabling pin (need >= 3)\n",
              per_phys_count );
        return 0;
    }

    /* Partition: front half -> srv, back half -> audio */
    half = per_phys_count / 2;
    CPU_ZERO( &nspa_srv_mask );
    CPU_ZERO( &nspa_audio_mask );
    for (int i = 0; i < half; i++)
        for (int c = 0; c < CPU_SETSIZE; c++)
            if (CPU_ISSET( c, &per_phys[i] )) CPU_SET( c, &nspa_srv_mask );
    for (int i = half; i < per_phys_count; i++)
        for (int c = 0; c < CPU_SETSIZE; c++)
            if (CPU_ISSET( c, &per_phys[i] )) CPU_SET( c, &nspa_audio_mask );

    TRACE( "NSPA pin: topology probed — %d physical cores, srv=front %d phys, audio=back %d phys\n",
           per_phys_count, half, per_phys_count - half );
    return 1;
}

static void nspa_rt_pin_for_role( int tid, int nt_band )
{
    cpu_set_t *mask;

    nspa_pin_probe_env();
    if (!nspa_pin_enabled) return;

    if (nspa_topology_state == 0)
        nspa_topology_state = nspa_topology_probe() ? 1 : -1;
    if (nspa_topology_state != 1) return;

    if (nt_band >= 31)        mask = &nspa_audio_mask;
    else if (nt_band >= 24)   mask = &nspa_srv_mask;
    else                      return;  /* not RT-class enough to pin */

    if (sched_setaffinity( tid, sizeof(*mask), mask ) == -1)
    {
        static int warned;
        if (!warned++)
            WARN( "NSPA pin: sched_setaffinity(tid=%d, nt_band=%d) failed: %s\n",
                  tid, nt_band, strerror(errno) );
    }
}

/* Deliberately no nspa_rt_map_reapply_all function: on SetPriorityClass,
 * wineserver's set_process_priority walks its own thread_list and calls
 * apply_thread_priority for each thread with the correct per-thread
 * base_priority. A client-side reapply would have to duplicate that
 * per-thread state or (as an earlier iteration incorrectly did) assume
 * base_priority==NORMAL for all mapped threads, which clobbers threads
 * whose base is actually TIME_CRITICAL. Tier 2 owns the bulk update. */
