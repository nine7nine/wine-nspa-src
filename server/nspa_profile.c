/*
 * NSPA wineserver per-request-type + per-thread profiling.
 *
 * Runtime-gated via NSPA_PROFILE=1 env var.
 *   SIGUSR1 -> dump global top-20 + per-thread breakdown
 *   SIGUSR2 -> reset all counters
 *
 * Counters use relaxed atomics; safe under multi-dispatcher concurrency.
 * Per-thread tracking uses a fixed-size open-addressed table (CAS-claimed slots).
 */

#include "config.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "request.h"

#define NSPA_PROFILE_MAX_THREADS 128

extern const char *get_request_name( unsigned int req ); /* from trace.c */

static int profile_enabled;

/* global per-request-type counters */
static uint64_t req_count[REQ_NB_REQUESTS];
static uint64_t req_time_ns[REQ_NB_REQUESTS];

/* per-thread tracking */
static unsigned int thread_keys[NSPA_PROFILE_MAX_THREADS];  /* 0 = free slot */
static int          thread_unix_tid[NSPA_PROFILE_MAX_THREADS];
static uint64_t thread_total_count[NSPA_PROFILE_MAX_THREADS];
static uint64_t thread_total_time_ns[NSPA_PROFILE_MAX_THREADS];
static uint64_t thread_req_count[NSPA_PROFILE_MAX_THREADS][REQ_NB_REQUESTS];
static uint64_t thread_req_time_ns[NSPA_PROFILE_MAX_THREADS][REQ_NB_REQUESTS];

static void read_comm( int unix_tid, char *buf, size_t bufsz )
{
    char path[64];
    int fd;
    ssize_t n;

    buf[0] = '\0';
    if (unix_tid <= 0) { snprintf( buf, bufsz, "?" ); return; }
    snprintf( path, sizeof(path), "/proc/%d/comm", unix_tid );
    if ((fd = open( path, O_RDONLY )) < 0) { snprintf( buf, bufsz, "(gone)" ); return; }
    n = read( fd, buf, bufsz - 1 );
    close( fd );
    if (n <= 0) { snprintf( buf, bufsz, "?" ); return; }
    buf[n] = '\0';
    if (n > 0 && buf[n-1] == '\n') buf[n-1] = '\0';
}

void nspa_profile_init(void)
{
    profile_enabled = (getenv( "NSPA_PROFILE" ) != NULL);
    if (profile_enabled)
        fprintf( stderr, "nspa_profile: active (SIGUSR1=dump, SIGUSR2=reset, max=%d threads)\n",
                 NSPA_PROFILE_MAX_THREADS );
}

int nspa_profile_active(void)
{
    return profile_enabled;
}

unsigned long long nspa_profile_start(void)
{
    struct timespec ts;
    if (!profile_enabled) return 0;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

/* Claim-or-find a per-thread slot. Returns -1 if table is full. */
static int thread_slot_lookup( unsigned int tid )
{
    int i;
    for (i = 0; i < NSPA_PROFILE_MAX_THREADS; i++)
    {
        unsigned int cur = __atomic_load_n( &thread_keys[i], __ATOMIC_RELAXED );
        if (cur == tid) return i;
        if (cur == 0)
        {
            unsigned int expected = 0;
            if (__atomic_compare_exchange_n( &thread_keys[i], &expected, tid, 0,
                                             __ATOMIC_RELAXED, __ATOMIC_RELAXED ))
                return i;
            /* someone else claimed this slot; re-check if it's us */
            if (__atomic_load_n( &thread_keys[i], __ATOMIC_RELAXED ) == tid)
                return i;
        }
    }
    return -1;
}

void nspa_profile_end( unsigned int req, unsigned long long start_ns,
                       unsigned int thread_id, int unix_tid )
{
    struct timespec ts;
    uint64_t end_ns, delta;
    int slot;
    if (!profile_enabled || req >= REQ_NB_REQUESTS) return;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    end_ns = (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
    delta = end_ns - start_ns;

    __atomic_fetch_add( &req_count[req], 1, __ATOMIC_RELAXED );
    __atomic_fetch_add( &req_time_ns[req], delta, __ATOMIC_RELAXED );

    if (thread_id && (slot = thread_slot_lookup( thread_id )) >= 0)
    {
        /* publish unix_tid once (safe to re-store if already set) */
        if (unix_tid > 0 && __atomic_load_n( &thread_unix_tid[slot], __ATOMIC_RELAXED ) != unix_tid)
            __atomic_store_n( &thread_unix_tid[slot], unix_tid, __ATOMIC_RELAXED );
        __atomic_fetch_add( &thread_req_count[slot][req], 1, __ATOMIC_RELAXED );
        __atomic_fetch_add( &thread_req_time_ns[slot][req], delta, __ATOMIC_RELAXED );
        __atomic_fetch_add( &thread_total_count[slot], 1, __ATOMIC_RELAXED );
        __atomic_fetch_add( &thread_total_time_ns[slot], delta, __ATOMIC_RELAXED );
    }
}

struct nspa_row
{
    unsigned int req;
    uint64_t count;
    uint64_t time_ns;
};

struct nspa_trow
{
    unsigned int tid;
    int slot;
    uint64_t count;
    uint64_t time_ns;
};

static int cmp_count_desc( const void *a, const void *b )
{
    const struct nspa_row *x = a, *y = b;
    if (x->count > y->count) return -1;
    if (x->count < y->count) return 1;
    return 0;
}

static int cmp_time_desc( const void *a, const void *b )
{
    const struct nspa_row *x = a, *y = b;
    if (x->time_ns > y->time_ns) return -1;
    if (x->time_ns < y->time_ns) return 1;
    return 0;
}

static int cmp_tcount_desc( const void *a, const void *b )
{
    const struct nspa_trow *x = a, *y = b;
    if (x->count > y->count) return -1;
    if (x->count < y->count) return 1;
    return 0;
}

static void dump_global_top( struct nspa_row *rows )
{
    unsigned int i;

    qsort( rows, REQ_NB_REQUESTS, sizeof(rows[0]), cmp_count_desc );
    fprintf( stderr, "\n-- global top 20 by count --\n" );
    fprintf( stderr, "%-32s %12s %12s %10s\n", "request", "count", "total_us", "avg_us" );
    for (i = 0; i < 20 && i < REQ_NB_REQUESTS; i++)
    {
        double total_us, avg_us;
        if (!rows[i].count) break;
        total_us = rows[i].time_ns / 1000.0;
        avg_us   = total_us / rows[i].count;
        fprintf( stderr, "%-32s %12llu %12.1f %10.2f\n",
                 get_request_name( rows[i].req ),
                 (unsigned long long)rows[i].count, total_us, avg_us );
    }

    qsort( rows, REQ_NB_REQUESTS, sizeof(rows[0]), cmp_time_desc );
    fprintf( stderr, "\n-- global top 20 by total handler time --\n" );
    fprintf( stderr, "%-32s %12s %12s %10s\n", "request", "total_us", "count", "avg_us" );
    for (i = 0; i < 20 && i < REQ_NB_REQUESTS; i++)
    {
        double total_us, avg_us;
        if (!rows[i].time_ns) break;
        total_us = rows[i].time_ns / 1000.0;
        avg_us   = rows[i].count ? total_us / rows[i].count : 0.0;
        fprintf( stderr, "%-32s %12.1f %12llu %10.2f\n",
                 get_request_name( rows[i].req ),
                 total_us, (unsigned long long)rows[i].count, avg_us );
    }
}

static void dump_per_thread( void )
{
    struct nspa_trow trows[NSPA_PROFILE_MAX_THREADS];
    struct nspa_row reqrows[REQ_NB_REQUESTS];
    int ntracked = 0;
    int i, j, k;
    char comm[32];

    for (i = 0; i < NSPA_PROFILE_MAX_THREADS; i++)
    {
        unsigned int tid = __atomic_load_n( &thread_keys[i], __ATOMIC_RELAXED );
        uint64_t c = __atomic_load_n( &thread_total_count[i], __ATOMIC_RELAXED );
        if (!tid || !c) continue;
        trows[ntracked].tid     = tid;
        trows[ntracked].slot    = i;
        trows[ntracked].count   = c;
        trows[ntracked].time_ns = __atomic_load_n( &thread_total_time_ns[i], __ATOMIC_RELAXED );
        ntracked++;
    }

    qsort( trows, ntracked, sizeof(trows[0]), cmp_tcount_desc );

    /* Summary: all tracked threads (not just top N) with comm name */
    fprintf( stderr, "\n-- per-thread summary (%d threads tracked) --\n", ntracked );
    fprintf( stderr, "%-6s %-7s %-18s %12s %12s %10s\n",
             "wsid", "unix", "comm", "count", "total_us", "avg_us" );
    for (j = 0; j < ntracked; j++)
    {
        int tid_slot = trows[j].slot;
        int unix_tid = __atomic_load_n( &thread_unix_tid[tid_slot], __ATOMIC_RELAXED );
        double total_us = trows[j].time_ns / 1000.0;
        double avg_us   = total_us / trows[j].count;
        read_comm( unix_tid, comm, sizeof(comm) );
        fprintf( stderr, "%04x   %-7d %-18.18s %12llu %12.1f %10.2f\n",
                 trows[j].tid, unix_tid, comm,
                 (unsigned long long)trows[j].count,
                 total_us, avg_us );
    }

    /* Detail: top 5 request types for every tracked thread with >= 50 calls */
    for (j = 0; j < ntracked; j++)
    {
        int slot = trows[j].slot;
        int unix_tid = __atomic_load_n( &thread_unix_tid[slot], __ATOMIC_RELAXED );
        int printed;
        if (trows[j].count < 50) continue;  /* skip low-volume threads in detail */
        for (i = 0; i < REQ_NB_REQUESTS; i++)
        {
            reqrows[i].req     = i;
            reqrows[i].count   = __atomic_load_n( &thread_req_count[slot][i], __ATOMIC_RELAXED );
            reqrows[i].time_ns = __atomic_load_n( &thread_req_time_ns[slot][i], __ATOMIC_RELAXED );
        }
        qsort( reqrows, REQ_NB_REQUESTS, sizeof(reqrows[0]), cmp_count_desc );
        read_comm( unix_tid, comm, sizeof(comm) );
        fprintf( stderr, "\n-- thread %04x [unix=%d %s] top request types --\n",
                 trows[j].tid, unix_tid, comm );
        fprintf( stderr, "  %-30s %10s %12s %10s\n", "request", "count", "total_us", "avg_us" );
        printed = 0;
        for (k = 0; k < REQ_NB_REQUESTS && printed < 5; k++)
        {
            double tu, au;
            if (!reqrows[k].count) break;
            tu = reqrows[k].time_ns / 1000.0;
            au = tu / reqrows[k].count;
            fprintf( stderr, "  %-30s %10llu %12.1f %10.2f\n",
                     get_request_name( reqrows[k].req ),
                     (unsigned long long)reqrows[k].count, tu, au );
            printed++;
        }
    }
}

void nspa_profile_dump(void)
{
    struct nspa_row rows[REQ_NB_REQUESTS];
    uint64_t total_count = 0, total_time_ns = 0;
    unsigned int i, nonzero = 0;

    if (!profile_enabled)
    {
        fprintf( stderr, "nspa_profile: not active (set NSPA_PROFILE=1 to enable)\n" );
        return;
    }

    for (i = 0; i < REQ_NB_REQUESTS; i++)
    {
        rows[i].req     = i;
        rows[i].count   = __atomic_load_n( &req_count[i],   __ATOMIC_RELAXED );
        rows[i].time_ns = __atomic_load_n( &req_time_ns[i], __ATOMIC_RELAXED );
        total_count   += rows[i].count;
        total_time_ns += rows[i].time_ns;
        if (rows[i].count) nonzero++;
    }

    fprintf( stderr,
             "\n=== NSPA profile: %llu requests across %u types, %.3f ms total handler time ===\n",
             (unsigned long long)total_count, nonzero, total_time_ns / 1000000.0 );

    dump_global_top( rows );
    dump_per_thread();
    fprintf( stderr, "\n" );
}

void nspa_profile_reset(void)
{
    unsigned int i, j;
    if (!profile_enabled) return;
    for (i = 0; i < REQ_NB_REQUESTS; i++)
    {
        __atomic_store_n( &req_count[i],   0, __ATOMIC_RELAXED );
        __atomic_store_n( &req_time_ns[i], 0, __ATOMIC_RELAXED );
    }
    for (i = 0; i < NSPA_PROFILE_MAX_THREADS; i++)
    {
        /* Keep thread_keys (so slots stay assigned); zero counters only */
        __atomic_store_n( &thread_total_count[i],   0, __ATOMIC_RELAXED );
        __atomic_store_n( &thread_total_time_ns[i], 0, __ATOMIC_RELAXED );
        for (j = 0; j < REQ_NB_REQUESTS; j++)
        {
            __atomic_store_n( &thread_req_count[i][j],   0, __ATOMIC_RELAXED );
            __atomic_store_n( &thread_req_time_ns[i][j], 0, __ATOMIC_RELAXED );
        }
    }
    fprintf( stderr, "nspa_profile: counters reset\n" );
}
