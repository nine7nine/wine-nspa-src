/*
 * NSPA Phase 2 — opportunistic transparent hugetlb opt-in (impl).
 *
 * See nspa/docs/working-set-and-hugetlb-design-20260505.md and
 * huge_auto.h for the full design + correctness audits.
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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "windef.h"
#include "winnt.h"
#include "wine/debug.h"

#include "huge_auto.h"

WINE_DEFAULT_DEBUG_CHANNEL(virtual);

static BOOL huge_auto_active;
static int huge_auto_init_done;

/* NSPA: hugetlb pool watermark cache.  Cap how aggressively auto-promote
 * drains the kernel's reserved 2 MiB pool by refusing eligibility once
 * the free count drops below a threshold.  The graceful fallback in
 * map_view_large_pages still catches actual exhaust; the watermark is
 * the soft brake that reduces failed-mmap dance frequency.
 *
 * Cache TTL keeps the /sys read off the hot path: at most one syscall
 * per 100ms regardless of allocation rate.
 *
 * Threshold = 10% of total pool.  For a typical NSPA-RT 550-page pool
 * (1.1 GiB), ~110 MiB is held in reserve before auto-promote refuses.
 * The reserve is what apps that explicitly call VirtualAlloc(MEM_LARGE_PAGES)
 * or NSPA's existing in-flight allocations need to make forward progress
 * even under memory pressure. */
#define HUGE_POOL_CACHE_TTL_NS  (100LL * 1000000LL)
#define HUGE_POOL_LOW_PCT       10

static SIZE_T  huge_pool_total;            /* nr_hugepages, read once at init */
static LONG    huge_pool_low_cached;       /* atomic: 1 = low, 0 = ok */
static LONG64  huge_pool_check_ns;         /* atomic: mono_ns of last refresh */

static LONGLONG mono_ns(void)
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    return (LONGLONG)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* Read a single integer from a /sys file.  Returns -1 on any failure
 * so callers can distinguish "kernel doesn't expose this" from "0
 * pages free." */
static int read_sys_int( const char *path )
{
    char buf[32];
    int fd, ret;
    ssize_t n;

    if ((fd = open( path, O_RDONLY | O_CLOEXEC )) < 0) return -1;
    n = read( fd, buf, sizeof(buf) - 1 );
    close( fd );
    if (n <= 0) return -1;
    buf[n] = 0;
    ret = atoi( buf );
    return ret;
}

/* TTL-cached pool low-water check.  Hot path: 2 atomic reads + comparison
 * (single-digit nanoseconds).  Cold path (every 100ms): open + read +
 * close + atoi (~10 µs total).  No allocation, no lock; safe to call
 * from any context including RT threads. */
static BOOL huge_pool_low( void )
{
    LONGLONG now = mono_ns();
    LONGLONG last = __atomic_load_n( &huge_pool_check_ns, __ATOMIC_RELAXED );
    int free_pages;
    BOOL low;

    if (now - last < HUGE_POOL_CACHE_TTL_NS)
        return __atomic_load_n( &huge_pool_low_cached, __ATOMIC_RELAXED ) != 0;

    /* Re-read nr_hugepages when total is 0: covers the case where the
     * kernel pool was sysctl'd up after Wine started (e.g. boot-order
     * race between systemd-sysctl and a daemon that pre-launches Wine).
     * Without this, total==0 latches forever and auto-promote stays
     * permanently disabled even after the pool comes online. */
    if (huge_pool_total == 0)
    {
        int total = read_sys_int( "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages" );
        if (total > 0) huge_pool_total = (SIZE_T)total;
    }

    /* Still no pool: treat as low so eligibility refuses immediately
     * instead of letting every alloc try mmap then fall back. */
    if (huge_pool_total == 0)
    {
        __atomic_store_n( &huge_pool_low_cached, 1, __ATOMIC_RELAXED );
        __atomic_store_n( &huge_pool_check_ns, now, __ATOMIC_RELAXED );
        return TRUE;
    }

    free_pages = read_sys_int( "/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages" );
    /* Read failure: treat as not-low so we don't disable auto-promote
     * just because /sys is unavailable.  The fallback covers actual
     * exhaust. */
    if (free_pages < 0) free_pages = (int)huge_pool_total;

    low = ((SIZE_T)free_pages < huge_pool_total * HUGE_POOL_LOW_PCT / 100);
    __atomic_store_n( &huge_pool_low_cached, low ? 1 : 0, __ATOMIC_RELAXED );
    __atomic_store_n( &huge_pool_check_ns, now, __ATOMIC_RELAXED );
    return low;
}

static void huge_auto_init( void )
{
    int total;

    /* Order matters under concurrent first-callers: state must be visible
     * before init_done is observable, otherwise a thread that sees
     * init_done==1 may read huge_auto_active==FALSE and miss the first
     * eligibility check.  Use release/acquire to enforce the ordering. */
    if (__atomic_load_n( &huge_auto_init_done, __ATOMIC_ACQUIRE )) return;

    /* Single gate: NSPA_RT_PRIO presence.  RT processes get RT defaults. */
    if (getenv( "NSPA_RT_PRIO" ))
    {
        huge_auto_active = TRUE;
        TRACE( "huge auto-promote active (NSPA_RT_PRIO set)\n" );
    }

    /* Cache total.  Zero-config or read failure leaves total==0; the
     * cold-path check in huge_pool_low() will retry the read in case
     * the pool comes online later. */
    total = read_sys_int( "/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages" );
    huge_pool_total = (total > 0) ? (SIZE_T)total : 0;

    __atomic_store_n( &huge_auto_init_done, 1, __ATOMIC_RELEASE );
}

BOOL nspa_huge_auto_eligible( ULONG type, ULONG protect,
                               void *base, SIZE_T size,
                               ULONG attributes, SIZE_T lp_unit )
{
    huge_auto_init();
    if (!huge_auto_active) return FALSE;
    if (lp_unit == 0) return FALSE;

    /* All conditions must hold (see huge_auto.h for rationale): */
    if (size < lp_unit) return FALSE;
    if ((size % lp_unit) != 0) return FALSE;
    if (attributes & MEM_EXTENDED_PARAMETER_NONPAGED_HUGE) return FALSE;
    if (!(type & MEM_RESERVE) || !(type & MEM_COMMIT)) return FALSE;
    if (type & ~(MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN)) return FALSE;
    if (base) return FALSE;
    if (protect != PAGE_READWRITE) return FALSE;

    /* Pool watermark check last: cheaper predicates short-circuit first.
     * When the kernel's 2 MiB free count is below 10% of total, refuse
     * auto-promote so the reserve stays available for explicit
     * MEM_LARGE_PAGES requests and in-flight allocs.  Caller falls
     * through to the regular-page allocation path with no behavior
     * change visible to the app. */
    if (huge_pool_low()) return FALSE;

    return TRUE;
}

int nspa_huge_auto_demote( void *base, SIZE_T size )
{
    void *scratch, *replaced;

    scratch = mmap( NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, -1, 0 );
    if (scratch == MAP_FAILED) return errno;

    memcpy( scratch, base, size );

    /* MAP_FIXED over the hugetlb VMA at view granularity: kernel
     * replaces the whole-hugepage(s) range with regular anon pages.
     * Linux requires the range to be a multiple of the underlying
     * hugepage size; map_view_large_pages already enforces that the
     * view is a 2 MiB-aligned multiple, so this always succeeds. */
    replaced = mmap( base, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0 );
    if (replaced == MAP_FAILED)
    {
        int saved = errno;
        munmap( scratch, size );
        return saved;
    }

    memcpy( base, scratch, size );
    munmap( scratch, size );
    return 0;
}
