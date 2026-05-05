/*
 * NSPA working-set page locking — implementation.
 *
 * Phase 1 of the working-set + hugetlb integration plan
 * (wine/nspa/docs/working-set-and-hugetlb-design-20260505.md).
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
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "windef.h"
#include "wine/debug.h"

#include "mlock_ws.h"

WINE_DEFAULT_DEBUG_CHANNEL(virtual);

/* Linux 4.4+ added MCL_ONFAULT — defers locking until pages are first
 * faulted in.  Without it, MCL_FUTURE force-commits every PROT_NONE
 * reservation Wine has made, ballooning RSS.  Provide a fallback
 * definition so this builds on older glibc headers; runtime detection
 * (EINVAL retry) handles older kernels. */
#ifndef MCL_ONFAULT
# define MCL_ONFAULT 4
#endif

static int mlock_ws_init_done;

static BOOL mlock_ws_should_enable( void )
{
    const char *gate = getenv( "NSPA_MLOCK_WORKINGSET" );

    if (gate)
    {
        if (gate[0] == '1' || gate[0] == 'y' || gate[0] == 'Y')
            return TRUE;
        if (gate[0] == '0' || gate[0] == 'n' || gate[0] == 'N')
            return FALSE;
        /* Anything else: fall through to NSPA_RT_PRIO heuristic. */
    }

    /* Default: auto-enable for RT processes.  NSPA_RT_PRIO is the
     * canonical NSPA "this is a real-time workload" signal. */
    return getenv( "NSPA_RT_PRIO" ) != NULL;
}

static void mlock_ws_raise_rlimit( void )
{
    struct rlimit rl;

    rl.rlim_cur = RLIM_INFINITY;
    rl.rlim_max = RLIM_INFINITY;
    if (setrlimit( RLIMIT_MEMLOCK, &rl ) == 0) return;

    /* EPERM: process lacks CAP_SYS_RESOURCE and a hard cap is in place.
     * Raise the soft limit to the hard cap as a best-effort. */
    if (errno == EPERM && getrlimit( RLIMIT_MEMLOCK, &rl ) == 0)
    {
        rl.rlim_cur = rl.rlim_max;
        if (setrlimit( RLIMIT_MEMLOCK, &rl ) == 0)
        {
            TRACE( "raised RLIMIT_MEMLOCK soft to hard cap %llu\n",
                   (unsigned long long)rl.rlim_max );
            return;
        }
    }

    WARN( "setrlimit RLIMIT_MEMLOCK failed: %s — mlockall may hit a low limit\n",
          strerror( errno ) );
}

void nspa_mlock_ws_init( void )
{
    int flags;

    if (mlock_ws_init_done) return;
    mlock_ws_init_done = 1;

    if (!mlock_ws_should_enable())
    {
        TRACE( "working-set locking disabled\n" );
        return;
    }

    mlock_ws_raise_rlimit();

    /* Try with MCL_ONFAULT first.  Without it, MCL_FUTURE forces every
     * PROT_NONE reservation into RAM — turning Wine's speculative
     * address-space reserves into committed memory. */
    flags = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT;
    if (mlockall( flags ) == 0)
    {
        TRACE( "mlockall(CURRENT|FUTURE|ONFAULT) ok\n" );
        return;
    }

    /* EINVAL: kernel doesn't recognise MCL_ONFAULT — retry without it.
     * Costs RSS but still gives reclaim safety.  Other errors are
     * preserved as-is for the failure WARN below. */
    if (errno == EINVAL)
    {
        flags = MCL_CURRENT | MCL_FUTURE;
        if (mlockall( flags ) == 0)
        {
            WARN( "MCL_ONFAULT unsupported on this kernel; using "
                  "MCL_CURRENT|MCL_FUTURE — RSS may inflate with "
                  "PROT_NONE reservations\n" );
            return;
        }
    }

    /* Non-fatal: process continues without working-set locking.
     * Normal swap/reclaim behaviour resumes; we lose the page-fault
     * pre-pay but everything else still works. */
    WARN( "mlockall failed: %s — working-set will not be pinned\n",
          strerror( errno ) );
}
