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

#include <stdlib.h>

#include "windef.h"
#include "winnt.h"
#include "wine/debug.h"

#include "huge_auto.h"

WINE_DEFAULT_DEBUG_CHANNEL(virtual);

static enum nspa_huge_auto_mode huge_auto_mode = NSPA_HUGE_AUTO_OFF;
static int huge_auto_init_done;

static void huge_auto_init( void )
{
    const char *gate;

    if (huge_auto_init_done) return;
    huge_auto_init_done = 1;

    gate = getenv( "NSPA_HEAP_HUGEPAGE" );
    if (gate)
    {
        if (gate[0] == '2')
        {
            huge_auto_mode = NSPA_HUGE_AUTO_AGGRESSIVE;
            TRACE( "aggressive mode (explicit)\n" );
            return;
        }
        if (gate[0] == '1' || gate[0] == 'y' || gate[0] == 'Y')
        {
            huge_auto_mode = NSPA_HUGE_AUTO_CONSERVATIVE;
            TRACE( "conservative mode (explicit)\n" );
            return;
        }
        if (gate[0] == '0' || gate[0] == 'n' || gate[0] == 'N')
        {
            return;  /* off — leave mode at default OFF */
        }
        /* anything else: fall through to NSPA_RT_PRIO default. */
    }

    /* Default policy: NSPA_RT_PRIO presence triggers conservative.
     * Aggressive is NEVER auto-on — explicit opt-in only. */
    if (getenv( "NSPA_RT_PRIO" ))
    {
        huge_auto_mode = NSPA_HUGE_AUTO_CONSERVATIVE;
        TRACE( "conservative mode (auto under NSPA_RT_PRIO)\n" );
    }
}

enum nspa_huge_auto_mode nspa_huge_auto_get_mode( void )
{
    huge_auto_init();
    return huge_auto_mode;
}

BOOL nspa_huge_auto_eligible( ULONG type, ULONG protect,
                               void *base, SIZE_T size,
                               ULONG attributes, SIZE_T lp_unit )
{
    enum nspa_huge_auto_mode mode = nspa_huge_auto_get_mode();

    if (mode == NSPA_HUGE_AUTO_OFF) return FALSE;
    if (lp_unit == 0) return FALSE;

    /* Common conditions (both modes):
     *   anonymous: implicit — virtual.c only calls us in the anon path.
     *   size:      must be >= and a multiple of lp_unit.
     *   no NONPAGED_HUGE attribute (1 GiB pages — explicit-only path). */
    if (size < lp_unit) return FALSE;
    if ((size % lp_unit) != 0) return FALSE;
    if (attributes & MEM_EXTENDED_PARAMETER_NONPAGED_HUGE) return FALSE;

    if (mode == NSPA_HUGE_AUTO_CONSERVATIVE)
    {
        /* Single-shot reserve+commit: heap arenas, large RW buffers. */
        if (!(type & MEM_RESERVE) || !(type & MEM_COMMIT)) return FALSE;
        /* No exotic flags. MEM_TOP_DOWN is fine — kernel just hints
         * placement; doesn't change correctness. */
        if (type & ~(MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN)) return FALSE;
        /* Kernel-chosen placement only — no fixed-address requests. */
        if (base) return FALSE;
        /* PAGE_READWRITE only.  PAGE_EXECUTE_*, PAGE_WRITECOPY,
         * PAGE_GUARD, PAGE_NOCACHE are incompatible with MAP_HUGETLB |
         * MAP_LOCKED, and PAGE_READONLY/NOACCESS are excluded here to
         * keep conservative truly conservative.  Aggressive mode below
         * relaxes this. */
        if (protect != PAGE_READWRITE) return FALSE;
    }
    else /* NSPA_HUGE_AUTO_AGGRESSIVE */
    {
        /* Still require single-shot RES+COMMIT — the existing
         * map_view_large_pages validation in allocate_virtual_memory
         * rejects anything else, and the commit-after-reserve case
         * needs a different code path (existing view → set_protection
         * → mprotect on hugetlb).  That's a Phase 2.5 follow-on. */
        if (!(type & MEM_RESERVE) || !(type & MEM_COMMIT)) return FALSE;
        /* MEM_WRITE_WATCH stays excluded — incompatible with MAP_HUGETLB. */
        if (type & MEM_WRITE_WATCH) return FALSE;
        /* No exotic flags — but accept MEM_TOP_DOWN like conservative. */
        if (type & ~(MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN)) return FALSE;
        /* Fixed-base allocations allowed iff hugepage-aligned (relaxed
         * vs conservative which rejects any non-NULL base). */
        if (base && ((UINT_PTR)base % lp_unit) != 0) return FALSE;
        /* RW, RO, and NOACCESS — but NEVER any EXEC variant or
         * WRITECOPY/GUARD (those break MAP_HUGETLB | MAP_LOCKED). */
        if (protect != PAGE_READWRITE
            && protect != PAGE_READONLY
            && protect != PAGE_NOACCESS)
        {
            return FALSE;
        }
    }

    return TRUE;
}
