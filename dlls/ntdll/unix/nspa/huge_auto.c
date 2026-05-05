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

static BOOL huge_auto_active;
static int huge_auto_init_done;

static void huge_auto_init( void )
{
    if (huge_auto_init_done) return;
    huge_auto_init_done = 1;

    /* Single gate: NSPA_RT_PRIO presence.  RT processes get RT defaults. */
    if (getenv( "NSPA_RT_PRIO" ))
    {
        huge_auto_active = TRUE;
        TRACE( "huge auto-promote active (NSPA_RT_PRIO set)\n" );
    }
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

    return TRUE;
}
