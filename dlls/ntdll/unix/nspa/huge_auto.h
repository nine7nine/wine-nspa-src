/*
 * NSPA Phase 2 — opportunistic transparent hugetlb opt-in.
 *
 * Routes eligible anonymous large allocations through the existing
 * map_view_large_pages path (MAP_HUGETLB | MAP_LOCKED) without
 * requiring the app to pass MEM_LARGE_PAGES.  Drops dTLB miss rate
 * on the affected views ~512× by backing them with 2 MB pages.
 *
 * Two modes (env NSPA_HEAP_HUGEPAGE):
 *
 *   1   conservative  6-condition heuristic — single-shot RES+COMMIT,
 *                     kernel-chosen placement, PAGE_READWRITE only.
 *                     Excludes every JIT pattern, file-backed mapping,
 *                     fixed-address allocation, RX/COW/EXEC scenario.
 *
 *   2   aggressive    relaxed: commit-after-reserve, caller-specified
 *                     hugepage-aligned base, PAGE_READONLY + NOACCESS
 *                     also accepted.  Explicit-only — never auto-on.
 *
 * NSPA_RT_PRIO presence triggers conservative when the explicit env
 * is unset; never triggers aggressive.
 *
 * First iteration (this version) does NOT implement the demote-on-
 * partial-op path.  An auto-promoted view that hits a partial
 * decommit / partial-protect / partial-release will surface
 * STATUS_INVALID_PARAMETER (or similar) from the underlying kernel
 * EINVAL — non-fatal, non-corrupting, but the app's operation fails.
 * This is acceptable for the default-OFF testing rollout: the
 * conservative heuristic excludes patterns we expect to hit partial
 * ops, and aggressive mode is opt-in for stress-testing.  When real
 * workloads demonstrate demote-need, the demote path is added in a
 * Phase 2.5 follow-on; this file's API is shaped to allow that.
 *
 * Design doc:
 *   nspa/docs/working-set-and-hugetlb-design-20260505.md
 *
 * NT semantics: views auto-promoted are tagged VPROT_NSPA_HUGE_AUTO
 * (visible to virtual.c; opaque to apps).  SEC_LARGE_PAGES is set on
 * the view, so QueryWorkingSetEx truthfully reports LargePage.  No
 * Win32 API surface change.
 *
 * RT semantics: eligibility check is a handful of integer comparisons,
 * cheap.  Auto-promote uses the same map_view_large_pages path that
 * apps explicitly opting into MEM_LARGE_PAGES use — no new RT-relevant
 * behaviour.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __NSPA_HUGE_AUTO_H
#define __NSPA_HUGE_AUTO_H

#include <windef.h>

enum nspa_huge_auto_mode
{
    NSPA_HUGE_AUTO_OFF          = 0,
    NSPA_HUGE_AUTO_CONSERVATIVE = 1,
    NSPA_HUGE_AUTO_AGGRESSIVE   = 2,
};

/* Returns the active mode (read-once cached on first call).  Cheap
 * after the first call. */
extern enum nspa_huge_auto_mode nspa_huge_auto_get_mode( void );

/* Returns TRUE if the requested allocation is eligible for opportunistic
 * auto-promotion to MEM_LARGE_PAGES backing.  Caller passes args from
 * NtAllocateVirtualMemory; lp_unit is user_shared_data->LargePageMinimum
 * (typically 2 MB on x86_64).
 *
 * The caller is expected to be allocate_virtual_memory() in virtual.c —
 * the eligibility check assumes the request is anonymous (no file
 * backing) because that's the only path that reaches this helper.
 */
extern BOOL nspa_huge_auto_eligible( ULONG type, ULONG protect,
                                      void *base, SIZE_T size,
                                      ULONG attributes, SIZE_T lp_unit );

#endif /* __NSPA_HUGE_AUTO_H */
