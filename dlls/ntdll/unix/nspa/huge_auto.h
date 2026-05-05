/*
 * NSPA Phase 2 — opportunistic transparent hugetlb opt-in.
 *
 * Routes eligible anonymous large allocations through the existing
 * map_view_large_pages path (MAP_HUGETLB | MAP_LOCKED) without
 * requiring the app to pass MEM_LARGE_PAGES.  Drops dTLB miss rate
 * on the affected views ~512× by backing them with 2 MB pages.
 *
 * Gate: NSPA_RT_PRIO presence.  No separate env override.
 *
 * Eligibility heuristic (all must hold):
 *
 *   1. Anonymous (no file backing) — implicit (caller is the anon path).
 *   2. Single-shot reserve+commit — (type & MEM_RESERVE) && (type & MEM_COMMIT).
 *   3. No exotic flags — type & ~(MEM_RESERVE|MEM_COMMIT|MEM_TOP_DOWN) == 0.
 *   4. Kernel-chosen placement — base == NULL.
 *   5. Size ≥ LargePageMinimum AND multiple of LargePageMinimum.
 *   6. Protection is PAGE_READWRITE only (excludes JIT/RX/COW/EXEC patterns).
 *
 * Excluded patterns: every JIT pattern, every file-backed mapping,
 * every fixed-address allocation, every RX/COW/EXEC/WRITECOPY/GUARD.
 *
 * Companion to Phase 3 (heap.c arena round-up) — Phase 3 reshapes
 * heap.c's arena allocations into single-shot RES+COMMIT requests
 * that satisfy this eligibility check.  Phase 2 alone catches any
 * direct VirtualAlloc(MEM_RESERVE|MEM_COMMIT) with size ≥ 2 MB and
 * RW protection.
 *
 * NT semantics: views auto-promoted are tagged VPROT_NSPA_HUGE_AUTO
 * (visible to virtual.c; opaque to apps).  SEC_LARGE_PAGES set on
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

/* Returns TRUE if the requested allocation is eligible for opportunistic
 * auto-promotion to MEM_LARGE_PAGES backing.  Caller passes args from
 * NtAllocateVirtualMemory; lp_unit is user_shared_data->LargePageMinimum
 * (typically 2 MB on x86_64).
 *
 * Implicitly OFF unless NSPA_RT_PRIO is set in the environment.
 */
extern BOOL nspa_huge_auto_eligible( ULONG type, ULONG protect,
                                      void *base, SIZE_T size,
                                      ULONG attributes, SIZE_T lp_unit );

#endif /* __NSPA_HUGE_AUTO_H */
