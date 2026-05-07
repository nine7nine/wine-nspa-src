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
 *   6. Protection is PAGE_READWRITE or PAGE_EXECUTE_READWRITE.  RW
 *      catches data arenas (Phase 3 heap) and W^X JIT initial alloc.
 *      RWX catches emit-and-execute JIT engines that skip the W^X
 *      round-trip.
 *
 * Excluded patterns: file-backed mappings, fixed-address allocations,
 * RX-only/COW/WRITECOPY/GUARD/PAGE_NOACCESS.
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

/* Demote an auto-promoted hugetlb-backed view to regular pages.
 *
 * Required before any sub-hugepage partial-op (MEM_DECOMMIT,
 * MEM_RELEASE, mprotect at non-2MB-aligned granularity) — Linux
 * MAP_FIXED replacement and mprotect both EINVAL on sub-hugepage
 * slices of a hugetlb VMA.  Demote replaces the entire view's backing
 * with regular anon pages, preserving contents.
 *
 * Caller must hold virtual_mutex.  On failure, view backing is
 * unchanged; caller should fail the requesting NT op accordingly.
 *
 * Cost: O(size) memcpy x 2 + transient size-bytes scratch mmap.
 * Rare path — only fires on first sub-hugepage op against an
 * auto-promoted view.
 *
 * Returns 0 on success, non-zero (errno-style) on failure. */
extern int nspa_huge_auto_demote( void *base, SIZE_T size );

#endif /* __NSPA_HUGE_AUTO_H */
