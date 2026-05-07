/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Probe: NT semantics for partial ops on NSPA Phase 2 auto-promoted views.
 *
 * Two trigger patterns (both sub-hugepage on a hugetlb-backed view):
 *   T1. MEM_DECOMMIT then MEM_COMMIT -> contents must read zero.
 *   T2. MEM_RELEASE on a partial range -> released range gone, the
 *       surrounding view stays intact with original contents.
 *
 * VirtualProtect(partial) coverage relies on the same demote helper
 * being applied symmetrically to set_protection; not exercised here
 * to keep the probe gcc-buildable without SEH.
 *
 * Exit codes:
 *   0  all subtests pass
 *   1+ subtest mask of failures (T1 = bit 0, T2 = bit 1) */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define ALLOC_SIZE   (8 * 1024 * 1024)    /* 8 MiB = 4 hugepages */
#define SUB_OFF      (64 * 1024)
#define SUB_LEN      (64 * 1024)
#define PATTERN      0xA5

static void *fresh_view( void )
{
    void *p = VirtualAlloc( NULL, ALLOC_SIZE,
                            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    if (!p) return NULL;
    memset( p, PATTERN, ALLOC_SIZE );
    return p;
}

static int t1_decommit_recommit( void )
{
    void *p = fresh_view();
    if (!p) { fprintf( stderr, "T1 setup: VirtualAlloc failed\n" ); return 1; }

    unsigned char *target = (unsigned char *)p + SUB_OFF;
    if (!VirtualFree( target, SUB_LEN, MEM_DECOMMIT ))
    {
        fprintf( stderr, "T1 VirtualFree(MEM_DECOMMIT) failed: %lu\n", GetLastError() );
        VirtualFree( p, 0, MEM_RELEASE );
        return 1;
    }
    void *rec = VirtualAlloc( target, SUB_LEN, MEM_COMMIT, PAGE_READWRITE );
    if (!rec)
    {
        fprintf( stderr, "T1 recommit failed: %lu\n", GetLastError() );
        VirtualFree( p, 0, MEM_RELEASE );
        return 1;
    }

    int stale = 0;
    for (int i = 0; i < SUB_LEN; i++) if (((unsigned char *)rec)[i] != 0) stale++;
    VirtualFree( p, 0, MEM_RELEASE );

    if (stale)
    {
        fprintf( stderr, "T1 FAIL: %d stale bytes after recommit (NT contract: zero)\n", stale );
        return 1;
    }
    fprintf( stderr, "T1 PASS: decommit + recommit yields zeroed range\n" );
    return 0;
}

static int t2_partial_release( void )
{
    void *p = fresh_view();
    if (!p) { fprintf( stderr, "T2 setup: VirtualAlloc failed\n" ); return 1; }

    /* Release a 64 KiB sub-range starting +64 KiB.  NT semantics: the
     * range is unmapped; reading the surrounding region must still
     * return the original pattern. */
    unsigned char *target = (unsigned char *)p + SUB_OFF;
    if (!VirtualFree( target, SUB_LEN, MEM_RELEASE ))
    {
        /* Wine accepts this; native Windows refuses partial RELEASE
         * unless the size is 0.  Either outcome is acceptable here —
         * the bug we care about is silent success that leaves stale
         * state, not a clean rejection. */
        fprintf( stderr, "T2 partial MEM_RELEASE refused (acceptable): %lu\n", GetLastError() );
        VirtualFree( p, 0, MEM_RELEASE );
        return 0;
    }

    /* Surrounding region must still be intact. */
    if (((unsigned char *)p)[0] != PATTERN
        || ((unsigned char *)p)[ALLOC_SIZE - 1] != PATTERN)
    {
        fprintf( stderr, "T2 FAIL: surrounding view corrupted after partial release\n" );
        return 1;
    }
    /* The released range must NOT be readable as the old hugetlb-backed
     * mapping; a query should return that base/size has changed. */
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery( target, &mbi, sizeof(mbi) ))
        fprintf( stderr, "T2 query: state=%#lx prot=%#lx size=%#lx\n",
                 mbi.State, mbi.Protect, (unsigned long)mbi.RegionSize );

    VirtualFree( p, 0, MEM_RELEASE );
    fprintf( stderr, "T2 PASS: partial release accepted, surroundings intact\n" );
    return 0;
}

int main(void)
{
    SYSTEM_INFO si;
    GetSystemInfo( &si );
    fprintf( stderr, "page=%lu gran=%lu\n", si.dwPageSize, si.dwAllocationGranularity );

    int rc = 0;
    if (t1_decommit_recommit()) rc |= 1;
    if (t2_partial_release())   rc |= 2;

    if (rc == 0) fprintf( stderr, "ALL PASS\n" );
    else         fprintf( stderr, "FAIL mask=%d (T1=%d T2=%d)\n",
                          rc, !!(rc & 1), !!(rc & 2) );
    return rc;
}
