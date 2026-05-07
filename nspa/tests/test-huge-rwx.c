/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Probe: NSPA Phase 2 auto-promote covers PAGE_EXECUTE_READWRITE.
 *
 * JIT engines that emit-and-execute (no W^X round-trip) allocate
 * PAGE_EXECUTE_READWRITE directly.  Eligibility was previously
 * restricted to PAGE_READWRITE only — those allocations did not get
 * hugetlb backing.  This probe confirms a >=2 MiB RWX allocation under
 * NSPA_RT_PRIO ends up huge-page-backed (visible via /proc/self/smaps
 * KernelPageSize == 2048 kB) AND is executable.
 *
 * Exit codes:
 *   0  pass (auto-promoted to hugetlb, executable)
 *   1  not auto-promoted (regular pages)
 *   2  not executable
 *   3  setup failure */

#include <windows.h>
#include <stdio.h>
#include <string.h>

#define ALLOC_SIZE (4 * 1024 * 1024)   /* 4 MiB = 2 hugepages */

static int read_kernelpagesize_kb( const void *addr )
{
    FILE *f;
    char line[256];
    int found = 0, kb = 0;
    unsigned long target = (unsigned long)addr;

    f = fopen( "/proc/self/smaps", "r" );
    if (!f) return -1;
    while (fgets( line, sizeof(line), f ))
    {
        unsigned long lo, hi;
        if (sscanf( line, "%lx-%lx", &lo, &hi ) == 2)
        {
            found = (target >= lo && target < hi);
            continue;
        }
        if (found && sscanf( line, "KernelPageSize: %d kB", &kb ) == 1) break;
    }
    fclose( f );
    return kb;
}

int main(void)
{
    void *p = VirtualAlloc( NULL, ALLOC_SIZE,
                            MEM_RESERVE | MEM_COMMIT,
                            PAGE_EXECUTE_READWRITE );
    if (!p)
    {
        fprintf( stderr, "VirtualAlloc(RWX) failed: %lu\n", GetLastError() );
        return 3;
    }
    fprintf( stderr, "VirtualAlloc(RWX, %d MiB) -> %p\n", ALLOC_SIZE >> 20, p );

    int kps = read_kernelpagesize_kb( p );
    fprintf( stderr, "smaps KernelPageSize: %d kB\n", kps );

    /* Write a trivial RET (x86_64) and execute it. */
    *(unsigned char *)p = 0xC3;
    typedef void (*fn_t)(void);
    fn_t fn = (fn_t)p;
    fn();
    fprintf( stderr, "executed bytes at %p (page size %d kB)\n", p, kps );

    VirtualFree( p, 0, MEM_RELEASE );

    if (kps < 2048) { fprintf( stderr, "FAIL: not hugepage-backed (kps=%d)\n", kps ); return 1; }
    fprintf( stderr, "PASS: hugepage-backed RWX, executable\n" );
    return 0;
}
