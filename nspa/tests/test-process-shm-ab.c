/*
 * NSPA process_shm A/B validation harness.
 *
 * Calls NtQueryInformationProcess for every class the shmem fast
 * path covers (ProcessBasicInformation, ProcessTimes,
 * ProcessPriorityBoost, ProcessAffinityMask,
 * ProcessSessionInformation, ProcessPriorityClass), and dumps the
 * raw reply fields in a canonical line-per-class form.
 *
 * Usage: run twice via /usr/bin/wine — once with NSPA_PROCESS_SHM
 * unset (RPC path) and once with NSPA_PROCESS_SHM=1 (shmem path) —
 * then diff the two outputs.
 *
 * NOTE on diffing: each test invocation is a fresh wine process, so
 * `pid` and `create_time` (and `ppid` for the wineserver-internal
 * relationship) legitimately differ between the two runs.  Filter
 * those out before diffing — empty diff on the filtered output =
 * bit-identical = shmem path validated.  Example one-liner:
 *
 *   filter() { sed -E 's/pid=[0-9]+/pid=<X>/g; s/ppid=[0-9]+/ppid=<Y>/g;
 *              s/create=[0-9]+/create=<T>/g'; }
 *   /usr/bin/wine ./test-process-shm-ab.exe        | filter > rpc.txt
 *   NSPA_PROCESS_SHM=1 /usr/bin/wine ./test-process-shm-ab.exe | filter > shm.txt
 *   diff rpc.txt shm.txt   # empty = bit-identical on stable fields
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -o test-process-shm-ab.exe \
 *     test-process-shm-ab.c -lntdll
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

/* PROCESSINFOCLASS values — mingw's winternl.h has the enum but the
 * exact integer values aren't all guaranteed to be exposed.  Matches
 * Wine's include/winternl.h. */
#ifndef ProcessBasicInformation
# define ProcessBasicInformation       ((PROCESSINFOCLASS)0)
#endif
#ifndef ProcessTimes
# define ProcessTimes                  ((PROCESSINFOCLASS)4)
#endif
#ifndef ProcessAffinityMask
# define ProcessAffinityMask           ((PROCESSINFOCLASS)21)
#endif
#ifndef ProcessPriorityClass
# define ProcessPriorityClass          ((PROCESSINFOCLASS)18)
#endif
#ifndef ProcessSessionInformation
# define ProcessSessionInformation     ((PROCESSINFOCLASS)24)
#endif
#ifndef ProcessPriorityBoost
# define ProcessPriorityBoost          ((PROCESSINFOCLASS)39)
#endif

NTSYSAPI NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength,
    PULONG ReturnLength );

typedef struct
{
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER ExitTime;
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
} TEST_KERNEL_USER_TIMES;

typedef struct
{
    BYTE PriorityClass;
    BYTE Foreground;
} TEST_PROCESS_PRIORITY_CLASS;

static void dump( HANDLE h, const char *who )
{
    NTSTATUS s;
    ULONG ret;

    /* ProcessBasicInformation */
    {
        PROCESS_BASIC_INFORMATION pbi;
        memset( &pbi, 0xcc, sizeof(pbi) );
        s = NtQueryInformationProcess( h, ProcessBasicInformation, &pbi, sizeof(pbi), &ret );
        printf( "%s ProcessBasicInformation     status=0x%08lx exit=0x%lx peb=%p mask=0x%016llx baseprio=%ld pid=%llu ppid=%llu\n",
                who, (unsigned long)s, (unsigned long)pbi.ExitStatus, pbi.PebBaseAddress,
                (unsigned long long)pbi.AffinityMask, (long)pbi.BasePriority,
                (unsigned long long)pbi.UniqueProcessId,
                (unsigned long long)pbi.InheritedFromUniqueProcessId );
    }
    /* ProcessTimes — note: KernelTime / UserTime come from the
     * /proc/PID/stat tms() path on the client, not from get_process_info,
     * so they are NOT served by shmem.  Only CreateTime + ExitTime are. */
    {
        TEST_KERNEL_USER_TIMES pti;
        memset( &pti, 0xcc, sizeof(pti) );
        s = NtQueryInformationProcess( h, ProcessTimes, &pti, sizeof(pti), &ret );
        printf( "%s ProcessTimes                status=0x%08lx create=%lld exit=%lld\n",
                who, (unsigned long)s,
                (long long)pti.CreateTime.QuadPart,
                (long long)pti.ExitTime.QuadPart );
    }
    /* ProcessAffinityMask */
    {
        ULONG_PTR mask = 0xcccccccccccccccc;
        s = NtQueryInformationProcess( h, ProcessAffinityMask, &mask, sizeof(mask), &ret );
        printf( "%s ProcessAffinityMask         status=0x%08lx mask=0x%016llx\n",
                who, (unsigned long)s, (unsigned long long)mask );
    }
    /* ProcessSessionInformation */
    {
        DWORD sid = 0xcccccccc;
        s = NtQueryInformationProcess( h, ProcessSessionInformation, &sid, sizeof(sid), &ret );
        printf( "%s ProcessSessionInformation   status=0x%08lx session=%lu\n",
                who, (unsigned long)s, (unsigned long)sid );
    }
    /* ProcessPriorityClass */
    {
        TEST_PROCESS_PRIORITY_CLASS prio;
        memset( &prio, 0xcc, sizeof(prio) );
        s = NtQueryInformationProcess( h, ProcessPriorityClass, &prio, sizeof(prio), &ret );
        printf( "%s ProcessPriorityClass        status=0x%08lx class=%u fg=%u\n",
                who, (unsigned long)s, prio.PriorityClass, prio.Foreground );
    }
    /* ProcessPriorityBoost */
    {
        ULONG disable = 0xcccccccc;
        s = NtQueryInformationProcess( h, ProcessPriorityBoost, &disable, sizeof(disable), &ret );
        printf( "%s ProcessPriorityBoost        status=0x%08lx disable_boost=%lu\n",
                who, (unsigned long)s, (unsigned long)disable );
    }
}

int main( void )
{
    printf( "=== self process queries ===\n" );
    dump( GetCurrentProcess(), "self" );
    return 0;
}
