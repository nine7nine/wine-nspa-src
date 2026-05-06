/*
 * NSPA thread_shm A/B validation harness.
 *
 * Calls NtQueryInformationThread for every class the shmem fast path
 * covers, on both the current thread and a worker thread, and dumps
 * the raw reply fields in a canonical line-per-class form.
 *
 * Usage: run twice via /usr/bin/wine — once with NSPA_THREAD_SHM unset
 * (RPC path) and once with NSPA_THREAD_SHM=1 (shmem path) — then diff
 * the two outputs.  Empty diff = bit-identical = shmem path validated.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -o test-thread-shm-ab.exe \
 *     test-thread-shm-ab.c -lntdll
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
#include <stdint.h>

/* mingw's winternl.h ships these prototypes but not always the full
 * ThreadInformationClass enum — declare the values we use. */
#ifndef ThreadBasicInformation
# define ThreadBasicInformation          ((THREADINFOCLASS)0)
#endif
#ifndef ThreadAffinityMask
# define ThreadAffinityMask              ((THREADINFOCLASS)4)
#endif
#ifndef ThreadQuerySetWin32StartAddress
# define ThreadQuerySetWin32StartAddress ((THREADINFOCLASS)9)
#endif
#ifndef ThreadPriorityBoost
# define ThreadPriorityBoost             ((THREADINFOCLASS)14)
#endif
#ifndef ThreadHideFromDebugger
# define ThreadHideFromDebugger          ((THREADINFOCLASS)17)
#endif
#ifndef ThreadIsTerminated
# define ThreadIsTerminated              ((THREADINFOCLASS)20)
#endif
#ifndef ThreadGroupInformation
# define ThreadGroupInformation          ((THREADINFOCLASS)30)
#endif
#ifndef ThreadSuspendCount
# define ThreadSuspendCount              ((THREADINFOCLASS)35)
#endif

/* GROUP_AFFINITY comes in via <windows.h>; don't redefine. */

/* mingw's winternl.h lacks THREAD_BASIC_INFORMATION; declare locally
 * to match Wine's include/winternl.h layout. */
typedef struct _TEST_THREAD_BASIC_INFORMATION
{
    NTSTATUS  ExitStatus;
    PVOID     TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
} TEST_THREAD_BASIC_INFORMATION;

NTSYSAPI NTSTATUS NTAPI NtQueryInformationThread(
    HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength,
    PULONG ReturnLength );

static DWORD WINAPI worker( LPVOID arg )
{
    /* Park indefinitely; main thread cancels via TerminateThread.  We
     * don't care about graceful exit — the worker exists only so we
     * can run queries against a non-self handle. */
    HANDLE wake = CreateEventW( NULL, TRUE, FALSE, NULL );
    WaitForSingleObject( wake, INFINITE );
    return 0;
    (void)arg;
}

static const char *label( HANDLE h, HANDLE worker_h )
{
    if (h == GetCurrentThread()) return "self";
    if (h == worker_h)           return "worker";
    return "?";
}

static void dump( HANDLE h, HANDLE worker_h )
{
    const char *who = label( h, worker_h );
    NTSTATUS s;
    ULONG ret;

    /* ThreadBasicInformation */
    {
        TEST_THREAD_BASIC_INFORMATION tbi;
        memset( &tbi, 0xcc, sizeof(tbi) );
        s = NtQueryInformationThread( h, ThreadBasicInformation, &tbi, sizeof(tbi), &ret );
        printf( "%s ThreadBasicInformation          status=0x%08lx exit=0x%lx teb=%p pid=%llu tid=%llu mask=0x%016llx prio=%ld baseprio=%ld\n",
                who, (unsigned long)s, (unsigned long)tbi.ExitStatus, tbi.TebBaseAddress,
                (unsigned long long)(ULONG_PTR)tbi.ClientId.UniqueProcess,
                (unsigned long long)(ULONG_PTR)tbi.ClientId.UniqueThread,
                (unsigned long long)tbi.AffinityMask,
                (long)tbi.Priority, (long)tbi.BasePriority );
    }
    /* ThreadAffinityMask */
    {
        ULONG_PTR mask = 0;
        s = NtQueryInformationThread( h, ThreadAffinityMask, &mask, sizeof(mask), &ret );
        printf( "%s ThreadAffinityMask              status=0x%08lx mask=0x%016llx\n",
                who, (unsigned long)s, (unsigned long long)mask );
    }
    /* ThreadQuerySetWin32StartAddress */
    {
        PVOID entry = NULL;
        s = NtQueryInformationThread( h, ThreadQuerySetWin32StartAddress, &entry, sizeof(entry), &ret );
        printf( "%s ThreadQuerySetWin32StartAddress status=0x%08lx entry=%p\n",
                who, (unsigned long)s, entry );
    }
    /* ThreadGroupInformation */
    {
        GROUP_AFFINITY ga;
        memset( &ga, 0xcc, sizeof(ga) );
        s = NtQueryInformationThread( h, ThreadGroupInformation, &ga, sizeof(ga), &ret );
        printf( "%s ThreadGroupInformation          status=0x%08lx group=%u mask=0x%016llx res=%04x%04x%04x\n",
                who, (unsigned long)s, ga.Group, (unsigned long long)ga.Mask,
                ga.Reserved[0], ga.Reserved[1], ga.Reserved[2] );
    }
    /* ThreadIsTerminated */
    {
        ULONG term = 0xcccccccc;
        s = NtQueryInformationThread( h, ThreadIsTerminated, &term, sizeof(term), &ret );
        printf( "%s ThreadIsTerminated              status=0x%08lx terminated=%lu\n",
                who, (unsigned long)s, (unsigned long)term );
    }
    /* ThreadSuspendCount */
    {
        ULONG susp = 0xcccccccc;
        s = NtQueryInformationThread( h, ThreadSuspendCount, &susp, sizeof(susp), &ret );
        printf( "%s ThreadSuspendCount              status=0x%08lx suspend=%lu\n",
                who, (unsigned long)s, (unsigned long)susp );
    }
    /* ThreadHideFromDebugger */
    {
        BOOLEAN hide = 0xcc;
        s = NtQueryInformationThread( h, ThreadHideFromDebugger, &hide, sizeof(hide), &ret );
        printf( "%s ThreadHideFromDebugger          status=0x%08lx hidden=%u\n",
                who, (unsigned long)s, hide );
    }
    /* ThreadPriorityBoost */
    {
        ULONG disable = 0xcccccccc;
        s = NtQueryInformationThread( h, ThreadPriorityBoost, &disable, sizeof(disable), &ret );
        printf( "%s ThreadPriorityBoost             status=0x%08lx disable_boost=%lu\n",
                who, (unsigned long)s, (unsigned long)disable );
    }
}

int main( void )
{
    HANDLE w;
    DWORD wtid;

    /* Create the worker thread suspended so we get a deterministic
     * non-zero suspend count to validate.  The worker's init_thread
     * RPC fires from the worker pthread asynchronously; we sleep
     * before querying so init_thread has fired and entry_point is
     * stable in both struct and shared (otherwise this is racy in
     * BOTH RPC and SHMEM paths — confirmed empirically). */
    w = CreateThread( NULL, 0, worker, NULL, CREATE_SUSPENDED, &wtid );
    if (!w) { fprintf( stderr, "CreateThread failed: %lu\n", GetLastError() ); return 2; }
    Sleep( 100 );

    printf( "=== self thread queries ===\n" );
    dump( GetCurrentThread(), w );

    printf( "=== worker thread (suspended) queries ===\n" );
    dump( w, w );

    /* Resume + let it park, then re-query to confirm suspend=0. */
    ResumeThread( w );
    Sleep( 100 );
    printf( "=== worker thread (resumed) queries ===\n" );
    dump( w, w );

    TerminateThread( w, 0 );
    /* Settle so the kill_thread shmem publish lands before we query
     * the now-terminated handle. */
    Sleep( 200 );
    printf( "=== worker thread (terminated) queries ===\n" );
    dump( w, w );

    CloseHandle( w );
    return 0;
}
