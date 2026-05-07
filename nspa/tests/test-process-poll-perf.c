/*
 * NSPA process_shm WaitForSingleObject(proc, 0) fast-path perf test.
 *
 * Uses OpenProcess(SYNCHRONIZE, FALSE, GetCurrentProcessId()) to get
 * a real process handle to self.  Polls it in a tight loop with
 * timeout=0; self-process is always alive so every poll returns
 * WAIT_TIMEOUT — exactly the inproc_wait → ntsync ioctl path the
 * shmem fast path replaces.  Times via QueryPerformanceCounter.
 *
 * Self-process avoids CreateProcess overhead/timeouts.  The handle
 * type and the inproc_wait code path are identical to a real child
 * process handle (both are PROCESS_QUERY_LIMITED_INFORMATION-derived
 * sync objects), so the per-poll cost measurement is representative.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -o test-process-poll-perf.exe \
 *     test-process-poll-perf.c -lntdll -lkernel32
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <windows.h>
#include <stdio.h>

#define POLL_COUNT 50000

int main( int argc, char **argv )
{
    HANDLE proc;
    LARGE_INTEGER freq, t0, t1;
    LONGLONG total_ns;
    DWORD ret;
    int i;

    QueryPerformanceFrequency( &freq );

    /* SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION matches what apps
     * doing liveness polling typically have (CreateProcess returns both
     * by default; OpenProcess callers usually request both since they
     * also want GetExitCodeProcess). */
    proc = OpenProcess( SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId() );
    if (!proc)
    {
        fprintf( stderr, "OpenProcess failed: %lu\n", GetLastError() );
        return 2;
    }

    /* Sanity: self-process is always alive so timeout=0 must return
     * WAIT_TIMEOUT.  Failure here means the wait path is broken. */
    ret = WaitForSingleObject( proc, 0 );
    if (ret != WAIT_TIMEOUT)
    {
        fprintf( stderr, "sanity check failed: WaitForSingleObject returned %lu (expected WAIT_TIMEOUT 0x%x)\n",
                 ret, (unsigned int)WAIT_TIMEOUT );
        return 3;
    }

    /* Warm-up: populates inproc_sync cache, shmem handle cache, and
     * branch predictor.  Hot loop measures steady-state. */
    for (i = 0; i < 1000; i++) WaitForSingleObject( proc, 0 );

    QueryPerformanceCounter( &t0 );
    for (i = 0; i < POLL_COUNT; i++) WaitForSingleObject( proc, 0 );
    QueryPerformanceCounter( &t1 );

    total_ns = ((t1.QuadPart - t0.QuadPart) * 1000000000LL) / freq.QuadPart;

    printf( "polls=%d  total=%.3f ms  mean=%.1f ns/poll\n",
            POLL_COUNT,
            (double)total_ns / 1.0e6,
            (double)total_ns / (double)POLL_COUNT );

    CloseHandle( proc );
    return 0;
    (void)argc; (void)argv;
}
