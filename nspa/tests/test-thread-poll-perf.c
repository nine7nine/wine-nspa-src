/*
 * NSPA thread_shm WaitForSingleObject(thread, 0) fast-path perf test.
 *
 * Uses GetCurrentThread() pseudo-handle duplicated to a real handle via
 * DuplicateHandle, then polls it in a tight loop with timeout=0.  Self-
 * thread is always alive so every poll returns WAIT_TIMEOUT — exactly
 * the inproc_wait → ntsync ioctl path the shmem fast path replaces.
 *
 * Sibling of test-process-poll-perf.c; the predicate inside the fast
 * path is THREAD_SHM_FLAG_TERMINATED instead of exit_code != STILL_ACTIVE,
 * but the per-poll cost shape is identical.
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -O2 -o test-thread-poll-perf.exe \
 *     test-thread-poll-perf.c -lntdll -lkernel32
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
    HANDLE thread;
    LARGE_INTEGER freq, t0, t1;
    LONGLONG total_ns;
    DWORD ret;
    int i;

    QueryPerformanceFrequency( &freq );

    /* DuplicateHandle on the GetCurrentThread() pseudo-handle yields a
     * real handle to self that goes through the full inproc_sync /
     * thread_shm machinery, just like a handle returned by CreateThread
     * or OpenThread.  SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION
     * matches the access an app polling for thread liveness would have. */
    if (!DuplicateHandle( GetCurrentProcess(), GetCurrentThread(),
                          GetCurrentProcess(), &thread,
                          SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION,
                          FALSE, 0 ))
    {
        fprintf( stderr, "DuplicateHandle failed: %lu\n", GetLastError() );
        return 2;
    }

    /* Sanity: self-thread is always alive so timeout=0 must return
     * WAIT_TIMEOUT.  Failure here means the wait path is broken. */
    ret = WaitForSingleObject( thread, 0 );
    if (ret != WAIT_TIMEOUT)
    {
        fprintf( stderr, "sanity check failed: WaitForSingleObject returned %lu (expected WAIT_TIMEOUT 0x%x)\n",
                 ret, (unsigned int)WAIT_TIMEOUT );
        return 3;
    }

    /* Warm-up: populates inproc_sync cache, thread_shm handle cache, and
     * branch predictor.  Hot loop measures steady-state. */
    for (i = 0; i < 1000; i++) WaitForSingleObject( thread, 0 );

    QueryPerformanceCounter( &t0 );
    for (i = 0; i < POLL_COUNT; i++) WaitForSingleObject( thread, 0 );
    QueryPerformanceCounter( &t1 );

    total_ns = ((t1.QuadPart - t0.QuadPart) * 1000000000LL) / freq.QuadPart;

    printf( "polls=%d  total=%.3f ms  mean=%.1f ns/poll\n",
            POLL_COUNT,
            (double)total_ns / 1.0e6,
            (double)total_ns / (double)POLL_COUNT );

    CloseHandle( thread );
    return 0;
    (void)argc; (void)argv;
}
