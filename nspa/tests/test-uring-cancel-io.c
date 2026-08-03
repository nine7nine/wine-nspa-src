/* NSPA U1 io_uring NtCancelIoFile reproducer / regression test.
 *
 * Targets dlls/ntdll/unix/file.c cancel_io + io_uring.c
 * ntdll_io_uring_cancel_ops: bypass ops (overlapped reads on real-fd
 * files routed via ntdll_io_uring_submit_file_read) have no server-side
 * async, so before the U1 fix the cancel_async RPC saw nothing to
 * cancel — CancelIo(Ex) returned success having cancelled nothing, the
 * IOSB stayed PENDING forever (CancelIoEx + GetOverlappedResult hung),
 * and an app freeing its buffer after the successful-looking cancel
 * could be scribbled on when data eventually arrived.
 *
 * Same deterministic client-uring shape as the U2/U3 tests: overlapped
 * reads on a filesystem FIFO opened via Z: (write end held open so the
 * empty read EAGAINs into the async path).
 *
 *   phase 1: CancelIoEx(h, &ov) on one pending read — event must fire
 *            promptly with ERROR_OPERATION_ABORTED.
 *   phase 2: CancelIo(h) (NULL-iosb variant, calling-thread scope).
 *   phase 3: selectivity — two pending reads on ONE handle, cancel only
 *            ov1; ov1 aborts, ov2 must survive and then complete with
 *            the written payload.
 *
 * Setup (unix side): mkfifo /tmp/nspa-u1-1.fifo
 * Build: x86_64-w64-mingw32-gcc -O2 -Wall -o test-uring-cancel-io.exe test-uring-cancel-io.c
 * Run:   WINEPREFIX=~/Winebox/winebox-master wine ./test-uring-cancel-io.exe [fifo-dos-path]
 * Exit:  0 = PASS, 1 = FAIL, 77 = SKIP
 */
#include <windows.h>
#include <stdio.h>

#define EVENT_CAP_MS 3000

static const char *fifo_path = "Z:\\tmp\\nspa-u1-1.fifo";

struct pending_read
{
    OVERLAPPED ov;
    char       buf[16];
};

/* Submit one overlapped read; returns 1 ok, 0 skip (not async). */
static int submit_read( HANDLE h, struct pending_read *r )
{
    memset( r, 0, sizeof(*r) );
    r->ov.hEvent = CreateEventA( NULL, TRUE, FALSE, NULL );
    if (!ReadFile( h, r->buf, sizeof(r->buf), NULL, &r->ov ) &&
        GetLastError() == ERROR_IO_PENDING)
        return 1;
    printf( "SKIP: read did not go async (err %lu) — io_uring file path not active\n",
            GetLastError() );
    return 0;
}

/* Expect the read to complete as OPERATION_ABORTED within the cap. */
static int expect_aborted( HANDLE h, struct pending_read *r, int phase )
{
    DWORD t0 = GetTickCount(), got = 0;

    if (WaitForSingleObject( r->ov.hEvent, EVENT_CAP_MS ) != WAIT_OBJECT_0)
    {
        printf( "FAIL: phase %d cancelled read never completed (cancel reached nothing)\n", phase );
        return 1;
    }
    if (GetOverlappedResult( h, &r->ov, &got, FALSE ) ||
        GetLastError() != ERROR_OPERATION_ABORTED)
    {
        printf( "FAIL: phase %d expected OPERATION_ABORTED, got err %lu (bytes %lu)\n",
                phase, GetLastError(), (unsigned long)got );
        return 1;
    }
    printf( "PASS: phase %d cancel delivered OPERATION_ABORTED in %lums\n",
            phase, (unsigned long)(GetTickCount() - t0) );
    return 0;
}

int main( int argc, char **argv )
{
    HANDLE h, wr;
    struct pending_read r1, r2;
    DWORD written = 0, got = 0;
    int failures = 0;

    if (argc > 1) fifo_path = argv[1];

    h = CreateFileA( fifo_path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                     FILE_FLAG_OVERLAPPED, NULL );
    if (h == INVALID_HANDLE_VALUE)
    {
        printf( "SKIP: cannot open fifo %s (err %lu) — run mkfifo first\n",
                fifo_path, GetLastError() );
        return 77;
    }
    wr = CreateFileA( fifo_path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );
    if (wr == INVALID_HANDLE_VALUE)
    {
        printf( "SKIP: cannot open fifo write end (err %lu)\n", GetLastError() );
        return 77;
    }

    /* phase 1: targeted CancelIoEx */
    if (!submit_read( h, &r1 )) return 77;
    if (!CancelIoEx( h, &r1.ov ) && GetLastError() != ERROR_NOT_FOUND)
        printf( "  note: CancelIoEx returned err %lu\n", GetLastError() );
    failures += expect_aborted( h, &r1, 1 );
    CloseHandle( r1.ov.hEvent );

    /* phase 2: CancelIo (all ops on handle, calling thread) */
    if (!submit_read( h, &r1 )) return 77;
    if (!CancelIo( h ))
        printf( "  note: CancelIo returned err %lu\n", GetLastError() );
    failures += expect_aborted( h, &r1, 2 );
    CloseHandle( r1.ov.hEvent );

    /* phase 3: selectivity — cancel ov1 only, ov2 must survive + complete */
    if (!submit_read( h, &r1 ) || !submit_read( h, &r2 )) return 77;
    if (!CancelIoEx( h, &r1.ov ) && GetLastError() != ERROR_NOT_FOUND)
        printf( "  note: CancelIoEx returned err %lu\n", GetLastError() );
    failures += expect_aborted( h, &r1, 3 );

    WriteFile( wr, "z", 1, &written, NULL );
    if (WaitForSingleObject( r2.ov.hEvent, EVENT_CAP_MS ) != WAIT_OBJECT_0)
    {
        printf( "FAIL: phase 3 surviving read never completed (cancel hit the wrong op?)\n" );
        failures++;
    }
    else if (!GetOverlappedResult( h, &r2.ov, &got, FALSE ) || got != 1 || r2.buf[0] != 'z')
    {
        printf( "FAIL: phase 3 surviving read orr err %lu bytes %lu buf %02x\n",
                GetLastError(), (unsigned long)got, (unsigned char)r2.buf[0] );
        failures++;
    }
    else
        printf( "PASS: phase 3 uncancelled read survived and completed with data\n" );
    CloseHandle( r1.ov.hEvent );
    CloseHandle( r2.ov.hEvent );

    /* NtCancelSynchronousIoFile / cross-thread CancelIoEx of another
     * thread's ring ops are documented residuals — not exercised here. */

    CloseHandle( wr );
    CloseHandle( h );
    if (!failures) printf( "PASS: cancel reaches io_uring bypass ops\n" );
    return failures ? 1 : 0;
}
