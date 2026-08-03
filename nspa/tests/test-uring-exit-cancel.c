/* NSPA U2 io_uring thread-exit reproducer / regression test.
 *
 * Targets dlls/ntdll/unix/io_uring.c ntdll_io_uring_cleanup: rings are
 * per-thread, and before the U2 fix a thread exiting with in-flight ops
 * just called io_uring_queue_exit — kernel-side cancellation is
 * asynchronous, so (a) each op's dup'd unix fd leaked, (b) waiters on the
 * op's overlapped event never saw a completion, and (c) RECVMSG buffers
 * living in the dead thread's TLS op_pool could be written by the kernel
 * after glibc reuses the block.  Windows cancels a thread's pending I/O
 * at thread exit and completes it with STATUS_CANCELLED.
 *
 * Uses the same deterministic client-uring shape as test-uring-sleep-stall:
 * an overlapped read on a filesystem FIFO opened via Z: (real unix fd,
 * FD_TYPE_CHAR, routes through ntdll_io_uring_submit_file_read).
 *
 *   phase 1: T1 submits the read and exits; main waits on the overlapped
 *            event.  Fixed: event set promptly, GetOverlappedResult fails
 *            with ERROR_OPERATION_ABORTED (STATUS_CANCELLED).  Buggy: the
 *            event never fires.
 *   phase 2: fd-leak sentinel — repeat the submit-and-exit shape 8 times
 *            (closing all NT handles each round) and compare the unix fd
 *            count via Z:\proc\self\fd.  Buggy: +1 leaked dup fd per
 *            round.  Skipped silently if procfs enumeration misbehaves.
 *
 * Setup (unix side): mkfifo /tmp/nspa-u2-1.fifo
 * Build: x86_64-w64-mingw32-gcc -O2 -Wall -o test-uring-exit-cancel.exe test-uring-exit-cancel.c
 * Run:   WINEPREFIX=~/Winebox/winebox-master wine ./test-uring-exit-cancel.exe [fifo-dos-path]
 * Exit:  0 = PASS, 1 = FAIL, 77 = SKIP (environment can't exercise the path)
 */
#include <windows.h>
#include <stdio.h>

#define EVENT_CAP_MS   3000
#define LEAK_ROUNDS    8

struct submit_ctx
{
    HANDLE      fifo_rd;
    OVERLAPPED *ov;
    char        buf[16];
    HANDLE      submitted;
    DWORD       pending_ok;
    DWORD       read_err;
};

static DWORD WINAPI submit_and_exit_thread( void *arg )
{
    struct submit_ctx *ctx = arg;
    DWORD ret;

    ret = ReadFile( ctx->fifo_rd, ctx->buf, sizeof(ctx->buf), NULL, ctx->ov );
    ctx->read_err   = ret ? 0 : GetLastError();
    ctx->pending_ok = (!ret && ctx->read_err == ERROR_IO_PENDING);
    SetEvent( ctx->submitted );
    return 0;   /* exit with the op in flight — the behavior under test */
}

/* One submit-and-exit round.  *aborted_out reports whether the completion
 * arrived as ERROR_OPERATION_ABORTED within the cap.  Returns 0 ok,
 * 77 skip (read didn't go async). */
static int one_round( const char *fifo_path, BOOL *aborted_out, DWORD *elapsed_out )
{
    struct submit_ctx ctx = { 0 };
    OVERLAPPED ov = { 0 };
    HANDLE thread, fifo_wr;
    DWORD wait_ret, t0, got = 0;
    BOOL orr;

    *aborted_out = FALSE;
    ctx.ov        = &ov;
    ctx.submitted = CreateEventA( NULL, FALSE, FALSE, NULL );
    ov.hEvent     = CreateEventA( NULL, TRUE, FALSE, NULL );

    ctx.fifo_rd = CreateFileA( fifo_path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED, NULL );
    if (ctx.fifo_rd == INVALID_HANDLE_VALUE)
    {
        printf( "SKIP: cannot open fifo %s (err %lu) — run mkfifo first\n",
                fifo_path, GetLastError() );
        return 77;
    }
    /* Hold a writer open (never written to): a FIFO read end with no
     * writer returns EOF instead of EAGAIN, which would bypass the async
     * submit entirely. */
    fifo_wr = CreateFileA( fifo_path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );
    if (fifo_wr == INVALID_HANDLE_VALUE)
    {
        printf( "SKIP: cannot open fifo write end (err %lu)\n", GetLastError() );
        CloseHandle( ctx.fifo_rd );
        return 77;
    }

    thread = CreateThread( NULL, 0, submit_and_exit_thread, &ctx, 0, NULL );
    WaitForSingleObject( ctx.submitted, 5000 );
    if (!ctx.pending_ok)
    {
        printf( "SKIP: read did not go async (err %lu) — io_uring file path not active\n",
                (unsigned long)ctx.read_err );
        CloseHandle( ctx.fifo_rd );
        CloseHandle( fifo_wr );
        return 77;
    }
    WaitForSingleObject( thread, 5000 );   /* let the submitter exit */
    CloseHandle( thread );

    t0 = GetTickCount();
    wait_ret = WaitForSingleObject( ov.hEvent, EVENT_CAP_MS );
    *elapsed_out = GetTickCount() - t0;

    if (wait_ret == WAIT_OBJECT_0)
    {
        orr = GetOverlappedResult( ctx.fifo_rd, &ov, &got, FALSE );
        *aborted_out = (!orr && GetLastError() == ERROR_OPERATION_ABORTED);
        if (!*aborted_out)
            printf( "  note: completion arrived but orr=%d bytes=%lu err=%lu (want OPERATION_ABORTED)\n",
                    orr, (unsigned long)got, GetLastError() );
    }

    CloseHandle( fifo_wr );
    CloseHandle( ctx.fifo_rd );
    CloseHandle( ov.hEvent );
    CloseHandle( ctx.submitted );
    return 0;
}

static int count_unix_fds( void )
{
    WIN32_FIND_DATAA fd;
    HANDLE find;
    int n = 0;

    find = FindFirstFileA( "Z:\\proc\\self\\fd\\*", &fd );
    if (find == INVALID_HANDLE_VALUE) return -1;
    do { n++; } while (FindNextFileA( find, &fd ));
    FindClose( find );
    return n;
}

/* Control for the leak sentinel: wine itself may hold a small number of
 * fds per created/exited thread (TLS/sched plumbing) independent of any
 * I/O.  Measure that so phase 2 only charges io_uring for growth beyond
 * it. */
static DWORD WINAPI noop_thread( void *arg ) { return 0; }

static int control_growth( void )
{
    int i, before, after;
    before = count_unix_fds();
    if (before < 0) return -1;
    for (i = 0; i < LEAK_ROUNDS; i++)
    {
        HANDLE t = CreateThread( NULL, 0, noop_thread, NULL, 0, NULL );
        if (!t) return -1;
        WaitForSingleObject( t, 5000 );
        CloseHandle( t );
    }
    after = count_unix_fds();
    return (after < 0) ? -1 : after - before;
}

int main( int argc, char **argv )
{
    const char *fifo = (argc > 1) ? argv[1] : "Z:\\tmp\\nspa-u2-1.fifo";
    BOOL aborted = FALSE;
    DWORD elapsed = 0;
    int rc, i, fds_before, fds_after, failures = 0;

    /* phase 1: exit-cancel completes the waiter */
    rc = one_round( fifo, &aborted, &elapsed );
    if (rc == 77) return 77;
    if (aborted)
        printf( "PASS: phase 1 exit cancelled the op in %lums (ERROR_OPERATION_ABORTED)\n",
                (unsigned long)elapsed );
    else
    {
        printf( "FAIL: phase 1 overlapped event not completed within %ums of submitter exit\n",
                EVENT_CAP_MS );
        failures++;
    }

    /* phase 2: fd-leak sentinel, charged against a no-I/O thread-churn
     * control (wine holds ~1 fd per exited thread regardless of I/O). */
    {
        int ctl = control_growth();

        fds_before = count_unix_fds();
        if (ctl >= 0 && fds_before > 0)
        {
            int io_growth;

            for (i = 0; i < LEAK_ROUNDS; i++)
            {
                rc = one_round( fifo, &aborted, &elapsed );
                if (rc == 77) break;
            }
            fds_after = count_unix_fds();
            io_growth = fds_after - fds_before;
            if (io_growth > ctl + 2)
            {
                printf( "FAIL: phase 2 fd growth %d over %d I/O rounds vs %d control (leaked dup fds)\n",
                        io_growth, LEAK_ROUNDS, ctl );
                failures++;
            }
            else
                printf( "PASS: phase 2 fd growth %d over %d I/O rounds (control %d)\n",
                        io_growth, LEAK_ROUNDS, ctl );
        }
        else
            printf( "note: phase 2 skipped (Z:\\proc\\self\\fd not enumerable)\n" );
    }

    if (!failures) printf( "PASS: thread-exit cancellation delivers and leaks nothing\n" );
    return failures ? 1 : 0;
}
