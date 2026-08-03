/* NSPA U3 io_uring completion-stall reproducer / regression test.
 *
 * Targets dlls/ntdll/unix/io_uring.c + sync.c NtDelayExecution: rings are
 * per-thread SINGLE_ISSUER, so only the submitting thread can drain its
 * CQEs and deliver completions (event set / IOSB write).  Before the U3
 * fix a thread that submitted an overlapped read and then slept
 * non-alertably (plain clock_nanosleep — no drain point) sat on the
 * completion for the whole sleep: another thread waiting on the
 * overlapped event stalled until the sleeper woke, and Sleep(INFINITE)
 * stalled it forever.  Windows delivers I/O completions regardless of
 * submitter state.
 *
 * Path selection (validated 2026-08-02 — the obvious candidates do NOT
 * route through the client ring on current defaults):
 *  - named/anonymous pipes: server pseudo-fd objects (alloc_pseudo_fd),
 *    asyncs server-delivered.
 *  - overlapped socket recv on an empty socket: recv_socket returns
 *    PENDING (not ALERTED), async stays server-owned, APC/signal-delivered.
 *  - overlapped socket send: intercept requires a full-EAGAIN
 *    (!async->sent_len); partial TCP sends re-arm server-side.
 *  - a filesystem FIFO opened via the Z: drive is a REAL unix fd typed
 *    FD_TYPE_CHAR (server file_get_fd_type), and an overlapped read on an
 *    empty FIFO deterministically reaches
 *    ntdll_io_uring_submit_file_read — no race window.  That is the shape
 *    used here.
 *
 * Repro: T1 overlapped-ReadFiles the (empty) FIFO read end — the SQE is
 * now in T1's ring — then sleeps.  Main writes a byte into the FIFO's
 * write end ~300ms later and waits on the overlapped event with a 3s cap.
 *   phase 1: T1 sleeps 4s (finite)   — fixed: event ~300ms; buggy: ~4s.
 *   phase 2: T1 sleeps INFINITE      — fixed: event ~300ms; buggy: never.
 * The test SKIPs (exit 77) if the read completes synchronously or fails —
 * that means the environment didn't provide the io_uring path at all.
 *
 * Setup (unix side): mkfifo /tmp/nspa-u3-1.fifo /tmp/nspa-u3-2.fifo
 * Build: x86_64-w64-mingw32-gcc -O2 -Wall -o test-uring-sleep-stall.exe test-uring-sleep-stall.c
 * Run:   WINEPREFIX=~/Winebox/winebox-master wine ./test-uring-sleep-stall.exe \
 *            [fifo1-dos-path] [fifo2-dos-path]
 *        (defaults: Z:\tmp\nspa-u3-1.fifo, Z:\tmp\nspa-u3-2.fifo)
 *   buggy build  => FAIL lines (event late / never)
 *   fixed build  => "PASS: completions delivered during non-alertable sleep"
 */
#include <windows.h>
#include <stdio.h>

#define STALL_MS       4000     /* phase 1 finite sleep, > wait cap */
#define WAIT_CAP_MS    3000     /* waiter gives up after this */
#define DELIVER_MAX_MS 1500     /* fixed build must deliver within this */

struct phase_ctx
{
    DWORD       sleep_ms;       /* INFINITE for phase 2 */
    HANDLE      fifo_rd;        /* overlapped read end */
    OVERLAPPED  ov;
    char        buf[16];
    HANDLE      submitted;      /* T1 -> main: read pending, sleep starts */
    DWORD       pending_ok;
    DWORD       read_ret;       /* raw ReadFile return + error for SKIP diag */
    DWORD       read_err;
};

static DWORD WINAPI stall_thread( void *arg )
{
    struct phase_ctx *ctx = arg;

    ctx->read_ret   = ReadFile( ctx->fifo_rd, ctx->buf, sizeof(ctx->buf), NULL, &ctx->ov );
    ctx->read_err   = ctx->read_ret ? 0 : GetLastError();
    ctx->pending_ok = (!ctx->read_ret && ctx->read_err == ERROR_IO_PENDING);
    SetEvent( ctx->submitted );
    if (!ctx->pending_ok) return 1;

    Sleep( ctx->sleep_ms );     /* non-alertable — the stall under test */
    return 0;
}

/* 0 = pass, 1 = fail, 77 = skip (path not available in this environment) */
static int run_phase( int phase, const char *fifo_path, DWORD sleep_ms )
{
    struct phase_ctx ctx = { 0 };
    HANDLE fifo_wr, thread;
    DWORD wait_ret, t0, elapsed, written = 0, got = 0;

    ctx.sleep_ms  = sleep_ms;
    ctx.submitted = CreateEventA( NULL, FALSE, FALSE, NULL );
    ctx.ov.hEvent = CreateEventA( NULL, TRUE, FALSE, NULL );

    /* read end FIRST (a write-end open with no reader fails), overlapped */
    ctx.fifo_rd = CreateFileA( fifo_path, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED, NULL );
    if (ctx.fifo_rd == INVALID_HANDLE_VALUE)
    {
        printf( "SKIP: phase %d cannot open fifo %s for read (err %lu) — run mkfifo first\n",
                phase, fifo_path, GetLastError() );
        return 77;
    }
    fifo_wr = CreateFileA( fifo_path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );
    if (fifo_wr == INVALID_HANDLE_VALUE)
    {
        printf( "SKIP: phase %d cannot open fifo write end (err %lu)\n", phase, GetLastError() );
        return 77;
    }

    thread = CreateThread( NULL, 0, stall_thread, &ctx, 0, NULL );
    WaitForSingleObject( ctx.submitted, 5000 );
    if (!ctx.pending_ok)
    {
        printf( "SKIP: phase %d read did not go async (ret=%lu err=%lu) — io_uring file path not active\n",
                phase, (unsigned long)ctx.read_ret, (unsigned long)ctx.read_err );
        return 77;
    }

    Sleep( 300 );               /* let T1 be well inside its sleep */
    WriteFile( fifo_wr, "x", 1, &written, NULL );

    t0 = GetTickCount();
    wait_ret = WaitForSingleObject( ctx.ov.hEvent, WAIT_CAP_MS );
    elapsed = GetTickCount() - t0;

    if (wait_ret != WAIT_OBJECT_0)
    {
        printf( "FAIL: phase %d overlapped event not set within %ums (sleeper owes the completion)\n",
                phase, WAIT_CAP_MS );
        return 1;
    }
    if (elapsed > DELIVER_MAX_MS)
    {
        printf( "FAIL: phase %d event arrived after %lums (> %ums — delivered by sleep END, not CQE)\n",
                phase, (unsigned long)elapsed, DELIVER_MAX_MS );
        return 1;
    }
    if (!GetOverlappedResult( ctx.fifo_rd, &ctx.ov, &got, FALSE ) || got != 1 || ctx.buf[0] != 'x')
    {
        printf( "FAIL: phase %d GetOverlappedResult bytes=%lu buf=%02x err=%lu\n",
                phase, (unsigned long)got, (unsigned char)ctx.buf[0], GetLastError() );
        return 1;
    }

    printf( "PASS: phase %d completion delivered in %lums during non-alertable sleep(%s)\n",
            phase, (unsigned long)elapsed, sleep_ms == INFINITE ? "INFINITE" : "finite" );

    /* Phase 1's sleeper wakes on its own; phase 2's sleeps forever — leave
     * it, process exit reaps it. */
    if (sleep_ms != INFINITE) WaitForSingleObject( thread, STALL_MS + 2000 );

    CloseHandle( fifo_wr );
    CloseHandle( ctx.fifo_rd );
    return 0;
}

int main( int argc, char **argv )
{
    const char *fifo1 = (argc > 1) ? argv[1] : "Z:\\tmp\\nspa-u3-1.fifo";
    const char *fifo2 = (argc > 2) ? argv[2] : "Z:\\tmp\\nspa-u3-2.fifo";
    int r1, r2;

    r1 = run_phase( 1, fifo1, STALL_MS );
    r2 = run_phase( 2, fifo2, INFINITE );

    if (r1 == 77 || r2 == 77) return 77;
    if (r1 || r2) return 1;
    printf( "PASS: completions delivered during non-alertable sleep\n" );
    return 0;
}
