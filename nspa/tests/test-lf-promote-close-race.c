/* NSPA L4 local-file lazy-promote vs concurrent-close reproducer.
 *
 * Targets dlls/ntdll/unix/nspa/local_file.c
 * nspa_local_file_get_or_promote_server_handle: before the L4 fix the
 * promote path snapshotted the entry's raw unix fd under the table lock,
 * dropped the lock, and only then wine_server_send_fd'd it.  A concurrent
 * NtClose could close that fd in the window, and an unrelated open would
 * reuse the fd number (kernel lowest-fd policy) — the server then minted
 * a struct fd over the WRONG file and registered it in its sharing
 * tables.  The store-back found no entry (or, after a 16K-slot handle
 * wrap, a recycled entry for a different file) and the orphaned server
 * handle was never closed: a permanent leak whose sharing registration
 * inflicts phantom SHARING_VIOLATIONs on the innocent file.
 *
 * Repro shape (fd-reuse variant — the slot-reuse variant needs a 16384
 * handle wrap and is covered by the same fix):
 *   loop: open A read/share-all (LF bypass local handle)
 *         promoter thread: LockFileEx(A) — lock_file is server-mediated,
 *             forcing the lazy promote
 *         main: immediately CloseHandle(A), open+close B (grabs A's just
 *             freed unix fd number)
 *   probe: exclusive-write CreateFile of A and of B must succeed — a
 *          persistent SHARING_VIOLATION means a leaked server-side open.
 *
 * This is a probabilistic hammer: a FAIL is definitive corruption; a
 * PASS on a buggy build is possible for any single run (the window is
 * microseconds), but the fixed build passes structurally (fd dup'd under
 * the table lock; orphaned promotions closed on every non-install path).
 *
 * Build: x86_64-w64-mingw32-gcc -O2 -Wall -o test-lf-promote-close-race.exe test-lf-promote-close-race.c
 * Run:   WINEPREFIX=~/Winebox/winebox-master wine ./test-lf-promote-close-race.exe
 * Exit:  0 = PASS, 1 = FAIL, 77 = SKIP
 */
#include <windows.h>
#include <stdio.h>

#define PATH_A     "Z:\\tmp\\nspa_l4_a.dat"
#define PATH_B     "Z:\\tmp\\nspa_l4_b.dat"
#define ITERATIONS 3000
#define PROBE_EVERY 256

static HANDLE go_event, done_event;
static volatile HANDLE race_handle;
static volatile LONG promoter_quit;

static DWORD WINAPI promoter_main( void *arg )
{
    for (;;)
    {
        OVERLAPPED ov = { 0 };
        HANDLE h;

        WaitForSingleObject( go_event, INFINITE );
        if (promoter_quit) break;
        h = race_handle;
        /* Server-mediated byte-range lock — forces the lazy promote.
         * The handle may be closed under us mid-call; any error is fine,
         * the promote attempt is what matters. */
        if (LockFileEx( h, LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ov ))
            UnlockFileEx( h, 0, 1, 0, &ov );
        SetEvent( done_event );
    }
    return 0;
}

static int make_file( const char *path )
{
    HANDLE h = CreateFileA( path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL );
    DWORD written;
    if (h == INVALID_HANDLE_VALUE) return 0;
    WriteFile( h, "x", 1, &written, NULL );
    CloseHandle( h );
    return 1;
}

/* Exclusive-open probe with one retry (absorbs transient deferred-close
 * artifacts; a leaked server open is permanent). */
static int probe_exclusive( const char *path, const char *tag, int iter )
{
    int attempt;
    for (attempt = 0; attempt < 2; attempt++)
    {
        HANDLE h = CreateFileA( path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, NULL );
        if (h != INVALID_HANDLE_VALUE)
        {
            CloseHandle( h );
            return 0;
        }
        if (GetLastError() != ERROR_SHARING_VIOLATION)
        {
            printf( "FAIL: probe %s open error %lu (iter %d)\n", tag, GetLastError(), iter );
            return 1;
        }
        Sleep( 100 );
    }
    printf( "FAIL: persistent SHARING_VIOLATION on %s (iter %d) — leaked server-side open\n",
            tag, iter );
    return 1;
}

int main( void )
{
    HANDLE promoter;
    int i, failures = 0;

    if (!make_file( PATH_A ) || !make_file( PATH_B ))
    {
        printf( "SKIP: cannot create %s / %s\n", PATH_A, PATH_B );
        return 77;
    }

    go_event   = CreateEventA( NULL, FALSE, FALSE, NULL );
    done_event = CreateEventA( NULL, FALSE, FALSE, NULL );
    promoter   = CreateThread( NULL, 0, promoter_main, NULL, 0, NULL );
    if (!promoter)
    {
        printf( "SKIP: CreateThread error %lu\n", GetLastError() );
        return 77;
    }

    for (i = 0; i < ITERATIONS && !failures; i++)
    {
        HANDLE ha, hb;

        ha = CreateFileA( PATH_A, GENERIC_READ,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
        if (ha == INVALID_HANDLE_VALUE) { printf( "SKIP: open A failed %lu\n", GetLastError() ); return 77; }

        race_handle = ha;
        SetEvent( go_event );

        /* Vary the interleaving: sometimes close instantly, sometimes
         * give the promoter a head start into its RPC. */
        if (i & 1) { volatile int spin = (i * 7) & 1023; while (spin--) ; }

        CloseHandle( ha );                 /* frees A's unix fd */
        hb = CreateFileA( PATH_B, GENERIC_READ,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
        if (hb != INVALID_HANDLE_VALUE) CloseHandle( hb );  /* likely reused A's fd */

        WaitForSingleObject( done_event, 5000 );

        if ((i % PROBE_EVERY) == PROBE_EVERY - 1)
        {
            failures += probe_exclusive( PATH_A, "A", i );
            if (!failures) failures += probe_exclusive( PATH_B, "B", i );
        }
    }

    /* Final probes. */
    if (!failures)
    {
        failures += probe_exclusive( PATH_A, "A", ITERATIONS );
        if (!failures) failures += probe_exclusive( PATH_B, "B", ITERATIONS );
    }

    promoter_quit = 1;
    SetEvent( go_event );
    WaitForSingleObject( promoter, 3000 );

    DeleteFileA( PATH_A );
    DeleteFileA( PATH_B );

    if (!failures)
        printf( "PASS: %d promote-vs-close races, no leaked server opens (exclusive probes clean)\n",
                ITERATIONS );
    return failures ? 1 : 0;
}
