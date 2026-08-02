/* NSPA M1-A SEND-timeout double-delivery reproducer.
 *
 * Targets dlls/win32u/nspa/msg_ring.c nspa_try_send_ring: before the M1-A
 * fix, a cross-thread SendMessage whose receiver did not pump for >2s hit
 * the ring reply timeout, which freed only the sender's reply slot and fell
 * back to the server send path WITHOUT retracting the still-READY ring
 * message slot.  The receiver then dispatched BOTH copies: the ring slot
 * (reply dropped by the MR1 stale/gen check) and the server message — one
 * SendMessage, two window-proc executions.
 *
 * Three phases, each asserting the winproc ran EXACTLY once per send:
 *   1. baseline    — receiver pumping; ring fast path end-to-end.
 *   2. stall       — receiver sleeps 3.5s without pumping; sender's 2s cap
 *                    must RETRACT the ring slot (receiver never claimed it)
 *                    and re-send via the server: one execution, not two.
 *   3. slow-winproc— receiver claims the message promptly but the winproc
 *                    itself sleeps 4s.  The sender's 2s cap fires while the
 *                    message is CLAIMED: retraction loses, so the sender
 *                    must keep waiting for the real reply instead of
 *                    re-sending (SendMessage has no timeout semantics).
 *
 * Build: x86_64-w64-mingw32-gcc -O2 -o test-send-timeout-dup.exe test-send-timeout-dup.c -luser32
 * Run:   WINEPREFIX=~/Winebox/winebox-master wine ./test-send-timeout-dup.exe
 *   buggy build  => "FAIL" lines (count==2 in phases 2/3)
 *   fixed build  => "PASS: all phases delivered exactly once"
 */
#include <windows.h>
#include <stdio.h>

#define TEST_MSG        (WM_APP + 0x11)
#define N_PHASES        3
#define PHASE_STALL_MS  3500    /* > the 2s ring reply cap */
#define WINPROC_NAP_MS  4000    /* phase 3: winproc busy past the 2s cap */
#define RESULT_COOKIE(p) ((LRESULT)(0xC0DE0000u | (unsigned)(p)))

static volatile LONG winproc_hits[N_PHASES + 1];
static HANDLE phase_start[N_PHASES + 1];   /* main -> sender: begin phase N */
static HANDLE phase_done[N_PHASES + 1];    /* sender -> main: phase N send returned */
static HWND   target_hwnd;

struct send_record
{
    LRESULT result;
    DWORD   elapsed_ms;
};
static struct send_record sends[N_PHASES + 1];

static LRESULT CALLBACK test_wndproc( HWND hwnd, UINT msg, WPARAM wp, LPARAM lp )
{
    if (msg == TEST_MSG)
    {
        int phase = (int)wp;
        if (phase >= 1 && phase <= N_PHASES) InterlockedIncrement( (LONG *)&winproc_hits[phase] );
        if (lp) Sleep( (DWORD)lp );        /* phase 3: stall inside the winproc */
        return RESULT_COOKIE( phase );
    }
    return DefWindowProcW( hwnd, msg, wp, lp );
}

static DWORD WINAPI sender_main( void *arg )
{
    int phase;

    for (phase = 1; phase <= N_PHASES; phase++)
    {
        LPARAM nap = (phase == 3) ? WINPROC_NAP_MS : 0;
        DWORD t0;

        WaitForSingleObject( phase_start[phase], INFINITE );
        if (phase == 2) Sleep( 200 );      /* let the receiver enter its no-pump stall */

        t0 = GetTickCount();
        sends[phase].result = SendMessageW( target_hwnd, TEST_MSG, (WPARAM)phase, nap );
        sends[phase].elapsed_ms = GetTickCount() - t0;

        SetEvent( phase_done[phase] );
    }
    return 0;
}

/* Pump until @done signals, or fail the test on @timeout_ms. */
static BOOL pump_until( HANDLE done, DWORD timeout_ms )
{
    DWORD start = GetTickCount();

    for (;;)
    {
        DWORD elapsed = GetTickCount() - start;
        DWORD wait_ret;
        MSG msg;

        if (elapsed >= timeout_ms) return FALSE;
        wait_ret = MsgWaitForMultipleObjects( 1, &done, FALSE, timeout_ms - elapsed, QS_ALLINPUT );
        if (wait_ret == WAIT_OBJECT_0) return TRUE;
        if (wait_ret != WAIT_OBJECT_0 + 1) return FALSE;
        while (PeekMessageW( &msg, NULL, 0, 0, PM_REMOVE ))
        {
            TranslateMessage( &msg );
            DispatchMessageW( &msg );
        }
    }
}

int main( void )
{
    WNDCLASSW wc = { 0 };
    HANDLE sender;
    int phase, failures = 0;

    wc.lpfnWndProc   = test_wndproc;
    wc.hInstance     = GetModuleHandleW( NULL );
    wc.lpszClassName = L"nspa_m1a_dup_test";
    RegisterClassW( &wc );

    target_hwnd = CreateWindowExW( 0, wc.lpszClassName, L"m1a", WS_OVERLAPPED,
                                   0, 0, 64, 64, NULL, NULL, wc.hInstance, NULL );
    if (!target_hwnd)
    {
        printf( "FAIL: CreateWindowExW error %lu\n", GetLastError() );
        return 2;
    }

    for (phase = 1; phase <= N_PHASES; phase++)
    {
        phase_start[phase] = CreateEventW( NULL, FALSE, FALSE, NULL );
        phase_done[phase]  = CreateEventW( NULL, FALSE, FALSE, NULL );
    }
    sender = CreateThread( NULL, 0, sender_main, NULL, 0, NULL );
    if (!sender)
    {
        printf( "FAIL: CreateThread error %lu\n", GetLastError() );
        return 2;
    }

    /* Phase 1: receiver pumping normally. */
    SetEvent( phase_start[1] );
    if (!pump_until( phase_done[1], 10000 )) { printf( "FAIL: phase 1 timed out\n" ); return 2; }

    /* Phase 2: stall without pumping past the sender's 2s cap, then resume. */
    SetEvent( phase_start[2] );
    Sleep( PHASE_STALL_MS );               /* sender's SendMessage arrives ~200ms in */
    if (!pump_until( phase_done[2], 15000 )) { printf( "FAIL: phase 2 timed out\n" ); return 2; }

    /* Phase 3: pump promptly; the winproc itself stalls past the cap. */
    SetEvent( phase_start[3] );
    if (!pump_until( phase_done[3], 20000 )) { printf( "FAIL: phase 3 timed out\n" ); return 2; }

    WaitForSingleObject( sender, 5000 );

    for (phase = 1; phase <= N_PHASES; phase++)
    {
        LONG hits = winproc_hits[phase];
        BOOL ok = (hits == 1) && (sends[phase].result == RESULT_COOKIE( phase ));

        printf( "%s: phase %d  winproc_hits=%ld  result=%08lx (want %08lx)  elapsed=%lums\n",
                ok ? "PASS" : "FAIL", phase, (long)hits,
                (unsigned long)sends[phase].result,
                (unsigned long)RESULT_COOKIE( phase ),
                (unsigned long)sends[phase].elapsed_ms );
        if (!ok) failures++;
    }
    /* Phase 3 must also have actually waited out the winproc nap — a fast
     * return would mean the sender bailed early instead of waiting. */
    if (sends[3].elapsed_ms < WINPROC_NAP_MS - 200)
    {
        printf( "FAIL: phase 3 returned after %lums (< winproc nap %ums) — sender did not wait\n",
                (unsigned long)sends[3].elapsed_ms, WINPROC_NAP_MS );
        failures++;
    }

    if (!failures) printf( "PASS: all phases delivered exactly once\n" );
    return failures ? 1 : 0;
}
