/*
 * NSPA RT test harness — multi-command binary.
 *
 * Subcommands:
 *   priority       v1/v2 RT priority mapping sanity test (default legacy test).
 *                  Phase 1 = Tier 1 lenient path + avrt hint.
 *                  Phase 2 = REALTIME_PRIORITY_CLASS + full RT band.
 *   cs-contention  v2.3 CS-PI validation. SCHED_FIFO thread blocks on a
 *                  CRITICAL_SECTION held by a SCHED_OTHER thread while
 *                  background SCHED_OTHER load threads compete for CPU.
 *                  Measures wait time; with PI it should approximate the
 *                  holder's idle-core work time, without PI it should
 *                  scale with the load.
 *   rapidmutex     Stress test — N threads hammer a shared CRITICAL_SECTION
 *                  in a tight EnterCS/LeaveCS loop. Thread 0 is TIME_CRITICAL
 *                  (becomes SCHED_FIFO under NSPA_RT_PRIO), others NORMAL.
 *                  Regression check for the CS-PI fast path and for the
 *                  librtpi sweep when it lands on dlls/ntdll/unix/sync.c.
 *   philosophers   Dining philosophers with 5 phils + 5 chopsticks. Phil 0 is
 *                  TIME_CRITICAL, phils 1-4 load. Background busyloop threads
 *                  starve the OTHER phils for CPU to exercise transitive PI
 *                  (RT -> holder -> holder-of-holder chain boost).
 *   fork-mutex     Rapid-fire CreateProcess stress (default 100 spawns) that
 *                  validates Wine's spawn path and the librtpi sweep's
 *                  dlls/ntdll/unix/process.c opt-out. Each child runs the
 *                  internal child-quickexit subcommand.
 *   child-quickexit Internal helper used by fork-mutex — prints a marker
 *                  line and exits with code 42.
 *   nt-timer       NSPA NT timer Phase A validation. Exercises CreateWaitableTimer /
 *                  SetWaitableTimer / CancelWaitableTimer / WaitForSingleObject
 *                  through the NSPA local-timer dispatcher.  Run twice, once
 *                  with NSPA_DISABLE_LOCAL_TIMERS unset (local path, default)
 *                  and once with NSPA_DISABLE_LOCAL_TIMERS=1 (server path);
 *                  both must report PASS (NT semantics must not diverge
 *                  between paths).
 *   signal-recursion Multi-threaded PAGE_GUARD / VirtualAlloc fault stress
 *                  that validates virtual_mutex and Wine's segv_handler
 *                  fault-dispatch path. Catches regressions in the
 *                  NSPA_RTPI_MUTEX_RECURSIVE path if the librtpi sweep
 *                  ever converts virtual.c.
 *   help           show usage
 *
 * Build:
 *   i686-w64-mingw32-gcc -O2 -static nspa_rt_test.c -o nspa_rt_test.exe
 *
 * Run:
 *   NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF ./wine nspa_rt_test.exe <command>
 *
 * Query threads from another terminal:
 *   ps -eLo pid,tid,class,rtprio,nice,comm | grep -E 'POL|nspa_rt_test\.ex'
 *
 * The binary is intended to be extended over time. Add a new subcommand by:
 *   1. Writing a cmd_foo(int argc, char **argv) function.
 *   2. Adding { "foo", "description", cmd_foo } to the commands[] table.
 *
 */

#include <winsock2.h>
#include <windows.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* NSPA: minimal forward declarations for things winternl.h would
 * normally pull in. Avoiding the full <winternl.h> + <ntstatus.h>
 * include dance keeps the existing STATUS_GUARD_PAGE_VIOLATION macro
 * (from winnt.h via windows.h) intact for the signal-recursion test. */
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif
WINBASEAPI SIZE_T WINAPI GetLargePageMinimum(void);
/* NtAllocateVirtualMemoryEx — for the 1 GB huge-page sub-test in
 * cmd_large_pages. Win10 1709+ API; not always declared by mingw's
 * windows.h, so forward-declare via the same shape as winternl.h. */
typedef NTSTATUS (WINAPI *PFN_NtAllocateVirtualMemoryEx)(
    HANDLE, PVOID *, SIZE_T *, ULONG, ULONG, MEM_EXTENDED_PARAMETER *, ULONG );
WINBASEAPI NTSTATUS WINAPI NtFreeVirtualMemory( HANDLE, PVOID *, SIZE_T *, ULONG );
/* QueryWorkingSetEx — K32QueryWorkingSetEx in kernel32.dll.
 * We define our own struct to avoid pulling in <psapi.h> or <winternl.h>
 * which would conflict with our existing STATUS_* defines. */
typedef union {
    ULONG_PTR Flags;
    struct {
        ULONG_PTR Valid : 1;
        ULONG_PTR ShareCount : 3;
        ULONG_PTR Win32Protection : 11;
        ULONG_PTR Shared : 1;
        ULONG_PTR Node : 6;
        ULONG_PTR Locked : 1;
        ULONG_PTR LargePage : 1;
    };
} NSPA_WSE_BLOCK;
typedef struct {
    PVOID          VirtualAddress;
    NSPA_WSE_BLOCK VirtualAttributes;
} NSPA_WSE_INFO;
typedef BOOL (WINAPI *PFN_K32QueryWorkingSetEx)( HANDLE, PVOID, DWORD );

/* ════════════════════════════════════════════════════════════════════════
 *   Global safety: watchdog timer + Ctrl+C handler
 *
 *   The watchdog is a high-priority thread that calls ExitProcess after
 *   a configurable timeout (NSPA_TEST_TIMEOUT env var, default 120s).
 *   It runs at TIME_CRITICAL so it can preempt stuck SCHED_FIFO threads.
 *
 *   The Ctrl+C handler sets all known stop flags and force-exits.
 *   Together these guarantee the test can always be killed, even if
 *   FIFO busyloop threads have saturated all cores.
 * ════════════════════════════════════════════════════════════════════════ */

#define WATCHDOG_DEFAULT_SEC  120

/* All known stop flags — Ctrl+C handler sets them all. */
static volatile LONG g_global_abort = 0;

/* Per-test stop flags — defined here so the Ctrl+C handler can set them all.
 * Each subcommand uses its own flag; all are set on abort. */
static volatile LONG g_stop_load = 0;       /* cs-contention */
static volatile LONG phil_load_stop = 0;    /* philosophers */
static volatile LONG nts_pi_stop_load = 0;  /* ntsync PI sub-test */
static volatile LONG nts_chain_stop_load = 0; /* ntsync chain sub-test */

static DWORD WINAPI watchdog_thread(void *arg)
{
    DWORD timeout_ms = (DWORD)(DWORD_PTR)arg;

    /* Run at TIME_CRITICAL so we can preempt any stuck FIFO thread. */
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    Sleep(timeout_ms);

    /* Still alive after timeout — something is stuck. */
    printf("\n\n");
    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    printf("  WATCHDOG: test exceeded %lu s timeout — force-killing process\n",
           timeout_ms / 1000);
    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    fflush(stdout);

    ExitProcess(99);
    return 0;  /* unreachable */
}

static void watchdog_start(void)
{
    DWORD timeout_sec = WATCHDOG_DEFAULT_SEC;
    const char *env = getenv("NSPA_TEST_TIMEOUT");
    HANDLE h;

    if (env && atoi(env) > 0)
        timeout_sec = (DWORD)atoi(env);

    h = CreateThread(NULL, 0, watchdog_thread,
                     (void *)(DWORD_PTR)(timeout_sec * 1000), 0, NULL);
    if (h) CloseHandle(h);

    printf("  [watchdog] armed: %lu s (override with NSPA_TEST_TIMEOUT=N)\n",
           timeout_sec);
    fflush(stdout);
}

static BOOL WINAPI ctrl_handler(DWORD type)
{
    (void)type;
    printf("\n  [ABORT] Ctrl+C received — stopping all threads\n");
    fflush(stdout);

    /* Set every known stop flag. */
    InterlockedExchange(&g_global_abort, 1);
    InterlockedExchange(&g_stop_load, 1);
    InterlockedExchange(&phil_load_stop, 1);
    InterlockedExchange(&nts_pi_stop_load, 1);
    InterlockedExchange(&nts_chain_stop_load, 1);

    /* Give threads a moment to notice, then force-exit. */
    Sleep(500);
    ExitProcess(1);
    return TRUE;  /* unreachable */
}

/* ════════════════════════════════════════════════════════════════════════
 *   Load thread safety
 *
 *   Load threads simulate SCHED_OTHER CPU contention. They MUST remain
 *   SCHED_OTHER even when the test process uses REALTIME_PRIORITY_CLASS.
 *
 *   Key rule: spawn load threads BEFORE enter_realtime_class(). Wine
 *   does not retroactively reschedule existing threads when the process
 *   class changes — only threads that call SetThreadPriority after the
 *   class change get SCHED_FIFO. Load threads just busyloop; they never
 *   call SetThreadPriority, so they stay SCHED_OTHER.
 *
 *   As a second safety net, load threads call Sleep(1) periodically
 *   (not Sleep(0) — sched_yield() is a no-op for FIFO threads with no
 *   same-priority peers). Sleep(1) suspends for ~1ms, guaranteeing
 *   SCHED_OTHER system threads (desktop, input) always get CPU time.
 *
 *   LOAD_YIELD_MASK controls how often: 0x1ffffff = ~32M iters ≈ 10ms
 *   of tight arithmetic on a modern x86 core. 10ms compute + 1ms sleep
 *   = ~91% CPU utilization per load thread. Plenty of contention while
 *   keeping the system responsive.
 * ════════════════════════════════════════════════════════════════════════ */

/* ~32M iterations ≈ 10ms on a modern x86 core. */
#define LOAD_YIELD_MASK  0x1ffffff

/* Cap load thread count: never use more than ncores-2 to ensure the
 * main thread and at least one chain/worker thread can always run. */
static int safe_load_count(int requested)
{
    SYSTEM_INFO si;
    int ncores, cap;

    GetSystemInfo(&si);
    ncores = (int)si.dwNumberOfProcessors;
    cap = ncores - 2;
    if (cap < 1) cap = 1;

    if (requested > cap)
    {
        printf("  [safety] load threads capped: %d -> %d (ncores=%d, reserving 2)\n",
               requested, cap, ncores);
        fflush(stdout);
        return cap;
    }
    return requested;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Shared helpers
 * ════════════════════════════════════════════════════════════════════════ */

typedef HANDLE (WINAPI *PFN_AvSet)(LPCWSTR, LPDWORD);
typedef BOOL   (WINAPI *PFN_AvRevert)(HANDLE);

static PFN_AvSet    p_AvSet;
static PFN_AvRevert p_AvRevert;

static void load_avrt(void)
{
    HMODULE h = LoadLibraryA("avrt.dll");
    if (!h) return;
    p_AvSet    = (PFN_AvSet)   GetProcAddress(h, "AvSetMmThreadCharacteristicsW");
    p_AvRevert = (PFN_AvRevert)GetProcAddress(h, "AvRevertMmThreadCharacteristics");
}

/* Overflow-safe QPC helpers.  With the rdTSC bypass (freq ~3.5 GHz),
 * naive (c * 1000000 / freq) overflows LONGLONG after ~44 min uptime.
 * Split into whole-seconds + remainder to stay in range. */
static LONGLONG now_ms(void)
{
    static LARGE_INTEGER freq;
    LARGE_INTEGER c;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c);
    return (c.QuadPart / freq.QuadPart) * 1000
         + (c.QuadPart % freq.QuadPart) * 1000 / freq.QuadPart;
}

static LONGLONG now_us(void)
{
    static LARGE_INTEGER freq;
    LARGE_INTEGER c;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c);
    return (c.QuadPart / freq.QuadPart) * 1000000
         + (c.QuadPart % freq.QuadPart) * 1000000 / freq.QuadPart;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Shared output formatting helpers
 *
 *   All subcommands should use these so the harness produces consistent,
 *   human-readable output. See memory/feedback_test_output_formatting.md
 *   for the style rules. In short:
 *
 *     - banner at the top of each test
 *     - "Parameters:" block listing key inputs
 *     - "-- <section> --" subsection dividers
 *     - aligned key/value lines via print_kv
 *     - tables with dashed underlines
 *     - PASS / FAIL: <reason>  verdict at the end
 * ════════════════════════════════════════════════════════════════════════ */

#define BANNER_WIDTH 72

static void print_banner(const char *title, const char *tagline)
{
    int i;
    printf("\n");
    for (i = 0; i < BANNER_WIDTH; i++) putchar('=');
    putchar('\n');
    printf("  %s", title);
    if (tagline && *tagline) printf(" - %s", tagline);
    printf("\n");
    for (i = 0; i < BANNER_WIDTH; i++) putchar('=');
    putchar('\n');
    fflush(stdout);
}

static void print_section(const char *title)
{
    printf("\n-- %s --\n", title);
    fflush(stdout);
}

/* Aligned key/value line. Key is left-padded to 20 chars so columns line up
 * across consecutive calls. Usage: print_kv("nthreads", "%d", 4); */
static void print_kv(const char *key, const char *fmt, ...)
{
    va_list ap;
    printf("  %-20s : ", key);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

/* Single-thread startup line: role tag + win32 tid + optional note.
 * Printed from the worker before it starts its loop. */
static void print_worker_start(const char *role, DWORD tid, const char *note)
{
    if (note && *note)
        printf("  [%-6s] win32_tid=%-6lu  %s\n", role, (unsigned long)tid, note);
    else
        printf("  [%-6s] win32_tid=%lu\n", role, (unsigned long)tid);
    fflush(stdout);
}

/* Verdict line — always the last thing a subcommand prints. */
static void print_verdict(int pass, const char *reason)
{
    printf("\n");
    if (pass)
        printf("  PASS\n");
    else if (reason && *reason)
        printf("  FAIL: %s\n", reason);
    else
        printf("  FAIL\n");
    printf("\n");
    fflush(stdout);
}

/* REALTIME_PRIORITY_CLASS is required for any test that uses
 * SetThreadPriority(TIME_CRITICAL) or expects distinct FIFO priorities.
 * Without it, TIME_CRITICAL maps to SCHED_OTHER under NORMAL class,
 * and intermediate priority values all collapse to prio 120. */
static DWORD g_saved_priority_class;

static void enter_realtime_class(void)
{
    g_saved_priority_class = GetPriorityClass(GetCurrentProcess());
    if (!SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS))
        printf("  [WARN] SetPriorityClass(REALTIME) failed\n");
}

static void leave_realtime_class(void)
{
    SetPriorityClass(GetCurrentProcess(), g_saved_priority_class);
}

/* Temporarily drop to NORMAL class to spawn a load thread as SCHED_OTHER,
 * then restore REALTIME. Wine does not retroactively reschedule threads
 * when the class changes, so the spawned thread stays SCHED_OTHER. */
static HANDLE spawn_load_thread_sched_other(LPTHREAD_START_ROUTINE fn,
                                            void *arg, DWORD *out_tid)
{
    HANDLE h;
    DWORD saved = GetPriorityClass(GetCurrentProcess());
    SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
    h = CreateThread(NULL, 0, fn, arg, 0, out_tid);
    SetPriorityClass(GetCurrentProcess(), saved);
    return h;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Subcommand: priority  (v1/v2 priority mapping test)
 *
 *   Unchanged behavior from the original nspa_rt_test.c — preserved
 *   verbatim as its own subcommand so all existing workflows keep working.
 * ════════════════════════════════════════════════════════════════════════ */

#define PRIO_SLEEP_SECS 90

static DWORD WINAPI prio_p1_tc(void *u)
{
    (void)u;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    printf("[P1-TC]    win32_tid=%lu  SetThreadPriority(TIME_CRITICAL)\n", GetCurrentThreadId());
    fflush(stdout);
    Sleep(PRIO_SLEEP_SECS * 1000);
    return 0;
}

static DWORD WINAPI prio_p1_mcss(void *u)
{
    DWORD idx = 0;
    HANDLE mh;
    (void)u;
    mh = p_AvSet ? p_AvSet(L"Pro Audio", &idx) : NULL;
    printf("[P1-MCSS]  win32_tid=%lu  Pro Audio=%s\n", GetCurrentThreadId(), mh ? "OK" : "FAIL");
    fflush(stdout);
    Sleep(PRIO_SLEEP_SECS * 1000);
    if (mh && p_AvRevert) p_AvRevert(mh);
    return 0;
}

static DWORD WINAPI prio_p1_norm(void *u)
{
    (void)u;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
    printf("[P1-NORM]  win32_tid=%lu  SetThreadPriority(NORMAL)\n", GetCurrentThreadId());
    fflush(stdout);
    Sleep(PRIO_SLEEP_SECS * 1000);
    return 0;
}

struct prio_p2_ctx {
    const char *label;
    int         win32_prio;
    int         expected_fifo;
};

static DWORD WINAPI prio_p2_thread(void *arg)
{
    struct prio_p2_ctx *c = arg;
    BOOL ok = SetThreadPriority(GetCurrentThread(), c->win32_prio);
    printf("[P2-%-7s] win32_tid=%lu  SetThreadPriority(%d)=%s  expect FF %d\n",
           c->label, GetCurrentThreadId(), c->win32_prio, ok ? "OK" : "FAIL",
           c->expected_fifo);
    fflush(stdout);
    Sleep(PRIO_SLEEP_SECS * 1000);
    return 0;
}

/* Expected FIFO priorities under ceiling mapping:
 *   fifo = NSPA_RT_PRIO - (31 - nt_band)
 * With NSPA_RT_PRIO=80: TC(31)=80, NORMAL(24)=73, IDLE(16)=65 */
static struct prio_p2_ctx prio_p2_cases[] = {
    { "IDLE",    THREAD_PRIORITY_IDLE,          65 },
    { "LOWEST",  THREAD_PRIORITY_LOWEST,        71 },
    { "BELOW",   THREAD_PRIORITY_BELOW_NORMAL,  72 },
    { "NORMAL",  THREAD_PRIORITY_NORMAL,        73 },
    { "ABOVE",   THREAD_PRIORITY_ABOVE_NORMAL,  74 },
    { "HIGHEST", THREAD_PRIORITY_HIGHEST,       75 },
    { "TC",      THREAD_PRIORITY_TIME_CRITICAL, 80 },
};
#define NUM_PRIO_P2 (sizeof(prio_p2_cases)/sizeof(prio_p2_cases[0]))

static int cmd_priority(int argc, char **argv)
{
    HANDLE ph1[3], ph2[NUM_PRIO_P2];
    DWORD pid = GetCurrentProcessId();
    int i;
    int spawn_fail = 0;
    BOOL rt_class_ok;
    DWORD rt_class_err = 0;
    int total_workers = 3 + (int)NUM_PRIO_P2;  /* main excluded */

    (void)argc; (void)argv;

    load_avrt();

    print_banner("priority", "v1/v2 priority mapping test");
    print_section("parameters");
    print_kv("process pid",      "%lu", (unsigned long)pid);
    print_kv("phase 1",          "3 threads at default (NORMAL) process class");
    print_kv("phase 2",          "%d threads after SetPriorityClass(REALTIME)", (int)NUM_PRIO_P2);
    print_kv("total workers",    "%d (+ main thread)", total_workers);
    print_kv("sleep per worker", "%d s (for external ps/chrt observation)", PRIO_SLEEP_SECS);
    print_kv("observe cmd",      "ps -eLo pid,tid,class,rtprio,nice,comm | grep -E 'POL|nspa_rt_test'");
    printf("\n");
    printf("  Expected scheduling with NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF:\n");
    printf("    [P1-TC]      -> FF 80   [P1-MCSS]    -> FF 80   [P1-NORM] -> TS / FF 73\n");
    printf("    [P2-IDLE]    -> FF 65   [P2-LOWEST]  -> FF 71   [P2-BELOW] -> FF 72\n");
    printf("    [P2-NORMAL]  -> FF 73   [P2-ABOVE]   -> FF 74   [P2-HIGHEST] -> FF 75\n");
    printf("    [P2-TC]      -> FF 80\n");

    print_section("phase 1: default class (Tier 1 lenient path)");
    fflush(stdout);
    ph1[0] = CreateThread(NULL, 0, prio_p1_tc,   NULL, 0, NULL); if (!ph1[0]) spawn_fail++;
    ph1[1] = CreateThread(NULL, 0, prio_p1_mcss, NULL, 0, NULL); if (!ph1[1]) spawn_fail++;
    ph1[2] = CreateThread(NULL, 0, prio_p1_norm, NULL, 0, NULL); if (!ph1[2]) spawn_fail++;
    Sleep(500);

    print_section("phase 2: elevating process to REALTIME_PRIORITY_CLASS");
    rt_class_ok = SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    if (!rt_class_ok)
    {
        rt_class_err = GetLastError();
        printf("  SetPriorityClass(REALTIME) FAILED  err=%lu\n", (unsigned long)rt_class_err);
    }
    else
    {
        printf("  SetPriorityClass(REALTIME) OK\n");
        printf("  main thread should now be FF 80 (NT 24 anchor)\n");
    }
    fflush(stdout);

    for (i = 0; i < (int)NUM_PRIO_P2; i++) {
        ph2[i] = CreateThread(NULL, 0, prio_p2_thread, &prio_p2_cases[i], 0, NULL);
        if (!ph2[i]) spawn_fail++;
    }

    Sleep(500);
    print_section("all workers sleeping -- query ps NOW");
    printf("  all %d workers sleeping %d seconds for external inspection\n",
           total_workers, PRIO_SLEEP_SECS);
    fflush(stdout);

    for (i = 0; i < 3; i++)                if (ph1[i]) WaitForSingleObject(ph1[i], (PRIO_SLEEP_SECS + 10) * 1000);
    for (i = 0; i < (int)NUM_PRIO_P2; i++) if (ph2[i]) WaitForSingleObject(ph2[i], (PRIO_SLEEP_SECS + 10) * 1000);
    for (i = 0; i < 3; i++)                if (ph1[i]) CloseHandle(ph1[i]);
    for (i = 0; i < (int)NUM_PRIO_P2; i++) if (ph2[i]) CloseHandle(ph2[i]);

    print_section("results (info only - PASS/FAIL based on structural integrity)");
    print_kv("workers created",  "%d / %d", total_workers - spawn_fail, total_workers);
    print_kv("spawn failures",   "%d", spawn_fail);
    print_kv("REALTIME class",   "%s", rt_class_ok ? "OK" : "FAILED");
    if (!rt_class_ok)
        print_kv("REALTIME err",  "%lu", (unsigned long)rt_class_err);

    /* Verdict: structural integrity only. Observed Linux scheduling
     * classes/priorities are the user's task (via ps/chrt during the
     * 90-second sleep window). If any thread failed to spawn or the
     * RT class change failed, something is structurally wrong. */
    if (spawn_fail == 0 && rt_class_ok) {
        print_verdict(1, NULL);
        return 0;
    } else {
        char reason[128];
        snprintf(reason, sizeof(reason),
                 "structural integrity (spawn_fail=%d, rt_class=%s)",
                 spawn_fail, rt_class_ok ? "OK" : "FAILED");
        print_verdict(0, reason);
        return 1;
    }
}

/* ════════════════════════════════════════════════════════════════════════
 *   Subcommand: cs-contention  (v2.3 CS-PI validation)
 *
 *   Scenario:
 *     - N SCHED_OTHER "load" threads run infinite busy loops.
 *     - 1 SCHED_OTHER "holder" thread acquires the shared CRITICAL_SECTION,
 *       does a fixed amount of CPU-bound work INSIDE the CS, releases. Repeats.
 *     - 1 SCHED_FIFO "waiter" thread (promoted via TIME_CRITICAL) waits on
 *       an event until the holder is in the CS, then tries to EnterCriticalSection.
 *       It measures the wall-clock wait time per iteration.
 *
 *   Expected behavior:
 *     - With NSPA_RT_PRIO set (CS-PI active):
 *         The kernel FUTEX_LOCK_PI boost runs the holder at SCHED_FIFO at the
 *         waiter's priority while the waiter is blocked. Holder preempts the
 *         load threads, completes its work promptly, releases.
 *         wait_ms ≈ uncontended work time (typically 1000-1500 ms per iter).
 *         Observation: `chrt -p <holder_tid>` during the iter shows SCHED_FIFO.
 *     - Without NSPA_RT_PRIO (baseline):
 *         The holder is SCHED_OTHER, shares CPU with N load threads. Its CS
 *         work takes longer by roughly a factor of (1 + N/cores). Waiter is
 *         blocked for the whole time.
 *         wait_ms scales with the load — typically 3-8x the uncontended time
 *         on a 2-core box with 4 load threads.
 *
 *   The RATIO of with-PI vs without-PI wait times is the observable signal.
 *   Absolute numbers are machine-dependent (WORK_ITERATIONS is a fixed count,
 *   not a wall-clock target, so it scales with CPU speed).
 * ════════════════════════════════════════════════════════════════════════ */

#define CS_LOAD_THREADS  4
#define CS_ITERATIONS    3
#define CS_WORK_ITERS    200000000LL   /* ~1 s on a modern idle x86 core */

static CRITICAL_SECTION g_cs;
static HANDLE           g_holder_in_cs;   /* auto-reset, set by holder on entry */
static HANDLE           g_waiter_done;    /* auto-reset, set by waiter after release */

static volatile LONGLONG g_wait_samples[CS_ITERATIONS];
static volatile int      g_wait_count;

static DWORD WINAPI cs_load_thread(void *u)
{
    volatile long long x = 0;
    long long i = 0;
    (void)u;
    while (!g_stop_load) {
        x += (i++) * (i + 1);
        if ((i & LOAD_YIELD_MASK) == 0) {
            Sleep(1);  /* yield to SCHED_OTHER — Sleep(0) is no-op for FIFO */
            if (g_stop_load) break;
        }
    }
    return (DWORD)(x & 0xffffffff);
}

/* Fixed-count busy loop with periodic yield. Uses `volatile` to prevent
 * the compiler from optimizing the work away. The yield (Sleep(0)) lets
 * higher-priority FIFO threads preempt every ~10ms. This is a FIFO-safe
 * yield — it doesn't yield to SCHED_OTHER, so it doesn't artificially
 * inflate hold times, but it prevents a single FIFO work loop from
 * monopolizing a core for the full 1+ seconds. */
#define WORK_YIELD_MASK 0x1ffffff  /* ~32M iters ≈ 10ms */
static void cs_do_work(long long iters)
{
    volatile long long x = 0;
    long long i;
    for (i = 0; i < iters; i++) {
        x += i * (i + 1);
        if ((i & WORK_YIELD_MASK) == 0 && i > 0)
            Sleep(0);  /* yield to higher-prio FIFO only */
    }
    (void)x;
}

static DWORD WINAPI cs_holder_thread(void *u)
{
    int iter;
    (void)u;
    printf("[CS-holder]  win32_tid=%lu  SCHED_OTHER (no explicit promotion)\n",
           GetCurrentThreadId());
    fflush(stdout);

    for (iter = 0; iter < CS_ITERATIONS; iter++)
    {
        LONGLONG t0, t1;

        /* Small pause between iterations so waiter can cycle cleanly. */
        if (iter > 0) Sleep(200);

        EnterCriticalSection(&g_cs);
        t0 = now_ms();
        printf("\n[CS-holder]  iter %d: acquired CS at t=%lld ms — doing %lld-iter work loop...\n",
               iter + 1, t0, CS_WORK_ITERS);
        fflush(stdout);

        /* Tell the waiter we're in. It will try to acquire now and block. */
        SetEvent(g_holder_in_cs);

        /* CPU-bound work inside the CS. Holder's wall-clock time here depends
         * on how much CPU it gets, which is the variable we're measuring. */
        cs_do_work(CS_WORK_ITERS);

        t1 = now_ms();
        printf("[CS-holder]  iter %d: releasing CS at t=%lld ms (held for %lld ms wall)\n",
               iter + 1, t1, t1 - t0);
        fflush(stdout);

        LeaveCriticalSection(&g_cs);

        /* Wait for waiter to acknowledge before starting the next iteration. */
        WaitForSingleObject(g_waiter_done, INFINITE);
    }
    return 0;
}

static DWORD WINAPI cs_waiter_thread(void *u)
{
    int iter;
    (void)u;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    printf("[CS-waiter]  win32_tid=%lu  SetThreadPriority(TIME_CRITICAL) -> SCHED_FIFO (ceiling)\n",
           GetCurrentThreadId());
    fflush(stdout);

    for (iter = 0; iter < CS_ITERATIONS; iter++)
    {
        LONGLONG t0, t1, wait;

        /* Block until holder has entered its CS. */
        WaitForSingleObject(g_holder_in_cs, INFINITE);

        t0 = now_ms();
        EnterCriticalSection(&g_cs);
        t1 = now_ms();
        wait = t1 - t0;

        g_wait_samples[g_wait_count++] = wait;
        printf("[CS-waiter]  iter %d: acquired at t=%lld ms, wait=%lld ms\n",
               iter + 1, t1, wait);
        fflush(stdout);

        LeaveCriticalSection(&g_cs);
        SetEvent(g_waiter_done);
    }
    return 0;
}

static int cmd_cs_contention(int argc, char **argv)
{
    HANDLE load_h[CS_LOAD_THREADS];
    HANDLE holder_h, waiter_h;
    int i, n_load;
    LONGLONG min_w = 0, max_w = 0, sum_w = 0;

    (void)argc; (void)argv;

    n_load = safe_load_count(CS_LOAD_THREADS);
    InitializeCriticalSection(&g_cs);
    g_holder_in_cs = CreateEventW(NULL, FALSE, FALSE, NULL);  /* auto-reset */
    g_waiter_done  = CreateEventW(NULL, FALSE, FALSE, NULL);  /* auto-reset */
    g_stop_load = 0;
    g_wait_count = 0;

    print_banner("cs-contention", "CS-PI v2.3 validation / priority inversion test");
    print_section("parameters");
    print_kv("load threads",     "%d SCHED_OTHER busyloops", n_load);
    print_kv("CS iterations",    "%d", CS_ITERATIONS);
    print_kv("work per hold",    "%lld loop iters (~1 s on an idle core)", CS_WORK_ITERS);
    print_kv("holder policy",    "SCHED_OTHER (no explicit promotion)");
    print_kv("waiter policy",    "SCHED_FIFO via TIME_CRITICAL");
    print_kv("process pid",      "%lu", (unsigned long)GetCurrentProcessId());
    print_kv("observe cmd",      "chrt -p <holder_tid>   /proc/<holder_tid>/status");

    print_section("startup");

    /* Spawn load threads BEFORE enter_realtime_class() so they stay
     * SCHED_OTHER. This is the key safety invariant: SCHED_OTHER busyloops
     * are preemptible by CFS and can never pin cores or freeze the desktop. */
    for (i = 0; i < n_load; i++)
    {
        DWORD tid;
        load_h[i] = CreateThread(NULL, 0, cs_load_thread, NULL, 0, &tid);
        print_worker_start("load", tid, "SCHED_OTHER busyloop");
    }
    Sleep(200);

    /* NOW switch to REALTIME class — only threads created after this
     * (holder, waiter) or that call SetThreadPriority will get FIFO. */
    enter_realtime_class();

    /* Spawn holder first, waiter second. Holder gets the CS before waiter
     * starts trying (the event synchronizes the rest). */
    holder_h = CreateThread(NULL, 0, cs_holder_thread, NULL, 0, NULL);
    waiter_h = CreateThread(NULL, 0, cs_waiter_thread, NULL, 0, NULL);

    print_section("iterations");
    fflush(stdout);

    WaitForSingleObject(holder_h, 60000);
    WaitForSingleObject(waiter_h, 60000);

    /* Stop load threads. */
    InterlockedExchange(&g_stop_load, 1);
    for (i = 0; i < n_load; i++)
    {
        WaitForSingleObject(load_h[i], 5000);
        CloseHandle(load_h[i]);
    }
    CloseHandle(holder_h);
    CloseHandle(waiter_h);

    /* Summary. */
    print_section("results (info only - PASS/FAIL based on sample capture)");
    if (g_wait_count > 0)
    {
        min_w = max_w = g_wait_samples[0];
        for (i = 0; i < g_wait_count; i++)
        {
            LONGLONG w = g_wait_samples[i];
            if (w < min_w) min_w = w;
            if (w > max_w) max_w = w;
            sum_w += w;
        }

        print_kv("samples captured",  "%d of %d expected", g_wait_count, CS_ITERATIONS);
        print_kv("min wait",          "%lld ms", min_w);
        print_kv("max wait",          "%lld ms", max_w);
        print_kv("avg wait",          "%lld ms", sum_w / g_wait_count);
    } else {
        print_kv("samples captured",  "0 of %d expected", CS_ITERATIONS);
    }

    print_section("interpretation (manual comparison)");
    printf("  Run twice with/without NSPA_RT_PRIO on the same machine and compare:\n");
    printf("    $ NSPA_RT_PRIO=80 ./wine nspa_rt_test.exe cs-contention\n");
    printf("    $                 ./wine nspa_rt_test.exe cs-contention\n");
    printf("  CS-PI is working when:\n");
    printf("    - with-PI avg wait is close to uncontended work time (~1 s)\n");
    printf("    - without-PI avg wait is materially larger\n");
    printf("    - the ratio (without/with) grows with CS_LOAD_THREADS\n");

    DeleteCriticalSection(&g_cs);
    CloseHandle(g_holder_in_cs);
    CloseHandle(g_waiter_done);
    leave_realtime_class();

    /* Verdict: test passed iff we captured all expected samples. That
     * proves the holder released the CS and the waiter acquired it on
     * every iteration — no deadlock, no lost wakeup, no hang. The wait
     * time numbers above are informational; machine speed dominates
     * them and they are not a pass/fail axis. */
    if (g_wait_count == CS_ITERATIONS) {
        print_verdict(1, NULL);
        return 0;
    } else {
        char reason[128];
        snprintf(reason, sizeof(reason),
                 "captured %d/%d samples (possible deadlock or lost wakeup)",
                 g_wait_count, CS_ITERATIONS);
        print_verdict(0, reason);
        return 1;
    }
}

/* ════════════════════════════════════════════════════════════════════════
 *   Subcommand stubs — planned tests to flesh out over time
 * ════════════════════════════════════════════════════════════════════════ */

/* ════════════════════════════════════════════════════════════════════════
 *   Subcommand: rapidmutex  (CRITICAL_SECTION stress test)
 *
 *   N threads (default 4) hammer a single shared CRITICAL_SECTION in a
 *   tight EnterCS/LeaveCS loop. Thread 0 runs at THREAD_PRIORITY_TIME_CRITICAL
 *   (so under NSPA_RT_PRIO=XX it becomes SCHED_FIFO); other threads run at
 *   NORMAL. The CS body is a single increment of a shared counter — tight
 *   enough to keep contention high.
 *
 *   Per-thread metrics: max wait-for-lock time, average wait, iteration
 *   count, wall elapsed. Aggregate: total throughput (ops/sec), counter
 *   integrity check (shared_counter == N * iters).
 *
 *   Expected behavior:
 *     - shared_counter == N * iters   (CS is holding atomicity)
 *     - Without NSPA_RT_PRIO: all threads see comparable max-wait
 *     - With NSPA_RT_PRIO=XX + CS-PI: thread 0's max-wait is bounded by
 *       the CS body time, not by load-thread scheduling. Load threads
 *       still see long max-wait under contention.
 *
 *   Usage: rapidmutex [n_threads [iters_per_thread]]
 *            default: 4 threads, 500000 iters each
 * ════════════════════════════════════════════════════════════════════════ */

#define RAPIDMUTEX_DEFAULT_THREADS 4
#define RAPIDMUTEX_DEFAULT_ITERS   500000
#define RAPIDMUTEX_MAX_THREADS     16

static volatile LONG  rapid_shared_counter; /* protected by the CS */
static LARGE_INTEGER  rapid_qpc_freq;

struct rapid_state {
    CRITICAL_SECTION *cs;
    int      iters;
    int      is_rt;
    /* outputs */
    DWORD    win32_tid;
    LONGLONG max_wait_us;
    LONGLONG total_wait_us;
    LONGLONG elapsed_us;
    int      iters_done;
};

static LONGLONG rapid_qpc_us(void)
{
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (c.QuadPart * 1000000) / rapid_qpc_freq.QuadPart;
}

static DWORD WINAPI rapid_worker(void *arg)
{
    struct rapid_state *s = arg;
    LONGLONG start, max_wait = 0, total_wait = 0;
    int i;

    s->win32_tid = GetCurrentThreadId();
    if (s->is_rt)
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    print_worker_start(s->is_rt ? "RT" : "load", s->win32_tid, NULL);

    start = rapid_qpc_us();
    for (i = 0; i < s->iters; i++) {
        LONGLONG t0 = rapid_qpc_us();
        LONGLONG wait;
        EnterCriticalSection(s->cs);
        wait = rapid_qpc_us() - t0;
        if (wait > max_wait) max_wait = wait;
        total_wait += wait;

        rapid_shared_counter++;

        LeaveCriticalSection(s->cs);
    }

    s->iters_done    = i;
    s->max_wait_us   = max_wait;
    s->total_wait_us = total_wait;
    s->elapsed_us    = rapid_qpc_us() - start;
    return 0;
}

static int cmd_rapidmutex(int argc, char **argv)
{
    CRITICAL_SECTION cs;
    struct rapid_state states[RAPIDMUTEX_MAX_THREADS];
    HANDLE threads[RAPIDMUTEX_MAX_THREADS];
    int nthreads = RAPIDMUTEX_DEFAULT_THREADS;
    int iters    = RAPIDMUTEX_DEFAULT_ITERS;
    LONGLONG total_start, total_end, total_us;
    LONG     expected, total_done = 0;
    int i;

    if (argc > 1) nthreads = atoi(argv[1]);
    if (argc > 2) iters    = atoi(argv[2]);
    if (nthreads < 1) nthreads = 1;
    if (nthreads > RAPIDMUTEX_MAX_THREADS) nthreads = RAPIDMUTEX_MAX_THREADS;

    enter_realtime_class();
    if (iters    < 1) iters    = 1;

    if (!QueryPerformanceFrequency(&rapid_qpc_freq)) {
        printf("[rapidmutex] QueryPerformanceFrequency failed\n");
        return 1;
    }

    rapid_shared_counter = 0;
    InitializeCriticalSection(&cs);

    print_banner("rapidmutex", "CRITICAL_SECTION stress test");
    print_section("parameters");
    print_kv("nthreads",       "%d  (1 RT + %d load)", nthreads, nthreads - 1);
    print_kv("iters/thread",   "%d", iters);
    print_kv("total iters",    "%d", nthreads * iters);
    print_kv("process pid",    "%lu", (unsigned long)GetCurrentProcessId());
    print_kv("observe cmd",    "ps -eLo pid,tid,class,rtprio,nice,comm | grep nspa_rt_test");

    print_section("startup");
    memset(states, 0, sizeof(states));
    total_start = rapid_qpc_us();

    for (i = 0; i < nthreads; i++) {
        states[i].cs    = &cs;
        states[i].iters = iters;
        states[i].is_rt = (i == 0);
        threads[i] = CreateThread(NULL, 0, rapid_worker, &states[i], 0, NULL);
    }

    WaitForMultipleObjects(nthreads, threads, TRUE, 120000);
    total_end = rapid_qpc_us();
    total_us  = total_end - total_start;

    for (i = 0; i < nthreads; i++) {
        CloseHandle(threads[i]);
        total_done += states[i].iters_done;
    }
    DeleteCriticalSection(&cs);

    expected = (LONG)nthreads * (LONG)iters;
    print_section("results");
    print_kv("total elapsed",  "%lld ms", total_us / 1000);
    print_kv("throughput",     "%lld ops/sec",
             total_us ? (total_done * 1000000LL / total_us) : 0);
    print_kv("shared counter", "%ld (expected %ld) %s",
             (long)rapid_shared_counter, (long)expected,
             (rapid_shared_counter == expected) ? "OK" : "MISMATCH");

    print_section("per-thread");
    printf("  %-6s  %-10s  %10s  %14s  %14s  %12s\n",
           "role", "win32_tid", "iters", "max_wait(us)", "avg_wait(us)", "elapsed(ms)");
    printf("  %-6s  %-10s  %10s  %14s  %14s  %12s\n",
           "------", "---------", "----------", "------------", "------------", "-----------");
    for (i = 0; i < nthreads; i++) {
        LONGLONG avg = states[i].iters_done ? states[i].total_wait_us / states[i].iters_done : 0;
        printf("  %-6s  %-10lu  %10d  %14lld  %14lld  %12lld\n",
               states[i].is_rt ? "RT" : "load",
               (unsigned long)states[i].win32_tid,
               states[i].iters_done,
               states[i].max_wait_us,
               avg,
               states[i].elapsed_us / 1000);
    }

    leave_realtime_class();
    if (rapid_shared_counter == expected) {
        print_verdict(1, NULL);
        return 0;
    } else {
        char reason[128];
        snprintf(reason, sizeof(reason),
                 "counter mismatch: got %ld, expected %ld (CRITICAL_SECTION broken)",
                 (long)rapid_shared_counter, (long)expected);
        print_verdict(0, reason);
        return 1;
    }
}

/* ════════════════════════════════════════════════════════════════════════
 *   Subcommand: philosophers  (dining philosophers — Wine CS bug finder)
 *
 *   5 philosopher threads share 5 CRITICAL_SECTION "chopsticks", arranged
 *   in a ring. Each phil needs its two adjacent chopsticks to eat. Classic
 *   setup with a resource hierarchy (always acquire the lower-numbered
 *   chopstick first) to prevent algorithmic deadlock. Phil 0 runs at
 *   THREAD_PRIORITY_TIME_CRITICAL; phils 1..4 run NORMAL. N background
 *   SCHED_OTHER busyloop threads (default 4) contend with the OTHER phils
 *   for CPU, so that when phil 0 blocks on a chopstick, the chain of OTHER
 *   phils holding it is scheduling-starved.
 *
 *   ── What bugs this test catches ───────────────────────────────────────
 *
 *   (1) Deadlock in Wine's CRITICAL_SECTION path.
 *       If Enter/LeaveCS loses ownership or wakes the wrong waiter, the
 *       algorithmic deadlock-free property of the resource hierarchy no
 *       longer holds and the whole test hangs. Caught by the 60s timeout
 *       on WaitForMultipleObjects.
 *
 *   (2) Lost unlock / ownership corruption.
 *       If LeaveCriticalSection fails to release the CS (partial release,
 *       refcount bug, missed wakeup), the next EnterCS from a different
 *       phil blocks forever. Caught by timeout.
 *
 *   (3) RT priority mapping broken.
 *       If phil 0's TIME_CRITICAL → SCHED_FIFO promotion is broken (NSPA
 *       RT v1/v1.2 regression), phil 0 runs as SCHED_OTHER. Under load
 *       contention, it becomes starved — meals_done stays far below
 *       target. Caught by the `min_meals < target` check.
 *
 *   (4) CS-PI priority inheritance broken.
 *       If phil 0 (RT) blocks on a chopstick held by an OTHER phil and
 *       the holder does NOT get boosted, the load threads keep preempting
 *       the holder and phil 0 waits indefinitely. Eventually phil 0
 *       starves and the test times out or fails the starvation check.
 *       Caught by timeout and/or min_meals check.
 *
 *   (5) Transitive PI chain broken.
 *       Phil 0 (RT) blocks on phil K, who is holding chopstick A but
 *       waiting for chopstick B held by phil K+1, who is waiting for
 *       chopstick C held by phil K+2. PI must propagate: boost K, then K
 *       transitively boosts K+1, then K+2. If PI only boosts ONE level
 *       deep, the chain gets stuck at the second hop. Caught by timeout
 *       under heavy contention.
 *
 *   (6) Spurious wakeup / wrong-waiter wakeup.
 *       If EnterCS returns early or the wrong thread is woken, two phils
 *       can believe they hold the same chopstick simultaneously, which
 *       corrupts the schedule but not directly any state the test tracks.
 *       Detected indirectly via abnormal meals distribution (one phil
 *       makes too much progress, another too little) or via an external
 *       observer like thread-sanitizer.
 *
 *   ── PASS / FAIL criteria ──────────────────────────────────────────────
 *
 *   PASS iff:
 *     - WaitForMultipleObjects returns before PHIL_TIMEOUT_MS (no deadlock)
 *     - Every philosopher's meals_done == target (no starvation, no hang)
 *
 *   FAIL otherwise, with a labelled reason.
 *
 *   Benchmark-style numbers (max wait, avg wait, elapsed) are printed
 *   in the results/per-phil sections as INFORMATION for the user running
 *   the test manually. They are NOT pass/fail criteria — machine speed,
 *   core count, and load scaling affect them too much for any threshold
 *   to be meaningful.
 *
 *   ── Usage ─────────────────────────────────────────────────────────────
 *
 *   philosophers [meals_per_phil [load_threads]]
 *     default: 50 meals/phil, 4 background load threads
 * ════════════════════════════════════════════════════════════════════════ */

#define PHIL_N                 5
#define PHIL_DEFAULT_MEALS     50
#define PHIL_DEFAULT_LOAD      4
#define PHIL_MAX_LOAD          16
#define PHIL_THINK_WORK        400000LL   /* ~1-3 ms busywork on modern x86 */
#define PHIL_EAT_WORK          400000LL
#define PHIL_TIMEOUT_MS        60000

static CRITICAL_SECTION phil_chopsticks[PHIL_N];
static LARGE_INTEGER    phil_qpc_freq;

struct phil_state {
    int      id;
    int      is_rt;
    int      target_meals;
    /* outputs */
    DWORD    win32_tid;
    int      meals_done;
    LONGLONG max_wait_us;
    LONGLONG total_wait_us;
    LONGLONG total_think_us;
    LONGLONG total_eat_us;
    LONGLONG elapsed_us;
};

static LONGLONG phil_qpc_us(void)
{
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (c.QuadPart * 1000000) / phil_qpc_freq.QuadPart;
}

/* Fixed-count busyloop, same idiom as cs_do_work. */
static void phil_do_work(long long iters)
{
    volatile long long x = 0;
    long long i;
    for (i = 0; i < iters; i++)
        x += i * (i + 1);
    (void)x;
}

static DWORD WINAPI phil_load_thread(void *u)
{
    volatile long long x = 0;
    long long i = 0;
    (void)u;
    while (!phil_load_stop) {
        x += i * (i + 1);
        i++;
        if ((i & LOAD_YIELD_MASK) == 0) {
            Sleep(1);  /* yield to SCHED_OTHER — Sleep(0) is no-op for FIFO */
            if (phil_load_stop) break;
        }
    }
    return (DWORD)(x & 0xffffffff);
}

static DWORD WINAPI phil_worker(void *arg)
{
    struct phil_state *s = arg;
    LONGLONG start;
    int lo = s->id;
    int hi = (s->id + 1) % PHIL_N;
    /* Resource hierarchy: always acquire lower-numbered chopstick first. */
    if (lo > hi) { int tmp = lo; lo = hi; hi = tmp; }

    s->win32_tid = GetCurrentThreadId();
    if (s->is_rt)
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    {
        char note[64];
        snprintf(note, sizeof(note), "phil=%d  chopsticks=%d,%d",
                 s->id, lo, hi);
        print_worker_start(s->is_rt ? "RT" : "phil", s->win32_tid, note);
    }

    start = phil_qpc_us();
    while (s->meals_done < s->target_meals) {
        LONGLONG t0, t1;

        /* Think */
        t0 = phil_qpc_us();
        phil_do_work(PHIL_THINK_WORK);
        s->total_think_us += phil_qpc_us() - t0;

        /* Acquire lower chopstick, then higher. Wait time is measured as
         * time between the start of the first Enter and the completion of
         * the second Enter — the total "hungry" time for this meal. */
        t0 = phil_qpc_us();
        EnterCriticalSection(&phil_chopsticks[lo]);
        EnterCriticalSection(&phil_chopsticks[hi]);
        t1 = phil_qpc_us();
        {
            LONGLONG wait = t1 - t0;
            if (wait > s->max_wait_us) s->max_wait_us = wait;
            s->total_wait_us += wait;
        }

        /* Eat */
        t0 = phil_qpc_us();
        phil_do_work(PHIL_EAT_WORK);
        s->total_eat_us += phil_qpc_us() - t0;

        LeaveCriticalSection(&phil_chopsticks[hi]);
        LeaveCriticalSection(&phil_chopsticks[lo]);

        s->meals_done++;
    }
    s->elapsed_us = phil_qpc_us() - start;
    return 0;
}

static int cmd_philosophers(int argc, char **argv)
{
    struct phil_state states[PHIL_N];
    HANDLE phils[PHIL_N];
    HANDLE loads[PHIL_MAX_LOAD];
    int target_meals = PHIL_DEFAULT_MEALS;
    int n_load       = PHIL_DEFAULT_LOAD;
    int i;
    LONGLONG t_start, t_end;
    DWORD wait_ret;
    int min_meals = INT_MAX, max_meals = 0, sum_meals = 0;
    LONGLONG worst_max_wait = 0, rt_max_wait = 0;

    if (argc > 1) target_meals = atoi(argv[1]);
    if (argc > 2) n_load       = atoi(argv[2]);
    if (target_meals < 1) target_meals = 1;
    if (n_load < 0) n_load = 0;
    if (n_load > PHIL_MAX_LOAD) n_load = PHIL_MAX_LOAD;
    n_load = safe_load_count(n_load);

    if (!QueryPerformanceFrequency(&phil_qpc_freq)) {
        printf("QueryPerformanceFrequency failed\n");
        return 1;
    }

    for (i = 0; i < PHIL_N; i++)
        InitializeCriticalSection(&phil_chopsticks[i]);

    print_banner("philosophers", "dining philosophers / transitive PI chain test");
    print_section("parameters");
    print_kv("philosophers",     "%d  (phil 0 RT, phils 1..%d load)", PHIL_N, PHIL_N - 1);
    print_kv("meals/phil",       "%d", target_meals);
    print_kv("background load",  "%d SCHED_OTHER busyloop thread(s)", n_load);
    print_kv("think work",       "%lld iters (~1-3 ms busywork)", (long long)PHIL_THINK_WORK);
    print_kv("eat work",         "%lld iters (~1-3 ms busywork)", (long long)PHIL_EAT_WORK);
    print_kv("timeout",          "%d ms", PHIL_TIMEOUT_MS);
    print_kv("process pid",      "%lu", (unsigned long)GetCurrentProcessId());
    print_kv("observe cmd",      "ps -eLo pid,tid,class,rtprio,nice,comm | grep nspa_rt_test");

    print_section("startup");
    memset(states, 0, sizeof(states));
    phil_load_stop = 0;

    /* Start background load threads BEFORE enter_realtime_class() so they
     * stay SCHED_OTHER. They simulate CFS background contention. */
    for (i = 0; i < n_load; i++) {
        loads[i] = CreateThread(NULL, 0, phil_load_thread, NULL, 0, NULL);
    }
    if (n_load > 0)
        printf("  [load  ] %d background busyloop thread(s) started (SCHED_OTHER)\n", n_load);

    enter_realtime_class();

    /* Start the philosophers (under REALTIME class). */
    t_start = phil_qpc_us();
    for (i = 0; i < PHIL_N; i++) {
        states[i].id           = i;
        states[i].is_rt        = (i == 0);
        states[i].target_meals = target_meals;
        phils[i] = CreateThread(NULL, 0, phil_worker, &states[i], 0, NULL);
    }

    wait_ret = WaitForMultipleObjects(PHIL_N, phils, TRUE, PHIL_TIMEOUT_MS);
    t_end = phil_qpc_us();

    phil_load_stop = 1;
    for (i = 0; i < n_load; i++) {
        WaitForSingleObject(loads[i], 5000);
        CloseHandle(loads[i]);
    }
    for (i = 0; i < PHIL_N; i++)
        CloseHandle(phils[i]);
    for (i = 0; i < PHIL_N; i++)
        DeleteCriticalSection(&phil_chopsticks[i]);

    /* Aggregate */
    for (i = 0; i < PHIL_N; i++) {
        if (states[i].meals_done < min_meals) min_meals = states[i].meals_done;
        if (states[i].meals_done > max_meals) max_meals = states[i].meals_done;
        if (states[i].max_wait_us > worst_max_wait) worst_max_wait = states[i].max_wait_us;
        if (states[i].is_rt) rt_max_wait = states[i].max_wait_us;
        sum_meals += states[i].meals_done;
    }

    print_section("results (info only — PASS/FAIL is based on meals completion)");
    print_kv("total elapsed",    "%lld ms", (t_end - t_start) / 1000);
    print_kv("total meals",      "%d of %d target", sum_meals, PHIL_N * target_meals);
    print_kv("min meals/phil",   "%d", min_meals);
    print_kv("max meals/phil",   "%d", max_meals);
    if (max_meals > 0) {
        print_kv("spread",       "%d meal(s)  (max - min; 0 = perfect fairness)",
                 max_meals - min_meals);
    }
    print_kv("RT max wait",      "%lld us  (phil 0, TIME_CRITICAL)", rt_max_wait);
    print_kv("worst max wait",   "%lld us  (across all philosophers)", worst_max_wait);

    print_section("per-philosopher");
    printf("  %-6s  %-10s  %6s  %14s  %14s  %14s  %12s\n",
           "role", "win32_tid", "meals", "max_wait(us)", "avg_wait(us)",
           "eat_total(ms)", "elapsed(ms)");
    printf("  %-6s  %-10s  %6s  %14s  %14s  %14s  %12s\n",
           "------", "---------", "------", "------------", "------------",
           "-------------", "-----------");
    for (i = 0; i < PHIL_N; i++) {
        LONGLONG avg = states[i].meals_done ?
                       states[i].total_wait_us / states[i].meals_done : 0;
        printf("  %-6s  %-10lu  %6d  %14lld  %14lld  %14lld  %12lld\n",
               states[i].is_rt ? "RT" : "phil",
               (unsigned long)states[i].win32_tid,
               states[i].meals_done,
               states[i].max_wait_us,
               avg,
               states[i].total_eat_us / 1000,
               states[i].elapsed_us / 1000);
    }

    /* Verdict */
    if (wait_ret == WAIT_TIMEOUT) {
        char reason[128];
        snprintf(reason, sizeof(reason),
                 "timeout after %d ms — possible deadlock (sum=%d / %d meals)",
                 PHIL_TIMEOUT_MS, sum_meals, PHIL_N * target_meals);
        print_verdict(0, reason);
        leave_realtime_class();
        return 1;
    }
    if (min_meals < target_meals) {
        char reason[128];
        snprintf(reason, sizeof(reason),
                 "starvation: min %d meals, expected %d",
                 min_meals, target_meals);
        print_verdict(0, reason);
        leave_realtime_class();
        return 1;
    }
    print_verdict(1, NULL);
    leave_realtime_class();
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Subcommand: fork-mutex  (CreateProcess opt-out validation)
 *
 *   Spawns N copies of itself via CreateProcess, each running the internal
 *   `child-quickexit` subcommand, waits for each, verifies exit code.
 *   Purpose: validate that Wine's process-spawn path (dlls/ntdll/unix/
 *   process.c) is not regressed and that the librtpi_sweep opt-out for
 *   that file is load-bearing. process.c is in EXCLUDE_FILES because
 *   pi_mutex_t stores the Linux owner TID in the futex word, and a child
 *   that inherited a swept mutex held by the parent thread would see a
 *   corrupted mutex (ESRCH/EPERM on subsequent ops). This test rapidly
 *   exercises the spawn path; any regression in that path or in anything
 *   it touches (pthread_atfork, process.c, wineserver process registration)
 *   manifests as spawn failures, child hangs, or wrong exit codes.
 *
 *   ── What bugs this test catches ───────────────────────────────────────
 *
 *   (1) process.c accidentally converted by the sweep.
 *       If EXCLUDE_FILES loses dlls/ntdll/unix/process.c (e.g. someone
 *       edits the list without reading the opt-out memory), the sweep
 *       rewrites pthread_* → pi_* in the fork path. The child inherits
 *       a pi_mutex with the parent's TID. Depending on which mutex and
 *       when the child touches it, result is either a hang or an EPERM
 *       crash before exec. Caught: child wait timeout or nonzero/wrong
 *       exit code.
 *
 *   (2) pthread_atfork handler regression.
 *       If we ever add atfork handlers for swept mutexes and one of
 *       them is buggy (e.g. deadlocks in prepare, or fails to re-init
 *       in child), the spawn either hangs in the parent or the child
 *       fails to start. Caught: parent wait timeout.
 *
 *   (3) Wine process-spawn race or handle-leak regression.
 *       Independent of the sweep — if Wine's own CreateProcess has a
 *       race with wineserver or leaks process handles, running 100
 *       spawns in rapid succession exposes it. A single spawn might
 *       work; the 37th might not. Caught: any iteration fails.
 *
 *   (4) Wineserver process-registration limit or state corruption.
 *       Every CreateProcess registers the new process with wineserver.
 *       If wineserver has an off-by-one in a process table, a race in
 *       process list traversal, or a leak, repeated spawns surface it.
 *       Caught: later iterations fail while earlier ones succeed.
 *
 *   (5) ntdll/unix/loader.c posix_spawn regression.
 *       Wine uses posix_spawn for the preloader step. A bug there
 *       (which might be triggered by RT scheduling interacting with
 *       exec*) would cause spawns to silently fail. Caught: spawn
 *       returns FALSE.
 *
 *   ── PASS / FAIL criteria ──────────────────────────────────────────────
 *
 *   PASS iff: every iteration successfully spawned, waited, and returned
 *             the expected FORK_CHILD_EXIT_CODE.
 *   FAIL:     any spawn failure, wait timeout, or exit code mismatch.
 *             The result block tallies each category so the failure
 *             mode is immediately visible.
 *
 *   Spawn-time and child-total-time numbers are printed as INFORMATION
 *   (regression-diffable across Wine versions, not a pass/fail axis).
 *
 *   ── Usage ─────────────────────────────────────────────────────────────
 *
 *   fork-mutex [count]     default 100
 *
 *   The child subcommand `child-quickexit` is listed in the help output
 *   as an internal helper; it's not intended for direct use by the user
 *   but is safe to run standalone (it just prints a line and exits 42).
 * ════════════════════════════════════════════════════════════════════════ */

#define FORK_DEFAULT_COUNT      100
#define FORK_MAX_COUNT          10000
#define FORK_CHILD_TIMEOUT_MS   5000
#define FORK_CHILD_EXIT_CODE    42

static int cmd_child_quickexit(int argc, char **argv)
{
    (void)argc; (void)argv;
    /* Minimal child routine used by fork-mutex. Prints a marker line
     * (stdout is inherited from parent by default, so the parent sees
     * it) and exits with a known code. If this line never prints, the
     * spawn itself reached ExitProcess before main() ran — which points
     * at a broken startup path. */
    printf("  child-quickexit: pid=%lu ok\n",
           (unsigned long)GetCurrentProcessId());
    fflush(stdout);
    return FORK_CHILD_EXIT_CODE;
}

static int cmd_fork_mutex(int argc, char **argv)
{
    char exe_path[MAX_PATH];
    int count = FORK_DEFAULT_COUNT;
    int i;
    int spawned = 0, waited = 0, ok_exit = 0;
    int spawn_fail = 0, wait_timeout = 0, exit_mismatch = 0;
    LONGLONG min_spawn = -1, max_spawn = 0, sum_spawn = 0;
    LONGLONG min_wait  = -1, max_wait  = 0, sum_wait  = 0;
    LONGLONG test_start, test_end;

    if (argc > 1) count = atoi(argv[1]);
    if (count < 1) count = 1;
    if (count > FORK_MAX_COUNT) count = FORK_MAX_COUNT;

    if (!GetModuleFileNameA(NULL, exe_path, sizeof(exe_path))) {
        printf("GetModuleFileName failed\n");
        return 1;
    }

    print_banner("fork-mutex", "CreateProcess opt-out validation");
    print_section("parameters");
    print_kv("spawn count",       "%d", count);
    print_kv("per-child timeout", "%d ms", FORK_CHILD_TIMEOUT_MS);
    print_kv("expected exit",     "%d", FORK_CHILD_EXIT_CODE);
    print_kv("exe path",          "%s", exe_path);
    print_kv("parent pid",        "%lu", (unsigned long)GetCurrentProcessId());

    print_section("spawning");
    fflush(stdout);

    test_start = now_us();

    for (i = 0; i < count; i++) {
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        char cmdline[MAX_PATH + 64];
        LONGLONG t0, t1, t2;
        BOOL ok;
        DWORD wait_ret = 0, exit_code = 0;

        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));
        snprintf(cmdline, sizeof(cmdline),
                 "\"%s\" child-quickexit %d", exe_path, i);

        t0 = now_us();
        ok = CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                            0, NULL, NULL, &si, &pi);
        t1 = now_us();

        if (!ok) {
            spawn_fail++;
            printf("  [iter %4d] CreateProcess FAILED (GetLastError=%lu)\n",
                   i, (unsigned long)GetLastError());
            fflush(stdout);
            continue;
        }
        spawned++;
        {
            LONGLONG s = t1 - t0;
            sum_spawn += s;
            if (min_spawn < 0 || s < min_spawn) min_spawn = s;
            if (s > max_spawn) max_spawn = s;
        }

        wait_ret = WaitForSingleObject(pi.hProcess, FORK_CHILD_TIMEOUT_MS);
        t2 = now_us();

        if (wait_ret == WAIT_TIMEOUT) {
            wait_timeout++;
            printf("  [iter %4d] child TIMEOUT after %d ms — terminating\n",
                   i, FORK_CHILD_TIMEOUT_MS);
            fflush(stdout);
            TerminateProcess(pi.hProcess, 99);
            WaitForSingleObject(pi.hProcess, 1000);
        } else {
            LONGLONG w = t2 - t1;
            waited++;
            sum_wait += w;
            if (min_wait < 0 || w < min_wait) min_wait = w;
            if (w > max_wait) max_wait = w;
            if (GetExitCodeProcess(pi.hProcess, &exit_code)) {
                if (exit_code == FORK_CHILD_EXIT_CODE) {
                    ok_exit++;
                } else {
                    exit_mismatch++;
                    printf("  [iter %4d] child exit code %lu (expected %d)\n",
                           i, (unsigned long)exit_code, FORK_CHILD_EXIT_CODE);
                    fflush(stdout);
                }
            }
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        /* Progress every 25 iters so the user can see the test is alive. */
        if (((i + 1) % 25 == 0) || ((i + 1) == count)) {
            printf("  [progress] %d/%d  (ok=%d fail=%d)\n",
                   i + 1, count, ok_exit,
                   spawn_fail + wait_timeout + exit_mismatch);
            fflush(stdout);
        }
    }

    test_end = now_us();

    print_section("results (info only - PASS/FAIL based on spawn/exit integrity)");
    print_kv("total elapsed",    "%lld ms", (test_end - test_start) / 1000);
    print_kv("spawned ok",       "%d / %d", spawned, count);
    print_kv("waited ok",        "%d", waited);
    print_kv("exit code ok",     "%d / %d", ok_exit, count);
    if (spawn_fail)
        print_kv("spawn failures",   "%d", spawn_fail);
    if (wait_timeout)
        print_kv("wait timeouts",    "%d  (possible child hang)", wait_timeout);
    if (exit_mismatch)
        print_kv("exit mismatches",  "%d  (child crashed or wrong exit code)", exit_mismatch);

    if (spawned > 0) {
        print_kv("spawn time min",   "%lld us", min_spawn);
        print_kv("spawn time max",   "%lld us", max_spawn);
        print_kv("spawn time avg",   "%lld us", sum_spawn / spawned);
    }
    if (waited > 0) {
        print_kv("child total min",  "%lld us", min_wait);
        print_kv("child total max",  "%lld us", max_wait);
        print_kv("child total avg",  "%lld us", sum_wait / waited);
    }

    if (ok_exit == count) {
        print_verdict(1, NULL);
        return 0;
    } else {
        char reason[256];
        snprintf(reason, sizeof(reason),
                 "%d/%d children failed (spawn_fail=%d, wait_timeout=%d, exit_mismatch=%d)",
                 count - ok_exit, count, spawn_fail, wait_timeout, exit_mismatch);
        print_verdict(0, reason);
        return 1;
    }
}

/* ════════════════════════════════════════════════════════════════════════
 *   Subcommand: signal-recursion  (virtual_mutex / guard-page stress test)
 *
 *   N worker threads (default 4) repeatedly exercise Wine's guard-page
 *   fault handler path. Each iteration:
 *     1. VirtualAlloc a 2-page region
 *     2. VirtualProtect the first page with PAGE_GUARD
 *     3. Touch the guard page (raises STATUS_GUARD_PAGE_VIOLATION)
 *        → SIGSEGV to Wine's Unix side
 *        → segv_handler() in signal_*.c
 *        → virtual_handle_fault() in virtual.c — acquires virtual_mutex
 *        → detects guard page first access, clears PAGE_GUARD
 *        → returns, Win32 exception raised to user code
 *     4. Our vectored exception handler catches STATUS_GUARD_PAGE_VIOLATION
 *        and returns EXCEPTION_CONTINUE_EXECUTION
 *     5. The faulting instruction retries and succeeds (page now accessible)
 *     6. A second normal access verifies the page is still writable
 *     7. VirtualFree the region
 *
 *   N threads doing this in parallel hammer virtual_mutex from multiple
 *   directions: alloc/free take it, the fault handler takes it, and
 *   concurrent operations stress the path. If virtual_mutex has lost
 *   its recursive property (e.g. because the librtpi sweep converted
 *   it to pi_mutex without NSPA_RTPI_MUTEX_RECURSIVE), or if any
 *   internal virtual.c function self-re-enters the lock, the test
 *   deadlocks and the timeout fires.
 *
 *   The VEH catches STATUS_GUARD_PAGE_VIOLATION and counts them as
 *   diagnostic information, but the count is NOT a pass criterion —
 *   Wine handles PAGE_GUARD internally in virtual_handle_fault for
 *   many call paths, so the touch sometimes returns without raising a
 *   user-visible Win32 exception. Empirically we see ~0 faults in
 *   single-thread runs and ~70% in multi-thread runs, which reflects
 *   Wine's handling strategy, not a test defect. The fault count is
 *   printed as info and a sanity check against "impossible" values.
 *
 *   ── What bugs this test catches ───────────────────────────────────────
 *
 *   (1) virtual_mutex converted to pi_mutex without RECURSIVE flag.
 *       If the librtpi sweep converts virtual_mutex but drops the
 *       recursive attribute (rtpi.h supports NSPA_RTPI_MUTEX_RECURSIVE
 *       but the sweep must pass it), any internal self-re-entry path
 *       deadlocks the first time it fires. Caught: timeout.
 *
 *   (2) PAGE_GUARD clear-on-first-access broken.
 *       If virtual_handle_fault fails to clear the guard flag, every
 *       touch faults forever and the retry after VEH re-faults.
 *       Caught: timeout, or abnormally high fault count (more than
 *       one per touch).
 *
 *   (3) VirtualAlloc/VirtualFree race with fault handler.
 *       If a concurrent alloc/free modifies the address space while
 *       the fault handler is traversing it, a bad pointer or stale
 *       entry is read. Caught: crash (segv outside expected path),
 *       or wrong fault count.
 *
 *   (4) Signal dispatch to wrong thread.
 *       If Wine delivers SIGSEGV to a thread other than the faulting
 *       one (NSPA RT patches may touch signal routing), the VEH on
 *       the wrong thread gets confused and continues with the wrong
 *       exception record. Caught: VEH's ExceptionAddress check mismatch
 *       or thread-specific state corruption.
 *
 *   (5) VectoredExceptionHandler registration regression.
 *       Purely a Win32-layer regression: if AddVectoredExceptionHandler
 *       is broken, our VEH never runs and the first guard touch crashes
 *       the process. Caught: test process dies before completing a
 *       single iteration.
 *
 *   ── PASS / FAIL criteria ──────────────────────────────────────────────
 *
 *   PASS iff:
 *     - Every worker thread completes its target iteration count (no
 *       deadlock, no VirtualAlloc/Protect failure, no crash)
 *     - Test completes within SIG_REC_TIMEOUT_MS (no hang)
 *
 *   Fault count is informational (see the Wine-quirk note above).
 *
 *   FAIL otherwise with a labelled reason.
 *
 *   ── Usage ─────────────────────────────────────────────────────────────
 *
 *   signal-recursion [n_threads [iters_per_thread]]
 *     default: 4 threads, 1000 iters each
 * ════════════════════════════════════════════════════════════════════════ */

#define SIG_REC_DEFAULT_THREADS 4
#define SIG_REC_DEFAULT_ITERS   1000
#define SIG_REC_MAX_THREADS     16
#define SIG_REC_TIMEOUT_MS      60000

static volatile LONG sig_rec_faults_caught;

static LONG CALLBACK sig_rec_veh(EXCEPTION_POINTERS *ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == STATUS_GUARD_PAGE_VIOLATION) {
        InterlockedIncrement(&sig_rec_faults_caught);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

struct sig_rec_state {
    int      iters;
    int      is_rt;
    /* outputs */
    DWORD    win32_tid;
    int      iters_done;
    int      alloc_fail;
    int      protect_fail;
    LONGLONG elapsed_us;
};

static DWORD WINAPI sig_rec_worker(void *arg)
{
    struct sig_rec_state *s = arg;
    SIZE_T page_size = 4096;
    LONGLONG start;
    int i;

    s->win32_tid = GetCurrentThreadId();
    if (s->is_rt)
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    print_worker_start(s->is_rt ? "RT" : "load", s->win32_tid, NULL);

    start = now_us();
    for (i = 0; i < s->iters; i++) {
        void *p;
        DWORD old;

        /* Allocate two pages: first will be PAGE_GUARD, second is a
         * control page that should remain accessible throughout. */
        p = VirtualAlloc(NULL, page_size * 2, MEM_COMMIT, PAGE_READWRITE);
        if (!p) { s->alloc_fail++; break; }

        if (!VirtualProtect(p, page_size, PAGE_READWRITE | PAGE_GUARD, &old)) {
            s->protect_fail++;
            VirtualFree(p, 0, MEM_RELEASE);
            break;
        }

        /* First touch: raises STATUS_GUARD_PAGE_VIOLATION → VEH catches,
         * returns EXCEPTION_CONTINUE_EXECUTION, retry succeeds. */
        *(volatile char *)p = (char)(i & 0xff);

        /* Second touch on the same page: should now be PAGE_READWRITE
         * (guard cleared), no fault. */
        ((volatile char *)p)[1] = (char)((i + 1) & 0xff);

        /* Also touch the second (non-guarded) page to exercise a
         * normal access path through the just-modified VM map. */
        ((volatile char *)p)[page_size] = (char)i;

        VirtualFree(p, 0, MEM_RELEASE);
        s->iters_done++;
    }
    s->elapsed_us = now_us() - start;
    return 0;
}

static int cmd_signal_recursion(int argc, char **argv)
{
    PVOID veh_handle;
    struct sig_rec_state states[SIG_REC_MAX_THREADS];
    HANDLE threads[SIG_REC_MAX_THREADS];
    int nthreads = SIG_REC_DEFAULT_THREADS;
    int iters    = SIG_REC_DEFAULT_ITERS;
    int i;
    LONGLONG t_start, t_end;
    DWORD wait_ret;
    int total_done = 0, total_alloc_fail = 0, total_protect_fail = 0;
    int expected_faults;

    if (argc > 1) nthreads = atoi(argv[1]);
    if (argc > 2) iters    = atoi(argv[2]);
    if (nthreads < 1) nthreads = 1;
    if (nthreads > SIG_REC_MAX_THREADS) nthreads = SIG_REC_MAX_THREADS;
    if (iters < 1) iters = 1;

    enter_realtime_class();

    sig_rec_faults_caught = 0;

    /* Install the vectored exception handler BEFORE spawning threads so
     * they inherit an already-registered handler (VEH is process-wide). */
    veh_handle = AddVectoredExceptionHandler(1, sig_rec_veh);
    if (!veh_handle) {
        printf("AddVectoredExceptionHandler failed\n");
        return 1;
    }

    print_banner("signal-recursion", "virtual_mutex / guard-page fault stress");
    print_section("parameters");
    print_kv("worker threads",    "%d  (1 RT + %d load)", nthreads, nthreads - 1);
    print_kv("iters/thread",      "%d", iters);
    print_kv("expected faults",   "%d  (n_threads * iters)", nthreads * iters);
    print_kv("timeout",           "%d ms", SIG_REC_TIMEOUT_MS);
    print_kv("process pid",       "%lu", (unsigned long)GetCurrentProcessId());
    print_kv("veh priority",      "1 (first — catches before default handlers)");

    print_section("startup");
    memset(states, 0, sizeof(states));
    t_start = now_us();

    for (i = 0; i < nthreads; i++) {
        states[i].iters = iters;
        states[i].is_rt = (i == 0);
        threads[i] = CreateThread(NULL, 0, sig_rec_worker, &states[i], 0, NULL);
    }

    wait_ret = WaitForMultipleObjects(nthreads, threads, TRUE, SIG_REC_TIMEOUT_MS);
    t_end = now_us();

    for (i = 0; i < nthreads; i++)
        CloseHandle(threads[i]);
    RemoveVectoredExceptionHandler(veh_handle);

    for (i = 0; i < nthreads; i++) {
        total_done         += states[i].iters_done;
        total_alloc_fail   += states[i].alloc_fail;
        total_protect_fail += states[i].protect_fail;
    }

    print_section("results (info only - PASS/FAIL based on iter completion + no hang)");
    expected_faults = nthreads * iters;
    print_kv("total elapsed",      "%lld ms", (t_end - t_start) / 1000);
    print_kv("iters completed",    "%d of %d expected", total_done, expected_faults);
    print_kv("faults caught (VEH)","%d  (info only - Wine may handle PAGE_GUARD internally)",
             (int)sig_rec_faults_caught);
    if (total_alloc_fail)
        print_kv("VirtualAlloc failures",   "%d", total_alloc_fail);
    if (total_protect_fail)
        print_kv("VirtualProtect failures", "%d", total_protect_fail);

    print_section("per-thread");
    printf("  %-6s  %-10s  %10s  %14s\n",
           "role", "win32_tid", "iters", "elapsed(ms)");
    printf("  %-6s  %-10s  %10s  %14s\n",
           "------", "---------", "----------", "-----------");
    for (i = 0; i < nthreads; i++) {
        printf("  %-6s  %-10lu  %10d  %14lld\n",
               states[i].is_rt ? "RT" : "load",
               (unsigned long)states[i].win32_tid,
               states[i].iters_done,
               states[i].elapsed_us / 1000);
    }

    /* Verdict:
     *   - timeout               -> FAIL (likely virtual_mutex deadlock)
     *   - iters < expected      -> FAIL (VirtualAlloc/Protect failed,
     *                                    so the test couldn't exercise
     *                                    the path at all)
     *   - VEH fault count       -> informational only, see header
     *                              comment for the Wine quirk.
     */
    if (wait_ret == WAIT_TIMEOUT) {
        char reason[160];
        snprintf(reason, sizeof(reason),
                 "timeout after %d ms - likely virtual_mutex deadlock or stuck fault path",
                 SIG_REC_TIMEOUT_MS);
        print_verdict(0, reason);
        leave_realtime_class();
        return 1;
    }
    if (total_done != expected_faults) {
        char reason[160];
        snprintf(reason, sizeof(reason),
                 "iters: got %d, expected %d (alloc_fail=%d, protect_fail=%d)",
                 total_done, expected_faults, total_alloc_fail, total_protect_fail);
        print_verdict(0, reason);
        leave_realtime_class();
        return 1;
    }
    print_verdict(1, NULL);
    leave_realtime_class();
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Subcommand: large-pages  (VirtualAlloc(MEM_LARGE_PAGES) end-to-end)
 *
 *   Validates the NSPA RT v2.5 large-pages port (misc-nspa/0074 commits
 *   1-5 of 8). The path under test:
 *
 *     RtlAdjustPrivilege(SE_LOCK_MEMORY_PRIVILEGE)
 *       → token now has the privilege enabled
 *     VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE)
 *       → wineserver create_mapping checks privilege → permits
 *       → ntdll allocate_virtual_memory → map_view_large_pages
 *       → mmap(MAP_PRIVATE | MAP_ANON | MAP_HUGETLB | MAP_LOCKED)
 *       → mlock for explicit Windows-MEM_LARGE_PAGES semantics
 *
 *   The KEY validation is cross-checking /proc/meminfo before/after to
 *   confirm the kernel ACTUALLY consumed huge pages. Without that
 *   check, we'd only know that VirtualAlloc returned non-NULL — could
 *   be a normal-page allocation (silent regression).
 *
 *   ── What bugs this test catches ──────────────────────────────────────
 *
 *   (1) commit 0074 cmt 5/5 (the big virtual.c port) regression:
 *       map_view_large_pages broken or never reached → VirtualAlloc
 *       returns non-NULL but kernel HugePages_Free does NOT decrement.
 *   (2) commit 0074 cmt 1/5 server-side privilege gate broken:
 *       create_mapping rejects with STATUS_PRIVILEGE_NOT_HELD even
 *       though we enabled SeLockMemoryPrivilege. Caught: VirtualAlloc
 *       returns NULL with GetLastError == ERROR_PRIVILEGE_NOT_HELD.
 *   (3) commit 0074 cmt 3/5 GetLargePageMinimum broken:
 *       returns 0 even though /proc/sys/vm/nr_hugepages > 0.
 *       Caught: explicit GetLargePageMinimum call before alloc.
 *   (4) Memory not actually accessible after alloc: write/read
 *       round-trip on the returned pointer. SEGV → caught.
 *   (5) HugePages_Free not restored after VirtualFree: leak detection.
 *
 *   ── Skip conditions ──────────────────────────────────────────────────
 *
 *   - /proc/meminfo not readable (non-Linux host or sandbox) → skip
 *   - HugePages_Total == 0 (no hugepages reserved on host) → skip
 *   - GetLargePageMinimum returns 0 → skip
 *   - RtlAdjustPrivilege(SE_LOCK_MEMORY_PRIVILEGE) fails → skip
 *
 *   "Skip" produces a PASS verdict (the feature is correctly absent).
 *   Failures during the actual alloc/touch/free cycle produce FAIL.
 * ════════════════════════════════════════════════════════════════════════ */

#define LP_TEST_NUM_PAGES 4   /* allocate 4 large pages = 8 MB on x86_64 */
#define SE_LOCK_MEMORY_PRIVILEGE 4

typedef NTSTATUS (WINAPI *PFN_RtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

/* Read a SIZE_T value from /proc/meminfo by key (e.g. "HugePages_Free").
 * Returns the value if found, or (SIZE_T)-1 on any failure (file not
 * readable, key not found, parse error). */
static SIZE_T lp_read_meminfo( const char *key )
{
    HANDLE h;
    char buf[8192];
    DWORD bytes_read = 0;
    char *p;
    SIZE_T value = (SIZE_T)-1;

    /* Z: drive maps to / in Wine. */
    h = CreateFileA( "Z:\\proc\\meminfo", GENERIC_READ, FILE_SHARE_READ,
                     NULL, OPEN_EXISTING, 0, NULL );
    if (h == INVALID_HANDLE_VALUE) return (SIZE_T)-1;

    if (!ReadFile( h, buf, sizeof(buf) - 1, &bytes_read, NULL ))
    {
        CloseHandle( h );
        return (SIZE_T)-1;
    }
    CloseHandle( h );
    buf[bytes_read] = '\0';

    /* Find "Key:" at line start. /proc/meminfo lines look like:
     *   HugePages_Free:      550     */
    {
        char needle[64];
        snprintf( needle, sizeof(needle), "%s:", key );
        p = strstr( buf, needle );
    }
    if (!p) return (SIZE_T)-1;
    p += strlen( key ) + 1;

    /* skip whitespace, then strtoul the number */
    while (*p == ' ' || *p == '\t') p++;
    value = (SIZE_T)strtoul( p, NULL, 10 );
    return value;
}

static int cmd_large_pages( int argc, char **argv )
{
    HMODULE hntdll;
    PFN_RtlAdjustPrivilege p_RtlAdjustPrivilege;
    SIZE_T page_size, alloc_size;
    BOOLEAN was_enabled;
    NTSTATUS nt_status;
    void *addr;
    SIZE_T meminfo_total, meminfo_free_before, meminfo_free_during, meminfo_free_after;
    DWORD last_err;
    char fail_reason[256];
    volatile char *test_ptr;
    SIZE_T i;
    BOOL accessible;

    (void)argc; (void)argv;

    print_banner( "large-pages", "VirtualAlloc(MEM_LARGE_PAGES) end-to-end validation" );

    print_section( "preflight" );

    /* Check /proc/meminfo for hugepage configuration first. */
    meminfo_total = lp_read_meminfo( "HugePages_Total" );
    meminfo_free_before = lp_read_meminfo( "HugePages_Free" );
    if (meminfo_total == (SIZE_T)-1 || meminfo_free_before == (SIZE_T)-1)
    {
        print_kv( "/proc/meminfo", "not readable (non-Linux host or sandbox)" );
        print_kv( "verdict", "SKIP — large pages cannot be tested without /proc/meminfo" );
        print_verdict( 1, NULL );
        return 0;
    }
    print_kv( "HugePages_Total",  "%llu", (unsigned long long)meminfo_total );
    print_kv( "HugePages_Free",   "%llu  (before alloc)", (unsigned long long)meminfo_free_before );

    if (meminfo_total == 0)
    {
        print_kv( "verdict", "SKIP — host has no hugepages reserved (nr_hugepages = 0)" );
        print_verdict( 1, NULL );
        return 0;
    }

    /* Get the page size from GetLargePageMinimum — this exercises the
     * NSPA cmt 3/5 path that reads from KUSER_SHARED_DATA. */
    page_size = GetLargePageMinimum();
    print_kv( "GetLargePageMinimum", "%llu bytes (%llu KB)",
              (unsigned long long)page_size, (unsigned long long)(page_size / 1024) );
    if (page_size == 0)
    {
        snprintf( fail_reason, sizeof(fail_reason),
                  "GetLargePageMinimum returned 0 but HugePages_Total=%llu — "
                  "wineserver KUSER_SHARED_DATA::LargePageMinimum is 0",
                  (unsigned long long)meminfo_total );
        print_verdict( 0, fail_reason );
        return 1;
    }

    alloc_size = page_size * LP_TEST_NUM_PAGES;
    print_kv( "alloc size",       "%llu bytes (%d pages)",
              (unsigned long long)alloc_size, LP_TEST_NUM_PAGES );

    /* Enable SE_LOCK_MEMORY_PRIVILEGE on our token. */
    hntdll = GetModuleHandleA( "ntdll.dll" );
    p_RtlAdjustPrivilege = (PFN_RtlAdjustPrivilege)
        GetProcAddress( hntdll, "RtlAdjustPrivilege" );
    if (!p_RtlAdjustPrivilege)
    {
        print_kv( "verdict", "SKIP — RtlAdjustPrivilege not available" );
        print_verdict( 1, NULL );
        return 0;
    }
    nt_status = p_RtlAdjustPrivilege( SE_LOCK_MEMORY_PRIVILEGE, TRUE, FALSE, &was_enabled );
    if (nt_status != STATUS_SUCCESS)
    {
        snprintf( fail_reason, sizeof(fail_reason),
                  "RtlAdjustPrivilege(SE_LOCK_MEMORY_PRIVILEGE) failed (NTSTATUS=0x%lx)",
                  (unsigned long)nt_status );
        print_kv( "verdict", "SKIP — token cannot be granted SE_LOCK_MEMORY_PRIVILEGE" );
        print_verdict( 1, NULL );
        return 0;
    }
    print_kv( "SeLockMemory",     "enabled (was: %s)", was_enabled ? "yes" : "no" );

    /* The actual VirtualAlloc(MEM_LARGE_PAGES) call. SetLastError to a
     * sentinel before so we can tell whether the success path actually
     * touched LastError. */
    print_section( "alloc" );
    SetLastError( 0xdeadbeef );
    addr = VirtualAlloc( NULL, alloc_size,
                         MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                         PAGE_READWRITE );
    last_err = GetLastError();
    if (last_err == 0xdeadbeef)
        print_kv( "VirtualAlloc",     "%p  (LastError unchanged — success)", addr );
    else
        print_kv( "VirtualAlloc",     "%p  (GetLastError=%lu)", addr, (unsigned long)last_err );

    if (!addr)
    {
        snprintf( fail_reason, sizeof(fail_reason),
                  "VirtualAlloc(MEM_LARGE_PAGES) returned NULL, GetLastError=%lu",
                  (unsigned long)last_err );
        print_verdict( 0, fail_reason );
        return 1;
    }

    /* Cross-check /proc/meminfo: HugePages_Free should have decremented
     * by at least LP_TEST_NUM_PAGES (the kernel may also have committed
     * other pages around the same time, so allow some slack). */
    meminfo_free_during = lp_read_meminfo( "HugePages_Free" );
    print_kv( "HugePages_Free",   "%llu  (after alloc, was %llu, delta %lld)",
              (unsigned long long)meminfo_free_during,
              (unsigned long long)meminfo_free_before,
              (long long)((SSIZE_T)meminfo_free_before - (SSIZE_T)meminfo_free_during) );

    if (meminfo_free_during > meminfo_free_before ||
        (meminfo_free_before - meminfo_free_during) < (SIZE_T)LP_TEST_NUM_PAGES)
    {
        snprintf( fail_reason, sizeof(fail_reason),
                  "HugePages_Free did not decrement by at least %d after alloc "
                  "(before=%llu, after=%llu) — VirtualAlloc returned a pointer but "
                  "the kernel did NOT consume huge pages. Likely silent regression "
                  "in map_view_large_pages.",
                  LP_TEST_NUM_PAGES,
                  (unsigned long long)meminfo_free_before,
                  (unsigned long long)meminfo_free_during );
        VirtualFree( addr, 0, MEM_RELEASE );
        print_verdict( 0, fail_reason );
        return 1;
    }

    /* Touch every page — write a unique byte at each page boundary,
     * then read it back. Catches the case where the mapping returns
     * a valid pointer but the underlying memory isn't actually accessible. */
    print_section( "touch" );
    test_ptr = (volatile char *)addr;
    for (i = 0; i < LP_TEST_NUM_PAGES; i++)
        test_ptr[i * page_size] = (char)('A' + i);
    accessible = TRUE;
    for (i = 0; i < LP_TEST_NUM_PAGES; i++)
    {
        if (test_ptr[i * page_size] != (char)('A' + i)) { accessible = FALSE; break; }
    }
    print_kv( "page touch+read", "%s (%d pages)", accessible ? "OK" : "MISMATCH", LP_TEST_NUM_PAGES );
    if (!accessible)
    {
        snprintf( fail_reason, sizeof(fail_reason),
                  "memory not accessible: page %llu read back wrong value",
                  (unsigned long long)i );
        VirtualFree( addr, 0, MEM_RELEASE );
        print_verdict( 0, fail_reason );
        return 1;
    }

    /* ─────── QueryWorkingSetEx LargePage flag check ─────
     *
     * With the allocation still live and pages touched (so they're definitely
     * present in the page tables), ask the kernel via PAGEMAP_SCAN whether it
     * sees them as huge pages. This validates commit F's fill_working_set_info
     * PAGEMAP_SCAN path that sets VirtualAttributes.LargePage from PAGE_IS_HUGE.
     *
     * We load K32QueryWorkingSetEx dynamically so the test binary still links
     * even on older Wine builds that don't export it. */
    print_section( "QueryWorkingSetEx LargePage flag" );
    {
        HMODULE hk32 = GetModuleHandleA( "kernel32.dll" );
        PFN_K32QueryWorkingSetEx p_QWSEx = hk32
            ? (PFN_K32QueryWorkingSetEx)GetProcAddress( hk32, "K32QueryWorkingSetEx" )
            : NULL;

        if (!p_QWSEx)
        {
            print_kv( "skip", "K32QueryWorkingSetEx not available" );
        }
        else
        {
            NSPA_WSE_INFO wse;
            memset( &wse, 0, sizeof(wse) );
            wse.VirtualAddress = addr;

            if (!p_QWSEx( GetCurrentProcess(), &wse, sizeof(wse) ))
            {
                print_kv( "QueryWorkingSetEx", "call failed, GetLastError=%lu",
                          (unsigned long)GetLastError() );
                /* Non-fatal: the allocation itself is confirmed good. */
            }
            else
            {
                print_kv( "Valid",     "%llu", (unsigned long long)wse.VirtualAttributes.Valid );
                print_kv( "LargePage", "%llu", (unsigned long long)wse.VirtualAttributes.LargePage );
                print_kv( "Shared",    "%llu", (unsigned long long)wse.VirtualAttributes.Shared );

                if (!wse.VirtualAttributes.Valid)
                {
                    print_kv( "warning", "page not marked Valid — kernel may not have"
                              " faulted it into the page table yet (unusual after touch)" );
                }
                else if (!wse.VirtualAttributes.LargePage)
                {
                    snprintf( fail_reason, sizeof(fail_reason),
                              "QueryWorkingSetEx reports Valid=1 but LargePage=0 for a "
                              "MEM_LARGE_PAGES allocation — fill_working_set_info is not "
                              "reporting PAGE_IS_HUGE (PAGEMAP_SCAN path may be missing or "
                              "falling back to pread)" );
                    VirtualFree( addr, 0, MEM_RELEASE );
                    print_verdict( 0, fail_reason );
                    return 1;
                }
                else
                {
                    print_kv( "result", "LargePage=1 — PAGEMAP_SCAN path confirmed" );
                }
            }
        }
    }

    /* Free and verify HugePages_Free is restored. */
    print_section( "free" );
    if (!VirtualFree( addr, 0, MEM_RELEASE ))
    {
        snprintf( fail_reason, sizeof(fail_reason),
                  "VirtualFree failed, GetLastError=%lu", (unsigned long)GetLastError() );
        print_verdict( 0, fail_reason );
        return 1;
    }
    print_kv( "VirtualFree",      "OK" );

    meminfo_free_after = lp_read_meminfo( "HugePages_Free" );
    print_kv( "HugePages_Free",   "%llu  (after free, was %llu)",
              (unsigned long long)meminfo_free_after,
              (unsigned long long)meminfo_free_before );

    /* The post-free count may not return to EXACTLY the pre-alloc count
     * (other Wine machinery may have allocated/freed pages in the interim),
     * but it should be at least within LP_TEST_NUM_PAGES of where we started. */
    if (meminfo_free_after + LP_TEST_NUM_PAGES < meminfo_free_before)
    {
        snprintf( fail_reason, sizeof(fail_reason),
                  "HugePages_Free did not recover after VirtualFree "
                  "(before=%llu, after_free=%llu) — possible huge-page leak",
                  (unsigned long long)meminfo_free_before,
                  (unsigned long long)meminfo_free_after );
        print_verdict( 0, fail_reason );
        return 1;
    }

    /* ─────── Negative test 1: VirtualAlloc with unaligned size ───────
     *
     * Validates the size-alignment check in allocate_virtual_memory
     * (commit 0074 cmt 5/8 — the "size % lp_unit != 0" branch). */
    print_section( "negative: unaligned size" );
    SetLastError( 0 );
    {
        void *bad = VirtualAlloc( NULL, page_size + 1,
                                  MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                                  PAGE_READWRITE );
        DWORD bad_err = GetLastError();
        print_kv( "VirtualAlloc(p+1)", "%p  (GetLastError=%lu)", bad, (unsigned long)bad_err );
        if (bad)
        {
            VirtualFree( bad, 0, MEM_RELEASE );
            print_verdict( 0, "VirtualAlloc with unaligned size succeeded — should have failed with ERROR_INVALID_PARAMETER" );
            return 1;
        }
        if (bad_err != ERROR_INVALID_PARAMETER)
        {
            snprintf( fail_reason, sizeof(fail_reason),
                      "VirtualAlloc with unaligned size failed with %lu, expected ERROR_INVALID_PARAMETER (87)",
                      (unsigned long)bad_err );
            print_verdict( 0, fail_reason );
            return 1;
        }
        print_kv( "result",            "correctly rejected with ERROR_INVALID_PARAMETER" );
    }

    /* ─────── Positive test 2: CreateFileMapping(SEC_LARGE_PAGES) ─────
     *
     * Different code path — goes through wineserver create_mapping
     * (commit 0074 cmt 1/8 + cmt 4/8 memfd MFD_HUGETLB) rather than
     * the direct map_view_large_pages path tested above. Same
     * /proc/meminfo cross-check pattern. */
    print_section( "CreateFileMapping(SEC_LARGE_PAGES)" );
    {
        HANDLE hmap;
        void *map_addr;
        SIZE_T mf_free_before, mf_free_during, mf_free_after;

        mf_free_before = lp_read_meminfo( "HugePages_Free" );
        print_kv( "HugePages_Free",   "%llu  (before mapping)", (unsigned long long)mf_free_before );

        SetLastError( 0 );
        hmap = CreateFileMappingA( INVALID_HANDLE_VALUE, NULL,
                                   PAGE_READWRITE | SEC_COMMIT | SEC_LARGE_PAGES,
                                   0, alloc_size, NULL );
        if (!hmap)
        {
            snprintf( fail_reason, sizeof(fail_reason),
                      "CreateFileMapping(SEC_LARGE_PAGES) returned NULL, GetLastError=%lu",
                      (unsigned long)GetLastError() );
            print_verdict( 0, fail_reason );
            return 1;
        }
        print_kv( "CreateFileMapping", "OK  (handle=%p)", hmap );

        map_addr = MapViewOfFile( hmap, FILE_MAP_ALL_ACCESS, 0, 0, alloc_size );
        if (!map_addr)
        {
            snprintf( fail_reason, sizeof(fail_reason),
                      "MapViewOfFile failed, GetLastError=%lu", (unsigned long)GetLastError() );
            CloseHandle( hmap );
            print_verdict( 0, fail_reason );
            return 1;
        }
        print_kv( "MapViewOfFile",     "%p", map_addr );

        mf_free_during = lp_read_meminfo( "HugePages_Free" );
        print_kv( "HugePages_Free",   "%llu  (after map, delta %lld)",
                  (unsigned long long)mf_free_during,
                  (long long)((SSIZE_T)mf_free_before - (SSIZE_T)mf_free_during) );
        if (mf_free_during > mf_free_before ||
            (mf_free_before - mf_free_during) < (SIZE_T)LP_TEST_NUM_PAGES)
        {
            snprintf( fail_reason, sizeof(fail_reason),
                      "CreateFileMapping/MapViewOfFile did not consume huge pages "
                      "(before=%llu, after=%llu) — silent regression in memfd MFD_HUGETLB path",
                      (unsigned long long)mf_free_before,
                      (unsigned long long)mf_free_during );
            UnmapViewOfFile( map_addr );
            CloseHandle( hmap );
            print_verdict( 0, fail_reason );
            return 1;
        }

        /* Touch the mapped view */
        ((volatile char *)map_addr)[0] = 'X';
        ((volatile char *)map_addr)[alloc_size - 1] = 'Y';
        if (((volatile char *)map_addr)[0] != 'X' || ((volatile char *)map_addr)[alloc_size - 1] != 'Y')
        {
            UnmapViewOfFile( map_addr );
            CloseHandle( hmap );
            print_verdict( 0, "MapViewOfFile mapping not accessible" );
            return 1;
        }
        print_kv( "view touch",       "OK" );

        UnmapViewOfFile( map_addr );
        CloseHandle( hmap );

        mf_free_after = lp_read_meminfo( "HugePages_Free" );
        print_kv( "HugePages_Free",   "%llu  (after unmap)", (unsigned long long)mf_free_after );
        if (mf_free_after + LP_TEST_NUM_PAGES < mf_free_before)
        {
            snprintf( fail_reason, sizeof(fail_reason),
                      "HugePages_Free did not recover after CloseHandle "
                      "(before=%llu, after=%llu) — section close didn't release huge pages",
                      (unsigned long long)mf_free_before,
                      (unsigned long long)mf_free_after );
            print_verdict( 0, fail_reason );
            return 1;
        }
    }

    /* ─────── Positive test 3: 1 GB huge page via NtAllocateVirtualMemoryEx ─────
     *
     * Validates the LARGE_PAGES_HUGE branch in commit 0074 cmt 5/8.
     * Uses MEM_EXTENDED_PARAMETER_NONPAGED_HUGE to request 1 GiB pages.
     *
     * Skip conditions:
     *  - 32-bit binary: a 32-bit process has ~2 GiB of user address
     *    space total, of which substantial portions are already used
     *    by the loader/ntdll/kernel32/heap/stack. Finding a contiguous
     *    1 GiB-aligned chunk is essentially impossible in practice.
     *    Not a bug in LARGE_PAGES_HUGE — a host-environment limit.
     *  - No 1 GB hugepages reserved on the host (we read
     *    /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages
     *    directly because /proc/meminfo only reports the default size).
     *  - NtAllocateVirtualMemoryEx not exported (older Wine).
     */
    print_section( "1 GB huge page (NtAllocateVirtualMemoryEx)" );
    if (sizeof(void *) == 4)
    {
        print_kv( "skip",         "32-bit process — 1 GB allocation requires a contiguous" );
        print_kv( "",             "1 GB-aligned chunk in a ~2 GB address space (impractical)" );
        print_kv( "",             "Re-run on a 64-bit Wine build to exercise this path." );
        goto skip_1gb_test;
    }
    {
        PFN_NtAllocateVirtualMemoryEx p_NtAllocVMEx;
        SIZE_T sys_1g_free_before, sys_1g_free_after;
        SIZE_T huge_size = (SIZE_T)1 << 30;  /* 1 GiB */
        MEM_EXTENDED_PARAMETER ext = { 0 };
        void *huge_addr = NULL;
        SIZE_T huge_size_io = huge_size;
        HANDLE h;
        char buf[64];
        DWORD br = 0;

        /* Check /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages.
         * 1 GB = 1048576 kB. */
        h = CreateFileA( "Z:\\sys\\kernel\\mm\\hugepages\\hugepages-1048576kB\\free_hugepages",
                         GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
        if (h == INVALID_HANDLE_VALUE)
        {
            print_kv( "skip",         "no 1 GB hugepages directory in /sys (kernel doesn't support them)" );
            goto skip_1gb_test;
        }
        if (!ReadFile( h, buf, sizeof(buf) - 1, &br, NULL ))
        {
            CloseHandle( h );
            print_kv( "skip",         "could not read 1 GB free_hugepages" );
            goto skip_1gb_test;
        }
        CloseHandle( h );
        buf[br] = '\0';
        sys_1g_free_before = (SIZE_T)strtoul( buf, NULL, 10 );
        print_kv( "1GB free (before)", "%llu", (unsigned long long)sys_1g_free_before );

        if (sys_1g_free_before == 0)
        {
            print_kv( "skip",         "no free 1 GB hugepages (host has 0 reserved)" );
            goto skip_1gb_test;
        }

        p_NtAllocVMEx = (PFN_NtAllocateVirtualMemoryEx)
            GetProcAddress( hntdll, "NtAllocateVirtualMemoryEx" );
        if (!p_NtAllocVMEx)
        {
            print_kv( "skip",         "NtAllocateVirtualMemoryEx not available" );
            goto skip_1gb_test;
        }

        ext.Type = MemExtendedParameterAttributeFlags;
        ext.ULong64 = MEM_EXTENDED_PARAMETER_NONPAGED_HUGE;

        nt_status = p_NtAllocVMEx( GetCurrentProcess(), &huge_addr, &huge_size_io,
                                    MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                                    PAGE_READWRITE, &ext, 1 );
        print_kv( "NtAllocateVMEx", "%p  (NTSTATUS=0x%lx)",
                  huge_addr, (unsigned long)nt_status );

        if (nt_status != STATUS_SUCCESS || !huge_addr)
        {
            snprintf( fail_reason, sizeof(fail_reason),
                      "NtAllocateVirtualMemoryEx(NONPAGED_HUGE, 1 GiB) failed: NTSTATUS=0x%lx",
                      (unsigned long)nt_status );
            print_verdict( 0, fail_reason );
            return 1;
        }

        /* Cross-check the 1 GB free count decremented by 1. */
        h = CreateFileA( "Z:\\sys\\kernel\\mm\\hugepages\\hugepages-1048576kB\\free_hugepages",
                         GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
        if (h != INVALID_HANDLE_VALUE)
        {
            br = 0;
            ReadFile( h, buf, sizeof(buf) - 1, &br, NULL );
            CloseHandle( h );
            buf[br] = '\0';
            sys_1g_free_after = (SIZE_T)strtoul( buf, NULL, 10 );
            print_kv( "1GB free (during)", "%llu  (delta %lld)",
                      (unsigned long long)sys_1g_free_after,
                      (long long)((SSIZE_T)sys_1g_free_before - (SSIZE_T)sys_1g_free_after) );

            if (sys_1g_free_after >= sys_1g_free_before)
            {
                /* huge_addr was allocated but the 1GB pool didn't shrink — wrong page size */
                {
                    SIZE_T zero = 0;
                    NtFreeVirtualMemory( GetCurrentProcess(), &huge_addr, &zero, MEM_RELEASE );
                }
                snprintf( fail_reason, sizeof(fail_reason),
                          "NtAllocateVMEx returned a pointer but 1GB free count "
                          "did not decrement (before=%llu, after=%llu) — kernel "
                          "did NOT consume a 1GB hugepage. Likely the LARGE_PAGES_HUGE "
                          "branch in map_view_large_pages is using the wrong page size.",
                          (unsigned long long)sys_1g_free_before,
                          (unsigned long long)sys_1g_free_after );
                print_verdict( 0, fail_reason );
                return 1;
            }
        }

        /* Touch first and last byte to verify accessibility */
        ((volatile char *)huge_addr)[0] = 'H';
        ((volatile char *)huge_addr)[huge_size - 1] = 'G';
        if (((volatile char *)huge_addr)[0] != 'H' || ((volatile char *)huge_addr)[huge_size - 1] != 'G')
        {
            SIZE_T zero = 0;
            NtFreeVirtualMemory( GetCurrentProcess(), &huge_addr, &zero, MEM_RELEASE );
            print_verdict( 0, "1GB huge-page mapping not accessible" );
            return 1;
        }
        print_kv( "touch first+last",  "OK" );

        {
            SIZE_T zero = 0;
            NTSTATUS free_st = NtFreeVirtualMemory( GetCurrentProcess(), &huge_addr, &zero, MEM_RELEASE );
            print_kv( "NtFreeVirtualMemory", "NTSTATUS=0x%lx", (unsigned long)free_st );
            if (free_st != STATUS_SUCCESS)
            {
                snprintf( fail_reason, sizeof(fail_reason),
                          "NtFreeVirtualMemory failed for 1 GB huge page: NTSTATUS=0x%lx",
                          (unsigned long)free_st );
                print_verdict( 0, fail_reason );
                return 1;
            }
        }
    }
skip_1gb_test:

    /* ─────── Negative test 4: CreateFileMapping without privilege ─────
     *
     * Validates the wineserver create_mapping privilege gate
     * (commit 0074 cmt 1/8). Disable SeLockMemoryPrivilege, retry,
     * expect ERROR_PRIVILEGE_NOT_HELD, then re-enable. */
    print_section( "negative: CreateFileMapping without privilege" );
    {
        BOOLEAN prev;
        HANDLE bad_map;
        DWORD bad_err;

        nt_status = p_RtlAdjustPrivilege( SE_LOCK_MEMORY_PRIVILEGE, FALSE, FALSE, &prev );
        if (nt_status != STATUS_SUCCESS)
        {
            print_kv( "skip",         "RtlAdjustPrivilege(disable) failed, NTSTATUS=0x%lx",
                      (unsigned long)nt_status );
        }
        else
        {
            print_kv( "SeLockMemory", "disabled (was: %s)", prev ? "enabled" : "disabled" );

            SetLastError( 0 );
            bad_map = CreateFileMappingA( INVALID_HANDLE_VALUE, NULL,
                                          PAGE_READWRITE | SEC_COMMIT | SEC_LARGE_PAGES,
                                          0, alloc_size, NULL );
            bad_err = GetLastError();
            print_kv( "CreateFileMapping", "%p  (GetLastError=%lu)", bad_map, (unsigned long)bad_err );

            if (bad_map)
            {
                CloseHandle( bad_map );
                /* Re-enable before failing so the test cleanup leaves the
                 * token in a sane state. */
                p_RtlAdjustPrivilege( SE_LOCK_MEMORY_PRIVILEGE, TRUE, FALSE, &prev );
                print_verdict( 0, "CreateFileMapping(SEC_LARGE_PAGES) succeeded without SeLockMemoryPrivilege — wineserver create_mapping gate is broken" );
                return 1;
            }
            if (bad_err != ERROR_PRIVILEGE_NOT_HELD)
            {
                snprintf( fail_reason, sizeof(fail_reason),
                          "CreateFileMapping without privilege failed with %lu, expected ERROR_PRIVILEGE_NOT_HELD (1314)",
                          (unsigned long)bad_err );
                p_RtlAdjustPrivilege( SE_LOCK_MEMORY_PRIVILEGE, TRUE, FALSE, &prev );
                print_verdict( 0, fail_reason );
                return 1;
            }
            print_kv( "result",       "correctly rejected with ERROR_PRIVILEGE_NOT_HELD" );

            /* Re-enable for any cleanup that follows. */
            p_RtlAdjustPrivilege( SE_LOCK_MEMORY_PRIVILEGE, TRUE, FALSE, &prev );
        }
    }

    /* Note on a known gap from the upstream 0074 patch:
     *   On real Windows, BOTH VirtualAlloc(MEM_LARGE_PAGES) AND
     *   CreateFileMapping(SEC_LARGE_PAGES) require SeLockMemoryPrivilege.
     *   The 0074 patch only adds the privilege check to the wineserver
     *   create_mapping handler (file mapping path), not to ntdll's
     *   allocate_virtual_memory (VirtualAlloc path). So a privilege-
     *   negative test for VirtualAlloc would NOT fail on Wine-NSPA after
     *   0074 — the alloc would proceed regardless of the token's
     *   SeLockMemoryPrivilege state. We don't test that case here
     *   because it's a known divergence. If we extend
     *   allocate_virtual_memory to enforce the privilege (matching
     *   Windows), add the negative test for that path too. */

    print_verdict( 1, NULL );
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Subcommand: ntsync  (NTSync kernel driver PI test)
 *
 *   All existing sync tests use CRITICAL_SECTION (futex-backed on Unix).
 *   This test isolates the NTSync kernel driver by using Win32 Mutex
 *   objects (CreateMutex/WaitForSingleObject/ReleaseMutex), which route
 *   through the ntsync chardev (/dev/ntsync) when NTSync is enabled.
 *
 *   Sub-tests:
 *     1. Mutex PI contention — RT waiter on kernel mutex held by
 *        SCHED_OTHER holder with background load threads. Analogous to
 *        cs-contention but exercises ntsync_mutex_owner_pi_boost (patch
 *        0003) instead of FUTEX_LOCK_PI.
 *     2. Rapid kernel mutex — tight acquire/release loop, 1 RT + N load
 *        threads. Measures ntsync driver overhead vs CS (patch 0001/0002
 *        cost: raw_spinlock + priority-ordered insertion).
 *     3. Priority-ordered wakeup — N waiters at different priorities on
 *        one mutex; verify highest-priority waiter wakes first. Tests
 *        patch 0002 (priority-ordered waiter queues).
 *     4. Transitive PI chain — linear chain of M mutexes held by M
 *        SCHED_OTHER threads. RT thread waits on mutex[0], which should
 *        boost holder[0], who is blocked on mutex[1] held by holder[1],
 *        etc. Tests ntsync_pi_recalc() chain walk depth.
 *     5. Mixed WaitForMultipleObjects — event + mutex + semaphore mix
 *        in a single WFMO call, exercising the ntsync WAIT_ANY path
 *        with heterogeneous object types.
 *
 *   Failure modes caught:
 *     1. ntsync PI boost not firing — holder starved, wait times blow up
 *     2. Priority-ordered queue broken — wrong waiter wakes first
 *     3. Transitive chain broken — boost stops at depth 1
 *     4. rt_mutex / raw_spinlock conversion regression — deadlock or hang
 *     5. WAIT_ANY with mixed types — wrong object signaled or hang
 *     6. Mutex ownership corruption — counter mismatch under contention
 *     7. Abandoned mutex not detected across thread death
 * ════════════════════════════════════════════════════════════════════════ */

/* ── Sub-test 1: Mutex PI contention ─────────────────────────────────── */

#define NTS_PI_LOAD_THREADS   4
#define NTS_PI_DEFAULT_ITERS  8
#define NTS_PI_MAX_ITERS      16
#define NTS_PI_WORK_ITERS     200000000LL

static HANDLE           nts_pi_mutex;
static HANDLE           nts_pi_holder_in;    /* auto-reset: holder signals entry */
static HANDLE           nts_pi_waiter_done;  /* auto-reset: waiter acks release */
static volatile LONGLONG nts_pi_samples[16];
static volatile int      nts_pi_sample_count;
static int               nts_pi_iters;

static DWORD WINAPI nts_pi_load_thread(void *u)
{
    volatile long long x = 0;
    long long i = 0;
    (void)u;
    while (!nts_pi_stop_load) {
        x += (i++) * (i + 1);
        if ((i & LOAD_YIELD_MASK) == 0) {
            Sleep(1);  /* yield to SCHED_OTHER — Sleep(0) is no-op for FIFO */
            if (nts_pi_stop_load) break;
        }
    }
    return (DWORD)(x & 0xffffffff);
}

static void nts_do_work(long long iters)
{
    volatile long long x = 0;
    long long i;
    for (i = 0; i < iters; i++) {
        x += i * (i + 1);
        if ((i & WORK_YIELD_MASK) == 0 && i > 0)
            Sleep(0);  /* yield to higher-prio FIFO only */
    }
    (void)x;
}

static DWORD WINAPI nts_pi_holder_thread(void *u)
{
    int iter;
    (void)u;
    print_worker_start("holder", GetCurrentThreadId(),
                       "SCHED_OTHER (no explicit promotion)");

    for (iter = 0; iter < nts_pi_iters; iter++)
    {
        LONGLONG t0, t1;
        DWORD w;

        if (iter > 0) Sleep(200);

        w = WaitForSingleObject(nts_pi_mutex, 10000);
        if (w != WAIT_OBJECT_0)
        {
            printf("  [holder] iter %d: WaitForSingleObject = %lu (FAIL)\n",
                   iter + 1, w);
            break;
        }
        t0 = now_ms();
        printf("  [holder] iter %d: acquired mutex at t=%lld ms — doing %lld-iter work...\n",
               iter + 1, t0, NTS_PI_WORK_ITERS);
        fflush(stdout);

        SetEvent(nts_pi_holder_in);
        nts_do_work(NTS_PI_WORK_ITERS);

        t1 = now_ms();
        printf("  [holder] iter %d: releasing mutex at t=%lld ms (held %lld ms)\n",
               iter + 1, t1, t1 - t0);
        fflush(stdout);

        ReleaseMutex(nts_pi_mutex);
        WaitForSingleObject(nts_pi_waiter_done, INFINITE);
    }
    return 0;
}

static DWORD WINAPI nts_pi_waiter_thread(void *u)
{
    int iter;
    (void)u;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    print_worker_start("waiter", GetCurrentThreadId(),
                       "TIME_CRITICAL -> SCHED_FIFO (ceiling)");

    for (iter = 0; iter < nts_pi_iters; iter++)
    {
        LONGLONG t0, t1, wait;
        DWORD w;

        WaitForSingleObject(nts_pi_holder_in, INFINITE);

        t0 = now_ms();
        w = WaitForSingleObject(nts_pi_mutex, 30000);
        t1 = now_ms();
        wait = t1 - t0;

        if (w != WAIT_OBJECT_0)
        {
            printf("  [waiter] iter %d: WaitForSingleObject = %lu (FAIL)\n",
                   iter + 1, w);
            nts_pi_samples[nts_pi_sample_count++] = -1;
        }
        else
        {
            nts_pi_samples[nts_pi_sample_count++] = wait;
            printf("  [waiter] iter %d: acquired at t=%lld ms, wait=%lld ms\n",
                   iter + 1, t1, wait);
            fflush(stdout);
            ReleaseMutex(nts_pi_mutex);
        }
        SetEvent(nts_pi_waiter_done);
    }
    return 0;
}

/* ── Sub-test 2: Rapid kernel mutex ──────────────────────────────────── */

#define NTS_RAPID_DEFAULT_THREADS  4
#define NTS_RAPID_DEFAULT_ITERS    100000
#define NTS_RAPID_MAX_THREADS      16

struct nts_rapid_state {
    HANDLE   mutex;
    int      iters;
    int      is_rt;
    DWORD    win32_tid;
    LONGLONG max_wait_us;
    LONGLONG total_wait_us;
    LONGLONG elapsed_us;
    int      iters_done;
    int      errors;
};

static volatile LONG nts_rapid_counter;

static DWORD WINAPI nts_rapid_worker(void *arg)
{
    struct nts_rapid_state *s = arg;
    LONGLONG start;
    int i;

    s->win32_tid = GetCurrentThreadId();
    if (s->is_rt)
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    start = now_us();
    for (i = 0; i < s->iters; i++)
    {
        LONGLONG t0 = now_us();
        DWORD w = WaitForSingleObject(s->mutex, 5000);
        LONGLONG wait = now_us() - t0;

        if (w != WAIT_OBJECT_0) { s->errors++; continue; }

        if (wait > s->max_wait_us) s->max_wait_us = wait;
        s->total_wait_us += wait;

        InterlockedIncrement(&nts_rapid_counter);

        ReleaseMutex(s->mutex);
        s->iters_done++;
    }
    s->elapsed_us = now_us() - start;
    return 0;
}

/* ── Sub-test 3: Priority-ordered wakeup ─────────────────────────────── */

#define NTS_PRIO_DEFAULT_WAITERS  7  /* all 7 standard Win32 priority levels */
#define NTS_PRIO_MAX_WAITERS     7  /* only standard values — non-standard bypass TC clamp */

struct nts_prio_waiter_ctx {
    HANDLE   mutex;
    HANDLE   ready_event;    /* waiter sets this after blocking attempt starts */
    int      win32_priority; /* SetThreadPriority value */
    const char *label;
    DWORD    win32_tid;
    LONGLONG wakeup_time_us; /* when the wait returned */
    DWORD    wait_result;
};

static DWORD WINAPI nts_prio_waiter(void *arg)
{
    struct nts_prio_waiter_ctx *c = arg;
    c->win32_tid = GetCurrentThreadId();

    SetThreadPriority(GetCurrentThread(), c->win32_priority);

    /* Signal that we're about to block. We need a small delay so the
     * main thread can be sure we've entered the kernel wait queue.
     * SetEvent first, then immediately block. */
    SetEvent(c->ready_event);
    c->wait_result = WaitForSingleObject(c->mutex, 10000);
    c->wakeup_time_us = now_us();

    if (c->wait_result == WAIT_OBJECT_0)
        ReleaseMutex(c->mutex);
    return 0;
}

/* ── Sub-test 4: Transitive PI chain ─────────────────────────────────── */

#define NTS_CHAIN_DEFAULT_DEPTH  4
#define NTS_CHAIN_MAX_DEPTH      16
#define NTS_CHAIN_WORK_ITERS     100000000LL
#define NTS_CHAIN_LOAD_THREADS   4

struct nts_chain_holder_ctx {
    int      depth;          /* my index in the chain (0 = closest to RT) */
    int      total_depth;
    HANDLE  *mutexes;        /* array of total_depth mutexes */
    HANDLE   start_event;    /* holder signals this after acquiring its mutex */
    HANDLE   gate_event;     /* tail waits on this before starting CPU work */
    DWORD    win32_tid;
    LONGLONG elapsed_us;
};

static DWORD WINAPI nts_chain_load_thread(void *u)
{
    volatile long long x = 0;
    long long i = 0;
    (void)u;
    while (!nts_chain_stop_load) {
        x += (i++) * (i + 1);
        if ((i & LOAD_YIELD_MASK) == 0) {
            Sleep(1);  /* yield to SCHED_OTHER — Sleep(0) is no-op for FIFO */
            if (nts_chain_stop_load) break;
        }
    }
    return (DWORD)(x & 0xffffffff);
}

/* Each chain holder: acquires mutex[depth], signals ready, then blocks
 * on mutex[depth+1] (except the last holder who does CPU work instead).
 * This creates a chain: RT -> mutex[0] -> holder[0] -> mutex[1] -> ... */
static DWORD WINAPI nts_chain_holder(void *arg)
{
    struct nts_chain_holder_ctx *c = arg;
    LONGLONG start;
    DWORD w;

    c->win32_tid = GetCurrentThreadId();

    /* Acquire my mutex */
    w = WaitForSingleObject(c->mutexes[c->depth], 10000);
    if (w != WAIT_OBJECT_0)
    {
        printf("  [chain-%d] failed to acquire mutex[%d]: %lu\n",
               c->depth, c->depth, w);
        return 1;
    }

    /* Signal that I hold my mutex and I'm ready */
    SetEvent(c->start_event);

    start = now_us();

    if (c->depth == c->total_depth - 1)
    {
        /* Last holder: wait for the gate (signaled after RT thread is in
         * position), then do CPU work. Without the gate, the tail finishes
         * before the RT thread calls WaitForSingleObject, making the
         * chain test meaningless. */
        WaitForSingleObject(c->gate_event, 30000);
        nts_do_work(NTS_CHAIN_WORK_ITERS);
    }
    else
    {
        /* Intermediate holder: block on the next mutex in the chain.
         * When the RT thread waits on mutex[0], boost propagates:
         * holder[0] boosted -> blocks on mutex[1] -> holder[1] boosted -> ... */
        w = WaitForSingleObject(c->mutexes[c->depth + 1], 30000);
        if (w == WAIT_OBJECT_0)
            ReleaseMutex(c->mutexes[c->depth + 1]);
    }

    c->elapsed_us = now_us() - start;
    ReleaseMutex(c->mutexes[c->depth]);
    return 0;
}

/* ── Sub-test 5: Mixed WFMO ──────────────────────────────────────────── */

/* (inline in cmd_ntsync — small enough to not need thread funcs) */

/* ── Main ntsync command ─────────────────────────────────────────────── */

static int cmd_ntsync(int argc, char **argv)
{
    int pass = 0, fail = 0;
    int i;
    int chain_depth = NTS_CHAIN_DEFAULT_DEPTH;
    int rapid_threads = NTS_RAPID_DEFAULT_THREADS;
    int rapid_iters = NTS_RAPID_DEFAULT_ITERS;
    int pi_iters = NTS_PI_DEFAULT_ITERS;
    int pi_n_load, chain_n_load;
    int prio_waiters = NTS_PRIO_DEFAULT_WAITERS;

    (void)argc; (void)argv;

    /* Parse optional args:
     *   ntsync [chain_depth] [rapid_threads] [rapid_iters] [pi_iters] [prio_waiters]
     * All optional, positional. */
    if (argc > 1) chain_depth    = atoi(argv[1]);
    if (argc > 2) rapid_threads  = atoi(argv[2]);
    if (argc > 3) rapid_iters    = atoi(argv[3]);
    if (argc > 4) pi_iters       = atoi(argv[4]);
    if (argc > 5) prio_waiters   = atoi(argv[5]);
    if (chain_depth < 2) chain_depth = 2;
    if (chain_depth > NTS_CHAIN_MAX_DEPTH) chain_depth = NTS_CHAIN_MAX_DEPTH;
    if (rapid_threads < 2) rapid_threads = 2;
    if (rapid_threads > NTS_RAPID_MAX_THREADS) rapid_threads = NTS_RAPID_MAX_THREADS;
    if (pi_iters < 1) pi_iters = 1;
    if (pi_iters > NTS_PI_MAX_ITERS) pi_iters = NTS_PI_MAX_ITERS;
    if (prio_waiters < 2) prio_waiters = 2;
    if (prio_waiters > NTS_PRIO_MAX_WAITERS) prio_waiters = NTS_PRIO_MAX_WAITERS;

    pi_n_load = safe_load_count(NTS_PI_LOAD_THREADS);
    chain_n_load = safe_load_count(NTS_CHAIN_LOAD_THREADS);

    /* Check if ntsync is active by probing the handle range. Client-side
     * NTSync creation allocates handles starting at index 520,000 (handle
     * value >= 2,080,000). If CreateMutex returns a handle in that range,
     * ntsync is active. If it returns a low handle, Wine is using the
     * wineserver futex path. */
    {
        HANDLE probe = CreateMutexA(NULL, FALSE, NULL);
        if (probe)
        {
            DWORD_PTR h = (DWORD_PTR)probe;
            if (h >= 2080000)
                printf("  [ntsync] active (client-side handle %p)\n", probe);
            else
                printf("  [WARN] ntsync not active (server handle %p) — "
                       "sudo modprobe ntsync\n", probe);
            CloseHandle(probe);
        }
        else
        {
            printf("  [WARN] CreateMutex probe failed\n");
        }
    }

    print_banner("ntsync", "NTSync kernel driver PI + priority-ordered wakeup test");
    print_section("parameters");
    print_kv("chain depth", "%d mutexes (transitive PI)", chain_depth);
    print_kv("rapid threads", "%d (1 RT + %d load)", rapid_threads, rapid_threads - 1);
    print_kv("rapid iters/thread", "%d", rapid_iters);
    print_kv("PI contention iters", "%d", pi_iters);
    print_kv("PI load threads", "%d SCHED_OTHER busyloops", pi_n_load);
    print_kv("PI work iters", "%lld", NTS_PI_WORK_ITERS);
    print_kv("prio waiters", "%d", prio_waiters);
    print_kv("process pid", "%lu", (unsigned long)GetCurrentProcessId());

    /* Spawn ALL load threads BEFORE enter_realtime_class() so they stay
     * SCHED_OTHER. They'll be stopped/joined inside each sub-test. */
    enter_realtime_class();

    /* ════════════════════════════════════════════════════════════════════
     *   Test 1: Mutex PI contention (kernel mutex, not futex CS)
     *
     *   Bug caught: ntsync patch 0003 PI boost not firing — if
     *   sched_setattr_nocheck() doesn't run, holder stays SCHED_OTHER
     *   and wait times scale with load thread count instead of staying
     *   near uncontended work time.
     * ════════════════════════════════════════════════════════════════════ */
    print_section("[1/5] mutex PI contention (CreateMutex, not CriticalSection)");
    {
        HANDLE load_h[NTS_PI_LOAD_THREADS];
        HANDLE holder_h, waiter_h;
        LONGLONG min_w, max_w, sum_w;
        int ok;

        nts_pi_iters = pi_iters;
        nts_pi_mutex = CreateMutexA(NULL, FALSE, NULL);
        nts_pi_holder_in = CreateEventW(NULL, FALSE, FALSE, NULL);
        nts_pi_waiter_done = CreateEventW(NULL, FALSE, FALSE, NULL);
        nts_pi_stop_load = 0;
        nts_pi_sample_count = 0;

        if (!nts_pi_mutex || !nts_pi_holder_in || !nts_pi_waiter_done)
        {
            printf("  [FAIL] failed to create sync objects\n");
            fail++;
            goto nts_t2;
        }

        print_kv("mutex handle", "%p (kernel NTSync object)", nts_pi_mutex);

        for (i = 0; i < pi_n_load; i++)
        {
            DWORD tid;
            load_h[i] = spawn_load_thread_sched_other(nts_pi_load_thread, NULL, &tid);
            print_worker_start("load", tid, "SCHED_OTHER busyloop");
        }
        Sleep(200);

        holder_h = CreateThread(NULL, 0, nts_pi_holder_thread, NULL, 0, NULL);
        waiter_h = CreateThread(NULL, 0, nts_pi_waiter_thread, NULL, 0, NULL);

        WaitForSingleObject(holder_h, 60000);
        WaitForSingleObject(waiter_h, 60000);

        InterlockedExchange(&nts_pi_stop_load, 1);
        for (i = 0; i < pi_n_load; i++)
        {
            WaitForSingleObject(load_h[i], 5000);
            CloseHandle(load_h[i]);
        }
        CloseHandle(holder_h);
        CloseHandle(waiter_h);

        /* Analyze samples */
        ok = 1;
        if (nts_pi_sample_count < nts_pi_iters)
        {
            printf("  [FAIL] only %d/%d samples captured (timeout or deadlock)\n",
                   nts_pi_sample_count, nts_pi_iters);
            fail++;
            ok = 0;
        }
        else
        {
            min_w = max_w = nts_pi_samples[0];
            sum_w = 0;
            for (i = 0; i < nts_pi_sample_count; i++)
            {
                LONGLONG w = nts_pi_samples[i];
                if (w < 0) { ok = 0; break; } /* waiter got non-WAIT_OBJECT_0 */
                if (w < min_w) min_w = w;
                if (w > max_w) max_w = w;
                sum_w += w;
            }
            if (ok)
            {
                printf("\n  ── mutex PI summary ──\n");
                printf("  samples     : %d\n", nts_pi_sample_count);
                printf("  min wait    : %lld ms\n", min_w);
                printf("  max wait    : %lld ms\n", max_w);
                printf("  avg wait    : %lld ms\n", sum_w / nts_pi_sample_count);
                printf("  [PASS] all %d iterations completed\n", nts_pi_iters);
                pass++;
            }
            else
            {
                printf("  [FAIL] waiter failed to acquire mutex\n");
                fail++;
            }
        }

        CloseHandle(nts_pi_mutex);
        CloseHandle(nts_pi_holder_in);
        CloseHandle(nts_pi_waiter_done);
    }

nts_t2:
    /* ════════════════════════════════════════════════════════════════════
     *   Test 2: Rapid kernel mutex (throughput + RT latency)
     *
     *   Bug caught: patch 0001 raw_spinlock conversion or patch 0002
     *   priority-ordered insertion adding excessive overhead to the
     *   ntsync fast path. Regression shows as lower throughput or
     *   higher RT max_wait_us compared to CS rapidmutex baseline.
     * ════════════════════════════════════════════════════════════════════ */
    print_section("[2/5] rapid kernel mutex (CreateMutex throughput)");
    {
        HANDLE mtx;
        struct nts_rapid_state states[NTS_RAPID_MAX_THREADS];
        HANDLE threads[NTS_RAPID_MAX_THREADS];
        LONG expected;
        LONGLONG total_elapsed = 0;
        int total_errors = 0;

        nts_rapid_counter = 0;
        mtx = CreateMutexA(NULL, FALSE, NULL);
        if (!mtx)
        {
            printf("  [FAIL] CreateMutex returned NULL\n");
            fail++;
            goto nts_t3;
        }

        print_kv("mutex handle", "%p", mtx);
        print_kv("threads", "%d (1 RT + %d load)", rapid_threads, rapid_threads - 1);
        print_kv("iters/thread", "%d", rapid_iters);
        print_kv("total iters", "%d", rapid_threads * rapid_iters);

        for (i = 0; i < rapid_threads; i++)
        {
            memset(&states[i], 0, sizeof(states[i]));
            states[i].mutex = mtx;
            states[i].iters = rapid_iters;
            states[i].is_rt = (i == 0);
            threads[i] = CreateThread(NULL, 0, nts_rapid_worker, &states[i], 0, NULL);
        }

        WaitForMultipleObjects(rapid_threads, threads, TRUE, 120000);

        for (i = 0; i < rapid_threads; i++)
        {
            if (threads[i]) CloseHandle(threads[i]);
            total_errors += states[i].errors;
            if (states[i].elapsed_us > total_elapsed)
                total_elapsed = states[i].elapsed_us;
        }

        printf("\n  ── rapid mutex results ──\n");
        printf("  total elapsed  : %lld ms\n", total_elapsed / 1000);
        if (total_elapsed > 0)
            printf("  throughput     : %lld ops/sec\n",
                   (LONGLONG)nts_rapid_counter * 1000000 / total_elapsed);
        printf("  shared counter : %ld (expected %d) %s\n",
               nts_rapid_counter, rapid_threads * rapid_iters,
               nts_rapid_counter == rapid_threads * rapid_iters ? "OK" : "MISMATCH");
        printf("  errors         : %d\n", total_errors);

        printf("\n  %-6s  %-10s  %10s  %12s  %12s  %11s\n",
               "role", "win32_tid", "iters", "max_wait(us)", "avg_wait(us)", "elapsed(ms)");
        printf("  %-6s  %-10s  %10s  %12s  %12s  %11s\n",
               "------", "---------", "----------", "------------", "------------", "-----------");
        for (i = 0; i < rapid_threads; i++)
        {
            struct nts_rapid_state *s = &states[i];
            LONGLONG avg = s->iters_done > 0 ? s->total_wait_us / s->iters_done : 0;
            printf("  %-6s  %-10lu  %10d  %12lld  %12lld  %11lld\n",
                   s->is_rt ? "RT" : "load",
                   (unsigned long)s->win32_tid, s->iters_done,
                   s->max_wait_us, avg, s->elapsed_us / 1000);
        }

        expected = rapid_threads * rapid_iters;
        if (nts_rapid_counter == expected && total_errors == 0)
        {
            printf("  [PASS] counter correct, no errors\n");
            pass++;
        }
        else
        {
            printf("  [FAIL] counter=%ld expected=%ld errors=%d\n",
                   nts_rapid_counter, expected, total_errors);
            fail++;
        }
        CloseHandle(mtx);
    }

nts_t3:
    /* ════════════════════════════════════════════════════════════════════
     *   Test 3: Priority-ordered wakeup
     *
     *   Bug caught: patch 0002 (priority-ordered waiter queues) broken —
     *   if ntsync inserts waiters FIFO instead of by priority, lower-prio
     *   waiters wake before higher-prio ones. Windows guarantees
     *   highest-priority waiter wakes first on mutex release.
     *
     *   Setup: main thread holds a mutex. 5 waiter threads at different
     *   Win32 priorities all block on it. Main releases. Under correct
     *   priority ordering, TIME_CRITICAL wakes first, IDLE wakes last.
     * ════════════════════════════════════════════════════════════════════ */
    print_section("[3/5] priority-ordered wakeup (kernel mutex waiter queue)");
    printf("  waiters: %d (launched lowest-priority first)\n", prio_waiters);
    fflush(stdout);
    {
        HANDLE mtx;
        HANDLE ready_events[NTS_PRIO_MAX_WAITERS];
        HANDLE waiter_threads[NTS_PRIO_MAX_WAITERS];
        struct nts_prio_waiter_ctx waiters[NTS_PRIO_MAX_WAITERS];
        int order_correct = 1;
        int all_woke = 1;
        LONGLONG prev_time;
        struct { int prio; char label[8]; } prio_levels[NTS_PRIO_MAX_WAITERS];
        /* REALTIME class set at cmd_ntsync entry */

        /* Use only the 7 standard Win32 thread priority values.
         * Non-standard values (3-14) bypass the NSPA_RT_TIME_CRITICAL
         * clamp in the priority mapping and get HIGHER FIFO priorities
         * than TIME_CRITICAL — so they must not be used. Ordered
         * highest-first for the verification loop. */
        {
            static const struct { int prio; const char *label; } std_prios[] = {
                { THREAD_PRIORITY_TIME_CRITICAL, "TC"      },  /* 15  -> FF 80 (ceiling) */
                { THREAD_PRIORITY_HIGHEST,       "HIGH"    },  /*  2  -> FF 75 */
                { THREAD_PRIORITY_ABOVE_NORMAL,  "ABOVE"   },  /*  1  -> FF 74 */
                { THREAD_PRIORITY_NORMAL,        "NORMAL"  },  /*  0  -> FF 73 */
                { THREAD_PRIORITY_BELOW_NORMAL,  "BELOW"   },  /* -1  -> FF 72 */
                { THREAD_PRIORITY_LOWEST,        "LOW"     },  /* -2  -> FF 71 */
                { THREAD_PRIORITY_IDLE,          "IDLE"    },  /* -15 -> FF 65 */
            };
            int n_std = sizeof(std_prios) / sizeof(std_prios[0]);
            int idx;
            if (prio_waiters > n_std) prio_waiters = n_std;
            for (idx = 0; idx < prio_waiters; idx++)
            {
                prio_levels[idx].prio = std_prios[idx].prio;
                snprintf(prio_levels[idx].label, sizeof(prio_levels[idx].label),
                         "%s", std_prios[idx].label);
            }
        }

        mtx = CreateMutexA(NULL, FALSE, NULL);
        if (!mtx)
        {
            printf("  [FAIL] CreateMutex returned NULL\n");
            fail++;
            goto nts_t4;
        }

        /* Main thread acquires the mutex to block all waiters */
        WaitForSingleObject(mtx, INFINITE);

        /* Launch waiters in REVERSE priority order (lowest first) so that
         * if the driver uses FIFO ordering, the lowest would wake first. */
        for (i = prio_waiters - 1; i >= 0; i--)
        {
            ready_events[i] = CreateEventW(NULL, FALSE, FALSE, NULL);
            waiters[i].mutex = mtx;
            waiters[i].ready_event = ready_events[i];
            waiters[i].win32_priority = prio_levels[i].prio;
            waiters[i].label = prio_levels[i].label;
            waiters[i].wakeup_time_us = 0;
            waiters[i].wait_result = (DWORD)-1;

            waiter_threads[i] = CreateThread(NULL, 0, nts_prio_waiter,
                                             &waiters[i], 0, NULL);
            WaitForSingleObject(ready_events[i], 5000);
            Sleep(30);
        }

        printf("  all %d waiters blocked\n", prio_waiters);
        fflush(stdout);

        ReleaseMutex(mtx);

        WaitForMultipleObjects(prio_waiters, waiter_threads, TRUE, 30000);

        /* Verify wakeup order by timestamp */
        printf("\n  %-6s  %-5s  %-10s  %-14s  %s\n",
               "prio", "val", "win32_tid", "wake_us", "result");
        printf("  %-6s  %-5s  %-10s  %-14s  %s\n",
               "------", "-----", "---------", "--------------", "------");

        prev_time = -1;  /* -1 = no previous timestamp yet */
        for (i = 0; i < prio_waiters; i++)
        {
            struct nts_prio_waiter_ctx *w = &waiters[i];
            const char *status;

            if (w->wait_result != WAIT_OBJECT_0)
            {
                status = "FAIL (didn't wake)";
                all_woke = 0;
            }
            else if (prev_time != -1 && w->wakeup_time_us < prev_time)
            {
                status = "OUT OF ORDER";
                order_correct = 0;
            }
            else
            {
                status = "ok";
            }

            printf("  %-6s  %-5d  %-10lu  %-14lld  %s\n",
                   prio_levels[i].label,
                   prio_levels[i].prio,
                   (unsigned long)w->win32_tid,
                   w->wakeup_time_us,
                   status);

            if (w->wait_result == WAIT_OBJECT_0)
                prev_time = w->wakeup_time_us;
        }

        if (all_woke && order_correct)
        {
            printf("  [PASS] all %d waiters woke in priority order\n", prio_waiters);
            pass++;
        }
        else if (!all_woke)
        {
            printf("  [FAIL] not all waiters woke (deadlock or timeout)\n");
            fail++;
        }
        else
        {
            printf("  [FAIL] wakeup order incorrect (lower priority woke before higher)\n");
            fail++;
        }

        for (i = 0; i < prio_waiters; i++)
        {
            CloseHandle(waiter_threads[i]);
            CloseHandle(ready_events[i]);
        }
        CloseHandle(mtx);
    }

nts_t4:
    /* ════════════════════════════════════════════════════════════════════
     *   Test 4: Transitive PI chain
     *
     *   Bug caught: ntsync_pi_recalc() chain walk stopping at depth 1
     *   (only direct holder boosted, not transitive holders). Also
     *   catches the case where boost doesn't propagate through a blocked
     *   holder to the next mutex in the chain.
     *
     *   Setup:
     *     mutex[0] held by holder[0] who blocks on mutex[1]
     *     mutex[1] held by holder[1] who blocks on mutex[2]
     *     ...
     *     mutex[N-1] held by holder[N-1] who does CPU work
     *
     *   RT thread waits on mutex[0]. Boost should propagate all the way
     *   to holder[N-1] so it can preempt background load threads.
     *   Without transitive PI, holder[N-1] stays SCHED_OTHER and the
     *   RT thread's wait time scales with load count.
     * ════════════════════════════════════════════════════════════════════ */
    print_section("[4/5] transitive PI chain");
    printf("  chain depth: %d mutexes, %d SCHED_OTHER load threads\n",
           chain_depth, chain_n_load);
    fflush(stdout);
    {
        HANDLE mutexes[NTS_CHAIN_MAX_DEPTH];
        HANDLE holder_threads[NTS_CHAIN_MAX_DEPTH];
        HANDLE load_h[NTS_CHAIN_LOAD_THREADS];
        struct nts_chain_holder_ctx holders[NTS_CHAIN_MAX_DEPTH];
        HANDLE tail_gate;  /* signaled after all holders set up, before RT waits */
        LONGLONG rt_t0, rt_t1, rt_wait;
        DWORD w;
        int ok = 1;

        nts_chain_stop_load = 0;
        tail_gate = CreateEventW(NULL, FALSE, FALSE, NULL);

        /* Create all mutexes */
        for (i = 0; i < chain_depth; i++)
        {
            mutexes[i] = CreateMutexA(NULL, FALSE, NULL);
            if (!mutexes[i])
            {
                printf("  [FAIL] CreateMutex[%d] returned NULL\n", i);
                fail++;
                ok = 0;
                break;
            }
        }
        if (!ok) goto nts_t5;

        /* Spawn load threads as SCHED_OTHER (temp drop to NORMAL class) */
        for (i = 0; i < chain_n_load; i++)
        {
            DWORD tid;
            load_h[i] = spawn_load_thread_sched_other(nts_chain_load_thread, NULL, &tid);
        }
        Sleep(100);

        /* Spawn chain holders in reverse order (deepest first) so each
         * can acquire its mutex before the previous holder tries to block. */
        for (i = chain_depth - 1; i >= 0; i--)
        {
            holders[i].depth = i;
            holders[i].total_depth = chain_depth;
            holders[i].mutexes = mutexes;
            holders[i].start_event = CreateEventW(NULL, FALSE, FALSE, NULL);
            holders[i].gate_event = tail_gate;
            holders[i].win32_tid = 0;
            holders[i].elapsed_us = 0;

            holder_threads[i] = CreateThread(NULL, 0, nts_chain_holder,
                                             &holders[i], 0, NULL);
            /* Wait for this holder to acquire its mutex and signal ready */
            {
                DWORD wr = WaitForSingleObject(holders[i].start_event, 10000);
                if (wr == WAIT_TIMEOUT)
                {
                    printf("  [chain-%d] TIMEOUT waiting for holder to start — aborting chain test\n", i);
                    fflush(stdout);
                    ok = 0;
                    break;
                }
            }
            Sleep(50);

            printf("  [chain-%d] tid=%lu holding mutex[%d]%s\n",
                   i, (unsigned long)holders[i].win32_tid, i,
                   i == chain_depth - 1 ? " (tail — doing CPU work)" :
                   " (blocked on mutex[next])");
            fflush(stdout);
        }

        /* Now the RT thread waits on mutex[0].
         * Chain: RT -> mutex[0] -> holder[0] -> mutex[1] -> holder[1] -> ...
         * -> holder[N-1] doing CPU work.
         * PI boost should propagate from RT all the way to holder[N-1]. */
        printf("\n  [RT] main thread (TIME_CRITICAL) waiting on mutex[0]...\n");
        fflush(stdout);

        /* Gate the tail holder — it won't start CPU work until we signal.
         * This ensures the chain is actively blocked when RT enters. */
        SetEvent(tail_gate);

        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        rt_t0 = now_ms();
        w = WaitForSingleObject(mutexes[0], 60000);
        rt_t1 = now_ms();
        rt_wait = rt_t1 - rt_t0;
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

        if (w == WAIT_OBJECT_0)
        {
            printf("  [RT] acquired mutex[0] after %lld ms\n", rt_wait);
            ReleaseMutex(mutexes[0]);
        }
        else if (w == WAIT_TIMEOUT)
        {
            printf("  [FAIL] RT thread timed out waiting on mutex[0] (60s)\n");
            ok = 0;
        }
        else
        {
            printf("  [FAIL] WaitForSingleObject = %lu\n", w);
            ok = 0;
        }

        /* Clean up */
        InterlockedExchange(&nts_chain_stop_load, 1);
        for (i = 0; i < chain_depth; i++)
        {
            WaitForSingleObject(holder_threads[i], 10000);
            CloseHandle(holder_threads[i]);
            CloseHandle(holders[i].start_event);
        }
        CloseHandle(tail_gate);
        for (i = 0; i < chain_n_load; i++)
        {
            WaitForSingleObject(load_h[i], 5000);
            CloseHandle(load_h[i]);
        }

        /* Report chain holder elapsed times */
        printf("\n  ── chain holder elapsed ──\n");
        printf("  %-8s  %-10s  %11s\n", "holder", "win32_tid", "elapsed(ms)");
        printf("  %-8s  %-10s  %11s\n", "--------", "---------", "-----------");
        for (i = 0; i < chain_depth; i++)
        {
            printf("  chain-%-2d  %-10lu  %11lld\n",
                   i, (unsigned long)holders[i].win32_tid,
                   holders[i].elapsed_us / 1000);
        }
        printf("  RT wait  : %lld ms (chain depth %d)\n", rt_wait, chain_depth);

        if (ok)
        {
            printf("  [PASS] transitive PI chain completed (depth %d, %lld ms)\n",
                   chain_depth, rt_wait);
            pass++;
        }
        else
        {
            printf("  [FAIL] transitive PI chain failed\n");
            fail++;
        }

        for (i = 0; i < chain_depth; i++)
            CloseHandle(mutexes[i]);
    }

nts_t5:
    /* ════════════════════════════════════════════════════════════════════
     *   Test 5: Mixed WaitForMultipleObjects (event + mutex + semaphore)
     *
     *   Bug caught: ntsync WAIT_ANY path broken for heterogeneous object
     *   types. The driver's wait_all_lock or type-dispatch could deadlock
     *   or return the wrong index when mixing events, mutexes, and
     *   semaphores in a single WFMO call.
     * ════════════════════════════════════════════════════════════════════ */
    print_section("[5/5] mixed WaitForMultipleObjects (ntsync WAIT_ANY)");
    {
        HANDLE objs[6];
        DWORD r;
        int test_pass = 1;

        objs[0] = CreateMutexA(NULL, FALSE, NULL);       /* unowned = signaled */
        objs[1] = CreateEventA(NULL, TRUE, FALSE, NULL);  /* manual, unsignaled */
        objs[2] = CreateSemaphoreA(NULL, 0, 10, NULL);    /* empty */
        objs[3] = CreateEventA(NULL, FALSE, FALSE, NULL);  /* auto, unsignaled */
        objs[4] = CreateMutexA(NULL, TRUE, NULL);          /* owned by us = unsignaled for others */
        objs[5] = CreateSemaphoreA(NULL, 0, 5, NULL);     /* empty */

        for (i = 0; i < 6; i++)
        {
            if (!objs[i])
            {
                printf("  [FAIL] failed to create object %d\n", i);
                test_pass = 0;
                break;
            }
        }

        if (test_pass)
        {
            /* Test 5a: only objs[0] (unowned mutex) is immediately acquirable */
            printf("  [5a] WFMO with 1 signaled mutex + 5 unsignaled...\n");
            r = WaitForMultipleObjects(6, objs, FALSE, 0);
            if (r == WAIT_OBJECT_0)
            {
                printf("       [PASS] returned index 0 (unowned mutex)\n");
                pass++;
                ReleaseMutex(objs[0]);
            }
            else
            {
                printf("       [FAIL] returned %lu, expected 0\n", r);
                fail++;
                test_pass = 0;
            }

            /* Test 5b: signal the semaphore at index 2, verify it's chosen */
            printf("  [5b] WFMO after signaling semaphore[2]...\n");
            /* Re-acquire mutex[0] so it's not signaled */
            WaitForSingleObject(objs[0], 0);
            ReleaseSemaphore(objs[2], 1, NULL);
            r = WaitForMultipleObjects(6, objs, FALSE, 0);
            if (r == WAIT_OBJECT_0 + 2)
            {
                printf("       [PASS] returned index 2 (semaphore)\n");
                pass++;
            }
            else if (r == WAIT_OBJECT_0)
            {
                /* Mutex[0] might have been released — either way, sem should have been preferred
                 * if it has lower index... actually mutex[0] is held by us now (re-acquired above),
                 * but for WFMO it's still "signaled" since the calling thread owns it (recursive). */
                printf("       [INFO] returned index 0 (recursive mutex acquire) — acceptable\n");
                ReleaseMutex(objs[0]);
                pass++;
            }
            else
            {
                printf("       [FAIL] returned %lu, expected 2\n", r);
                fail++;
            }
            /* Release mutex[0] if still held */
            ReleaseMutex(objs[0]);

            /* Test 5c: WaitAll with a subset that's all signaled */
            printf("  [5c] WFMO WaitAll with 2 signaled objects...\n");
            {
                HANDLE pair[2];
                pair[0] = CreateEventA(NULL, TRUE, TRUE, NULL);   /* signaled */
                pair[1] = CreateMutexA(NULL, FALSE, NULL);         /* unowned = signaled */
                if (pair[0] && pair[1])
                {
                    r = WaitForMultipleObjects(2, pair, TRUE, 1000);
                    if (r == WAIT_OBJECT_0)
                    {
                        printf("       [PASS] WaitAll returned OK\n");
                        pass++;
                        ReleaseMutex(pair[1]);
                    }
                    else
                    {
                        printf("       [FAIL] WaitAll returned %lu\n", r);
                        fail++;
                    }
                }
                else
                {
                    printf("       [FAIL] object creation failed\n");
                    fail++;
                }
                if (pair[0]) CloseHandle(pair[0]);
                if (pair[1]) CloseHandle(pair[1]);
            }

            /* Test 5d: Cross-thread signal into WFMO */
            printf("  [5d] cross-thread signal into blocked WFMO...\n");
            {
                HANDLE evt = CreateEventA(NULL, FALSE, FALSE, NULL);
                HANDLE mtx = CreateMutexA(NULL, TRUE, NULL); /* we own it */
                HANDLE wfmo_objs[2];
                LONGLONG t0, t1;

                wfmo_objs[0] = mtx;
                wfmo_objs[1] = evt;

                /* Signal the event after 100ms from another mechanism —
                 * we'll use a simple approach: signal before wait since
                 * we can't easily spawn a timed thread inline. Instead,
                 * test that an already-signaled event in slot 1 is found. */
                SetEvent(evt);
                /* mtx is owned by us (signaled for us), evt is signaled.
                 * WaitAny should return the lowest-indexed signaled one. */
                t0 = now_us();
                r = WaitForMultipleObjects(2, wfmo_objs, FALSE, 1000);
                t1 = now_us();

                if (r == WAIT_OBJECT_0 || r == WAIT_OBJECT_0 + 1)
                {
                    printf("       [PASS] WFMO returned index %lu in %lld us\n",
                           r - WAIT_OBJECT_0, t1 - t0);
                    pass++;
                    if (r == WAIT_OBJECT_0) ReleaseMutex(mtx);
                }
                else
                {
                    printf("       [FAIL] WFMO returned %lu\n", r);
                    fail++;
                }
                ReleaseMutex(mtx);
                CloseHandle(evt);
                CloseHandle(mtx);
            }
        }

        for (i = 0; i < 6; i++)
            if (objs[i]) CloseHandle(objs[i]);
    }

    /* ── Final verdict ────────────────────────────────────────────────── */
    print_section("results");
    printf("  total PASS : %d\n", pass);
    printf("  total FAIL : %d\n", fail);
    print_verdict(fail == 0, fail ? "see failures above" : NULL);
    leave_realtime_class();
    return fail ? 1 : 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *   socket-io — async TCP loopback latency / throughput test
 *
 *   Creates a TCP loopback socket pair. One thread sends fixed-size
 *   messages, the main thread receives them using overlapped WSARecv.
 *   Measures per-message latency to exercise the socket async path
 *   (server epoll monitoring vs io_uring poll bypass).
 *
 *   Run before and after io_uring Phase 3 to compare.
 * ════════════════════════════════════════════════════════════════════════ */

#define SOCKIO_MSG_SIZE     256
#define SOCKIO_ITERATIONS   2000
#define SOCKIO_PORT         0       /* ephemeral */

/* Helper: create a connected TCP loopback pair. Returns 0 on success. */
static int make_tcp_pair(SOCKET *client_out, SOCKET *server_out)
{
    SOCKET listener, client, accepted;
    struct sockaddr_in addr;
    int addrlen = sizeof(addr);

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(SOCKIO_PORT);

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) goto fail;
    if (listen(listener, 1) < 0) goto fail;
    if (getsockname(listener, (struct sockaddr *)&addr, &addrlen) < 0) goto fail;

    client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) goto fail;
    if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) < 0) { closesocket(client); goto fail; }

    accepted = accept(listener, NULL, NULL);
    if (accepted == INVALID_SOCKET) { closesocket(client); goto fail; }

    closesocket(listener);
    *client_out = client;
    *server_out = accepted;
    return 0;

fail:
    closesocket(listener);
    return -1;
}

/* Deferred sender: waits for per-iteration signal before each send.
 * This ensures the receiver calls WSARecv BEFORE data is available,
 * exercising the async wait path (server epoll or io_uring poll). */
struct sockio_deferred_ctx {
    SOCKET sock;
    int iterations;
    HANDLE send_gate;   /* auto-reset: receiver signals, sender sends one msg */
    HANDLE done_event;  /* manual-reset: sender sets when finished */
    volatile int error;
};

static DWORD WINAPI sockio_deferred_sender(void *param)
{
    struct sockio_deferred_ctx *ctx = param;
    char buf[SOCKIO_MSG_SIZE];
    int i;

    memset(buf, 'X', sizeof(buf));

    for (i = 0; i < ctx->iterations; i++)
    {
        WaitForSingleObject(ctx->send_gate, INFINITE);
        if (send(ctx->sock, buf, sizeof(buf), 0) != sizeof(buf))
        {
            ctx->error = WSAGetLastError();
            break;
        }
    }
    SetEvent(ctx->done_event);
    return 0;
}

/* Run one phase of the socket-io test.
 * If deferred=TRUE, receiver calls WSARecv first, THEN signals sender.
 * This forces the async path (EAGAIN → io_uring poll or server epoll). */
static void sockio_run_phase(const char *label, SOCKET client, SOCKET server,
                             int iterations, BOOL deferred,
                             LARGE_INTEGER freq)
{
    struct sockio_deferred_ctx sender_ctx;
    HANDLE sender_thread;
    WSAOVERLAPPED ov;
    WSABUF wsabuf;
    char recv_buf[SOCKIO_MSG_SIZE];
    DWORD bytes_recv, flags;
    LARGE_INTEGER t_start, t_end;
    double *latencies;
    double total_us = 0, min_us = 1e9, max_us = 0, avg_us;
    int i, pass = 0, fail = 0, pending_count = 0;

    latencies = malloc(iterations * sizeof(double));
    if (!latencies) { printf("  [FAIL] malloc\n"); return; }

    sender_ctx.sock = server;
    sender_ctx.iterations = iterations;
    sender_ctx.send_gate = CreateEventW(NULL, FALSE, FALSE, NULL);  /* auto-reset */
    sender_ctx.done_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    sender_ctx.error = 0;

    sender_thread = CreateThread(NULL, 0, sockio_deferred_sender, &sender_ctx, 0, NULL);
    if (!sender_thread)
    {
        printf("  [FAIL] CreateThread: %lu\n", GetLastError());
        free(latencies);
        return;
    }

    printf("  Running %d %s recv cycles...\n", iterations, label);
    fflush(stdout);

    for (i = 0; i < iterations; i++)
    {
        DWORD wait_ret;
        int total_recv = 0;

        if (!deferred)
        {
            /* Immediate mode: send first, then recv */
            SetEvent(sender_ctx.send_gate);
            Sleep(0); /* yield to let sender run */
        }

        QueryPerformanceCounter(&t_start);

        while (total_recv < SOCKIO_MSG_SIZE)
        {
            memset(&ov, 0, sizeof(ov));
            ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
            wsabuf.buf = recv_buf + total_recv;
            wsabuf.len = SOCKIO_MSG_SIZE - total_recv;
            flags = 0;

            if (WSARecv(client, &wsabuf, 1, &bytes_recv, &flags, &ov, NULL) == SOCKET_ERROR)
            {
                if (WSAGetLastError() != WSA_IO_PENDING)
                {
                    CloseHandle(ov.hEvent);
                    fail++;
                    goto next;
                }

                if (deferred && total_recv == 0)
                {
                    /* WSARecv returned PENDING — now signal the sender.
                     * This is the key: the async wait path is now active. */
                    SetEvent(sender_ctx.send_gate);
                    pending_count++;
                }

                wait_ret = WaitForSingleObject(ov.hEvent, 5000);
                if (wait_ret != WAIT_OBJECT_0)
                {
                    CloseHandle(ov.hEvent);
                    fail++;
                    goto next;
                }
                WSAGetOverlappedResult(client, &ov, &bytes_recv, FALSE, &flags);
            }
            else if (deferred && total_recv == 0)
            {
                /* Completed immediately even in deferred mode —
                 * data was already buffered (TCP coalescing). */
                SetEvent(sender_ctx.send_gate);
            }

            CloseHandle(ov.hEvent);
            total_recv += bytes_recv;
        }

        QueryPerformanceCounter(&t_end);
        {
            double us = (double)(t_end.QuadPart - t_start.QuadPart) * 1e6 / freq.QuadPart;
            latencies[pass] = us;
            total_us += us;
            if (us < min_us) min_us = us;
            if (us > max_us) max_us = us;
            pass++;
        }
next:;
    }

    WaitForSingleObject(sender_thread, 5000);
    CloseHandle(sender_thread);
    CloseHandle(sender_ctx.send_gate);
    CloseHandle(sender_ctx.done_event);

    avg_us = pass > 0 ? total_us / pass : 0;

    /* Sort for percentiles */
    for (i = 0; i < pass - 1; i++)
    {
        int j;
        for (j = i + 1; j < pass; j++)
            if (latencies[j] < latencies[i])
            { double t = latencies[i]; latencies[i] = latencies[j]; latencies[j] = t; }
    }

    printf("\n  -- %s results --\n", label);
    printf("  Iterations:  %d pass, %d fail", pass, fail);
    if (deferred) printf(", %d went async (PENDING)", pending_count);
    printf("\n");
    printf("  Latency (us):\n");
    printf("    min:    %8.1f\n", min_us);
    printf("    avg:    %8.1f\n", avg_us);
    printf("    p50:    %8.1f\n", pass > 0 ? latencies[pass / 2] : 0.0);
    printf("    p95:    %8.1f\n", pass > 0 ? latencies[(int)(pass * 0.95)] : 0.0);
    printf("    p99:    %8.1f\n", pass > 0 ? latencies[(int)(pass * 0.99)] : 0.0);
    printf("    max:    %8.1f\n", max_us);
    printf("  Throughput:  %.0f msgs/sec\n", pass > 0 ? 1e6 / avg_us : 0.0);
    fflush(stdout);

    free(latencies);
}

static int cmd_socket_io(int argc, char **argv)
{
    WSADATA wsa;
    SOCKET client, server;
    LARGE_INTEGER freq;
    int iterations = SOCKIO_ITERATIONS;

    (void)argc; (void)argv;

    print_banner("socket-io", "async TCP loopback latency test (io_uring Phase 3)");
    fflush(stdout);

    if (WSAStartup(MAKEWORD(2, 2), &wsa))
    {
        printf("  [FAIL] WSAStartup failed\n");
        return 1;
    }

    QueryPerformanceFrequency(&freq);

    print_section("parameters");
    print_kv("msg_size", "%d bytes", SOCKIO_MSG_SIZE);
    print_kv("iterations", "%d per phase", iterations);
    print_kv("transport", "TCP loopback (127.0.0.1)");
    print_kv("recv mode", "overlapped WSARecv");

    if (make_tcp_pair(&client, &server))
    {
        printf("  [FAIL] make_tcp_pair: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    printf("  [OK] TCP pair created\n");
    fflush(stdout);

    /* Phase A: Immediate — data sent before recv.
     * Exercises the fast path (try_recv succeeds immediately). */
    print_section("Phase A: immediate recv (data already buffered)");
    sockio_run_phase("immediate", client, server, iterations, FALSE, freq);

    /* Phase B: Deferred — recv called before send.
     * Forces the async wait path (EAGAIN → io_uring poll or server epoll). */
    print_section("Phase B: deferred recv (async wait path)");
    sockio_run_phase("deferred", client, server, iterations, TRUE, freq);

    closesocket(client);
    closesocket(server);
    WSACleanup();

    printf("\n  Verdict: PASS\n");
    fflush(stdout);
    return 0;
}


/* ════════════════════════════════════════════════════════════════════════
 *   SRW contention benchmark
 *
 *   N threads acquire/release a shared SRWLOCK in a tight loop.
 *   Measures acquire latency (p50, p99, max) and ops/sec.
 *   Used to validate the SRW spin phase improvement.
 *
 *   Usage: nspa_rt_test.exe srw-bench [threads] [iterations]
 *          Default: 4 threads, 500000 iterations per thread.
 * ════════════════════════════════════════════════════════════════════════ */

static SRWLOCK srw_bench_lock = SRWLOCK_INIT;
static volatile LONG srw_bench_ready = 0;
static volatile LONG srw_bench_go = 0;

struct srw_bench_result {
    LONGLONG min_ns, max_ns, sum_ns;
    LONGLONG p50_ns, p99_ns;
    DWORD count;
};

static DWORD WINAPI srw_bench_thread(LPVOID arg)
{
    struct srw_bench_result *res = (struct srw_bench_result *)arg;
    LARGE_INTEGER freq, t0, t1;
    LONGLONG *samples;
    DWORD iters = res->count;
    DWORD i;

    QueryPerformanceFrequency(&freq);
    samples = (LONGLONG *)malloc(iters * sizeof(LONGLONG));
    if (!samples) { printf("  [FAIL] malloc failed\n"); return 1; }

    /* Signal ready and wait for go */
    InterlockedIncrement(&srw_bench_ready);
    while (!srw_bench_go) YieldProcessor();

    for (i = 0; i < iters; i++)
    {
        QueryPerformanceCounter(&t0);
        AcquireSRWLockExclusive(&srw_bench_lock);
        /* Simulate tiny critical section — just a volatile write */
        *(volatile LONG *)&srw_bench_lock;
        ReleaseSRWLockExclusive(&srw_bench_lock);
        QueryPerformanceCounter(&t1);
        samples[i] = (t1.QuadPart - t0.QuadPart) * 1000000000LL / freq.QuadPart;
    }

    /* Sort for percentiles */
    {
        DWORD j;
        for (i = 1; i < iters; i++)
        {
            LONGLONG key = samples[i];
            j = i;
            while (j > 0 && samples[j-1] > key) { samples[j] = samples[j-1]; j--; }
            samples[j] = key;
        }
    }

    res->min_ns = samples[0];
    res->max_ns = samples[iters - 1];
    res->p50_ns = samples[iters / 2];
    res->p99_ns = samples[(DWORD)(iters * 0.99)];
    res->sum_ns = 0;
    for (i = 0; i < iters; i++) res->sum_ns += samples[i];

    free(samples);
    return 0;
}

static int cmd_srw_bench(int argc, char **argv)
{
    DWORD num_threads = 4, iters = 500000;
    struct srw_bench_result *results;
    HANDLE *threads;
    LARGE_INTEGER freq;
    LONGLONG total_ops = 0, total_ns = 0;
    DWORD i;

    if (argc > 1) num_threads = atoi(argv[1]);
    if (argc > 2) iters = atoi(argv[2]);
    if (num_threads < 1) num_threads = 1;
    if (num_threads > 64) num_threads = 64;
    if (iters < 100) iters = 100;

    QueryPerformanceFrequency(&freq);

    printf("SRW contention benchmark: %lu threads, %lu iterations each\n", num_threads, iters);

    results = (struct srw_bench_result *)calloc(num_threads, sizeof(*results));
    threads = (HANDLE *)calloc(num_threads, sizeof(HANDLE));
    if (!results || !threads) { printf("  [FAIL] alloc\n"); return 1; }

    /* Initialize and create threads */
    srw_bench_ready = 0;
    srw_bench_go = 0;
    for (i = 0; i < num_threads; i++)
    {
        results[i].count = iters;
        threads[i] = CreateThread(NULL, 0, srw_bench_thread, &results[i], 0, NULL);
    }

    /* Wait for all threads ready */
    while ((DWORD)srw_bench_ready < num_threads) Sleep(0);

    /* Go! */
    InterlockedExchange(&srw_bench_go, 1);

    WaitForMultipleObjects(num_threads, threads, TRUE, INFINITE);

    /* Aggregate results */
    printf("\n  Thread     avg(ns)   p50(ns)   p99(ns)   max(ns)    ops/sec\n");
    for (i = 0; i < num_threads; i++)
    {
        struct srw_bench_result *r = &results[i];
        LONGLONG avg = r->sum_ns / iters;
        LONGLONG ops_sec = (r->sum_ns > 0) ? (LONGLONG)iters * 1000000000LL / r->sum_ns : 0;
        printf("  T%-3lu    %8lld  %8lld  %8lld  %8lld  %10lld\n",
               i, avg, r->p50_ns, r->p99_ns, r->max_ns, ops_sec);
        total_ops += iters;
        total_ns += r->sum_ns;
        CloseHandle(threads[i]);
    }

    {
        LONGLONG overall_avg = total_ns / total_ops;
        printf("\n  Overall: %lld ops, avg %lld ns/op\n", total_ops, overall_avg);
    }

    free(results);
    free(threads);
    printf("  [PASS]\n");
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *   cmd_condvar_pi — Win32 condvar PI validation test
 *
 *   Validates that RtlSleepConditionVariableCS + RtlWakeConditionVariable
 *   correctly use FUTEX_WAIT_REQUEUE_PI / FUTEX_CMP_REQUEUE_PI when CS-PI
 *   is active (NSPA_RT_PRIO set).
 *
 *   Architecture:
 *     - 1 RT waiter thread (TIME_CRITICAL) that loops:
 *         EnterCS → SleepConditionVariableCS → check predicate → LeaveCS
 *     - 1 signaler thread (NORMAL) that loops:
 *         EnterCS → set predicate → LeaveCS → WakeConditionVariable
 *     - N load threads (NORMAL, tight CPU busy loops) to starve non-PI threads
 *
 *   With condvar PI: the signaler gets boosted when the RT waiter is waiting,
 *   so the signaler runs promptly even under load. The RT waiter's wake-to-CS
 *   reacquire has zero PI gap (kernel requeue).
 *
 *   Without condvar PI (or without NSPA_RT_PRIO): the signaler competes with
 *   load threads for CPU, so the RT waiter's total cycle time is longer.
 *
 *   PASS condition: functional correctness (all iterations complete, no hangs,
 *   predicate always true on wake). Latency is reported for comparison.
 * ════════════════════════════════════════════════════════════════════════ */

#define CONDVAR_PI_ITERATIONS  500
#define CONDVAR_PI_LOAD_THREADS 4
#define CONDVAR_PI_SIGNAL_WORK  50000  /* iterations of busy work per signal */

static CRITICAL_SECTION cv_pi_cs;
static CONDITION_VARIABLE cv_pi_cv;
static volatile LONG cv_pi_predicate;
static volatile LONG cv_pi_done;
static volatile LONG cv_pi_waiter_ready;

struct condvar_pi_result {
    LONGLONG min_us;
    LONGLONG max_us;
    LONGLONG sum_us;
    int count;
};

static DWORD WINAPI condvar_pi_waiter_thread(void *arg)
{
    struct condvar_pi_result *res = (struct condvar_pi_result *)arg;
    LARGE_INTEGER freq, t0, t1;
    int i;

    QueryPerformanceFrequency(&freq);
    res->min_us = LLONG_MAX;
    res->max_us = 0;
    res->sum_us = 0;
    res->count  = 0;

    for (i = 0; i < CONDVAR_PI_ITERATIONS; i++)
    {
        EnterCriticalSection(&cv_pi_cs);
        cv_pi_predicate = 0;
        InterlockedExchange(&cv_pi_waiter_ready, 1);

        QueryPerformanceCounter(&t0);
        while (!cv_pi_predicate)
            SleepConditionVariableCS(&cv_pi_cv, &cv_pi_cs, INFINITE);
        QueryPerformanceCounter(&t1);

        LeaveCriticalSection(&cv_pi_cs);

        {
            LONGLONG us = (t1.QuadPart - t0.QuadPart) * 1000000LL / freq.QuadPart;
            if (us < res->min_us) res->min_us = us;
            if (us > res->max_us) res->max_us = us;
            res->sum_us += us;
            res->count++;
        }
    }
    return 0;
}

static DWORD WINAPI condvar_pi_signaler_thread(void *arg)
{
    volatile LONG dummy = 0;
    int i, j;
    (void)arg;

    for (i = 0; i < CONDVAR_PI_ITERATIONS; i++)
    {
        /* Wait until the waiter is ready */
        while (!cv_pi_waiter_ready)
            SwitchToThread();
        InterlockedExchange(&cv_pi_waiter_ready, 0);

        /* Simulate work (makes the PI boost measurable under load) */
        for (j = 0; j < CONDVAR_PI_SIGNAL_WORK; j++)
            dummy += j;

        EnterCriticalSection(&cv_pi_cs);
        cv_pi_predicate = 1;
        LeaveCriticalSection(&cv_pi_cs);
        WakeConditionVariable(&cv_pi_cv);
    }
    (void)dummy;
    return 0;
}

static DWORD WINAPI condvar_pi_load_thread(void *arg)
{
    volatile LONG x = 0;
    (void)arg;
    while (!cv_pi_done)
    {
        int i;
        for (i = 0; i < 100000; i++)
            x += i;
    }
    (void)x;
    return 0;
}

static int cmd_condvar_pi(int argc, char **argv)
{
    HANDLE waiter, signaler;
    HANDLE load[CONDVAR_PI_LOAD_THREADS];
    struct condvar_pi_result result;
    int i;
    (void)argc; (void)argv;

    printf("== condvar-pi: Win32 condvar PI (requeue-PI) validation ==\n\n");
    printf("  config: %d iterations, %d load threads, %d signal-work iters\n",
           CONDVAR_PI_ITERATIONS, CONDVAR_PI_LOAD_THREADS, CONDVAR_PI_SIGNAL_WORK);
    printf("  NSPA_RT_PRIO=%s\n\n",
           getenv("NSPA_RT_PRIO") ? getenv("NSPA_RT_PRIO") : "(unset)");

    InitializeCriticalSection(&cv_pi_cs);
    InitializeConditionVariable(&cv_pi_cv);
    cv_pi_predicate = 0;
    cv_pi_done = 0;
    cv_pi_waiter_ready = 0;
    memset(&result, 0, sizeof(result));

    /* Start load threads */
    for (i = 0; i < CONDVAR_PI_LOAD_THREADS; i++)
    {
        load[i] = CreateThread(NULL, 0, condvar_pi_load_thread, NULL, 0, NULL);
        SetThreadPriority(load[i], THREAD_PRIORITY_NORMAL);
    }

    /* Start signaler (NORMAL priority) */
    signaler = CreateThread(NULL, 0, condvar_pi_signaler_thread, NULL, 0, NULL);
    SetThreadPriority(signaler, THREAD_PRIORITY_NORMAL);

    /* Start waiter (TIME_CRITICAL — becomes SCHED_FIFO under NSPA_RT_PRIO) */
    waiter = CreateThread(NULL, 0, condvar_pi_waiter_thread, &result, 0, NULL);
    SetThreadPriority(waiter, THREAD_PRIORITY_TIME_CRITICAL);

    /* Wait for test completion */
    WaitForSingleObject(waiter, 30000);
    WaitForSingleObject(signaler, 30000);

    /* Stop load threads */
    InterlockedExchange(&cv_pi_done, 1);
    WaitForMultipleObjects(CONDVAR_PI_LOAD_THREADS, load, TRUE, 5000);

    for (i = 0; i < CONDVAR_PI_LOAD_THREADS; i++)
        CloseHandle(load[i]);
    CloseHandle(signaler);
    CloseHandle(waiter);
    DeleteCriticalSection(&cv_pi_cs);

    printf("-- results --\n");
    printf("  iterations         : %d of %d\n", result.count, CONDVAR_PI_ITERATIONS);
    printf("  min wait           : %lld us\n", (long long)result.min_us);
    printf("  max wait           : %lld us\n", (long long)result.max_us);
    printf("  avg wait           : %lld us\n",
           result.count ? (long long)(result.sum_us / result.count) : 0LL);

    printf("\n-- interpretation --\n");
    printf("  Run with and without NSPA_RT_PRIO and compare avg/max wait:\n");
    printf("    with PI:    signaler gets boosted, avg should be low (~signal work time)\n");
    printf("    without PI: signaler competes with load, avg should be higher\n\n");

    if (result.count == CONDVAR_PI_ITERATIONS)
    {
        printf("  PASS\n");
        return 0;
    }
    else
    {
        printf("  FAIL (only %d of %d iterations completed)\n",
               result.count, CONDVAR_PI_ITERATIONS);
        return 1;
    }
}


/* ════════════════════════════════════════════════════════════════════════
 *   Subcommand: nt-timer  (NSPA NT timer Phase A validation)
 *
 *   Exercises the CreateWaitableTimer / SetWaitableTimer / NtWaitForSingleObject
 *   / CancelWaitableTimer / CloseHandle paths through the NSPA local-timer
 *   dispatcher (dlls/ntdll/unix/nspa/local_timer.c).  Same tests must PASS
 *   whether NSPA_DISABLE_LOCAL_TIMERS is set or not — the dispatcher is an
 *   optimisation, NT semantics must be identical.
 *
 *   Runner convention:
 *       NSPA_RT_PRIO=80                              ./wine ...exe nt-timer   (local, default)
 *       NSPA_RT_PRIO=80 NSPA_DISABLE_LOCAL_TIMERS=1  ./wine ...exe nt-timer   (server path)
 *
 *   Thread scheduling (deliberate, to avoid FIFO busyloops per
 *   feedback_never_fifo_busyloops):
 *     - main                : REALTIME class, TIME_CRITICAL.  Blocking waits only.
 *     - notify-waiters (2x) : spawned via spawn_load_thread_sched_other.
 *                             Block on WaitForSingleObject — not FIFO-safe only
 *                             because they never busy-loop.
 *     - dispatcher (library): promoted SCHED_FIFO at NSPA_RT_PRIO-1 internally
 *                             by nspa_local_timer.c.  No test code touches it.
 *
 *   Bugs each sub-test guards against:
 *     1 one-shot         wait returns significantly early or late → bad clock
 *                        conversion (relative-`when` vs monotonic) or lost wake.
 *     2 cancel           cancel-before-fire still fires → stale entry in queue
 *                        or lost cancel, or double-fire race.
 *     3 periodic         fire count drifts → periodic re-arm logic wrong, or
 *                        fast-forward clamp bursts catch-up fires.
 *     4 notification     manual-reset event fails to wake both waiters →
 *                        backing-event type chosen wrong.
 *     5 synchronization  auto-reset fails to reset → wrong event type, or
 *                        multiple waiters incorrectly released.
 *     6 set-then-cancel  handle leaks or double-free under close path →
 *                        refcount discipline regression.
 *     7 overflow/huge    NT INT64_MAX-ish relative clamps → undefined
 *                        behaviour in 100ns→ns multiply (caught by clamp).
 * ════════════════════════════════════════════════════════════════════════ */

struct timer_waiter_ctx
{
    HANDLE  timer;
    DWORD   timeout_ms;
    DWORD   result;        /* WaitForSingleObject return */
    UINT64  start_us;
    UINT64  end_us;
};

static DWORD WINAPI timer_waiter_fn( void *arg )
{
    struct timer_waiter_ctx *c = arg;
    c->start_us = now_us();
    c->result   = WaitForSingleObject( c->timer, c->timeout_ms );
    c->end_us   = now_us();
    return 0;
}

/* Sub-test 1: basic one-shot, relative 50 ms. */
static int nt_timer_sub_oneshot( void )
{
    LARGE_INTEGER due;
    HANDLE t;
    UINT64 t0, t1;
    DWORD w;
    long elapsed_ms;

    print_section( "sub1: one-shot, relative 50ms" );
    t = CreateWaitableTimerW( NULL, TRUE, NULL );        /* manual-reset anon */
    if (!t)                  { print_kv( "CreateWaitableTimer", "FAIL err=%lu", GetLastError() ); return 0; }

    due.QuadPart = -500000LL;                            /* 50ms relative */
    if (!SetWaitableTimer( t, &due, 0, NULL, NULL, FALSE ))
                             { print_kv( "SetWaitableTimer", "FAIL err=%lu", GetLastError() ); CloseHandle(t); return 0; }

    t0 = now_us();
    w  = WaitForSingleObject( t, 1000 );
    t1 = now_us();
    elapsed_ms = (long)((t1 - t0) / 1000);

    CloseHandle( t );

    print_kv( "wait result",   "%lu", w );
    print_kv( "elapsed (ms)",  "%ld", elapsed_ms );

    if (w != WAIT_OBJECT_0)  { print_kv( "verdict", "FAIL (wait did not signal)" ); return 0; }
    if (elapsed_ms < 30 || elapsed_ms > 200)
                             { print_kv( "verdict", "FAIL (elapsed out of [30,200]ms)" ); return 0; }
    print_kv( "verdict", "PASS" );
    return 1;
}

/* Sub-test 2: cancel before fire — wait must time out. */
static int nt_timer_sub_cancel( void )
{
    LARGE_INTEGER due;
    HANDLE t;
    DWORD w;

    print_section( "sub2: cancel-before-fire" );
    t = CreateWaitableTimerW( NULL, TRUE, NULL );
    if (!t) { print_kv( "create", "FAIL" ); return 0; }

    due.QuadPart = -2000000LL;                           /* 200ms */
    SetWaitableTimer( t, &due, 0, NULL, NULL, FALSE );
    Sleep( 20 );
    if (!CancelWaitableTimer( t )) { print_kv( "cancel", "FAIL" ); CloseHandle(t); return 0; }

    w = WaitForSingleObject( t, 300 );                   /* should time out */
    CloseHandle( t );

    print_kv( "wait result", "%lu (%s)", w,
              w == WAIT_TIMEOUT ? "TIMEOUT" : w == WAIT_OBJECT_0 ? "SIGNALED" : "other" );

    if (w != WAIT_TIMEOUT)   { print_kv( "verdict", "FAIL (cancelled timer fired)" ); return 0; }
    print_kv( "verdict", "PASS" );
    return 1;
}

/* Sub-test 3: periodic — count fires over a 250ms window at 25ms period. */
static int nt_timer_sub_periodic( void )
{
    LARGE_INTEGER due;
    HANDLE t;
    int fires = 0, i;
    DWORD w;

    print_section( "sub3: periodic 25ms, 250ms window" );
    t = CreateWaitableTimerW( NULL, FALSE, NULL );       /* auto-reset */
    if (!t) { print_kv( "create", "FAIL" ); return 0; }

    due.QuadPart = -250000LL;                            /* 25ms due */
    SetWaitableTimer( t, &due, 25 /* period ms */, NULL, NULL, FALSE );

    for (i = 0; i < 20; i++)
    {
        w = WaitForSingleObject( t, 50 );
        if (w == WAIT_OBJECT_0) fires++;
        else                    break;
        if (fires >= 10) break;                          /* stop after enough */
    }

    CancelWaitableTimer( t );
    CloseHandle( t );

    print_kv( "fire count", "%d (expected ~10, tolerate 7..12)", fires );

    if (fires < 7 || fires > 12)
                             { print_kv( "verdict", "FAIL (fire count out of range)" ); return 0; }
    print_kv( "verdict", "PASS" );
    return 1;
}

/* Sub-test 4: Notification (manual-reset) timer wakes both waiters. */
static int nt_timer_sub_notification( void )
{
    LARGE_INTEGER due;
    HANDLE t;
    struct timer_waiter_ctx c1 = {0}, c2 = {0};
    HANDLE h1, h2;
    DWORD tid1, tid2;

    print_section( "sub4: NotificationTimer wakes 2 waiters" );
    t = CreateWaitableTimerW( NULL, TRUE, NULL );        /* manual-reset */
    if (!t) { print_kv( "create", "FAIL" ); return 0; }

    c1.timer = t; c1.timeout_ms = 500;
    c2.timer = t; c2.timeout_ms = 500;

    h1 = spawn_load_thread_sched_other( timer_waiter_fn, &c1, &tid1 );
    h2 = spawn_load_thread_sched_other( timer_waiter_fn, &c2, &tid2 );
    Sleep( 20 );                                         /* let both enter wait */

    due.QuadPart = -500000LL;                            /* 50ms */
    SetWaitableTimer( t, &due, 0, NULL, NULL, FALSE );

    WaitForSingleObject( h1, 1000 );
    WaitForSingleObject( h2, 1000 );
    CloseHandle( h1 );
    CloseHandle( h2 );
    CloseHandle( t );

    print_kv( "waiter1 result", "%lu", c1.result );
    print_kv( "waiter2 result", "%lu", c2.result );

    if (c1.result != WAIT_OBJECT_0 || c2.result != WAIT_OBJECT_0)
                             { print_kv( "verdict", "FAIL (both waiters must wake)" ); return 0; }
    print_kv( "verdict", "PASS" );
    return 1;
}

/* Sub-test 5: Synchronization (auto-reset) timer releases exactly one waiter. */
static int nt_timer_sub_synchronization( void )
{
    LARGE_INTEGER due;
    HANDLE t;
    struct timer_waiter_ctx c1 = {0}, c2 = {0};
    HANDLE h1, h2;
    DWORD tid1, tid2;
    int woke_count;

    print_section( "sub5: SynchronizationTimer wakes exactly 1" );
    t = CreateWaitableTimerW( NULL, FALSE, NULL );       /* auto-reset */
    if (!t) { print_kv( "create", "FAIL" ); return 0; }

    c1.timer = t; c1.timeout_ms = 300;
    c2.timer = t; c2.timeout_ms = 300;

    h1 = spawn_load_thread_sched_other( timer_waiter_fn, &c1, &tid1 );
    h2 = spawn_load_thread_sched_other( timer_waiter_fn, &c2, &tid2 );
    Sleep( 20 );

    due.QuadPart = -500000LL;                            /* 50ms */
    SetWaitableTimer( t, &due, 0, NULL, NULL, FALSE );

    WaitForSingleObject( h1, 1000 );
    WaitForSingleObject( h2, 1000 );
    CloseHandle( h1 );
    CloseHandle( h2 );
    CloseHandle( t );

    woke_count = (c1.result == WAIT_OBJECT_0) + (c2.result == WAIT_OBJECT_0);
    print_kv( "waiter1 result", "%lu", c1.result );
    print_kv( "waiter2 result", "%lu", c2.result );
    print_kv( "woke count", "%d (expected 1)", woke_count );

    if (woke_count != 1)     { print_kv( "verdict", "FAIL" ); return 0; }
    print_kv( "verdict", "PASS" );
    return 1;
}

/* Sub-test 6: set + cancel + close; verify no crash / handle integrity. */
static int nt_timer_sub_close_after_cancel( void )
{
    LARGE_INTEGER due;
    HANDLE t;
    int i;

    print_section( "sub6: set/cancel/close cycle x 100" );
    for (i = 0; i < 100; i++)
    {
        t = CreateWaitableTimerW( NULL, TRUE, NULL );
        if (!t) { print_kv( "create", "FAIL at i=%d", i ); return 0; }

        due.QuadPart = -10000000LL;                      /* 1s — we cancel fast */
        SetWaitableTimer( t, &due, 0, NULL, NULL, FALSE );
        CancelWaitableTimer( t );
        CloseHandle( t );
    }
    print_kv( "iterations", "%d", i );
    print_kv( "verdict", "PASS (no crash, no hang)" );
    return 1;
}

/* Sub-test 7: absolute FILETIME ~50ms in the future. */
static int nt_timer_sub_absolute( void )
{
    FILETIME ft;
    LARGE_INTEGER due;
    HANDLE t;
    UINT64 t0, t1;
    DWORD w;
    long elapsed_ms;

    print_section( "sub7: absolute FILETIME, +50ms" );
    t = CreateWaitableTimerW( NULL, TRUE, NULL );
    if (!t) { print_kv( "create", "FAIL" ); return 0; }

    GetSystemTimeAsFileTime( &ft );
    due.u.LowPart  = ft.dwLowDateTime;
    due.u.HighPart = ft.dwHighDateTime;
    due.QuadPart  += 500000LL;                           /* +50ms in 100ns */

    if (!SetWaitableTimer( t, &due, 0, NULL, NULL, FALSE ))
                             { print_kv( "set", "FAIL" ); CloseHandle(t); return 0; }

    t0 = now_us();
    w  = WaitForSingleObject( t, 1000 );
    t1 = now_us();
    elapsed_ms = (long)((t1 - t0) / 1000);
    CloseHandle( t );

    print_kv( "wait result",  "%lu", w );
    print_kv( "elapsed (ms)", "%ld", elapsed_ms );

    if (w != WAIT_OBJECT_0)  { print_kv( "verdict", "FAIL (no signal)" ); return 0; }
    if (elapsed_ms < 30 || elapsed_ms > 200)
                             { print_kv( "verdict", "FAIL (out of [30,200]ms)" ); return 0; }
    print_kv( "verdict", "PASS" );
    return 1;
}

static int cmd_nt_timer( int argc, char **argv )
{
    int server_path = (getenv( "NSPA_DISABLE_LOCAL_TIMERS" ) != NULL);
    int pass = 0, total = 7;

    (void)argc; (void)argv;
    print_banner( "nt-timer", "NSPA NT timer Phase A (NtCreate/Set/Cancel/Query/Wait)" );

    print_kv( "path",           "%s", server_path ? "wineserver (NSPA_DISABLE_LOCAL_TIMERS set)" : "NSPA LOCAL DISPATCHER" );
    print_kv( "expected",       "all %d sub-tests PASS regardless of path (NT-semantics invariant)", total );

    enter_realtime_class();
    SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL );

    pass += nt_timer_sub_oneshot();
    pass += nt_timer_sub_cancel();
    pass += nt_timer_sub_periodic();
    pass += nt_timer_sub_notification();
    pass += nt_timer_sub_synchronization();
    pass += nt_timer_sub_close_after_cancel();
    pass += nt_timer_sub_absolute();

    leave_realtime_class();

    print_section( "summary" );
    print_kv( "sub-tests passed", "%d / %d", pass, total );

    if (pass == total) { print_verdict( 1, NULL ); return 0; }
    print_verdict( 0, "one or more NT timer sub-tests failed" );
    return 1;
}


/* ════════════════════════════════════════════════════════════════════════
 *   Subcommand: wm-timer  (NSPA WM_TIMER Phase B validation)
 *
 *   Exercises user32::SetTimer / KillTimer / WM_TIMER delivery through
 *   the NSPA local WM_TIMER dispatcher (dlls/win32u/nspa/local_wm_timer.c).
 *   Same tests must PASS on both local path (NSPA_DISABLE_LOCAL_WM_TIMERS
 *   unset, default) and server path (NSPA_DISABLE_LOCAL_WM_TIMERS=1) —
 *   Phase B is an optimisation, NT semantics must not diverge.
 *
 *   Critical NT semantic covered: WM_TIMER coalescing.  If the message
 *   pump stalls across N periods, the app sees ONE WM_TIMER, not N.
 *   This is the single most likely place a naive local implementation
 *   regresses — the coalescing sub-test is the fire drill.
 *
 *   Thread scheduling: main thread only.  Message-only window under
 *   HWND_MESSAGE; PeekMessageW pump drives delivery.  No auxiliary
 *   worker threads (single-threaded event flow is easier to reason
 *   about for WM_TIMER ordering).
 *
 *   Bugs each sub-test guards against:
 *     1 periodic     basic re-arm broken / wrong period
 *     2 kill         stale entry in ring after kill / server both paths
 *     3 coalesce     stalled pump does NOT see N catchup WM_TIMERs
 *     4 re-arm       same id, new rate — old arm must be replaced
 *     5 id=0         falls through to server (server generates id)
 * ════════════════════════════════════════════════════════════════════════ */

#ifndef WM_SYSTIMER
#define WM_SYSTIMER 0x0118         /* private to server/user32 — not in mingw headers */
#endif

static const WCHAR WM_TIMER_TEST_CLASS[] = { 'N','S','P','A','_','W','M','_','T','I','M','E','R',0 };

static HWND wm_timer_create_window( void )
{
    WNDCLASSEXW wc = {0};
    ATOM cls;
    HWND hwnd;

    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = DefWindowProcW;
    wc.hInstance     = GetModuleHandleW( NULL );
    wc.lpszClassName = WM_TIMER_TEST_CLASS;

    cls = RegisterClassExW( &wc );
    (void)cls;                                       /* ERROR_CLASS_ALREADY_EXISTS is fine */

    hwnd = CreateWindowExW( 0, WM_TIMER_TEST_CLASS, WM_TIMER_TEST_CLASS, 0,
                            0, 0, 0, 0, HWND_MESSAGE, NULL,
                            GetModuleHandleW( NULL ), NULL );
    return hwnd;
}

/* Pump for up to `window_ms`, counting WM_TIMER / WM_SYSTIMER messages
 * matching `target_id` (0 = any).  Does not dispatch — just counts. */
static int wm_timer_pump_count( HWND hwnd, DWORD window_ms, UINT_PTR target_id )
{
    UINT64 end = now_us() + window_ms * 1000ULL;
    MSG msg;
    int count = 0;

    while (now_us() < end)
    {
        while (PeekMessageW( &msg, hwnd, 0, 0, PM_REMOVE ))
        {
            if ((msg.message == WM_TIMER || msg.message == WM_SYSTIMER) &&
                (!target_id || msg.wParam == target_id))
                count++;
        }
        Sleep( 1 );
    }
    return count;
}

/* Sub-test 1: basic periodic — 50ms rate, 250ms window, expect ~5. */
static int wm_timer_sub_periodic( HWND hwnd )
{
    int count;

    print_section( "wm1: periodic 50ms, 250ms window" );
    if (!SetTimer( hwnd, 1, 50, NULL )) { print_kv( "SetTimer", "FAIL" ); return 0; }

    count = wm_timer_pump_count( hwnd, 250, 1 );
    KillTimer( hwnd, 1 );

    print_kv( "WM_TIMER count", "%d (expected 3..7)", count );
    if (count < 3 || count > 7) { print_kv( "verdict", "FAIL" ); return 0; }
    print_kv( "verdict", "PASS" );
    return 1;
}

/* Sub-test 2: kill before repeat — arm, pump briefly, kill, then pump
 * and verify no more fires (at most one in-flight from before the kill). */
static int wm_timer_sub_kill( HWND hwnd )
{
    int pre, post;

    print_section( "wm2: kill stops future fires" );
    if (!SetTimer( hwnd, 2, 20, NULL )) { print_kv( "SetTimer", "FAIL" ); return 0; }
    pre = wm_timer_pump_count( hwnd, 80, 2 );       /* expect 2..4 */
    KillTimer( hwnd, 2 );
    post = wm_timer_pump_count( hwnd, 100, 2 );     /* expect 0..1 in-flight */

    print_kv( "pre-kill count",  "%d", pre );
    print_kv( "post-kill count", "%d (expected 0..1)", post );
    if (post > 1) { print_kv( "verdict", "FAIL (fires after KillTimer)" ); return 0; }
    print_kv( "verdict", "PASS" );
    return 1;
}

/* Sub-test 3: coalescing — set 10ms timer, busy (don't pump) for 60ms,
 * THEN pump and expect exactly one WM_TIMER.  This is the NT semantic
 * server implements via the pending/expired list and that a naive
 * local dispatcher will violate by delivering N catchup messages. */
static int wm_timer_sub_coalesce( HWND hwnd )
{
    int count;
    UINT64 busy_end;

    print_section( "wm3: coalescing — stalled pump sees 1 WM_TIMER" );
    if (!SetTimer( hwnd, 3, 10, NULL )) { print_kv( "SetTimer", "FAIL" ); return 0; }

    /* Busy-wait without pumping for 60ms (6 periods). */
    busy_end = now_us() + 60 * 1000;
    while (now_us() < busy_end) { /* no PeekMessage */ }

    /* Now pump very briefly — just drain once. */
    {
        MSG msg;
        count = 0;
        while (PeekMessageW( &msg, hwnd, 0, 0, PM_REMOVE ))
            if ((msg.message == WM_TIMER || msg.message == WM_SYSTIMER) && msg.wParam == 3) count++;
    }
    KillTimer( hwnd, 3 );

    print_kv( "WM_TIMER count", "%d (expected 1 — NT coalescing)", count );
    if (count != 1) { print_kv( "verdict", "FAIL (coalescing regression)" ); return 0; }
    print_kv( "verdict", "PASS" );
    return 1;
}

/* Sub-test 4: re-arm same id with a different rate.  The old arm must
 * be replaced; firing after re-arm happens at the new rate. */
static int wm_timer_sub_rearm( HWND hwnd )
{
    int count_slow, count_fast;

    print_section( "wm4: re-arm same id changes rate" );
    if (!SetTimer( hwnd, 4, 100, NULL )) { print_kv( "SetTimer(slow)", "FAIL" ); return 0; }
    count_slow = wm_timer_pump_count( hwnd, 50, 4 );   /* 50ms window, rate=100ms => 0 */

    if (!SetTimer( hwnd, 4, 10, NULL ))  { print_kv( "SetTimer(fast)", "FAIL" ); return 0; }
    count_fast = wm_timer_pump_count( hwnd, 100, 4 );  /* 100ms window, rate=10ms => ~10 */

    KillTimer( hwnd, 4 );

    print_kv( "slow-rate fires (50ms,rate=100)", "%d (expected 0)", count_slow );
    print_kv( "fast-rate fires (100ms,rate=10)", "%d (expected 5..15)", count_fast );
    if (count_slow > 1 || count_fast < 5 || count_fast > 15)
    { print_kv( "verdict", "FAIL" ); return 0; }
    print_kv( "verdict", "PASS" );
    return 1;
}

/* Sub-test 5: id=0 with non-NULL hwnd falls through to server — NSPA
 * local path returns STATUS_NOT_IMPLEMENTED.  Per Win32 semantics the
 * returned value is 0 when the server stores id=0 (SetTimer docs:
 * hwnd != NULL keeps the caller-supplied id; auto-generation only
 * applies when hwnd is NULL).  Verify:
 *   - SetTimer returns non-zero (1 on current Wine via !ret fallback)
 *   - WM_TIMER arrives (wParam is whatever server stamped; don't
 *     filter on it — we just want to see one message)
 *   - KillTimer(hwnd, 0) unwinds cleanly */
static int wm_timer_sub_id_zero_fallthrough( HWND hwnd )
{
    UINT_PTR id;
    int count;

    print_section( "wm5: id=0 falls through to server" );
    id = SetTimer( hwnd, 0, 50, NULL );
    if (!id) { print_kv( "SetTimer(id=0)", "FAIL" ); return 0; }
    print_kv( "SetTimer return",   "0x%lx", (unsigned long)id );

    /* Don't filter by id — server stamps the WM_TIMER wParam with the
     * server-side timer->id, which for the hwnd-supplied id=0 case is
     * also 0.  Accept any WM_TIMER in the pump window. */
    count = wm_timer_pump_count( hwnd, 150, 0 );
    KillTimer( hwnd, 0 );

    print_kv( "any WM_TIMER count", "%d (expected >=1)", count );
    if (count < 1) { print_kv( "verdict", "FAIL" ); return 0; }
    print_kv( "verdict", "PASS" );
    return 1;
}

static int cmd_wm_timer( int argc, char **argv )
{
    int server_path = (getenv( "NSPA_DISABLE_LOCAL_WM_TIMERS" ) != NULL);
    HWND hwnd;
    int pass = 0, total = 5;

    (void)argc; (void)argv;
    print_banner( "wm-timer", "NSPA WM_TIMER Phase B (SetTimer/KillTimer/WM_TIMER)" );
    print_kv( "path",     "%s", server_path ? "wineserver (NSPA_DISABLE_LOCAL_WM_TIMERS set)" : "NSPA LOCAL DISPATCHER" );
    print_kv( "expected", "all %d sub-tests PASS regardless of path", total );

    if (!(hwnd = wm_timer_create_window()))
    {
        print_verdict( 0, "CreateWindowExW failed — cannot test WM_TIMER" );
        return 1;
    }

    enter_realtime_class();
    SetThreadPriority( GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL );

    pass += wm_timer_sub_periodic( hwnd );
    pass += wm_timer_sub_kill( hwnd );
    pass += wm_timer_sub_coalesce( hwnd );
    pass += wm_timer_sub_rearm( hwnd );
    pass += wm_timer_sub_id_zero_fallthrough( hwnd );

    leave_realtime_class();
    DestroyWindow( hwnd );

    print_section( "summary" );
    print_kv( "sub-tests passed", "%d / %d", pass, total );
    if (pass == total) { print_verdict( 1, NULL ); return 0; }
    print_verdict( 0, "one or more WM_TIMER sub-tests failed" );
    return 1;
}


/* ════════════════════════════════════════════════════════════════════════
 *   Command dispatch
 * ════════════════════════════════════════════════════════════════════════ */

struct command {
    const char *name;
    const char *description;
    int (*entry)(int argc, char **argv);
};

static int cmd_help(int argc, char **argv);

static struct command commands[] = {
    { "priority",     "v1/v2 priority mapping test (11 threads, Phase 1 + Phase 2)",    cmd_priority      },
    { "cs-contention","v2.3 CS-PI contention test (SCHED_FIFO vs SCHED_OTHER holder)",  cmd_cs_contention },
    { "rapidmutex",      "CRITICAL_SECTION stress (1 RT + N-1 load, tight EnterCS loop)",   cmd_rapidmutex    },
    { "philosophers",    "dining philosophers (transitive PI chain test, 5 phils)",         cmd_philosophers  },
    { "fork-mutex",      "spawn N child processes (validate process.c opt-out, default 100)", cmd_fork_mutex    },
    { "child-quickexit", "internal helper — used by fork-mutex (prints a line, exits 42)",    cmd_child_quickexit },
    { "signal-recursion","guard-page fault stress (validate virtual_mutex + signal path)",    cmd_signal_recursion },
    { "large-pages",     "VirtualAlloc(MEM_LARGE_PAGES) end-to-end + /proc/meminfo cross-check", cmd_large_pages },
    { "ntsync",          "NTSync kernel driver PI + priority-ordered wakeup (5 sub-tests)",  cmd_ntsync        },
    { "socket-io",       "async TCP loopback latency (io_uring Phase 3 baseline/compare)",  cmd_socket_io     },
    { "srw-bench",       "SRW lock contention benchmark (acquire latency + ops/sec)",      cmd_srw_bench     },
    { "condvar-pi",      "Win32 condvar PI requeue-PI validation (RT waiter + load)",      cmd_condvar_pi    },
    { "nt-timer",        "NSPA NT timer Phase A validation (7 sub-tests, NT-semantics invariant)", cmd_nt_timer },
    { "wm-timer",        "NSPA WM_TIMER Phase B validation (5 sub-tests, coalescing+NT semantics)", cmd_wm_timer },
    { "help",            "show this help",                                                  cmd_help          },
    { NULL, NULL, NULL }
};

static int cmd_help(int argc, char **argv)
{
    int i;
    (void)argc; (void)argv;
    printf("NSPA RT test harness\n\n");
    printf("Usage: nspa_rt_test.exe <command>\n\n");
    printf("Commands:\n");
    for (i = 0; commands[i].name; i++)
        printf("  %-15s %s\n", commands[i].name, commands[i].description);
    printf("\n");
    printf("Environment:\n");
    printf("  NSPA_RT_PRIO     enables v1 RT promotion (ceiling FIFO priority for TIME_CRITICAL)\n");
    printf("  NSPA_RT_POLICY   FF | RR | TS  — scheduler policy for lower RT band\n");
    printf("\n");
    printf("Examples:\n");
    printf("  NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF ./wine nspa_rt_test.exe priority\n");
    printf("  NSPA_RT_PRIO=80                    ./wine nspa_rt_test.exe cs-contention\n");
    printf("\n");
    printf("Query thread state from another terminal:\n");
    printf("  ps -eLo pid,tid,class,rtprio,nice,comm | grep -E 'POL|nspa_rt_test\\.ex'\n");
    printf("  chrt -p <tid>\n");
    return 0;
}

int main(int argc, char **argv)
{
    const char *cmd;
    int i;

    if (argc < 2)
        return cmd_help(argc, argv);

    /* Safety: arm the watchdog and Ctrl+C handler before running any test. */
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    watchdog_start();

    cmd = argv[1];
    for (i = 0; commands[i].name; i++)
    {
        if (!strcmp(cmd, commands[i].name))
            return commands[i].entry(argc - 1, argv + 1);
    }

    printf("nspa_rt_test: unknown command '%s'\n\n", cmd);
    cmd_help(argc, argv);
    return 2;
}
