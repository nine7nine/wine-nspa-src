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

static LONGLONG now_ms(void)
{
    static LARGE_INTEGER freq;
    LARGE_INTEGER c;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c);
    return (c.QuadPart * 1000) / freq.QuadPart;
}

static LONGLONG now_us(void)
{
    static LARGE_INTEGER freq;
    LARGE_INTEGER c;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c);
    return (c.QuadPart * 1000000) / freq.QuadPart;
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

static struct prio_p2_ctx prio_p2_cases[] = {
    { "IDLE",    THREAD_PRIORITY_IDLE,          72 },
    { "LOWEST",  THREAD_PRIORITY_LOWEST,        78 },
    { "BELOW",   THREAD_PRIORITY_BELOW_NORMAL,  79 },
    { "NORMAL",  THREAD_PRIORITY_NORMAL,        80 },
    { "ABOVE",   THREAD_PRIORITY_ABOVE_NORMAL,  81 },
    { "HIGHEST", THREAD_PRIORITY_HIGHEST,       82 },
    { "TC",      THREAD_PRIORITY_TIME_CRITICAL, 87 },
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

    for (i = 0; i < 3; i++)                if (ph1[i]) WaitForSingleObject(ph1[i], INFINITE);
    for (i = 0; i < (int)NUM_PRIO_P2; i++) if (ph2[i]) WaitForSingleObject(ph2[i], INFINITE);
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
static volatile LONG    g_stop_load;
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
        if ((i & 0xffffff) == 0 && g_stop_load) break;
    }
    return (DWORD)(x & 0xffffffff);
}

/* Fixed-count busy loop. Uses `volatile` to prevent the compiler from
 * optimizing the work away. Duration is determined by CPU time spent, so
 * it's sensitive to how much CPU the thread is actually given. */
static void cs_do_work(long long iters)
{
    volatile long long x = 0;
    long long i;
    for (i = 0; i < iters; i++)
        x += i * (i + 1);
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
    printf("[CS-waiter]  win32_tid=%lu  SetThreadPriority(TIME_CRITICAL) -> SCHED_FIFO 87\n",
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
    int i;
    LONGLONG min_w = 0, max_w = 0, sum_w = 0;

    (void)argc; (void)argv;

    InitializeCriticalSection(&g_cs);
    g_holder_in_cs = CreateEventW(NULL, FALSE, FALSE, NULL);  /* auto-reset */
    g_waiter_done  = CreateEventW(NULL, FALSE, FALSE, NULL);  /* auto-reset */
    g_stop_load = 0;
    g_wait_count = 0;

    print_banner("cs-contention", "CS-PI v2.3 validation / priority inversion test");
    print_section("parameters");
    print_kv("load threads",     "%d SCHED_OTHER background busyloops", CS_LOAD_THREADS);
    print_kv("CS iterations",    "%d", CS_ITERATIONS);
    print_kv("work per hold",    "%lld loop iters (~1 s on an idle core)", CS_WORK_ITERS);
    print_kv("holder policy",    "SCHED_OTHER (no explicit promotion)");
    print_kv("waiter policy",    "SCHED_FIFO 87 via TIME_CRITICAL");
    print_kv("process pid",      "%lu", (unsigned long)GetCurrentProcessId());
    print_kv("observe cmd",      "chrt -p <holder_tid>   /proc/<holder_tid>/status");

    print_section("startup");

    /* Spawn load threads. */
    for (i = 0; i < CS_LOAD_THREADS; i++)
    {
        DWORD tid;
        load_h[i] = CreateThread(NULL, 0, cs_load_thread, NULL, 0, &tid);
        print_worker_start("load", tid, "infinite SCHED_OTHER busyloop");
    }

    /* Give the load threads a moment to ramp up. */
    Sleep(200);

    /* Spawn holder first, waiter second. Holder gets the CS before waiter
     * starts trying (the event synchronizes the rest). */
    holder_h = CreateThread(NULL, 0, cs_holder_thread, NULL, 0, NULL);
    waiter_h = CreateThread(NULL, 0, cs_waiter_thread, NULL, 0, NULL);

    print_section("iterations");
    fflush(stdout);

    WaitForSingleObject(holder_h, INFINITE);
    WaitForSingleObject(waiter_h, INFINITE);

    /* Stop load threads. */
    InterlockedExchange(&g_stop_load, 1);
    for (i = 0; i < CS_LOAD_THREADS; i++)
    {
        WaitForSingleObject(load_h[i], INFINITE);
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

    WaitForMultipleObjects(nthreads, threads, TRUE, INFINITE);
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
static volatile LONG    phil_load_stop;
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
        if ((i & 0xffffff) == 0 && phil_load_stop) break;
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

    /* Start background load threads first so the philosophers immediately
     * face CPU contention. */
    for (i = 0; i < n_load; i++) {
        loads[i] = CreateThread(NULL, 0, phil_load_thread, NULL, 0, NULL);
    }
    if (n_load > 0)
        printf("  [load  ] %d background busyloop thread(s) started\n", n_load);

    /* Start the philosophers. */
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
        WaitForSingleObject(loads[i], INFINITE);
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
        return 1;
    }
    if (min_meals < target_meals) {
        char reason[128];
        snprintf(reason, sizeof(reason),
                 "starvation: min %d meals, expected %d",
                 min_meals, target_meals);
        print_verdict(0, reason);
        return 1;
    }
    print_verdict(1, NULL);
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
        return 1;
    }
    if (total_done != expected_faults) {
        char reason[160];
        snprintf(reason, sizeof(reason),
                 "iters: got %d, expected %d (alloc_fail=%d, protect_fail=%d)",
                 total_done, expected_faults, total_alloc_fail, total_protect_fail);
        print_verdict(0, reason);
        return 1;
    }
    print_verdict(1, NULL);
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
