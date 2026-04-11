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
 *                  (RT → holder → holder-of-holder chain boost).
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

    (void)argc; (void)argv;

    load_avrt();

    printf("===============================================\n");
    printf("  NSPA RT priority test — Wine pid %lu\n", pid);
    printf("===============================================\n\n");
    printf("Query with (in another terminal):\n");
    printf("  ps -eLo pid,tid,class,rtprio,nice,comm | grep -E 'POL|nspa_rt_test\\.ex'\n\n");
    fflush(stdout);

    /* Phase 1 */
    printf("── Phase 1: default class (Tier 1 lenient path) ──\n");
    fflush(stdout);
    ph1[0] = CreateThread(NULL, 0, prio_p1_tc,   NULL, 0, NULL);
    ph1[1] = CreateThread(NULL, 0, prio_p1_mcss, NULL, 0, NULL);
    ph1[2] = CreateThread(NULL, 0, prio_p1_norm, NULL, 0, NULL);
    Sleep(500);

    /* Phase 2 */
    printf("\n── Phase 2: elevating process to REALTIME_PRIORITY_CLASS ──\n");
    fflush(stdout);
    if (!SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS))
    {
        DWORD e = GetLastError();
        printf("  SetPriorityClass(REALTIME) FAILED: err=%lu\n", e);
    }
    else
    {
        printf("  SetPriorityClass(REALTIME) OK\n");
        printf("  main thread should now be FF 80 (NT 24 anchor)\n");
    }
    fflush(stdout);

    for (i = 0; i < (int)NUM_PRIO_P2; i++)
        ph2[i] = CreateThread(NULL, 0, prio_p2_thread, &prio_p2_cases[i], 0, NULL);

    Sleep(500);
    printf("\n── All 11 threads (main + 3 P1 + 7 P2) now sleeping %d seconds ──\n", PRIO_SLEEP_SECS);
    printf("── Query ps now ──\n\n");
    fflush(stdout);

    for (i = 0; i < 3; i++)              WaitForSingleObject(ph1[i], INFINITE);
    for (i = 0; i < (int)NUM_PRIO_P2; i++) WaitForSingleObject(ph2[i], INFINITE);
    for (i = 0; i < 3; i++)              CloseHandle(ph1[i]);
    for (i = 0; i < (int)NUM_PRIO_P2; i++) CloseHandle(ph2[i]);
    return 0;
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

    printf("==========================================================\n");
    printf("  NSPA RT CS contention test — CS-PI v2.3 validation\n");
    printf("==========================================================\n\n");
    printf("Config:\n");
    printf("  SCHED_OTHER background load threads:  %d\n", CS_LOAD_THREADS);
    printf("  CS work iterations per hold:          %lld\n", CS_WORK_ITERS);
    printf("  Iterations:                           %d\n", CS_ITERATIONS);
    printf("\n");
    printf("This test spawns %d infinite-busyloop SCHED_OTHER load threads to\n", CS_LOAD_THREADS);
    printf("create CPU contention, then has a SCHED_OTHER holder thread acquire\n");
    printf("a shared CRITICAL_SECTION and do a fixed-count CPU-bound work loop\n");
    printf("inside the CS. A SCHED_FIFO (TIME_CRITICAL) waiter blocks on the CS.\n\n");
    printf("Under NSPA_RT_PRIO with CS-PI v2.3 active, the kernel's FUTEX_LOCK_PI\n");
    printf("chain should temporarily boost the holder to the waiter's priority\n");
    printf("(SCHED_FIFO 87), letting it preempt the load threads and complete\n");
    printf("the work in uncontended-core time (~1-2s). Without the env var the\n");
    printf("holder shares CPU with the load threads, taking proportionally\n");
    printf("longer, which the waiter sees as a longer wait time.\n\n");
    fflush(stdout);

    /* Spawn load threads. */
    for (i = 0; i < CS_LOAD_THREADS; i++)
    {
        DWORD tid;
        load_h[i] = CreateThread(NULL, 0, cs_load_thread, NULL, 0, &tid);
        printf("[CS-load]    win32_tid=%lu  infinite SCHED_OTHER busyloop\n", tid);
    }
    fflush(stdout);

    /* Give the load threads a moment to ramp up. */
    Sleep(200);

    /* Spawn holder first, waiter second. Holder gets the CS before waiter
     * starts trying (the event synchronizes the rest). */
    holder_h = CreateThread(NULL, 0, cs_holder_thread, NULL, 0, NULL);
    waiter_h = CreateThread(NULL, 0, cs_waiter_thread, NULL, 0, NULL);

    printf("\nDuring each iteration (while the holder is inside the CS), run\n");
    printf("this in another terminal to see the kernel's view of the holder:\n\n");
    printf("  chrt -p <holder_tid>\n");
    printf("  cat /proc/<holder_tid>/status | grep -E '^Name|^State|^Policy'\n\n");
    printf("Expected with NSPA_RT_PRIO=80:  policy=SCHED_FIFO, priority=87 during hold\n");
    printf("Expected without NSPA_RT_PRIO:  policy=SCHED_OTHER, priority=0 throughout\n\n");
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

        printf("\n── Summary ────────────────────────────────────────────────\n");
        printf("  Samples:  %d\n", g_wait_count);
        printf("  Min wait: %4lld ms\n", min_w);
        printf("  Max wait: %4lld ms\n", max_w);
        printf("  Avg wait: %4lld ms\n", sum_w / g_wait_count);
        printf("\n");
        printf("Interpretation:\n");
        printf("  Run twice and compare (same machine, same build):\n");
        printf("    $ NSPA_RT_PRIO=80 ./wine nspa_rt_test.exe cs-contention\n");
        printf("    $                 ./wine nspa_rt_test.exe cs-contention\n");
        printf("  CS-PI is working when:\n");
        printf("    - with-PI avg wait is close to uncontended work time\n");
        printf("    - without-PI avg wait is materially larger\n");
        printf("    - the ratio (without/with) grows with CS_LOAD_THREADS\n");
    }

    DeleteCriticalSection(&g_cs);
    CloseHandle(g_holder_in_cs);
    CloseHandle(g_waiter_done);
    return 0;
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
    { "rapidmutex",   "CRITICAL_SECTION stress (1 RT + N-1 load, tight EnterCS loop)", cmd_rapidmutex    },
    { "philosophers", "dining philosophers (transitive PI chain test, 5 phils)",       cmd_philosophers  },
    { "help",         "show this help",                                                  cmd_help          },
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
    printf("  NSPA_RT_PRIO     enables v1 RT promotion (anchor FIFO priority)\n");
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
