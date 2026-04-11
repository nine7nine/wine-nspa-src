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
 *   philosophers   [TODO] dining philosophers deadlock-free test — exercises
 *                  multi-lock acquire-order and PI-chain transitivity.
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

    printf("[rapidmutex] %-5s worker  win32_tid=%lu\n",
           s->is_rt ? "RT" : "load", (unsigned long)s->win32_tid);
    fflush(stdout);

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

    printf("[rapidmutex] %d threads (1 RT + %d load), %d iters each\n",
           nthreads, nthreads - 1, iters);
    printf("[rapidmutex] process pid=%lu\n", (unsigned long)GetCurrentProcessId());
    printf("[rapidmutex] tight EnterCS/LeaveCS stress on a shared CRITICAL_SECTION\n");
    printf("[rapidmutex] observe via: ps -eLo pid,tid,class,rtprio,nice,comm | grep nspa_rt_test\n\n");
    fflush(stdout);

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
    printf("\n=== results ===\n");
    printf("total elapsed       : %lld ms\n", total_us / 1000);
    printf("aggregate throughput: %lld ops/sec\n",
           total_us ? (total_done * 1000000LL / total_us) : 0);
    printf("shared counter      : %ld (expected %ld)  %s\n",
           (long)rapid_shared_counter, (long)expected,
           (rapid_shared_counter == expected) ? "OK" : "MISMATCH — CS broken!");

    printf("\nper-thread:\n");
    printf("  %-5s  %-10s  %8s  %10s  %10s  %10s\n",
           "role", "win32_tid", "iters", "max_wait", "avg_wait", "elapsed");
    printf("  %-5s  %-10s  %8s  %10s  %10s  %10s\n",
           "----", "---------", "-----", "--------", "--------", "-------");
    for (i = 0; i < nthreads; i++) {
        LONGLONG avg = states[i].iters_done ? states[i].total_wait_us / states[i].iters_done : 0;
        printf("  %-5s  %-10lu  %8d  %7lld us  %7lld us  %7lld ms\n",
               states[i].is_rt ? "RT" : "load",
               (unsigned long)states[i].win32_tid,
               states[i].iters_done,
               states[i].max_wait_us,
               avg,
               states[i].elapsed_us / 1000);
    }
    printf("\n");
    return (rapid_shared_counter == expected) ? 0 : 1;
}

static int cmd_philosophers(int argc, char **argv)
{
    (void)argc; (void)argv;
    printf("[philosophers] not yet implemented\n");
    printf("\n");
    printf("Planned scope:\n");
    printf("  - N philosopher threads, N CRITICAL_SECTION 'chopsticks'.\n");
    printf("  - Deadlock-free acquire order (resource hierarchy).\n");
    printf("  - Mix of RT and non-RT philosophers to exercise transitive PI\n");
    printf("    chains — an RT philosopher blocked behind an OTHER philosopher\n");
    printf("    that is itself blocked behind another OTHER philosopher.\n");
    printf("  - Measures: meals/sec per philosopher, starvation count, max\n");
    printf("    wait. RT philosophers should never starve if PI is working.\n");
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
    { "rapidmutex",   "CRITICAL_SECTION stress (1 RT + N-1 load, tight EnterCS loop)", cmd_rapidmutex    },
    { "philosophers", "[TODO] dining philosophers — transitive PI chain test",          cmd_philosophers  },
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
