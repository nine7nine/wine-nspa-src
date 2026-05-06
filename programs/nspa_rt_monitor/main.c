/*
 * nspa_rt_monitor — Win32 GUI RT-latency monitor for Wine-NSPA.
 *
 * Better-than-dpclat replacement that measures the paths Wine actually
 * uses, not synthetic Windows-driver DPCs.
 *
 * Five measurement modes, switch with 1..5:
 *
 *   1 — NtDelayExecution     RT-thread wakeup-from-deadline jitter (Linux
 *                            scheduler floor; closest to what dpclat
 *                            *thinks* it measures).
 *   2 — ntsync ping-pong     Cross-thread event signal/wait latency
 *                            through anonymous events (Phase 4.6 ->
 *                            inproc-sync -> kernel ntsync direct).
 *   3 — NT timer periodic    NtCreateTimer + NtSetTimer at 1ms period;
 *                            anonymous so lands on local_timer.c -> RT
 *                            sched dispatch.  Tests the migrated path.
 *   4 — CS-PI contention     High-prio thread acquires a CS held by a
 *                            low-prio thread; measures CS-PI boost +
 *                            release-handoff under NSPA_RT_PRIO.
 *   5 — KDPC dispatcher      KeInitializeDpc + KeSetTimerEx through
 *                            Wine ntoskrnl.exe -> dpc.c dispatcher.
 *                            Measures fire jitter inside the
 *                            DeferredRoutine.
 *
 * UI: GDI-drawn histogram (last 30s, 1s buckets, color-coded by
 * threshold — green <500us / yellow <2ms / red >=2ms) + per-mode stats
 * (current / min / max / p50 / p99 / p99.9).
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <windows.h>
#include <winternl.h>

#include <ddk/wdm.h>

NTSYSAPI NTSTATUS NTAPI NtDelayExecution(BOOLEAN alertable, const LARGE_INTEGER *timeout);
NTSYSAPI NTSTATUS NTAPI NtCreateTimer(PHANDLE handle, ACCESS_MASK access,
                                       const OBJECT_ATTRIBUTES *attr, TIMER_TYPE type);
NTSYSAPI NTSTATUS NTAPI NtSetTimer(HANDLE handle, const LARGE_INTEGER *due_time,
                                    PTIMER_APC_ROUTINE apc, void *apc_ctx,
                                    BOOLEAN resume, ULONG period, BOOLEAN *prev);
NTSYSAPI NTSTATUS NTAPI NtCancelTimer(HANDLE handle, BOOLEAN *prev);
NTSYSAPI NTSTATUS NTAPI NtCreateEvent(PHANDLE handle, ACCESS_MASK access,
                                       const OBJECT_ATTRIBUTES *attr,
                                       EVENT_TYPE type, BOOLEAN state);
NTSYSAPI NTSTATUS NTAPI NtSetEvent(HANDLE handle, LONG *prev);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE handle);

/* ---------- constants ---------- */

#define WIN_W                720
#define WIN_H                480
#define BUCKET_SECONDS       30
#define HIST_CAPACITY        4096
#define MODE_COUNT           6
/* 10 ms — large enough to be reliably achievable on a mainstream
 * RT-Linux host (the dispatch round-trip floor is ~1-2 ms in the good
 * case), small enough that real DAW jitter sits well above the noise
 * floor.  At 1 ms targets every fire reads as catastrophically late
 * because the inter-fire floor is set by the slowest of (host HZ,
 * Wine local_timer dispatch, NSPA sched), not by the test subject. */
#define TARGET_PERIOD_US     10000
#define UI_TIMER_ID          1

/* Custom message: dedicated 1Hz ticker thread posts this to the UI
 * thread.  WM_TIMER dispatch on Wine can miss / consolidate fires when
 * the message loop is briefly busy; a tick thread doing
 * NtDelayExecution(1s) -> PostMessage gives a guaranteed 1Hz cadence
 * regardless of message-loop occupancy. */
#define WM_NSPA_TICK (WM_USER + 1)

#define COLOR_BG     RGB(0x1a, 0x1b, 0x26)
#define COLOR_FG     RGB(0xc0, 0xca, 0xf5)
#define COLOR_DIM    RGB(0x8c, 0x92, 0xb3)
#define COLOR_GREEN  RGB(0x9e, 0xce, 0x6a)
#define COLOR_YELLOW RGB(0xe0, 0xaf, 0x68)
#define COLOR_RED    RGB(0xf7, 0x76, 0x8e)
#define COLOR_ACCENT RGB(0x7a, 0xa2, 0xf7)
#define COLOR_GRID   RGB(0x3b, 0x42, 0x61)

/* ---------- per-mode state ---------- */

struct mode_state {
    HANDLE  worker;
    HANDLE  helper;            /* signaler / low-prio thread for some modes */
    volatile LONG running;
    CRITICAL_SECTION lock;

    LONGLONG samples[HIST_CAPACITY];
    int      sample_count;
    int      sample_pos;       /* next write index (ring) */

    LONGLONG bucket_max[BUCKET_SECONDS];   /* completed buckets only */
    int      bucket_pos;                   /* next write index in ring */
    LONGLONG current_max;                  /* in-progress bucket; not in ring until roll */

    LONGLONG last_us;          /* most recent sample */
    LONGLONG total_min, total_max;
    BOOL     have_min;
};

static struct mode_state modes[MODE_COUNT];
static int active_mode = 0;
static const char * const mode_names[MODE_COUNT] = {
    "1: NtDelayExecution",
    "2: ntsync ping-pong",
    "3: event recycle throughput",
    "4: CS-PI contention",
    "5: KDPC dispatcher",
    "6: NSPA system info"
};
static const char * const mode_desc[MODE_COUNT] = {
    "NtDelayExecution lateness vs 10ms relative deadline",
    "Cross-thread event signal->wake delay (anonymous event, inproc-sync)",
    "NtCreateEvent + NtSetEvent + NtClose tight loop - per-cycle latency (us)",
    "High-prio thread acquires CS held by low-prio (CS-PI boost path)",
    "KDPC 10ms periodic - gap-jitter |gap_n - 10ms| (KeSetTimerEx + DPC)",
    "NSPA running state - Wine version, kernel, RT env, processes, memory"
};

/* ---------- timing ---------- */

static double qpc_to_us = 0.0;
static LARGE_INTEGER qpc_freq;

static inline LONGLONG qpc(void)
{
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return c.QuadPart;
}

static inline double ticks_to_us(LONGLONG t)
{
    return (double)t * qpc_to_us;
}

/* ---------- sample plumbing ---------- */

static void push_sample(int mode, LONGLONG us)
{
    struct mode_state *m = &modes[mode];
    if (us < 0) us = 0;
    EnterCriticalSection(&m->lock);
    if (m->sample_count < HIST_CAPACITY) m->sample_count++;
    m->samples[m->sample_pos] = us;
    m->sample_pos = (m->sample_pos + 1) % HIST_CAPACITY;
    /* In-progress bucket lives outside the displayed ring; this avoids
     * the "rightmost bar resets to 0 at tick" flicker.  The ring only
     * carries completed buckets. */
    if (us > m->current_max) m->current_max = us;
    if (us > m->total_max) m->total_max = us;
    if (!m->have_min || us < m->total_min) { m->total_min = us; m->have_min = TRUE; }
    m->last_us = us;
    LeaveCriticalSection(&m->lock);
}

static void roll_bucket(int mode)
{
    struct mode_state *m = &modes[mode];
    EnterCriticalSection(&m->lock);
    /* Snapshot the just-completed in-progress bucket into the ring at
     * the current write position, advance the write position, reset
     * the in-progress accumulator for the next second. */
    m->bucket_max[m->bucket_pos] = m->current_max;
    m->bucket_pos = (m->bucket_pos + 1) % BUCKET_SECONDS;
    m->current_max = 0;
    LeaveCriticalSection(&m->lock);
}

static int compare_lls(const void *a, const void *b)
{
    LONGLONG la = *(const LONGLONG *)a, lb = *(const LONGLONG *)b;
    return (la < lb) ? -1 : (la > lb) ? 1 : 0;
}

struct stats {
    LONGLONG last, min, max, p50, p99, p999;
    int count;
};

static void compute_stats(int mode, struct stats *s)
{
    struct mode_state *m = &modes[mode];
    LONGLONG copy[HIST_CAPACITY];
    int n;

    EnterCriticalSection(&m->lock);
    n = m->sample_count;
    memcpy(copy, m->samples, sizeof(LONGLONG) * n);
    s->last = m->last_us;
    s->min  = m->have_min ? m->total_min : 0;
    s->max  = m->total_max;
    LeaveCriticalSection(&m->lock);

    s->count = n;
    if (n == 0) { s->p50 = s->p99 = s->p999 = 0; return; }
    qsort(copy, n, sizeof(LONGLONG), compare_lls);
    s->p50  = copy[n / 2];
    s->p99  = copy[(n * 99)  / 100];
    s->p999 = copy[(n * 999) / 1000];
}

/* ---------- mode 1: NtDelayExecution ---------- */

static DWORD WINAPI mode1_worker(LPVOID arg)
{
    int idx = (int)(LONG_PTR)arg;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)TARGET_PERIOD_US * 10;  /* 100ns units, relative */

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    while (modes[idx].running)
    {
        LONGLONG t0 = qpc();
        NtDelayExecution(FALSE, &timeout);
        LONGLONG t1 = qpc();
        LONGLONG actual_us = (LONGLONG)ticks_to_us(t1 - t0);
        push_sample(idx, actual_us - TARGET_PERIOD_US);
    }
    return 0;
}

/* ---------- mode 2: ntsync event ping-pong ---------- */

static HANDLE m2_event;
static volatile LONGLONG m2_signal_qpc;
static volatile LONG m2_helper_run;

static DWORD WINAPI mode2_signaler(LPVOID arg)
{
    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)TARGET_PERIOD_US * 10;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    while (m2_helper_run)
    {
        NtDelayExecution(FALSE, &timeout);
        m2_signal_qpc = qpc();
        SetEvent(m2_event);
    }
    return 0;
}

static DWORD WINAPI mode2_worker(LPVOID arg)
{
    int idx = (int)(LONG_PTR)arg;

    m2_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!m2_event) return 0;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    m2_helper_run = 1;
    modes[idx].helper = CreateThread(NULL, 0, mode2_signaler, NULL, 0, NULL);

    while (modes[idx].running)
    {
        DWORD r = WaitForSingleObject(m2_event, 200);
        if (r != WAIT_OBJECT_0) continue;
        LONGLONG wake = qpc();
        LONGLONG signal_at = m2_signal_qpc;
        if (signal_at == 0) continue;
        LONGLONG delta_us = (LONGLONG)ticks_to_us(wake - signal_at);
        push_sample(idx, delta_us);
    }

    m2_helper_run = 0;
    if (modes[idx].helper)
    {
        WaitForSingleObject(modes[idx].helper, 500);
        CloseHandle(modes[idx].helper);
        modes[idx].helper = NULL;
    }
    CloseHandle(m2_event);
    m2_event = NULL;
    return 0;
}

/* ---------- mode 3: PE-side anonymous-event recycle throughput ----------
 *
 * Tight loop: NtCreateEvent -> NtSetEvent -> NtClose.  Each sample is
 * the per-cycle latency in microseconds.  Exercises the NSPA inproc-
 * sync fast path (PE-side ntsync ioctl + client-handle freelist), so
 * a sudden p99 climb is a regression detector for that whole stack.
 *
 * Ran at TIME_CRITICAL so we measure the inproc-sync path itself, not
 * scheduler queue time. */
static DWORD WINAPI mode3_worker(LPVOID arg)
{
    int idx = (int)(LONG_PTR)arg;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    while (modes[idx].running)
    {
        LONGLONG t0 = qpc();
        HANDLE event;
        NTSTATUS s = NtCreateEvent(&event, EVENT_ALL_ACCESS, NULL,
                                    NotificationEvent, FALSE);
        if (s) { Sleep(1); continue; }
        NtSetEvent(event, NULL);
        NtClose(event);
        push_sample(idx, (LONGLONG)ticks_to_us(qpc() - t0));
    }
    return 0;
}

/* ---------- mode 4: CS-PI contention ---------- */

static CRITICAL_SECTION m4_cs;
static volatile LONG m4_helper_run;

static DWORD WINAPI mode4_holder(LPVOID arg)
{
    LARGE_INTEGER hold, gap;
    /* Hold for ~200us, release, sleep 800us — ~1ms cycle.  Low priority
     * so the high-prio worker has to boost us via CS-PI to acquire
     * (CS-PI is automatic under NSPA_RT_PRIO; futex_lock_pi semantics). */
    hold.QuadPart = -2000;   /* 200us */
    gap.QuadPart  = -8000;   /* 800us */

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    while (m4_helper_run)
    {
        EnterCriticalSection(&m4_cs);
        NtDelayExecution(FALSE, &hold);
        LeaveCriticalSection(&m4_cs);
        NtDelayExecution(FALSE, &gap);
    }
    return 0;
}

static DWORD WINAPI mode4_worker(LPVOID arg)
{
    int idx = (int)(LONG_PTR)arg;

    InitializeCriticalSection(&m4_cs);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    m4_helper_run = 1;
    modes[idx].helper = CreateThread(NULL, 0, mode4_holder, NULL, 0, NULL);

    LARGE_INTEGER short_pause;
    short_pause.QuadPart = -10000;  /* 1ms between attempts */

    while (modes[idx].running)
    {
        NtDelayExecution(FALSE, &short_pause);
        LONGLONG t0 = qpc();
        EnterCriticalSection(&m4_cs);
        LONGLONG t1 = qpc();
        LeaveCriticalSection(&m4_cs);
        push_sample(idx, (LONGLONG)ticks_to_us(t1 - t0));
    }

    m4_helper_run = 0;
    if (modes[idx].helper)
    {
        WaitForSingleObject(modes[idx].helper, 500);
        CloseHandle(modes[idx].helper);
        modes[idx].helper = NULL;
    }
    DeleteCriticalSection(&m4_cs);
    return 0;
}

/* ---------- mode 5: KDPC dispatcher (gap-jitter) ----------
 *
 * Gap-jitter metric: |(now - last_fire) - period|.  Each sample is
 * how far this fire's gap deviates from the nominal period.  Anchor-
 * less, so no resync sawtooth artifact; insensitive to one-shot
 * stalls (a 100 ms stall produces ONE outlier sample, not a
 * cascading hundred). */

static volatile LONGLONG m5_last_fire;
static int               m5_idx;

static void WINAPI m5_deferred(KDPC *dpc, void *ctx, void *arg1, void *arg2)
{
    LONGLONG now = qpc();
    LONGLONG last = m5_last_fire;
    if (last)
    {
        LONGLONG gap_us = (LONGLONG)ticks_to_us(now - last);
        LONGLONG jit = gap_us - TARGET_PERIOD_US;
        push_sample(m5_idx, jit < 0 ? -jit : jit);
    }
    m5_last_fire = now;
}

static DWORD WINAPI mode5_worker(LPVOID arg)
{
    int idx = (int)(LONG_PTR)arg;
    static KDPC dpc;
    static KTIMER timer;
    LARGE_INTEGER duetime;

    m5_idx       = idx;
    m5_last_fire = 0;

    KeInitializeDpc(&dpc, m5_deferred, NULL);
    KeInitializeTimer(&timer);

    duetime.QuadPart = -(LONGLONG)TARGET_PERIOD_US * 10;
    KeSetTimerEx(&timer, duetime, TARGET_PERIOD_US / 1000, &dpc);

    /* Worker just keeps the mode alive — DPC fires from dpc.c's
     * dpc_dispatch_thread, not here. */
    while (modes[idx].running)
        Sleep(100);

    KeCancelTimer(&timer);
    return 0;
}

/* ---------- mode 6: NSPA system info (no measurement, idle worker) ---------- */

static DWORD WINAPI mode6_worker(LPVOID arg)
{
    int idx = (int)(LONG_PTR)arg;
    /* Info page reads /proc + sysfs in the paint path on each tick.
     * Worker just keeps the mode "running" so the lifecycle code is
     * uniform with the latency modes. */
    while (modes[idx].running)
        Sleep(200);
    return 0;
}

/* ---------- mode lifecycle ---------- */

typedef DWORD (WINAPI *worker_fn)(LPVOID);
static const worker_fn workers[MODE_COUNT] = {
    mode1_worker, mode2_worker, mode3_worker, mode4_worker, mode5_worker, mode6_worker
};

static void mode_reset(int idx)
{
    struct mode_state *m = &modes[idx];
    EnterCriticalSection(&m->lock);
    m->sample_count = 0;
    m->sample_pos = 0;
    m->bucket_pos = 0;
    memset(m->bucket_max, 0, sizeof(m->bucket_max));
    m->current_max = 0;
    m->last_us = 0;
    m->total_min = 0;
    m->total_max = 0;
    m->have_min = FALSE;
    LeaveCriticalSection(&m->lock);
}

static void mode_start(int idx)
{
    /* Note: do NOT reset stats here — switching modes preserves
     * histogram + percentile history per mode, so the user can
     * compare at-a-glance.  Explicit 'R' key resets the active mode. */
    if (modes[idx].running) return;
    modes[idx].running = 1;
    modes[idx].worker = CreateThread(NULL, 0, workers[idx], (LPVOID)(LONG_PTR)idx, 0, NULL);
}

static void mode_stop(int idx)
{
    if (!modes[idx].running) return;
    modes[idx].running = 0;
    if (modes[idx].worker)
    {
        WaitForSingleObject(modes[idx].worker, 1000);
        CloseHandle(modes[idx].worker);
        modes[idx].worker = NULL;
    }
}

/* ---------- rendering ---------- */

/* ---------- info-mode helpers (mode 6) ---------- */

/* Read up to cap-1 bytes from a host file via Wine's Z: drive mapping.
 * Returns bytes read (0 on failure).  Cheap on every paint (1 Hz). */
static int read_host_file(const char *unix_path, char *buf, size_t cap)
{
    char dos_path[260];
    HANDLE h;
    DWORD got = 0;
    if (cap < 2) return 0;
    snprintf(dos_path, sizeof(dos_path), "Z:%s", unix_path);
    h = CreateFileA(dos_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { buf[0] = 0; return 0; }
    if (!ReadFile(h, buf, (DWORD)(cap - 1), &got, NULL)) got = 0;
    CloseHandle(h);
    buf[got] = 0;
    return (int)got;
}

/* Find a key like "HugePages_Total:" in /proc/meminfo-style content,
 * parse the integer that follows.  Returns -1 if missing. */
static long find_proc_long(const char *content, const char *key)
{
    const char *p = strstr(content, key);
    if (!p) return -1;
    p += strlen(key);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    return strtol(p, NULL, 10);
}

/* /sys/devices/system/cpu/online: "0-7" or "0,2-5,7" — count via
 * range-list semantics. */
static long count_online_cpus(const char *cpu_online)
{
    long count = 0;
    const char *p = cpu_online;
    while (*p)
    {
        long a = strtol(p, (char **)&p, 10);
        long b = a;
        if (*p == '-') { p++; b = strtol(p, (char **)&p, 10); }
        if (b >= a) count += (b - a + 1);
        if (*p == ',') p++;
        else break;
    }
    return count;
}

/* Section header (accent colour) + key/value row helpers. */
static void info_section(HDC hdc, int x, int *row_y, int row_h, const char *title)
{
    SetTextColor(hdc, COLOR_ACCENT);
    TextOutA(hdc, x, *row_y, title, (int)strlen(title));
    *row_y += row_h;
}

static void info_kv(HDC hdc, int x, int *row_y, int row_h, const char *fmt, ...)
{
    char line[200];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    SetTextColor(hdc, COLOR_FG);
    TextOutA(hdc, x, *row_y, line, (int)strlen(line));
    *row_y += row_h;
}

/* ----- Wine-process scan (Phase 1/3 effectiveness panel) ----- */

struct wine_proc {
    int  pid;
    char name[40];
    long rss_kb;
    long lck_kb;       /* VmLck — non-zero means working-set pinning is active */
    long hugetlb_kb;   /* HugetlbPages — explicit MAP_HUGETLB usage */
    int  threads;
    int  fifo_threads; /* SCHED_FIFO/RR count via /proc/<pid>/task/<tid>/sched */
};

/* Count SCHED_FIFO / SCHED_RR threads under /proc/<pid>/task/.  Capped
 * at 64 task reads per process to bound the worst-case repaint cost. */
static int count_fifo_threads(int pid)
{
    char dos_glob[260], path[260], buf[2048];
    HANDLE find;
    WIN32_FIND_DATAA wfd;
    int count = 0, scanned = 0;

    snprintf(dos_glob, sizeof(dos_glob), "Z:\\proc\\%d\\task\\*", pid);
    find = FindFirstFileA(dos_glob, &wfd);
    if (find == INVALID_HANDLE_VALUE) return 0;
    do {
        char *e;
        long tid;
        const char *p;
        if (++scanned > 64) break;
        tid = strtol(wfd.cFileName, &e, 10);
        if (*e != 0 || tid <= 0) continue;
        snprintf(path, sizeof(path), "/proc/%d/task/%ld/sched", pid, tid);
        if (read_host_file(path, buf, sizeof(buf)) <= 0) continue;
        p = strstr(buf, "policy");
        if (!p) continue;
        while (*p && *p != ':') p++;
        if (*p == ':')
        {
            long pol = strtol(p + 1, NULL, 10);
            if (pol == 1 || pol == 2) count++;
        }
    } while (FindNextFileA(find, &wfd));
    FindClose(find);
    return count;
}

static void clean_wine_name(char *name)
{
    size_t n = strlen(name);
    if (n >= 4 && !strcasecmp(name + n - 4, ".exe")) name[n - 4] = 0;
    else if (n >= 2 && !strcmp(name + n - 2, ".e")) name[n - 2] = 0;
}

/* Scan /proc, return up to max_count Wine processes ranked by RSS desc.
 * "Wine process" = comm == "wineserver" OR cmdline contains ".exe" or
 * "/wine".  All reads come from /proc/<pid>/{comm,cmdline,status}. */
static int scan_wine_processes(struct wine_proc *out, int max_count)
{
    HANDLE find;
    WIN32_FIND_DATAA wfd;
    int count = 0;
    char path[260], buf[16384];

    find = FindFirstFileA("Z:\\proc\\*", &wfd);
    if (find == INVALID_HANDLE_VALUE) return 0;
    do {
        char *e;
        long pid = strtol(wfd.cFileName, &e, 10);
        char comm[64] = {0}, cmdline[512] = {0};
        int cmdline_len, is_wine;
        long rss, lck, threads, hugetlb;
        char *nl;
        struct wine_proc p;

        if (*e != 0 || pid <= 0) continue;

        snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
        if (read_host_file(path, comm, sizeof(comm)) <= 0) continue;
        if ((nl = strchr(comm, '\n'))) *nl = 0;

        snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
        cmdline_len = read_host_file(path, cmdline, sizeof(cmdline));
        if (cmdline_len < 0) cmdline_len = 0;

        is_wine = (strcmp(comm, "wineserver") == 0) ||
                  (cmdline_len > 0 &&
                   (strstr(cmdline, ".exe") != NULL ||
                    strstr(cmdline, "/wine") != NULL ||
                    strstr(cmdline, "wine64") != NULL));
        if (!is_wine) continue;

        snprintf(path, sizeof(path), "/proc/%ld/status", pid);
        if (read_host_file(path, buf, sizeof(buf)) <= 0) continue;
        rss     = find_proc_long(buf, "VmRSS");
        lck     = find_proc_long(buf, "VmLck");
        threads = find_proc_long(buf, "Threads");
        hugetlb = find_proc_long(buf, "HugetlbPages");

        p.pid          = (int)pid;
        lstrcpynA(p.name, comm, sizeof(p.name));
        clean_wine_name(p.name);
        p.rss_kb       = rss     >= 0 ? rss     : 0;
        p.lck_kb       = lck     >= 0 ? lck     : 0;
        p.hugetlb_kb   = hugetlb >= 0 ? hugetlb : 0;
        p.threads      = (int)(threads >= 0 ? threads : 0);
        p.fifo_threads = count_fifo_threads((int)pid);

        /* Insertion sort by rss_kb desc, capped at max_count. */
        {
            int i = (count < max_count) ? count : max_count - 1;
            while (i > 0 && out[i - 1].rss_kb < p.rss_kb)
            {
                out[i] = out[i - 1];
                i--;
            }
            if (i < max_count) out[i] = p;
            if (count < max_count) count++;
        }
    } while (FindNextFileA(find, &wfd));
    FindClose(find);
    return count;
}

static void format_us(char *buf, size_t cap, LONGLONG us)
{
    if (us >= 10000) snprintf(buf, cap, "%lld.%lld ms", us / 1000, (us % 1000) / 100);
    else             snprintf(buf, cap, "%lld us", us);
}

static COLORREF threshold_color(LONGLONG us)
{
    if (us < 500)  return COLOR_GREEN;
    if (us < 2000) return COLOR_YELLOW;
    return COLOR_RED;
}

/* Paint one wine-process row.  Numeric columns are right-aligned at
 * fixed pixel positions so columns line up under any proportional
 * font: we measure each value's width with GetTextExtentPoint32A and
 * paint at (col_right - width).  The header uses the same right-edge
 * positions, so values stack visually. */
static void paint_wine_processes(HDC hdc, int x, int *row_y, int row_h, int w)
{
    static struct wine_proc cached_procs[8];
    static int cached_n = 0;
    static DWORD cached_at_ms = 0;
    DWORD now_ms = GetTickCount();
    int n;
    int x_pid_r, x_rss_r, x_lck_r, x_huge_r, x_thr_r, x_rt_r;
    char line[256];
    int i;

    /* 1 Hz cache so resize repaints don't re-walk /proc. */
    if (cached_at_ms == 0 || (now_ms - cached_at_ms) >= 1000)
    {
        cached_n = scan_wine_processes(cached_procs, 8);
        cached_at_ms = now_ms;
    }
    n = cached_n;

    /* Right-edge x positions for each numeric column, distributed
     * across the panel width.  Columns: process / pid / rss / lck /
     * huge / thr / rt.  Process name is left-aligned at x; everything
     * else right-aligns at the corresponding *_r position. */
    x_pid_r  = x + (int)(w * 0.38);
    x_rss_r  = x + (int)(w * 0.50);
    x_lck_r  = x + (int)(w * 0.62);
    x_huge_r = x + (int)(w * 0.74);
    x_thr_r  = x + (int)(w * 0.84);
    x_rt_r   = x + (int)(w * 0.94);

    info_section(hdc, x, row_y, row_h, "Wine processes");
    if (!n)
    {
        SetTextColor(hdc, COLOR_DIM);
        TextOutA(hdc, x, *row_y, "  (no Wine processes detected)", 30);
        *row_y += row_h;
        return;
    }

    /* Header row — labels right-aligned at the same edges as data. */
    {
        const char *labels[6] = { "pid", "rss", "lck", "huge", "thr", "rt" };
        int edges[6] = { x_pid_r, x_rss_r, x_lck_r, x_huge_r, x_thr_r, x_rt_r };
        SIZE sz;
        SetTextColor(hdc, COLOR_DIM);
        TextOutA(hdc, x, *row_y, "  process", 9);
        for (i = 0; i < 6; i++)
        {
            int len = (int)strlen(labels[i]);
            if (GetTextExtentPoint32A(hdc, labels[i], len, &sz))
                TextOutA(hdc, edges[i] - sz.cx, *row_y, labels[i], len);
        }
        *row_y += row_h;
    }

    for (i = 0; i < n; i++)
    {
        struct wine_proc *p = &cached_procs[i];
        char rss_buf[16], lck_buf[16], huge_buf[16];
        char pid_buf[16], thr_buf[16], rt_buf[16];
        COLORREF lck_col  = p->lck_kb     > 0 ? COLOR_GREEN : COLOR_DIM;
        COLORREF huge_col = p->hugetlb_kb > 0 ? COLOR_GREEN : COLOR_DIM;
        SIZE sz;

        if (p->rss_kb >= 1024) snprintf(rss_buf, sizeof(rss_buf), "%ldM", p->rss_kb / 1024);
        else                   snprintf(rss_buf, sizeof(rss_buf), "%ldK", p->rss_kb);

        if (p->lck_kb == 0)        snprintf(lck_buf, sizeof(lck_buf), "off");
        else if (p->lck_kb >= 1024) snprintf(lck_buf, sizeof(lck_buf), "%ldM", p->lck_kb / 1024);
        else                        snprintf(lck_buf, sizeof(lck_buf), "%ldK", p->lck_kb);

        if (p->hugetlb_kb == 0)         snprintf(huge_buf, sizeof(huge_buf), "-");
        else if (p->hugetlb_kb >= 1024) snprintf(huge_buf, sizeof(huge_buf), "%ldM", p->hugetlb_kb / 1024);
        else                            snprintf(huge_buf, sizeof(huge_buf), "%ldK", p->hugetlb_kb);

        snprintf(pid_buf, sizeof(pid_buf), "%d", p->pid);
        snprintf(thr_buf, sizeof(thr_buf), "%d", p->threads);
        snprintf(rt_buf,  sizeof(rt_buf),  "%d", p->fifo_threads);

        /* process name left-aligned (truncate if needed) */
        SetTextColor(hdc, COLOR_FG);
        snprintf(line, sizeof(line), "  %.32s", p->name);
        TextOutA(hdc, x, *row_y, line, (int)strlen(line));

        /* right-align each numeric column */
        #define RPAINT(buf_, edge_, color_) do {                                \
            int blen = (int)strlen(buf_);                                       \
            if (GetTextExtentPoint32A(hdc, buf_, blen, &sz)) {                  \
                SetTextColor(hdc, color_);                                      \
                TextOutA(hdc, (edge_) - sz.cx, *row_y, buf_, blen);             \
            }                                                                   \
        } while (0)

        RPAINT(pid_buf,  x_pid_r,  COLOR_FG);
        RPAINT(rss_buf,  x_rss_r,  COLOR_FG);
        RPAINT(lck_buf,  x_lck_r,  lck_col);
        RPAINT(huge_buf, x_huge_r, huge_col);
        RPAINT(thr_buf,  x_thr_r,  COLOR_FG);
        RPAINT(rt_buf,   x_rt_r,   COLOR_FG);

        #undef RPAINT
        *row_y += row_h;
    }
}

/* NSPA system info page (mode 6).  Two-column layout that fills the
 * available rect.  Reads /proc + /sys + sysfs via Wine's Z: drive on
 * each tick.  Sections are suppressed silently when their source file
 * is unreadable. */
static void paint_info_panel(HDC hdc, int x, int y, int w, int h)
{
    char buf[16384], buf2[1024];
    int col_w = w / 2;
    int col1_x = x;
    int col2_x = x + col_w + 16;
    int row_h, font_h;
    HFONT panel_font, old_font;
    int row_y, max_y;

    /* Scale text to ~1/28 of panel height, clamped to a legible band. */
    row_h = h / 28;
    if (row_h < 20) row_h = 20;
    if (row_h > 32) row_h = 32;
    font_h = row_h - 4;

    panel_font = CreateFontA(font_h, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                             CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FF_DONTCARE, "Tahoma");
    old_font = (HFONT)SelectObject(hdc, panel_font);

    /* ===== Column 1: Wine / Kernel / ntsync.ko / RT env ===== */
    row_y = y;

    info_section(hdc, col1_x, &row_y, row_h, "Wine");
    {
        typedef const char * (CDECL *pfn_str)(void);
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        pfn_str pf_ver = (pfn_str)GetProcAddress(ntdll, "wine_get_version");
        pfn_str pf_bid = (pfn_str)GetProcAddress(ntdll, "wine_get_build_id");
        info_kv(hdc, col1_x, &row_y, row_h,
                "  version   : %s", pf_ver ? pf_ver() : "(not Wine)");
        if (pf_bid) {
            const char *bid = pf_bid();
            if (bid && *bid)
                info_kv(hdc, col1_x, &row_y, row_h, "  build id  : %s", bid);
        }
    }
    row_y += 6;

    info_section(hdc, col1_x, &row_y, row_h, "Kernel");
    if (read_host_file("/proc/sys/kernel/osrelease", buf, sizeof(buf)) > 0)
    {
        char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
        info_kv(hdc, col1_x, &row_y, row_h, "  release   : %s", buf);
    }
    if (read_host_file("/sys/devices/system/cpu/online", buf, sizeof(buf)) > 0)
    {
        char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
        info_kv(hdc, col1_x, &row_y, row_h, "  cpus      : %ld online (%s)",
                count_online_cpus(buf), buf);
    }
    if (read_host_file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
                       buf, sizeof(buf)) > 0)
    {
        char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
        info_kv(hdc, col1_x, &row_y, row_h, "  governor  : %s (cpu0)", buf);
    }
    row_y += 6;

    info_section(hdc, col1_x, &row_y, row_h, "ntsync.ko");
    if (read_host_file("/sys/module/ntsync/srcversion", buf, sizeof(buf)) > 0)
    {
        char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
        info_kv(hdc, col1_x, &row_y, row_h, "  status    : loaded");
        info_kv(hdc, col1_x, &row_y, row_h, "  srcversion: %s", buf);
        if (read_host_file("/sys/module/ntsync/refcnt", buf2, sizeof(buf2)) > 0)
        {
            char *n2 = strchr(buf2, '\n'); if (n2) *n2 = 0;
            info_kv(hdc, col1_x, &row_y, row_h, "  refcnt    : %s", buf2);
        }
    }
    else
        info_kv(hdc, col1_x, &row_y, row_h, "  status    : not loaded");
    row_y += 6;

    info_section(hdc, col1_x, &row_y, row_h, "RT environment");
    {
        DWORD len;
        len = GetEnvironmentVariableA("NSPA_RT_PRIO",   buf, sizeof(buf));
        info_kv(hdc, col1_x, &row_y, row_h, "  NSPA_RT_PRIO   : %s",
                len ? buf : "(unset, vanilla mode)");
        len = GetEnvironmentVariableA("NSPA_RT_POLICY", buf, sizeof(buf));
        info_kv(hdc, col1_x, &row_y, row_h, "  NSPA_RT_POLICY : %s",
                len ? buf : "(default FF)");
        if (read_host_file("/proc/sys/kernel/sched_rt_runtime_us", buf, sizeof(buf)) > 0)
        {
            char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
            info_kv(hdc, col1_x, &row_y, row_h, "  sched_rt_runtime: %s us", buf);
        }
    }
    max_y = row_y;

    /* ===== Column 2: memory / hugepages / load ===== */
    row_y = y;

    if (read_host_file("/proc/meminfo", buf, sizeof(buf)) > 0)
    {
        long mt = find_proc_long(buf, "MemTotal");
        long ma = find_proc_long(buf, "MemAvailable");
        long mf = find_proc_long(buf, "MemFree");
        long ht = find_proc_long(buf, "HugePages_Total");
        long hf = find_proc_long(buf, "HugePages_Free");
        long hr = find_proc_long(buf, "HugePages_Rsvd");
        long hs = find_proc_long(buf, "Hugepagesize");

        info_section(hdc, col2_x, &row_y, row_h, "Memory");
        if (mt >= 0)
            info_kv(hdc, col2_x, &row_y, row_h,
                    "  total %ld MB   avail %ld MB   free %ld MB",
                    mt / 1024, ma / 1024, mf / 1024);
        row_y += 6;

        /* Explicit MAP_HUGETLB pool.  THP / anon-HP rows are omitted —
         * PREEMPT_RT kernels disable THP, so those numbers are always 0. */
        info_section(hdc, col2_x, &row_y, row_h, "Hugepages (2 MB pool)");
        if (ht >= 0)
        {
            info_kv(hdc, col2_x, &row_y, row_h,
                    "  pool      : %ld total, %ld free, %ld rsvd",
                    ht, hf, hr >= 0 ? hr : 0);
            info_kv(hdc, col2_x, &row_y, row_h,
                    "  page size : %ld KB   used : %ld",
                    hs >= 0 ? hs : 2048, ht - hf);
        }
        row_y += 6;
    }

    info_section(hdc, col2_x, &row_y, row_h, "System load");
    if (read_host_file("/proc/loadavg", buf, sizeof(buf)) > 0)
    {
        float la1, la5, la15;
        int run, total;
        if (sscanf(buf, "%f %f %f %d/%d", &la1, &la5, &la15, &run, &total) >= 5)
        {
            info_kv(hdc, col2_x, &row_y, row_h,
                    "  loadavg : %.2f %.2f %.2f", la1, la5, la15);
            info_kv(hdc, col2_x, &row_y, row_h,
                    "  procs   : %d running / %d total", run, total);
        }
    }

    if (row_y > max_y) max_y = row_y;
    max_y += 6;

    /* ===== Full-width: Wine processes table ===== */
    paint_wine_processes(hdc, col1_x, &max_y, row_h, w);

    SelectObject(hdc, old_font);
    DeleteObject(panel_font);
}

static void paint_window(HWND hwnd, HDC hdc, RECT *rc)
{
    HBRUSH bg = CreateSolidBrush(COLOR_BG);
    FillRect(hdc, rc, bg);
    DeleteObject(bg);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, COLOR_ACCENT);

    HFONT title_font = CreateFontA(18, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                   FF_DONTCARE, "Sans Serif");
    HFONT body_font  = CreateFontA(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                   OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                   FF_DONTCARE, "Sans Serif");

    SelectObject(hdc, title_font);
    char title[256];
    snprintf(title, sizeof(title), "nspa_rt_monitor — %s", mode_names[active_mode]);
    TextOutA(hdc, 12, 8, title, (int)strlen(title));

    SelectObject(hdc, body_font);
    SetTextColor(hdc, COLOR_DIM);
    TextOutA(hdc, 12, 30, mode_desc[active_mode], (int)strlen(mode_desc[active_mode]));

    /* Layout: scale content to the actual client rect.  Top: title +
     * desc (fixed 60 px).  Bottom: stats line (44 px above bottom).
     * Middle is the chart.  No bottom mode list — title already shows
     * active mode and arrow-key nav switches between them. */
    int win_w = rc->right - rc->left;
    int win_h = rc->bottom - rc->top;
    if (win_w < 320) win_w = 320;
    if (win_h < 240) win_h = 240;
    int header_h = 60;
    int axis_label_h = 18;
    int stats_h = 44;
    int hist_x = 12, hist_y = header_h, hist_w = win_w - 24;
    int hist_h = win_h - header_h - axis_label_h - stats_h - 12;
    if (hist_h < 60) hist_h = 60;
    int hist_bottom = hist_y + hist_h;
    int stats_y = hist_bottom + axis_label_h;

    /* Mode 6: NSPA system info — info panel fills the entire body
     * region (no histogram / stats line). */
    if (active_mode == 5)
    {
        int info_h = win_h - header_h - 24;
        if (info_h < 60) info_h = 60;
        paint_info_panel(hdc, hist_x, hist_y, hist_w, info_h);
        /* fall through to nav hint paint, then return */
    }

    /* Top-right nav hint + page indicator (replaces old bottom mode
     * list, which was dead space). */
    {
        char nav[96];
        SIZE sz;
        snprintf(nav, sizeof(nav),
                 "<- / -> switch  R reset  ESC quit       page %d/%d",
                 active_mode + 1, MODE_COUNT);
        SelectObject(hdc, body_font);
        SetTextColor(hdc, COLOR_DIM);
        if (GetTextExtentPoint32A(hdc, nav, (int)strlen(nav), &sz))
            TextOutA(hdc, win_w - sz.cx - 12, 12, nav, (int)strlen(nav));
    }

    /* Mode 6 has no chart / stats line — info panel painted above.  Done. */
    if (active_mode == 5)
    {
        DeleteObject(title_font);
        DeleteObject(body_font);
        return;
    }

    /* Auto-scaled log Y axis.  Y_LOG_MAX = log10(max) + 1.0 — exactly
     * one decade of headroom above the recent max, smooth (no integer
     * decade snapping) so the chart top tracks the data instead of
     * jumping at decade boundaries.  Worst sample lands ~67% up the
     * chart with 10x spike tolerance above.  Floor clamps at 100 us so
     * the lower band stays legible when nothing has spiked yet. */
    struct stats stats_for_scale;
    compute_stats(active_mode, &stats_for_scale);
    static const double Y_LOG_MIN = 0.0;   /* log10(1 us) */
    double Y_LOG_MAX;
    {
        double lmax = stats_for_scale.max > 0
                      ? log10((double)stats_for_scale.max) : 0.0;
        Y_LOG_MAX = lmax + 1.0;
        if (Y_LOG_MAX < 2.0) Y_LOG_MAX = 2.0;  /* floor: show 0..100 us */
        if (Y_LOG_MAX > 7.0) Y_LOG_MAX = 7.0;  /* cap:   10 s */
    }
    #define Y_FOR_US(us)  ((us) < 1 ? hist_bottom :                                    \
                           (hist_bottom - (int)((double)hist_h *                        \
                            (log10((double)(us)) - Y_LOG_MIN) /                         \
                            (Y_LOG_MAX - Y_LOG_MIN))))

    /* Threshold guides — only decade marks inside the current Y range
     * are drawn; extra half-decade ticks (3, 30, 300 us etc.) appear as
     * faint unlabelled grid lines so the eye can interpolate inside a
     * decade. */
    {
        const struct { int us; COLORREF c; const char *label; int show_label; } guides[] = {
            { 1,       COLOR_GRID,   "   1 us",  1 },
            { 3,       COLOR_GRID,   "",         0 },
            { 10,      COLOR_GRID,   "  10 us",  1 },
            { 30,      COLOR_GRID,   "",         0 },
            { 100,     COLOR_GREEN,  " 100 us",  1 },
            { 300,     COLOR_GRID,   "",         0 },
            { 1000,    COLOR_YELLOW, "   1 ms",  1 },
            { 3000,    COLOR_GRID,   "",         0 },
            { 10000,   COLOR_RED,    "  10 ms",  1 },
            { 30000,   COLOR_GRID,   "",         0 },
            { 100000,  COLOR_RED,    " 100 ms",  1 },
            { 300000,  COLOR_GRID,   "",         0 },
            { 1000000, COLOR_RED,    "   1 s",   1 },
        };
        for (size_t i = 0; i < sizeof(guides)/sizeof(guides[0]); i++)
        {
            int y;
            HPEN line, old;
            COLORREF line_col;
            if (log10((double)guides[i].us) > Y_LOG_MAX + 0.01) continue;
            y = Y_FOR_US(guides[i].us);
            line_col = guides[i].show_label ? guides[i].c : COLOR_GRID;
            line = CreatePen(PS_SOLID, 1, line_col);
            old  = (HPEN)SelectObject(hdc, line);
            MoveToEx(hdc, hist_x + 60, y, NULL);
            LineTo(hdc, hist_x + hist_w, y);
            SelectObject(hdc, old);
            DeleteObject(line);

            if (guides[i].show_label)
            {
                SetTextColor(hdc, guides[i].c);
                TextOutA(hdc, hist_x + 4, y - 7, guides[i].label,
                         (int)strlen(guides[i].label));
            }
        }
    }

    /* High-resolution stripchart: each pixel column is a 1-px-wide
     * vertical line spanning min..max of the samples that map to that
     * column.  Threshold-coloured by the column's max so outliers
     * stand out without losing the floor.  Replaces the 30-bucket bar
     * chart — bars showed only max-per-second, which made every test
     * look equally bad even when typical was fine. */
    {
        struct mode_state *m = &modes[active_mode];
        static LONGLONG snap[HIST_CAPACITY];
        static LONGLONG ordered[HIST_CAPACITY];
        int n, pos;
        int chart_x = hist_x + 60;
        int chart_w = hist_w - 60;

        EnterCriticalSection(&m->lock);
        n = m->sample_count;
        pos = m->sample_pos;
        memcpy(snap, m->samples, sizeof(LONGLONG) * (n < HIST_CAPACITY ? n : HIST_CAPACITY));
        LeaveCriticalSection(&m->lock);

        if (n > 0 && chart_w > 1)
        {
            int col, i;
            /* Pre-create the 3 threshold pens once per repaint instead
             * of per-column.  CreatePen + DeleteObject in a hot loop
             * was the slow path; selecting a pre-created pen via
             * SelectObject is a single state change. */
            HPEN pen_green  = CreatePen(PS_SOLID, 1, COLOR_GREEN);
            HPEN pen_yellow = CreatePen(PS_SOLID, 1, COLOR_YELLOW);
            HPEN pen_red    = CreatePen(PS_SOLID, 1, COLOR_RED);
            HPEN current = NULL;
            HPEN old_pen = NULL;

            /* Linearise the ring into chronological order. */
            if (n < HIST_CAPACITY)
                memcpy(ordered, snap, sizeof(LONGLONG) * n);
            else
                for (i = 0; i < HIST_CAPACITY; i++)
                    ordered[i] = snap[(pos + i) % HIST_CAPACITY];

            for (col = 0; col < chart_w; col++)
            {
                int s0 = (int)((LONGLONG)col       * n / chart_w);
                int s1 = (int)((LONGLONG)(col + 1) * n / chart_w);
                LONGLONG smin, smax;
                int y_max_px, x;
                HPEN want;
                if (s1 <= s0) continue;
                smin = smax = ordered[s0];
                for (i = s0 + 1; i < s1; i++)
                {
                    if (ordered[i] < smin) smin = ordered[i];
                    if (ordered[i] > smax) smax = ordered[i];
                }
                (void)smin;
                want = (smax < 100)  ? pen_green
                     : (smax < 1000) ? pen_yellow
                                     : pen_red;
                if (want != current)
                {
                    if (current == NULL) old_pen = (HPEN)SelectObject(hdc, want);
                    else                 SelectObject(hdc, want);
                    current = want;
                }
                y_max_px = Y_FOR_US(smax);
                x = chart_x + col;
                MoveToEx(hdc, x, y_max_px, NULL);
                LineTo(hdc, x, hist_bottom);
            }
            if (old_pen) SelectObject(hdc, old_pen);
            DeleteObject(pen_green);
            DeleteObject(pen_yellow);
            DeleteObject(pen_red);
        }

        /* x-axis baseline + axis labels */
        {
            HPEN axis = CreatePen(PS_SOLID, 1, COLOR_DIM);
            HPEN old  = (HPEN)SelectObject(hdc, axis);
            MoveToEx(hdc, chart_x, hist_bottom, NULL);
            LineTo(hdc, chart_x + chart_w, hist_bottom);
            SelectObject(hdc, old);
            DeleteObject(axis);
        }
        SetTextColor(hdc, COLOR_DIM);
        TextOutA(hdc, chart_x, hist_bottom + 4, "older", 5);
        TextOutA(hdc, chart_x + chart_w - 22, hist_bottom + 4, "newer", 5);
    }

    /* stats panel — reuse the scale-pass stats so we compute_stats once */
    {
        struct stats s = stats_for_scale;
        char l1[128], l2[128];

        char b_last[32], b_min[32], b_max[32], b_p50[32], b_p99[32], b_p999[32];
        format_us(b_last, sizeof(b_last), s.last);
        format_us(b_min,  sizeof(b_min),  s.min);
        format_us(b_max,  sizeof(b_max),  s.max);
        format_us(b_p50,  sizeof(b_p50),  s.p50);
        format_us(b_p99,  sizeof(b_p99),  s.p99);
        format_us(b_p999, sizeof(b_p999), s.p999);

        SetTextColor(hdc, COLOR_FG);
        snprintf(l1, sizeof(l1), "current: %-12s  min: %-12s  max: %-12s",
                 b_last, b_min, b_max);
        snprintf(l2, sizeof(l2), "p50: %-12s  p99: %-12s  p99.9: %-12s   (n=%d)",
                 b_p50, b_p99, b_p999, s.count);
        TextOutA(hdc, 12, stats_y,      l1, (int)strlen(l1));
        TextOutA(hdc, 12, stats_y + 20, l2, (int)strlen(l2));
    }

    DeleteObject(title_font);
    DeleteObject(body_font);
}

/* ---------- 1Hz tick thread ---------- */

static volatile LONG tick_running;

static DWORD WINAPI tick_thread(LPVOID arg)
{
    HWND hwnd = (HWND)arg;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000000LL;  /* -1s relative, NT 100ns units */

    while (tick_running)
    {
        NtDelayExecution(FALSE, &timeout);
        if (!tick_running) break;
        PostMessageW(hwnd, WM_NSPA_TICK, 0, 0);
    }
    return 0;
}

/* ---------- window procedure ---------- */

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
        mode_start(active_mode);
        tick_running = 1;
        CreateThread(NULL, 0, tick_thread, hwnd, 0, NULL);
        return 0;

    case WM_NSPA_TICK:
        /* Roll only the active mode's buckets.  Inactive modes freeze
         * in place; switching back resumes from where the histogram
         * left off — no time-axis gap from the period the user spent
         * in other modes.  The histogram time-scale is "seconds since
         * this mode last sampled" rather than wall-clock, which is
         * what the user actually wants for comparing modes. */
        roll_bucket(active_mode);
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;

    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        HDC      mem_dc;
        HBITMAP  mem_bmp;
        HBITMAP  old_bmp;
        int      w, h;

        GetClientRect(hwnd, &rc);
        w = rc.right - rc.left;
        h = rc.bottom - rc.top;

        /* Double-buffer: render to off-screen bitmap, BitBlt in one op.
         * Eliminates the flicker / "redraws from right" artifact a
         * single-buffer FillRect-then-redraw produces. */
        mem_dc  = CreateCompatibleDC(hdc);
        mem_bmp = CreateCompatibleBitmap(hdc, w, h);
        old_bmp = (HBITMAP)SelectObject(mem_dc, mem_bmp);

        paint_window(hwnd, mem_dc, &rc);
        BitBlt(hdc, 0, 0, w, h, mem_dc, 0, 0, SRCCOPY);

        SelectObject(mem_dc, old_bmp);
        DeleteObject(mem_bmp);
        DeleteDC(mem_dc);
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_KEYDOWN:
        if (wp == VK_ESCAPE) { PostMessageW(hwnd, WM_CLOSE, 0, 0); return 0; }
        if (wp == 'R' || wp == 'r') { mode_reset(active_mode); InvalidateRect(hwnd, NULL, FALSE); return 0; }
        if (wp == VK_LEFT || wp == VK_RIGHT)
        {
            int next = wp == VK_RIGHT
                       ? (active_mode + 1) % MODE_COUNT
                       : (active_mode + MODE_COUNT - 1) % MODE_COUNT;
            mode_stop(active_mode);
            active_mode = next;
            mode_start(active_mode);
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        if (wp >= '1' && wp < '1' + MODE_COUNT)
        {
            int next = (int)(wp - '1');
            if (next != active_mode)
            {
                mode_stop(active_mode);
                active_mode = next;
                mode_start(active_mode);
                InvalidateRect(hwnd, NULL, FALSE);
            }
            return 0;
        }
        return 0;

    case WM_ERASEBKGND:
        return 1;  /* we draw the bg in WM_PAINT, skip default erase */

    case WM_DESTROY:
        tick_running = 0;
        for (int i = 0; i < MODE_COUNT; i++) mode_stop(i);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI WinMain(HINSTANCE hi, HINSTANCE prev, LPSTR cmd, int show)
{
    /* Bump process priority class to REALTIME so worker threads calling
     * SetThreadPriority(THREAD_PRIORITY_TIME_CRITICAL) actually get NT
     * priority 31 (which NSPA maps to FF 80 per the banner) rather than
     * NT 15 under NORMAL_PRIORITY_CLASS — which would map to ~FF 60-65,
     * below wineserver's FF 64.  Without this, the workers run at lower
     * priority than wineserver and get starved on a busy system,
     * dilating measured latencies.  Same priority class real audio
     * threads use under NSPA_RT_PRIO. */
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);

    QueryPerformanceFrequency(&qpc_freq);
    qpc_to_us = 1000000.0 / (double)qpc_freq.QuadPart;

    for (int i = 0; i < MODE_COUNT; i++)
        InitializeCriticalSection(&modes[i].lock);

    WNDCLASSEXW wc = { sizeof(wc) };
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hi;
    wc.hCursor       = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = NULL;
    wc.lpszClassName = L"NspaRtMonitor";
    if (!RegisterClassExW(&wc)) return 1;

    RECT rc = { 0, 0, WIN_W, WIN_H };
    AdjustWindowRect(&rc, WS_OVERLAPPEDWINDOW, FALSE);

    HWND hwnd = CreateWindowExW(0, L"NspaRtMonitor", L"nspa_rt_monitor",
                                WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT,
                                rc.right - rc.left, rc.bottom - rc.top,
                                NULL, NULL, hi, NULL);
    if (!hwnd) return 1;

    ShowWindow(hwnd, show);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    for (int i = 0; i < MODE_COUNT; i++) DeleteCriticalSection(&modes[i].lock);
    return (int)msg.wParam;
}
