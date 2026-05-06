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

/* ---------- constants ---------- */

#define WIN_W                720
#define WIN_H                480
#define BUCKET_SECONDS       30
#define HIST_CAPACITY        4096
#define MODE_COUNT           5
#define TARGET_PERIOD_US     1000
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
    "3: NT timer periodic",
    "4: CS-PI contention",
    "5: KDPC dispatcher"
};
static const char * const mode_desc[MODE_COUNT] = {
    "RT thread wakeup-from-deadline jitter (1ms relative timeout)",
    "Cross-thread event signal/wait via inproc-sync (anonymous event)",
    "NtCreateTimer + NtSetTimer 1ms periodic (NSPA local_timer -> RT sched)",
    "High-prio thread acquires CS held by low-prio (CS-PI boost path)",
    "KeSetTimerEx + KeInitializeDpc through Wine ntoskrnl dpc.c"
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

/* ---------- mode 3: NT timer periodic ---------- */

static DWORD WINAPI mode3_worker(LPVOID arg)
{
    int idx = (int)(LONG_PTR)arg;
    HANDLE timer;
    LARGE_INTEGER first;
    NTSTATUS s;

    if ((s = NtCreateTimer(&timer, TIMER_ALL_ACCESS, NULL, SynchronizationTimer)))
        return 0;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

    first.QuadPart = -(LONGLONG)TARGET_PERIOD_US * 10;
    NtSetTimer(timer, &first, NULL, NULL, FALSE, TARGET_PERIOD_US / 1000, NULL);

    LONGLONG expected = qpc() + (LONGLONG)((double)TARGET_PERIOD_US / qpc_to_us);
    LONGLONG period_ticks = (LONGLONG)((double)TARGET_PERIOD_US / qpc_to_us);

    while (modes[idx].running)
    {
        DWORD r = WaitForSingleObject(timer, 200);
        if (r != WAIT_OBJECT_0) continue;
        LONGLONG now = qpc();
        LONGLONG late_us = (LONGLONG)ticks_to_us(now - expected);
        push_sample(idx, late_us);
        expected += period_ticks;
        /* if we fall way behind (debugger pause etc.), resync */
        if (now - expected > period_ticks * 100) expected = now + period_ticks;
    }

    NtCancelTimer(timer, NULL);
    CloseHandle(timer);
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

/* ---------- mode 5: KDPC dispatcher ---------- */

static volatile LONGLONG m5_expected;
static int               m5_idx;
static LONGLONG           m5_period_ticks;

static void WINAPI m5_deferred(KDPC *dpc, void *ctx, void *arg1, void *arg2)
{
    LONGLONG now = qpc();
    LONGLONG late_us = (LONGLONG)ticks_to_us(now - m5_expected);
    push_sample(m5_idx, late_us);
    m5_expected += m5_period_ticks;
    if (now - m5_expected > m5_period_ticks * 100)
        m5_expected = now + m5_period_ticks;
}

static DWORD WINAPI mode5_worker(LPVOID arg)
{
    int idx = (int)(LONG_PTR)arg;
    static KDPC dpc;
    static KTIMER timer;
    LARGE_INTEGER duetime;

    m5_idx          = idx;
    m5_period_ticks = (LONGLONG)((double)TARGET_PERIOD_US / qpc_to_us);
    m5_expected     = qpc() + m5_period_ticks;

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

/* ---------- mode lifecycle ---------- */

typedef DWORD (WINAPI *worker_fn)(LPVOID);
static const worker_fn workers[MODE_COUNT] = {
    mode1_worker, mode2_worker, mode3_worker, mode4_worker, mode5_worker
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

    /* histogram region — log Y scale spans 1us .. 16ms.  Linear 0-16ms
     * squishes the realistic sub-ms range into the bottom 3% of the
     * graph, which is why the previous scale looked empty under healthy
     * RT load.  Log scale: 1us at 0%, 10us at 24%, 100us at 48%,
     * 1ms at 71%, 10ms at 95%. */
    int hist_x = 12, hist_y = 80, hist_w = WIN_W - 24, hist_h = 220;
    int hist_bottom = hist_y + hist_h;
    static const double Y_LOG_MIN = 0.0;   /* log10(1 us)  */
    static const double Y_LOG_MAX = 4.2;   /* log10(16000 us) */
    #define Y_FOR_US(us)  ((us) < 1 ? hist_bottom :                                    \
                           (hist_bottom - (int)((double)hist_h *                        \
                            (log10((double)(us)) - Y_LOG_MIN) /                         \
                            (Y_LOG_MAX - Y_LOG_MIN))))

    /* threshold guides */
    {
        const struct { int us; COLORREF c; const char *label; } guides[] = {
            { 100,   COLOR_GRID,   "  100 us" },
            { 500,   COLOR_GREEN,  "  500 us" },
            { 1000,  COLOR_GRID,   "  1 ms" },
            { 2000,  COLOR_YELLOW, "  2 ms" },
            { 8000,  COLOR_RED,    "  8 ms" },
            { 16000, COLOR_RED,    " 16 ms" },
        };
        for (int i = 0; i < 6; i++)
        {
            int y = Y_FOR_US(guides[i].us);
            HPEN line = CreatePen(PS_SOLID, 1, guides[i].c);
            HPEN old  = (HPEN)SelectObject(hdc, line);
            MoveToEx(hdc, hist_x + 60, y, NULL);
            LineTo(hdc, hist_x + hist_w, y);
            SelectObject(hdc, old);
            DeleteObject(line);

            SetTextColor(hdc, guides[i].c);
            TextOutA(hdc, hist_x + 4, y - 7, guides[i].label, (int)strlen(guides[i].label));
        }
    }

    /* histogram bars */
    {
        struct mode_state *m = &modes[active_mode];
        LONGLONG snap[BUCKET_SECONDS];
        int pos;
        int bar_w, bx0;

        EnterCriticalSection(&m->lock);
        pos = m->bucket_pos;
        /* bucket_pos is the next-write index in the ring.  Buckets
         * [pos, pos+1, ..., pos+29] (mod 30) are oldest..newest
         * completed, i.e. the rightmost bar = newest completed
         * (frozen for this display second). */
        for (int i = 0; i < BUCKET_SECONDS; i++)
            snap[i] = m->bucket_max[(pos + i) % BUCKET_SECONDS];
        LeaveCriticalSection(&m->lock);

        bar_w = (hist_w - 60) / BUCKET_SECONDS;
        bx0 = hist_x + 60;
        for (int i = 0; i < BUCKET_SECONDS; i++)
        {
            LONGLONG v = snap[i];
            int top, h;
            HBRUSH br;
            RECT r;
            if (v <= 0) continue;
            top = Y_FOR_US(v);
            h = hist_bottom - top;
            if (h < 2) h = 2;
            if (h > hist_h) h = hist_h;
            br = CreateSolidBrush(threshold_color(v));
            r.left   = bx0 + i * bar_w + 1;
            r.top    = hist_bottom - h;
            r.right  = bx0 + (i + 1) * bar_w - 1;
            r.bottom = hist_bottom;
            FillRect(hdc, &r, br);
            DeleteObject(br);
        }

        /* x-axis baseline */
        HPEN axis = CreatePen(PS_SOLID, 1, COLOR_DIM);
        HPEN old  = (HPEN)SelectObject(hdc, axis);
        MoveToEx(hdc, bx0, hist_bottom, NULL);
        LineTo(hdc, bx0 + BUCKET_SECONDS * bar_w, hist_bottom);
        SelectObject(hdc, old);
        DeleteObject(axis);

        SetTextColor(hdc, COLOR_DIM);
        TextOutA(hdc, bx0, hist_bottom + 4, "-30s", 4);
        TextOutA(hdc, bx0 + BUCKET_SECONDS * bar_w - 16, hist_bottom + 4, "now", 3);
    }

    /* stats panel */
    {
        struct stats s;
        compute_stats(active_mode, &s);
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
        TextOutA(hdc, 12, 320, l1, (int)strlen(l1));
        TextOutA(hdc, 12, 340, l2, (int)strlen(l2));
    }

    /* mode menu */
    {
        SetTextColor(hdc, COLOR_DIM);
        TextOutA(hdc, 12, 376, "press 1..5 to switch mode, ESC to quit, R to reset stats", 56);
        for (int i = 0; i < MODE_COUNT; i++)
        {
            SetTextColor(hdc, i == active_mode ? COLOR_ACCENT : COLOR_DIM);
            TextOutA(hdc, 12, 400 + i * 16, mode_names[i], (int)strlen(mode_names[i]));
        }
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
