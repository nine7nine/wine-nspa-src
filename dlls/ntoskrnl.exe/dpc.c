/*
 * DPC dispatcher for ntoskrnl.exe
 *
 * Drivers schedule DeferredRoutines via KeInsertQueueDpc (immediate)
 * or KeSetTimerEx (timer-driven, possibly periodic).  Wine previously
 * backed timer-driven DPCs with CreateThreadpoolTimer, whose worker
 * dispatch latency on Wine quantises to one Windows tick (~15ms) even
 * when the underlying timer fires sub-ms; and KeInsertQueueDpc was a
 * FIXME stub that never queued anything.  Tools like DPCLatencyChecker
 * measured the ~15ms dispatch jitter as "DPC latency", producing
 * meaningless readings.
 *
 * This file replaces both paths with a dedicated per-process
 * dispatcher thread, sub-ms accurate via NtWaitForSingleObject on an
 * auto-reset event with a relative timeout (hrtimer on PREEMPT_RT).
 * Optionally SCHED_FIFO-promoted under NSPA_RT_PRIO.
 */

#include <stdarg.h>
#include <stdlib.h>

#include "ntoskrnl_private.h"
#include "ddk/ntddk.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntoskrnl);

struct dpc_entry
{
    struct list entry;      /* in dpc_queue (timer) or dpc_immediate */
    KTIMER *timer;          /* NULL => immediate (KeInsertQueueDpc) */
    KDPC *dpc;
    LONGLONG deadline;      /* NT 100ns, absolute (CLOCK_REALTIME/FILETIME epoch) */
    LONG period;            /* ms, 0 = one-shot */
};

DECLARE_CRITICAL_SECTION(dpc_cs);

static struct list dpc_queue = LIST_INIT(dpc_queue);     /* sorted by deadline */
static struct list dpc_immediate = LIST_INIT(dpc_immediate);
static HANDLE dpc_wake;
static HANDLE dpc_thread;
static INIT_ONCE dpc_init_once = INIT_ONCE_STATIC_INIT;

static LONGLONG dpc_now_nt(void)
{
    LARGE_INTEGER now;
    NtQuerySystemTime(&now);
    return now.QuadPart;
}

/* duetime semantics: negative = relative (100ns units from now),
 * positive = absolute NT FILETIME.  Convert to absolute. */
static LONGLONG duetime_to_absolute(LARGE_INTEGER duetime)
{
    if (duetime.QuadPart < 0)
        return dpc_now_nt() - duetime.QuadPart;
    return duetime.QuadPart;
}

static void dpc_queue_insert_sorted(struct dpc_entry *entry)
{
    struct dpc_entry *cur;
    LIST_FOR_EACH_ENTRY(cur, &dpc_queue, struct dpc_entry, entry)
    {
        if (cur->deadline > entry->deadline)
        {
            list_add_before(&cur->entry, &entry->entry);
            return;
        }
    }
    list_add_tail(&dpc_queue, &entry->entry);
}

/* DPCs run at IRQL > passive on Windows, i.e. the DeferredRoutine is
 * expected to execute at elevated priority relative to normal user-mode
 * threads.  Emulate that by always promoting the dispatcher to
 * THREAD_PRIORITY_TIME_CRITICAL.  NSPA's ntdll Unix-side priority mapper
 * turns this into SCHED_FIFO at the appropriate band when NSPA_RT_PRIO /
 * NSPA_RT_POLICY are set; on stock Wine it still bumps the thread to
 * the highest SCHED_OTHER nice.  Either way the dispatcher gets
 * scheduling precedence over normal user-mode work. */
static void dpc_thread_promote(void)
{
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
}

static DWORD WINAPI dpc_dispatch_thread(void *arg)
{
    dpc_thread_promote();

    for (;;)
    {
        struct list batch = LIST_INIT(batch);
        struct dpc_entry *entry, *next;
        LONGLONG now;
        LARGE_INTEGER timeout;
        BOOL have_timeout = FALSE;

        EnterCriticalSection(&dpc_cs);
        now = dpc_now_nt();

        /* Drain immediate queue */
        LIST_FOR_EACH_ENTRY_SAFE(entry, next, &dpc_immediate, struct dpc_entry, entry)
        {
            list_remove(&entry->entry);
            list_add_tail(&batch, &entry->entry);
        }

        /* Pop every timer entry whose deadline has passed */
        LIST_FOR_EACH_ENTRY_SAFE(entry, next, &dpc_queue, struct dpc_entry, entry)
        {
            if (entry->deadline > now) break;
            list_remove(&entry->entry);
            list_add_tail(&batch, &entry->entry);
        }

        /* Compute next wake */
        if (!list_empty(&dpc_queue))
        {
            entry = LIST_ENTRY(list_head(&dpc_queue), struct dpc_entry, entry);
            /* NtWaitForSingleObject relative timeout: negative 100ns */
            timeout.QuadPart = -(entry->deadline - now);
            if (timeout.QuadPart > 0) timeout.QuadPart = 0;   /* already due: spin-check */
            have_timeout = TRUE;
        }
        LeaveCriticalSection(&dpc_cs);

        /* Fire DPCs outside the lock so a DeferredRoutine that calls
         * KeSetTimer / KeInsertQueueDpc / KeCancelTimer doesn't deadlock. */
        LIST_FOR_EACH_ENTRY_SAFE(entry, next, &batch, struct dpc_entry, entry)
        {
            KDPC *dpc = entry->dpc;
            KTIMER *timer = entry->timer;
            LONG period = entry->period;

            list_remove(&entry->entry);

            if (dpc && dpc->DeferredRoutine)
                dpc->DeferredRoutine(dpc, dpc->DeferredContext,
                                     dpc->SystemArgument1, dpc->SystemArgument2);

            /* Signal the timer + wake waiters after the DPC runs.
             * Matches Windows: waiters only see the timer satisfied
             * after any associated DPC has executed. */
            if (timer)
                sync_timer_signal(timer);

            if (period && timer)
            {
                /* Periodic timer: advance deadline and re-insert.
                 * Use the absolute deadline we just fired at so drift
                 * does not accumulate across periods. */
                entry->deadline += (LONGLONG)period * 10000;
                /* If we're way behind (paused debugger, etc.) fast-
                 * forward to the current time + one period so we don't
                 * burst-fire N back-to-back catch-up DPCs. */
                {
                    LONGLONG now2 = dpc_now_nt();
                    if (entry->deadline < now2)
                        entry->deadline = now2 + (LONGLONG)period * 10000;
                }
                EnterCriticalSection(&dpc_cs);
                dpc_queue_insert_sorted(entry);
                LeaveCriticalSection(&dpc_cs);
            }
            else
            {
                if (timer)
                    sync_timer_clear_inserted(timer);
                free(entry);
            }
        }

        /* NSPA fix: recompute the wait timeout AFTER the fire batch.
         * The original `have_timeout` / `timeout` were computed from
         * the queue head BEFORE firing.  If the queue became empty
         * during the pop loop (the only entry was a periodic one we
         * just popped to fire), the pre-fire computation set
         * have_timeout = FALSE → infinite wait — but we just re-
         * inserted the periodic entry above, so the wait would block
         * forever waiting on dpc_wake (which periodic re-insert does
         * not signal).  This was the cause of mode 5's "n=2 in 30s"
         * regression in nspa_rt_monitor.  Recomputing here picks up
         * the re-inserted entries and waits the right amount. */
        EnterCriticalSection(&dpc_cs);
        have_timeout = FALSE;
        if (!list_empty(&dpc_queue))
        {
            LONGLONG now2 = dpc_now_nt();
            entry = LIST_ENTRY(list_head(&dpc_queue), struct dpc_entry, entry);
            timeout.QuadPart = -(entry->deadline - now2);
            if (timeout.QuadPart > 0) timeout.QuadPart = 0;
            have_timeout = TRUE;
        }
        LeaveCriticalSection(&dpc_cs);

        NtWaitForSingleObject(dpc_wake, FALSE, have_timeout ? &timeout : NULL);
    }
    return 0;
}

static BOOL WINAPI dpc_init(INIT_ONCE *once, void *param, void **ctx)
{
    dpc_wake = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!dpc_wake)
    {
        ERR("Could not create DPC wake event.\n");
        return FALSE;
    }
    dpc_thread = CreateThread(NULL, 0, dpc_dispatch_thread, NULL, 0, NULL);
    if (!dpc_thread)
    {
        ERR("Could not create DPC dispatcher thread.\n");
        CloseHandle(dpc_wake);
        dpc_wake = NULL;
        return FALSE;
    }
    return TRUE;
}

static void dpc_ensure_initialised(void)
{
    InitOnceExecuteOnce(&dpc_init_once, dpc_init, NULL, NULL);
}

/* Cancel any pending queue entries for the given timer.  Does not wait
 * for an in-flight DeferredRoutine to finish (matches Windows KeCancelTimer). */
void dpc_cancel_timer(KTIMER *timer)
{
    struct dpc_entry *entry, *next;

    dpc_ensure_initialised();

    EnterCriticalSection(&dpc_cs);
    LIST_FOR_EACH_ENTRY_SAFE(entry, next, &dpc_queue, struct dpc_entry, entry)
    {
        if (entry->timer == timer)
        {
            list_remove(&entry->entry);
            free(entry);
        }
    }
    LeaveCriticalSection(&dpc_cs);
}

/* Arm a timer-driven DPC.  Replaces existing queue entry for the same
 * timer if any (matches Windows KeSetTimerEx re-arming semantics). */
void dpc_arm_timer(KTIMER *timer, LARGE_INTEGER duetime, LONG period, KDPC *dpc)
{
    struct dpc_entry *entry;

    dpc_ensure_initialised();

    entry = calloc(1, sizeof(*entry));
    if (!entry)
    {
        ERR("Out of memory arming DPC timer.\n");
        return;
    }
    entry->timer = timer;
    entry->dpc = dpc;
    entry->period = period;
    entry->deadline = duetime_to_absolute(duetime);

    EnterCriticalSection(&dpc_cs);
    /* Remove any previous entry for this timer */
    {
        struct dpc_entry *cur, *tmp;
        LIST_FOR_EACH_ENTRY_SAFE(cur, tmp, &dpc_queue, struct dpc_entry, entry)
        {
            if (cur->timer == timer)
            {
                list_remove(&cur->entry);
                free(cur);
            }
        }
    }
    dpc_queue_insert_sorted(entry);
    LeaveCriticalSection(&dpc_cs);

    NtSetEvent(dpc_wake, NULL);
}

/* Queue an immediate DPC (KeInsertQueueDpc).  Returns FALSE if a DPC
 * for this KDPC object is already queued (matches Windows). */
BOOL dpc_queue_immediate(KDPC *dpc, void *arg1, void *arg2)
{
    struct dpc_entry *entry;
    BOOL already_queued = FALSE;

    if (!dpc) return FALSE;
    dpc_ensure_initialised();

    EnterCriticalSection(&dpc_cs);
    {
        struct dpc_entry *cur;
        LIST_FOR_EACH_ENTRY(cur, &dpc_immediate, struct dpc_entry, entry)
        {
            if (cur->dpc == dpc) { already_queued = TRUE; break; }
        }
    }
    if (already_queued)
    {
        LeaveCriticalSection(&dpc_cs);
        return FALSE;
    }

    entry = calloc(1, sizeof(*entry));
    if (!entry)
    {
        LeaveCriticalSection(&dpc_cs);
        return FALSE;
    }
    dpc->SystemArgument1 = arg1;
    dpc->SystemArgument2 = arg2;
    entry->dpc = dpc;
    entry->timer = NULL;
    entry->deadline = 0;
    entry->period = 0;
    list_add_tail(&dpc_immediate, &entry->entry);
    LeaveCriticalSection(&dpc_cs);

    NtSetEvent(dpc_wake, NULL);
    return TRUE;
}
