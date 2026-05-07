/*
 * NSPA local NT timer dispatcher.
 *
 * Replaces the wineserver round-trip on NT timer expiry with an in-process
 * dispatcher thread.  Timer handles are backed by a server-allocated NTSync
 * event (via NtCreateEvent) so that all NT semantics -- wait, query state,
 * close, duplicate, mixed-wait via NtWaitFor{Single,Multiple}Objects -- are
 * preserved exactly as today.  Only the dispatch (the zero-RTT path) moves
 * local; the object lifecycle still sits on the server side.
 *
 * The intent, following the same pattern as the DPC dispatcher in
 * dlls/ntoskrnl.exe/dpc.c, is that the server knows about the backing event
 * but has no concept of "timer armed"; the client is the sole authority on
 * when the timer fires.  Expiry = NtSetEvent on the backing handle (fast
 * NTSync path, no RTT) + optional WM_TIMER post + optional APC queue.
 *
 * Scope of migration:
 *   - Anonymous NtCreateTimer: migrated.  Creation calls NtCreateEvent
 *     instead; an entry is registered in this module's local table.
 *   - Named timers (OBJECT_ATTRIBUTES->ObjectName set): not migrated; fall
 *     through to server as today.  We cannot migrate these without risking
 *     cross-process semantics.
 *   - Opened timers (NtOpenTimer by name): not migrated; the resulting
 *     handle is not in our table, so NtSetTimer falls through to server.
 *   - Cross-process NtDuplicateObject of a managed timer: rejected with
 *     STATUS_ACCESS_DENIED.  Matches timer audit §H.
 *
 * Local dispatch is always on; the env-gate retired 2026-05-04 after
 * confirming production never used the opt-out path.
 *
 * Clock semantics: the dispatcher's internal deadline, queue ordering, and
 * pi_cond_timedwait all run on CLOCK_MONOTONIC.  This is the RT-correct
 * choice: it matches elapsed-time semantics for NT's relative (negative)
 * `when` parameter (which is what short-term pollers and audio timers use
 * exclusively), and it is immune to NTP slews/steps that would otherwise
 * skew a wait.  Same pattern as NtDelayExecution's clock split (commit
 * 43c300c4b22) and the in-tree feedback rule "pick the Linux primitive that
 * matches NT; split shared code paths per branch; never blind-swap".
 *
 * For NT absolute FILETIME (positive `when`), we snapshot the offset between
 * CLOCK_REALTIME and CLOCK_MONOTONIC once at insert time and convert the
 * deadline into the monotonic reference frame.  An NTP step that lands
 * between insert and fire shifts the wall-clock relationship but the
 * dispatcher still fires at the originally-intended wall moment modulo the
 * step size; for Wine-NSPA's audio/RT workload, which uses relative timers
 * almost exclusively, this is a correct outcome.
 *
 * Primitives: we use librtpi's pi_mutex_t / pi_cond_t rather than raw
 * pthread_mutex_t / pthread_cond_t so that a low-priority thread holding the
 * timer_lock (e.g. during NtSetTimer) boosts to the waiting dispatcher's
 * priority under PREEMPT_RT.  The backing event handle is a normal server-
 * allocated NTSync event, which already benefits from the NTSync PI kernel
 * patches (priority-ordered wait queue + mutex owner boost) for any waiter.
 *
 * Dispatcher priority: promoted to SCHED_FIFO at NSPA_RT_PRIO-1 on thread
 * start when NSPA_RT_PRIO is set.  Staying one band below the audio-callback
 * band keeps timer wakes sharp without ever preempting the RT audio thread.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"
#include "wine/list.h"
#include "../unix_private.h"
#include <rtpi.h>

WINE_DEFAULT_DEBUG_CHANNEL(timer);

/* NT FILETIME epoch (1601-01-01) to Unix epoch (1970-01-01), in 100ns units. */
#define NT_UNIX_EPOCH_DIFF_100NS   116444736000000000LL

/* Hash table for HANDLE -> local timer entry lookup. */
#define TIMER_TABLE_BUCKETS   64
#define TIMER_TABLE_MASK      (TIMER_TABLE_BUCKETS - 1)

struct nspa_local_timer
{
    struct list     table_entry;        /* in timer_table bucket */
    struct list     queue_entry;        /* in timer_queue (sorted by deadline) or detached */
    HANDLE          handle;             /* backing event handle (server-allocated) */

    LONGLONG        deadline_mono_ns;   /* absolute CLOCK_MONOTONIC deadline, ns */
    LONG            period_ms;          /* 0 = one-shot */
    BOOLEAN         manual_reset;       /* NotificationTimer */

    /* Optional APC delivery. */
    PTIMER_APC_ROUTINE apc_routine;
    void           *apc_arg;
    HANDLE          apc_thread;         /* thread that registered the APC */

    /* State. */
    LONG            refcount;           /* 1 for table presence + N for in-flight handlers */
    BOOLEAN         armed;              /* in queue */
    BOOLEAN         cancelled;          /* set_timer(when=0) + never re-armed, or cancel called */
    BOOLEAN         was_signaled;       /* for NtQueryTimer TimerState reporting */
};

static struct list timer_table[TIMER_TABLE_BUCKETS];
static struct list timer_queue = LIST_INIT( timer_queue );

static pi_mutex_t timer_lock = PI_MUTEX_INIT(0);
/* No RTPI_COND_CLOCK_REALTIME flag: dispatcher times on CLOCK_MONOTONIC. */
static pi_cond_t  timer_wake = PI_COND_INIT(0);
static pthread_t  timer_thread;
static int        timer_thread_started;
static int        timer_shutdown;

static pthread_once_t table_once = PTHREAD_ONCE_INIT;

/*--------------------------------------------------------------------------
 * NSPA Phase 3 sched-RT migration state (default-OFF gate).
 *
 * Same pattern as wm_timer migration: when NSPA_SCHED_USE_FOR_LOCAL_TIMER=1
 * AND nspa_sched_rt_available(), the NT timer dispatcher work runs on
 * the per-process RT sched thread (NTDLL_SCHED_CLASS_RT) instead of on
 * its own dedicated pthread.  Same priority class (FIFO at NSPA_RT_PRIO-1).
 *
 * When both wm_timer AND local_timer migrate, both legacy pthreads
 * disappear and the work consolidates onto a shared wine-sched-rt
 * thread → net -1 thread per process.
 *
 * Lock order: timer_lock OUTER, sched per-instance lock INNER.  sched
 * code never reaches into local_timer; local_timer calls into sched
 * while holding timer_lock — no inversion possible.  signal_fd write
 * is non-blocking (Phase 3 sched.c change), so the producer can never
 * deadlock on a full pipe waiting for sched to drain.
 *
 * Fire-outside-lock pattern (legacy dispatcher_main: drop timer_lock
 * before NtSetEvent/NtQueueApcThread, re-acquire for periodic re-arm)
 * is preserved in the sched dispatch callback so callbacks that
 * re-enter via NtSetTimer/NtCancelTimer don't deadlock.
 *--------------------------------------------------------------------------*/

#include "wine/unixlib.h"   /* sched_handle_t + ntdll_sched_*_class */

static int             local_timer_use_sched = -1;       /* tri-state cache */
static sched_handle_t  local_timer_pending_dispatch;     /* protected by timer_lock */
static pthread_once_t  local_timer_atexit_once = PTHREAD_ONCE_INIT;

/*--------------------------------------------------------------------------
 * Lazy table init
 *--------------------------------------------------------------------------*/

static void init_table_buckets(void)
{
    int i;
    for (i = 0; i < TIMER_TABLE_BUCKETS; i++) list_init( &timer_table[i] );
}

/* Ensure the hash buckets are initialised before any entry point runs
 * find_entry().  Without this, NtClose -> nspa_local_timer_close can
 * reach find_entry() before any NtCreateTimer ever did — the buckets
 * would be zero memory and LIST_FOR_EACH_ENTRY would deref a NULL next
 * pointer on the first handle passed through close. */
static inline BOOL nspa_local_timers_active(void)
{
    pthread_once( &table_once, init_table_buckets );
    return TRUE;
}

/*--------------------------------------------------------------------------
 * Time helpers
 *
 * All internal deadlines are absolute CLOCK_MONOTONIC nanoseconds.  NT's
 * relative `when` (negative) is elapsed-time, which is exactly what
 * CLOCK_MONOTONIC tracks — no NTP sensitivity.  NT's absolute `when`
 * (positive FILETIME) is converted once at insert-time into the monotonic
 * reference frame via the current CLOCK_REALTIME/CLOCK_MONOTONIC offset.
 *--------------------------------------------------------------------------*/

static LONGLONG mono_now_ns(void)
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    return (LONGLONG)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static LONGLONG real_now_ft(void)
{
    struct timespec ts;
    clock_gettime( CLOCK_REALTIME, &ts );
    return (LONGLONG)ts.tv_sec * 10000000LL + ts.tv_nsec / 100LL + NT_UNIX_EPOCH_DIFF_100NS;
}

/* Convert NT `when` (LARGE_INTEGER.QuadPart) to an absolute CLOCK_MONOTONIC
 * deadline in nanoseconds.  Negative values are relative 100ns offsets; we
 * stay entirely in CLOCK_MONOTONIC for those.  Positive values are absolute
 * FILETIME; we translate through the current wall/mono offset. */
static LONGLONG when_to_deadline_mono_ns( LONGLONG when )
{
    /* Cap 100ns-units-to-ns conversion to avoid signed overflow.  INT64_MAX/100
     * is ~29,000 years of nanoseconds, so this clamp only triggers for
     * pathological inputs — but we still must not invoke UB. */
    static const LONGLONG NS_MAX_DELTA = (LONGLONG)9223372036854775807LL / 100LL;
    LONGLONG mono_now = mono_now_ns();
    LONGLONG dl;

    if (when < 0)
    {
        LONGLONG delta_100ns = -when;                /* always positive */
        if (delta_100ns > NS_MAX_DELTA) delta_100ns = NS_MAX_DELTA;
        return mono_now + delta_100ns * 100LL;
    }

    /* Absolute NT FILETIME: snapshot offset once, convert into mono. */
    {
        LONGLONG real_now = real_now_ft();
        LONGLONG delta_100ns = when - real_now;      /* may be negative (past) */
        if (delta_100ns >  NS_MAX_DELTA) delta_100ns =  NS_MAX_DELTA;
        if (delta_100ns < -NS_MAX_DELTA) delta_100ns = -NS_MAX_DELTA;
        dl = mono_now + delta_100ns * 100LL;
        if (dl < mono_now) dl = mono_now;            /* clamp past to "now" */
    }
    return dl;
}

/* Turn an absolute CLOCK_MONOTONIC nanosecond deadline into the timespec
 * pi_cond_timedwait expects (same clock domain, absolute). */
static void mono_ns_to_timespec( LONGLONG ns, struct timespec *ts )
{
    if (ns < 0) ns = 0;
    ts->tv_sec = ns / 1000000000LL;
    ts->tv_nsec = ns % 1000000000LL;
}

/*--------------------------------------------------------------------------
 * Table lookup (caller holds timer_lock)
 *--------------------------------------------------------------------------*/

static struct list *bucket_for( HANDLE handle )
{
    UINT_PTR v = (UINT_PTR)handle;
    v = (v >> 2) * 0x9E3779B1u;          /* Knuth multiplicative hash */
    return &timer_table[v & TIMER_TABLE_MASK];
}

static struct nspa_local_timer *find_entry( HANDLE handle )
{
    struct list *bucket = bucket_for( handle );
    struct nspa_local_timer *t;

    LIST_FOR_EACH_ENTRY( t, bucket, struct nspa_local_timer, table_entry )
    {
        if (t->handle == handle) return t;
    }
    return NULL;
}

/*--------------------------------------------------------------------------
 * Queue discipline (caller holds timer_lock)
 *--------------------------------------------------------------------------*/

static void queue_remove( struct nspa_local_timer *t )
{
    if (t->armed)
    {
        list_remove( &t->queue_entry );
        t->armed = FALSE;
    }
}

static void queue_insert_sorted( struct nspa_local_timer *t )
{
    struct nspa_local_timer *cur;

    LIST_FOR_EACH_ENTRY( cur, &timer_queue, struct nspa_local_timer, queue_entry )
    {
        if (cur->deadline_mono_ns > t->deadline_mono_ns)
        {
            list_add_before( &cur->queue_entry, &t->queue_entry );
            t->armed = TRUE;
            return;
        }
    }
    list_add_tail( &timer_queue, &t->queue_entry );
    t->armed = TRUE;
}

/*--------------------------------------------------------------------------
 * Firing: signal backing event, optionally queue APC
 *--------------------------------------------------------------------------*/

static void fire_timer( struct nspa_local_timer *t )
{
    LONG prev_state;

    /* NtSetEvent takes the fast NTSync inproc path for server-allocated
     * events once the fd is cached, so this is effectively zero-RTT.
     * We call it outside timer_lock so a callback that re-arms the timer
     * does not deadlock (matches DPC discipline). */
    NtSetEvent( t->handle, &prev_state );

    /* APC callback: Windows fires this only when the thread that set the
     * timer is in an alertable wait.  NtQueueApcThread preserves that
     * semantic; if the thread is not alertable, the APC stays pending
     * until it becomes alertable. */
    if (t->apc_routine && t->apc_thread)
    {
        /* Windows documents the TimerAPCProc signature as receiving the
         * expiry FILETIME in (LowValue, HighValue).  We report the current
         * wall-clock at fire time (which is what Windows reports in
         * practice — the timer "fired just now" in wall-clock terms). */
        LARGE_INTEGER timer_time;
        timer_time.QuadPart = real_now_ft();
        NtQueueApcThread( t->apc_thread,
                          (PNTAPCFUNC)t->apc_routine,
                          (ULONG_PTR)t->apc_arg,
                          (ULONG_PTR)timer_time.u.LowPart,
                          (ULONG_PTR)timer_time.u.HighPart );
    }
}

/*--------------------------------------------------------------------------
 * Dispatcher thread
 *--------------------------------------------------------------------------*/

/* Promote self to SCHED_FIFO one band below NSPA_RT_PRIO if the env var is
 * set.  Timers sit just under the audio-callback band: low enough never to
 * preempt RT audio, high enough that timer wakes are sharp versus any
 * SCHED_OTHER contention.  Silently skipped when NSPA_RT_PRIO is unset or
 * out of the FIFO range (e.g. developer run without RT capabilities). */
static void dispatcher_promote_self(void)
{
    const char *env = getenv( "NSPA_RT_PRIO" );
    struct sched_param param;
    int fmin, fmax, prio;

    if (!env || !*env) return;
    prio = atoi( env ) - 1;

    fmin = sched_get_priority_min( SCHED_FIFO );
    fmax = sched_get_priority_max( SCHED_FIFO );
    if (fmin < 0 || fmax < 0) return;
    if (prio < fmin) prio = fmin;
    if (prio >= fmax) prio = fmax - 1;

    param.sched_priority = prio;
    if (sched_setscheduler( 0, SCHED_FIFO | SCHED_RESET_ON_FORK, &param ) < 0)
    {
        WARN( "SCHED_FIFO promotion failed for timer dispatcher: %s\n", strerror( errno ) );
    }
}

static void *dispatcher_main( void *arg )
{
    dispatcher_promote_self();

    pi_mutex_lock( &timer_lock );

    while (!timer_shutdown)
    {
        LONGLONG now_ns = mono_now_ns();
        struct nspa_local_timer *t, *next;
        struct list fire_batch = LIST_INIT( fire_batch );
        BOOLEAN have_deadline = FALSE;
        struct timespec wait_until = {0};

        /* Pop every entry whose deadline has passed into fire_batch. */
        LIST_FOR_EACH_ENTRY_SAFE( t, next, &timer_queue, struct nspa_local_timer, queue_entry )
        {
            if (t->deadline_mono_ns > now_ns) break;
            list_remove( &t->queue_entry );
            t->armed = FALSE;
            t->was_signaled = TRUE;
            t->refcount++;          /* hold across unlocked fire */
            list_add_tail( &fire_batch, &t->queue_entry );
        }

        /* Compute next wake. */
        if (!list_empty( &timer_queue ))
        {
            t = LIST_ENTRY( list_head( &timer_queue ), struct nspa_local_timer, queue_entry );
            mono_ns_to_timespec( t->deadline_mono_ns, &wait_until );
            have_deadline = TRUE;
        }

        /* Fire outside the lock: callbacks/APCs may call NtSetTimer/NtCancelTimer
         * which re-acquire timer_lock. */
        if (!list_empty( &fire_batch ))
        {
            pi_mutex_unlock( &timer_lock );

            LIST_FOR_EACH_ENTRY_SAFE( t, next, &fire_batch, struct nspa_local_timer, queue_entry )
            {
                list_remove( &t->queue_entry );

                if (!t->cancelled) fire_timer( t );

                pi_mutex_lock( &timer_lock );

                /* Periodic re-arm, but only if nothing else (concurrent
                 * NtSetTimer) has already armed this entry while we were
                 * firing outside the lock.  Re-inserting an already-armed
                 * entry would corrupt the queue with a double link. */
                if (t->period_ms && !t->cancelled && !t->armed)
                {
                    /* Advance from the logical deadline so drift does not
                     * accumulate; fast-forward if we're far behind (paused
                     * debugger, load spike) to avoid bursting N catch-ups.
                     * period_ms -> ns: multiply by 1e6. */
                    t->deadline_mono_ns += (LONGLONG)t->period_ms * 1000000LL;
                    {
                        LONGLONG now2 = mono_now_ns();
                        if (t->deadline_mono_ns < now2)
                            t->deadline_mono_ns = now2 + (LONGLONG)t->period_ms * 1000000LL;
                    }
                    queue_insert_sorted( t );
                }

                /* Drop the fire refcount.  If the user closed the handle
                 * while we were firing, we may be the last holder; free. */
                if (--t->refcount == 0)
                {
                    pi_mutex_unlock( &timer_lock );
                    free( t );
                    pi_mutex_lock( &timer_lock );
                    continue;
                }

                pi_mutex_unlock( &timer_lock );
            }

            pi_mutex_lock( &timer_lock );
            continue;    /* re-evaluate after firing */
        }

        if (have_deadline)
            pi_cond_timedwait( &timer_wake, &timer_lock, &wait_until );
        else
            pi_cond_wait( &timer_wake, &timer_lock );
    }

    pi_mutex_unlock( &timer_lock );
    return NULL;
}

/*--------------------------------------------------------------------------
 * NSPA Phase 3 sched-RT path
 *
 * Replaces dispatcher_main + pthread + pi_cond_timedwait with an
 * event-driven sched-timer chain hosted on the per-process RT sched
 * thread.  Each fire of the dispatch callback runs ONE iteration of the
 * legacy loop body (pop expired into fire_batch, fire OUTSIDE the lock,
 * periodic re-arm + refcount under the lock) and then registers the
 * next deadline.
 *
 * RT-safety: dispatch callback runs on wine-sched-rt at SCHED_FIFO,
 * NSPA_RT_PRIO-1 — same priority class as the legacy dispatcher.  No
 * RT downgrade.  PI mutex on timer_lock handles cross-priority lock
 * contention correctness.
 *--------------------------------------------------------------------------*/

static BOOL nspa_local_timer_sched_active(void)
{
    /* NSPA_SCHED_USE_FOR_LOCAL_TIMER env-gate dropped after Ableton
     * validation per the NSPA convention "no A/B gating crap on default-on
     * features".  Migration runs whenever the RT instance is available;
     * absence of RT (no NSPA_RT_PRIO) falls back to the legacy pthread
     * dispatcher via the existing fallback path. */
    if (local_timer_use_sched == -1)
        local_timer_use_sched = nspa_sched_rt_available() ? 1 : 0;
    return local_timer_use_sched == 1;
}

/* Caller holds timer_lock.  Returns the next absolute CLOCK_MONOTONIC
 * deadline (ns) that the dispatcher needs to wake at, or LLONG_MAX if
 * the queue is empty. */
static LONGLONG local_timer_next_deadline_locked(void)
{
    struct nspa_local_timer *t;

    if (list_empty( &timer_queue )) return LLONG_MAX;
    t = LIST_ENTRY( list_head( &timer_queue ), struct nspa_local_timer, queue_entry );
    return t->deadline_mono_ns;
}

/* Forward decl — the sched-timer callback. */
static void local_timer_sched_dispatch_cb( void *arg );

/* Caller holds timer_lock.  Cancels the current pending sched
 * registration (if any) and registers a new one for the next deadline.
 * Called from NtSetTimer/NtCancelTimer wake paths and from the dispatch
 * callback itself for re-arm.
 *
 * Safe under timer_lock: the cancel and register both go through the
 * sched per-instance lock (INNER); signal_fd write is non-blocking so
 * we can never deadlock on a full pipe waiting for sched to drain
 * while sched is waiting for timer_lock. */
static void local_timer_sched_rearm_locked(void)
{
    sched_handle_t old, new = SCHED_HANDLE_NULL;
    LONGLONG next_ns, now_ns, rel_ns;
    LARGE_INTEGER timeout;
    NTSTATUS status;

    /* Atomically swap out the stored handle so a racing cancel /
     * dispatch sees a coherent before/after.  Cancel of the old is
     * gen-checked: if it has already fired, returns STATUS_NOT_FOUND
     * harmlessly. */
    old = local_timer_pending_dispatch;
    local_timer_pending_dispatch = SCHED_HANDLE_NULL;
    if (old.priv) ntdll_sched_cancel( old );

    if (timer_shutdown) return;        /* no rearm during teardown */

    next_ns = local_timer_next_deadline_locked();
    if (next_ns == LLONG_MAX) return;  /* queue empty */

    now_ns = mono_now_ns();
    rel_ns = next_ns - now_ns;
    if (rel_ns < 0) rel_ns = 0;        /* deadline already passed — fire ASAP */

    /* NT 100ns units, negative = relative timeout. */
    timeout.QuadPart = -(rel_ns / 100);
    if (timeout.QuadPart == 0) timeout.QuadPart = -1;   /* min representable */

    status = ntdll_sched_register_timer_class( NTDLL_SCHED_CLASS_RT, &timeout,
                                               local_timer_sched_dispatch_cb, NULL, &new );
    if (status == STATUS_SUCCESS)
    {
        local_timer_pending_dispatch = new;
    }
    else
    {
        WARN( "local_timer sched rearm failed status=%#x — dispatch stalls until next NtSetTimer\n",
              (unsigned int)status );
        /* No retry; next NtSetTimer/NtCancelTimer triggers another rearm. */
    }
}

/* Sched-RT thread callback.  Runs ONE iteration of the legacy
 * dispatcher loop body (pop expired, fire outside lock, periodic
 * re-arm under lock, refcount dec/free), then re-arms for the next
 * deadline. */
static void local_timer_sched_dispatch_cb( void *arg )
{
    struct nspa_local_timer *t, *next;
    struct list fire_batch = LIST_INIT( fire_batch );
    LONGLONG now_ns;

    (void)arg;

    pi_mutex_lock( &timer_lock );

    if (timer_shutdown)
    {
        local_timer_pending_dispatch = SCHED_HANDLE_NULL;
        pi_mutex_unlock( &timer_lock );
        return;
    }

    now_ns = mono_now_ns();

    /* Pop expired into fire_batch (deliberately copied line-for-line
     * from dispatcher_main for behavioral parity). */
    LIST_FOR_EACH_ENTRY_SAFE( t, next, &timer_queue, struct nspa_local_timer, queue_entry )
    {
        if (t->deadline_mono_ns > now_ns) break;
        list_remove( &t->queue_entry );
        t->armed = FALSE;
        t->was_signaled = TRUE;
        t->refcount++;          /* hold across unlocked fire */
        list_add_tail( &fire_batch, &t->queue_entry );
    }

    /* Fire OUTSIDE the lock.  This is critical: callbacks/APCs may
     * call NtSetTimer/NtCancelTimer which re-acquire timer_lock — if
     * we held the lock during fire, every such re-entrant call would
     * deadlock.  Matches legacy dispatcher_main exactly. */
    if (!list_empty( &fire_batch ))
    {
        pi_mutex_unlock( &timer_lock );

        LIST_FOR_EACH_ENTRY_SAFE( t, next, &fire_batch, struct nspa_local_timer, queue_entry )
        {
            list_remove( &t->queue_entry );

            if (!t->cancelled) fire_timer( t );

            pi_mutex_lock( &timer_lock );

            /* Periodic re-arm, but only if nothing else (concurrent
             * NtSetTimer) has already armed this entry while we were
             * firing outside the lock.  Re-inserting an already-armed
             * entry would corrupt the queue with a double link. */
            if (t->period_ms && !t->cancelled && !t->armed)
            {
                t->deadline_mono_ns += (LONGLONG)t->period_ms * 1000000LL;
                {
                    LONGLONG now2 = mono_now_ns();
                    if (t->deadline_mono_ns < now2)
                        t->deadline_mono_ns = now2 + (LONGLONG)t->period_ms * 1000000LL;
                }
                queue_insert_sorted( t );
            }

            /* Drop the fire refcount.  If the user closed the handle
             * while we were firing, we may be the last holder; free. */
            if (--t->refcount == 0)
            {
                pi_mutex_unlock( &timer_lock );
                free( t );
                pi_mutex_lock( &timer_lock );
                continue;
            }

            pi_mutex_unlock( &timer_lock );
        }

        pi_mutex_lock( &timer_lock );
    }

    /* The just-fired sched registration is consumed; clear our cached
     * handle (the underlying timer_user was freed by sched.c after
     * invoking our callback, so a stale gen-checked cancel of it would
     * NOT_FOUND harmlessly anyway). */
    local_timer_pending_dispatch = SCHED_HANDLE_NULL;

    /* Re-arm for the next deadline (or no-op if queue empty / shutdown). */
    local_timer_sched_rearm_locked();

    pi_mutex_unlock( &timer_lock );
}

/* atexit: signal shutdown, cancel pending dispatch, no post-exit
 * fires.  In-flight callbacks finish under the lock and observe
 * shutdown=1 on their next iteration (won't re-arm). */
static void local_timer_sched_atexit_cb(void)
{
    sched_handle_t h = SCHED_HANDLE_NULL;

    pi_mutex_lock( &timer_lock );
    timer_shutdown = 1;
    h = local_timer_pending_dispatch;
    local_timer_pending_dispatch = SCHED_HANDLE_NULL;
    pi_mutex_unlock( &timer_lock );

    if (h.priv) ntdll_sched_cancel( h );
    /* In-flight callbacks finish naturally without rearm.  Memory in
     * the queue/table is intentionally leaked at exit — OS reaps;
     * explicit teardown would risk freeing under a callback running
     * outside the lock during fire. */
}

static void local_timer_sched_atexit_register(void)
{
    atexit( local_timer_sched_atexit_cb );
}

static void local_timer_sched_arm_atexit_once(void)
{
    pthread_once( &local_timer_atexit_once, local_timer_sched_atexit_register );
}

static NTSTATUS ensure_dispatcher_started(void)
{
    int err;

    if (nspa_local_timer_sched_active())
    {
        /* Sched path: registrations are made on demand from
         * NtSetTimer/NtCancelTimer/dispatch_cb.  Just arm atexit
         * and trigger an initial rearm if nothing is pending.
         * Caller MUST already hold timer_lock per existing contract. */
        local_timer_sched_arm_atexit_once();
        if (!local_timer_pending_dispatch.priv && !timer_shutdown)
            local_timer_sched_rearm_locked();
        return STATUS_SUCCESS;
    }

    if (timer_thread_started) return STATUS_SUCCESS;
    if ((err = pthread_create( &timer_thread, NULL, dispatcher_main, NULL )))
    {
        ERR( "Failed to start NSPA local-timer dispatcher: %d\n", err );
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    timer_thread_started = 1;
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Public API (called from sync.c NT timer syscalls)
 *
 * Each entry point returns:
 *   STATUS_NOT_IMPLEMENTED  -> caller must fall through to server path
 *   anything else           -> the local dispatcher handled it
 *--------------------------------------------------------------------------*/

/* Called from NtCreateTimer for anonymous timers when the feature gate is
 * on.  On success, *handle holds a server-allocated event backing the timer;
 * caller returns that to user code as the "timer" handle.  STATUS_NOT_IMPLEMENTED
 * means: fall through to the original create_timer server path. */
NTSTATUS nspa_local_timer_create( HANDLE *handle, ACCESS_MASK access,
                                  const OBJECT_ATTRIBUTES *attr,
                                  TIMER_TYPE timer_type )
{
    struct nspa_local_timer *entry;
    EVENT_TYPE event_type;
    NTSTATUS ret;
    HANDLE event;

    if (!nspa_local_timers_active()) return STATUS_NOT_IMPLEMENTED;

    /* Only anonymous timers are eligible for local dispatch.  Named timers
     * are cross-process visible and must stay on the server path. */
    if (attr && attr->ObjectName && attr->ObjectName->Length)
        return STATUS_NOT_IMPLEMENTED;

    /* Manual-reset event for NotificationTimer; auto-reset for Synchronization.
     * This preserves NT wait semantics exactly: a NotificationTimer fires and
     * remains signalled until explicitly reset (we never reset it on re-arm);
     * a SynchronizationTimer auto-resets after a single successful wait. */
    event_type = (timer_type == NotificationTimer) ? NotificationEvent : SynchronizationEvent;

    /* The backing event is set/reset by the dispatcher thread and waited
     * by app threads — both PE-side via inproc-sync.  After Phase 4.6
     * (events Option A), NtCreateEvent routes anonymous events through
     * the client-range fast path; server-aware client-range events
     * handle the cross-context cases for which the timer backing
     * previously required a workaround helper (nspa_create_internal_event,
     * removed in Phase 4.6.F). */
    if ((ret = NtCreateEvent( &event, access, NULL /* suppress name */,
                              event_type, FALSE /* initial state */ )))
        return ret;

    if (!(entry = calloc( 1, sizeof(*entry) )))
    {
        NtClose( event );
        return STATUS_NO_MEMORY;
    }
    entry->handle = event;
    entry->manual_reset = (timer_type == NotificationTimer);
    entry->refcount = 1;

    pthread_once( &table_once, init_table_buckets );
    pi_mutex_lock( &timer_lock );

    list_add_tail( bucket_for( event ), &entry->table_entry );

    if ((ret = ensure_dispatcher_started()))
    {
        list_remove( &entry->table_entry );
        pi_mutex_unlock( &timer_lock );
        free( entry );
        NtClose( event );
        return ret;
    }

    pi_mutex_unlock( &timer_lock );

    *handle = event;
    return STATUS_SUCCESS;
}

/* Called from NtSetTimer.  If the handle is ours, arms the local dispatcher
 * and returns success; otherwise returns STATUS_NOT_IMPLEMENTED so the caller
 * falls through to the server path. */
NTSTATUS nspa_local_timer_set( HANDLE handle, const LARGE_INTEGER *when,
                               PTIMER_APC_ROUTINE callback, void *arg,
                               ULONG period, BOOLEAN *previous_state )
{
    struct nspa_local_timer *entry;
    LONG prev_state = 0;

    if (!nspa_local_timers_active()) return STATUS_NOT_IMPLEMENTED;

    pi_mutex_lock( &timer_lock );

    if (!(entry = find_entry( handle )))
    {
        pi_mutex_unlock( &timer_lock );
        return STATUS_NOT_IMPLEMENTED;
    }

    /* NtSetTimer re-arms; the `state` output reports the previous signal
     * state (boolean), which is simply our tracked `was_signaled`.  NT does
     * NOT auto-reset the signal state on re-arm (a Notification timer stays
     * signaled until the caller resets it explicitly, and a Synchronization
     * timer auto-resets only on the next successful wait).  Do not reset
     * the backing event here. */
    prev_state = entry->was_signaled ? 1 : 0;

    queue_remove( entry );
    entry->cancelled = FALSE;
    entry->deadline_mono_ns = when_to_deadline_mono_ns( when->QuadPart );
    entry->period_ms = period;
    entry->apc_routine = callback;
    entry->apc_arg = arg;
    entry->apc_thread = callback ? NtCurrentTeb()->ClientId.UniqueThread : NULL;
    entry->was_signaled = FALSE;

    queue_insert_sorted( entry );

    if (previous_state) *previous_state = prev_state ? TRUE : FALSE;

    if (nspa_local_timer_sched_active())
    {
        /* Sched path: re-evaluate next deadline + re-arm pending
         * sched-timer.  Done while holding the lock — sched write end
         * is non-blocking so no deadlock risk. */
        local_timer_sched_rearm_locked();
        pi_mutex_unlock( &timer_lock );
    }
    else
    {
        pi_mutex_unlock( &timer_lock );
        pi_cond_signal( &timer_wake, &timer_lock );
    }
    return STATUS_SUCCESS;
}

/* Called from NtCancelTimer. */
NTSTATUS nspa_local_timer_cancel( HANDLE handle, BOOLEAN *previous_state )
{
    struct nspa_local_timer *entry;
    BOOLEAN was_armed;

    if (!nspa_local_timers_active()) return STATUS_NOT_IMPLEMENTED;

    pi_mutex_lock( &timer_lock );

    if (!(entry = find_entry( handle )))
    {
        pi_mutex_unlock( &timer_lock );
        return STATUS_NOT_IMPLEMENTED;
    }

    was_armed = entry->armed;
    queue_remove( entry );
    entry->cancelled = TRUE;
    entry->period_ms = 0;

    if (previous_state) *previous_state = was_armed;

    /* Sched path: removing an entry can only push the next deadline
     * later (head may have changed).  Rearm so we don't wake at the
     * old head's deadline only to find nothing.  Correctness-neutral
     * but saves one spurious wake.  Legacy path doesn't need this — it
     * just lets pi_cond_timedwait expire on the stale deadline. */
    if (nspa_local_timer_sched_active())
        local_timer_sched_rearm_locked();

    pi_mutex_unlock( &timer_lock );
    return STATUS_SUCCESS;
}

/* Called from NtQueryTimer (TimerBasicInformation).  Populates the caller's
 * TIMER_BASIC_INFORMATION from local state. */
NTSTATUS nspa_local_timer_query( HANDLE handle, TIMER_BASIC_INFORMATION *info )
{
    struct nspa_local_timer *entry;
    LONGLONG now_ns;

    if (!nspa_local_timers_active()) return STATUS_NOT_IMPLEMENTED;

    pi_mutex_lock( &timer_lock );

    if (!(entry = find_entry( handle )))
    {
        pi_mutex_unlock( &timer_lock );
        return STATUS_NOT_IMPLEMENTED;
    }

    now_ns = mono_now_ns();
    info->TimerState = entry->was_signaled ? TRUE : FALSE;
    if (entry->armed && entry->deadline_mono_ns > now_ns)
    {
        /* NtQueryTimer returns RemainingTime in the "negative = relative
         * 100ns" convention (the same shape as a relative `when`).
         * Convert ns remaining -> 100ns units; negate. */
        LONGLONG remaining_100ns = (entry->deadline_mono_ns - now_ns) / 100LL;
        info->RemainingTime.QuadPart = -remaining_100ns;
    }
    else
        info->RemainingTime.QuadPart = 0;

    pi_mutex_unlock( &timer_lock );
    return STATUS_SUCCESS;
}

/* Called from NtClose when the closing handle might be a managed timer. */
void nspa_local_timer_close( HANDLE handle )
{
    struct nspa_local_timer *entry;

    if (!nspa_local_timers_active()) return;

    pi_mutex_lock( &timer_lock );

    if (!(entry = find_entry( handle )))
    {
        pi_mutex_unlock( &timer_lock );
        return;
    }

    queue_remove( entry );
    list_remove( &entry->table_entry );
    entry->cancelled = TRUE;

    /* refcount: table presence (1) + any in-flight fires.  We released table,
     * so decrement; dispatcher releases its hold when it finishes firing. */
    if (--entry->refcount == 0)
    {
        pi_mutex_unlock( &timer_lock );
        free( entry );
        return;
    }

    pi_mutex_unlock( &timer_lock );
}

/* Called from NtDuplicateObject.  Returns STATUS_NOT_IMPLEMENTED if the
 * source handle is not a managed timer (caller does normal dup).  Returns
 * STATUS_ACCESS_DENIED for cross-process dup of a managed timer (audit §H).
 * Returns STATUS_SUCCESS if caller should proceed with same-process dup and
 * we have registered the new handle. */
NTSTATUS nspa_local_timer_check_duplicate( HANDLE source_handle, HANDLE source_process,
                                           HANDLE target_process )
{
    struct nspa_local_timer *entry;
    NTSTATUS ret;

    if (!nspa_local_timers_active()) return STATUS_NOT_IMPLEMENTED;

    /* Phase 4.5: when the backing event is client-range, the wineserver-routed
     * "normal dup" path would fail (the handle isn't in the server's table).
     * Reject dup in that case; apps that need to dup a timer should not be
     * using the fully-local fast path.  Same-process dup of a server-backed
     * timer continues to work as before. */
    if (is_client_handle( source_handle ))
        return STATUS_ACCESS_DENIED;

    pi_mutex_lock( &timer_lock );
    entry = find_entry( source_handle );
    ret = entry ? (target_process == source_process ? STATUS_SUCCESS : STATUS_ACCESS_DENIED)
                : STATUS_NOT_IMPLEMENTED;
    pi_mutex_unlock( &timer_lock );
    return ret;
}

/* Called after a successful same-process NtDuplicateObject where the source
 * was a managed timer; registers the duplicated handle in our table so the
 * duplicate inherits local dispatch.  The duplicate shares the same entry
 * state; the backing event refcount was incremented by the server as part
 * of dup, so close() on either handle decrements independently.  A new
 * dispatcher entry is created since timer state (deadline, period, apc) is
 * per-handle in NT semantics. */
NTSTATUS nspa_local_timer_register_duplicate( HANDLE source_handle, HANDLE new_handle )
{
    struct nspa_local_timer *src, *dup;

    if (!nspa_local_timers_active()) return STATUS_NOT_IMPLEMENTED;

    if (!(dup = calloc( 1, sizeof(*dup) ))) return STATUS_NO_MEMORY;

    pi_mutex_lock( &timer_lock );

    if (!(src = find_entry( source_handle )))
    {
        pi_mutex_unlock( &timer_lock );
        free( dup );
        return STATUS_NOT_IMPLEMENTED;
    }

    dup->handle = new_handle;
    dup->manual_reset = src->manual_reset;
    dup->refcount = 1;

    list_add_tail( bucket_for( new_handle ), &dup->table_entry );

    pi_mutex_unlock( &timer_lock );
    return STATUS_SUCCESS;
}
