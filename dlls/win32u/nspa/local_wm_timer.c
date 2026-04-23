/*
 * NSPA local WM_TIMER dispatcher (Phase B).
 *
 * Intercepts NtUserSetTimer / NtUserKillTimer (and the WM_SYSTIMER
 * variants) in dlls/win32u/message.c.  When the feature gate is on and
 * the caller supplies a non-zero id on an hwnd owned by this process,
 * the timer is managed by a per-process dispatcher thread here instead
 * of the wineserver pending_timers / expired_timers lists.  Expiries
 * are published to the owner thread's nspa_timer_ring carve-out inside
 * nspa_queue_bypass_shm_t (Phase A protocol extension), and
 * peek_message drains them client-side via nspa_try_pop_own_timer_ring.
 *
 * Architecture notes, ties to existing NSPA code:
 *   - Dispatcher lives PE-side so that every producer and consumer is
 *     in the same binary (win32u).  We reuse the already-built PE-side
 *     peer-memfd cache from nspa_msg_ring.c instead of building a
 *     second Unix-side lookup path.
 *   - The ring is class-isolated (sole producer: this dispatcher) per
 *     project_msg_ring_class_isolated_pattern.  Head advance is a plain
 *     atomic store — no CAS contention with the Send/Post ring.
 *   - Coalescing matches NT semantics.  Server's WM_TIMER has implicit
 *     coalescing: timer_callback moves pending -> expired, and
 *     find_expired_timer (drain) restarts via restart_timer.  If the
 *     pump stalls across N periods, the app only sees ONE WM_TIMER.
 *     We replicate this by tagging each entry with in_ring when we
 *     publish a slot; the dispatcher re-checks slot state on its next
 *     wake and only re-arms when CONSUMED.
 *
 * Scope of migration:
 *   - hwnd owned by the same process AND non-zero id supplied.
 *     Everything else falls through to server, preserving existing
 *     semantics for:
 *       * cross-process hwnds (server ACCESS_DENIED path)
 *       * id=0 auto-generation (server picks ID; skipped here to
 *         avoid any ID-space collision with server-allocated IDs)
 *       * named/opened timers — not applicable for WM_TIMER, it's
 *         always anonymous per hwnd
 *
 * Kill-vs-fire race:
 *   NT delivers WM_TIMER already in the queue even after KillTimer.
 *   Our design matches: kill removes the wheel entry but any slot
 *   already published to the ring stays READY until peek_message
 *   drains it.  Dispatcher's coalescing can never re-publish a killed
 *   entry because it's gone from the table.
 *
 * Feature gate: on by default.  Set NSPA_DISABLE_LOCAL_WM_TIMERS=1 to
 * fall back to wineserver WM_TIMER dispatch (bisection aid).
 */

#if 0
#pragma makedep unix
#endif

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* SCHED_RESET_ON_FORK is Linux-specific and not always declared in
 * <sched.h> — preserve fork-resilience for the dispatcher without
 * gating the whole file behind glibc version checks. */
#ifndef SCHED_RESET_ON_FORK
#define SCHED_RESET_ON_FORK 0x40000000
#endif

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include "../win32u_private.h"
#include "wine/debug.h"
#include "wine/list.h"
#include "wine/server_protocol.h"
#include <rtpi.h>

WINE_DEFAULT_DEBUG_CHANNEL(timer);

/* Exposed from nspa_msg_ring.c so we can reach peer memfds without
 * rebuilding the whole cache-fill machinery here. */
extern const nspa_queue_bypass_shm_t *nspa_get_own_bypass_shm_public( void );
extern const nspa_queue_bypass_shm_t *nspa_get_peer_bypass_shm_public( DWORD peer_tid );

/* Hwnd-to-owner-tid resolver from win32u/window.c. */
extern DWORD get_window_thread( HWND hwnd, DWORD *process );

#define WM_TIMER_TABLE_BUCKETS   64
#define WM_TIMER_TABLE_MASK      (WM_TIMER_TABLE_BUCKETS - 1)

struct nspa_wm_timer
{
    struct list     table_entry;        /* in wm_timer_table bucket */
    struct list     wheel_entry;        /* in wm_timer_wheel (sorted), or detached */

    HWND            hwnd;
    UINT_PTR        id;
    UINT            msg;                /* WM_TIMER or WM_SYSTIMER */
    UINT            rate_ms;
    WNDPROC         winproc;            /* alloc_winproc result; lparam in the posted message */
    DWORD           owner_tid;          /* thread that will receive WM_TIMER */

    /* Resolved at SetTimer time from the caller thread (which has a
     * wineserver session) so that the dispatcher thread only reads +
     * writes shared memory.  Dispatcher never issues server calls. */
    const nspa_queue_bypass_shm_t *peer_shm;

    LONGLONG        deadline_mono_ns;
    BOOLEAN         armed;
    BOOLEAN         cancelled;
    BOOLEAN         in_ring;            /* slot published; awaiting consumer drain */
    unsigned int    last_slot_idx;      /* which slot we published into (when in_ring) */
};

static struct list wm_timer_table[WM_TIMER_TABLE_BUCKETS];
static struct list wm_timer_wheel = LIST_INIT( wm_timer_wheel );

static pi_mutex_t wm_timer_lock = PI_MUTEX_INIT(0);
/* Dispatcher sleeps on CLOCK_MONOTONIC absolute deadlines. */
static pi_cond_t  wm_timer_wake = PI_COND_INIT(0);
static pthread_t  wm_timer_thread;
static int        wm_timer_thread_started;
static int        wm_timer_shutdown;

static int              nspa_wm_timers_enabled = -1;
static pthread_once_t   gate_once = PTHREAD_ONCE_INIT;
static pthread_once_t   table_once = PTHREAD_ONCE_INIT;

/*--------------------------------------------------------------------------
 * Feature gate
 *--------------------------------------------------------------------------*/

static void init_feature_gate(void)
{
    nspa_wm_timers_enabled = (getenv( "NSPA_DISABLE_LOCAL_WM_TIMERS" ) == NULL);
    if (!nspa_wm_timers_enabled)
        TRACE( "NSPA local WM_TIMER dispatch: DISABLED (NSPA_DISABLE_LOCAL_WM_TIMERS set)\n" );
}

static void init_table_buckets(void)
{
    int i;
    for (i = 0; i < WM_TIMER_TABLE_BUCKETS; i++) list_init( &wm_timer_table[i] );
}

static inline BOOL nspa_wm_timers_active(void)
{
    pthread_once( &gate_once, init_feature_gate );
    if (nspa_wm_timers_enabled == 1)
        pthread_once( &table_once, init_table_buckets );
    return nspa_wm_timers_enabled == 1;
}

/*--------------------------------------------------------------------------
 * Time helpers (MONOTONIC, NTP-immune; same convention as Phase A)
 *--------------------------------------------------------------------------*/

static LONGLONG mono_now_ns(void)
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    return (LONGLONG)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void mono_ns_to_timespec( LONGLONG ns, struct timespec *ts )
{
    if (ns < 0) ns = 0;
    ts->tv_sec = ns / 1000000000LL;
    ts->tv_nsec = ns % 1000000000LL;
}

/*--------------------------------------------------------------------------
 * Table + wheel discipline (caller holds wm_timer_lock)
 *--------------------------------------------------------------------------*/

static struct list *bucket_for( HWND hwnd, UINT_PTR id )
{
    UINT_PTR v = (UINT_PTR)hwnd ^ (id << 3);
    v = (v >> 2) * 0x9E3779B1u;
    return &wm_timer_table[v & WM_TIMER_TABLE_MASK];
}

static struct nspa_wm_timer *find_entry( HWND hwnd, UINT_PTR id, UINT msg )
{
    struct list *bucket = bucket_for( hwnd, id );
    struct nspa_wm_timer *t;

    LIST_FOR_EACH_ENTRY( t, bucket, struct nspa_wm_timer, table_entry )
        if (t->hwnd == hwnd && t->id == id && t->msg == msg) return t;
    return NULL;
}

static void wheel_remove( struct nspa_wm_timer *t )
{
    if (t->armed)
    {
        list_remove( &t->wheel_entry );
        t->armed = FALSE;
    }
}

static void wheel_insert_sorted( struct nspa_wm_timer *t )
{
    struct nspa_wm_timer *cur;

    LIST_FOR_EACH_ENTRY( cur, &wm_timer_wheel, struct nspa_wm_timer, wheel_entry )
    {
        if (cur->deadline_mono_ns > t->deadline_mono_ns)
        {
            list_add_before( &cur->wheel_entry, &t->wheel_entry );
            t->armed = TRUE;
            return;
        }
    }
    list_add_tail( &wm_timer_wheel, &t->wheel_entry );
    t->armed = TRUE;
}

/*--------------------------------------------------------------------------
 * Ring publish / coalescing check
 *--------------------------------------------------------------------------*/

/* Producer-side: publish a WM_TIMER slot into the owner thread's ring.
 * Returns TRUE on success (slot_idx_out populated), FALSE on ring-full.
 * The entry's peer_shm was resolved at SetTimer time; dispatcher does
 * a plain shared-memory write, no server call required. */
static BOOL publish_timer_slot( struct nspa_wm_timer *t, unsigned int *slot_idx_out )
{
    volatile nspa_timer_ring_t *ring;
    unsigned int head, idx, state;
    volatile nspa_timer_slot_t *slot;

    if (!t->peer_shm) return FALSE;

    /* Producer-side access; cast away the const qualifier the public
     * accessor applies for consumer-typical callers. */
    ring = (volatile nspa_timer_ring_t *)&t->peer_shm->nspa_timer_ring;
    if (!ring->active) return FALSE;

    /* Sole producer — plain load suffices; stores are release. */
    head = __atomic_load_n( &ring->head, __ATOMIC_RELAXED );
    idx  = head & (NSPA_TIMER_RING_SLOTS - 1);
    slot = &ring->slots[idx];

    state = __atomic_load_n( &slot->state, __ATOMIC_ACQUIRE );
    if (state != NSPA_TIMER_STATE_EMPTY && state != NSPA_TIMER_STATE_CONSUMED)
    {
        /* Ring is full at this index.  Don't publish — NT coalescing
         * applies naturally: consumer hasn't drained; one WM_TIMER is
         * already pending. */
        __atomic_fetch_add( &ring->overflow, 1, __ATOMIC_RELAXED );
        return FALSE;
    }

    __atomic_store_n( &slot->state, NSPA_TIMER_STATE_WRITING, __ATOMIC_RELAXED );

    slot->win      = HandleToUlong( t->hwnd );
    slot->msg      = t->msg;
    slot->timer_id = (lparam_t)t->id;
    /* GetTickCount equivalent without entering the Wine syscall path
     * (dispatcher is a non-Wine pthread on some builds; CLOCK_MONOTONIC
     * ms is the same semantic and matches NtGetTickCount's underlying
     * source).  The consumer sees the same value shape (ms-since-boot
     * wrapped to 32 bits) so peek_message's downstream consumers that
     * diff against GetTickCount() values compare like against like. */
    {
        struct timespec ts;
        clock_gettime( CLOCK_MONOTONIC, &ts );
        slot->time = (unsigned int)((LONGLONG)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL);
    }

    __atomic_store_n( &slot->state, NSPA_TIMER_STATE_READY, __ATOMIC_RELEASE );
    __atomic_store_n( &ring->head, head + 1, __ATOMIC_RELEASE );

    *slot_idx_out = idx;
    return TRUE;
}

/* Dispatcher-side coalescing check: has the slot we published been
 * drained?  If yes, clear in_ring so the next period can re-publish. */
static BOOL slot_was_drained( struct nspa_wm_timer *t )
{
    volatile nspa_timer_ring_t *ring;
    volatile nspa_timer_slot_t *slot;
    unsigned int state;

    if (!t->peer_shm) return TRUE;   /* peer gone — treat as drained, re-arm will reattempt */

    ring = (volatile nspa_timer_ring_t *)&t->peer_shm->nspa_timer_ring;
    slot = &ring->slots[t->last_slot_idx];
    state = __atomic_load_n( &slot->state, __ATOMIC_ACQUIRE );

    /* We published with win+id+msg matching this entry.  If someone
     * else published in the same slot afterward (state=READY again but
     * for a different (win,id,msg)), the consumer will see it and move
     * to CONSUMED eventually; either way, this entry's old slot is
     * conceptually drained. */
    if (state == NSPA_TIMER_STATE_CONSUMED) return TRUE;
    if (state == NSPA_TIMER_STATE_EMPTY)    return TRUE;

    if (state == NSPA_TIMER_STATE_READY)
    {
        if (slot->win != HandleToUlong( t->hwnd ) ||
            slot->timer_id != (lparam_t)t->id ||
            slot->msg != t->msg)
            return TRUE;                /* recycled for a different timer */
    }
    return FALSE;
}

/*--------------------------------------------------------------------------
 * Dispatcher thread
 *--------------------------------------------------------------------------*/

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
        WARN( "SCHED_FIFO promotion failed for WM_TIMER dispatcher: %s\n",
              strerror( errno ) );
}

static void *wm_timer_dispatcher_main( void *arg )
{
    (void)arg;
    dispatcher_promote_self();

    pi_mutex_lock( &wm_timer_lock );

    while (!wm_timer_shutdown)
    {
        LONGLONG now_ns = mono_now_ns();
        struct nspa_wm_timer *t, *next;
        BOOLEAN have_deadline = FALSE;
        struct timespec wait_until = {0};

        /* Step 1: clear in_ring for any entry whose slot has been drained. */
        LIST_FOR_EACH_ENTRY_SAFE( t, next, &wm_timer_wheel, struct nspa_wm_timer, wheel_entry )
        {
            if (t->in_ring && slot_was_drained( t )) t->in_ring = FALSE;
        }

        /* Step 2: for each expired wheel entry, publish if not already
         * in ring.  Leave the wheel entry alone until we know publish
         * succeeded AND coalescing has cleared. */
        LIST_FOR_EACH_ENTRY_SAFE( t, next, &wm_timer_wheel, struct nspa_wm_timer, wheel_entry )
        {
            if (t->deadline_mono_ns > now_ns) break;

            if (!t->cancelled && !t->in_ring)
            {
                unsigned int slot_idx;
                if (publish_timer_slot( t, &slot_idx ))
                {
                    t->in_ring = TRUE;
                    t->last_slot_idx = slot_idx;
                }
                /* If publish failed (ring full) we fall through to
                 * re-arm anyway; the lost event is the coalesced one. */
            }

            /* Re-arm for next period (rate_ms>0) or remove (one-shot).
             * SetTimer is always periodic in Win32 (KillTimer ends it),
             * so rate_ms>0 always; keep the one-shot branch for safety. */
            wheel_remove( t );
            if (t->rate_ms && !t->cancelled)
            {
                t->deadline_mono_ns += (LONGLONG)t->rate_ms * 1000000LL;
                if (t->deadline_mono_ns < now_ns)
                    t->deadline_mono_ns = now_ns + (LONGLONG)t->rate_ms * 1000000LL;
                wheel_insert_sorted( t );
            }
        }

        /* Step 3: compute next wake.  Entries with in_ring set but
         * their deadline passed contribute a short poll interval so we
         * recheck coalescing promptly. */
        LIST_FOR_EACH_ENTRY( t, &wm_timer_wheel, struct nspa_wm_timer, wheel_entry )
        {
            mono_ns_to_timespec( t->deadline_mono_ns, &wait_until );
            have_deadline = TRUE;
            break;
        }

        /* If any entry is waiting on a slot drain (in_ring=TRUE), poll
         * at least every 1ms so we can re-arm on the next period. */
        {
            LONGLONG poll_until = now_ns + 1000000LL;    /* 1ms */
            struct nspa_wm_timer *any_pending = NULL;
            LIST_FOR_EACH_ENTRY( t, &wm_timer_wheel, struct nspa_wm_timer, wheel_entry )
                if (t->in_ring) { any_pending = t; break; }
            if (any_pending)
            {
                struct timespec poll_ts;
                mono_ns_to_timespec( poll_until, &poll_ts );
                if (!have_deadline ||
                    poll_ts.tv_sec < wait_until.tv_sec ||
                    (poll_ts.tv_sec == wait_until.tv_sec && poll_ts.tv_nsec < wait_until.tv_nsec))
                {
                    wait_until = poll_ts;
                    have_deadline = TRUE;
                }
            }
        }

        if (have_deadline)
            pi_cond_timedwait( &wm_timer_wake, &wm_timer_lock, &wait_until );
        else
            pi_cond_wait( &wm_timer_wake, &wm_timer_lock );
    }

    pi_mutex_unlock( &wm_timer_lock );
    return NULL;
}

static NTSTATUS ensure_dispatcher_started(void)
{
    int err;
    if (wm_timer_thread_started) return STATUS_SUCCESS;
    /* Pure pthread is fine: the dispatcher only touches shared memory
     * (ring slots) and pthread/futex primitives — no wineserver session
     * required because peer_shm is resolved and cached by the caller
     * thread at SetTimer time. */
    if ((err = pthread_create( &wm_timer_thread, NULL, wm_timer_dispatcher_main, NULL )))
    {
        ERR( "Failed to start WM_TIMER dispatcher: %d\n", err );
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    wm_timer_thread_started = 1;
    return STATUS_SUCCESS;
}

/*--------------------------------------------------------------------------
 * Public API (called from dlls/win32u/message.c NtUserSetTimer /
 * NtUserKillTimer / NtUserSetSystemTimer / NtUserKillSystemTimer +
 * peek_message).
 *
 * Each entry point returns STATUS_NOT_IMPLEMENTED for "caller must
 * fall through to server"; other status means we handled it.
 *--------------------------------------------------------------------------*/

/* Set or re-arm a local WM_TIMER.  Returns STATUS_SUCCESS and puts the
 * timer id in *out_id.  STATUS_NOT_IMPLEMENTED => fall through to
 * server (id=0, cross-process hwnd, or gate off). */
NTSTATUS nspa_local_wm_timer_set( HWND hwnd, UINT_PTR id, UINT timeout,
                                  UINT msg, WNDPROC winproc, UINT_PTR *out_id )
{
    struct nspa_wm_timer *entry;
    DWORD owner_tid, owner_pid;
    const nspa_queue_bypass_shm_t *peer_shm;
    NTSTATUS ret;

    if (!nspa_wm_timers_active()) return STATUS_NOT_IMPLEMENTED;

    /* Auto-ID assignment stays server-side to avoid any collision with
     * server-allocated IDs (server's range 0x100..0x7fff is on queue
     * scope, our process scope is wider — too messy to dedupe). */
    if (!id || !hwnd) return STATUS_NOT_IMPLEMENTED;

    /* Resolve hwnd owner; must be in this process to use local path. */
    owner_tid = get_window_thread( hwnd, &owner_pid );
    if (!owner_tid) return STATUS_NOT_IMPLEMENTED;
    if (owner_pid != GetCurrentProcessId()) return STATUS_NOT_IMPLEMENTED;

    /* Resolve the owner's memfd shm pointer from THIS thread, which has
     * a wineserver session.  The dispatcher thread does not — it just
     * writes to this cached pointer when the timer fires. */
    if (owner_tid == GetCurrentThreadId())
        peer_shm = nspa_get_own_bypass_shm_public();
    else
        peer_shm = nspa_get_peer_bypass_shm_public( owner_tid );
    if (!peer_shm) return STATUS_NOT_IMPLEMENTED;
    if (!peer_shm->nspa_timer_ring.active) return STATUS_NOT_IMPLEMENTED;

    pi_mutex_lock( &wm_timer_lock );

    if ((entry = find_entry( hwnd, id, msg )))
    {
        /* Re-arm: update rate/winproc/deadline; preserve handle. */
        wheel_remove( entry );
        entry->cancelled = FALSE;
        entry->rate_ms   = timeout;
        entry->winproc   = winproc;
        entry->deadline_mono_ns = mono_now_ns() + (LONGLONG)timeout * 1000000LL;
        wheel_insert_sorted( entry );
    }
    else
    {
        if (!(entry = calloc( 1, sizeof(*entry) )))
        {
            pi_mutex_unlock( &wm_timer_lock );
            return STATUS_NO_MEMORY;
        }
        entry->hwnd      = hwnd;
        entry->id        = id;
        entry->msg       = msg;
        entry->rate_ms   = timeout;
        entry->winproc   = winproc;
        entry->owner_tid = owner_tid;
        entry->peer_shm  = peer_shm;
        entry->deadline_mono_ns = mono_now_ns() + (LONGLONG)timeout * 1000000LL;

        list_add_tail( bucket_for( hwnd, id ), &entry->table_entry );
        wheel_insert_sorted( entry );
    }

    if ((ret = ensure_dispatcher_started()))
    {
        wheel_remove( entry );
        list_remove( &entry->table_entry );
        pi_mutex_unlock( &wm_timer_lock );
        free( entry );
        return ret;
    }

    pi_mutex_unlock( &wm_timer_lock );
    pi_cond_signal( &wm_timer_wake, &wm_timer_lock );

    *out_id = id;
    return STATUS_SUCCESS;
}

/* Kill a local WM_TIMER.  STATUS_SUCCESS if we owned it; otherwise
 * STATUS_NOT_IMPLEMENTED so caller falls through to server.  NT
 * guarantees any WM_TIMER already in the queue at KillTimer time is
 * still delivered — our ring slot (if published) stays READY and
 * peek_message will drain it normally. */
NTSTATUS nspa_local_wm_timer_kill( HWND hwnd, UINT_PTR id, UINT msg )
{
    struct nspa_wm_timer *entry;

    if (!nspa_wm_timers_active()) return STATUS_NOT_IMPLEMENTED;

    pi_mutex_lock( &wm_timer_lock );
    if (!(entry = find_entry( hwnd, id, msg )))
    {
        pi_mutex_unlock( &wm_timer_lock );
        return STATUS_NOT_IMPLEMENTED;
    }

    wheel_remove( entry );
    list_remove( &entry->table_entry );
    entry->cancelled = TRUE;
    /* entry->in_ring slot (if any) stays READY in the ring; pump
     * will drain it and peek_message will deliver WM_TIMER as
     * NT semantics require. */
    pi_mutex_unlock( &wm_timer_lock );

    free( entry );
    return STATUS_SUCCESS;
}

/* Consumer-side drain.  Called from peek_message before the server
 * get_message RTT.  Pops at most one slot matching the filters and
 * fills the out params.  Returns TRUE if a slot was popped. */
BOOL nspa_try_pop_own_timer_ring( HWND filter_hwnd, UINT first, UINT last,
                                  HWND *out_hwnd, UINT *out_msg,
                                  WPARAM *out_wparam, LPARAM *out_lparam,
                                  DWORD *out_time )
{
    const nspa_queue_bypass_shm_t *shm;
    volatile nspa_timer_ring_t *ring;
    unsigned int head, tail, i, slots;
    HWND slot_hwnd;
    UINT slot_msg;

    if (!nspa_wm_timers_active()) return FALSE;

    shm = nspa_get_own_bypass_shm_public();
    if (!shm) return FALSE;
    ring = (volatile nspa_timer_ring_t *)&shm->nspa_timer_ring;
    if (!ring->active) return FALSE;

    head = __atomic_load_n( &ring->head, __ATOMIC_ACQUIRE );
    tail = __atomic_load_n( &ring->tail, __ATOMIC_RELAXED );
    slots = NSPA_TIMER_RING_SLOTS;

    /* Scan from tail up to head; deliver the first slot that matches
     * the peek_message filters.  Ordering by head-advance gives FIFO
     * within the ring, which matches server's expired_timers list. */
    for (i = 0; (tail + i) != head && i < slots; i++)
    {
        volatile nspa_timer_slot_t *slot = &ring->slots[(tail + i) & (slots - 1)];
        unsigned int state = __atomic_load_n( &slot->state, __ATOMIC_ACQUIRE );

        if (state != NSPA_TIMER_STATE_READY) continue;

        slot_hwnd = UlongToHandle( slot->win );
        slot_msg  = slot->msg;

        if (filter_hwnd && filter_hwnd != (HWND)-1 && slot_hwnd != filter_hwnd) continue;
        if (first != 0 || last != (UINT)~0U)
            if (slot_msg < first || slot_msg > last) continue;

        *out_hwnd   = slot_hwnd;
        *out_msg    = slot_msg;
        *out_wparam = (WPARAM)slot->timer_id;
        *out_lparam = 0;                /* winproc was stamped server-side as lparam;
                                         * in local path we treat the handler as
                                         * the default DispatchMessage path — apps
                                         * that registered a TIMERPROC via
                                         * alloc_winproc use winproc on the server
                                         * path.  Matches behaviour for callers
                                         * that pass proc=NULL (the common case). */
        *out_time   = slot->time;

        __atomic_store_n( &slot->state, NSPA_TIMER_STATE_CONSUMED, __ATOMIC_RELEASE );

        /* Advance tail past any leading CONSUMED/EMPTY slots so the
         * producer can recycle without scanning far. */
        {
            unsigned int t2 = tail;
            while (t2 != head)
            {
                volatile nspa_timer_slot_t *s = &ring->slots[t2 & (slots - 1)];
                unsigned int st = __atomic_load_n( &s->state, __ATOMIC_ACQUIRE );
                if (st != NSPA_TIMER_STATE_CONSUMED && st != NSPA_TIMER_STATE_EMPTY) break;
                __atomic_store_n( &s->state, NSPA_TIMER_STATE_EMPTY, __ATOMIC_RELEASE );
                t2++;
            }
            __atomic_store_n( &ring->tail, t2, __ATOMIC_RELEASE );
        }
        return TRUE;
    }
    return FALSE;
}
