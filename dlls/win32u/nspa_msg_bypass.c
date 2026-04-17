/*
 * NSPA cross-thread SendMessage bypass — per-queue shmem ring fast path.
 *
 * Routes same-process MSG_POSTED / MSG_NOTIFY (and in a later increment
 * MSG_ASCII / MSG_UNICODE) directly into the receiving thread's shmem
 * ring and wakes the receiver via its queue's ntsync event.  This removes
 * ~80% of wineserver traffic measured during Ableton playback.
 *
 * Scope this increment: MSG_POSTED only.  Blocking SendMessage + reply
 * ring wiring + EVENT_SET_PI integration come in a follow-up.
 *
 * Design doc: docs/send-message-bypass-design.md
 */

#if 0
#pragma makedep unix
#endif

#include <stddef.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "winternl.h"
#include "win32u_private.h"
#include "ntuser_private.h"
#include "dde.h"
#include "wine/debug.h"

/* message_type enum from server protocol (same values used internally) */
#include "wine/server.h"

WINE_DEFAULT_DEBUG_CHANNEL(msg);


/* ---------------------------------------------------------------------
 * Per-thread cache of peer queues we've sent to.
 *
 * Open-addressed linear-probed hash on wineserver thread_id.  Small and
 * bounded (32 entries) — far more than a DAW thread typically targets
 * in a 30-second window.  Cache entries are never invalidated
 * proactively; if a slot holds a stale tid (thread exited), the NtSetEvent
 * on sync_handle will fail and we fall back to the server path, which
 * properly detects the dead thread.
 * --------------------------------------------------------------------- */

#define NSPA_CACHE_SLOTS 32

struct nspa_cache_entry
{
    DWORD                tid;            /* 0 = empty slot */
    const queue_shm_t   *queue_shm;      /* session-shared queue for that tid */
    HANDLE               sync_handle;    /* event handle for queue->sync */
    ULONG                object_id;      /* shared_object_t.id at lookup time (stale-detect) */
};

/* Per-thread state lives in user_thread_info via a dedicated field.
 * For this first cut we keep the table static-per-thread using TLS
 * allocated lazily on first use. */
static __thread struct nspa_cache_entry nspa_cache[NSPA_CACHE_SLOTS];
static __thread int nspa_cache_init_done;

/* ---------------------------------------------------------------------
 * Ring helpers — atomic ops over shared memory.
 *
 * Head is MPSC (many producers), tail is SPSC (single consumer = owner
 * of the queue).  Slot state transitions:
 *   EMPTY -> WRITING (CAS during reserve)
 *   WRITING -> READY (release store after fill)
 *   READY -> CONSUMED (release store after dispatch)
 *   CONSUMED -> EMPTY (relaxed store during tail advance)
 * --------------------------------------------------------------------- */

static inline unsigned int ring_load_head( const volatile nspa_msg_ring_t *ring )
{
    return __atomic_load_n( &ring->head, __ATOMIC_ACQUIRE );
}

static inline unsigned int ring_load_tail( const volatile nspa_msg_ring_t *ring )
{
    return __atomic_load_n( &ring->tail, __ATOMIC_ACQUIRE );
}

/* Reserve a slot index via CAS.  Returns U32_MAX on FULL. */
static unsigned int ring_reserve_slot( volatile nspa_msg_ring_t *ring )
{
    unsigned int head, tail, next;

    for (;;)
    {
        head = __atomic_load_n( &ring->head, __ATOMIC_RELAXED );
        tail = __atomic_load_n( &ring->tail, __ATOMIC_ACQUIRE );
        if (head - tail >= NSPA_MSG_RING_SLOTS)
        {
            __atomic_fetch_add( &ring->overflow, 1, __ATOMIC_RELAXED );
            return ~0u;
        }
        next = head + 1;
        if (__atomic_compare_exchange_n( &ring->head, &head, next, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED ))
            return head;
    }
}


/* ---------------------------------------------------------------------
 * Peer queue lookup — called on first send to a tid.
 *
 * Returns TRUE with entry filled in on success, FALSE if the server
 * rejected the lookup (thread gone, no queue) or if we ran out of cache
 * slots.
 * --------------------------------------------------------------------- */

static void nspa_cache_init( void )
{
    if (nspa_cache_init_done) return;
    memset( nspa_cache, 0, sizeof(nspa_cache) );
    nspa_cache_init_done = 1;
}

static struct nspa_cache_entry *nspa_cache_find( DWORD tid )
{
    unsigned int h = (tid * 2654435761u) & (NSPA_CACHE_SLOTS - 1);
    unsigned int i;

    for (i = 0; i < NSPA_CACHE_SLOTS; i++)
    {
        struct nspa_cache_entry *e = &nspa_cache[(h + i) & (NSPA_CACHE_SLOTS - 1)];
        if (e->tid == tid) return e;
        if (e->tid == 0)   return e;   /* first free slot — reserve for caller */
    }
    return NULL; /* table full */
}

/* Do the server lookup to populate a cache slot.  Returns TRUE on success. */
static BOOL nspa_populate_cache_entry( DWORD tid, struct nspa_cache_entry *entry )
{
    struct obj_locator locator = {0};
    HANDLE sync_handle = 0;
    const shared_object_t *object;
    NTSTATUS status;

    SERVER_START_REQ( nspa_get_thread_queue )
    {
        req->tid = tid;
        if (!(status = wine_server_call( req )))
        {
            locator = reply->locator;
            sync_handle = wine_server_ptr_handle( reply->sync_handle );
        }
    }
    SERVER_END_REQ;

    if (status || !sync_handle) return FALSE;

    object = find_shared_session_object( locator.id, locator.offset );
    if (!object) {
        NtClose( sync_handle );
        return FALSE;
    }

    entry->tid         = tid;
    entry->queue_shm   = &object->shm.queue;
    entry->sync_handle = sync_handle;
    entry->object_id   = (ULONG)locator.id;
    return TRUE;
}

/* Return cache entry for @tid, populating via server if necessary.
 * Returns NULL on failure (should fall back to server for this send). */
static struct nspa_cache_entry *nspa_lookup_peer( DWORD tid )
{
    struct nspa_cache_entry *entry;

    if (!tid) return NULL;

    nspa_cache_init();

    entry = nspa_cache_find( tid );
    if (!entry) return NULL;       /* cache full */
    if (entry->tid == tid) return entry;

    if (!nspa_populate_cache_entry( tid, entry )) return NULL;
    return entry;
}


/* ---------------------------------------------------------------------
 * Sender side — MSG_POSTED fast path.
 *
 * nspa_try_post_ring returns TRUE when the message was delivered via
 * the ring; caller should NOT do the server SendMessage in that case.
 * FALSE means "ineligible / failed" — caller does the server path.
 * --------------------------------------------------------------------- */

BOOL nspa_try_post_ring( DWORD dest_tid, UINT type_enum, HWND hwnd,
                         UINT msg, LPARAM wparam, LPARAM lparam )
{
    struct nspa_cache_entry *entry;
    volatile nspa_msg_ring_t *ring;
    volatile nspa_msg_slot_t *slot;
    unsigned int idx;

    /* This increment: MSG_POSTED only.  Other types fall through. */
    if (type_enum != MSG_POSTED) return FALSE;

    /* No DDE through the ring — the server handles DDE specially. */
    if (msg >= WM_DDE_FIRST && msg <= WM_DDE_LAST) return FALSE;

    entry = nspa_lookup_peer( dest_tid );
    if (!entry) return FALSE;

    ring = &((queue_shm_t *)entry->queue_shm)->nspa_msg_ring;
    if (!ring->active) return FALSE;

    /* Skip the ring if a message hook is active on the receiver — the
     * server runs the hook chain for posted messages. */
    if (entry->queue_shm->hooks_count[0 /* WH_MSGFILTER-WH_MINHOOK */] != 0 ||
        entry->queue_shm->hooks_count[3 /* WH_GETMESSAGE-WH_MINHOOK */] != 0)
        return FALSE;

    idx = ring_reserve_slot( ring );
    if (idx == ~0u) return FALSE;   /* FULL — fall back to server */

    slot = &ring->slots[idx & (NSPA_MSG_RING_SLOTS - 1)];

    __atomic_store_n( &slot->state, NSPA_MSG_STATE_WRITING, __ATOMIC_RELAXED );

    slot->type        = MSG_POSTED;
    slot->win         = (UINT)(UINT_PTR)hwnd;
    slot->msg         = msg;
    slot->wparam      = (ULONG_PTR)wparam;
    slot->lparam      = (ULONG_PTR)lparam;
    slot->x           = 0;
    slot->y           = 0;
    slot->time        = NtGetTickCount();
    slot->sender_tid  = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );
    slot->sender_pid  = HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess );
    slot->reply_slot  = ~0u;        /* posted = no reply expected */
    slot->data_size   = 0;

    /* Publish — consumer can read the slot from here on. */
    __atomic_store_n( &slot->state, NSPA_MSG_STATE_READY, __ATOMIC_RELEASE );

    /* Update wake_bits atomically so the receiver's check_queue_bits /
     * get_queue_status sees the pending message even if it hasn't yet
     * drained the ring.  The seqlock is NOT bumped — these fields are
     * single-word atomic OR'd from the server too (no struct-wide write),
     * so torn reads aren't an issue. */
    {
        volatile queue_shm_t *peer = (queue_shm_t *)entry->queue_shm;
        __atomic_fetch_or( (volatile unsigned int *)&peer->wake_bits,
                           QS_POSTMESSAGE | QS_ALLPOSTMESSAGE, __ATOMIC_RELEASE );
        __atomic_fetch_or( (volatile unsigned int *)&peer->changed_bits,
                           QS_POSTMESSAGE | QS_ALLPOSTMESSAGE, __ATOMIC_RELEASE );
    }

    /* Wake the receiver.  Plain NtSetEvent for MSG_POSTED — fire-and-
     * forget, no PI propagation needed (sender is not waiting). */
    NtSetEvent( entry->sync_handle, NULL );
    return TRUE;
}


/* ---------------------------------------------------------------------
 * Receiver side — drain our own ring during peek_message.
 *
 * We walk tail..head looking for the first slot matching the peek
 * filter (hwnd / first / last).  Non-matching slots are left in place
 * for a later peek.  Consuming a non-tail slot creates a "hole" that
 * gets reclaimed when the tail advances past it.
 *
 * Returns TRUE with @msg filled in if a message was dispatched; FALSE
 * means the caller should fall through to the existing server path.
 * --------------------------------------------------------------------- */

static BOOL nspa_slot_matches( const volatile nspa_msg_slot_t *slot,
                               HWND hwnd, UINT first, UINT last )
{
    HWND slot_win = (HWND)(UINT_PTR)slot->win;

    if (hwnd && hwnd != (HWND)-1 && slot_win && slot_win != hwnd)
        return FALSE;
    if (first != 0 || last != ~0u)
    {
        if (slot->msg < first || slot->msg > last) return FALSE;
    }
    return TRUE;
}

BOOL nspa_drain_peek( const queue_shm_t *queue_shm, HWND hwnd, UINT first, UINT last,
                      UINT flags, MSG *msg, UINT *out_type )
{
    volatile nspa_msg_ring_t *ring = (volatile nspa_msg_ring_t *)&queue_shm->nspa_msg_ring;
    unsigned int tail, head, cursor;
    volatile nspa_msg_slot_t *slot;
    BOOL want_remove = !!(flags & PM_REMOVE);
    unsigned int match_idx = ~0u;

    if (!ring->active) return FALSE;

    tail = ring_load_tail( ring );
    head = ring_load_head( ring );

    /* Scan tail..head looking for the first matching READY slot */
    for (cursor = tail; (int)(cursor - head) < 0; cursor++)
    {
        unsigned int slot_idx = cursor & (NSPA_MSG_RING_SLOTS - 1);
        unsigned int state;

        slot = &ring->slots[slot_idx];
        state = __atomic_load_n( &slot->state, __ATOMIC_ACQUIRE );
        if (state == NSPA_MSG_STATE_WRITING) break;  /* head-of-line block */
        if (state != NSPA_MSG_STATE_READY) continue; /* CONSUMED/EMPTY — skip */

        if (nspa_slot_matches( slot, hwnd, first, last ))
        {
            match_idx = cursor;
            break;
        }
    }

    if (match_idx == ~0u) return FALSE;

    slot = &ring->slots[match_idx & (NSPA_MSG_RING_SLOTS - 1)];

    /* Copy out the message fields */
    msg->hwnd    = (HWND)(UINT_PTR)slot->win;
    msg->message = slot->msg;
    msg->wParam  = slot->wparam;
    msg->lParam  = slot->lparam;
    msg->time    = slot->time;
    msg->pt.x    = slot->x;
    msg->pt.y    = slot->y;
    if (out_type) *out_type = slot->type;

    if (!want_remove)
    {
        /* PM_NOREMOVE — peek only, leave slot READY */
        return TRUE;
    }

    /* Consume */
    __atomic_store_n( &slot->state, NSPA_MSG_STATE_CONSUMED, __ATOMIC_RELEASE );

    /* Advance tail past any leading CONSUMED slots */
    cursor = tail;
    while ((int)(cursor - head) < 0)
    {
        unsigned int slot_idx = cursor & (NSPA_MSG_RING_SLOTS - 1);
        unsigned int state = __atomic_load_n( &ring->slots[slot_idx].state,
                                              __ATOMIC_ACQUIRE );
        if (state != NSPA_MSG_STATE_CONSUMED) break;
        __atomic_store_n( &ring->slots[slot_idx].state, NSPA_MSG_STATE_EMPTY,
                          __ATOMIC_RELEASE );
        cursor++;
    }
    if (cursor != tail)
        __atomic_store_n( &ring->tail, cursor, __ATOMIC_RELEASE );

    return TRUE;
}
