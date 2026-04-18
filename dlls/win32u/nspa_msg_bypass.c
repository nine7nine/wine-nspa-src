/*
 * NSPA cross-thread SendMessage bypass — per-queue shmem ring fast path.
 *
 * Routes same-process MSG_POSTED / MSG_NOTIFY / MSG_ASCII / MSG_UNICODE
 * directly into the receiving thread's shmem ring and wakes the receiver
 * via its queue's ntsync event.
 *
 * POSTED / NOTIFY are asynchronous: sender publishes and returns.
 * ASCII / UNICODE are synchronous: sender allocates a reply slot in its
 * own per-queue reply ring, publishes the message with a reference to the
 * reply slot, then waits on its own queue sync.  The receiver dispatches
 * the window proc as normal, then writes the result into the sender's
 * reply slot and signals the sender's queue sync with EVENT_SET_PI.
 *
 * Scope is same-process only (the ring addresses are session-shared but
 * HWND / WPARAM / LPARAM meaning is per-process).  Cross-process, DDE,
 * hooked hardware paths, and callback sends all fall back to the server.
 *
 * Design doc: docs/send-message-bypass-design.md (§5.2, §15)
 */

#if 0
#pragma makedep unix
#endif

#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

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
WINE_DECLARE_DEBUG_CHANNEL(nspa_bypass);


/* ---------------------------------------------------------------------
 * Per-thread cache of peer queues we've sent to.
 *
 * Open-addressed linear-probed hash on wineserver thread_id.  Small and
 * bounded (32 entries) — far more than a DAW thread typically targets
 * in a 30-second window.  Entries cache the peer queue bypass object's
 * shared-object locator (id + offset) and sync handle; we re-resolve the
 * shared object on each use so thread exit / queue teardown / TID reuse
 * don't leave us writing through a raw stale queue pointer.
 * --------------------------------------------------------------------- */

#define NSPA_CACHE_SLOTS 32

struct nspa_cache_entry
{
    DWORD                tid;            /* 0 = empty slot */
    HANDLE               sync_handle;    /* event handle for queue->sync */
    nspa_queue_bypass_shm_t *mapped_ptr; /* mmap of peer's bypass memfd (or NULL for negative cache) */
    size_t               mapped_size;    /* for munmap on clear */
};

/* Per-thread cache via pthread_key + lazy heap allocation.
 *
 * ELF __thread TLS was tried first, but PE-created threads in Ableton
 * (DWM-Sync, AudioCalc, VST hosts) fault on their first access to a
 * __thread static declared inside win32u — the dynamic-TLS block for
 * this module isn't set up for every PE-spawned thread by the time it
 * enters win32u.  The fault is swallowed by PE-side SEH and the thread
 * retries on the next message, burning 100% CPU without surfacing any
 * error (see project_msg_bypass_tls_fault.md).
 *
 * pthread TLS is initialised by glibc at pthread_create (which Wine
 * uses to back CreateThread), so pthread_getspecific is safe on any
 * thread that the process's scheduler can dispatch, regardless of
 * which TEB/loader layer created it.  Lazy heap allocation on first
 * access keeps cost to one calloc per message-sending thread.
 */
static pthread_key_t nspa_cache_tls_key;
static pthread_once_t nspa_cache_tls_once = PTHREAD_ONCE_INIT;

static void nspa_cache_tls_destructor( void *p )
{
    free( p );
}

static void nspa_cache_tls_init_once( void )
{
    pthread_key_create( &nspa_cache_tls_key, nspa_cache_tls_destructor );
}

/* Returns this thread's cache array, allocating on first use.
 * Returns NULL if allocation failed — caller must fall back to server. */
static struct nspa_cache_entry *nspa_cache_get( void )
{
    struct nspa_cache_entry *cache;

    pthread_once( &nspa_cache_tls_once, nspa_cache_tls_init_once );

    cache = pthread_getspecific( nspa_cache_tls_key );
    if (cache) return cache;

    cache = calloc( NSPA_CACHE_SLOTS, sizeof(*cache) );
    if (!cache) return NULL;

    if (pthread_setspecific( nspa_cache_tls_key, cache ) != 0)
    {
        free( cache );
        return NULL;
    }
    return cache;
}

static BOOL nspa_bypass_disabled( void )
{
    static int cached = -1;

    if (cached == -1)
    {
        /* Opt-in: off by default while the feature is being stabilised.
         * Legacy NSPA_DISABLE_MSG_BYPASS=1 still forces off. */
        if (getenv( "NSPA_DISABLE_MSG_BYPASS" )) cached = 1;
        else if (getenv( "NSPA_ENABLE_MSG_BYPASS" )) cached = 0;
        else cached = 1;
    }
    return cached;
}

/* ---------------------------------------------------------------------
 * Ring helpers — atomic ops over shared memory.
 *
 * Head is MPSC (many producers), tail is SPSC (single consumer = owner
 * of the queue).  Slot state transitions:
 *   EMPTY -> WRITING (CAS during reserve)
 *   WRITING -> READY (release store after fill)
 *   READY -> CONSUMED (release store after dispatch)
 *   CONSUMED -> EMPTY (server-side tail advance during dequeue)
 * --------------------------------------------------------------------- */

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

static struct nspa_cache_entry *nspa_cache_find( struct nspa_cache_entry *cache, DWORD tid )
{
    unsigned int h = (tid * 2654435761u) & (NSPA_CACHE_SLOTS - 1);
    unsigned int i;

    for (i = 0; i < NSPA_CACHE_SLOTS; i++)
    {
        struct nspa_cache_entry *e = &cache[(h + i) & (NSPA_CACHE_SLOTS - 1)];
        if (e->tid == tid) return e;
        if (e->tid == 0)   return e;   /* first free slot — reserve for caller */
    }
    return NULL; /* table full */
}

static void nspa_clear_cache_entry( struct nspa_cache_entry *entry )
{
    HANDLE sync_handle = entry->sync_handle;
    void *mapped = (void *)entry->mapped_ptr;
    size_t mapped_size = entry->mapped_size;

    memset( entry, 0, sizeof(*entry) );
    if (mapped && mapped_size) munmap( mapped, mapped_size );
    if (sync_handle) NtClose( sync_handle );
}

static const nspa_queue_bypass_shm_t *nspa_get_cached_bypass_shm( const struct nspa_cache_entry *entry )
{
    /* Post-memfd-redesign: the shmem is a private mmap held by this cache
     * entry. No session-shmem lookup needed. NULL mapped_ptr = negative
     * cache (peer has no bypass ring available). */
    if (!entry->tid || !entry->mapped_ptr) return NULL;
    return entry->mapped_ptr;
}

/* Do the server lookup to populate a cache slot.  Returns TRUE on success. */
static BOOL nspa_populate_cache_entry( DWORD tid, struct nspa_cache_entry *entry )
{
    HANDLE sync_handle = 0;
    unsigned int has_bypass_fd = 0;
    NTSTATUS status;
    int fd = -1;
    void *map = NULL;
    size_t map_size = sizeof(nspa_queue_bypass_shm_t);

    SERVER_START_REQ( nspa_get_thread_queue )
    {
        req->tid = tid;
        if (!(status = wine_server_call( req )))
        {
            sync_handle   = wine_server_ptr_handle( reply->sync_handle );
            /* Phase-1 sentinel: bypass_locator.id != 0 means server sent an
             * fd via SCM_RIGHTS on this reply.  Phase 2 replaces the
             * sentinel with a proper protocol field. */
            has_bypass_fd = (unsigned int)reply->bypass_locator.id;
        }
    }
    SERVER_END_REQ;

    if (status || !sync_handle) return FALSE;

    if (!has_bypass_fd)
    {
        /* Server has no bypass ring for this peer — close the sync handle
         * we don't need and let the caller install a negative-cache
         * sentinel (tid set, mapped_ptr NULL).  Returning FALSE is the
         * existing contract for "peer unreachable via bypass". */
        NtClose( sync_handle );
        return FALSE;
    }

    {
        obj_handle_t fd_token = 0;
        fd = wine_server_receive_fd( &fd_token );
        if (fd == -1 || wine_server_ptr_handle( fd_token ) != sync_handle)
        {
            /* Protocol mismatch — close what we have and fall back. */
            if (fd != -1) close( fd );
            NtClose( sync_handle );
            return FALSE;
        }

        /* MAP_POPULATE prefaults all pages so the RT fast path never takes
         * a minor page fault on first ring access.  Size is small (10 KB),
         * prefault cost is fixed and paid once per peer off the RT path. */
        map = mmap( NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0 );
        close( fd );   /* mmap holds its own reference */

        if (map == MAP_FAILED)
        {
            NtClose( sync_handle );
            return FALSE;
        }

        /* mlock the region so no future demand-paging happens on RT-critical
         * ring accesses.  If mlock fails (RLIMIT_MEMLOCK), we log and
         * continue — the bypass still works, just may take minor faults on
         * the first touch of a cold page under memory pressure. */
        if (mlock( map, map_size ) != 0)
            TRACE_(nspa_bypass)( "mlock failed for tid=%04x (RLIMIT_MEMLOCK?); continuing without pinning\n",
                                 (UINT)tid );
    }

    /* Positive cache (has_bypass_fd) OR negative cache (bypass inert for
     * this peer).  Negative cache is represented by tid set + mapped_ptr
     * NULL; it avoids re-issuing the server round-trip on every subsequent
     * send to the same peer. */
    entry->tid         = tid;
    entry->sync_handle = sync_handle;
    entry->mapped_ptr  = (nspa_queue_bypass_shm_t *)map;
    entry->mapped_size = map ? map_size : 0;
    return TRUE;
}

/* Return cache entry for @tid, populating via server if necessary.
 * Returns NULL on failure (should fall back to server for this send).
 *
 * Negative caching: we mark a slot as "known-unreachable" for a tid by
 * setting entry->tid=tid and leaving entry->sync_handle=0.  This avoids
 * re-issuing a wineserver round-trip on every subsequent send to a
 * cross-process destination (the server correctly rejects it every time
 * but the round-trip itself is visible, and measurably so — see the
 * regression notes in docs/send-message-bypass-design.md §15.4). */
static struct nspa_cache_entry *nspa_lookup_peer( DWORD tid )
{
    struct nspa_cache_entry *cache, *entry;

    if (!tid) return NULL;

    if (!(cache = nspa_cache_get())) return NULL;  /* TLS alloc failed */

    entry = nspa_cache_find( cache, tid );
    if (!entry) return NULL;       /* cache full */
    if (entry->tid == tid)
    {
        /* Positive cache: mapped_ptr holds the peer's ring mmap. */
        if (entry->mapped_ptr) return entry;
        /* Negative cache: tid set, mapped_ptr NULL (server had no bypass). */
        return NULL;
    }

    if (!nspa_populate_cache_entry( tid, entry ))
    {
        /* Leave a negative-cache sentinel so we don't retry on every post. */
        entry->tid         = tid;
        entry->sync_handle = NULL;
        entry->mapped_ptr  = NULL;
        entry->mapped_size = 0;
        return NULL;
    }
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
    const nspa_queue_bypass_shm_t *queue_bypass;
    volatile nspa_msg_ring_t *ring;
    volatile nspa_msg_slot_t *slot;
    NTSTATUS status;
    unsigned int idx;

    if (nspa_bypass_disabled())
    {
        TRACE_(nspa_bypass)( "skip disabled tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

    /* This increment: MSG_POSTED only.  Other types fall through. */
    if (type_enum != MSG_POSTED)
    {
        TRACE_(nspa_bypass)( "skip not-posted type=%u tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             type_enum, HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

    /* Original design scope is same-process cross-thread window messages.
     * Thread-messages (hwnd == 0) and same-thread posts have semantics the
     * ring does not currently preserve — e.g. WebView2 / auth pumps expect
     * PostThreadMessage and self-post to match the server's queue rules
     * exactly — so fall back to the server path for those. */
    if (!hwnd)
    {
        TRACE_(nspa_bypass)( "skip thread-msg tid=%04x dest=%04x msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, msg );
        return FALSE;
    }
    if (dest_tid == HandleToULong( NtCurrentTeb()->ClientId.UniqueThread ))
    {
        TRACE_(nspa_bypass)( "skip self-post tid=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

    /* No DDE through the ring — the server handles DDE specially. */
    if (msg >= WM_DDE_FIRST && msg <= WM_DDE_LAST)
    {
        TRACE_(nspa_bypass)( "skip dde tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

    entry = nspa_lookup_peer( dest_tid );
    if (!entry)
    {
        TRACE_(nspa_bypass)( "skip lookup-fail tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

    queue_bypass = nspa_get_cached_bypass_shm( entry );
    if (!queue_bypass)
    {
        TRACE_(nspa_bypass)( "skip no-bypass-shm tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        nspa_clear_cache_entry( entry );
        return FALSE;
    }

    ring = &((nspa_queue_bypass_shm_t *)queue_bypass)->nspa_msg_ring;
    if (!ring->active)
    {
        TRACE_(nspa_bypass)( "skip ring-inactive tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

    idx = ring_reserve_slot( ring );
    if (idx == ~0u)
    {
        TRACE_(nspa_bypass)( "skip ring-full tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

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

    /* Publish queue-visible pending state before making the slot READY.
     * The server uses ring-owned pending_count to know there is posted
     * work to arbitrate, even if it races a writer that hasn't completed
     * the slot payload yet. */
    __atomic_fetch_add( &ring->pending_count, 1, __ATOMIC_ACQ_REL );

    /* Allocate the canonical posted sequence immediately before READY so
     * ordering tracks publication, not reserve time. */
    slot->post_seq = __atomic_add_fetch( &ring->next_post_seq, 1, __ATOMIC_RELAXED );

    /* Publish — consumer can read the slot from here on. */
    __atomic_store_n( &slot->state, NSPA_MSG_STATE_READY, __ATOMIC_RELEASE );
    __atomic_add_fetch( &ring->change_seq, 1, __ATOMIC_RELEASE );

    status = wine_server_signal_internal_sync( entry->sync_handle );
    if (status) status = NtSetEvent( entry->sync_handle, NULL );
    if (status)
    {
        nspa_clear_cache_entry( entry );
        WARN( "failed to signal bypass queue %u\n", dest_tid );
    }
    TRACE_(nspa_bypass)( "post tid=%04x dest=%04x hwnd=%p msg=%04x wp=%lx lp=%lx\n",
                         HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                         (UINT)dest_tid, hwnd, msg, (unsigned long)wparam, (unsigned long)lparam );
    return TRUE;
}


/* ---------------------------------------------------------------------
 * Blocking SendMessage (MSG_ASCII / MSG_UNICODE) — and MSG_NOTIFY async —
 * bypass via peer msg ring + own reply ring.
 *
 * Wire:
 *   sender   reserves a slot in own reply ring (CAS FREE -> PENDING)
 *   sender   fills peer msg slot with type + sender_tid + reply_slot_idx
 *   sender   publishes, signals peer ntsync (EVENT_SET_PI when RT)
 *   receiver dequeues via server get_message (unchanged path)
 *   receiver runs the window proc as normal
 *   receiver calls nspa_write_ring_reply with sender_tid + reply_slot_idx
 *   receiver writes result into sender's reply slot, signals sender sync
 *   sender   wakes, reads result, frees slot, returns
 *
 * For MSG_NOTIFY no reply slot is reserved and the sender returns TRUE
 * immediately after publishing.
 * --------------------------------------------------------------------- */

/* Fetch our own queue's bypass shm (cached per-thread inside winstation). */
static const nspa_queue_bypass_shm_t *nspa_get_own_bypass_shm( void )
{
    struct object_lock lock = OBJECT_LOCK_INIT;
    const queue_shm_t *queue_shm = NULL;
    const nspa_queue_bypass_shm_t *bypass = NULL;
    NTSTATUS status;

    while ((status = get_shared_queue( &lock, &queue_shm )) == STATUS_PENDING)
        bypass = get_queue_bypass_shm( queue_shm );
    if (status) return NULL;
    return bypass;
}

/* Reserve a free reply slot (CAS FREE -> PENDING).  Returns index or ~0u. */
static unsigned int nspa_reply_ring_reserve( volatile nspa_reply_ring_t *ring )
{
    unsigned int start = __atomic_load_n( &ring->next_alloc, __ATOMIC_RELAXED );
    unsigned int i;

    for (i = 0; i < NSPA_REPLY_RING_SLOTS; i++)
    {
        unsigned int idx = (start + i) & (NSPA_REPLY_RING_SLOTS - 1);
        unsigned int expected = NSPA_REPLY_STATE_FREE;

        if (__atomic_compare_exchange_n( &ring->slots[idx].state, &expected,
                                         NSPA_REPLY_STATE_PENDING, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED ))
        {
            __atomic_store_n( &ring->next_alloc, idx + 1, __ATOMIC_RELAXED );
            return idx;
        }
    }
    return ~0u;
}

/* Write a reply to a remote sender's reply slot and wake them.
 * Called by the receiver after its window proc returns, if the message
 * came from a ring slot (sender_tid != 0, reply_slot_idx in range).
 * Returns TRUE if the reply was delivered; FALSE means the caller
 * should fall back to the server reply_message path. */
BOOL nspa_write_ring_reply( DWORD sender_tid, UINT reply_slot_idx,
                            LRESULT result, const void *data, UINT data_size )
{
    struct nspa_cache_entry *entry;
    const nspa_queue_bypass_shm_t *bypass;
    volatile nspa_reply_slot_t *slot;
    NTSTATUS status;

    if (!sender_tid || reply_slot_idx >= NSPA_REPLY_RING_SLOTS) return FALSE;
    if (data_size > NSPA_REPLY_INLINE_MAX)
    {
        TRACE_(nspa_bypass)( "reply skip data-too-big sender=%04x slot=%u size=%u\n",
                             (UINT)sender_tid, reply_slot_idx, data_size );
        return FALSE;
    }

    entry = nspa_lookup_peer( sender_tid );
    if (!entry)
    {
        TRACE_(nspa_bypass)( "reply skip lookup-fail sender=%04x slot=%u\n",
                             (UINT)sender_tid, reply_slot_idx );
        return FALSE;
    }
    bypass = nspa_get_cached_bypass_shm( entry );
    if (!bypass)
    {
        nspa_clear_cache_entry( entry );
        TRACE_(nspa_bypass)( "reply skip no-bypass-shm sender=%04x slot=%u\n",
                             (UINT)sender_tid, reply_slot_idx );
        return FALSE;
    }

    slot = &((nspa_queue_bypass_shm_t *)bypass)->nspa_reply_ring.slots[reply_slot_idx];

    /* Guard: only write if slot is PENDING — a FREE/READY slot means the
     * sender already timed out or a stale reply; dropping is the right thing. */
    {
        unsigned int state = __atomic_load_n( &slot->state, __ATOMIC_ACQUIRE );
        if (state != NSPA_REPLY_STATE_PENDING)
        {
            TRACE_(nspa_bypass)( "reply drop stale-slot sender=%04x slot=%u state=%u\n",
                                 (UINT)sender_tid, reply_slot_idx, state );
            return FALSE;
        }
    }

    slot->result    = result;
    slot->error     = 0;
    slot->data_size = data_size;
    if (data_size) memcpy( (void *)slot->data, data, data_size );

    __atomic_store_n( &slot->state, NSPA_REPLY_STATE_READY, __ATOMIC_RELEASE );

    status = wine_server_signal_internal_sync( entry->sync_handle );
    if (status) status = NtSetEvent( entry->sync_handle, NULL );
    if (status)
    {
        nspa_clear_cache_entry( entry );
        WARN( "reply: failed to signal sender %u\n", sender_tid );
    }

    TRACE_(nspa_bypass)( "reply written sender=%04x slot=%u result=%lx data=%u\n",
                         (UINT)sender_tid, reply_slot_idx, (unsigned long)result, data_size );
    return TRUE;
}

/* Try the blocking send fast path.  On success, *result_out is filled and
 * TRUE is returned.  FALSE means the caller must fall back to the server
 * send_message path (ineligible, no peer, ring full, or timeout). */
BOOL nspa_try_send_ring( DWORD dest_tid, UINT type_enum, HWND hwnd,
                         UINT msg, LPARAM wparam, LPARAM lparam,
                         LRESULT *result_out )
{
    struct nspa_cache_entry *entry;
    const nspa_queue_bypass_shm_t *dest_bypass, *own_bypass;
    volatile nspa_msg_ring_t *ring;
    volatile nspa_msg_slot_t *slot;
    volatile nspa_reply_slot_t *reply_slot = NULL;
    volatile nspa_reply_ring_t *own_reply_ring = NULL;
    HANDLE own_sync = NULL;
    unsigned int msg_idx;
    unsigned int reply_idx = ~0u;
    NTSTATUS status;
    DWORD own_tid;
    BOOL is_notify;
    int waits = 0;

    TRACE_(nspa_bypass)( "PROBE try_send_ring enter dest=%04x type=%u hwnd=%p msg=%04x\n",
                         (UINT)dest_tid, type_enum, hwnd, msg );

    if (nspa_bypass_disabled())
    {
        TRACE_(nspa_bypass)( "send skip disabled dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

    is_notify = (type_enum == MSG_NOTIFY);
    if (type_enum != MSG_ASCII && type_enum != MSG_UNICODE && !is_notify)
    {
        TRACE_(nspa_bypass)( "send skip not-send-type type=%u dest=%04x msg=%04x\n",
                             type_enum, (UINT)dest_tid, msg );
        return FALSE;
    }

    if (!hwnd)
    {
        TRACE_(nspa_bypass)( "send skip thread-msg dest=%04x msg=%04x\n",
                             (UINT)dest_tid, msg );
        return FALSE;
    }
    own_tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );
    if (dest_tid == own_tid)
    {
        TRACE_(nspa_bypass)( "send skip self-send dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }
    if (msg >= WM_DDE_FIRST && msg <= WM_DDE_LAST)
    {
        TRACE_(nspa_bypass)( "send skip dde dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

    entry = nspa_lookup_peer( dest_tid );
    if (!entry)
    {
        TRACE_(nspa_bypass)( "send skip lookup-fail dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

    dest_bypass = nspa_get_cached_bypass_shm( entry );
    if (!dest_bypass)
    {
        nspa_clear_cache_entry( entry );
        TRACE_(nspa_bypass)( "send skip no-bypass-shm dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

    ring = &((nspa_queue_bypass_shm_t *)dest_bypass)->nspa_msg_ring;
    if (!ring->active)
    {
        TRACE_(nspa_bypass)( "send skip ring-inactive dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        return FALSE;
    }

    /* Sync sends need our own reply ring + sync handle. */
    if (!is_notify)
    {
        own_bypass = nspa_get_own_bypass_shm();
        if (!own_bypass)
        {
            TRACE_(nspa_bypass)( "send skip no-own-bypass dest=%04x msg=%04x\n",
                                 (UINT)dest_tid, msg );
            return FALSE;
        }
        own_reply_ring = &((nspa_queue_bypass_shm_t *)own_bypass)->nspa_reply_ring;
        reply_idx = nspa_reply_ring_reserve( own_reply_ring );
        if (reply_idx == ~0u)
        {
            TRACE_(nspa_bypass)( "send skip reply-ring-full dest=%04x msg=%04x\n",
                                 (UINT)dest_tid, msg );
            return FALSE;
        }
        own_sync = nspa_get_own_server_queue_handle();
        if (!own_sync)
        {
            __atomic_store_n( &own_reply_ring->slots[reply_idx].state,
                              NSPA_REPLY_STATE_FREE, __ATOMIC_RELEASE );
            TRACE_(nspa_bypass)( "send skip no-own-sync dest=%04x msg=%04x\n",
                                 (UINT)dest_tid, msg );
            return FALSE;
        }
        reply_slot = &own_reply_ring->slots[reply_idx];
        /* The slot's state is PENDING (set by the CAS in reserve) so it is
         * visible to a receiver that looks it up by index.  Reset result
         * payload before the receiver sees us as PENDING. */
        reply_slot->result    = 0;
        reply_slot->error     = 0;
        reply_slot->data_size = 0;
        reply_slot->generation++;   /* discriminates against stale writebacks */
    }

    msg_idx = ring_reserve_slot( ring );
    if (msg_idx == ~0u)
    {
        if (reply_slot)
            __atomic_store_n( &reply_slot->state, NSPA_REPLY_STATE_FREE, __ATOMIC_RELEASE );
        TRACE_(nspa_bypass)( "send skip ring-full dest=%04x msg=%04x\n",
                             (UINT)dest_tid, msg );
        return FALSE;
    }

    slot = &ring->slots[msg_idx & (NSPA_MSG_RING_SLOTS - 1)];
    __atomic_store_n( &slot->state, NSPA_MSG_STATE_WRITING, __ATOMIC_RELAXED );

    slot->type       = type_enum;
    slot->win        = (UINT)(UINT_PTR)hwnd;
    slot->msg        = msg;
    slot->wparam     = (ULONG_PTR)wparam;
    slot->lparam     = (ULONG_PTR)lparam;
    slot->x          = 0;
    slot->y          = 0;
    slot->time       = NtGetTickCount();
    slot->sender_tid = own_tid;
    slot->sender_pid = HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess );
    slot->reply_slot = is_notify ? ~0u : reply_idx;
    slot->data_size  = 0;

    __atomic_fetch_add( &ring->pending_count, 1, __ATOMIC_ACQ_REL );
    __atomic_fetch_add( &ring->pending_send_count, 1, __ATOMIC_ACQ_REL );
    slot->post_seq = __atomic_add_fetch( &ring->next_post_seq, 1, __ATOMIC_RELAXED );

    __atomic_store_n( &slot->state, NSPA_MSG_STATE_READY, __ATOMIC_RELEASE );
    __atomic_add_fetch( &ring->change_seq, 1, __ATOMIC_RELEASE );

    status = wine_server_signal_internal_sync( entry->sync_handle );
    if (status) status = NtSetEvent( entry->sync_handle, NULL );
    if (status)
    {
        nspa_clear_cache_entry( entry );
        WARN( "send: failed to signal %u\n", dest_tid );
    }

    TRACE_(nspa_bypass)( "send posted tid=%04x dest=%04x type=%u msg=%04x slot=%u reply=%u\n",
                         own_tid, (UINT)dest_tid, type_enum, msg, msg_idx, reply_idx );

    if (is_notify) return TRUE;

    /* Wait for reply.  queue->sync is manual-reset and shared with ordinary
     * pump traffic, so we poll the reply state with a short timeout rather
     * than blocking indefinitely on the event.  5 s total cap before giving
     * up and returning FALSE (caller falls back to server).
     *
     * Cross-send deadlock protection: if the peer's winproc SendMessages
     * back to us while we are waiting, we must pump those incoming SEND
     * messages.  Otherwise peer blocks on its own reply waiting for us to
     * dispatch, and we block on our reply waiting for peer — classic
     * deadlock.  Mirror wait_message_reply's QS_SENDMESSAGE drain. */
    for (;;)
    {
        unsigned int state = __atomic_load_n( &reply_slot->state, __ATOMIC_ACQUIRE );
        LARGE_INTEGER timeout;

        if (state == NSPA_REPLY_STATE_READY) break;
        if (waits > 500)  /* 500 * 10 ms = 5 s */
        {
            TRACE_(nspa_bypass)( "send timeout dest=%04x msg=%04x slot=%u\n",
                                 (UINT)dest_tid, msg, reply_idx );
            __atomic_store_n( &reply_slot->state, NSPA_REPLY_STATE_FREE, __ATOMIC_RELEASE );
            return FALSE;
        }
        /* Drain inbound SEND messages before waiting so a peer that has
         * called back into us can make forward progress. */
        nspa_process_sent_messages();
        /* Re-check state after the drain — peer may have replied during it. */
        state = __atomic_load_n( &reply_slot->state, __ATOMIC_ACQUIRE );
        if (state == NSPA_REPLY_STATE_READY) break;
        timeout.QuadPart = -100000LL;  /* 10 ms */
        NtWaitForSingleObject( own_sync, FALSE, &timeout );
        waits++;
    }

    *result_out = reply_slot->result;
    __atomic_store_n( &reply_slot->state, NSPA_REPLY_STATE_FREE, __ATOMIC_RELEASE );

    TRACE_(nspa_bypass)( "send got-reply dest=%04x msg=%04x result=%lx waits=%d\n",
                         (UINT)dest_tid, msg, (unsigned long)*result_out, waits );
    return TRUE;
}
