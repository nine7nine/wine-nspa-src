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

#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE (FUTEX_WAIT | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_WAKE_PRIVATE
#define FUTEX_WAKE_PRIVATE (FUTEX_WAKE | FUTEX_PRIVATE_FLAG)
#endif

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

/* Per-thread bypass cache size.  Open-addressed linear-probed hash; once
 * full, lookups for unseen tids return NULL with no eviction → the receiver-
 * side reply path falls back to server reply_message, the sender doesn't
 * see its ring slot fill, times out after 5s, and re-dispatches via server
 * send_message → DUPLICATE window proc execution.  Sized at 128 to comfortably
 * cover a DAW main thread receiving from 14 AudioCalc workers + ~20 misc
 * UI/timer/library threads + headroom for VST plugin worker pools.  Cost is
 * 128 × ~32B = 4 KB per producing thread (lazy-allocated). */
#define NSPA_CACHE_SLOTS 128

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
 * T1 SEND/POST diagnostic — rejection-path counters.
 *
 * Opt-in via NSPA_SEND_DIAG=1.  Every exit branch of nspa_try_send_ring
 * and nspa_try_post_ring bumps one atomic counter; a background pthread
 * snapshots /tmp/nspa_send_diag.<pid>.log every 5 seconds and atexit()
 * writes the final snapshot on clean exit.  The 5-second tick makes the
 * dump robust under SIGKILL (which bypasses atexit).
 *
 * Cannot use SIGUSR1/2: Wine's ntdll/unix signal handlers reserve both
 * for thread suspend / context on the client side.
 *
 * Forward-pointing taxonomy — each bucket maps to a scalability response:
 *   REJ_*_RING_FULL    → Vyukov v2 (per-slot seqnum, wider ring, per-class carve-outs)
 *   REJ_NOT_SEND_TYPE  → extend msg-bypass scope (MSG_CALLBACK etc.)
 *   REJ_PEER_*         → bootstrap/ensure-own-bypass plumbing fix
 *   REJ_NO_*_SHM       → session-shmem plumbing fix
 *   REJ_*_OPT_IN_OFF   → gate-logic fix / default-on decision
 * --------------------------------------------------------------------- */

enum nspa_send_reason
{
    SEND_ENTRY = 0,
    SEND_ACCEPT_SYNC,
    SEND_ACCEPT_NOTIFY,
    SEND_REJ_GATE_OFF,
    SEND_REJ_NOT_SEND_TYPE,
    SEND_REJ_NO_HWND,
    SEND_REJ_SELF_SEND,
    SEND_REJ_DDE,
    SEND_REJ_PEER_FIRST_FAIL,
    SEND_REJ_PEER_NEG_CACHE,
    SEND_REJ_NO_DEST_SHM,
    SEND_REJ_RING_INACTIVE,
    SEND_REJ_SEND_OPT_IN_OFF,
    SEND_REJ_NO_OWN_SHM,
    SEND_REJ_REPLY_RING_FULL,
    SEND_REJ_NO_OWN_SYNC,
    SEND_REJ_DEST_RING_FULL,
    SEND_REJ_REPLY_TIMEOUT,
    SEND_REJ_FAULTED_SEH,
    SEND_REASON_NB
};

enum nspa_post_reason
{
    POST_ENTRY = 0,
    POST_ACCEPT,
    POST_REJ_GATE_OFF,
    POST_REJ_NOT_POSTED,
    POST_REJ_NO_HWND,
    POST_REJ_SELF_POST,
    POST_REJ_DDE,
    POST_REJ_PEER_FIRST_FAIL,
    POST_REJ_PEER_NEG_CACHE,
    POST_REJ_NO_DEST_SHM,
    POST_REJ_RING_INACTIVE,
    POST_REJ_DEST_RING_FULL,
    POST_REASON_NB
};

static const char *const nspa_send_reason_name[SEND_REASON_NB] = {
    "entry",
    "accept_sync",
    "accept_notify",
    "rej_gate_off",
    "rej_not_send_type",
    "rej_no_hwnd",
    "rej_self_send",
    "rej_dde",
    "rej_peer_first_fail",
    "rej_peer_neg_cache",
    "rej_no_dest_shm",
    "rej_ring_inactive",
    "rej_send_opt_in_off",
    "rej_no_own_shm",
    "rej_reply_ring_full",
    "rej_no_own_sync",
    "rej_dest_ring_full",
    "rej_reply_timeout",
    "rej_faulted_seh",
};

static const char *const nspa_post_reason_name[POST_REASON_NB] = {
    "entry",
    "accept",
    "rej_gate_off",
    "rej_not_posted",
    "rej_no_hwnd",
    "rej_self_post",
    "rej_dde",
    "rej_peer_first_fail",
    "rej_peer_neg_cache",
    "rej_no_dest_shm",
    "rej_ring_inactive",
    "rej_dest_ring_full",
};

static uint64_t nspa_diag_send[SEND_REASON_NB];
static uint64_t nspa_diag_post[POST_REASON_NB];

/* Per-thread breakdown — informs whether contention is concentrated on a
 * few producer threads (e.g. AudioCalc workers) which is the signal for
 * per-producer class rings in Vyukov v2. */
#define NSPA_DIAG_TID_SLOTS 64
struct nspa_diag_tid
{
    unsigned int tid;            /* 0 = free (CAS-claimed) */
    uint64_t entries;
    uint64_t accepts;
    uint64_t rej_ring_full;      /* SEND dest_ring_full | reply_ring_full, POST dest_ring_full */
    uint64_t rej_peer;           /* PEER_FIRST_FAIL | PEER_NEG_CACHE | NO_DEST_SHM */
    uint64_t rej_type;           /* NOT_SEND_TYPE | NOT_POSTED (scope-miss) */
};
static struct nspa_diag_tid nspa_diag_tids[NSPA_DIAG_TID_SLOTS];
static uint64_t nspa_diag_tid_overflow;

static int nspa_send_diag_enabled( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv( "NSPA_SEND_DIAG" );
        cached = (v && *v && *v != '0');
    }
    return cached;
}

static struct nspa_diag_tid *nspa_diag_tid_slot( unsigned int tid )
{
    unsigned int h = (tid * 2654435761u) & (NSPA_DIAG_TID_SLOTS - 1);
    unsigned int i;

    for (i = 0; i < NSPA_DIAG_TID_SLOTS; i++)
    {
        struct nspa_diag_tid *e = &nspa_diag_tids[(h + i) & (NSPA_DIAG_TID_SLOTS - 1)];
        unsigned int cur = __atomic_load_n( &e->tid, __ATOMIC_ACQUIRE );
        if (cur == tid) return e;
        if (cur == 0)
        {
            unsigned int expected = 0;
            if (__atomic_compare_exchange_n( &e->tid, &expected, tid, 0,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE ))
                return e;
            if (expected == tid) return e;
            /* someone else claimed this slot for a different tid — keep probing */
        }
    }
    __atomic_fetch_add( &nspa_diag_tid_overflow, 1, __ATOMIC_RELAXED );
    return NULL;
}

static void nspa_diag_tid_bump_send( unsigned int tid, enum nspa_send_reason r )
{
    struct nspa_diag_tid *slot = nspa_diag_tid_slot( tid );
    if (!slot) return;

    switch (r)
    {
    case SEND_ENTRY:
        __atomic_fetch_add( &slot->entries, 1, __ATOMIC_RELAXED ); break;
    case SEND_ACCEPT_SYNC:
    case SEND_ACCEPT_NOTIFY:
        __atomic_fetch_add( &slot->accepts, 1, __ATOMIC_RELAXED ); break;
    case SEND_REJ_DEST_RING_FULL:
    case SEND_REJ_REPLY_RING_FULL:
        __atomic_fetch_add( &slot->rej_ring_full, 1, __ATOMIC_RELAXED ); break;
    case SEND_REJ_PEER_FIRST_FAIL:
    case SEND_REJ_PEER_NEG_CACHE:
    case SEND_REJ_NO_DEST_SHM:
        __atomic_fetch_add( &slot->rej_peer, 1, __ATOMIC_RELAXED ); break;
    case SEND_REJ_NOT_SEND_TYPE:
        __atomic_fetch_add( &slot->rej_type, 1, __ATOMIC_RELAXED ); break;
    default:
        break;
    }
}

static void nspa_diag_tid_bump_post( unsigned int tid, enum nspa_post_reason r )
{
    struct nspa_diag_tid *slot = nspa_diag_tid_slot( tid );
    if (!slot) return;

    switch (r)
    {
    case POST_ENTRY:
        __atomic_fetch_add( &slot->entries, 1, __ATOMIC_RELAXED ); break;
    case POST_ACCEPT:
        __atomic_fetch_add( &slot->accepts, 1, __ATOMIC_RELAXED ); break;
    case POST_REJ_DEST_RING_FULL:
        __atomic_fetch_add( &slot->rej_ring_full, 1, __ATOMIC_RELAXED ); break;
    case POST_REJ_PEER_FIRST_FAIL:
    case POST_REJ_PEER_NEG_CACHE:
    case POST_REJ_NO_DEST_SHM:
        __atomic_fetch_add( &slot->rej_peer, 1, __ATOMIC_RELAXED ); break;
    case POST_REJ_NOT_POSTED:
        __atomic_fetch_add( &slot->rej_type, 1, __ATOMIC_RELAXED ); break;
    default:
        break;
    }
}

/* Forward decl — defined below the dump function. */
static void nspa_diag_lazy_start( void );

static void nspa_send_diag_bump( enum nspa_send_reason r )
{
    if (!nspa_send_diag_enabled()) return;
    __atomic_fetch_add( &nspa_diag_send[r], 1, __ATOMIC_RELAXED );
    nspa_diag_tid_bump_send( HandleToULong( NtCurrentTeb()->ClientId.UniqueThread ), r );
    nspa_diag_lazy_start();
}

static void nspa_post_diag_bump( enum nspa_post_reason r )
{
    if (!nspa_send_diag_enabled()) return;
    __atomic_fetch_add( &nspa_diag_post[r], 1, __ATOMIC_RELAXED );
    nspa_diag_tid_bump_post( HandleToULong( NtCurrentTeb()->ClientId.UniqueThread ), r );
    nspa_diag_lazy_start();
}

/* External-facing bumper for send_inter_thread_message's __EXCEPT block. */
void nspa_send_diag_fault_bump( void )
{
    if (!nspa_send_diag_enabled()) return;
    __atomic_fetch_add( &nspa_diag_send[SEND_REJ_FAULTED_SEH], 1, __ATOMIC_RELAXED );
    nspa_diag_lazy_start();
}

static time_t nspa_diag_start_epoch;

static void nspa_diag_dump( void )
{
    char path[128];
    char tmp[128];
    FILE *f;
    unsigned int i;
    uint64_t send_total = 0, send_accepts = 0;
    uint64_t post_total = 0, post_accepts = 0;
    time_t now;

    snprintf( tmp,  sizeof(tmp),  "/tmp/nspa_send_diag.%d.log.tmp", (int)getpid() );
    snprintf( path, sizeof(path), "/tmp/nspa_send_diag.%d.log",      (int)getpid() );

    if (!(f = fopen( tmp, "w" ))) return;

    now = time( NULL );
    fprintf( f, "NSPA T1 diagnostic  pid=%d  elapsed_s=%lld\n",
             (int)getpid(), (long long)(now - nspa_diag_start_epoch) );
    fprintf( f, "----\n" );

    fprintf( f, "[send] nspa_try_send_ring\n" );
    for (i = 0; i < SEND_REASON_NB; i++)
    {
        uint64_t v = __atomic_load_n( &nspa_diag_send[i], __ATOMIC_RELAXED );
        fprintf( f, "  %-24s %llu\n", nspa_send_reason_name[i], (unsigned long long)v );
        if (i == SEND_ACCEPT_SYNC || i == SEND_ACCEPT_NOTIFY) send_accepts += v;
        if (i != SEND_ENTRY) send_total += v;   /* accept + all rejects */
    }
    {
        uint64_t entry = __atomic_load_n( &nspa_diag_send[SEND_ENTRY], __ATOMIC_RELAXED );
        fprintf( f, "  sanity  entry=%llu  accept+rej=%llu  delta=%lld\n",
                 (unsigned long long)entry,
                 (unsigned long long)send_total,
                 (long long)(entry - send_total) );
        fprintf( f, "  accept_rate=%.2f%%\n",
                 entry ? (100.0 * (double)send_accepts / (double)entry) : 0.0 );
    }

    fprintf( f, "\n[post] nspa_try_post_ring\n" );
    for (i = 0; i < POST_REASON_NB; i++)
    {
        uint64_t v = __atomic_load_n( &nspa_diag_post[i], __ATOMIC_RELAXED );
        fprintf( f, "  %-24s %llu\n", nspa_post_reason_name[i], (unsigned long long)v );
        if (i == POST_ACCEPT) post_accepts = v;
        if (i != POST_ENTRY) post_total += v;
    }
    {
        uint64_t entry = __atomic_load_n( &nspa_diag_post[POST_ENTRY], __ATOMIC_RELAXED );
        fprintf( f, "  sanity  entry=%llu  accept+rej=%llu  delta=%lld\n",
                 (unsigned long long)entry,
                 (unsigned long long)post_total,
                 (long long)(entry - post_total) );
        fprintf( f, "  accept_rate=%.2f%%\n",
                 entry ? (100.0 * (double)post_accepts / (double)entry) : 0.0 );
    }

    fprintf( f, "\n[per-thread]  tid       entries    accepts   ring_full    peer    type   accept%%\n" );
    for (i = 0; i < NSPA_DIAG_TID_SLOTS; i++)
    {
        struct nspa_diag_tid *s = &nspa_diag_tids[i];
        unsigned int tid = __atomic_load_n( &s->tid, __ATOMIC_RELAXED );
        uint64_t entries, accepts, ring_full, peer, type;
        if (!tid) continue;
        entries   = __atomic_load_n( &s->entries,       __ATOMIC_RELAXED );
        accepts   = __atomic_load_n( &s->accepts,       __ATOMIC_RELAXED );
        ring_full = __atomic_load_n( &s->rej_ring_full, __ATOMIC_RELAXED );
        peer      = __atomic_load_n( &s->rej_peer,      __ATOMIC_RELAXED );
        type      = __atomic_load_n( &s->rej_type,      __ATOMIC_RELAXED );
        fprintf( f, "              %6x  %10llu  %9llu  %10llu  %6llu  %6llu   %5.1f%%\n",
                 tid,
                 (unsigned long long)entries,
                 (unsigned long long)accepts,
                 (unsigned long long)ring_full,
                 (unsigned long long)peer,
                 (unsigned long long)type,
                 entries ? (100.0 * (double)accepts / (double)entries) : 0.0 );
    }
    {
        uint64_t overflow = __atomic_load_n( &nspa_diag_tid_overflow, __ATOMIC_RELAXED );
        if (overflow) fprintf( f, "  tid-table overflow bumps: %llu\n", (unsigned long long)overflow );
    }

    fclose( f );
    rename( tmp, path );
}

static void *nspa_diag_thread_main( void *arg )
{
    (void)arg;
    for (;;)
    {
        struct timespec ts = { 5, 0 };
        nanosleep( &ts, NULL );
        nspa_diag_dump();
    }
    return NULL;
}

static pthread_once_t nspa_diag_start_once = PTHREAD_ONCE_INIT;

static void nspa_diag_start_once_fn( void )
{
    pthread_t th;
    nspa_diag_start_epoch = time( NULL );
    atexit( nspa_diag_dump );
    if (pthread_create( &th, NULL, nspa_diag_thread_main, NULL ) == 0)
        pthread_detach( th );
}

static void nspa_diag_lazy_start( void )
{
    pthread_once( &nspa_diag_start_once, nspa_diag_start_once_fn );
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
/* Three-valued variant: out-param lets the caller distinguish an existing
 * negative-cache entry (server already said "no bypass" on a prior call —
 * no RPC issued this time) from a first-time populate failure (RPC issued,
 * just now rejected).  The difference matters for the T1 diagnostic:
 * neg-cache hits indicate a persistent plumbing gap, first-fails indicate
 * peer threads we haven't yet successfully reached. */
static struct nspa_cache_entry *nspa_lookup_peer_ex( DWORD tid, BOOL *was_neg_cache )
{
    struct nspa_cache_entry *cache, *entry;

    if (was_neg_cache) *was_neg_cache = FALSE;
    if (!tid) return NULL;

    if (!(cache = nspa_cache_get())) return NULL;  /* TLS alloc failed */

    entry = nspa_cache_find( cache, tid );
    if (!entry) return NULL;       /* cache full */
    if (entry->tid == tid)
    {
        /* Positive cache: mapped_ptr holds the peer's ring mmap. */
        if (entry->mapped_ptr) return entry;
        /* Negative cache: tid set, mapped_ptr NULL (server had no bypass). */
        if (was_neg_cache) *was_neg_cache = TRUE;
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

static struct nspa_cache_entry *nspa_lookup_peer( DWORD tid )
{
    return nspa_lookup_peer_ex( tid, NULL );
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
    BOOL was_neg_cache = FALSE;

    nspa_post_diag_bump( POST_ENTRY );

    if (nspa_bypass_disabled())
    {
        TRACE_(nspa_bypass)( "skip disabled tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        nspa_post_diag_bump( POST_REJ_GATE_OFF );
        return FALSE;
    }

    /* This increment: MSG_POSTED only.  Other types fall through. */
    if (type_enum != MSG_POSTED)
    {
        TRACE_(nspa_bypass)( "skip not-posted type=%u tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             type_enum, HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        nspa_post_diag_bump( POST_REJ_NOT_POSTED );
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
        nspa_post_diag_bump( POST_REJ_NO_HWND );
        return FALSE;
    }
    if (dest_tid == HandleToULong( NtCurrentTeb()->ClientId.UniqueThread ))
    {
        TRACE_(nspa_bypass)( "skip self-post tid=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        nspa_post_diag_bump( POST_REJ_SELF_POST );
        return FALSE;
    }

    /* No DDE through the ring — the server handles DDE specially. */
    if (msg >= WM_DDE_FIRST && msg <= WM_DDE_LAST)
    {
        TRACE_(nspa_bypass)( "skip dde tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        nspa_post_diag_bump( POST_REJ_DDE );
        return FALSE;
    }

    entry = nspa_lookup_peer_ex( dest_tid, &was_neg_cache );
    if (!entry)
    {
        TRACE_(nspa_bypass)( "skip lookup-fail tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        nspa_post_diag_bump( was_neg_cache ? POST_REJ_PEER_NEG_CACHE : POST_REJ_PEER_FIRST_FAIL );
        return FALSE;
    }

    queue_bypass = nspa_get_cached_bypass_shm( entry );
    if (!queue_bypass)
    {
        TRACE_(nspa_bypass)( "skip no-bypass-shm tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        nspa_clear_cache_entry( entry );
        nspa_post_diag_bump( POST_REJ_NO_DEST_SHM );
        return FALSE;
    }

    ring = &((nspa_queue_bypass_shm_t *)queue_bypass)->nspa_msg_ring;
    if (!ring->active)
    {
        TRACE_(nspa_bypass)( "skip ring-inactive tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        nspa_post_diag_bump( POST_REJ_RING_INACTIVE );
        return FALSE;
    }

    idx = ring_reserve_slot( ring );
    if (idx == ~0u)
    {
        TRACE_(nspa_bypass)( "skip ring-full tid=%04x dest=%04x hwnd=%p msg=%04x\n",
                             HandleToULong(NtCurrentTeb()->ClientId.UniqueThread),
                             (UINT)dest_tid, hwnd, msg );
        nspa_post_diag_bump( POST_REJ_DEST_RING_FULL );
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
    nspa_post_diag_bump( POST_ACCEPT );
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

/* Fetch our own queue's bypass shm.
 *
 * Post-memfd-redesign: each thread gets its own mmap of the server-allocated
 * bypass ring via the nspa_ensure_own_bypass protocol request, cached in
 * pthread TLS to avoid repeated server round-trips.
 *
 * Sentinel values in the TLS slot:
 *   NULL          = never queried
 *   (void *)-1    = queried, server had no bypass (negative cache)
 *   valid ptr     = queried, positive — points at mmap'd ring
 */
static pthread_key_t nspa_own_tls_key;
static pthread_once_t nspa_own_tls_once = PTHREAD_ONCE_INIT;
#define NSPA_OWN_NEG ((const nspa_queue_bypass_shm_t *)(intptr_t)-1)

static void nspa_own_tls_destructor( void *p )
{
    /* Note: mmap is shared across threads so we don't munmap on thread
     * exit.  The server-side fd owner (the queue) is what controls ring
     * lifetime; thread exit just drops this cache. */
}

static void nspa_own_tls_init_once( void )
{
    pthread_key_create( &nspa_own_tls_key, nspa_own_tls_destructor );
}

static int nspa_own_bootstrap_enabled( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv( "NSPA_ENABLE_OWN_BOOTSTRAP" );
        cached = (v && *v && *v != '0');
    }
    return cached;
}

static const nspa_queue_bypass_shm_t *nspa_get_own_bypass_shm( void )
{
    const nspa_queue_bypass_shm_t *cached;
    int fd_sent = 0;
    NTSTATUS status;
    int fd = -1;
    void *map = NULL;
    size_t map_size = sizeof(nspa_queue_bypass_shm_t);

    /* Bootstrap own ring on first call regardless of send-opt-in flag.
     * Dual purpose:
     * 1. Local wake-bit synthesis in check_queue_bits() needs the own
     *    ring's pending_count to include ring activity in the fast-path
     *    local shmem check — without it, check_queue_bits returns
     *    "nothing to do" for ring-pending SENDs and the thread never
     *    wakes the dispatcher until some other trigger fires.
     * 2. Reply slot reservation for SEND-class bypass (gated opt-in via
     *    NSPA_ENABLE_OWN_BOOTSTRAP in nspa_try_send_ring — that's the
     *    dispatch-latency-sensitive path).
     */
    if (nspa_bypass_disabled()) return NULL;

    pthread_once( &nspa_own_tls_once, nspa_own_tls_init_once );

    cached = pthread_getspecific( nspa_own_tls_key );
    if (cached == NSPA_OWN_NEG) return NULL;
    if (cached) return cached;

    /* First-call path: bootstrap own bypass ring via new server request. */
    SERVER_START_REQ( nspa_ensure_own_bypass )
    {
        if (!(status = wine_server_call( req )))
            fd_sent = reply->fd_sent;
    }
    SERVER_END_REQ;

    if (status || !fd_sent)
    {
        pthread_setspecific( nspa_own_tls_key, (void *)NSPA_OWN_NEG );
        return NULL;
    }

    {
        obj_handle_t fd_token = 0;
        fd = wine_server_receive_fd( &fd_token );
        if (fd == -1)
        {
            pthread_setspecific( nspa_own_tls_key, (void *)NSPA_OWN_NEG );
            return NULL;
        }

        map = mmap( NULL, map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0 );
        close( fd );

        if (map == MAP_FAILED)
        {
            pthread_setspecific( nspa_own_tls_key, (void *)NSPA_OWN_NEG );
            return NULL;
        }

        if (mlock( map, map_size ) != 0)
            TRACE_(nspa_bypass)( "own-bypass mlock failed; continuing unpinned\n" );
    }

    pthread_setspecific( nspa_own_tls_key, map );
    return (const nspa_queue_bypass_shm_t *)map;
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

/* Public wrapper so winstation.c and input.c's wake-bit synthesis can
 * resolve the current thread's own bypass ring via the memfd-era TLS
 * cache instead of the retired queue_shm_t.nspa_bypass_locator. */
const nspa_queue_bypass_shm_t *nspa_get_own_bypass_shm_public( void )
{
    return nspa_get_own_bypass_shm();
}

/* Public wrapper for the peer bypass-shm lookup.  NSPA Phase B
 * (local WM_TIMER dispatcher) needs to publish expiries into the
 * owner thread's ring when the owner is not the current thread;
 * it uses this to reach the peer's nspa_queue_bypass_shm_t.
 * Returns NULL if the peer is not local / not publishable. */
const nspa_queue_bypass_shm_t *nspa_get_peer_bypass_shm_public( DWORD peer_tid )
{
    struct nspa_cache_entry *entry = nspa_lookup_peer( peer_tid );
    return entry ? nspa_get_cached_bypass_shm( entry ) : NULL;
}

/* Opt-in: NSPA_ENABLE_CLIENT_RING_DISPATCH=1 makes peek_message scan the
 * own ring for SEND-class msgs BEFORE issuing the wineserver get_message
 * request.  This is the Phase 4.6 dispatch-latency fix: removes the
 * server RTT from the hot SEND dispatch path so MainThread can consume
 * ring SENDs within microseconds instead of tens of milliseconds.
 * Default off until validated. */
static int nspa_client_ring_dispatch_enabled( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv( "NSPA_ENABLE_CLIENT_RING_DISPATCH" );
        cached = (v && *v && *v != '0');
    }
    return cached;
}

/* Walk own ring tail forward, marking CONSUMED slots as EMPTY and
 * advancing tail.  Mirrors server's consume_nspa_ring_message tail
 * advance.  Safe for single-thread-advance; MainThread is the typical
 * consumer.  If server also advances via its own consume path, the
 * atomics race harmlessly: last writer wins and tail only moves
 * forward past EMPTY slots. */
static void nspa_client_advance_own_ring_tail( volatile nspa_msg_ring_t *ring )
{
    unsigned int tail = __atomic_load_n( &ring->tail, __ATOMIC_ACQUIRE );
    unsigned int head = __atomic_load_n( &ring->head, __ATOMIC_ACQUIRE );
    unsigned int cursor;

    for (cursor = tail; (int)(cursor - head) < 0; cursor++)
    {
        volatile nspa_msg_slot_t *slot = &ring->slots[cursor & (NSPA_MSG_RING_SLOTS - 1)];
        if (__atomic_load_n( &slot->state, __ATOMIC_ACQUIRE ) != NSPA_MSG_STATE_CONSUMED) break;
        __atomic_store_n( &slot->state, NSPA_MSG_STATE_EMPTY, __ATOMIC_RELEASE );
    }
    if (cursor != tail)
        __atomic_store_n( &ring->tail, cursor, __ATOMIC_RELEASE );
}

/* Scan own ring for a SEND-class msg in READY state matching (win, first,
 * last) filter.  On match: CAS-claim (READY -> CONSUMED), decrement counts,
 * fill info, and (caller-chosen) advance tail.  Returns TRUE if a msg was
 * claimed; info is populated.  FALSE = no match / opt-in gate off / bypass
 * disabled / cross-process window filter (can't match client-side without
 * server's window tree).
 *
 * Called from peek_message BEFORE the wineserver get_message request —
 * eliminates the server RTT for ring SEND dispatch (Phase 4.6). */
BOOL nspa_try_pop_own_ring_send( HWND filter_hwnd, UINT first, UINT last,
                                 UINT *type_out, UINT *msg_out,
                                 WPARAM *wp_out, LPARAM *lp_out,
                                 DWORD *time_out, UINT *sender_tid_out,
                                 UINT *reply_slot_out, HWND *win_out )
{
    const nspa_queue_bypass_shm_t *own = nspa_get_own_bypass_shm_public();
    volatile nspa_msg_ring_t *ring;
    unsigned int head, tail, cursor;

    if (!nspa_client_ring_dispatch_enabled()) return FALSE;
    if (!own) return FALSE;

    /* Only the "any window" case can be handled correctly client-side.
     * Specific-window or parent-child filter needs is_child_window on
     * the server's window tree; fall back to server in that case. */
    if (filter_hwnd) return FALSE;

    ring = (volatile nspa_msg_ring_t *)&own->nspa_msg_ring;
    if (!ring->active) return FALSE;

    head = __atomic_load_n( &ring->head, __ATOMIC_ACQUIRE );
    tail = __atomic_load_n( &ring->tail, __ATOMIC_ACQUIRE );

    for (cursor = tail; (int)(cursor - head) < 0; cursor++)
    {
        volatile nspa_msg_slot_t *slot = &ring->slots[cursor & (NSPA_MSG_RING_SLOTS - 1)];
        unsigned int state = __atomic_load_n( &slot->state, __ATOMIC_ACQUIRE );
        unsigned int type;
        unsigned int slot_msg;
        unsigned int expected;

        if (state != NSPA_MSG_STATE_READY) continue;
        type = slot->type;
        if (type >= 32) continue;
        /* SEND-class only for Phase 4.6 — POSTs still dispatch via
         * server arbitration (works fine today). */
        if (!((1u << type) & ((1u << MSG_ASCII) | (1u << MSG_UNICODE) | (1u << MSG_NOTIFY))))
            continue;

        slot_msg = slot->msg;
        if (slot_msg < first || slot_msg > last) continue;

        /* CAS claim: READY -> CONSUMED.  If it fails, someone else got
         * this slot (server arbitration); continue scanning. */
        expected = NSPA_MSG_STATE_READY;
        if (!__atomic_compare_exchange_n( &slot->state, &expected,
                                          NSPA_MSG_STATE_CONSUMED, 0,
                                          __ATOMIC_ACQUIRE, __ATOMIC_RELAXED ))
            continue;

        /* Got it — pull fields out before decrementing counts (slot
         * contents stay intact through CONSUMED state). */
        *type_out       = type;
        *msg_out        = slot_msg;
        *wp_out         = (WPARAM)slot->wparam;
        *lp_out         = (LPARAM)slot->lparam;
        *time_out       = slot->time;
        *sender_tid_out = slot->sender_tid;
        *reply_slot_out = slot->reply_slot;
        *win_out        = wine_server_ptr_handle( slot->win );

        __atomic_fetch_sub( &ring->pending_count, 1, __ATOMIC_ACQ_REL );
        __atomic_fetch_sub( &ring->pending_send_count, 1, __ATOMIC_ACQ_REL );

        nspa_client_advance_own_ring_tail( ring );
        return TRUE;
    }

    return FALSE;
}

/* Phase 4.7: client-side POST-class pop.  Mirrors nspa_try_pop_own_ring_send
 * but for MSG_POSTED slots, with one critical addition — arbitration check
 * against server-side wake bits.
 *
 * Why arbitration matters for POST and not SEND:
 *   - SEND messages are independent (each is a synchronous unit, no FIFO
 *     ordering between distinct SENDs from different threads).
 *   - POST messages are FIFO within a queue.  Win32 also enforces priority:
 *     hardware (QS_INPUT/QS_HOTKEY) > POST > PAINT.  A blind client-side
 *     pop of a ring POST when the server has older POSTs queued or any
 *     hardware messages pending would deliver out of order.
 *
 * Arbitration rule: pop ring only when queue_shm->wake_bits indicates
 * server has nothing of equal-or-higher priority.  set_queue_bits() sets
 * QS_POSTMESSAGE only for server-routed posts (line 3446 in server/queue.c)
 * — ring posts bump pending_count instead and never touch wake_bits — so
 * a clean QS_POSTMESSAGE bit reliably means "ring POSTs are uncontested
 * by server-queue POSTs".  Same for QS_INPUT/QS_HOTKEY (server-only signals).
 *
 * Race window: between reading wake_bits and CAS-claiming the slot a
 * server-routed POST could land with an earlier post_seq.  In practice:
 *   - Audio playback workload has near-zero server-routed POSTs (everything
 *     ring-routed since the eager-allocate fix); race is degenerate.
 *   - Window is microseconds; even a misorder within that window is below
 *     the granularity any app actually observes.
 *   - If we ever need strict ordering: re-read wake_bits after CAS; if
 *     QS_POSTMESSAGE appeared, undo with CAS CONSUMED → READY.  Not done
 *     here; cost > benefit at current workload.
 */
BOOL nspa_try_pop_own_ring_post( HWND filter_hwnd, UINT first, UINT last,
                                 UINT *msg_out, WPARAM *wp_out, LPARAM *lp_out,
                                 DWORD *time_out, HWND *win_out )
{
    const nspa_queue_bypass_shm_t *own;
    volatile nspa_msg_ring_t *ring;
    unsigned int head, tail, cursor;

    /* Same opt-in gate as Phase 4.6 — single env var for all client-side
     * ring dispatch behaviour. */
    if (!nspa_client_ring_dispatch_enabled()) return FALSE;

    /* Specific-window filter requires server's window tree to evaluate
     * is_child_window correctly.  Fall back to server.  Same constraint
     * as the SEND pop. */
    if (filter_hwnd) return FALSE;

    own = nspa_get_own_bypass_shm_public();
    if (!own) return FALSE;

    /* Arbitration: defer to server when it has higher-priority or
     * order-conflicting work pending. */
    {
        struct object_lock lock = OBJECT_LOCK_INIT;
        const queue_shm_t *queue_shm;
        UINT status, server_pending = 0;

        while ((status = get_shared_queue( &lock, &queue_shm )) == STATUS_PENDING)
            server_pending = queue_shm->wake_bits &
                             (QS_INPUT | QS_HOTKEY | QS_POSTMESSAGE);
        if (status) return FALSE;
        if (server_pending) return FALSE;
    }

    ring = (volatile nspa_msg_ring_t *)&own->nspa_msg_ring;
    if (!ring->active) return FALSE;

    head = __atomic_load_n( &ring->head, __ATOMIC_ACQUIRE );
    tail = __atomic_load_n( &ring->tail, __ATOMIC_ACQUIRE );

    for (cursor = tail; (int)(cursor - head) < 0; cursor++)
    {
        volatile nspa_msg_slot_t *slot = &ring->slots[cursor & (NSPA_MSG_RING_SLOTS - 1)];
        unsigned int state = __atomic_load_n( &slot->state, __ATOMIC_ACQUIRE );
        unsigned int slot_msg, expected;

        if (state != NSPA_MSG_STATE_READY) continue;
        if (slot->type != MSG_POSTED) continue;
        slot_msg = slot->msg;
        if (slot_msg < first || slot_msg > last) continue;

        expected = NSPA_MSG_STATE_READY;
        if (!__atomic_compare_exchange_n( &slot->state, &expected,
                                          NSPA_MSG_STATE_CONSUMED, 0,
                                          __ATOMIC_ACQUIRE, __ATOMIC_RELAXED ))
            continue;

        *msg_out  = slot_msg;
        *wp_out   = (WPARAM)slot->wparam;
        *lp_out   = (LPARAM)slot->lparam;
        *time_out = slot->time;
        *win_out  = wine_server_ptr_handle( slot->win );

        /* POST decrements pending_count only — pending_send_count tracks
         * SEND-class only and was never incremented for this slot. */
        __atomic_fetch_sub( &ring->pending_count, 1, __ATOMIC_ACQ_REL );

        nspa_client_advance_own_ring_tail( ring );
        return TRUE;
    }

    return FALSE;
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

    /* Wake the sender's targeted futex on slot->state.  Sender's wait loop
     * uses futex_wait directly on the reply slot value so it sees this
     * exact transition with no false wakes from unrelated queue traffic. */
    syscall( SYS_futex, (void *)&slot->state, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0 );

    /* Also kick the queue->sync ntsync event for any waiter that came in
     * via the legacy queue-wide path (e.g. wait_message_reply on a server-
     * routed send).  Cheap; no-op if no waiter. */
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
    BOOL was_neg_cache = FALSE;
    int waits = 0;

    TRACE_(nspa_bypass)( "PROBE try_send_ring enter dest=%04x type=%u hwnd=%p msg=%04x\n",
                         (UINT)dest_tid, type_enum, hwnd, msg );

    nspa_send_diag_bump( SEND_ENTRY );

    if (nspa_bypass_disabled())
    {
        TRACE_(nspa_bypass)( "send skip disabled dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        nspa_send_diag_bump( SEND_REJ_GATE_OFF );
        return FALSE;
    }

    is_notify = (type_enum == MSG_NOTIFY);
    if (type_enum != MSG_ASCII && type_enum != MSG_UNICODE && !is_notify)
    {
        TRACE_(nspa_bypass)( "send skip not-send-type type=%u dest=%04x msg=%04x\n",
                             type_enum, (UINT)dest_tid, msg );
        nspa_send_diag_bump( SEND_REJ_NOT_SEND_TYPE );
        return FALSE;
    }

    if (!hwnd)
    {
        TRACE_(nspa_bypass)( "send skip thread-msg dest=%04x msg=%04x\n",
                             (UINT)dest_tid, msg );
        nspa_send_diag_bump( SEND_REJ_NO_HWND );
        return FALSE;
    }
    own_tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );
    if (dest_tid == own_tid)
    {
        TRACE_(nspa_bypass)( "send skip self-send dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        nspa_send_diag_bump( SEND_REJ_SELF_SEND );
        return FALSE;
    }
    if (msg >= WM_DDE_FIRST && msg <= WM_DDE_LAST)
    {
        TRACE_(nspa_bypass)( "send skip dde dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        nspa_send_diag_bump( SEND_REJ_DDE );
        return FALSE;
    }

    entry = nspa_lookup_peer_ex( dest_tid, &was_neg_cache );
    if (!entry)
    {
        TRACE_(nspa_bypass)( "send skip lookup-fail dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        nspa_send_diag_bump( was_neg_cache ? SEND_REJ_PEER_NEG_CACHE : SEND_REJ_PEER_FIRST_FAIL );
        return FALSE;
    }

    dest_bypass = nspa_get_cached_bypass_shm( entry );
    if (!dest_bypass)
    {
        nspa_clear_cache_entry( entry );
        TRACE_(nspa_bypass)( "send skip no-bypass-shm dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        nspa_send_diag_bump( SEND_REJ_NO_DEST_SHM );
        return FALSE;
    }

    ring = &((nspa_queue_bypass_shm_t *)dest_bypass)->nspa_msg_ring;
    if (!ring->active)
    {
        TRACE_(nspa_bypass)( "send skip ring-inactive dest=%04x hwnd=%p msg=%04x\n",
                             (UINT)dest_tid, hwnd, msg );
        nspa_send_diag_bump( SEND_REJ_RING_INACTIVE );
        return FALSE;
    }

    /* Sync sends need our own reply ring + sync handle. */
    if (!is_notify)
    {
        /* SEND bypass remains opt-in via NSPA_ENABLE_OWN_BOOTSTRAP until
         * the dispatch-latency fix (Phase 4.5 client-side ring-SEND pump)
         * lands.  Own ring is still bootstrapped for wake-bit synthesis
         * (nspa_get_own_bypass_shm is called elsewhere); only using the
         * reply ring for synchronous SEND is gated. */
        if (!nspa_own_bootstrap_enabled())
        {
            TRACE_(nspa_bypass)( "send skip send-opt-in-disabled dest=%04x msg=%04x\n",
                                 (UINT)dest_tid, msg );
            nspa_send_diag_bump( SEND_REJ_SEND_OPT_IN_OFF );
            return FALSE;
        }
        own_bypass = nspa_get_own_bypass_shm();
        if (!own_bypass)
        {
            TRACE_(nspa_bypass)( "send skip no-own-bypass dest=%04x msg=%04x\n",
                                 (UINT)dest_tid, msg );
            nspa_send_diag_bump( SEND_REJ_NO_OWN_SHM );
            return FALSE;
        }
        own_reply_ring = &((nspa_queue_bypass_shm_t *)own_bypass)->nspa_reply_ring;
        reply_idx = nspa_reply_ring_reserve( own_reply_ring );
        if (reply_idx == ~0u)
        {
            TRACE_(nspa_bypass)( "send skip reply-ring-full dest=%04x msg=%04x\n",
                                 (UINT)dest_tid, msg );
            nspa_send_diag_bump( SEND_REJ_REPLY_RING_FULL );
            return FALSE;
        }
        own_sync = nspa_get_own_server_queue_handle();
        if (!own_sync)
        {
            __atomic_store_n( &own_reply_ring->slots[reply_idx].state,
                              NSPA_REPLY_STATE_FREE, __ATOMIC_RELEASE );
            TRACE_(nspa_bypass)( "send skip no-own-sync dest=%04x msg=%04x\n",
                                 (UINT)dest_tid, msg );
            nspa_send_diag_bump( SEND_REJ_NO_OWN_SYNC );
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
        nspa_send_diag_bump( SEND_REJ_DEST_RING_FULL );
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

    if (is_notify)
    {
        nspa_send_diag_bump( SEND_ACCEPT_NOTIFY );
        return TRUE;
    }

    /* Wait for reply via futex on the reply slot's state field.  This is
     * targeted: only wakes when the receiver writes the reply (which calls
     * FUTEX_WAKE_PRIVATE on the same address).  No false wakes from
     * unrelated queue traffic — the previous NtWaitForSingleObject on
     * queue->sync was woken by every incoming message, causing waits++ to
     * advance much faster than the nominal 10 ms tick and the "5 s timeout"
     * to fire in milliseconds under busy-queue conditions.
     *
     * Cross-send deadlock protection retained: if the peer's winproc
     * SendMessages back to us while we are waiting, we drain incoming
     * SENDs before each futex_wait so the peer can make forward progress.
     *
     * Total cap: 2 s (200 iterations × 10 ms futex timeout).  Lower than
     * the legacy 5 s because the futex actually waits the full 10 ms when
     * no real signal is pending; under genuine receiver outage the cap is
     * the floor for falling back to the server send_message path. */
    for (;;)
    {
        unsigned int state = __atomic_load_n( &reply_slot->state, __ATOMIC_ACQUIRE );
        struct timespec rel;
        long ret;

        if (state == NSPA_REPLY_STATE_READY) break;
        if (waits > 200)  /* 200 * 10 ms = 2 s */
        {
            TRACE_(nspa_bypass)( "send timeout dest=%04x msg=%04x slot=%u\n",
                                 (UINT)dest_tid, msg, reply_idx );
            __atomic_store_n( &reply_slot->state, NSPA_REPLY_STATE_FREE, __ATOMIC_RELEASE );
            nspa_send_diag_bump( SEND_REJ_REPLY_TIMEOUT );
            return FALSE;
        }
        /* Drain inbound SEND messages before waiting so a peer that has
         * called back into us can make forward progress. */
        nspa_process_sent_messages();
        /* Re-check state after the drain — peer may have replied during it. */
        state = __atomic_load_n( &reply_slot->state, __ATOMIC_ACQUIRE );
        if (state == NSPA_REPLY_STATE_READY) break;
        /* futex_wait returns immediately with EAGAIN if state has already
         * changed from PENDING (the receiver beat us to the wait), so no
         * lost-wake race vs. the WAKE on the receiver side. */
        rel.tv_sec  = 0;
        rel.tv_nsec = 10 * 1000 * 1000;  /* 10 ms */
        ret = syscall( SYS_futex, (void *)&reply_slot->state,
                       FUTEX_WAIT_PRIVATE, NSPA_REPLY_STATE_PENDING,
                       &rel, NULL, 0 );
        (void)ret;  /* EAGAIN / ETIMEDOUT / 0 / EINTR all loop back to recheck */
        waits++;
    }
    (void)own_sync;  /* legacy fallback path no longer needed; see receiver-side futex_wake */

    *result_out = reply_slot->result;
    __atomic_store_n( &reply_slot->state, NSPA_REPLY_STATE_FREE, __ATOMIC_RELEASE );

    TRACE_(nspa_bypass)( "send got-reply dest=%04x msg=%04x result=%lx waits=%d\n",
                         (UINT)dest_tid, msg, (unsigned long)*result_out, waits );
    nspa_send_diag_bump( SEND_ACCEPT_SYNC );
    return TRUE;
}
