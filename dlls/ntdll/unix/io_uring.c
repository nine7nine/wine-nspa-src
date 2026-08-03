/*
 * Wine-NSPA io_uring integration for ntdll
 *
 * Copyright 2026 Wine-NSPA
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Per-thread io_uring ring management for file and socket I/O.
 * Reduces syscall overhead and bypasses wineserver for I/O operations.
 *
 * Design:
 *   - Per-thread rings (SINGLE_ISSUER) — no cross-thread submission
 *   - COOP_TASKRUN — completions processed in submitter context (RT safe)
 *   - Every io_uring path has a fallback to existing behavior
 *   - Cooperative completion drain at server_call / server_wait entry points
 *   - fd references held for the lifetime of in-flight SQEs
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <sys/socket.h>

#ifdef HAVE_LIBURING_H
#include <liburing.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"
#include "unix_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(io_uring);


#ifdef HAVE_LIBURING_H

#define RING_SIZE 32

/* Sentinel user_data value for internal operations (cancel, etc.) */
#define URING_INTERNAL_TAG ((void *)(uintptr_t)1)

/* CQE user_data discipline.  Three tag classes share the 64-bit user_data:
 *   - async op:   pointer into this thread's op_pool (aligned, so even)
 *   - sync poll:  per-call odd tag minted from uring_poll_seq (see
 *                 ntdll_io_uring_poll) — odd values can never alias a pool
 *                 pointer, and the sequence makes every call's tag unique
 *                 so a stale CQE from an orphaned earlier poll can never be
 *                 misattributed to a later call
 *   - internal:   URING_INTERNAL_TAG (cancel SQEs)
 * Only pool pointers may ever be dereferenced; everything else is
 * discardable on sight.  is_pool_op() is the single authority. */

/* -----------------------------------------------------------------------
 * Async op types and per-thread pool (forward declarations needed by
 * ensure_ring → op_pool_init)
 * ----------------------------------------------------------------------- */

enum uring_op_type
{
    URING_OP_FILE_READ,
    URING_OP_FILE_WRITE,
    URING_OP_SOCKET_POLL_RECV,  /* Phase 3: async poll for socket recv readiness */
    URING_OP_SOCKET_POLL_SEND,  /* Phase 3: async poll for socket send readiness */
    URING_OP_SOCKET_RECVMSG,    /* Phase 4.8.A: full RECVMSG (data movement + post-process via try_recv_post_process) */
    URING_OP_SOCKET_SENDMSG,    /* Phase 4.8.B: full SENDMSG (reserved; wired by Phase B commit) */
};

struct uring_async_op
{
    enum uring_op_type type;
    HANDLE             handle;      /* NT file/socket handle */
    HANDLE             event;       /* completion event (may be NULL) */
    PIO_APC_ROUTINE    apc;         /* completion APC (may be NULL) */
    void              *apc_user;    /* APC user context / IOCP cvalue */
    IO_STATUS_BLOCK   *io;          /* IO status block */
    unsigned int       options;     /* file options for set_sync_iosb */
    int                dup_fd;      /* dup'd fd — we own this, always close (-1 = none) */
    ULONG              already;     /* bytes transferred before io_uring */
    ULONG              count;       /* total bytes requested */
    BOOL               avail_mode;  /* return on any data (pipes) */
    /* Phase 3 socket poll fields */
    void              *sock_async;  /* async_recv_ioctl* or async_send_ioctl* */
    HANDLE             wait_handle; /* server async wait handle */
    int                poll_unix_fd;/* unix fd for bitmap clear on completion */
    int                event_sync_fd;/* pre-resolved ntsync fd for ov.hEvent (-1 = none) */
    /* Phase 4.8.A socket RECVMSG fields — lifetime spans submit→CQE, kernel
     * reads/writes msghdr in place across the io_uring round-trip.  Only
     * populated for URING_OP_SOCKET_RECVMSG / URING_OP_SOCKET_SENDMSG ops;
     * other op types ignore these fields.  Memory cost: ~600 bytes per
     * op_pool slot regardless of which type is used (acceptable at
     * RING_SIZE=32 = ~22 KB per thread). */
    struct msghdr      sock_msghdr;     /* msghdr for RECVMSG/SENDMSG */
    char               sock_control[512];/* control buffer (cmsg storage) */
    union { struct sockaddr_storage st; char buf[128]; } sock_addr_storage; /* address storage */
    struct uring_async_op *next_free; /* freelist link (only valid when not in flight) */
};

/* Pre-allocated per-thread op pool.  At most RING_SIZE SQEs can be in
 * flight simultaneously, so a fixed array of that size is sufficient.
 * Allocated once at ring init time — zero malloc in the submit path. */
static __thread struct uring_async_op  op_pool[RING_SIZE];
static __thread struct uring_async_op *op_free_head;

/* U3: count of async ops submitted to this thread's ring whose CQE has not
 * yet been drained (one CQE per op, no multishot).  Together with
 * ntdll_io_uring_deferred_count this answers "does this thread owe anyone
 * a completion delivery?" — consulted by the non-alertable NtDelayExecution
 * routing (a plain clock_nanosleep would sit on completions that only this
 * thread can deliver, stalling any other thread waiting on the op's event).
 * The sync ntdll_io_uring_poll never counts: its SQE is consumed within the
 * call and represents no deliverable completion. */
__thread unsigned int ntdll_io_uring_inflight_count;

static BOOL is_pool_op( void *p )
{
    return p >= (void *)op_pool && p < (void *)(op_pool + RING_SIZE);
}

/* Defined in the async-op section below; needed by the sync-poll foreign-CQE
 * routing above it. */
static void complete_uring_op( struct uring_async_op *op, int result );

static void op_pool_init(void)
{
    int i;
    for (i = 0; i < RING_SIZE - 1; i++)
        op_pool[i].next_free = &op_pool[i + 1];
    op_pool[RING_SIZE - 1].next_free = NULL;
    op_free_head = &op_pool[0];
}

static struct uring_async_op *op_pool_alloc(void)
{
    struct uring_async_op *op = op_free_head;
    if (op)
    {
        op_free_head = op->next_free;
        memset( op, 0, sizeof(*op) );
    }
    return op;
}

static void op_pool_free( struct uring_async_op *op )
{
    op->next_free = op_free_head;
    op_free_head = op;
}

/* -----------------------------------------------------------------------
 * Per-thread ring management
 * ----------------------------------------------------------------------- */

static __thread struct io_uring thread_ring;
static __thread BOOL ring_initialized;
static __thread BOOL ring_init_failed;
/* Exposed via unix_private.h's static-inline ntdll_io_uring_get_eventfd
 * so audio-path callers (sync.c inproc_wait) avoid the per-wait function
 * call.  Visible name: ntdll_io_uring_ring_efd. */
__thread int  ntdll_io_uring_ring_efd = -1;

/* Deferred completion queue — for completions that can't be delivered
 * from inside the CQ drain (e.g. overlapped socket completions that
 * call file_complete_async, which is unsafe from ntsync wait context).
 * Processed by ntdll_io_uring_flush_deferred() after linux_wait_objs. */
struct deferred_completion
{
    struct deferred_completion *next;
    struct uring_async_op op;  /* copy of the op at CQE time */
    int poll_revents;
};
static __thread struct deferred_completion *deferred_head;
static __thread struct deferred_completion *deferred_free;

/* TLS counter for unix_private.h's inline ntdll_io_uring_flush_deferred
 * fast-path.  Bumped by defer_socket_poll, zeroed by flush_deferred_slow. */
__thread unsigned int ntdll_io_uring_deferred_count;

static BOOL ensure_ring(void)
{
    struct io_uring_params params;
    int ret;

    if (ring_initialized) return TRUE;
    if (ring_init_failed)  return FALSE;

    memset( &params, 0, sizeof(params) );
    params.flags = IORING_SETUP_SINGLE_ISSUER
                 | IORING_SETUP_COOP_TASKRUN;

    ret = io_uring_queue_init_params( RING_SIZE, &thread_ring, &params );
    if (ret < 0)
    {
        /* kernel too old for advanced flags — try plain init */
        memset( &params, 0, sizeof(params) );
        ret = io_uring_queue_init_params( RING_SIZE, &thread_ring, &params );
    }
    if (ret < 0)
    {
        WARN( "io_uring_queue_init failed: %s\n", strerror( -ret ) );
        ring_init_failed = TRUE;
        {
            static LONG once;
            if (!InterlockedExchange( &once, 1 ))
                fprintf( stderr, "wine: NSPA RT:io_uring: unavailable (%s) — file I/O uses server path\n",
                         strerror( -ret ) );
        }
        return FALSE;
    }

    ring_initialized = TRUE;
    op_pool_init();

    /* Create an eventfd for CQE notification.  When io_uring posts a CQE,
     * the kernel writes to this eventfd.  The ntsync uring_fd extension
     * watches it so that threads blocked in ntsync waits wake on I/O
     * completion.  EFD_NONBLOCK avoids blocking reads in the drain path. */
    ntdll_io_uring_ring_efd = eventfd( 0, EFD_NONBLOCK | EFD_CLOEXEC );
    if (ntdll_io_uring_ring_efd >= 0)
    {
        if (io_uring_register_eventfd( &thread_ring, ntdll_io_uring_ring_efd ) < 0)
        {
            WARN( "io_uring_register_eventfd failed: %s\n", strerror( errno ) );
            close( ntdll_io_uring_ring_efd );
            ntdll_io_uring_ring_efd = -1;
        }
    }

    /* One-time banner on first ring init in the process */
    {
        static LONG once;
        if (!InterlockedExchange( &once, 1 ))
            fprintf( stderr, "wine: NSPA RT:io_uring: ring active (sq=%u cq=%u flags=0x%x efd=%d) — file I/O bypasses wineserver\n",
                     params.sq_entries, params.cq_entries, params.flags, ntdll_io_uring_ring_efd );
    }

    TRACE( "io_uring ring initialized (sq=%u cq=%u flags=0x%x) for thread %04x\n",
           params.sq_entries, params.cq_entries, params.flags, GetCurrentThreadId() );
    return TRUE;
}

BOOL ntdll_io_uring_enabled(void)
{
    return ensure_ring();
}

void ntdll_io_uring_cleanup(void)
{
    if (!ring_initialized) return;

    ntdll_io_uring_process_completions();
    io_uring_queue_exit( &thread_ring );
    if (ntdll_io_uring_ring_efd >= 0) { close( ntdll_io_uring_ring_efd ); ntdll_io_uring_ring_efd = -1; }
    ring_initialized = FALSE;
    TRACE( "io_uring ring cleaned up\n" );
}

/* ntdll_io_uring_get_eventfd lives as a static inline in unix_private.h
 * to avoid a per-wait function call on the audio hot path.  The TLS
 * variable ntdll_io_uring_ring_efd is the actual storage. */

/* Queue a deferred socket poll completion — saves the entire op + revents.
 * Called from complete_uring_op when the socket poll is overlapped
 * (wait_handle == 0). The FULL completion (fd fetch, try_recv/try_send,
 * file_complete_async, release_fileio) runs in flush_deferred. */
void ntdll_io_uring_defer_socket_poll( struct uring_async_op *op, int poll_revents )
{
    struct deferred_completion *dc = deferred_free;
    if (dc)
        deferred_free = dc->next;
    else
        dc = malloc( sizeof(*dc) );
    if (!dc) return;

    dc->op = *op;  /* shallow copy — all fields are values or pointers we own */
    dc->poll_revents = poll_revents;
    dc->next = deferred_head;
    deferred_head = dc;
    ntdll_io_uring_deferred_count++;
}

/* Flush deferred completions — called from NtWaitForSingleObject /
 * NtWaitForMultipleObjects AFTER inproc_wait returns via the inline
 * ntdll_io_uring_flush_deferred() in unix_private.h, which gates on
 * ntdll_io_uring_deferred_count to skip the call when the queue is
 * empty (the steady-state condition since complete_uring_op completes
 * socket polls inline).  Safe context: fully outside the ntsync ioctl
 * stack. */
extern void ntdll_complete_socket_poll( struct uring_async_op *op, int poll_revents );

void ntdll_io_uring_flush_deferred_slow(void)
{
    struct deferred_completion *dc;

    while ((dc = deferred_head))
    {
        deferred_head = dc->next;
        ntdll_complete_socket_poll( &dc->op, dc->poll_revents );
        dc->next = deferred_free;
        deferred_free = dc;
    }
    ntdll_io_uring_deferred_count = 0;
}


/* -----------------------------------------------------------------------
 * Phase 1: Blocking poll replacement
 *
 * Replaces poll(fd, events, timeout_ms) in synchronous I/O wait loops.
 * Returns: positive revents on success, 0 on timeout, negative on error.
 * ----------------------------------------------------------------------- */

/* Per-thread sequence for sync-poll CQE tags.  Tag = ((++seq) << 1) | 1:
 * odd, so it can never alias an op_pool pointer, and unique per call, so a
 * CQE from an earlier orphaned poll can never be taken for the current
 * call's result. */
static __thread uintptr_t uring_poll_seq;

/* Route one foreign CQE encountered while waiting for our own.  Async op
 * completions are delivered properly (they used to be silently eaten here:
 * this function took the FIRST CQE as its poll result, so an async op
 * completing between the entry drain and the wait lost its event/IOSB
 * delivery, leaked its op slot + dup fd, and fed its res to the caller as
 * revents).  Anything else — stale poll tags, internal cancels — is
 * discardable by the user_data discipline. */
static void uring_poll_route_foreign( struct io_uring_cqe *cqe )
{
    void *data = io_uring_cqe_get_data( cqe );
    if (is_pool_op( data )) complete_uring_op( data, cqe->res );
}

/* Cancel this call's still-pending poll SQE and reap CQEs until the poll's
 * own CQE has been seen (routing foreign completions on the way).  Exits
 * early on wait errors — any CQEs left behind are safely discarded later
 * by the user_data discipline. */
static void uring_poll_cancel_and_reap( void *tag )
{
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int spins = 0;

    sqe = io_uring_get_sqe( &thread_ring );
    if (!sqe)
    {
        ntdll_io_uring_process_completions();
        sqe = io_uring_get_sqe( &thread_ring );
        /* No room for the cancel: orphan the poll.  Its CQE carries our
         * unique odd tag and is discarded by any later drain. */
        if (!sqe) return;
    }
    io_uring_prep_cancel64( sqe, (uintptr_t)tag, 0 );
    io_uring_sqe_set_data( sqe, URING_INTERNAL_TAG );
    io_uring_submit( &thread_ring );

    for (;;)
    {
        int ret = io_uring_wait_cqe( &thread_ring, &cqe );
        if (ret == -EINTR)
        {
            if (++spins > 1000) return;   /* pathological signal storm — orphan */
            continue;
        }
        if (ret < 0) return;
        if (io_uring_cqe_get_data( cqe ) == tag)
        {
            io_uring_cqe_seen( &thread_ring, cqe );
            return;   /* poll CQE reaped (fired or -ECANCELED) — done */
        }
        uring_poll_route_foreign( cqe );
        io_uring_cqe_seen( &thread_ring, cqe );
    }
}

int ntdll_io_uring_poll( int fd, short events, int timeout_ms )
{
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    struct __kernel_timespec ts;
    void *tag;
    int ret;

    if (!ensure_ring()) return -ENOSYS;

    /* drain any pending completions first */
    ntdll_io_uring_process_completions();

    sqe = io_uring_get_sqe( &thread_ring );
    if (!sqe) return -ENOMEM;

    tag = (void *)(uintptr_t)(((++uring_poll_seq) << 1) | 1);
    io_uring_prep_poll_add( sqe, fd, (unsigned)events );
    io_uring_sqe_set_data( sqe, tag );
    io_uring_submit( &thread_ring );

    if (timeout_ms >= 0)
    {
        ts.tv_sec  = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000;
    }

    for (;;)
    {
        if (timeout_ms > 0)
            ret = io_uring_wait_cqe_timeout( &thread_ring, &cqe, &ts );
        else if (timeout_ms == 0)
            ret = io_uring_peek_cqe( &thread_ring, &cqe );
        else
            ret = io_uring_wait_cqe( &thread_ring, &cqe );

        if (ret == -ETIME || (ret == -EAGAIN && timeout_ms == 0))
        {
            /* timed out / not ready — retract our poll before returning so
             * it can't linger in the ring. */
            uring_poll_cancel_and_reap( tag );
            return 0;  /* timeout — matches poll() returning 0 */
        }
        if (ret < 0)
        {
            /* -EINTR (or wait failure): retract and surface to the caller,
             * which handles EINTR by restarting its I/O loop. */
            uring_poll_cancel_and_reap( tag );
            return ret;
        }

        if (io_uring_cqe_get_data( cqe ) == tag)
        {
            ret = cqe->res;
            io_uring_cqe_seen( &thread_ring, cqe );
            return ret;  /* revents mask or error */
        }

        /* Foreign CQE (async op / stale tag) — deliver or discard, then
         * keep waiting for ours.  NOTE: the fixed timeout is re-armed per
         * iteration; foreign completions are rare enough that the small
         * timeout stretch is preferable to deadline bookkeeping here. */
        uring_poll_route_foreign( cqe );
        io_uring_cqe_seen( &thread_ring, cqe );
    }
}


/* -----------------------------------------------------------------------
 * Phase 2 & 3: Async I/O — server bypass
 *
 * Track pending operations.  The unix_fd is dup'd to ensure it stays
 * valid for the lifetime of the in-flight SQE, regardless of what the
 * server-side handle table does.
 * ----------------------------------------------------------------------- */

/* Dup the fd so it remains valid for the in-flight SQE.
 * The caller's fd and its needs_close semantics are unaffected. */
static int dup_fd_for_ring( int unix_fd )
{
    int fd = dup( unix_fd );
    if (fd < 0)
        WARN( "dup(%d) failed: %s\n", unix_fd, strerror( errno ) );
    return fd;
}

/* Socket poll CQE handler — called when POLL_ADD fires.
 * For synchronous sockets (wait_handle != 0): completes inline.
 * For overlapped (wait_handle == 0): defers EVERYTHING — the entire
 * completion (fd fetch, try_recv/try_send, file_complete_async) runs
 * later in ntdll_io_uring_flush_deferred, safely outside ntsync. */
extern void ntdll_complete_socket_poll( struct uring_async_op *op, int poll_revents );
/* Phase 4.8.A: socket-specific RECVMSG completion handler in socket.c. */
extern void ntdll_complete_socket_recvmsg( struct uring_async_op *op, int result );
/* Phase 4.8.B: socket-specific SENDMSG completion handler in socket.c. */
extern void ntdll_complete_socket_sendmsg( struct uring_async_op *op, int result );

/* Field accessors for socket.c — avoids exposing uring_async_op struct */
void *ntdll_uring_op_sock_async( struct uring_async_op *op ) { return op->sock_async; }
HANDLE ntdll_uring_op_wait_handle( struct uring_async_op *op ) { return op->wait_handle; }
unsigned int ntdll_uring_op_options( struct uring_async_op *op ) { return op->options; }
IO_STATUS_BLOCK *ntdll_uring_op_io( struct uring_async_op *op ) { return op->io; }
BOOL ntdll_uring_op_is_send( struct uring_async_op *op )
{
    return op->type == URING_OP_SOCKET_POLL_SEND;
}
int ntdll_uring_op_poll_unix_fd( struct uring_async_op *op ) { return op->poll_unix_fd; }
HANDLE ntdll_uring_op_handle( struct uring_async_op *op ) { return op->handle; }
HANDLE ntdll_uring_op_event( struct uring_async_op *op ) { return op->event; }
PIO_APC_ROUTINE ntdll_uring_op_apc( struct uring_async_op *op ) { return op->apc; }
void *ntdll_uring_op_apc_user( struct uring_async_op *op ) { return op->apc_user; }
int ntdll_uring_op_event_sync_fd( struct uring_async_op *op ) { return op->event_sync_fd; }
int ntdll_uring_op_dup_fd( struct uring_async_op *op ) { return op->dup_fd; }
/* Phase 4.8.A accessors for the populated msghdr / addr storage carried
 * across submit→CQE in the op slot (used by the RECVMSG CQE handler). */
struct msghdr *ntdll_uring_op_sock_msghdr( struct uring_async_op *op ) { return &op->sock_msghdr; }
void *ntdll_uring_op_sock_addr_storage( struct uring_async_op *op ) { return &op->sock_addr_storage; }

static void complete_uring_op( struct uring_async_op *op, int result )
{
    NTSTATUS status;
    ULONG_PTR information;

    /* U3: every submitted async op funnels through here exactly once (one
     * CQE per op).  Guarded so an accounting bug degrades Sleep routing
     * instead of wrapping the counter. */
    if (ntdll_io_uring_inflight_count) ntdll_io_uring_inflight_count--;
    else ERR( "in-flight counter underflow (type=%d handle=%p)\n", op->type, op->handle );

    /* Socket poll completions — both sync and overlapped complete inline.
     * Overlapped uses ntdll_signal_event_direct (raw ntsync ioctl) instead
     * of NtSetEvent to avoid ntsync reentrancy. */
    if (op->type == URING_OP_SOCKET_POLL_RECV || op->type == URING_OP_SOCKET_POLL_SEND)
    {
        ntdll_complete_socket_poll( op, result );
        op_pool_free( op );
        return;
    }

    /* Phase 4.8.A: full RECVMSG completion — data is already moved by the
     * kernel; CQE handler runs try_recv_post_process to apply Wine-specific
     * post-processing (MSG_TRUNC, ICMP fixup, control / sockaddr conversion,
     * OOB quirk).  The op slot's sock_msghdr / sock_control / sock_addr_storage
     * carry the populated msghdr through the round-trip. */
    if (op->type == URING_OP_SOCKET_RECVMSG)
    {
        ntdll_complete_socket_recvmsg( op, result );
        op_pool_free( op );
        return;
    }

    /* Phase 4.8.B: full SENDMSG completion.  CQE handler runs
     * try_send_post_process to update sent_len + advance iov_cursor.
     * EISCONN / ECONNREFUSED / EINTR retry conditions fall back to
     * sync try_send from inside the handler (rare-path; mirrors
     * existing socket_poll fallback shape). */
    if (op->type == URING_OP_SOCKET_SENDMSG)
    {
        ntdll_complete_socket_sendmsg( op, result );
        op_pool_free( op );
        return;
    }

    if (result >= 0)
    {
        information = op->already + result;
        if (result == 0 && !op->already)
            status = (op->type == URING_OP_FILE_READ) ? STATUS_PIPE_BROKEN : STATUS_SUCCESS;
        else
            status = STATUS_SUCCESS;
    }
    else
    {
        information = op->already;
        status = errno_to_status( -result );
    }

    file_complete_async( op->handle, op->options, op->event, op->apc,
                         op->apc_user, op->io, status, information );

    if (op->dup_fd >= 0) close( op->dup_fd );
    op_pool_free( op );
}


int ntdll_io_uring_submit_file_read( int unix_fd, int needs_close, void *buffer,
                                     ULONG already, ULONG count, HANDLE handle,
                                     HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                     IO_STATUS_BLOCK *io, unsigned int options,
                                     BOOL avail_mode )
{
    struct uring_async_op *op;
    struct io_uring_sqe *sqe;
    int ring_fd;

    if (!ensure_ring()) return -ENOSYS;

    /* dup the fd so we own a stable reference for the in-flight SQE */
    ring_fd = dup_fd_for_ring( unix_fd );
    if (ring_fd < 0) return -errno;

    op = op_pool_alloc();
    if (!op) { close( ring_fd ); return -ENOMEM; }

    op->type       = URING_OP_FILE_READ;
    op->handle     = handle;
    op->event      = event;
    op->apc        = apc;
    op->apc_user   = apc_user;
    op->io         = io;
    op->options    = options;
    op->dup_fd     = ring_fd;
    op->already    = already;
    op->count      = count;
    op->avail_mode = avail_mode;

    sqe = io_uring_get_sqe( &thread_ring );
    if (!sqe)
    {
        io_uring_submit( &thread_ring );
        ntdll_io_uring_process_completions();
        sqe = io_uring_get_sqe( &thread_ring );
        if (!sqe) { close( ring_fd ); op_pool_free( op ); return -ENOMEM; }
    }

    io_uring_prep_read( sqe, ring_fd, (char *)buffer + already, count - already, 0 );
    io_uring_sqe_set_data( sqe, op );
    io_uring_submit( &thread_ring );
    ntdll_io_uring_inflight_count++;

    /* the caller's fd lifecycle is unchanged — close if needed */
    if (needs_close) close( unix_fd );

    TRACE( "submitted async read: handle=%p fd=%d(%d) buf=%p+%u len=%u\n",
           handle, unix_fd, ring_fd, buffer, already, count - already );
    return 0;
}


int ntdll_io_uring_submit_file_write( int unix_fd, int needs_close, const void *buffer,
                                      ULONG already, ULONG count, HANDLE handle,
                                      HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                      IO_STATUS_BLOCK *io, unsigned int options )
{
    struct uring_async_op *op;
    struct io_uring_sqe *sqe;
    int ring_fd;

    if (!ensure_ring()) return -ENOSYS;

    ring_fd = dup_fd_for_ring( unix_fd );
    if (ring_fd < 0) return -errno;

    op = op_pool_alloc();
    if (!op) { close( ring_fd ); return -ENOMEM; }

    op->type     = URING_OP_FILE_WRITE;
    op->handle   = handle;
    op->event    = event;
    op->apc      = apc;
    op->apc_user = apc_user;
    op->io       = io;
    op->options  = options;
    op->dup_fd   = ring_fd;
    op->already  = already;
    op->count    = count;

    sqe = io_uring_get_sqe( &thread_ring );
    if (!sqe)
    {
        io_uring_submit( &thread_ring );
        ntdll_io_uring_process_completions();
        sqe = io_uring_get_sqe( &thread_ring );
        if (!sqe) { close( ring_fd ); op_pool_free( op ); return -ENOMEM; }
    }

    io_uring_prep_write( sqe, ring_fd, (const char *)buffer + already, count - already, 0 );
    io_uring_sqe_set_data( sqe, op );
    io_uring_submit( &thread_ring );
    ntdll_io_uring_inflight_count++;

    if (needs_close) close( unix_fd );

    TRACE( "submitted async write: handle=%p fd=%d(%d) buf=%p+%u len=%u\n",
           handle, unix_fd, ring_fd, buffer, already, count - already );
    return 0;
}


/* -----------------------------------------------------------------------
 * Phase 3: Socket I/O
 *
 * NOTE: The msghdr and its iov/control buffers must remain valid until
 * the CQE is processed.  The caller is responsible for keeping them
 * alive (typically on the stack of a function that blocks until
 * completion, or heap-allocated for true async).
 * ----------------------------------------------------------------------- */

/* (Phase 4.8.A) socket-specific RECVMSG submission.  Earlier file-shaped
 * submit_recv / submit_send stubs were removed because their completion
 * routed through file_complete_async which produces wrong NT semantics
 * for socket completions (no try_recv post-process, no
 * set_async_direct_result, no NSPA bitmap clear).
 *
 * Lifetime: msghdr, control buffer, address storage all live in the
 * uring_async_op slot from submit until CQE drain; kernel reads/writes
 * them in place across the io_uring round-trip.  Caller (sock_recv)
 * passes the async_recv_ioctl pointer so the CQE handler can run
 * try_recv_post_process against the populated msghdr. */
/* Setup helper provided by socket.c — populates msghdr / control / addr
 * in the op slot from the async_recv_ioctl.  socket.c-private because
 * async_recv_ioctl layout is socket.c-private. */
extern void try_recv_setup_op_msghdr( void *sock_async,
                                      struct msghdr *hdr,
                                      char *control_buffer,
                                      size_t control_size,
                                      void *addr_storage );

/* Phase 4.8.B: setup helper for SENDMSG — populates msghdr + addr
 * storage in the op slot from the async_send_ioctl.  Needs fd to
 * getsockopt(SO_TYPE).  Returns NTSTATUS (STATUS_ACCESS_VIOLATION on
 * address-conversion failure). */
extern NTSTATUS try_send_setup_op_msghdr( int fd, void *sock_async,
                                          struct msghdr *hdr,
                                          void *addr_storage );

int ntdll_io_uring_submit_socket_recvmsg( int unix_fd, HANDLE handle,
                                          HANDLE wait_handle, HANDLE event,
                                          PIO_APC_ROUTINE apc, void *apc_user,
                                          IO_STATUS_BLOCK *io, unsigned int options,
                                          void *sock_async, int unix_flags )
{
    struct uring_async_op *op;
    struct io_uring_sqe *sqe;
    int ring_fd;

    if (!ensure_ring()) return -ENOSYS;

    /* dup the fd so we own a stable reference for the in-flight SQE — the
     * caller's fd may be closed (or invalidated by handle close) before
     * the CQE arrives. */
    ring_fd = dup_fd_for_ring( unix_fd );
    if (ring_fd < 0) return -errno;

    op = op_pool_alloc();
    if (!op) { close( ring_fd ); return -ENOMEM; }

    op->type         = URING_OP_SOCKET_RECVMSG;
    op->handle       = handle;
    op->event        = event;
    op->apc          = apc;
    op->apc_user     = apc_user;
    op->io           = io;
    op->options      = options;
    op->dup_fd       = ring_fd;
    op->sock_async   = sock_async;
    op->wait_handle  = wait_handle;
    op->poll_unix_fd = unix_fd;        /* for ntdll_client_poll_clear at completion */
    op->event_sync_fd = -1;            /* not pre-resolved (uses set_async_direct_result via wait_handle) */

    /* Populate msghdr / control / addr storage in the op slot from
     * async_recv_ioctl fields.  socket.c-private helper because
     * async_recv_ioctl layout is socket.c-private. */
    try_recv_setup_op_msghdr( sock_async, &op->sock_msghdr,
                              op->sock_control, sizeof(op->sock_control),
                              &op->sock_addr_storage );

    sqe = io_uring_get_sqe( &thread_ring );
    if (!sqe)
    {
        io_uring_submit( &thread_ring );
        ntdll_io_uring_process_completions();
        sqe = io_uring_get_sqe( &thread_ring );
        if (!sqe) { close( ring_fd ); op_pool_free( op ); return -ENOMEM; }
    }

    io_uring_prep_recvmsg( sqe, ring_fd, &op->sock_msghdr, unix_flags );
    io_uring_sqe_set_data( sqe, op );
    io_uring_submit( &thread_ring );
    ntdll_io_uring_inflight_count++;

    TRACE( "submitted socket RECVMSG: handle=%p fd=%d(%d) sock_async=%p flags=%#x\n",
           handle, unix_fd, ring_fd, sock_async, unix_flags );
    return 0;
}

int ntdll_io_uring_submit_socket_sendmsg( int unix_fd, HANDLE handle,
                                          HANDLE wait_handle, HANDLE event,
                                          PIO_APC_ROUTINE apc, void *apc_user,
                                          IO_STATUS_BLOCK *io, unsigned int options,
                                          void *sock_async, int unix_flags )
{
    struct uring_async_op *op;
    struct io_uring_sqe *sqe;
    int ring_fd;
    NTSTATUS setup_status;

    if (!ensure_ring()) return -ENOSYS;

    /* dup the fd so we own a stable reference for the in-flight SQE.
     * Setup uses the original fd because getsockopt(SO_TYPE) and
     * getsockopt(IPX_TYPE) need the original socket — both fds refer
     * to the same kernel object so the result is identical. */
    ring_fd = dup_fd_for_ring( unix_fd );
    if (ring_fd < 0) return -errno;

    op = op_pool_alloc();
    if (!op) { close( ring_fd ); return -ENOMEM; }

    op->type         = URING_OP_SOCKET_SENDMSG;
    op->handle       = handle;
    op->event        = event;
    op->apc          = apc;
    op->apc_user     = apc_user;
    op->io           = io;
    op->options      = options;
    op->dup_fd       = ring_fd;
    op->sock_async   = sock_async;
    op->wait_handle  = wait_handle;
    op->poll_unix_fd = unix_fd;        /* for ntdll_client_poll_clear at completion */
    op->event_sync_fd = -1;

    /* Populate msghdr + address from async_send_ioctl.  Failure here means
     * the address couldn't be converted — surface to caller so it can fall
     * back (rather than submit an SQE that would fault inside the kernel). */
    setup_status = try_send_setup_op_msghdr( unix_fd, sock_async, &op->sock_msghdr,
                                              &op->sock_addr_storage );
    if (setup_status)
    {
        close( ring_fd );
        op_pool_free( op );
        return -EINVAL;   /* generic submit failure; caller falls back */
    }

    sqe = io_uring_get_sqe( &thread_ring );
    if (!sqe)
    {
        io_uring_submit( &thread_ring );
        ntdll_io_uring_process_completions();
        sqe = io_uring_get_sqe( &thread_ring );
        if (!sqe) { close( ring_fd ); op_pool_free( op ); return -ENOMEM; }
    }

    io_uring_prep_sendmsg( sqe, ring_fd, &op->sock_msghdr, unix_flags );
    io_uring_sqe_set_data( sqe, op );
    io_uring_submit( &thread_ring );
    ntdll_io_uring_inflight_count++;

    TRACE( "submitted socket SENDMSG: handle=%p fd=%d(%d) sock_async=%p flags=%#x\n",
           handle, unix_fd, ring_fd, sock_async, unix_flags );
    return 0;
}


/* -----------------------------------------------------------------------
 * Phase 3: Async socket poll
 *
 * Submits an async POLL_ADD for socket readiness.  The CQE fires when
 * the fd becomes readable/writable.  The completion handler calls
 * try_recv/try_send and reports the result via set_async_direct_result.
 *
 * This replaces server-side epoll monitoring for socket I/O — the fd
 * is removed from the wineserver's epoll set (because the async stays
 * in ALERTED state, not WAITING) and monitored client-side via io_uring.
 * ----------------------------------------------------------------------- */

int ntdll_io_uring_submit_socket_poll( int unix_fd, short events,
                                       HANDLE handle, HANDLE wait_handle,
                                       HANDLE event, PIO_APC_ROUTINE apc,
                                       void *apc_user, IO_STATUS_BLOCK *io,
                                       unsigned int options, void *sock_async,
                                       BOOL is_send )
{
    struct uring_async_op *op;
    struct io_uring_sqe *sqe;
    int recv_fd = -1;

    if (!ensure_ring()) return -ENOSYS;

    /* For overlapped sockets (wait_handle == 0), dup the fd now so the
     * CQ drain can call try_recv/try_send without server_get_unix_fd
     * (which is unsafe from CQ drain context — signal manipulation). */
    if (!wait_handle)
    {
        recv_fd = dup( unix_fd );
        if (recv_fd < 0) return -errno;
    }

    op = op_pool_alloc();
    if (!op) { if (recv_fd >= 0) close( recv_fd ); return -ENOMEM; }

    op->type          = is_send ? URING_OP_SOCKET_POLL_SEND : URING_OP_SOCKET_POLL_RECV;
    op->handle        = handle;
    op->event         = event;
    op->apc           = apc;
    op->apc_user      = apc_user;
    op->io            = io;
    op->options       = options;
    op->dup_fd        = recv_fd;  /* overlapped: dup'd fd for try_recv; sync: -1 */
    op->sock_async    = sock_async;
    op->wait_handle   = wait_handle;
    op->poll_unix_fd  = unix_fd;
    /* Pre-resolve event ntsync fd for overlapped — CQ drain can't call
     * get_inproc_sync (server call, signal manipulation = crash). */
    op->event_sync_fd = (!wait_handle && event) ? ntdll_resolve_event_sync_fd( event ) : -1;

    sqe = io_uring_get_sqe( &thread_ring );
    if (!sqe)
    {
        io_uring_submit( &thread_ring );
        ntdll_io_uring_process_completions();
        sqe = io_uring_get_sqe( &thread_ring );
        if (!sqe) { op_pool_free( op ); return -ENOMEM; }
    }

    io_uring_prep_poll_add( sqe, unix_fd, (unsigned)events );
    io_uring_sqe_set_data( sqe, op );
    io_uring_submit( &thread_ring );
    ntdll_io_uring_inflight_count++;

    TRACE( "submitted async socket poll: handle=%p fd=%d events=%#x %s\n",
           handle, unix_fd, events, is_send ? "send" : "recv" );
    return 0;
}


/* -----------------------------------------------------------------------
 * Cooperative completion drain
 *
 * Called from wine_server_call() and server_wait() entry points so that
 * completions are processed in the calling thread's context (preserving
 * RT priority).  Also called from ntdll_io_uring_poll() and before new
 * SQE submissions when the ring is full.
 * ----------------------------------------------------------------------- */

void ntdll_io_uring_process_completions(void)
{
    struct io_uring_cqe *cqe;
    unsigned int head, count = 0;

    if (!ring_initialized) return;

    io_uring_for_each_cqe( &thread_ring, head, cqe )
    {
        struct uring_async_op *op = io_uring_cqe_get_data( cqe );

        /* Only op_pool pointers may be dereferenced — NULL, internal cancel
         * tags and (unique, odd) sync-poll tags from orphaned polls are all
         * discardable on sight.  See the user_data discipline note at the
         * top of the file. */
        if (is_pool_op( op ))
        {
            int result = cqe->res;

            if (result == -EFAULT)
            {
                /* Buffer in a write-watched page.  We cannot retry from
                 * io_uring — let the app re-issue the I/O (which will
                 * fall through to the server async path and use
                 * virtual_locked_read with proper page fault handling).
                 * Socket poll ops need proper cleanup (release_fileio,
                 * set_async_direct_result) — delegate to complete_uring_op
                 * which handles all types correctly. */
                TRACE( "EFAULT for handle %p type=%d — cleanup via complete_uring_op\n",
                       op->handle, op->type );
                complete_uring_op( op, result );
            }
            else
            {
                TRACE( "completing type=%d handle=%p result=%d\n",
                       op->type, op->handle, result );
                complete_uring_op( op, result );
            }
        }
        count++;
    }

    if (count)
        io_uring_cq_advance( &thread_ring, count );
}


/* -----------------------------------------------------------------------
 * U3: drain-capable non-alertable sleep
 *
 * A thread that submits an async op and then blocks in a plain
 * clock_nanosleep / select sits on completions only it can deliver (rings
 * are SINGLE_ISSUER, per-thread): another thread waiting on the op's event
 * stalls for the whole sleep — Sleep(INFINITE) forever.  Windows delivers
 * I/O completions regardless of what the submitting thread is doing, so
 * when this thread owes completions, NtDelayExecution sleeps here instead:
 * ppoll on the ring's registered eventfd, drain + flush on every CQE
 * arrival, re-sleep for the remainder.
 *
 * Draining from a non-alertable sleep is NT-correct: events / IOSBs are
 * published (as the kernel would), and APCs are only *queued* — they still
 * deliver at the next alertable point.
 *
 * @clock_id / @deadline: absolute deadline on that clock; NULL = sleep
 * forever.  Returns TRUE when the deadline was reached (sleep satisfied),
 * FALSE when nothing is left in flight (caller finishes the remaining
 * sleep with the precise clock_nanosleep path) or the mechanism is
 * unavailable.
 * ----------------------------------------------------------------------- */

BOOL ntdll_io_uring_sleep_drain( int clock_id, const struct timespec *deadline )
{
    struct pollfd pfd;

    if (!ring_initialized || ntdll_io_uring_ring_efd < 0) return FALSE;

    pfd.fd     = ntdll_io_uring_ring_efd;
    pfd.events = POLLIN;

    while (ntdll_io_uring_inflight_count || ntdll_io_uring_deferred_count)
    {
        struct timespec rel, *prel = NULL;
        int ret;

        if (deadline)
        {
            struct timespec now;
            clock_gettime( clock_id, &now );
            rel.tv_sec  = deadline->tv_sec - now.tv_sec;
            rel.tv_nsec = deadline->tv_nsec - now.tv_nsec;
            if (rel.tv_nsec < 0) { rel.tv_sec--; rel.tv_nsec += 1000000000; }
            if (rel.tv_sec < 0) return TRUE;   /* deadline already passed */
            prel = &rel;
        }

        pfd.revents = 0;
        ret = ppoll( &pfd, 1, prel, NULL );
        if (ret > 0)
        {
            uint64_t val;
            if (!(pfd.revents & POLLIN)) return FALSE;   /* can't happen on an eventfd; bail to precise sleep */
            /* Clear the (level-triggered) eventfd counter, then deliver.
             * EAGAIN is fine — another drain path may have consumed it. */
            if (read( ntdll_io_uring_ring_efd, &val, sizeof(val) ) < 0) { /* EAGAIN */ }
            ntdll_io_uring_process_completions();
            ntdll_io_uring_flush_deferred();
        }
        else if (ret == 0) return TRUE;   /* deadline reached */
        /* ret < 0: EINTR — non-alertable sleep ignores signals; recompute
         * the remainder and continue (mirrors the clock_nanosleep EINTR
         * retry in NtDelayExecution). */
    }
    return FALSE;   /* nothing left in flight */
}


#else /* !HAVE_LIBURING_H */

/* Stubs — all return -ENOSYS so callers fall back to existing paths */

BOOL ntdll_io_uring_enabled(void) { return FALSE; }
void ntdll_io_uring_cleanup(void) { }
int  ntdll_io_uring_poll( int fd, short events, int timeout_ms ) { return -ENOSYS; }
void ntdll_io_uring_process_completions(void) { }
__thread int ntdll_io_uring_ring_efd = -1;
__thread unsigned int ntdll_io_uring_deferred_count;
__thread unsigned int ntdll_io_uring_inflight_count;
void ntdll_io_uring_flush_deferred_slow(void) { }
BOOL ntdll_io_uring_sleep_drain( int clock_id, const struct timespec *deadline ) { return FALSE; }

int ntdll_io_uring_submit_socket_poll( int unix_fd, short events,
                                       HANDLE handle, HANDLE wait_handle,
                                       HANDLE event, PIO_APC_ROUTINE apc,
                                       void *apc_user, IO_STATUS_BLOCK *io,
                                       unsigned int options, void *sock_async,
                                       BOOL is_send )
{ return -ENOSYS; }

int ntdll_io_uring_submit_file_read( int unix_fd, int needs_close, void *buffer,
                                     ULONG already, ULONG count, HANDLE handle,
                                     HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                     IO_STATUS_BLOCK *io, unsigned int options,
                                     BOOL avail_mode )
{ return -ENOSYS; }

int ntdll_io_uring_submit_file_write( int unix_fd, int needs_close, const void *buffer,
                                      ULONG already, ULONG count, HANDLE handle,
                                      HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                      IO_STATUS_BLOCK *io, unsigned int options )
{ return -ENOSYS; }

int ntdll_io_uring_submit_socket_recvmsg( int unix_fd, HANDLE handle, HANDLE wait_handle,
                                          HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                          IO_STATUS_BLOCK *io, unsigned int options,
                                          void *sock_async, int unix_flags )
{ return -ENOSYS; }

int ntdll_io_uring_submit_socket_sendmsg( int unix_fd, HANDLE handle, HANDLE wait_handle,
                                          HANDLE event, PIO_APC_ROUTINE apc, void *apc_user,
                                          IO_STATUS_BLOCK *io, unsigned int options,
                                          void *sock_async, int unix_flags )
{ return -ENOSYS; }

#endif /* HAVE_LIBURING_H */
