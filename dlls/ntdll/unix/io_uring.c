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

/* -----------------------------------------------------------------------
 * Async op types and per-thread pool (forward declarations needed by
 * ensure_ring → op_pool_init)
 * ----------------------------------------------------------------------- */

enum uring_op_type
{
    URING_OP_FILE_READ,
    URING_OP_FILE_WRITE,
    URING_OP_SOCKET_RECV,
    URING_OP_SOCKET_SEND,
    URING_OP_SOCKET_POLL_RECV,  /* Phase 3: async poll for socket recv readiness */
    URING_OP_SOCKET_POLL_SEND,  /* Phase 3: async poll for socket send readiness */
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
    struct uring_async_op *next_free; /* freelist link (only valid when not in flight) */
};

/* Pre-allocated per-thread op pool.  At most RING_SIZE SQEs can be in
 * flight simultaneously, so a fixed array of that size is sufficient.
 * Allocated once at ring init time — zero malloc in the submit path. */
static __thread struct uring_async_op  op_pool[RING_SIZE];
static __thread struct uring_async_op *op_free_head;

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
static __thread int  ring_efd = -1;   /* eventfd for CQE notification (ntsync integration) */

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
    ring_efd = eventfd( 0, EFD_NONBLOCK | EFD_CLOEXEC );
    if (ring_efd >= 0)
    {
        if (io_uring_register_eventfd( &thread_ring, ring_efd ) < 0)
        {
            WARN( "io_uring_register_eventfd failed: %s\n", strerror( errno ) );
            close( ring_efd );
            ring_efd = -1;
        }
    }

    /* One-time banner on first ring init in the process */
    {
        static LONG once;
        if (!InterlockedExchange( &once, 1 ))
            fprintf( stderr, "wine: NSPA RT:io_uring: ring active (sq=%u cq=%u flags=0x%x efd=%d) — file I/O bypasses wineserver\n",
                     params.sq_entries, params.cq_entries, params.flags, ring_efd );
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
    if (ring_efd >= 0) { close( ring_efd ); ring_efd = -1; }
    ring_initialized = FALSE;
    TRACE( "io_uring ring cleaned up\n" );
}

/* Return the io_uring eventfd for this thread, or -1 if unavailable.
 * Used by sync.c to pass to ntsync uring_fd for CQE wakeup. */
int ntdll_io_uring_get_eventfd(void)
{
    return ring_efd;
}


/* -----------------------------------------------------------------------
 * Phase 1: Blocking poll replacement
 *
 * Replaces poll(fd, events, timeout_ms) in synchronous I/O wait loops.
 * Returns: positive revents on success, 0 on timeout, negative on error.
 * ----------------------------------------------------------------------- */

int ntdll_io_uring_poll( int fd, short events, int timeout_ms )
{
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    struct __kernel_timespec ts;
    int ret;

    if (!ensure_ring()) return -ENOSYS;

    /* drain any pending completions first */
    ntdll_io_uring_process_completions();

    sqe = io_uring_get_sqe( &thread_ring );
    if (!sqe) return -ENOMEM;

    io_uring_prep_poll_add( sqe, fd, (unsigned)events );
    io_uring_sqe_set_data( sqe, NULL );

    if (timeout_ms > 0)
    {
        ts.tv_sec  = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000;
        ret = io_uring_submit_and_wait_timeout( &thread_ring, &cqe, 1, &ts, NULL );
    }
    else if (timeout_ms == 0)
    {
        io_uring_submit( &thread_ring );
        ret = io_uring_peek_cqe( &thread_ring, &cqe );
    }
    else
    {
        io_uring_submit( &thread_ring );
        ret = io_uring_wait_cqe( &thread_ring, &cqe );
    }

    if (ret == -ETIME || (ret == -EAGAIN && timeout_ms == 0))
    {
        /* timed out — cancel the pending poll, drain all CQEs */
        struct io_uring_sqe *cancel_sqe = io_uring_get_sqe( &thread_ring );
        if (cancel_sqe)
        {
            io_uring_prep_cancel64( cancel_sqe, 0, 0 );
            io_uring_sqe_set_data( cancel_sqe, URING_INTERNAL_TAG );
            io_uring_submit( &thread_ring );
            /* wait for the cancel completion + the cancelled poll */
            for (int i = 0; i < 2; i++)
            {
                if (io_uring_wait_cqe( &thread_ring, &cqe ) == 0)
                    io_uring_cqe_seen( &thread_ring, cqe );
            }
        }
        return 0;  /* timeout — matches poll() returning 0 */
    }
    if (ret < 0) return ret;

    ret = cqe->res;
    io_uring_cqe_seen( &thread_ring, cqe );
    return (ret < 0) ? ret : ret;  /* revents mask or error */
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
 * The CQE result contains poll revents (POLLIN/POLLOUT/etc).
 * We call the socket I/O completion function in socket.c which
 * does try_recv/try_send and set_async_direct_result. */
extern void ntdll_complete_socket_poll( struct uring_async_op *op, int poll_revents );

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

static void complete_uring_op( struct uring_async_op *op, int result )
{
    NTSTATUS status;
    ULONG_PTR information;

    /* Socket poll completions are handled differently — the result is
     * poll events, not bytes transferred. Delegate to socket.c. */
    if (op->type == URING_OP_SOCKET_POLL_RECV || op->type == URING_OP_SOCKET_POLL_SEND)
    {
        ntdll_complete_socket_poll( op, result );
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

int ntdll_io_uring_submit_recv( int unix_fd, int needs_close, struct msghdr *hdr,
                                int flags, HANDLE handle, HANDLE event,
                                PIO_APC_ROUTINE apc, void *apc_user,
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

    op->type     = URING_OP_SOCKET_RECV;
    op->handle   = handle;
    op->event    = event;
    op->apc      = apc;
    op->apc_user = apc_user;
    op->io       = io;
    op->options  = options;
    op->dup_fd   = ring_fd;

    sqe = io_uring_get_sqe( &thread_ring );
    if (!sqe)
    {
        io_uring_submit( &thread_ring );
        ntdll_io_uring_process_completions();
        sqe = io_uring_get_sqe( &thread_ring );
        if (!sqe) { close( ring_fd ); op_pool_free( op ); return -ENOMEM; }
    }

    io_uring_prep_recvmsg( sqe, ring_fd, hdr, flags );
    io_uring_sqe_set_data( sqe, op );
    io_uring_submit( &thread_ring );

    if (needs_close) close( unix_fd );
    return 0;
}


int ntdll_io_uring_submit_send( int unix_fd, int needs_close, struct msghdr *hdr,
                                int flags, HANDLE handle, HANDLE event,
                                PIO_APC_ROUTINE apc, void *apc_user,
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

    op->type     = URING_OP_SOCKET_SEND;
    op->handle   = handle;
    op->event    = event;
    op->apc      = apc;
    op->apc_user = apc_user;
    op->io       = io;
    op->options  = options;
    op->dup_fd   = ring_fd;

    sqe = io_uring_get_sqe( &thread_ring );
    if (!sqe)
    {
        io_uring_submit( &thread_ring );
        ntdll_io_uring_process_completions();
        sqe = io_uring_get_sqe( &thread_ring );
        if (!sqe) { close( ring_fd ); op_pool_free( op ); return -ENOMEM; }
    }

    io_uring_prep_sendmsg( sqe, ring_fd, hdr, flags );
    io_uring_sqe_set_data( sqe, op );
    io_uring_submit( &thread_ring );

    if (needs_close) close( unix_fd );
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

    if (!ensure_ring()) return -ENOSYS;

    op = op_pool_alloc();
    if (!op) return -ENOMEM;

    op->type        = is_send ? URING_OP_SOCKET_POLL_SEND : URING_OP_SOCKET_POLL_RECV;
    op->handle      = handle;
    op->event       = event;
    op->apc         = apc;
    op->apc_user    = apc_user;
    op->io          = io;
    op->options     = options;
    op->dup_fd       = -1;  /* POLL_ADD — kernel pins the file, no dup needed */
    op->sock_async   = sock_async;
    op->wait_handle  = wait_handle;
    op->poll_unix_fd = unix_fd;  /* for bitmap clear on completion */

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

        if (op && op != URING_INTERNAL_TAG)
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


#else /* !HAVE_LIBURING_H */

/* Stubs — all return -ENOSYS so callers fall back to existing paths */

BOOL ntdll_io_uring_enabled(void) { return FALSE; }
void ntdll_io_uring_cleanup(void) { }
int  ntdll_io_uring_poll( int fd, short events, int timeout_ms ) { return -ENOSYS; }
void ntdll_io_uring_process_completions(void) { }
int  ntdll_io_uring_get_eventfd(void) { return -1; }

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

int ntdll_io_uring_submit_recv( int unix_fd, int needs_close, struct msghdr *hdr,
                                int flags, HANDLE handle, HANDLE event,
                                PIO_APC_ROUTINE apc, void *apc_user,
                                IO_STATUS_BLOCK *io, unsigned int options )
{ return -ENOSYS; }

int ntdll_io_uring_submit_send( int unix_fd, int needs_close, struct msghdr *hdr,
                                int flags, HANDLE handle, HANDLE event,
                                PIO_APC_ROUTINE apc, void *apc_user,
                                IO_STATUS_BLOCK *io, unsigned int options )
{ return -ENOSYS; }

#endif /* HAVE_LIBURING_H */
