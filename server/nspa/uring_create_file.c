/*
 * NSPA Phase 4 — async-completing handler for req_create_file.
 *
 * On submit:  validate eligibility, copy out request data, grab ref
 *             on current thread, allocate async ctx, submit
 *             IORING_OP_OPENAT with IOSQE_ASYNC, defer reply.
 * On CQE:     wrap unix_fd via create_inode_fd_from_unix_fd, build
 *             struct file via create_file_obj, alloc handle, write
 *             reply, signal channel, release thread ref.
 *
 * Eligibility (narrow first cut, matches Phase C's read-only narrowing
 * from ffb15c8cf6d to avoid the cross-thread async/atomic-rename
 * residual that was reverted with the broken bridge):
 *   - Gate NSPA_ENABLE_ASYNC_CREATE_FILE=1 (default OFF)
 *   - objattr->rootdir == 0  (AT_FDCWD only — no rootdir-relative)
 *   - create == FILE_OPEN    (no creation/truncation paths)
 *   - !(options & FILE_DIRECTORY_FILE)
 *   - sd == NULL             (no custom security descriptor)
 *   - !(options & FILE_DELETE_ON_CLOSE)
 *   - !(access & FILE_UNIX_WRITE_ACCESS)  (read-only — Phase 4 first cut)
 *   - name + nt_name fit in inline buffers
 *   - per-process uring active, ctx pool not exhausted, SQ not full
 *
 * Anything outside this set falls through to the synchronous path.
 *
 * Lifetime contract vs original Phase C:
 *   - submit: grab_object(current).  CQE: release_object(ctx->thread).
 *     Closes the window where the requesting thread terminates while
 *     the openat is in flight (would have been ctx->thread UAF).
 *   - per-process uring is owned by the gamma dispatcher pthread;
 *     dispatcher exit drains in-flight CQEs before tearing down the
 *     ring (server/nspa/shmem_channel.c::channel_dispatcher cleanup).
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef HAVE_LIBURING_H
#include <liburing.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winbase.h"

#include "../object.h"   /* current, debug_level, grab_object, release_object */
#include "../process.h"
#include "../thread.h"
#include "../request.h"
#include "../file.h"     /* file_set_error, create_inode_fd_from_unix_fd, create_file_obj, file_type, set_error */
#include "../handle.h"   /* alloc_handle */
#include "../security.h"
#include "../unicode.h"  /* struct unicode_str */
#include "uring.h"
#include "uring_create_file.h"

#ifdef HAVE_LIBURING_H

/* -----------------------------------------------------------------
 * Async ctx pool.  Sized to match the io_uring ring depth so a
 * successful ctx alloc guarantees an SQE slot is also available.
 * Inline name + nt_name buffers avoid heap on the submit path.
 *
 * Pool is wineserver-global (one main wineserver process).  All
 * allocations happen under global_lock, so no atomics needed on the
 * freelist.
 * ----------------------------------------------------------------- */

#define NSPA_ACF_NAME_MAX  4096   /* PATH_MAX on Linux */
#define NSPA_ACF_POOL_SIZE 64

struct create_file_async_ctx
{
    /* Reply context — needed to complete the channel REPLY. */
    struct thread       *thread;
    struct request_shm  *request_shm;
    unsigned int         data_size;
    int                  channel_fd;
    unsigned long long   entry_id;

    /* Original request args, copied so they survive the dispatcher
     * pthread loading a fresh request into thread->req. */
    unsigned int         access;
    unsigned int         sharing;
    unsigned int         options;
    unsigned int         attrs;
    unsigned int         objattr_attributes;
    /* req->create is always FILE_OPEN — we filter eligibility for it */

    /* Inline-copied path data. */
    char                 name[NSPA_ACF_NAME_MAX];
    unsigned int         name_len;
    WCHAR                nt_name_buf[NSPA_ACF_NAME_MAX / sizeof(WCHAR)];
    unsigned int         nt_name_byte_len;

    /* Submit-time prep. */
    int                  open_flags;   /* O_RDONLY/O_RDWR/etc | O_NONBLOCK */
    mode_t               mode;

    /* Pool freelist. */
    struct create_file_async_ctx *next_free;
};

static struct create_file_async_ctx g_ctx_pool[NSPA_ACF_POOL_SIZE];
static struct create_file_async_ctx *g_ctx_free_head = NULL;
static int g_ctx_pool_initialised = 0;

static void ctx_pool_init( void )
{
    int i;
    if (g_ctx_pool_initialised) return;
    for (i = 0; i < NSPA_ACF_POOL_SIZE - 1; i++)
        g_ctx_pool[i].next_free = &g_ctx_pool[i + 1];
    g_ctx_pool[NSPA_ACF_POOL_SIZE - 1].next_free = NULL;
    g_ctx_free_head = &g_ctx_pool[0];
    g_ctx_pool_initialised = 1;
}

static struct create_file_async_ctx *ctx_alloc( void )
{
    struct create_file_async_ctx *c;
    if (!g_ctx_free_head) return NULL;
    c = g_ctx_free_head;
    g_ctx_free_head = c->next_free;
    c->next_free = NULL;
    return c;
}

static void ctx_free( struct create_file_async_ctx *c )
{
    if (!c) return;
    c->next_free = g_ctx_free_head;
    g_ctx_free_head = c;
}

/* -----------------------------------------------------------------
 * Gate.  Cached on first call.  Setting NSPA_ENABLE_ASYNC_CREATE_FILE=1
 * enables; default is OFF.
 * ----------------------------------------------------------------- */

static int gate_enabled( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv( "NSPA_ENABLE_ASYNC_CREATE_FILE" );
        cached = (v && *v && *v != '0') ? 1 : 0;
        if (debug_level && cached)
            fprintf( stderr, "wineserver: nspa_uring_create_file enabled via gate\n" );
    }
    return cached;
}

/* -----------------------------------------------------------------
 * CQE callback.  Runs from nspa_uring_drain() under global_lock
 * (acquired by the gamma dispatcher around drain — see
 * server/nspa/shmem_channel.c::channel_dispatcher uring-fired branch).
 * cqe->res is the openat result (negative errno on failure, unix_fd
 * on success).  ctx is the pool entry stamped on user_data at submit.
 * ----------------------------------------------------------------- */

static void create_file_cqe_callback( void *ctx_ptr, int result )
{
    struct create_file_async_ctx *ctx = ctx_ptr;
    struct thread *saved_current = current;
    struct unicode_str nt_name;
    struct fd *fd = NULL;
    struct object *file_obj = NULL;

    if (!ctx) return;

    /* Restore the requesting thread as current so all subsequent
     * server helpers (alloc_handle, etc.) bind to its process.
     * ctx->thread is kept alive by the grab_object we did at submit
     * time — released at the end of this function. */
    current = ctx->thread;

    nt_name.str = ctx->nt_name_buf;
    nt_name.len = ctx->nt_name_byte_len;

    /* DIAGNOSTIC (NSPA_ENABLE_ASYNC_CREATE_FILE_DEBUG=1): log every
     * async create_file CQE so we can trace which files go through
     * the async path and the result.  Critical for chasing the
     * Ableton Undo regression — gives us the path + result + access
     * + options so we can correlate with sync-path traces. */
    {
        static int diag_cached = -1;
        if (diag_cached < 0)
        {
            const char *v = getenv( "NSPA_ENABLE_ASYNC_CREATE_FILE_DEBUG" );
            diag_cached = (v && *v && *v != '0') ? 1 : 0;
        }
        if (diag_cached)
            fprintf( stderr, "[async-create-file] result=%d name=%s access=%#x sharing=%#x options=%#x\n",
                     result, ctx->name, ctx->access, ctx->sharing, ctx->options );
    }

    /* Initialise reply payload to safe default before we possibly
     * set_error.  send_reply_shm reads thread->error / reply_size
     * via nspa_uring_signal_reply. */
    ctx->request_shm->u.reply.create_file_reply.handle = 0;
    current->error = 0;
    current->reply_size = 0;

    if (result < 0)
    {
        /* openat failed.  Map -errno to NTSTATUS via the same path
         * the synchronous handler uses (file_set_error reads errno). */
        errno = -result;
        if (errno == ENOENT && ctx->name_len > 0 && ctx->name[ctx->name_len - 1] == '/')
            set_error( STATUS_OBJECT_NAME_INVALID );
        else
            file_set_error();
        goto reply;
    }

    /* result is the unix_fd.  Use nspa_create_fd_from_async_unix_fd
     * which produces an fd with IDENTICAL NT semantics to what the
     * synchronous open_fd path would have produced — same closed_fd
     * disp_flags wiring, same realpath-based unix_name, same sharing
     * check (with real flags, not 0), same FADV / O_TRUNC handling.
     *
     * Critical for app correctness: replacing create_inode_fd_from_unix_fd
     * here was the fix for the Ableton Undo regression — that helper
     * was a SUBSET of open_fd's post-openat work and shipped a
     * half-cooked NT handle.  See feedback_async_must_match_sync_semantics.md.
     *
     * Takes ownership of the fd: closes on failure. */
    {
        mode_t out_mode = 0;

        fd = nspa_create_fd_from_async_unix_fd( result, NULL /* root: AT_FDCWD */,
                                                 ctx->name, nt_name,
                                                 ctx->open_flags, &out_mode,
                                                 ctx->access, ctx->sharing,
                                                 ctx->options );
        if (!fd) goto reply;  /* error already set; unix_fd already closed */

        /* Mirror create_file()'s dispatch (server/file.c lines 277-282):
         * directories → create_dir_obj, char devices that are serial
         * ports → create_serial, everything else → create_file_obj.
         * Phase 4 eligibility doesn't gate on FILE_DIRECTORY_FILE in
         * options because Win32 lets you open a directory handle
         * without that flag (e.g. wineboot opens /windows/system32/
         * with FILE_LIST_DIRECTORY only).  Calling create_file_obj on
         * an S_ISDIR fd produces a wrong-type handle: subsequent
         * NtQueryDirectoryFile, NtSetInformation, etc. behave
         * incorrectly. */
        if (S_ISDIR(out_mode))
            file_obj = create_dir_obj( fd, ctx->access, out_mode );
        else if (S_ISCHR(out_mode) && is_serial_fd(fd))
            file_obj = create_serial( fd );
        else
            file_obj = create_file_obj( fd, ctx->access, out_mode );
        release_object( fd );
        if (!file_obj) goto reply;  /* error already set */
    }

    ctx->request_shm->u.reply.create_file_reply.handle =
        alloc_handle( current->process, file_obj, ctx->access, ctx->objattr_attributes );
    release_object( file_obj );

reply:
    nspa_uring_signal_reply( current, ctx->request_shm, ctx->data_size,
                             ctx->channel_fd, ctx->entry_id );
    current = saved_current;

    /* Release the thread ref we grabbed at submit.  Must happen AFTER
     * signal_reply (which uses ctx->thread → current). */
    release_object( ctx->thread );

    ctx_free( ctx );
}

/* -----------------------------------------------------------------
 * Eligibility check.  Returns 1 if the request can be async-dispatched.
 * ----------------------------------------------------------------- */

static int eligible(
    const struct create_file_request *req,
    const struct object_attributes *objattr,
    const struct security_descriptor *sd,
    struct unicode_str nt_name,
    unsigned int name_len )
{
    unsigned int mapped_access;

    if (!gate_enabled()) return 0;
    if (objattr->rootdir) return 0;       /* AT_FDCWD only */
    if (sd) return 0;                      /* no custom SD */
    if (req->create != FILE_OPEN) return 0;
    if (req->options & FILE_DIRECTORY_FILE) return 0;
    if (req->options & FILE_DELETE_ON_CLOSE) return 0;

    /* CRITICAL: the access check MUST run on MAPPED access.  req->access
     * is the raw value from the client and may carry GENERIC_READ /
     * GENERIC_WRITE / GENERIC_ALL bits that don't expand into
     * FILE_UNIX_WRITE_ACCESS until map_access() runs against the file
     * type's generic-mapping table.  Before this fix Phase 4 would
     * accept GENERIC_READ|GENERIC_WRITE opens (req->access & WRITE_BITS
     * == 0 since GENERIC_* are in 0x4000000-range), open the file
     * O_RDONLY, hand back a handle that LOOKS like it has write access
     * (post-map ctx->access has WRITE_DATA bits), then writes through
     * that handle would fail with EBADF.  Ableton's Undo journal hit
     * exactly this — observed in nspa-logs/ableton_phase4_debug_*.log
     * with access=0x12019f for Undo.lock and 0.band.
     *
     * Read-only first cut.  Eventually we'll widen to write opens, but
     * not until we have a story for FILE_DELETE_ON_CLOSE temp files
     * + atomic-write-then-rename (Ableton's pattern). */
    mapped_access = map_access( req->access, &file_type.mapping );
    /* Reject ALL write-class access bits, not just FILE_UNIX_WRITE_ACCESS.
     * DELETE alone is enough to drive Ableton's atomic-write-then-rename
     * flow on Undo/AbletonTmp-* — observed in the debug log.  Until we
     * understand the full close-time delete + rename semantics under
     * async, exclude every bit that would normally exercise those paths. */
    if (mapped_access & (FILE_UNIX_WRITE_ACCESS | DELETE | WRITE_DAC | WRITE_OWNER))
        return 0;

    if (name_len == 0 || name_len >= NSPA_ACF_NAME_MAX) return 0;
    if (nt_name.len > sizeof(((struct create_file_async_ctx *)0)->nt_name_buf)) return 0;
    /* per-process uring must be active for this process */
    if (!current || !current->process) return 0;
    if (nspa_uring_get_eventfd( current->process->nspa_uring ) < 0) return 0;
    return 1;
}

/* -----------------------------------------------------------------
 * try_async — main entry point from DECL_HANDLER(create_file).
 * Returns 1 if dispatched async, 0 if caller should fall through.
 * ----------------------------------------------------------------- */

int nspa_uring_create_file_try_async(
    const struct create_file_request *req,
    const struct object_attributes *objattr,
    const struct security_descriptor *sd,
    struct unicode_str nt_name,
    const char *name, unsigned int name_len )
{
    struct create_file_async_ctx *ctx;
    struct nspa_uring_pending *pending;
    struct io_uring_sqe *sqe;
    struct nspa_uring_instance *uring;
    int rw_mode;

    ctx_pool_init();

    if (!eligible( req, objattr, sd, nt_name, name_len )) return 0;
    if (!current || !current->request_shm || current->process->request_channel_fd < 0)
        return 0;

    uring = current->process->nspa_uring;
    if (!uring) return 0;

    if (!(ctx = ctx_alloc()))
    {
        if (debug_level)
            fprintf( stderr, "wineserver: nspa_uring_create_file ctx pool exhausted, falling back\n" );
        return 0;
    }

    /* Copy out everything we'll need in the CQE callback.  Critical:
     * expand req->access through the file-type access map so generic
     * bits (GENERIC_READ/WRITE/EXECUTE) become specific file rights
     * (FILE_READ_DATA / etc.) before the handle is minted.  Without
     * this, subsequent NtReadFile/NtClose paths see raw GENERIC_*
     * bits on the handle and fail their access checks.  Mirrors the
     * sync path in server/file.c::create_file. */
    ctx->thread             = current;
    ctx->request_shm        = (struct request_shm *)current->request_shm;
    ctx->data_size          = current->req.request_header.request_size;
    ctx->channel_fd         = current->process->request_channel_fd;
    ctx->entry_id           = current->nspa_channel_entry_id;
    ctx->access             = map_access( req->access, &file_type.mapping );
    ctx->sharing            = req->sharing;
    ctx->options            = req->options;
    ctx->attrs              = req->attrs;
    ctx->objattr_attributes = objattr->attributes;

    memcpy( ctx->name, name, name_len );
    ctx->name[name_len] = 0;
    ctx->name_len = name_len;

    if (nt_name.len)
    {
        memcpy( ctx->nt_name_buf, nt_name.str, nt_name.len );
        ctx->nt_name_byte_len = nt_name.len;
    }
    else
    {
        ctx->nt_name_byte_len = 0;
    }

    /* Compute open flags the same way create_file()/open_fd() does
     * for FILE_OPEN.  Eligibility excluded write access, but keep the
     * generic shape for clarity (rw_mode collapses to O_RDONLY here). */
    if ((req->access & FILE_UNIX_WRITE_ACCESS) && !(req->options & FILE_DIRECTORY_FILE))
    {
        if (req->access & FILE_UNIX_READ_ACCESS) rw_mode = O_RDWR;
        else rw_mode = O_WRONLY;
    }
    else rw_mode = O_RDONLY;
    ctx->open_flags = rw_mode | O_NONBLOCK;
    ctx->mode = (req->attrs & FILE_ATTRIBUTE_READONLY) ? 0444 : 0666;

    /* Reserve io_uring resources.  pending_alloc + get_sqe MUST come
     * BEFORE grab_object(current) — if either fails we want to bail
     * cleanly without a leftover thread ref. */
    pending = nspa_uring_pending_alloc( uring, create_file_cqe_callback, ctx );
    if (!pending)
    {
        ctx_free( ctx );
        return 0;
    }

    sqe = nspa_uring_get_sqe( uring );
    if (!sqe)
    {
        nspa_uring_pending_free( uring, pending );
        ctx_free( ctx );
        return 0;
    }

    /* Grab a ref on the requesting thread so the CQE callback can
     * use ctx->thread safely even if the thread terminates while the
     * openat is in flight.  Closes the UAF the original Phase C had.
     * Released in create_file_cqe_callback after signal_reply. */
    grab_object( current );

    /* Submit IORING_OP_OPENAT.  IOSQE_ASYNC is load-bearing: it
     * forces the openat to dispatch through the io_uring kernel
     * worker pool rather than inline-submit on this RT thread.
     * (nspa_uring_get_sqe already pre-set the flag, but be explicit
     * so anyone reading this code sees the intent.) */
    io_uring_prep_openat( sqe, AT_FDCWD, ctx->name, ctx->open_flags, ctx->mode );
    sqe->flags |= IOSQE_ASYNC;
    io_uring_sqe_set_data( sqe, pending );

    /* Mark the thread's reply as deferred.  Both call_req_handler_shm
     * (request.c) and the gamma dispatcher (shmem_channel.c) will skip
     * their reply paths and let the CQE callback own completion. */
    nspa_uring_defer_reply( current );

    if (nspa_uring_submit( uring ) < 0)
    {
        /* Submission failed — recover.  This is rare (the kernel ran
         * out of room mid-submit).  Clear defer flag, drop the thread
         * ref we just grabbed, and fall through so the synchronous
         * path can run instead. */
        current->nspa_async_reply_deferred = 0;
        release_object( current );
        nspa_uring_pending_free( uring, pending );
        ctx_free( ctx );
        return 0;
    }

    return 1;  /* dispatched async; handler returns immediately */
}

#else  /* !HAVE_LIBURING_H */

int nspa_uring_create_file_try_async(
    const struct create_file_request *req,
    const struct object_attributes *objattr,
    const struct security_descriptor *sd,
    struct unicode_str nt_name,
    const char *name, unsigned int name_len )
{
    (void)req; (void)objattr; (void)sd; (void)nt_name;
    (void)name; (void)name_len;
    return 0;
}

#endif /* HAVE_LIBURING_H */
