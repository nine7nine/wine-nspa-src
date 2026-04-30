/*
 * NSPA shm-IPC γ: per-process kernel-mediated request/reply channel.
 *
 * Wineserver-side implementation.  Replaces N×nspa_request_shm_thread
 * per-thread dispatcher pthreads with one per-process channel
 * dispatcher pthread that does CHANNEL_RECV → handle → CHANNEL_REPLY
 * in a loop.  Priority inheritance is kernel-mediated: senders boost
 * the dispatcher atomically via SEND_PI, and the kernel re-boosts on
 * each RECV pop to the popped entry's priority for the duration of
 * the handler.  No more user-space sched_setscheduler boost machinery.
 *
 * The channel fd is opened in process attach (create_process) and
 * sent to the client via SCM_RIGHTS in the init_first_thread reply
 * (mirroring the existing per-thread request_shm fd plumbing).  When
 * the process terminates, closing the channel fd causes the dispatcher's
 * blocked CHANNEL_RECV to return EBADF; the (detached) pthread exits.
 *
 * Payload convention:
 *   payload_off = client-side TID (Wine thread id_t cast to u64).
 *   reply_off   = same; the channel only carries metadata, the actual
 *                 request/reply payload lives in the per-thread
 *                 request_shm region (zero-copy, unchanged from v1.5).
 *
 * RT-safety:
 *   - Dispatcher inherits explicit SCHED_FIFO attrs when
 *     NSPA_SRV_RT_PRIO is set (matching v1.5 per-thread dispatcher).
 *     When a sender posts at higher priority, the kernel boosts the
 *     dispatcher atomically (apply_event_pi_boost machinery).  The
 *     dispatcher returns to its base attrs on the next RECV via
 *     drain_event_pi_boosts, then auto-re-boosts to the next entry's
 *     priority — no PI gaps between requests.
 *   - global_lock is taken once per request inside the dispatcher; with
 *     only one dispatcher per process, contention reduces from O(N
 *     threads) to O(1) per process.
 *
 * NT semantics:
 *   - Per-thread request ordering is preserved (each sender blocks for
 *     reply, so a thread's k-th request precedes its (k+1)-th).
 *   - Cross-thread ordering becomes priority-ordered, which is strictly
 *     stronger than the prior "whichever pthread wakes first" shape.
 */

#include "config.h"

#ifdef __linux__

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/ntsync.h>

/* NSPA gamma: channel UAPI fallback for systems whose linux/ntsync.h
 * predates patch 1004-ntsync-channel.patch.  Same pattern as the
 * NTSYNC_IOC_EVENT_SET_PI fallback in dlls/ntdll/unix/sync.c. */
#ifndef NTSYNC_IOC_CREATE_CHANNEL
struct ntsync_channel_create_args {
    __u32 max_depth;
    __u32 __pad;
};
struct ntsync_channel_send_args {
    __u32 policy;
    __u32 prio;
    __u64 payload_off;
    __u64 reply_off;
};
struct ntsync_channel_recv_args {
    __u64 entry_id;
    __u64 payload_off;
    __u64 reply_off;
    __u32 sender_tid;
    __u32 prio;
};
# define NTSYNC_IOC_CREATE_CHANNEL  _IOWR('N', 0x90, struct ntsync_channel_create_args)
# define NTSYNC_IOC_CHANNEL_SEND_PI _IOWR('N', 0x91, struct ntsync_channel_send_args)
# define NTSYNC_IOC_CHANNEL_RECV    _IOWR('N', 0x92, struct ntsync_channel_recv_args)
# define NTSYNC_IOC_CHANNEL_REPLY   _IOW ('N', 0x93, __u64)
#endif

/* NSPA gamma: thread-token pass-through fallback (1005-ntsync-channel-thread-token).
 * Independent #ifndef so it works against both pre-1004 and post-1004
 * kernel headers that lack the 1005 additions. */
#ifndef NTSYNC_IOC_CHANNEL_REGISTER_THREAD
struct ntsync_channel_register_thread_args {
    __u32 tid;
    __u32 __pad;
    __u64 token;
};
struct ntsync_channel_recv2_args {
    __u64 entry_id;
    __u64 payload_off;
    __u64 reply_off;
    __u32 sender_tid;
    __u32 prio;
    __u64 thread_token;
};
# define NTSYNC_IOC_CHANNEL_REGISTER_THREAD \
            _IOW ('N', 0x94, struct ntsync_channel_register_thread_args)
# define NTSYNC_IOC_CHANNEL_DEREGISTER_THREAD \
            _IOW ('N', 0x95, __u32)
# define NTSYNC_IOC_CHANNEL_RECV2 \
            _IOWR('N', 0x96, struct ntsync_channel_recv2_args)
#endif

/* NSPA 1010 Phase 3: AGGREGATE_WAIT UAPI fallback.  Independent #ifndef
 * so this builds against any kernel header up to ntsync 1009 — runtime
 * detect via ENOTTY at first ioctl falls back to direct CHANNEL_RECV2
 * (today's behaviour). */
#ifndef NTSYNC_IOC_AGGREGATE_WAIT
struct ntsync_aggregate_source {
    __u32 type;
    __u32 events;
    __u32 fd;
    __u32 __pad;
};
struct ntsync_aggregate_wait_args {
    __u64 timeout;
    __u64 sources;
    __u32 nb_sources;
    __u32 fired_index;
    __u32 flags;
    __u32 owner;
    __u32 fired_events;
    __u32 __pad;
};
# define NTSYNC_AGG_OBJECT          0x1
# define NTSYNC_AGG_FD              0x2
# define NTSYNC_AGG_FLAG_REALTIME   0x1
# define NTSYNC_AGG_TIMEOUT         0xFFFFFFFFu
# define NTSYNC_IOC_AGGREGATE_WAIT \
            _IOWR('N', 0x97, struct ntsync_aggregate_wait_args)
#endif

#include "process.h"
#include "thread.h"
#include "request.h"
#include "file.h"
#include "nspa/rt.h"
#include "nspa/shmem_channel.h"
#include "nspa/uring.h"

#define NSPA_CHANNEL_MAX_DEPTH 256

extern int get_inproc_device_fd(void); /* server/inproc_sync.c */

/*
 * NSPA 1010 Phase 3: heap-owned dispatcher context.  Owns the per-
 * process io_uring instance and the shutdown eventfd.  The pthread
 * arg is a struct nspa_dispatcher_ctx *; the dispatcher frees the
 * struct on its way out (NOT shmem_channel_destroy).
 *
 * Lifetime contract:
 *  - shmem_channel_init: alloc ctx, init uring inside it, store back-
 *    pointers in process for handler access (process->nspa_uring,
 *    process->nspa_dispatcher_ctx), pthread_create.
 *  - shmem_channel_destroy: write to ctx->shutdown_efd to wake the
 *    dispatcher, close the channel_fd (EBADF wakes pre-1010 fallback
 *    path), clear process->* back-pointers.  Does NOT free ctx —
 *    the process struct may be torn down concurrently with the
 *    dispatcher pthread, so the dispatcher owns ctx lifetime.
 *  - dispatcher exit: drain in-flight CQEs, shutdown uring, close
 *    shutdown_efd, free ctx.
 *
 * The dispatcher must NEVER touch struct process — process may be
 * freed before the dispatcher finishes its cleanup.  All state the
 * dispatcher needs is in ctx.  (Existing thread->process touch on
 * the request thread is OK — that thread holds a ref keeping its
 * process alive for the duration of the request.)
 */
struct nspa_dispatcher_ctx
{
    int channel_fd;                       /* channel ntsync fd */
    int shutdown_efd;                     /* eventfd: destroy writes 1 to wake dispatcher */
    struct nspa_uring_instance uring;     /* embedded; init at ctx alloc, shutdown at dispatcher exit */
};

/*
 * Dispatcher pthread.  Has two operating modes selected at runtime:
 *
 * Post-1010 (preferred): NTSYNC_IOC_AGGREGATE_WAIT on
 *   {channel, uring eventfd, shutdown eventfd} — atomic wait for
 *   either channel request, io_uring CQE, or shutdown signal.  On
 *   channel-fired, follows up with CHANNEL_RECV2 to consume the
 *   entry (existing path, unchanged).  On uring-fired, drains CQEs
 *   inline.  On shutdown-fired, cleans up and exits.
 *
 * Pre-1010 fallback: direct CHANNEL_RECV2 (or legacy CHANNEL_RECV
 * when NSPA_DISPATCHER_USE_TOKEN=0) — today's behaviour.  Exits on
 * EBADF when shmem_channel_destroy closes channel_fd.
 *
 * Selection is by ENOTTY at first AGGREGATE_WAIT call (set
 * agg_supported = 0 permanently for this ctx).  Once detected, no
 * per-iteration cost.
 *
 * The default since 2026-04-26 is RECV2 + direct thread_token
 * consumption (skips get_thread_from_id when the kernel provides a
 * non-zero token).  Set NSPA_DISPATCHER_USE_TOKEN=0 to force legacy
 * RECV + get_thread_from_id for A/B testing.
 */
/* Forward declaration: process one channel entry (RECV2 result).
 * Shared between AGGREGATE_WAIT path and pre-1010 fallback. */
static void dispatch_channel_entry( int channel_fd, int use_token,
                                    const struct ntsync_channel_recv2_args *recv,
                                    unsigned long *generation_ptr );

static void *channel_dispatcher( void *param )
{
    struct nspa_dispatcher_ctx *ctx = param;
    int channel_fd  = ctx->channel_fd;
    int shutdown_efd = ctx->shutdown_efd;
    int dev_fd      = get_inproc_device_fd();
    int uring_efd   = nspa_uring_get_eventfd( &ctx->uring );  /* -1 if uring inactive */
    unsigned long generation = 0;
    int cached_use_token;
    int recv2_state;
    int agg_supported;
    const char *v;
    const char *agg_v;

    /* recv2_state: 1 = try RECV2 first, 0 = legacy RECV.  Set once. */
    v = getenv( "NSPA_DISPATCHER_USE_TOKEN" );
    cached_use_token = !(v && *v == '0');
    recv2_state = cached_use_token ? 1 : 0;

    /* AGGREGATE_WAIT path: DEFAULT-ON since 2026-04-29.  Validated by
     * test-aggregate-wait 9/9 + 1k stress + Ableton level-2/3 session
     * (boot, library scan, demo load, 60s play, GUI interaction)
     * under NSPA_AGG_WAIT=1 with kernel CFF56DE1EF28.  The PI-boost
     * regression that gated this default-off was fixed in ntsync 1010
     * (send_pi any_waiters fallback + wake-after-boost reorder).
     *
     * Set NSPA_AGG_WAIT=0 to opt out (legacy CHANNEL_RECV2 path,
     * today's pre-Phase-3 behaviour) for A/B testing.
     *
     *   agg_supported: -1 unknown (try once), 1 use AGG, 0 fallback.
     *   Falls back permanently on ENOTTY (pre-1010 kernel) or unexpected
     *   error (we break out — no infinite-retry loop). */
    agg_v = getenv( "NSPA_AGG_WAIT" );
    agg_supported = (dev_fd >= 0 && !(agg_v && *agg_v == '0')) ? -1 : 0;

    for (;;)
    {
        struct ntsync_channel_recv2_args recv;
        int ret;

        /* ---- AGGREGATE_WAIT path (post-1010 kernel, opt-in) ---- */
        if (agg_supported != 0)
        {
            struct ntsync_aggregate_wait_args agg;
            struct ntsync_aggregate_source srcs[3];
            __u32 nb = 0;
            __u32 channel_idx;
            __u32 uring_idx;
            __u32 shutdown_idx;

            /* Source order: channel first, uring (if active) next,
             * shutdown last.  fired_index reflects this order. */
            srcs[nb].type = NTSYNC_AGG_OBJECT;
            srcs[nb].events = 0;
            srcs[nb].fd = channel_fd;
            srcs[nb].__pad = 0;
            channel_idx = nb++;

            uring_idx = (__u32)-1;
            if (uring_efd >= 0)
            {
                srcs[nb].type = NTSYNC_AGG_FD;
                srcs[nb].events = POLLIN;
                srcs[nb].fd = uring_efd;
                srcs[nb].__pad = 0;
                uring_idx = nb++;
            }

            srcs[nb].type = NTSYNC_AGG_FD;
            srcs[nb].events = POLLIN;
            srcs[nb].fd = shutdown_efd;
            srcs[nb].__pad = 0;
            shutdown_idx = nb++;

            memset( &agg, 0, sizeof(agg) );
            agg.timeout = (__u64)-1;          /* no deadline */
            agg.sources = (uintptr_t)srcs;
            agg.nb_sources = nb;
            agg.flags = 0;
            agg.owner = 0;

            ret = ioctl( dev_fd, NTSYNC_IOC_AGGREGATE_WAIT, &agg );
            if (ret < 0)
            {
                if (errno == ENOTTY)
                {
                    /* Pre-1010 kernel — fall back permanently. */
                    agg_supported = 0;
                    continue;
                }
                if (errno == EINTR) continue;
                /* EBADF on dev_fd (or any other unexpected error) =
                 * we cannot continue safely.  Break out — dispatcher
                 * exits cleanly.  Avoids the §4.1-class infinite-retry
                 * lockup pattern. */
                break;
            }

            /* Shutdown signal?  Just exit; dispatcher cleanup runs below. */
            if (agg.fired_index == shutdown_idx)
                break;

            /* Uring CQE?  Drain inline.  global_lock NOT taken here in
             * Phase 3 because there are no submitters yet — drain is a
             * no-op.  Phase 4 will wrap drain in pi_mutex_lock so CQE
             * callbacks can mutate per-thread state safely. */
            if (uring_idx != (__u32)-1 && agg.fired_index == uring_idx)
            {
                uint64_t evfd_val;
                if (read( uring_efd, &evfd_val, sizeof(evfd_val) ) < 0
                    && errno != EAGAIN)
                    break;     /* fatal eventfd error — exit cleanly */
                /* Phase 4: drain runs CQE callbacks which mutate
                 * per-thread state (current, request_shm reply,
                 * thread->error, etc.) and call send_reply_shm /
                 * nspa_shmem_channel_reply.  Take global_lock to
                 * serialize with other handlers + main thread state.
                 * Phase 3 left this unlocked because there were no
                 * submitters; Phase 4's create_file handler is the
                 * first. */
                pi_mutex_lock( &global_lock );
                nspa_uring_drain( &ctx->uring );
                pi_mutex_unlock( &global_lock );
                continue;
            }

            /* Channel source fired — fall through to RECV2 below. */
            (void)channel_idx;
        }

        /* ---- RECV path (consume the channel entry) ---- */
        if (recv2_state == 1)
        {
            ret = ioctl( channel_fd, NTSYNC_IOC_CHANNEL_RECV2, &recv );
            if (ret < 0 && errno == ENOTTY)
            {
                /* Old kernel without 1005 patch — fall back permanently. */
                recv2_state = 0;
                continue;
            }
        }
        else
        {
            struct ntsync_channel_recv_args recv1;
            ret = ioctl( channel_fd, NTSYNC_IOC_CHANNEL_RECV, &recv1 );
            if (ret >= 0)
            {
                recv.entry_id     = recv1.entry_id;
                recv.payload_off  = recv1.payload_off;
                recv.reply_off    = recv1.reply_off;
                recv.sender_tid   = recv1.sender_tid;
                recv.prio         = recv1.prio;
                recv.thread_token = 0;
            }
        }
        if (ret < 0)
        {
            if (errno == EINTR) continue;
            /* In the AGGREGATE_WAIT path, channel-fired but RECV2 empty
             * is a benign race (another consumer drained — shouldn't
             * happen with one dispatcher, but defensive).  In the
             * pre-1010 path, EBADF is the exit signal. */
            if (errno == EAGAIN) continue;
            break;
        }

        dispatch_channel_entry( channel_fd, cached_use_token, &recv, &generation );
    }

    /* ---- Cleanup: drain in-flight CQEs (Phase 4 may have submitted),
     * shutdown uring, free ctx.  shmem_channel_destroy already closed
     * channel_fd; we close shutdown_efd here as the ctx owner. ---- */
    nspa_uring_drain( &ctx->uring );
    nspa_uring_instance_shutdown( &ctx->uring );
    close( ctx->shutdown_efd );
    free( ctx );
    return NULL;
}

/* Process one received channel entry: lock global_lock, resolve sender
 * thread, read request, write reply, REPLY ioctl.  Same lifecycle as
 * the pre-Phase-3 inline body. */
static void dispatch_channel_entry( int channel_fd, int use_token,
                                    const struct ntsync_channel_recv2_args *recv,
                                    unsigned long *generation_ptr )
{
    struct thread *thread = NULL;

    pi_mutex_lock( &global_lock );
    *generation_ptr = poll_generation;

    /* Resolve the originating thread.  Prefer the kernel-provided
     * token (no userspace lookup); fall back to get_thread_from_id
     * when token is zero (un-registered sender, e.g. very early
     * pre-init traffic) or when the recv2 path is disabled. */
    if (recv->thread_token)
        thread = (struct thread *)(uintptr_t)recv->thread_token;
    else
        thread = get_thread_from_id( (thread_id_t)recv->payload_off );

    if (thread)
    {
        /* Validate the resolved thread belongs to this dispatcher's
         * process.  The channel is per-process; a payload_off that
         * resolves to a thread elsewhere is either client tampering
         * or a logic bug, and running the handler against the wrong
         * process would corrupt unrelated state. */
        if (thread->process->request_channel_fd == channel_fd && thread->request_shm)
        {
            /* NSPA Phase 4: stash entry_id BEFORE the handler runs so
             * an async-completing handler (e.g. nspa_uring_create_file)
             * can copy it into its CQE context.  Cleared at the end of
             * dispatch (not strictly necessary — only valid during
             * handler dispatch — but keeps state hygienic). */
            thread->nspa_channel_entry_id = recv->entry_id;
            __atomic_thread_fence( __ATOMIC_SEQ_CST );
            read_request_shm( thread, (struct request_shm *)thread->request_shm );
            __atomic_thread_fence( __ATOMIC_SEQ_CST );
        }
        if (!recv->thread_token)
            release_object( thread );
    }

    /* NSPA Phase 4: detect deferred reply BEFORE dropping global_lock.
     * If the handler submitted an io_uring op and deferred its reply
     * (set thread->nspa_async_reply_deferred = 1), the CQE callback
     * owns the reply path — both send_reply_shm AND CHANNEL_REPLY.
     * Skip our own CHANNEL_REPLY ioctl in that case.
     *
     * Reading the flag must be inside the lock — the field is on
     * thread state which the CQE callback (running under global_lock
     * later) will clear before it issues its own CHANNEL_REPLY. */
    {
        int deferred = (thread && thread->nspa_async_reply_deferred);

        pi_mutex_unlock( &global_lock );

        if (!deferred)
        {
            __u64 entry_id = recv->entry_id;
            ioctl( channel_fd, NTSYNC_IOC_CHANNEL_REPLY, &entry_id );
        }
    }

    /* Read poll_generation outside the lock — RELAXED is intentional.
     * Worst case is one missed or one spurious force_exit_poll call;
     * both are benign (force_exit_poll is just a wakeup nudge). */
    if (poll_generation != *generation_ptr)
        force_exit_poll();
    (void)use_token;
}

void nspa_shmem_channel_init( struct process *process )
{
    int dev_fd = get_inproc_device_fd();
    struct ntsync_channel_create_args args = { .max_depth = NSPA_CHANNEL_MAX_DEPTH };
    pthread_t pth;
    pthread_attr_t attr;
    pthread_attr_t *pattr = NULL;
    struct nspa_dispatcher_ctx *ctx;
    int channel_fd;

    if (dev_fd < 0) return;

    channel_fd = ioctl( dev_fd, NTSYNC_IOC_CREATE_CHANNEL, &args );
    if (channel_fd < 0) return;

    /* NSPA 1010 Phase 3: heap-owned ctx.  Holds channel_fd, the
     * shutdown eventfd, and the per-process io_uring instance.
     * Dispatcher takes ownership; on its exit it shuts down the uring,
     * closes shutdown_efd, and frees ctx.  shmem_channel_destroy
     * doesn't free ctx (process struct may be torn down before the
     * detached dispatcher exits). */
    ctx = calloc( 1, sizeof(*ctx) );
    if (!ctx)
    {
        close( channel_fd );
        return;
    }
    ctx->channel_fd  = channel_fd;
    ctx->shutdown_efd = eventfd( 0, EFD_NONBLOCK | EFD_CLOEXEC );
    if (ctx->shutdown_efd < 0)
    {
        free( ctx );
        close( channel_fd );
        return;
    }
    /* Init the io_uring inside ctx.  Failure is non-fatal — the
     * instance is left inactive (uring.active = 0) and the dispatcher
     * skips the uring source in AGGREGATE_WAIT. */
    nspa_uring_instance_init( &ctx->uring );

    /* Match v1.5 per-thread dispatcher: explicit RT attrs when
     * NSPA_SRV_RT_PRIO is active so the dispatcher is born RT
     * (PTHREAD_EXPLICIT_SCHED bypasses PR_SET_KEEPCAPS reset-on-fork). */
    if (nspa_srv_rt_prio > 0)
    {
        struct sched_param sp = { .sched_priority = nspa_srv_rt_prio };
        pthread_attr_init( &attr );
        pthread_attr_setinheritsched( &attr, PTHREAD_EXPLICIT_SCHED );
        pthread_attr_setschedpolicy( &attr, nspa_srv_rt_policy );
        pthread_attr_setschedparam( &attr, &sp );
        pthread_attr_setscope( &attr, PTHREAD_SCOPE_SYSTEM );
        pattr = &attr;
    }

    /* Hand ctx ownership to the dispatcher.  Set process back-pointers
     * BEFORE pthread_create so handlers running on the new thread see
     * a fully-published ctx. */
    process->nspa_uring          = &ctx->uring;
    process->nspa_dispatcher_ctx = ctx;

    if (pthread_create( &pth, pattr, channel_dispatcher, ctx ) == 0)
    {
        pthread_detach( pth );
        process->request_channel_fd = channel_fd;
        process->channel_dispatcher_running = 1;
    }
    else
    {
        /* pthread_create failed: take ctx back and tear down. */
        process->nspa_uring          = NULL;
        process->nspa_dispatcher_ctx = NULL;
        nspa_uring_instance_shutdown( &ctx->uring );
        close( ctx->shutdown_efd );
        free( ctx );
        close( channel_fd );
    }

    if (pattr) pthread_attr_destroy( &attr );
}

void nspa_shmem_channel_destroy( struct process *process )
{
    struct nspa_dispatcher_ctx *ctx = process->nspa_dispatcher_ctx;

    if (process->request_channel_fd < 0) return;

    /* Clear back-pointers BEFORE signalling shutdown.  Once cleared,
     * any future handler attempting to access process->nspa_uring sees
     * NULL and falls back to sync.  Doing this before the signal
     * avoids a window where dispatcher has woken on shutdown but a
     * concurrent handler is still mid-call referencing the (about-to-
     * be-freed) ctx. */
    process->nspa_uring          = NULL;
    process->nspa_dispatcher_ctx = NULL;

    /* Close channel_fd: pre-1010 path's dispatcher exits via EBADF on
     * its blocking RECV.  In the post-1010 path the AGGREGATE_WAIT
     * holds an internal fget on the channel so close alone won't wake
     * it — that's what shutdown_efd is for. */
    close( process->request_channel_fd );
    process->request_channel_fd = -1;

    /* Wake the AGGREGATE_WAIT path (if active).  eventfd write is
     * level-triggered; one byte is enough.  Errors here are advisory
     * — if write fails, the dispatcher will eventually exit on its
     * own (channel close already triggered the EBADF path; pre-1010
     * path doesn't need shutdown_efd at all). */
    if (ctx)
    {
        uint64_t one = 1;
        (void)write( ctx->shutdown_efd, &one, sizeof(one) );
    }

    /* DO NOT free ctx — dispatcher owns it.  See struct
     * nspa_dispatcher_ctx doc above for lifetime rules. */

    process->channel_dispatcher_running = 0;
}

/* NSPA thread-token: register (thread->unix_tid -> thread *) with the
 * kernel.  Idempotent (existing registration is replaced).  No-op if
 * the channel isn't up or the thread has no unix_tid yet.  Safe against
 * old kernels — the ioctl returns -ENOTTY and we silently skip.
 *
 * Lifetime invariant: register BEFORE the client may send any request
 * that would resolve to `thread`.  In practice we register from
 * req_init_first_thread / req_init_thread, both of which run inside a
 * server handler that completes BEFORE the client sees the reply. */
void nspa_shmem_channel_register_thread( struct process *process, struct thread *thread )
{
    struct ntsync_channel_register_thread_args args;

    if (process->request_channel_fd < 0) return;
    if (thread->unix_tid <= 0) return;

    args.tid   = (__u32)thread->unix_tid;
    args.__pad = 0;
    args.token = (__u64)(uintptr_t)thread;

    /* Failure (ENOTTY on old kernel; ENOMEM extremely unlikely) is non-
     * fatal — dispatcher token path will see token=0 and fall through
     * to get_thread_from_id. */
    (void)ioctl( process->request_channel_fd, NTSYNC_IOC_CHANNEL_REGISTER_THREAD, &args );
}

/* NSPA thread-token: drop the registration.  Idempotent.  Already-
 * enqueued channel entries retain the token they were stamped with at
 * SEND_PI; this only affects FUTURE sends from this tid (which won't
 * happen because the thread is being destroyed). */
void nspa_shmem_channel_deregister_thread( struct process *process, struct thread *thread )
{
    __u32 tid;

    if (process->request_channel_fd < 0) return;
    if (thread->unix_tid <= 0) return;

    tid = (__u32)thread->unix_tid;
    (void)ioctl( process->request_channel_fd, NTSYNC_IOC_CHANNEL_DEREGISTER_THREAD, &tid );
}

/* NSPA Phase 4: signal CHANNEL_REPLY for an in-flight channel entry
 * from an io_uring CQE-completion path.  The kernel walks the channel's
 * dispatched list, marks the entry replied, wakes the sender, and
 * drains our PI boost.  Failure (e.g. stale entry_id) is logged at
 * debug_level only — caller has nothing useful to do with the error. */
void nspa_shmem_channel_reply( int channel_fd, unsigned long long entry_id )
{
    __u64 ent = (__u64)entry_id;

    if (channel_fd < 0) return;
    if (ioctl( channel_fd, NTSYNC_IOC_CHANNEL_REPLY, &ent ) < 0)
    {
        if (debug_level)
            fprintf( stderr, "nspa_shmem_channel_reply: ioctl failed: %s\n",
                     strerror( errno ) );
    }
}

#endif /* __linux__ */
