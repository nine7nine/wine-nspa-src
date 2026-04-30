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
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
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
 * Dispatcher pthread: blocks on CHANNEL_RECV (or RECV2 if the gate is
 * on), dispatches the request via the existing read_request_shm code
 * path, then signals completion via CHANNEL_REPLY.  Exits on EBADF
 * (channel closed by destroy).
 *
 * Default since 2026-04-26 is RECV2 + direct thread_token consumption
 * (skips get_thread_from_id when the kernel provides a non-zero token,
 * ~10% dispatcher CPU reclaim per perf 2026-04-26).  Falls back
 * gracefully if RECV2 returns -ENOTTY (running against an old kernel
 * without the 1005 patch) or if token is zero (sender thread predates
 * registration).  Set NSPA_DISPATCHER_USE_TOKEN=0 to force legacy RECV
 * + get_thread_from_id for A/B testing.
 */
static void *channel_dispatcher( void *param )
{
    int channel_fd = (int)(uintptr_t)param;
    unsigned long generation = 0;

    /* One-time env-var read: same pattern as NSPA_DISABLE_EPOLL /
     * NSPA_OPENFD_LOCKDROP.  recv2_state: -1 = uninitialised, 0 = use
     * legacy RECV, 1 = try RECV2 (with on-the-fly fallback to legacy
     * if RECV2 returns -ENOTTY). */
    static int cached_use_token = -1;
    static int recv2_state = -1;
    if (cached_use_token < 0)
    {
        const char *v = getenv( "NSPA_DISPATCHER_USE_TOKEN" );
        cached_use_token = !(v && *v == '0');
        recv2_state = cached_use_token ? 1 : 0;
    }

    for (;;)
    {
        struct ntsync_channel_recv2_args recv;
        struct thread *thread = NULL;
        int ret;

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
            /* EBADF (channel closed) or any other error → exit. */
            break;
        }

        pi_mutex_lock( &global_lock );
        generation = poll_generation;

        /* Resolve the originating thread.  Prefer the kernel-provided
         * token (no userspace lookup); fall back to get_thread_from_id
         * when token is zero (un-registered sender, e.g. very early
         * pre-init traffic) or when the recv2 path is disabled. */
        if (recv.thread_token)
            thread = (struct thread *)(uintptr_t)recv.thread_token;
        else
            thread = get_thread_from_id( (thread_id_t)recv.payload_off );

        if (thread)
        {
            /* Validate the resolved thread belongs to this dispatcher's
             * process.  The channel is per-process; a payload_off that
             * resolves to a thread elsewhere is either client tampering
             * or a logic bug, and running the handler against the wrong
             * process would corrupt unrelated state.  thread->process
             * is kept alive by the ref grab_object grants on the thread
             * (thread.c:602 holds a strong process ref for every thread). */
            if (thread->process->request_channel_fd == channel_fd && thread->request_shm)
            {
                /* Memory barriers: ensure we observe all of the sender's
                 * shmem writes before reading the request, and that all
                 * our reply writes are visible before we wake the sender. */
                __atomic_thread_fence( __ATOMIC_SEQ_CST );
                read_request_shm( thread, (struct request_shm *)thread->request_shm );
                __atomic_thread_fence( __ATOMIC_SEQ_CST );
            }
            /* Only release the ref if get_thread_from_id grabbed one.
             * The token path borrows the registration's reference (kept
             * alive by deregister-after-last-reply invariant). */
            if (!recv.thread_token)
                release_object( thread );
        }

        pi_mutex_unlock( &global_lock );

        /* Wake the sender + drain our PI boost in one ioctl. */
        {
            __u64 entry_id = recv.entry_id;
            ioctl( channel_fd, NTSYNC_IOC_CHANNEL_REPLY, &entry_id );
        }

        /* Read poll_generation outside the lock — RELAXED is intentional.
         * Worst case is one missed or one spurious force_exit_poll call;
         * both are benign (force_exit_poll is just a wakeup nudge). */
        if (poll_generation != generation)
            force_exit_poll();
    }

    return NULL;
}

void nspa_shmem_channel_init( struct process *process )
{
    int dev_fd = get_inproc_device_fd();
    struct ntsync_channel_create_args args = { .max_depth = NSPA_CHANNEL_MAX_DEPTH };
    pthread_t pth;
    pthread_attr_t attr;
    pthread_attr_t *pattr = NULL;
    int channel_fd;

    if (dev_fd < 0) return;

    channel_fd = ioctl( dev_fd, NTSYNC_IOC_CREATE_CHANNEL, &args );
    if (channel_fd < 0) return;

    /* NSPA 1010 Phase 2: bring up the per-process server-side io_uring
     * before the dispatcher pthread starts.  Failure is non-fatal — the
     * instance is left inactive and async-completing handlers fall back
     * to synchronous behaviour.  Phase 3 will wire nspa_uring_get_eventfd()
     * into the dispatcher's NTSYNC_IOC_AGGREGATE_WAIT call. */
    nspa_uring_instance_init( &process->nspa_uring );

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

    /* Pass the channel fd to the dispatcher.  We do NOT pass `process`:
     * the dispatcher needs no other process-scoped state, so there's no
     * risk of access-after-free if the process terminates.  Channel
     * close (via nspa_shmem_channel_destroy) is the dispatcher's exit
     * signal via EBADF on the pending RECV. */
    if (pthread_create( &pth, pattr, channel_dispatcher, (void *)(uintptr_t)channel_fd ) == 0)
    {
        pthread_detach( pth );
        process->request_channel_fd = channel_fd;
        process->channel_dispatcher_running = 1;
    }
    else
    {
        close( channel_fd );
    }

    if (pattr) pthread_attr_destroy( &attr );
}

void nspa_shmem_channel_destroy( struct process *process )
{
    if (process->request_channel_fd < 0) return;
    /* Closing the fd unblocks the dispatcher's CHANNEL_RECV with EBADF;
     * the (detached) pthread observes and exits cleanly. */
    close( process->request_channel_fd );
    process->request_channel_fd = -1;
    /* NSPA 1010 Phase 2: tear down the per-process io_uring after the
     * channel is closed.  Phase 2 has no submitters, so this is safe
     * regardless of dispatcher exit timing.  Phase 3+ will need to gate
     * this on dispatcher actually having exited (it is detached, so the
     * teardown contract evolves with the submitter set). */
    nspa_uring_instance_shutdown( &process->nspa_uring );
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

#endif /* __linux__ */
