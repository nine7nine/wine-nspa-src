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

#include "process.h"
#include "thread.h"
#include "request.h"
#include "file.h"
#include "nspa/rt.h"
#include "nspa/shmem_channel.h"

#define NSPA_CHANNEL_MAX_DEPTH 256

extern int get_inproc_device_fd(void); /* server/inproc_sync.c */

/*
 * Dispatcher pthread: blocks on CHANNEL_RECV, dispatches the request
 * via the existing read_request_shm code path, then signals completion
 * via CHANNEL_REPLY.  Exits on EBADF (channel closed by destroy).
 */
static void *channel_dispatcher( void *param )
{
    int channel_fd = (int)(uintptr_t)param;
    unsigned long generation = 0;

    for (;;)
    {
        struct ntsync_channel_recv_args recv;
        struct thread *thread;
        int ret;

        ret = ioctl( channel_fd, NTSYNC_IOC_CHANNEL_RECV, &recv );
        if (ret < 0)
        {
            if (errno == EINTR) continue;
            /* EBADF (channel closed) or any other error → exit. */
            break;
        }

        pi_mutex_lock( &global_lock );
        generation = poll_generation;

        thread = get_thread_from_id( (thread_id_t)recv.payload_off );
        if (thread && thread->request_shm)
        {
            /* Memory barriers: ensure we observe all of the sender's
             * shmem writes before reading the request, and that all
             * our reply writes are visible before we wake the sender. */
            __atomic_thread_fence( __ATOMIC_SEQ_CST );
            read_request_shm( thread, (struct request_shm *)thread->request_shm );
            __atomic_thread_fence( __ATOMIC_SEQ_CST );
        }

        pi_mutex_unlock( &global_lock );

        /* Wake the sender + drain our PI boost in one ioctl. */
        {
            __u64 entry_id = recv.entry_id;
            ioctl( channel_fd, NTSYNC_IOC_CHANNEL_REPLY, &entry_id );
        }

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
    process->channel_dispatcher_running = 0;
}

#endif /* __linux__ */
