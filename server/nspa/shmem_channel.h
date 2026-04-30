/*
 * NSPA shm-IPC γ: per-process kernel-mediated request/reply channel.
 *
 * Replaces the v2.4 user-space futex + manual sched_setscheduler shm-IPC
 * fast path between wineserver and Wine clients with a kernel-mediated
 * priority queue (NTSYNC_TYPE_CHANNEL).  One channel per client process;
 * one dispatcher pthread per process drains it.  See ntsync-patches/
 * 1004-ntsync-channel.patch for the kernel side.
 */
#ifndef __WINE_SERVER_NSPA_SHMEM_CHANNEL_H
#define __WINE_SERVER_NSPA_SHMEM_CHANNEL_H

struct process;
struct thread;

#ifdef __linux__

/* Open a per-process channel + spawn dispatcher pthread.  No-op if the
 * ntsync device is unavailable.  Failure to open/spawn leaves
 * process->request_channel_fd at -1; clients fall back to socket IPC. */
extern void nspa_shmem_channel_init( struct process *process );

/* Close the channel fd.  The dispatcher pthread exits asynchronously
 * via EBADF on its blocked CHANNEL_RECV.  Idempotent. */
extern void nspa_shmem_channel_destroy( struct process *process );

/* NSPA thread-token pass-through (T2 plumbing).  Register the
 * (thread->unix_tid, (uint64_t)thread) pair with the kernel so
 * subsequent CHANNEL_SEND_PI from this thread stamp the entry's
 * thread_token.  No-op if the channel isn't up or the thread has no
 * unix_tid yet.  Idempotent (existing registration is replaced). */
extern void nspa_shmem_channel_register_thread( struct process *process, struct thread *thread );

/* Inverse: drop the registration.  Called from destroy_thread.
 * Idempotent.  Does NOT affect already-enqueued channel entries —
 * they retain the token they were stamped with at SEND_PI. */
extern void nspa_shmem_channel_deregister_thread( struct process *process, struct thread *thread );

/* NSPA Phase 4: signal CHANNEL_REPLY from an io_uring CQE callback.
 * Used by async-completing handlers (e.g. uring_create_file) when the
 * syscall completes — the dispatcher has already skipped its own
 * REPLY because thread->nspa_async_reply_deferred was set. */
extern void nspa_shmem_channel_reply( int channel_fd, unsigned long long entry_id );

#else

static inline void nspa_shmem_channel_init( struct process *process ) {}
static inline void nspa_shmem_channel_destroy( struct process *process ) {}
static inline void nspa_shmem_channel_register_thread( struct process *process, struct thread *thread ) {}
static inline void nspa_shmem_channel_deregister_thread( struct process *process, struct thread *thread ) {}
static inline void nspa_shmem_channel_reply( int channel_fd, unsigned long long entry_id ) {}

#endif

#endif /* __WINE_SERVER_NSPA_SHMEM_CHANNEL_H */
