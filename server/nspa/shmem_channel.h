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

#ifdef __linux__

/* Open a per-process channel + spawn dispatcher pthread.  No-op if the
 * ntsync device is unavailable.  Failure to open/spawn leaves
 * process->request_channel_fd at -1; clients fall back to socket IPC. */
extern void nspa_shmem_channel_init( struct process *process );

/* Close the channel fd.  The dispatcher pthread exits asynchronously
 * via EBADF on its blocked CHANNEL_RECV.  Idempotent. */
extern void nspa_shmem_channel_destroy( struct process *process );

#else

static inline void nspa_shmem_channel_init( struct process *process ) {}
static inline void nspa_shmem_channel_destroy( struct process *process ) {}

#endif

#endif /* __WINE_SERVER_NSPA_SHMEM_CHANNEL_H */
