/*
 * NSPA: lock-drop wrappers around slow filesystem syscalls in fd.c.
 *
 * Releases pi_mutex_lock(&global_lock) for the duration of the syscall
 * so other RT waiters (audio thread via gamma channel, dispatcher
 * pthread, etc.) can make progress while a slow file open is pending
 * in the kernel.  Eliminates audio xruns during plugin / sample /
 * drum loads — see nspa/docs/open-fd-async-plan.md.
 */

#ifndef __WINE_SERVER_NSPA_FD_LOCKDROP_H
#define __WINE_SERVER_NSPA_FD_LOCKDROP_H

#include <sys/types.h>

struct fd;

/* openat() with global_lock optionally released across the syscall.
 *
 * Behaviour-equivalent to:
 *
 *   int rc = openat(dirfd, name, rw_mode | (flags & ~O_TRUNC), *mode);
 *   if (rc == -1 && errno == EISDIR &&
 *       ((access & FILE_UNIX_WRITE_ACCESS) || (flags & O_CREAT)))
 *       rc = openat(dirfd, name,
 *                   O_RDONLY | (flags & ~(O_TRUNC | O_CREAT | O_EXCL)),
 *                   *mode);
 *
 * Default ON since 2026-04-26 (originally gated default-off due to a
 * host lockup later traced to ntsync driver bugs, not Phase B; see
 * ntsync-patches/1006-ntsync-rt-alloc-hoist.patch).  With the gate
 * ON, global_lock is released across the syscall(s) and the wineserver
 * per-thread state (current, current->error) is saved/restored around
 * the unlocked window so a concurrent handler running on the other RT
 * thread cannot trample us; fd_object and root_object are pinned via
 * grab_object for the unlocked window so neither can be freed by a
 * concurrent handler.  Always-on as of 2026-05-04 (env-gate retired).
 *
 * Caller MUST hold global_lock; on return the caller again holds it.
 *
 * Returns the unix fd on success, -1 on failure with errno set to the
 * value the openat() syscall returned (so the caller's existing
 * file_set_error() / STATUS_OBJECT_NAME_INVALID logic works
 * unchanged).
 */
extern int nspa_openat_lockdrop( struct fd *fd_object,
                                 struct fd *root_object,
                                 int dirfd,
                                 const char *name,
                                 int rw_mode,
                                 int flags,
                                 mode_t *mode,
                                 unsigned int access );

#endif  /* __WINE_SERVER_NSPA_FD_LOCKDROP_H */
