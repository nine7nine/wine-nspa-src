/*
 * NSPA: lock-drop wrappers around slow filesystem syscalls in fd.c.
 *
 * See header for rationale.  Implementation lives here so the upstream
 * server/fd.c diff stays minimal — easier to read, easier to rebase
 * against upstream Wine.
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "object.h"
#include "thread.h"
#include "file.h"        /* global_lock */

#include "fd_lockdrop.h"

int nspa_openat_lockdrop( struct fd *fd_object,
                          struct fd *root_object,
                          int dirfd,
                          const char *name,
                          int rw_mode,
                          int flags,
                          mode_t *mode,
                          unsigned int access )
{
    /* `current` is a global (server/request.c:121) holding the per-
     * request thread pointer.  Another handler running in our unlocked
     * window will overwrite it; save and restore.
     *
     * `current->error` belongs to our request and gets read by the
     * reply path (call_req_handler_shm); save and restore so we don't
     * pick up a different handler's error state.
     *
     * Defensive grab_object on fd_object and root_object: fd_object
     * was just allocated by alloc_fd_object() — only the caller knows
     * about it — but pinning makes the unlocked window bullet-proof.
     * root_object is held by the caller's request handler; pinning
     * means a concurrent close-handle of root cannot free it during
     * our syscall.
     *
     * `errno` is per-thread; preserved across the lock dance
     * naturally.  We snapshot the openat() errno into local_errno
     * explicitly so the caller's file_set_error() sees exactly what
     * openat returned and not an errno set by pi_mutex_lock or any
     * other intervening libc call.
     */
    struct thread *saved_current = current;
    unsigned int saved_error = saved_current ? saved_current->error : 0;
    struct object *fd_ref = fd_object ? grab_object( fd_object ) : NULL;
    struct object *root_ref = root_object ? grab_object( root_object ) : NULL;
    int unix_fd, local_errno = 0;

    pi_mutex_unlock( &global_lock );

    unix_fd = openat( dirfd, name, rw_mode | (flags & ~O_TRUNC), *mode );
    if (unix_fd == -1)
    {
        local_errno = errno;
        /* if we tried to open a directory for write access, retry read-only */
        if (local_errno == EISDIR &&
            ((access & FILE_UNIX_WRITE_ACCESS) || (flags & O_CREAT)))
        {
            unix_fd = openat( dirfd, name,
                              O_RDONLY | (flags & ~(O_TRUNC | O_CREAT | O_EXCL)),
                              *mode );
            local_errno = (unix_fd == -1) ? errno : 0;
        }
    }

    pi_mutex_lock( &global_lock );

    current = saved_current;
    if (saved_current) saved_current->error = saved_error;
    if (root_ref) release_object( root_ref );
    if (fd_ref)   release_object( fd_ref );

    errno = local_errno;
    return unix_fd;
}
