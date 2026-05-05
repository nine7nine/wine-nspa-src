/*
 * NSPA wineserver-disconnect listener — implementation.
 *
 * Registers a passive POLLHUP/POLLERR listener on fd_socket via the
 * default sched thread (NTDLL_SCHED_CLASS_DEFAULT).  Closes the bug
 * documented in project_sched_thread_no_shutdown_20260503.md.
 *
 * Why POLLPRI in the events mask?
 *
 *   The sched poll-user dispatcher (sched.c sched_run_inst) frees a user
 *   when its events == 0, so we can't pass 0 to mean "passive".  POLLIN
 *   would fire on every legitimate server -> client SCM_RIGHTS recv,
 *   tight-looping our callback until the synchronous recvmsg consumes
 *   the data.  POLLPRI is never generated on AF_UNIX SOCK_STREAM (no
 *   out-of-band semantics on Unix domain sockets), so it never fires
 *   spuriously — but POLLHUP and POLLERR are reported in revents
 *   regardless of the events mask, so we still wake on disconnect.
 *
 *   Passive listener with zero false-wake cost.
 *
 * Lifecycle:
 *
 *   - Registered from sched_run() once, never canceled (process exits
 *     before cancel would matter).
 *   - sched_run_inst auto-clears user->events on POLLHUP|POLLERR
 *     (sched.c:605), which would auto-deregister on the next loop —
 *     but our callback _exit()s before that happens, so the
 *     auto-deregister path is unreachable in practice.
 *
 * Why _exit(0), not abort_process / exit?
 *
 *   - abort_process is the normal Win32-thread shutdown path; it
 *     decrements nb_threads and calls exit_process when the count
 *     reaches zero.  But the documented bug is that nb_threads stays
 *     positive (idle system processes have non-trivial thread
 *     populations from spawn-main, ntsync, sched, etc.) so
 *     abort_process never fires from any one thread.  _exit bypasses
 *     the counter entirely.
 *   - exit() runs atexit handlers.  Those may try to talk to the
 *     dead server and hang.  _exit skips them.
 *   - The kernel reaps file descriptors / mappings cleanly on _exit;
 *     no resource leak.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <unistd.h>
#include <poll.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"
#include "wine/unixlib.h"

#include "../unix_private.h"
#include "server_disconnect.h"

WINE_DEFAULT_DEBUG_CHANNEL(server);

static int on_server_disconnect( void *priv, int events )
{
    /* Reachable only on POLLHUP|POLLERR|POLLNVAL (POLLPRI never fires
     * on AF_UNIX SOCK_STREAM); defensive check anyway in case the sched
     * poll mechanics evolve.  Returning POLLPRI re-arms passively. */
    if (!(events & (POLLHUP | POLLERR | POLLNVAL))) return POLLPRI;

    /* Race guard: if the process is already in the graceful exit path
     * (NtTerminateProcess -> abort_process -> exit_process), fd_socket
     * may have been closed by us, producing POLLNVAL/POLLHUP via our
     * own close.  In that window we must not _exit prematurely — the
     * regular exit path is mid-cleanup.  Just deregister (return 0)
     * and let normal shutdown complete. */
    if (process_exiting)
    {
        TRACE( "process_exiting=TRUE; deregistering quietly\n" );
        return 0;
    }

    ERR( "wineserver disconnected (revents=%#x); exiting process\n", events );

    /* See header / .c top comment for the _exit-vs-exit/abort_process
     * rationale.  Final operation; no return path. */
    _exit( 0 );
    return 0;  /* unreachable */
}

void nspa_server_disconnect_init( void )
{
    NTSTATUS status;

    if (fd_socket < 0)
    {
        /* Should not happen: sched_run() runs after server_init_process()
         * has set fd_socket.  Warn and skip — better to lose this listener
         * than to crash here. */
        WARN( "fd_socket not set at sched_run; skipping disconnect listener\n" );
        return;
    }

    /* Register on the DEFAULT sched class.  Using POLLPRI as a "passive"
     * events mask; POLLHUP/POLLERR/POLLNVAL still report regardless. */
    status = ntdll_sched_register_poll_class( NTDLL_SCHED_CLASS_DEFAULT,
                                              fd_socket, POLLPRI,
                                              on_server_disconnect, NULL,
                                              NULL );
    if (status)
        WARN( "ntdll_sched_register_poll_class failed: %#x\n", (unsigned)status );
    else
        TRACE( "server disconnect listener armed on fd_socket=%d\n", fd_socket );
}
