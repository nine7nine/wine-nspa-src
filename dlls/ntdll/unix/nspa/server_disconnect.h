/*
 * NSPA wineserver-disconnect listener.
 *
 * Registers a passive POLLHUP listener on the per-process server socket
 * (server.c:fd_socket) onto the default sched thread.  When the server
 * goes away (clean kill, crash, network partition, etc.) the kernel sets
 * POLLHUP on our half of the socket; the sched thread wakes the callback,
 * which calls _exit(0) to terminate this process.
 *
 * Background: project_sched_thread_no_shutdown_20260503.md documents
 * idle Wine system processes (services / plugplay / winedevice / explorer)
 * surviving `wineserver -k` because their disconnect detection isn't
 * wired to anything.  The SIGQUIT-unblock fix in sched_run() covers the
 * normal `wineserver -k` SIGQUIT-delivery path; this listener covers
 * the broader cases (server crash, server killed externally, lost
 * connection) where SIGQUIT never reaches us.
 *
 * Out of scope for this listener:
 *   - graceful flush of close_queue / fsync_queue: server is already
 *     gone, any RPC-bearing close would fail anyway.  _exit(0) skips
 *     those queues' drain on purpose.
 */

#ifndef __WINE_NSPA_SERVER_DISCONNECT_H
#define __WINE_NSPA_SERVER_DISCONNECT_H

extern void nspa_server_disconnect_init( void );

#endif /* __WINE_NSPA_SERVER_DISCONNECT_H */
