/*
 * NSPA per-process client-range event registration table — header.
 *
 * Phase 4.6.A of the events Option A plan.  See
 * wine/nspa/docs/events-option-a-plan-20260502.md for the full design.
 *
 * Maps PE-allocated client-range event handles to server-side ntsync fds
 * (received via SCM_RIGHTS at register time).  Lets server-side async I/O
 * completion signal client-range events directly via NTSYNC_IOC_EVENT_SET
 * without going through the (nonexistent) server handle table entry.
 *
 * Lookup is a small linked-list walk per process — events registered here
 * are only those used as async-I/O completion targets, not every PE-side
 * client-range event.  Promote to a hash if the per-process count grows.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __WINE_SERVER_NSPA_INPROC_EVENT_TABLE_H
#define __WINE_SERVER_NSPA_INPROC_EVENT_TABLE_H

#include "wine/server_protocol.h"   /* obj_handle_t */

struct process;

/* Register a (handle → fd) entry.  Caller transfers ownership of fd to the
 * table; subsequent unregister or process-exit cleanup will close it.  If a
 * prior entry exists for the handle, it is replaced (old fd is closed).
 * Returns 0 on success, -1 on allocation failure (caller must close fd). */
extern int  nspa_inproc_event_register( struct process *process,
                                        obj_handle_t handle, int fd );

/* Look up the fd for a previously-registered handle.  Returns the fd (still
 * owned by the table — do not close) or -1 if not registered.  Used by the
 * async-completion path in server/async.c. */
extern int  nspa_inproc_event_lookup( struct process *process, obj_handle_t handle );

/* Unregister + close the fd for a handle.  No-op if not registered. */
extern void nspa_inproc_event_unregister( struct process *process, obj_handle_t handle );

/* Walk the table on process exit + close all fds.  Called from
 * process_destroy. */
extern void nspa_inproc_event_table_destroy( struct process *process );

#endif /* __WINE_SERVER_NSPA_INPROC_EVENT_TABLE_H */
