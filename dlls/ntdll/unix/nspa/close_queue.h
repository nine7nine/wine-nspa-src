/*
 * NSPA local-file async close queue.
 *
 * Phase 3 (first real consumer of the new sched infrastructure).
 *
 * Defers the unix-fd close + server close_handle RPC for fully-shareable
 * local-file handles to the per-process sched thread, removing close-path
 * latency from caller threads during bursty teardowns (DAW project tear-
 * down, plugin scan, NtClose loops in general).
 *
 * NT-semantic preservation:
 *   - NtClose returns success immediately (same as today)
 *   - Local handle slot is freed immediately (caller can re-use)
 *   - Server-side handle ref-count + unix-fd close happen DEFERRED
 *
 * Eligibility predicate (chosen conservatively):
 *   - Handle's sharing == FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
 *   - i.e., caller did not request any exclusive lock; closing has no
 *     observable side effect for other openers.
 *   - Handles with restrictive sharing always close inline (current path).
 *
 * Queue semantics:
 *   - Bounded depth (NSPA_CLOSE_QUEUE_CAP).  Push fails on overflow;
 *     caller MUST then close inline.
 *   - Pre-flush API: any code path that may open a file (NtCreateFile,
 *     try_bypass, table_add) drains the queue first to eliminate same-
 *     path race.  Cheap when queue is empty.
 *   - At process exit: drain via flush.
 *
 * Default OFF — only engages when NSPA_USE_SCHED_THREAD=1.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __NSPA_CLOSE_QUEUE_H
#define __NSPA_CLOSE_QUEUE_H

#include <windef.h>

/* Eligibility predicate: returns TRUE if the handle can be safely
 * deferred-closed.  Inline this in callers — it's a single load + cmp. */
#include <winternl.h>
#define NSPA_CLOSE_QUEUE_LF_SHARE_ALL (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)

/* Try to enqueue a close for later async dispatch.
 *
 *   server_handle   wineserver-side handle (0 if never lazy-promoted)
 *   unix_fd         per-process unix fd (-1 if none)
 *
 * Returns TRUE if enqueued (caller skips inline close).
 * Returns FALSE if the queue is full or the gate is OFF — caller MUST
 * fall through to inline close path. */
extern BOOL nspa_close_queue_push( HANDLE server_handle, int unix_fd );

/* Synchronously drain any pending closes.  Cheap (no-op) when queue is
 * empty.  MUST be called from any code path that could observe a stale
 * server-side handle reference, before the racing operation begins.
 *
 * Currently the only required pre-flush site is the LF allocator
 * (nspa_local_file_table_add) — every NSPA-bypassed file open passes
 * through there.  Direct (non-bypass) NtCreateFile paths go to the
 * server which is unaware of NSPA's local pending closes; those paths
 * are unaffected by deferral because the lingering local FDs do not
 * conflict with FRESH server handles for new files (only same-path
 * re-opens within NSPA's bypass window are at risk, and those go
 * through the bypass allocator). */
extern void nspa_close_queue_flush( void );

/* Pending count — diagnostic only. */
extern unsigned int nspa_close_queue_pending( void );

#endif /* __NSPA_CLOSE_QUEUE_H */
