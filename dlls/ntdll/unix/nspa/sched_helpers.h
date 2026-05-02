/*
 * NSPA sched helpers — env gate + thin NSPA wrappers around the
 * upstream ntdll_sched_* API surface (dlls/ntdll/unix/sched.c).
 *
 * Phase 2.5 introduces nspa_sched_enabled() so Phase 3+ migrations
 * can opt into routing their work onto the per-process sched thread
 * via the NSPA_USE_SCHED_THREAD=1 env var.  Default-OFF until a
 * migration is validated end-to-end.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __NSPA_SCHED_HELPERS_H
#define __NSPA_SCHED_HELPERS_H

#include <windef.h>

/* Returns TRUE if the per-process sched thread should host migrated
 * NSPA dispatchers.  Reads NSPA_USE_SCHED_THREAD once at first call
 * and caches the result for the lifetime of the process.
 *
 * Consumers (e.g. nspa/io_uring.c per-process worker, future
 * shmem_channel client-side routing, etc.) check this before
 * spawning their own pthread:
 *
 *   if (nspa_sched_enabled())
 *       ntdll_sched_register_poll( my_fd, POLLIN, my_drain_cb, NULL, NULL );
 *   else
 *       pthread_create( &worker, NULL, my_legacy_loop, NULL );
 *
 * Default OFF.  Set NSPA_USE_SCHED_THREAD=1 to opt in. */
extern BOOL nspa_sched_enabled( void );

/* NSPA-shaped thin wrapper around ntdll_sched_async.  Enqueues `cb(arg)`
 * to run on the per-process sched thread (SCHED_OTHER).  Fire-and-forget
 * — caller cannot wait for completion.  cb runs without holding any
 * NSPA lock; if cb needs to lock NSPA state, use PI mutexes (the sched
 * thread inherits priority via PI when an RT thread waits on it).
 *
 * Returns non-zero on failure (e.g. malloc failed inside the underlying
 * sched layer); caller should fall back to inline execution.  No
 * fallback is performed by this helper — it is up to the consumer to
 * decide. */
extern int nspa_sched_submit_async( void (*cb)( void *arg ), void *arg );

/* NSPA Phase 3 multi-class: returns TRUE if NSPA RT support is
 * available in this process.  Cheap (single env-cache read).  RT
 * consumers (wm_timer migration, future precision dispatchers) check
 * this before requesting NTDLL_SCHED_CLASS_RT. */
extern BOOL nspa_sched_rt_available( void );

#endif /* __NSPA_SCHED_HELPERS_H */
