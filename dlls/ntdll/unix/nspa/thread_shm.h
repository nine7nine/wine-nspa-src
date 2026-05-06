/*
 * NSPA per-thread shared-memory snapshot reader (client side).
 *
 * Resolves obj_locators returned by the server's get_thread_shm request
 * through the session-shared mapping and exposes typed accessors that
 * read fields under the existing seqlock retry pattern.
 *
 * Replaces a subset of SERVER_START_REQ(get_thread_info) round-trips
 * in NtQueryInformationThread for the read-mostly query classes whose
 * fields are already published in thread_shm_t (see protocol.def).
 *
 * Validation env-gate: NSPA_THREAD_SHM=1 enables the shmem fast path;
 * any other value (default) keeps callers on the existing RPC fallback.
 * The gate exists for A/B bring-up and is intended to be removed once
 * the shmem path has been validated default-on.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __NSPA_THREAD_SHM_H
#define __NSPA_THREAD_SHM_H

#include "winternl.h"

/* Read NSPA_THREAD_SHM env-gate and lazily set up shared-session
 * mapping primitives.  Idempotent; safe to call multiple times. */
extern void nspa_thread_shm_init(void);

/* TRUE iff init succeeded and the env-gate is on.  Hot-path callers
 * read the cached static — branchy but trivially predictable. */
extern BOOL nspa_thread_shm_enabled(void);

/* Read the current affinity mask for the given thread handle from the
 * shared snapshot.  Returns STATUS_SUCCESS on hit; STATUS_NOT_SUPPORTED
 * if the gate is off or the shmem path can't satisfy the read (caller
 * falls back to the get_thread_info RPC). */
extern NTSTATUS nspa_thread_shm_query_affinity( HANDLE handle, ULONG_PTR *out );

#endif /* __NSPA_THREAD_SHM_H */
