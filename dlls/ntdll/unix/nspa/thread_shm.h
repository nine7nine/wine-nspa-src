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
#include "wine/server_protocol.h"  /* client_ptr_t */

/* Snapshot of the fields in thread_shm_t that callers actually read.
 * Filled atomically by nspa_thread_shm_query under one seqlock cycle;
 * callers pick the field they need.  flags are the THREAD_SHM_FLAG_*
 * bits defined in server/protocol.def — kept opaque here so callers
 * stay decoupled from the wire format. */
struct nspa_thread_shm_snapshot
{
    int          priority;     /* current effective thread priority */
    int          base_priority;/* base priority level */
    ULONG_PTR    affinity;     /* ULONG_PTR-cast affinity mask */
    int          exit_code;    /* STILL_PENDING (0x103) when running */
    client_ptr_t teb;          /* TEB address */
    client_ptr_t entry_point;  /* Win32 entry point */
    DWORD        id;           /* this thread's NT tid */
    DWORD        process_id;   /* owning process's NT pid */
    ULONG        suspend;      /* current suspend count */
    ULONG        flags;        /* THREAD_SHM_FLAG_* — see thread_shm.c bit accessors */
};

/* Bit accessors for snapshot.flags.  Keep these in sync with
 * server/protocol.def THREAD_SHM_FLAG_* values; the wire format is
 * not exposed in this header so callers stay decoupled. */
extern BOOL nspa_thread_shm_snapshot_is_terminated   ( const struct nspa_thread_shm_snapshot *s );
extern BOOL nspa_thread_shm_snapshot_is_dbg_hidden   ( const struct nspa_thread_shm_snapshot *s );
extern BOOL nspa_thread_shm_snapshot_is_disable_boost( const struct nspa_thread_shm_snapshot *s );

/* Read all snapshot fields for the given thread handle atomically
 * under one seqlock cycle.  Returns STATUS_SUCCESS on hit;
 * STATUS_NOT_SUPPORTED if the shmem path can't satisfy the read
 * (caller falls back to the get_thread_info RPC). */
extern NTSTATUS nspa_thread_shm_query( HANDLE handle, struct nspa_thread_shm_snapshot *out );

#endif /* __NSPA_THREAD_SHM_H */
