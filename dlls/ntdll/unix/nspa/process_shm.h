/*
 * NSPA per-process shared-memory snapshot reader (client side).
 *
 * Mirror of nspa/thread_shm.h for processes.  Resolves obj_locators
 * returned by the server's get_process_shm request through the
 * session-shared mapping and exposes a snapshot accessor that reads
 * fields under the existing seqlock retry pattern.
 *
 * Replaces a subset of SERVER_START_REQ(get_process_info) round-trips
 * in NtQueryInformationProcess for the read-mostly query classes whose
 * fields are already published in process_shm_t (see protocol.def).
 * Also short-circuits Wait(process, 0) polls via the exit_code != STILL_ACTIVE
 * predicate (see dlls/ntdll/unix/sync.c:inproc_wait fast path).
 *
 * Default-on, no env-gate: the shmem path is always live when the
 * shared mapping is available, falling back to the RPC on resolve
 * failure or slot-recycle detection.  An earlier validation gate
 * (NSPA_PROCESS_SHM) was stripped post-Ableton-soak.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __NSPA_PROCESS_SHM_H
#define __NSPA_PROCESS_SHM_H

#include "winternl.h"
#include "wine/server_protocol.h"  /* client_ptr_t, process_id_t, affinity_t, timeout_t */

/* Snapshot of the fields in process_shm_t that callers actually read.
 * Filled atomically by nspa_process_shm_query under one seqlock cycle;
 * callers pick the field they need.  flags are the PROCESS_SHM_FLAG_*
 * bits defined in server/protocol.def — kept opaque here so callers
 * stay decoupled from the wire format. */
struct nspa_process_shm_snapshot
{
    int          priority;       /* PROCESS_PRIOCLASS_* */
    int          base_priority;
    ULONG_PTR    affinity;       /* ULONG_PTR-cast affinity mask */
    int          exit_code;
    LONGLONG     start_time;     /* timeout_t cast for client convenience */
    LONGLONG     end_time;
    client_ptr_t peb;
    DWORD        id;             /* this process's pid */
    DWORD        parent_id;
    DWORD        group_id;
    DWORD        session_id;
    ULONG        suspend;
    ULONG        thread_flags;
    USHORT       machine;
    ULONG        flags;          /* PROCESS_SHM_FLAG_* — see process_shm.c bit accessors */
};

/* Bit accessors for snapshot.flags. */
extern BOOL nspa_process_shm_snapshot_is_disable_boost( const struct nspa_process_shm_snapshot *s );

/* Read all snapshot fields for the given process handle atomically
 * under one seqlock cycle.  Returns STATUS_SUCCESS on hit;
 * STATUS_NOT_SUPPORTED if the shmem path can't satisfy the read
 * (caller falls back to the get_process_info RPC). */
extern NTSTATUS nspa_process_shm_query( HANDLE handle, struct nspa_process_shm_snapshot *out );

#endif /* __NSPA_PROCESS_SHM_H */
