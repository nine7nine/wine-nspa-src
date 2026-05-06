/*
 * NSPA per-process shared-memory snapshot reader (client side).
 *
 * Builds on dlls/ntdll/unix/nspa/shared_obj_reader.{c,h} for the
 * session-mapping + seqlock plumbing.  Owns the per-handle resolve
 * cache, the env-gate state, the get_process_shm RPC wrapper, and
 * the process-specific snapshot read.
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

#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winnt.h"
#include "wine/server.h"
#include "wine/list.h"

#include <rtpi.h>

#include "shared_obj_reader.h"
#include "process_shm.h"

enum gate_state
{
    GATE_UNINIT = 0,
    GATE_OFF,
    GATE_ON,
};

static LONG gate_state;

struct handle_cache_entry
{
    struct list entry;
    HANDLE      handle;
    object_id_t locator_id;
    const shared_object_t *object;
};

static DEFINE_PI_MUTEX( cache_lock, 0 );
static struct list handle_cache = LIST_INIT( handle_cache );

/* Caller holds cache_lock. */
static struct handle_cache_entry *cache_lookup( HANDLE handle )
{
    struct handle_cache_entry *entry;

    LIST_FOR_EACH_ENTRY( entry, &handle_cache, struct handle_cache_entry, entry )
    {
        if (entry->handle == handle) return entry;
    }
    return NULL;
}

/* Caller holds cache_lock. */
static void cache_insert( HANDLE handle, struct obj_locator locator, const shared_object_t *object )
{
    struct handle_cache_entry *entry;

    if (!(entry = calloc( 1, sizeof(*entry) ))) return;
    entry->handle     = handle;
    entry->locator_id = locator.id;
    entry->object     = object;
    list_add_tail( &handle_cache, &entry->entry );
}

/* Caller holds cache_lock. */
static void cache_evict( HANDLE handle )
{
    struct handle_cache_entry *entry;

    LIST_FOR_EACH_ENTRY( entry, &handle_cache, struct handle_cache_entry, entry )
    {
        if (entry->handle == handle)
        {
            list_remove( &entry->entry );
            free( entry );
            return;
        }
    }
}

void nspa_process_shm_init(void)
{
    LONG expected = GATE_UNINIT;
    LONG next;
    const char *env;

    if (ReadNoFence( &gate_state ) != GATE_UNINIT) return;

    /* Default ON; NSPA_PROCESS_SHM=0 is the explicit escape hatch.
     * A/B validated bit-identical with the get_process_info RPC
     * fallback across all 6 covered query classes (stable fields). */
    env = getenv( "NSPA_PROCESS_SHM" );
    next = (env && !strcmp( env, "0" )) ? GATE_OFF : GATE_ON;

    InterlockedCompareExchange( &gate_state, next, expected );
}

BOOL nspa_process_shm_enabled(void)
{
    LONG state = ReadNoFence( &gate_state );
    if (state == GATE_UNINIT)
    {
        nspa_process_shm_init();
        state = ReadNoFence( &gate_state );
    }
    return state == GATE_ON;
}

static const shared_object_t *resolve_process_object( HANDLE handle, object_id_t *locator_id )
{
    struct handle_cache_entry *entry;
    const shared_object_t *object;
    struct obj_locator locator;
    NTSTATUS status;

    pi_mutex_lock( &cache_lock );
    if ((entry = cache_lookup( handle )))
    {
        object       = entry->object;
        *locator_id  = entry->locator_id;
        pi_mutex_unlock( &cache_lock );
        return object;
    }
    pi_mutex_unlock( &cache_lock );

    SERVER_START_REQ( get_process_shm )
    {
        req->handle = wine_server_obj_handle( handle );
        status = wine_server_call( req );
        locator = reply->locator;
    }
    SERVER_END_REQ;

    if (status) return NULL;

    pi_mutex_lock( &cache_lock );
    if ((entry = cache_lookup( handle )))
    {
        object      = entry->object;
        *locator_id = entry->locator_id;
    }
    else
    {
        object = nspa_shared_obj_resolve( locator );
        if (object)
        {
            cache_insert( handle, locator, object );
            *locator_id = locator.id;
        }
    }
    pi_mutex_unlock( &cache_lock );

    return object;
}

BOOL nspa_process_shm_snapshot_is_disable_boost( const struct nspa_process_shm_snapshot *s )
{
    return !!(s->flags & PROCESS_SHM_FLAG_DISABLE_BOOST);
}

NTSTATUS nspa_process_shm_query( HANDLE handle, struct nspa_process_shm_snapshot *out )
{
    const shared_object_t *object;
    object_id_t locator_id, cur_id;
    UINT64 seq;
    struct nspa_process_shm_snapshot snap;

    if (!nspa_process_shm_enabled()) return STATUS_NOT_SUPPORTED;
    if (!(object = resolve_process_object( handle, &locator_id ))) return STATUS_NOT_SUPPORTED;

    /* Single seqlock cycle pulls every cached field. */
    do
    {
        nspa_shared_obj_acquire_seqlock( object, &seq );
        cur_id             = object->id;
        snap.priority      = object->shm.process.priority;
        snap.base_priority = object->shm.process.base_priority;
        snap.affinity      = (ULONG_PTR)object->shm.process.affinity;
        snap.exit_code     = object->shm.process.exit_code;
        snap.start_time    = (LONGLONG)object->shm.process.start_time;
        snap.end_time      = (LONGLONG)object->shm.process.end_time;
        snap.peb           = object->shm.process.peb;
        snap.id            = (DWORD)object->shm.process.id;
        snap.parent_id     = (DWORD)object->shm.process.parent_id;
        snap.group_id      = (DWORD)object->shm.process.group_id;
        snap.session_id    = (DWORD)object->shm.process.session_id;
        snap.suspend       = (ULONG)object->shm.process.suspend;
        snap.thread_flags  = (ULONG)object->shm.process.thread_flags;
        snap.machine       = (USHORT)object->shm.process.machine;
        snap.flags         = (ULONG)object->shm.process.flags;
    } while (!nspa_shared_obj_release_seqlock( object, seq ));

    if (cur_id != locator_id)
    {
        pi_mutex_lock( &cache_lock );
        cache_evict( handle );
        pi_mutex_unlock( &cache_lock );
        return STATUS_NOT_SUPPORTED;
    }

    *out = snap;
    return STATUS_SUCCESS;
}
