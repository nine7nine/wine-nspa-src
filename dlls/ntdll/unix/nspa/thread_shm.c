/*
 * NSPA per-thread shared-memory snapshot reader (client side).
 *
 * Builds on dlls/ntdll/unix/nspa/shared_obj_reader.{c,h} for the
 * session-mapping + seqlock plumbing.  Owns the per-handle resolve
 * cache, the env-gate state, the get_thread_shm RPC wrapper, and the
 * thread-specific snapshot read.
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
#include "thread_shm.h"

enum gate_state
{
    GATE_UNINIT = 0,
    GATE_OFF,
    GATE_ON,
};

static LONG gate_state;

/* Per-handle resolved-object cache.  `locator_id` is captured at
 * resolve time and re-checked on every read: if the server-side slot
 * was freed and recycled, the slot's id field is incremented inside
 * alloc_shared_object's seqlock, so any reader comparing object->id
 * to the cached locator_id catches it.  Without this check, the
 * reader would silently consume fields from another thread's snapshot. */
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

void nspa_thread_shm_init(void)
{
    LONG expected = GATE_UNINIT;
    LONG next;
    const char *env;

    if (ReadNoFence( &gate_state ) != GATE_UNINIT) return;

    /* Default ON; NSPA_THREAD_SHM=0 is the explicit escape hatch.
     * A/B validated bit-identical with the get_thread_info RPC
     * fallback across all 7 covered query classes. */
    env = getenv( "NSPA_THREAD_SHM" );
    next = (env && !strcmp( env, "0" )) ? GATE_OFF : GATE_ON;

    InterlockedCompareExchange( &gate_state, next, expected );
}

BOOL nspa_thread_shm_enabled(void)
{
    LONG state = ReadNoFence( &gate_state );
    if (state == GATE_UNINIT)
    {
        nspa_thread_shm_init();
        state = ReadNoFence( &gate_state );
    }
    return state == GATE_ON;
}

/* Resolve the shared object for a given thread handle, returning the
 * object pointer + the locator id captured at resolve time.  Lazy:
 * queries the server on first miss, caches the result.  Returns NULL
 * on any failure; callers must fall back to the get_thread_info RPC. */
static const shared_object_t *resolve_thread_object( HANDLE handle, object_id_t *locator_id )
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

    /* Cache miss — round-trip to the server.  Drop the lock during the
     * RPC; multiple threads may race and each insert a duplicate, but
     * that's a tiny one-time cost (the duplicate entries are equally
     * valid). */
    SERVER_START_REQ( get_thread_shm )
    {
        req->handle = wine_server_obj_handle( handle );
        status = wine_server_call( req );
        locator = reply->locator;
    }
    SERVER_END_REQ;

    pi_mutex_lock( &cache_lock );
    if ((entry = cache_lookup( handle )))    /* re-check after lock re-acq */
    {
        object      = entry->object;
        *locator_id = entry->locator_id;
    }
    else
    {
        /* Resolve may fail because the handle lacks
         * THREAD_QUERY_LIMITED_INFORMATION (server returned empty
         * locator), shmem mapping is unavailable, or the slot got
         * recycled before we resolved.  Cache a NEGATIVE entry so
         * subsequent queries on the same handle skip the RPC + resolve
         * work and fall through to the caller's RPC fallback
         * immediately.  Without this, every miss-prone call burns a
         * fresh get_thread_shm RPC. */
        object = (status == STATUS_SUCCESS) ? nspa_shared_obj_resolve( locator ) : NULL;
        cache_insert( handle, locator, object );
        *locator_id = object ? locator.id : 0;
    }
    pi_mutex_unlock( &cache_lock );

    return object;
}

BOOL nspa_thread_shm_snapshot_is_terminated( const struct nspa_thread_shm_snapshot *s )
{
    return !!(s->flags & THREAD_SHM_FLAG_TERMINATED);
}

BOOL nspa_thread_shm_snapshot_is_dbg_hidden( const struct nspa_thread_shm_snapshot *s )
{
    return !!(s->flags & THREAD_SHM_FLAG_DBG_HIDDEN);
}

BOOL nspa_thread_shm_snapshot_is_disable_boost( const struct nspa_thread_shm_snapshot *s )
{
    return !!(s->flags & THREAD_SHM_FLAG_DISABLE_BOOST);
}

NTSTATUS nspa_thread_shm_query( HANDLE handle, struct nspa_thread_shm_snapshot *out )
{
    const shared_object_t *object;
    object_id_t locator_id, cur_id;
    UINT64 seq;
    struct nspa_thread_shm_snapshot snap;

    if (!nspa_thread_shm_enabled()) return STATUS_NOT_SUPPORTED;
    if (!(object = resolve_thread_object( handle, &locator_id ))) return STATUS_NOT_SUPPORTED;

    /* Single seqlock cycle pulls every cached field; callers pick the
     * one they need.  Cost is the same as a single-field read because
     * the seqlock retry dominates over the field copies. */
    do
    {
        nspa_shared_obj_acquire_seqlock( object, &seq );
        cur_id             = object->id;
        snap.priority      = object->shm.thread.priority;
        snap.base_priority = object->shm.thread.base_priority;
        snap.affinity      = (ULONG_PTR)object->shm.thread.affinity;
        snap.exit_code     = object->shm.thread.exit_code;
        snap.teb           = object->shm.thread.teb;
        snap.entry_point   = object->shm.thread.entry_point;
        snap.id            = (DWORD)object->shm.thread.id;
        snap.process_id    = (DWORD)object->shm.thread.process_id;
        snap.suspend       = (ULONG)object->shm.thread.suspend;
        snap.flags         = (ULONG)object->shm.thread.flags;
    } while (!nspa_shared_obj_release_seqlock( object, seq ));

    /* Slot recycling: if id no longer matches the locator we cached, the
     * server freed this slot (thread died) and possibly re-allocated it
     * to another object.  Evict the stale cache entry and report not-
     * supported so the caller falls back to the RPC. */
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
