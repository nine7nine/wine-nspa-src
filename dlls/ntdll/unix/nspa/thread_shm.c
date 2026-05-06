/*
 * NSPA per-thread shared-memory snapshot reader (client side).
 *
 * Mirrors the session-mapping plumbing in dlls/win32u/winstation.c so
 * that ntdll/unix can resolve obj_locators independently — win32u may
 * not be loaded in every Wine process (command-line tools, services),
 * and circular-dep concerns rule out calling into win32u from ntdll.
 * The duplicate NtMapViewOfSection on the same `\KernelObjects\
 * __wine_session` section shares physical pages with win32u's mapping;
 * cost is one extra address-space slot per process.
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
#include "wine/debug.h"

#include <rtpi.h>

#include "thread_shm.h"

WINE_DEFAULT_DEBUG_CHANNEL(nspa);

/* Process-wide state: env-gate decision, session blocks, and per-handle cache. */

enum gate_state
{
    GATE_UNINIT = 0,    /* nspa_thread_shm_init not yet run */
    GATE_OFF,           /* env unset or != "1" */
    GATE_ON,            /* env == "1" */
};

static LONG gate_state;     /* atomic, written once via InterlockedCompareExchange */

struct session_block
{
    struct list entry;
    const char *data;       /* mmap base */
    SIZE_T      offset;     /* offset within the session shared mapping */
    SIZE_T      size;       /* mapped size */
};

static DEFINE_PI_MUTEX( session_lock, 0 );
static struct list session_blocks = LIST_INIT( session_blocks );

/* Per-handle resolved-object cache.  Most processes query
 * GetCurrentThread() (handle == ~1) almost exclusively, but
 * NtQueryInformationThread accepts any thread handle so we keep a
 * small linked list rather than a single static.
 *
 * `locator_id` is captured at resolve time and re-checked on every
 * read: if the server-side slot was freed and recycled (thread died,
 * a later thread alloc grabbed the same slot), the slot's id field is
 * incremented inside alloc_shared_object's seqlock, so any reader
 * comparing object->id to the cached locator_id catches it.  Without
 * this check, the reader would silently consume fields from another
 * thread's snapshot. */
struct handle_cache_entry
{
    struct list entry;
    HANDLE      handle;     /* thread handle as passed to the query */
    object_id_t locator_id; /* locator->id at cache-insert time */
    const shared_object_t *object;  /* resolved through the session mapping */
};

static struct list handle_cache = LIST_INIT( handle_cache );

/* x86: only need to block compiler reordering of non-volatile reads
 * (memcpy etc.) past the seq check.  Other archs need a real fence.
 * Same trade-off as dlls/win32u/win32u_private.h. */
#if defined(__i386__) || defined(__x86_64__)
# define NSPA_SHM_READ_FENCE do { __asm__ __volatile__( "" ::: "memory" ); } while (0)
#else
# define NSPA_SHM_READ_FENCE __atomic_thread_fence( __ATOMIC_ACQUIRE )
#endif

/* Mirrors of dlls/win32u/winstation.c's seqlock helpers.  Inline-able
 * since they're tiny; declared static so they don't escape this TU. */
static void shm_acquire_seqlock( const shared_object_t *object, UINT64 *seq )
{
    while ((*seq = ReadNoFence64( &object->seq )) & 1) YieldProcessor();
    NSPA_SHM_READ_FENCE;
}

static BOOL shm_release_seqlock( const shared_object_t *object, UINT64 seq )
{
    NSPA_SHM_READ_FENCE;
    return ReadNoFence64( &object->seq ) == seq;
}

static NTSTATUS map_session_block( SIZE_T offset, SIZE_T size, struct session_block **ret )
{
    static const WCHAR nameW[] =
    {
        '\\','K','e','r','n','e','l','O','b','j','e','c','t','s','\\',
        '_','_','w','i','n','e','_','s','e','s','s','i','o','n',0
    };
    UNICODE_STRING name = RTL_CONSTANT_STRING( nameW );
    SYSTEM_BASIC_INFORMATION info;
    LARGE_INTEGER off;
    struct session_block *block;
    OBJECT_ATTRIBUTES attr;
    NTSTATUS status;
    HANDLE handle;

    if ((status = NtQuerySystemInformation( SystemBasicInformation, &info, sizeof(info), NULL )))
        return status;

    off.QuadPart = offset - (offset % info.AllocationGranularity);

    if (!(block = calloc( 1, sizeof(*block) ))) return STATUS_NO_MEMORY;

    InitializeObjectAttributes( &attr, &name, 0, NULL, NULL );
    if ((status = NtOpenSection( &handle, SECTION_MAP_READ, &attr )))
    {
        WARN( "NtOpenSection __wine_session failed, status %#x\n", (unsigned int)status );
        free( block );
        return status;
    }

    if ((status = NtMapViewOfSection( handle, GetCurrentProcess(), (void **)&block->data,
                                       0, 0, &off, &block->size, ViewUnmap, 0, PAGE_READONLY )))
    {
        WARN( "NtMapViewOfSection failed, status %#x\n", (unsigned int)status );
        NtClose( handle );
        free( block );
        return status;
    }

    NtClose( handle );
    block->offset = off.QuadPart;
    list_add_tail( &session_blocks, &block->entry );
    *ret = block;
    return STATUS_SUCCESS;
}

/* Caller holds session_lock. */
static NTSTATUS find_session_block( SIZE_T offset, SIZE_T size, struct session_block **ret )
{
    struct session_block *block;

    LIST_FOR_EACH_ENTRY( block, &session_blocks, struct session_block, entry )
    {
        if (block->offset <= offset && offset + size <= block->offset + block->size)
        {
            *ret = block;
            return STATUS_SUCCESS;
        }
    }
    return map_session_block( offset, size, ret );
}

/* Caller holds session_lock.  Resolves a server-supplied locator into
 * a stable shared_object_t pointer; verifies the object's id matches
 * what the server told us so we don't read into a recycled slot. */
static const shared_object_t *resolve_locator( struct obj_locator locator )
{
    const shared_object_t *object;
    struct session_block *block = NULL;

    if (!locator.id) return NULL;
    if (find_session_block( locator.offset, sizeof(*object), &block )) return NULL;

    object = (const shared_object_t *)(block->data + locator.offset - block->offset);

    /* Walk the seqlock once to read object->id; any mismatch with the
     * locator indicates the underlying server-side slot was freed and
     * possibly re-allocated to another object since the server returned
     * the locator.  Fail closed in that case. */
    {
        UINT64 seq;
        object_id_t id;
        do
        {
            shm_acquire_seqlock( object, &seq );
            id = object->id;
        } while (!shm_release_seqlock( object, seq ));

        if (id != locator.id) return NULL;
    }

    return object;
}

/* Caller holds session_lock. */
static struct handle_cache_entry *cache_lookup( HANDLE handle )
{
    struct handle_cache_entry *entry;

    LIST_FOR_EACH_ENTRY( entry, &handle_cache, struct handle_cache_entry, entry )
    {
        if (entry->handle == handle) return entry;
    }
    return NULL;
}

/* Caller holds session_lock. */
static void cache_insert( HANDLE handle, struct obj_locator locator, const shared_object_t *object )
{
    struct handle_cache_entry *entry;

    if (!(entry = calloc( 1, sizeof(*entry) ))) return;
    entry->handle     = handle;
    entry->locator_id = locator.id;
    entry->object     = object;
    list_add_tail( &handle_cache, &entry->entry );
}

/* Caller holds session_lock.  Drops a stale entry so a subsequent
 * resolve_thread_object call re-asks the server. */
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

    /* Single-shot: only the first caller transitions GATE_UNINIT → GATE_ON/OFF.
     * Subsequent calls observe the cached state.  No mutex needed. */
    if (ReadNoFence( &gate_state ) != GATE_UNINIT) return;

    env = getenv( "NSPA_THREAD_SHM" );
    next = (env && !strcmp( env, "1" )) ? GATE_ON : GATE_OFF;

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

    pi_mutex_lock( &session_lock );
    if ((entry = cache_lookup( handle )))
    {
        object       = entry->object;
        *locator_id  = entry->locator_id;
        pi_mutex_unlock( &session_lock );
        return object;
    }
    pi_mutex_unlock( &session_lock );

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

    if (status) return NULL;

    pi_mutex_lock( &session_lock );
    if ((entry = cache_lookup( handle )))    /* re-check after lock re-acq */
    {
        object      = entry->object;
        *locator_id = entry->locator_id;
    }
    else
    {
        object = resolve_locator( locator );
        if (object)
        {
            cache_insert( handle, locator, object );
            *locator_id = locator.id;
        }
    }
    pi_mutex_unlock( &session_lock );

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
        shm_acquire_seqlock( object, &seq );
        cur_id          = object->id;
        snap.affinity    = (ULONG_PTR)object->shm.thread.affinity;
        snap.entry_point = object->shm.thread.entry_point;
        snap.suspend     = (ULONG)object->shm.thread.suspend;
        snap.flags       = (ULONG)object->shm.thread.flags;
    } while (!shm_release_seqlock( object, seq ));

    /* Slot recycling: if id no longer matches the locator we cached, the
     * server freed this slot (thread died) and possibly re-allocated it
     * to another object.  Evict the stale cache entry and report not-
     * supported so the caller falls back to the RPC, which will
     * authoritatively answer the query (and report STATUS_INVALID_HANDLE
     * if appropriate). */
    if (cur_id != locator_id)
    {
        pi_mutex_lock( &session_lock );
        cache_evict( handle );
        pi_mutex_unlock( &session_lock );
        return STATUS_NOT_SUPPORTED;
    }

    *out = snap;
    return STATUS_SUCCESS;
}
