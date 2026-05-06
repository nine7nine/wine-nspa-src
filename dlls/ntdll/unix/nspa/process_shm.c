/*
 * NSPA per-process shared-memory snapshot reader (client side).
 *
 * Sibling of dlls/ntdll/unix/nspa/thread_shm.c.  The session-mapping
 * plumbing is duplicated here rather than extracted: the duplication
 * is small (<100 LoC), the two readers may evolve independently
 * during bring-up (e.g. different cache eviction policies, different
 * gate semantics), and a refactor to a shared utility can land later
 * if duplication becomes painful.  Both readers map the same kernel
 * \KernelObjects\__wine_session section, so the underlying physical
 * memory is shared even though the address-space mapping is separate.
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

#include "process_shm.h"

WINE_DEFAULT_DEBUG_CHANNEL(nspa);

enum gate_state
{
    GATE_UNINIT = 0,
    GATE_OFF,
    GATE_ON,
};

static LONG gate_state;

struct session_block
{
    struct list entry;
    const char *data;
    SIZE_T      offset;
    SIZE_T      size;
};

static DEFINE_PI_MUTEX( session_lock, 0 );
static struct list session_blocks = LIST_INIT( session_blocks );

struct handle_cache_entry
{
    struct list entry;
    HANDLE      handle;
    object_id_t locator_id;
    const shared_object_t *object;
};

static struct list handle_cache = LIST_INIT( handle_cache );

#if defined(__i386__) || defined(__x86_64__)
# define NSPA_SHM_READ_FENCE do { __asm__ __volatile__( "" ::: "memory" ); } while (0)
#else
# define NSPA_SHM_READ_FENCE __atomic_thread_fence( __ATOMIC_ACQUIRE )
#endif

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

static const shared_object_t *resolve_locator( struct obj_locator locator )
{
    const shared_object_t *object;
    struct session_block *block = NULL;

    if (!locator.id) return NULL;
    if (find_session_block( locator.offset, sizeof(*object), &block )) return NULL;

    object = (const shared_object_t *)(block->data + locator.offset - block->offset);

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

static struct handle_cache_entry *cache_lookup( HANDLE handle )
{
    struct handle_cache_entry *entry;

    LIST_FOR_EACH_ENTRY( entry, &handle_cache, struct handle_cache_entry, entry )
    {
        if (entry->handle == handle) return entry;
    }
    return NULL;
}

static void cache_insert( HANDLE handle, struct obj_locator locator, const shared_object_t *object )
{
    struct handle_cache_entry *entry;

    if (!(entry = calloc( 1, sizeof(*entry) ))) return;
    entry->handle     = handle;
    entry->locator_id = locator.id;
    entry->object     = object;
    list_add_tail( &handle_cache, &entry->entry );
}

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

    /* Default OFF for now: process_shm is in A/B bring-up.  Set
     * NSPA_PROCESS_SHM=1 to enable.  Polarity flips after A/B
     * validation, mirroring the thread_shm rollout. */
    env = getenv( "NSPA_PROCESS_SHM" );
    next = (env && !strcmp( env, "1" )) ? GATE_ON : GATE_OFF;

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

    pi_mutex_lock( &session_lock );
    if ((entry = cache_lookup( handle )))
    {
        object       = entry->object;
        *locator_id  = entry->locator_id;
        pi_mutex_unlock( &session_lock );
        return object;
    }
    pi_mutex_unlock( &session_lock );

    SERVER_START_REQ( get_process_shm )
    {
        req->handle = wine_server_obj_handle( handle );
        status = wine_server_call( req );
        locator = reply->locator;
    }
    SERVER_END_REQ;

    if (status) return NULL;

    pi_mutex_lock( &session_lock );
    if ((entry = cache_lookup( handle )))
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
        shm_acquire_seqlock( object, &seq );
        cur_id            = object->id;
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
    } while (!shm_release_seqlock( object, seq ));

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
