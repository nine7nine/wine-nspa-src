/*
 * NSPA shared-session-object reader primitives — implementation.
 *
 * Sole owner of the session-block list, the session-block mapping
 * primitives, and the seqlock acquire/release helpers.  Replaces the
 * duplicated copies that previously lived in thread_shm.c and
 * process_shm.c (commit 7a's known duplication).
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

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "winnt.h"
#include "wine/list.h"
#include "wine/debug.h"

#include <rtpi.h>

#include "shared_obj_reader.h"

WINE_DEFAULT_DEBUG_CHANNEL(nspa);

/* x86: only need to block compiler reordering of non-volatile reads
 * past the seq check.  Other archs need a real fence.  Same trade-off
 * as dlls/win32u/win32u_private.h. */
#if defined(__i386__) || defined(__x86_64__)
# define NSPA_SHM_READ_FENCE do { __asm__ __volatile__( "" ::: "memory" ); } while (0)
#else
# define NSPA_SHM_READ_FENCE __atomic_thread_fence( __ATOMIC_ACQUIRE )
#endif

void nspa_shared_obj_acquire_seqlock( const shared_object_t *object, UINT64 *seq )
{
    while ((*seq = ReadNoFence64( &object->seq )) & 1) YieldProcessor();
    NSPA_SHM_READ_FENCE;
}

BOOL nspa_shared_obj_release_seqlock( const shared_object_t *object, UINT64 seq )
{
    NSPA_SHM_READ_FENCE;
    return ReadNoFence64( &object->seq ) == seq;
}

struct session_block
{
    struct list entry;
    const char *data;       /* mmap base */
    SIZE_T      offset;     /* offset within the session shared mapping */
    SIZE_T      size;       /* mapped size */
};

static DEFINE_PI_MUTEX( session_lock, 0 );
static struct list session_blocks = LIST_INIT( session_blocks );

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

const shared_object_t *nspa_shared_obj_resolve( struct obj_locator locator )
{
    const shared_object_t *object;
    struct session_block *block = NULL;

    if (!locator.id) return NULL;

    pi_mutex_lock( &session_lock );
    if (find_session_block( locator.offset, sizeof(*object), &block ))
    {
        pi_mutex_unlock( &session_lock );
        return NULL;
    }
    pi_mutex_unlock( &session_lock );

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
            nspa_shared_obj_acquire_seqlock( object, &seq );
            id = object->id;
        } while (!nspa_shared_obj_release_seqlock( object, seq ));

        if (id != locator.id) return NULL;
    }

    return object;
}
