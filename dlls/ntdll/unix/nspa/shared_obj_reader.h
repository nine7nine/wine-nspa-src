/*
 * NSPA shared-session-object reader primitives.
 *
 * Common plumbing for ntdll/unix client-side readers that resolve
 * obj_locators returned by server RPCs through the kernel
 * \KernelObjects\__wine_session section, and read fields under the
 * existing seqlock retry pattern.
 *
 * Used by:
 *   - dlls/ntdll/unix/nspa/thread_shm.c
 *   - dlls/ntdll/unix/nspa/process_shm.c
 *
 * Each consumer keeps its own per-handle cache + type-specific RPC
 * wrapper + snapshot struct; this header exposes only the parts that
 * are bit-identical between consumers (session block mapping, locator
 * resolution, seqlock acquire/release).
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __NSPA_SHARED_OBJ_READER_H
#define __NSPA_SHARED_OBJ_READER_H

#include "winternl.h"
#include "wine/server_protocol.h"

/* Resolve a server-supplied obj_locator into a stable shared_object_t
 * pointer.  Validates the object's id matches what the server told us
 * (slot-recycling protection at resolve time; callers should also
 * re-check on every read in case the slot is freed mid-use).
 *
 * Returns NULL if the locator is invalid, the session block can't be
 * mapped, or the object id doesn't match the locator. */
extern const shared_object_t *nspa_shared_obj_resolve( struct obj_locator locator );

/* Seqlock acquire/release helpers.  Caller does the read between
 * acquire and release in a do-while retry loop:
 *
 *   UINT64 seq;
 *   do {
 *       nspa_shared_obj_acquire_seqlock( object, &seq );
 *       value = object->shm.X.field;
 *   } while (!nspa_shared_obj_release_seqlock( object, seq )); */
extern void nspa_shared_obj_acquire_seqlock( const shared_object_t *object, UINT64 *seq );
extern BOOL nspa_shared_obj_release_seqlock( const shared_object_t *object, UINT64 seq );

#endif /* __NSPA_SHARED_OBJ_READER_H */
