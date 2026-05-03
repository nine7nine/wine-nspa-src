/*
 * NSPA per-process client-range event registration table.
 *
 * Phase 4.6.A of the events Option A plan.  See header + plan doc.
 *
 * Stores (PE-allocated client-range event handle → server-side ntsync fd)
 * so async-I/O completion in server/async.c can ioctl(NTSYNC_IOC_EVENT_SET)
 * directly on the registered fd, instead of looking up a server-side
 * event obj that doesn't exist for client-range handles.
 *
 * Implementation note: linked list per process for now.  Lookup is O(N)
 * where N = registered events for that process.  Bounded in practice
 * because only events used as async-I/O completion targets get registered
 * (not every client-range event the PE side allocates).  Promote to a
 * hash if profiling shows the lookup matters.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "config.h"

#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "wine/list.h"

#include "../object.h"
#include "../process.h"
#include "../request.h"
#include "../thread.h"
#include "../file.h"

#include "inproc_event_table.h"

struct inproc_event_entry
{
    struct list  entry;
    obj_handle_t handle;
    int          fd;
};

static struct list *get_table( struct process *process )
{
#ifdef __linux__
    return process->nspa_inproc_event_table;
#else
    (void)process;
    return NULL;
#endif
}

static struct list *ensure_table( struct process *process )
{
#ifdef __linux__
    if (!process->nspa_inproc_event_table)
    {
        struct list *list = malloc( sizeof(*list) );
        if (!list) return NULL;
        list_init( list );
        process->nspa_inproc_event_table = list;
    }
    return process->nspa_inproc_event_table;
#else
    (void)process;
    return NULL;
#endif
}

static struct inproc_event_entry *find_entry( struct list *list, obj_handle_t handle )
{
    struct inproc_event_entry *e;
    if (!list) return NULL;
    LIST_FOR_EACH_ENTRY( e, list, struct inproc_event_entry, entry )
        if (e->handle == handle) return e;
    return NULL;
}

int nspa_inproc_event_register( struct process *process, obj_handle_t handle, int fd )
{
    struct list *list;
    struct inproc_event_entry *e;

    if (!handle || fd < 0) return -1;

    list = ensure_table( process );
    if (!list) return -1;

    /* Replace existing entry if any — defensive against PE-side double
     * register (shouldn't happen under correct PE-side code, but the
     * server must remain robust against a misbehaving client). */
    if ((e = find_entry( list, handle )))
    {
        if (e->fd != fd)
        {
            close( e->fd );
            e->fd = fd;
        }
        return 0;
    }

    if (!(e = malloc( sizeof(*e) ))) return -1;
    e->handle = handle;
    e->fd     = fd;
    list_add_tail( list, &e->entry );
    return 0;
}

int nspa_inproc_event_lookup( struct process *process, obj_handle_t handle )
{
    struct inproc_event_entry *e = find_entry( get_table( process ), handle );
    return e ? e->fd : -1;
}

void nspa_inproc_event_unregister( struct process *process, obj_handle_t handle )
{
    struct inproc_event_entry *e = find_entry( get_table( process ), handle );
    if (!e) return;
    list_remove( &e->entry );
    close( e->fd );
    free( e );
}

void nspa_inproc_event_table_destroy( struct process *process )
{
#ifdef __linux__
    struct list *list = process->nspa_inproc_event_table;
    struct inproc_event_entry *e, *next;

    if (!list) return;

    LIST_FOR_EACH_ENTRY_SAFE( e, next, list, struct inproc_event_entry, entry )
    {
        list_remove( &e->entry );
        close( e->fd );
        free( e );
    }
    free( list );
    process->nspa_inproc_event_table = NULL;
#else
    (void)process;
#endif
}

/* Request handlers — see protocol.def for the request shapes. */

DECL_HANDLER(nspa_register_inproc_event)
{
    int fd = thread_get_inflight_fd( current, req->fd );
    if (fd < 0)
    {
        set_error( STATUS_INVALID_HANDLE );
        return;
    }
    if (nspa_inproc_event_register( current->process, req->handle, fd ) < 0)
    {
        close( fd );
        set_error( STATUS_NO_MEMORY );
    }
}

DECL_HANDLER(nspa_unregister_inproc_event)
{
    nspa_inproc_event_unregister( current->process, req->handle );
}
