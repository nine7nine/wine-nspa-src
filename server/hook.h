/*
 * Server-side window hook structures.
 *
 * Extracted from server/hook.c so server/nspa code (Tier 2 cache
 * rebuild, future drains) can walk hook chains without going through
 * a callback API.  No upstream behaviour change.
 */
#ifndef __WINE_SERVER_HOOK_H
#define __WINE_SERVER_HOOK_H

#include "wine/list.h"
#include "wine/server_protocol.h"
#include "object.h"

struct desktop;
struct process;
struct thread;
struct hook_table;

struct hook
{
    struct list         chain;    /* hook chain entry */
    user_handle_t       handle;   /* user handle for this hook */
    struct desktop     *desktop;  /* desktop the hook is registered for */
    struct process     *process;  /* process the hook is set to */
    struct thread      *thread;   /* thread the hook is set to */
    struct thread      *owner;    /* owner of the out of context hook */
    struct hook_table  *table;    /* hook table that contains this hook */
    int                 index;    /* hook table index */
    int                 event_min;
    int                 event_max;
    int                 flags;
    client_ptr_t        proc;     /* hook function */
    int                 unicode;  /* is it a unicode hook? */
    WCHAR              *module;   /* module name for global hooks */
    data_size_t         module_size;
};

struct hook_table
{
    struct object obj;              /* object header */
    struct list   hooks[NB_HOOKS];  /* array of hook chains */
    int           counts[NB_HOOKS]; /* use counts for each hook chain */
};

extern int  run_hook_in_thread( struct hook *hook, struct thread *thread );
extern struct hook_table *get_global_hooks( struct thread *thread );

#endif /* __WINE_SERVER_HOOK_H */
