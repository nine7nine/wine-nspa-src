/*
 * NSPA: in-wineserver state for relocated rpcss interfaces.
 *
 * Phase 1.A — irpcss (COM class-factory registry).
 *
 * Replaces the per-prefix rpcss.exe state for the four irpcss_* RPC
 * methods with a single-thread-protected (wineserver event loop)
 * in-memory list.  Per-process ownership is tracked explicitly so
 * registrations are released when the registering process exits;
 * this matches the rpcss-side context-handle cleanup semantics.
 *
 * State model:
 *   - One global linked list of registered_class entries.  Small
 *     (typically <50 per prefix).  Linear scan is fine for v1; if a
 *     profile ever flags it we move to a hash.
 *   - Cookie + thread_seq_id are global monotonic counters, identical
 *     to the static LONG counters rpcss uses today.
 *
 * Concurrency:
 *   - All access is from inside a wineserver request handler; the
 *     server event loop is single-threaded so no locking is needed.
 *
 * See nspa/docs/rpc-fast-and-solid-plan.md.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS

#include "../object.h"
#include "../process.h"
#include "../request.h"
#include "wine/list.h"

#include "rpc_state.h"


struct registered_class
{
    struct list      entry;
    struct process  *owner;            /* registering process; cleared on owner exit */
    unsigned __int64 clsid_lo;
    unsigned __int64 clsid_hi;
    unsigned int     cookie;
    unsigned int     single_use;       /* 1 = revoke on first lookup hit */
    void            *object;           /* MInterfacePointer blob (malloc'd) */
    data_size_t      object_size;
};

static struct list registered_classes = LIST_INIT( registered_classes );
static unsigned int next_cookie;
static unsigned int next_thread_seq_id;


/* CoRegisterClassObject flag bits we care about — definitions
 * mirror those in dlls/combase/.  We only need REGCLS_MULTIPLEUSE
 * and REGCLS_MULTI_SEPARATE to compute single_use the same way
 * rpcss does (see programs/rpcss/rpcss_main.c). */
#define NSPA_REGCLS_MULTIPLEUSE     1
#define NSPA_REGCLS_MULTI_SEPARATE  2


static void free_class_entry( struct registered_class *entry )
{
    list_remove( &entry->entry );
    free( entry->object );
    free( entry );
}


void nspa_rpc_state_release( struct process *process )
{
    struct registered_class *cur, *next;

    LIST_FOR_EACH_ENTRY_SAFE( cur, next, &registered_classes,
                              struct registered_class, entry )
    {
        if (cur->owner == process)
            free_class_entry( cur );
    }
}


DECL_HANDLER(nspa_register_class_factory)
{
    struct registered_class *entry;
    const void *object_data = get_req_data();
    data_size_t object_size = get_req_data_size();

    if (!(entry = mem_alloc( sizeof(*entry) )))
        return;

    if (object_size && !(entry->object = memdup( object_data, object_size )))
    {
        free( entry );
        return;
    }
    entry->owner       = current->process;
    entry->clsid_lo    = req->clsid_lo;
    entry->clsid_hi    = req->clsid_hi;
    entry->cookie      = ++next_cookie;
    entry->single_use  = !(req->flags & (NSPA_REGCLS_MULTIPLEUSE | NSPA_REGCLS_MULTI_SEPARATE));
    entry->object_size = object_size;
    if (!object_size) entry->object = NULL;

    list_add_tail( &registered_classes, &entry->entry );

    reply->cookie = entry->cookie;
}


DECL_HANDLER(nspa_revoke_class_factory)
{
    struct registered_class *cur;

    LIST_FOR_EACH_ENTRY( cur, &registered_classes, struct registered_class, entry )
    {
        if (cur->cookie == req->cookie && cur->owner == current->process)
        {
            free_class_entry( cur );
            return;
        }
    }
    /* No match.  rpcss returns S_OK silently for unknown cookies; mirror that. */
}


DECL_HANDLER(nspa_get_class_factory)
{
    struct registered_class *cur;

    LIST_FOR_EACH_ENTRY( cur, &registered_classes, struct registered_class, entry )
    {
        if (cur->clsid_lo != req->clsid_lo || cur->clsid_hi != req->clsid_hi)
            continue;

        if (cur->object_size)
        {
            data_size_t reply_max = get_reply_max_size();
            data_size_t out_size  = min( cur->object_size, reply_max );
            void       *out;

            if (out_size < cur->object_size)
            {
                set_error( STATUS_BUFFER_TOO_SMALL );
                return;
            }
            if ((out = set_reply_data_size( out_size )))
                memcpy( out, cur->object, out_size );
        }

        if (cur->single_use)
            free_class_entry( cur );
        return;
    }

    set_error( STATUS_NOT_FOUND );
}


DECL_HANDLER(nspa_alloc_thread_seq_id)
{
    reply->seq_id = ++next_thread_seq_id;
}
