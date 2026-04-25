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


/* irot (Phase 1.B) state — declared up front so nspa_rpc_state_release()
 * can sweep it on process exit.  Handlers themselves live further down
 * in the irot section, after the irpcss handlers, to keep the file
 * organised by sub-phase. */

struct registered_irot
{
    struct list      entry;
    struct process  *owner;
    void            *moniker_data;
    data_size_t      moniker_data_size;
    void            *object;
    data_size_t      object_size;
    void            *moniker;
    data_size_t      moniker_size;
    unsigned __int64 last_modified;
    unsigned int     cookie;
};

static struct list registered_irot_list = LIST_INIT( registered_irot_list );
static unsigned int next_irot_cookie;

static void free_irot_entry( struct registered_irot *e )
{
    list_remove( &e->entry );
    free( e->moniker_data );
    free( e->object );
    free( e->moniker );
    free( e );
}


void nspa_rpc_state_release( struct process *process )
{
    struct registered_class *cur, *next;
    struct registered_irot  *icur, *inext;

    LIST_FOR_EACH_ENTRY_SAFE( cur, next, &registered_classes,
                              struct registered_class, entry )
    {
        if (cur->owner == process)
            free_class_entry( cur );
    }

    LIST_FOR_EACH_ENTRY_SAFE( icur, inext, &registered_irot_list,
                              struct registered_irot, entry )
    {
        if (icur->owner == process)
            free_irot_entry( icur );
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


/* ════════════════════════════════════════════════════════════════════════
 *   Phase 1.B — irot (Running Object Table)
 *
 *   State and handlers for the seven IrotRegister/Revoke/IsRunning/
 *   GetObject/NoteChangeTime/GetTimeOfLastChange/EnumRunning RPC
 *   methods.  Same single-thread, single-list discipline as the
 *   irpcss state above.
 *
 *   Per-process cleanup hooks into the existing nspa_rpc_state_release()
 *   below — entries owned by a dying process are walked and freed.
 *
 *   Owner-check policy matches rpcss exactly: revoke and
 *   note_change_time look up entries by cookie alone, NOT by owner.
 *   Any process knowing a cookie can revoke or update its time.
 *   Cleanup on process exit IS owner-keyed (so leaked registrations
 *   from a dead process are reaped).
 * ════════════════════════════════════════════════════════════════════════ */


static struct registered_irot *find_irot_by_moniker_data( const void *data,
                                                          data_size_t size )
{
    struct registered_irot *cur;
    LIST_FOR_EACH_ENTRY( cur, &registered_irot_list, struct registered_irot, entry )
    {
        if (cur->moniker_data_size == size &&
            !memcmp( cur->moniker_data, data, size ))
            return cur;
    }
    return NULL;
}


static struct registered_irot *find_irot_by_cookie( unsigned int cookie )
{
    struct registered_irot *cur;
    LIST_FOR_EACH_ENTRY( cur, &registered_irot_list, struct registered_irot, entry )
    {
        if (cur->cookie == cookie) return cur;
    }
    return NULL;
}


DECL_HANDLER(nspa_irot_register)
{
    struct registered_irot *entry;
    const unsigned char *blob = get_req_data();
    data_size_t blob_size = get_req_data_size();
    data_size_t expected = req->moniker_data_len + req->object_len + req->moniker_len;

    if (blob_size != expected)
    {
        set_error( STATUS_INVALID_PARAMETER );
        return;
    }

    if (!(entry = mem_alloc( sizeof(*entry) ))) return;
    memset( entry, 0, sizeof(*entry) );

    if (req->moniker_data_len &&
        !(entry->moniker_data = memdup( blob, req->moniker_data_len )))
    {
        free( entry );
        return;
    }
    entry->moniker_data_size = req->moniker_data_len;

    if (req->object_len &&
        !(entry->object = memdup( blob + req->moniker_data_len, req->object_len )))
    {
        free( entry->moniker_data );
        free( entry );
        return;
    }
    entry->object_size = req->object_len;

    if (req->moniker_len &&
        !(entry->moniker = memdup( blob + req->moniker_data_len + req->object_len,
                                   req->moniker_len )))
    {
        free( entry->object );
        free( entry->moniker_data );
        free( entry );
        return;
    }
    entry->moniker_size = req->moniker_len;

    entry->owner         = current->process;
    entry->last_modified = req->time;
    entry->cookie        = ++next_irot_cookie;

    /* Match rpcss: duplicate moniker_data is allowed, but we report it
     * via already_registered so the client can map to MK_S_MONIKERALREADYREGISTERED. */
    reply->already_registered = find_irot_by_moniker_data( entry->moniker_data,
                                                           entry->moniker_data_size ) ? 1 : 0;

    list_add_tail( &registered_irot_list, &entry->entry );
    reply->cookie = entry->cookie;
}


DECL_HANDLER(nspa_irot_revoke)
{
    struct registered_irot *entry = find_irot_by_cookie( req->cookie );
    data_size_t total, reply_max;
    unsigned char *out;

    if (!entry)
    {
        set_error( STATUS_NOT_FOUND );
        return;
    }

    reply->object_len  = entry->object_size;
    reply->moniker_len = entry->moniker_size;

    total     = entry->object_size + entry->moniker_size;
    reply_max = get_reply_max_size();
    if (total > reply_max)
    {
        set_error( STATUS_BUFFER_TOO_SMALL );
        return;
    }

    if (total && (out = set_reply_data_size( total )))
    {
        if (entry->object_size)
            memcpy( out, entry->object, entry->object_size );
        if (entry->moniker_size)
            memcpy( out + entry->object_size, entry->moniker, entry->moniker_size );
    }

    free_irot_entry( entry );
}


DECL_HANDLER(nspa_irot_is_running)
{
    if (!find_irot_by_moniker_data( get_req_data(), get_req_data_size() ))
        set_error( STATUS_NOT_FOUND );
}


DECL_HANDLER(nspa_irot_get_object)
{
    struct registered_irot *entry =
        find_irot_by_moniker_data( get_req_data(), get_req_data_size() );

    if (!entry)
    {
        set_error( STATUS_NOT_FOUND );
        return;
    }

    reply->cookie = entry->cookie;

    if (entry->object_size)
    {
        data_size_t reply_max = get_reply_max_size();
        if (entry->object_size > reply_max)
        {
            set_error( STATUS_BUFFER_TOO_SMALL );
            return;
        }
        {
            void *out = set_reply_data_size( entry->object_size );
            if (out) memcpy( out, entry->object, entry->object_size );
        }
    }
}


DECL_HANDLER(nspa_irot_note_change_time)
{
    struct registered_irot *entry = find_irot_by_cookie( req->cookie );
    if (!entry)
    {
        set_error( STATUS_NOT_FOUND );
        return;
    }
    entry->last_modified = req->time;
}


DECL_HANDLER(nspa_irot_get_time_of_last_change)
{
    struct registered_irot *entry =
        find_irot_by_moniker_data( get_req_data(), get_req_data_size() );

    if (!entry)
    {
        set_error( STATUS_NOT_FOUND );
        return;
    }
    reply->time = entry->last_modified;
}


DECL_HANDLER(nspa_irot_enum_running)
{
    struct registered_irot *cur;
    data_size_t total = 0, reply_max = get_reply_max_size();
    unsigned int count = 0;
    unsigned char *out, *p;

    /* First pass: count + total size needed.  TLV stream:
     * for each entry, u32 size header + size bytes payload (the
     * "object" InterfaceData blob — that's what EnumRunning hands
     * back to the IRunningObjectTable client). */
    LIST_FOR_EACH_ENTRY( cur, &registered_irot_list, struct registered_irot, entry )
    {
        total += sizeof(unsigned int) + cur->object_size;
        count++;
    }

    reply->count = count;

    if (!total) return;
    if (total > reply_max)
    {
        set_error( STATUS_BUFFER_TOO_SMALL );
        return;
    }

    if (!(out = set_reply_data_size( total ))) return;

    p = out;
    LIST_FOR_EACH_ENTRY( cur, &registered_irot_list, struct registered_irot, entry )
    {
        unsigned int sz = cur->object_size;
        memcpy( p, &sz, sizeof(sz) );
        p += sizeof(sz);
        if (sz) memcpy( p, cur->object, sz );
        p += sz;
    }
}
