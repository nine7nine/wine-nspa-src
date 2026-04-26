/*
 * NSPA Tier 2 hook cache — wineserver side.
 *
 * Server-only writer of the per-(queue, hook id) snapshot in
 * nspa_queue_bypass_shm_t::nspa_hook_chains[].  Client reads under a
 * seqlock and falls back to the legacy start_hook_chain RPC trio
 * whenever the cache has `overflowed` set.
 *
 * Wineserver is single-threaded for request handling, so there is
 * never a writer/writer race on the cache.  The seqlock (even=stable,
 * odd=writer mid-update) exists purely to give clients a consistent
 * snapshot during the brief mutation window.
 */

#include "config.h"

#include <stdarg.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winuser.h"

#include "../object.h"
#include "../process.h"
#include "../thread.h"
#include "../user.h"
#include "../hook.h"
#include "hook_cache.h"

/* Bump-allocator for the per-queue UTF-16 module string pool.  Pool is
 * reset to cursor=0 at the start of every chain rebuild, so stale
 * strings need no individual cleanup.  Returns the byte offset into the
 * pool, or 0 if the string didn't fit (caller must set the chain's
 * `overflowed` flag in that case — offset 0 is also reserved as the
 * "no module" sentinel, so callers also pass module_size to
 * disambiguate). */
static unsigned int hook_pool_alloc( nspa_queue_bypass_shm_t *shm, unsigned int *cursor,
                                     const WCHAR *src, data_size_t size_bytes )
{
    unsigned int off;
    if (!size_bytes || !src) return 0;
    if (size_bytes > NSPA_HOOK_MODULE_POOL) return 0;
    /* leave offset 0 as the "no module" sentinel — start cursor at one
     * WCHAR-aligned slot on first allocation so a real module never
     * lands at 0. */
    if (*cursor == 0) *cursor = sizeof(WCHAR);
    if (*cursor + size_bytes > NSPA_HOOK_MODULE_POOL) return 0;
    off = *cursor;
    memcpy( (void *)&shm->nspa_hook_module_pool[off], src, size_bytes );
    *cursor += size_bytes;
    /* round up to WCHAR alignment so the next string starts even-aligned */
    *cursor = (*cursor + sizeof(WCHAR) - 1) & ~(unsigned int)(sizeof(WCHAR) - 1);
    return off;
}

void nspa_hook_cache_rebuild( struct thread *thread, int index )
{
    nspa_queue_bypass_shm_t *shm;
    nspa_hook_chain_t *chain;
    struct hook_table *table;
    struct hook_table *global_table;
    struct hook *hook;
    unsigned int pool_cursor = 0;
    unsigned int count = 0;
    unsigned int overflowed = 0;
    unsigned int v;

    if (index < 0 || index >= NB_HOOKS) return;
    if (!(shm = nspa_queue_bypass_shm( thread ))) return;

    chain = (nspa_hook_chain_t *)&shm->nspa_hook_chains[index];

    /* Begin write: bump version to odd so concurrent readers retry. */
    v = chain->version;
    __atomic_store_n( &chain->version, v + 1, __ATOMIC_RELEASE );
    __atomic_thread_fence( __ATOMIC_ACQ_REL );

    /* Force overflow if any global hook fires here for this queue —
     * those stay on the legacy RPC path (Tier 1 fallback also keeps
     * global hooks on counts[]). */
    global_table = get_global_hooks( thread );
    if (global_table)
    {
        LIST_FOR_EACH_ENTRY( hook, &global_table->hooks[index], struct hook, chain )
        {
            if (!hook->proc) continue;
            if (run_hook_in_thread( hook, thread ))
            {
                overflowed = 1;
                break;
            }
        }
    }

    table = get_queue_hooks( thread );
    if (!overflowed && table)
    {
        LIST_FOR_EACH_ENTRY( hook, &table->hooks[index], struct hook, chain )
        {
            nspa_hook_entry_t *e;
            if (!hook->proc) continue;
            /* WINEVENT out-of-context hooks need server-side post_win_event;
             * the client can't dispatch them locally.  Force overflow. */
            if (hook->index + WH_MINHOOK == WH_WINEVENT && !(hook->flags & WINEVENT_INCONTEXT))
            {
                overflowed = 1;
                break;
            }
            if (count >= NSPA_HOOK_CHAIN_CAP)
            {
                overflowed = 1;
                break;
            }
            e = (nspa_hook_entry_t *)&chain->entries[count];
            e->handle    = hook->handle;
            e->proc      = hook->proc;
            e->flags     = hook->flags;
            e->event_min = hook->event_min;
            e->event_max = hook->event_max;
            /* per-hook window/object/child scoping is not stored on
             * struct hook (those are runtime args from start_hook_chain
             * caller); reserved fields stay zero. */
            e->window    = 0;
            e->object_id = 0;
            e->child_id  = 0;
            e->pid       = hook->process ? hook->process->id : 0;
            e->tid       = hook->thread  ? hook->thread->id  : 0;
            e->module_offset = hook_pool_alloc( shm, &pool_cursor, hook->module, hook->module_size );
            if (hook->module_size && hook->module && e->module_offset == 0)
            {
                /* pool exhausted — fall back to RPC */
                overflowed = 1;
                break;
            }
            e->module_size = hook->module_size / sizeof(WCHAR);
            e->unicode     = hook->unicode;
            e->__pad       = 0;
            count++;
        }
    }

    if (overflowed) count = 0;
    chain->count      = (unsigned short)count;
    chain->overflowed = (unsigned short)overflowed;
    chain->__pad      = 0;

    /* End write: bump version to even.  Pair with the client-side
     * acquire load on version. */
    __atomic_thread_fence( __ATOMIC_ACQ_REL );
    __atomic_store_n( &chain->version, v + 2, __ATOMIC_RELEASE );
}

void nspa_hook_cache_rebuild_global( struct desktop *desktop, int index )
{
    struct thread *thread;

    if (!desktop || index < 0 || index >= NB_HOOKS) return;
    LIST_FOR_EACH_ENTRY( thread, &desktop->threads, struct thread, desktop_entry )
        nspa_hook_cache_rebuild( thread, index );
}
