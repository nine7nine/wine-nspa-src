/*
 * NSPA msg-ring v2 Phase C Stage 3b — client-side hardware-message cache.
 *
 * Per-thread cache populated from the nspa_get_hw_msg_batch RPC and
 * drained by peek_message_internal before the existing single-msg
 * get_message path.  Each cached entry has the same shape that
 * get_message would have returned for MSG_HARDWARE.
 *
 * Per-thread storage uses pthread_key + lazy heap allocation, matching
 * the pattern in dlls/win32u/nspa/msg_ring.c — __thread TLS faults on
 * PE-spawned threads (see project_msg_bypass_tls_fault.md).
 *
 * Lockup-bug-class audit (feedback_dont_reintroduce_silent_contract_bugs.md):
 *
 *   1. Discriminator (MR1):  filter snapshot in the cache acts as the
 *      ownership token; try_pop validates the caller's filter matches
 *      the snapshot before delivering.  unique_id is stamped server-
 *      side and only used as the continuation cursor passed back to
 *      the next batch RPC (server validates by walking the input list).
 *
 *   2. Wake fallback (MR4):  no shmem rings or futex signalling; pure
 *      RPC + heap.  N/A.
 *
 *   3. FUTEX_PRIVATE (MR2):  no futex calls.  N/A.
 *
 *   4. Slot ownership:  cache is per-thread, no cross-thread access.
 *      Server walker runs single-handler within wineserver event loop.
 *
 * Additional design guards (audit doc):
 *
 *   - Batch path engaged only when (flags & PM_REMOVE).  PM_NOREMOVE
 *     would violate caller's intent for RAWINPUT/POINTER msgs that
 *     server removes during batch; defer to single-msg RPC.
 *
 *   - Skipped when wake_bits & QS_HOTKEY since server returns hotkey
 *     before hardware in get_message priority order; we'd reorder.
 *
 *   - Skipped when signal_bits doesn't include QS_INPUT — no hardware
 *     would be returned anyway, save the RPC.
 */

#if 0
#pragma makedep unix
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "wine/server.h"
#include "wine/server_protocol.h"

#include "hw_msg_cache.h"

#define NSPA_HW_BATCH_CACHE_CAP 16

typedef struct
{
    /* Filter snapshot — invalidates cache when caller filter changes. */
    HWND  filter_hwnd;
    UINT  filter_first;
    UINT  filter_last;
    UINT  filter_flags_remove;   /* the relevant PM_REMOVE bit only */
    /* Buffer state */
    UINT  count;                 /* number of populated entries */
    UINT  next;                  /* index of next-to-deliver */
    /* Entries */
    struct nspa_hw_msg_batch_entry entries[NSPA_HW_BATCH_CACHE_CAP];
} hw_msg_cache_t;

/* ------------------------------------------------------------------ *
 *  env-var gate
 * ------------------------------------------------------------------ */

/* Read once at process startup via __attribute__((constructor)) for
 * zero per-call overhead in the steady state — see
 * feedback_debug_off_means_off.md.  Default OFF until validated. */
static int hw_batch_enabled = 0;

static void __attribute__((constructor)) nspa_hw_batch_init( void )
{
    const char *v = getenv( "NSPA_ENABLE_HW_BATCH" );
    hw_batch_enabled = (v && *v == '1');
}

BOOL nspa_hw_batch_enabled( void )
{
    return hw_batch_enabled;
}

/* ------------------------------------------------------------------ *
 *  per-thread cache via pthread_key
 * ------------------------------------------------------------------ */

static pthread_key_t  cache_tls_key;
static pthread_once_t cache_tls_once = PTHREAD_ONCE_INIT;

static void cache_tls_destructor( void *p )
{
    free( p );
}

static void cache_tls_init_once( void )
{
    pthread_key_create( &cache_tls_key, cache_tls_destructor );
}

/* Returns this thread's cache, allocating on first use.  Returns NULL
 * if allocation failed — caller falls through to server. */
static hw_msg_cache_t *cache_get( void )
{
    hw_msg_cache_t *cache;

    pthread_once( &cache_tls_once, cache_tls_init_once );

    cache = pthread_getspecific( cache_tls_key );
    if (cache) return cache;

    cache = calloc( 1, sizeof(*cache) );
    if (!cache) return NULL;

    if (pthread_setspecific( cache_tls_key, cache ) != 0)
    {
        free( cache );
        return NULL;
    }
    return cache;
}

static inline UINT pm_remove_bit( UINT flags )
{
    return flags & PM_REMOVE;
}

static inline BOOL filter_matches( const hw_msg_cache_t *cache,
                                   HWND hwnd, UINT first, UINT last, UINT flags )
{
    return cache->filter_hwnd        == hwnd
        && cache->filter_first       == first
        && cache->filter_last        == last
        && cache->filter_flags_remove == pm_remove_bit( flags );
}

/* ------------------------------------------------------------------ *
 *  public API
 * ------------------------------------------------------------------ */

BOOL nspa_hw_msg_cache_try_pop( HWND filter_hwnd, UINT first, UINT last, UINT flags,
                                struct nspa_hw_msg_batch_entry *out )
{
    hw_msg_cache_t *cache = cache_get();
    if (!cache) return FALSE;
    if (cache->next >= cache->count) return FALSE;

    /* Filter discriminator check — invariant from MR1 audit.  Cached
     * entries were resolved server-side under a specific filter
     * snapshot; if caller's filter differs, the entries may not all
     * be valid for the new filter.  Drop the cache and force a refill. */
    if (!filter_matches( cache, filter_hwnd, first, last, flags ))
    {
        cache->count = 0;
        cache->next  = 0;
        return FALSE;
    }

    *out = cache->entries[cache->next++];
    return TRUE;
}

unsigned int nspa_hw_msg_cache_refill( HWND filter_hwnd, UINT first, UINT last,
                                       UINT flags, UINT continuation_hw_id )
{
    hw_msg_cache_t *cache;
    unsigned int returned = 0;

    if (!hw_batch_enabled) return 0;
    cache = cache_get();
    if (!cache) return 0;

    /* Invalidate before refill — defensive even if filter matches.
     * The next/count fields will be set fresh from the RPC reply. */
    cache->count = 0;
    cache->next  = 0;

    SERVER_START_REQ( nspa_get_hw_msg_batch )
    {
        req->max_count  = NSPA_HW_BATCH_CACHE_CAP;
        req->hw_id      = continuation_hw_id;
        req->filter_win = wine_server_user_handle( filter_hwnd );
        req->first      = first;
        req->last       = last;
        req->flags      = flags;
        wine_server_set_reply( req, cache->entries, sizeof(cache->entries) );
        if (!wine_server_call( req ))
            returned = reply->returned;
    }
    SERVER_END_REQ;

    if (returned > NSPA_HW_BATCH_CACHE_CAP) returned = 0;  /* defensive */

    cache->count = returned;
    cache->next  = 0;
    if (returned)
    {
        cache->filter_hwnd         = filter_hwnd;
        cache->filter_first        = first;
        cache->filter_last         = last;
        cache->filter_flags_remove = pm_remove_bit( flags );
    }
    return returned;
}
