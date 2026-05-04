/*
 * Windows hook functions
 *
 * Copyright 2002 Alexandre Julliard
 * Copyright 2005 Dmitry Timoshkov
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include <assert.h>
#include <pthread.h>
#include <time.h>
#include "win32u_private.h"
#include "ntuser_private.h"
#include "wine/server.h"
#include "wine/debug.h"
#include "nspa_hook_filter.h"

WINE_DEFAULT_DEBUG_CHANNEL(hook);

static const char * const hook_names[NB_HOOKS] =
{
    "WH_MSGFILTER",
    "WH_JOURNALRECORD",
    "WH_JOURNALPLAYBACK",
    "WH_KEYBOARD",
    "WH_GETMESSAGE",
    "WH_CALLWNDPROC",
    "WH_CBT",
    "WH_SYSMSGFILTER",
    "WH_MOUSE",
    "WH_HARDWARE",
    "WH_DEBUG",
    "WH_SHELL",
    "WH_FOREGROUNDIDLE",
    "WH_CALLWNDPROCRET",
    "WH_KEYBOARD_LL",
    "WH_MOUSE_LL",
    "WH_WINEVENT"
};

static const char *debugstr_hook_id( unsigned int id )
{
    if (id - WH_MINHOOK >= ARRAYSIZE(hook_names)) return wine_dbg_sprintf( "%u", id );
    return hook_names[id - WH_MINHOOK];
}

BOOL is_hooked( INT id )
{
    struct object_lock lock = OBJECT_LOCK_INIT;
    const queue_shm_t *queue_shm;
    BOOL ret = TRUE;
    unsigned int spin = 0;
    UINT status;

    /* On exhaustion return TRUE so message dispatch falls through to
     * the legacy hook RPCs (server has the authoritative chain). */
    while ((status = get_shared_queue( &lock, &queue_shm )) == STATUS_PENDING)
    {
        ret = queue_shm->hooks_count[id - WH_MINHOOK] > 0;
        NSPA_SHM_RETRY_GUARD( spin, return TRUE );
    }

    if (status) return TRUE;
    return ret;
}

/* ---------------------------------------------------------------------
 * NSPA hook-chain feasibility diagnostic — REMOVED 2026-04-26.
 *
 * The diag pile (top_calls / skipped_no_hooks / server_dispatch / cat_*
 * / tier1_shmem_inc/dec / tier1_finish_forced/skipped / tier2_*) and
 * its 5-second background dump thread were added pre-Tier-1/Tier-2 to
 * decide *whether to build* a hook cache.  T1 + T2 shipped
 * (commits f21a1d7a952 + bec766b35a9), the decision was made, the
 * counters became dead instrumentation paying ~13 atomic adds per
 * call_message_hooks invocation forever.  Removed in the same pass
 * that deleted Phase C Stage 1's getmsg_diag.c and gated the paint
 * fastpath stats — see project memory for the cleanup rationale.
 *
 * Load-bearing kept: bypass->nspa_hook_walk_counts[idx] (server reads
 * those for tier1 refcount); nspa_hook_try_read_cache (the actual
 * cache reader). */
/* ---------------------------------------------------------------------
 * NSPA Tier 2 hook cache reader.
 *
 * The wineserver maintains a per-(queue, hook id) snapshot of the chain
 * in nspa_queue_bypass_shm_t::nspa_hook_chains[] under a seqlock (see
 * server/nspa/hook_cache.c).  When the snapshot is stable and not
 * marked overflowed, the client iterates entries directly from shmem
 * instead of round-tripping start_hook_chain / get_hook_info /
 * finish_hook_chain.
 *
 * Walker is allocated on the dispatching thread's stack inside
 * call_message_hooks; nspa_hook_walker_current points at the innermost
 * walker so NtUserCallNextHookEx can advance through entries[] without
 * an RPC.  Nested calls (one hook proc triggering another hook chain)
 * push/pop via the prev pointer.
 *
 * Falls back to the Tier 1 RPC path on overflow, seqlock retry
 * exhaustion, or any structural reason the cache can't serve the
 * request. */

struct nspa_hook_walker
{
    struct nspa_hook_walker *prev;                /* nesting chain */
    int                      count;               /* entries[0..count-1] valid */
    int                      hook_id;             /* WH_* */
    nspa_hook_entry_t        entries[NSPA_HOOK_CHAIN_CAP];
    /* Per-entry copy of the module name from bypass->nspa_hook_module_pool.
     * Copied during the seqlock-stable snapshot so subsequent server-side
     * rebuilds can't pull the bytes out from under us. */
    WCHAR                    modules[NSPA_HOOK_CHAIN_CAP][MAX_PATH];
    unsigned int             module_lengths[NSPA_HOOK_CHAIN_CAP]; /* WCHARs, no NUL */
};

static __thread struct nspa_hook_walker *nspa_hook_walker_current;

/* Try to populate `walker` from the cache.  Returns count of matching
 * entries (>=0) on success, or -1 on overflow / retry exhaustion /
 * bypass shm unavailable / module copy out of range.  Caller falls back
 * to RPC on -1; on >=0 result, walker is populated and call sites must
 * push it onto nspa_hook_walker_current before dispatching. */
static int nspa_hook_try_read_cache( struct nspa_hook_walker *walker, int hook_id, int event )
{
    nspa_queue_bypass_shm_t *bypass;
    nspa_hook_chain_t *chain;
    unsigned int my_pid;
    unsigned int my_tid;
    int idx;
    int retry;

    bypass = (nspa_queue_bypass_shm_t *)nspa_get_own_bypass_shm_public();
    if (!bypass) return -1;

    idx = hook_id - WH_MINHOOK;
    if (idx < 0 || idx >= NB_HOOKS) return -1;

    chain = (nspa_hook_chain_t *)&bypass->nspa_hook_chains[idx];
    my_pid = HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess );
    my_tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );

    for (retry = 0; retry < 8; retry++)
    {
        unsigned int v1, v2;
        unsigned int cnt;
        unsigned int over;
        nspa_hook_entry_t local[NSPA_HOOK_CHAIN_CAP];
        WCHAR local_modules[NSPA_HOOK_CHAIN_CAP][MAX_PATH];
        unsigned int local_modlen[NSPA_HOOK_CHAIN_CAP];
        unsigned int i;
        int copy_failed = 0;

        v1 = __atomic_load_n( &chain->version, __ATOMIC_ACQUIRE );
        if (v1 & 1) { __builtin_ia32_pause(); sched_yield(); continue; }

        cnt  = chain->count;
        over = chain->overflowed;
        if (over) return -1;
        if (cnt > NSPA_HOOK_CHAIN_CAP) return -1;

        for (i = 0; i < cnt; i++)
        {
            unsigned int mlen;
            local[i] = chain->entries[i];
            mlen = local[i].module_size;
            if (mlen >= MAX_PATH) { copy_failed = 1; break; }
            local_modlen[i] = mlen;
            if (mlen)
            {
                unsigned int off = local[i].module_offset;
                if (off == 0 || off + mlen * sizeof(WCHAR) > NSPA_HOOK_MODULE_POOL)
                {
                    copy_failed = 1; break;
                }
                memcpy( local_modules[i],
                        (const void *)&bypass->nspa_hook_module_pool[off],
                        mlen * sizeof(WCHAR) );
            }
            local_modules[i][mlen] = 0;
        }

        v2 = __atomic_load_n( &chain->version, __ATOMIC_ACQUIRE );
        if (v1 != v2 || (v2 & 1)) { __builtin_ia32_pause(); sched_yield(); continue; }
        if (copy_failed) return -1;

        /* Stable snapshot — apply filter, copy survivors to walker. */
        {
            int out = 0;
            for (i = 0; i < cnt; i++)
            {
                if (!nspa_hook_match_thread( local[i].pid, local[i].tid, local[i].flags,
                                             my_pid, my_tid )) continue;
                if (!nspa_hook_match_event( event, local[i].event_min, local[i].event_max )) continue;
                walker->entries[out] = local[i];
                memcpy( walker->modules[out], local_modules[i],
                        (local_modlen[i] + 1) * sizeof(WCHAR) );
                walker->module_lengths[out] = local_modlen[i];
                out++;
            }
            walker->count   = out;
            walker->hook_id = hook_id;
            walker->prev    = NULL;  /* caller chains */
            return out;
        }
    }
    /* retry exhausted — likely server churn; fall back to RPC. */
    return -1;
}

/* Find the entry index whose handle matches.  Returns -1 if not present
 * (caller falls back to RPC for this CallNextHookEx). */
static int nspa_hook_walker_find( const struct nspa_hook_walker *walker, user_handle_t handle )
{
    int i;
    for (i = 0; i < walker->count; i++)
        if (walker->entries[i].handle == handle) return i;
    return -1;
}

/* Populate a win_hook_params struct from a Tier 2 cache entry.  module
 * is copied into `module_out` (caller-supplied buffer of MAX_PATH).
 *
 * Note on info->tid: the cache entry's e->tid is the bound thread (used
 * by the run-in-thread filter we already passed).  But struct
 * win_hook_params interprets a non-zero info->tid as "dispatch via
 * send_internal_message_timeout cross-thread", which is only valid for
 * low-level hooks (WH_MOUSE_LL / WH_KEYBOARD_LL).  Tier 2 only serves
 * hooks the cache could legitimately populate (low-level hooks are
 * forced global, and global hooks force overflowed=1), so dispatch is
 * always in-thread — info->tid must stay 0 to take call_hook's local
 * branch. */
static void nspa_hook_fill_info_from_entry( struct win_hook_params *info,
                                            const struct nspa_hook_walker *walker,
                                            int idx, WCHAR *module_out )
{
    const nspa_hook_entry_t *e = &walker->entries[idx];
    info->handle       = wine_server_ptr_handle( e->handle );
    info->id           = walker->hook_id;
    info->pid          = e->pid;
    info->tid          = 0;  /* in-thread dispatch only — see comment above */
    info->proc         = wine_server_get_ptr( e->proc );
    info->next_unicode = e->unicode;
    if (walker->module_lengths[idx])
        memcpy( module_out, walker->modules[idx],
                (walker->module_lengths[idx] + 1) * sizeof(WCHAR) );
    else
        module_out[0] = 0;
}

/***********************************************************************
 *           NtUserSetWindowsHookEx   (win32u.@)
 */
HHOOK WINAPI NtUserSetWindowsHookEx( HINSTANCE inst, UNICODE_STRING *module, DWORD tid, INT id,
                                     HOOKPROC proc, BOOL ansi )
{
    HHOOK handle = 0;

    if (!proc)
    {
        RtlSetLastWin32Error( ERROR_INVALID_FILTER_PROC );
        return 0;
    }

    if (tid)  /* thread-local hook */
    {
        if (id == WH_JOURNALRECORD ||
            id == WH_JOURNALPLAYBACK ||
            id == WH_KEYBOARD_LL ||
            id == WH_MOUSE_LL ||
            id == WH_SYSMSGFILTER)
        {
            /* these can only be global */
            RtlSetLastWin32Error( ERROR_GLOBAL_ONLY_HOOK );
            return 0;
        }
    }
    else  /* system-global hook */
    {
        if (id == WH_JOURNALRECORD || id == WH_JOURNALPLAYBACK)
        {
            RtlSetLastWin32Error( ERROR_ACCESS_DENIED );
            return 0;
        }
        if (id == WH_KEYBOARD_LL || id == WH_MOUSE_LL) inst = 0;
        else if (!inst)
        {
            RtlSetLastWin32Error( ERROR_HOOK_NEEDS_HMOD );
            return 0;
        }
    }

    SERVER_START_REQ( set_hook )
    {
        req->id        = id;
        req->pid       = 0;
        req->tid       = tid;
        req->event_min = EVENT_MIN;
        req->event_max = EVENT_MAX;
        req->flags     = WINEVENT_INCONTEXT;
        req->unicode   = !ansi;
        if (inst) /* make proc relative to the module base */
        {
            req->proc = wine_server_client_ptr( (void *)((char *)proc - (char *)inst) );
            wine_server_add_data( req, module->Buffer, module->Length );
        }
        else req->proc = wine_server_client_ptr( proc );

        if (!wine_server_call_err( req ))
        {
            handle = wine_server_ptr_handle( reply->handle );
        }
    }
    SERVER_END_REQ;

    TRACE( "%s %p %x -> %p\n", debugstr_hook_id(id), proc, tid, handle );
    return handle;
}

/***********************************************************************
 *	     NtUserUnhookWindowsHookEx   (win32u.@)
 */
BOOL WINAPI NtUserUnhookWindowsHookEx( HHOOK handle )
{
    NTSTATUS status;

    SERVER_START_REQ( remove_hook )
    {
        req->handle = wine_server_user_handle( handle );
        req->id     = 0;
        status = wine_server_call_err( req );
    }
    SERVER_END_REQ;
    if (status == STATUS_INVALID_HANDLE) RtlSetLastWin32Error( ERROR_INVALID_HOOK_HANDLE );
    return !status;
}

/***********************************************************************
 *	     NtUserUnhookWindowsHook   (win32u.@)
 */
BOOL WINAPI NtUserUnhookWindowsHook( INT id, HOOKPROC proc )
{
    NTSTATUS status;

    TRACE( "%s %p\n", debugstr_hook_id(id), proc );

    SERVER_START_REQ( remove_hook )
    {
        req->handle = 0;
        req->id   = id;
        req->proc = wine_server_client_ptr( proc );
        status = wine_server_call_err( req );
    }
    SERVER_END_REQ;
    if (status == STATUS_INVALID_HANDLE) RtlSetLastWin32Error( ERROR_INVALID_HOOK_HANDLE );
    return !status;
}

/***********************************************************************
 *           NtUserCallMsgFilter (win32u.@)
 */
BOOL WINAPI NtUserCallMsgFilter( MSG *msg, INT code )
{
    /* FIXME: We should use NtCallbackReturn instead of passing (potentially kernel) pointer
     * like that, but we need to consequently use syscall thunks first for that to work. */
    if (call_hooks( WH_SYSMSGFILTER, code, 0, (LPARAM)msg, sizeof(*msg) )) return TRUE;
    return call_hooks( WH_MSGFILTER, code, 0, (LPARAM)msg, sizeof(*msg) );
}

static UINT get_ll_hook_timeout(void)
{
    /* FIXME: should retrieve LowLevelHooksTimeout in HKEY_CURRENT_USER\Control Panel\Desktop */
    return 2000;
}

/***********************************************************************
 *	     call_hook
 *
 * Call hook either in current thread or send message to the destination
 * thread.
 */
static LRESULT call_hook( struct win_hook_params *info, const WCHAR *module, size_t lparam_size,
                          size_t message_size, BOOL ansi )
{
    DWORD_PTR ret = 0;

    if (info->tid)
    {
        struct hook_extra_info h_extra;
        h_extra.handle = info->handle;
        h_extra.lparam = info->lparam;

        TRACE( "calling hook in thread %04x %s code %x wp %lx lp %lx\n",
               info->tid, hook_names[info->id-WH_MINHOOK],
               info->code, (long)info->wparam, info->lparam );

        switch(info->id)
        {
        case WH_KEYBOARD_LL:
            send_internal_message_timeout( info->pid, info->tid, WM_WINE_KEYBOARD_LL_HOOK,
                                           info->wparam, (LPARAM)&h_extra, SMTO_ABORTIFHUNG,
                                           get_ll_hook_timeout(), &ret );
            break;
        case WH_MOUSE_LL:
            send_internal_message_timeout( info->pid, info->tid, WM_WINE_MOUSE_LL_HOOK,
                                           info->wparam, (LPARAM)&h_extra, SMTO_ABORTIFHUNG,
                                           get_ll_hook_timeout(), &ret );
            break;
        default:
            ERR("Unknown hook id %d\n", info->id);
            assert(0);
            break;
        }
    }
    else if (info->proc)
    {
        struct user_thread_info *thread_info = get_user_thread_info();
        size_t size, lparam_offset = 0, message_offset = 0;
        size_t lparam_ret_size = lparam_size;
        HHOOK prev = thread_info->hook;
        BOOL prev_unicode = thread_info->hook_unicode;
        struct win_hook_params *params = info;
        void *ret_ptr, *extra_buffer = NULL;
        SIZE_T extra_buffer_size = 0;
        size_t reply_size;
        ULONG ret_len;

        size = FIELD_OFFSET( struct win_hook_params, module[module ? lstrlenW( module ) + 1 : 1] );

        if (lparam_size)
        {
            if (params->id == WH_CBT && params->code == HCBT_CREATEWND)
            {
                CBT_CREATEWNDW *cbtc = (CBT_CREATEWNDW *)params->lparam;
                message_size = user_message_size( (HWND)params->wparam, WM_NCCREATE,
                                                  0, (LPARAM)cbtc->lpcs, TRUE, FALSE, &reply_size );
                lparam_size = lparam_ret_size = 0;
            }

            if (lparam_size)
            {
                lparam_offset = (size + 15) & ~15; /* align offset */
                size = lparam_offset + lparam_size;
            }

            if (message_size)
            {
                message_offset = (size + 15) & ~15; /* align offset */
                size = message_offset + message_size;
            }
        }

        if (size > sizeof(*info))
        {
            if (!(params = malloc( size ))) return 0;
            memcpy( params, info, FIELD_OFFSET( struct win_hook_params, module ));
        }
        if (module)
            wcscpy( params->module, module );
        else
            params->module[0] = 0;

        if (lparam_size)
            memcpy( (char *)params + lparam_offset, (const void *)params->lparam, lparam_size );

        if (message_size)
        {
            switch (params->id)
            {
            case WH_CBT:
                {
                    CBT_CREATEWNDW *cbtc = (CBT_CREATEWNDW *)params->lparam;
                    LPARAM lp = (LPARAM)cbtc->lpcs;
                    pack_user_message( (char *)params + message_offset, message_size,
                                       WM_CREATE, 0, lp, FALSE, &extra_buffer );
                }
                break;
            case WH_CALLWNDPROC:
                {
                    CWPSTRUCT *cwp = (CWPSTRUCT *)((char *)params + lparam_offset);
                    pack_user_message( (char *)params + message_offset, message_size,
                                       cwp->message, cwp->wParam, cwp->lParam, ansi, &extra_buffer );
                }
                break;
            case WH_CALLWNDPROCRET:
                {
                    CWPRETSTRUCT *cwpret = (CWPRETSTRUCT *)((char *)params + lparam_offset);
                    pack_user_message( (char *)params + message_offset, message_size,
                                       cwpret->message, cwpret->wParam, cwpret->lParam, ansi, &extra_buffer );
                }
                break;
            }
        }

        /*
         * Windows protects from stack overflow in recursive hook calls. Different Windows
         * allow different depths.
         */
        if (thread_info->hook_call_depth >= 25)
        {
            WARN("Too many hooks called recursively, skipping call.\n");
            if (params != info) free( params );
            if (extra_buffer)
                NtFreeVirtualMemory( GetCurrentProcess(), &extra_buffer, &extra_buffer_size, MEM_RELEASE );
            return 0;
        }

        TRACE( "calling hook %p %s code %x wp %lx lp %lx module %s\n",
               params->proc, hook_names[params->id-WH_MINHOOK], params->code, (long)params->wparam,
               params->lparam, debugstr_w(module) );

        thread_info->hook = params->handle;
        thread_info->hook_unicode = params->next_unicode;
        thread_info->hook_call_depth++;
        if (!KeUserModeCallback( NtUserCallWindowsHook, params, size, &ret_ptr, &ret_len ) &&
            ret_len >= sizeof(ret))
        {
            LRESULT *result_ptr = ret_ptr;
            ret = *result_ptr;
            if (ret_len == sizeof(ret) + lparam_ret_size)
                memcpy( (void *)params->lparam, result_ptr + 1, ret_len - sizeof(ret) );
        }
        thread_info->hook = prev;
        thread_info->hook_unicode = prev_unicode;
        thread_info->hook_call_depth--;

        if (params != info) free( params );
        if (extra_buffer)
            NtFreeVirtualMemory( GetCurrentProcess(), &extra_buffer, &extra_buffer_size, MEM_RELEASE );
    }

    return ret;
}

/***********************************************************************
 *	     NtUserCallNextHookEx (win32u.@)
 */
LRESULT WINAPI NtUserCallNextHookEx( HHOOK hhook, INT code, WPARAM wparam, LPARAM lparam )
{
    struct user_thread_info *thread_info = get_user_thread_info();
    struct nspa_hook_walker *walker = nspa_hook_walker_current;
    struct win_hook_params info;
    WCHAR module[MAX_PATH];

    memset( &info, 0, sizeof(info) );

    /* NSPA Tier 2: if we're inside a cache-served dispatch, advance
     * through the snapshot's entries[] without an RPC.  Identifies the
     * "current" entry by matching thread_info->hook (set by call_hook
     * before invoking the proc) against entries[].handle. */
    if (walker)
    {
        user_handle_t cur = wine_server_user_handle( thread_info->hook );
        int idx = nspa_hook_walker_find( walker, cur );
        if (idx >= 0)
        {
            if (idx + 1 >= walker->count) return 0;  /* end of chain */
            nspa_hook_fill_info_from_entry( &info, walker, idx + 1, module );
            info.code         = code;
            info.wparam       = wparam;
            info.lparam       = lparam;
            info.prev_unicode = thread_info->hook_unicode;
            return call_hook( &info, module, 0, 0, FALSE );
        }
        /* current handle isn't in this walker — likely a nested dispatch
         * from a non-Tier-2 path.  Fall through to RPC. */
    }

    SERVER_START_REQ( get_hook_info )
    {
        req->handle = wine_server_user_handle( thread_info->hook );
        req->get_next = 1;
        req->event = EVENT_MIN;
        wine_server_set_reply( req, module, sizeof(module) - sizeof(WCHAR) );
        if (!wine_server_call_err( req ))
        {
            module[wine_server_reply_size(req) / sizeof(WCHAR)] = 0;
            info.handle       = wine_server_ptr_handle( reply->handle );
            info.id           = reply->id;
            info.pid          = reply->pid;
            info.tid          = reply->tid;
            info.proc         = wine_server_get_ptr( reply->proc );
            info.next_unicode = reply->unicode;
        }
    }
    SERVER_END_REQ;

    info.code   = code;
    info.wparam = wparam;
    info.lparam = lparam;
    info.prev_unicode = thread_info->hook_unicode;
    return call_hook( &info, module, 0, 0, FALSE );
}

LRESULT call_current_hook( HHOOK hhook, INT code, WPARAM wparam, LPARAM lparam )
{
    struct win_hook_params info;
    WCHAR module[MAX_PATH];

    memset( &info, 0, sizeof(info) );

    SERVER_START_REQ( get_hook_info )
    {
        req->handle = wine_server_user_handle( hhook );
        req->get_next = 0;
        req->event = EVENT_MIN;
        wine_server_set_reply( req, module, sizeof(module) );
        if (!wine_server_call_err( req ))
        {
            module[wine_server_reply_size(req) / sizeof(WCHAR)] = 0;
            info.handle       = wine_server_ptr_handle( reply->handle );
            info.id           = reply->id;
            info.pid          = reply->pid;
            info.tid          = reply->tid;
            info.proc         = wine_server_get_ptr( reply->proc );
            info.next_unicode = reply->unicode;
        }
    }
    SERVER_END_REQ;

    info.code   = code;
    info.wparam = wparam;
    info.lparam = lparam;
    info.prev_unicode = TRUE;  /* assume Unicode for this function */
    return call_hook( &info, module, 0, 0, FALSE );
}

LRESULT call_message_hooks( INT id, INT code, WPARAM wparam, LPARAM lparam, size_t lparam_size,
                            size_t message_size, BOOL ansi )
{
    struct win_hook_params info;
    WCHAR module[MAX_PATH];
    DWORD_PTR ret = 0;
    int idx = id - WH_MINHOOK;
    int has_global = 0;
    int tier1_active = 0;
    nspa_queue_bypass_shm_t *bypass = NULL;

    user_check_not_lock();

    if (!is_hooked( id ))
    {
        TRACE( "skipping hook %s\n", hook_names[id - WH_MINHOOK] );
        return 0;
    }

    memset( &info, 0, sizeof(info) );
    info.prev_unicode = TRUE;
    info.id = id;

    /* NSPA Tier 1: pin the queue-local chain against deferred-free via
     * the memfd-backed bypass shm BEFORE sending start_hook_chain.  Must
     * happen pre-RPC: a remove_hook arriving at the server from another
     * thread before our start_hook_chain is processed needs to see count>0.
     * The atomic store is published before the RPC's send(2), which is a
     * global fence.  If bypass shm isn't mapped yet (bootstrap failed or
     * msg-bypass off), fall back to the legacy path — server matches by
     * setting reply->tier1_active=0 for this queue. */
    if (idx >= 0 && idx < NB_HOOKS)
        bypass = (nspa_queue_bypass_shm_t *)nspa_get_own_bypass_shm_public();
    if (bypass)
        __atomic_fetch_add( &bypass->nspa_hook_walk_counts[idx], 1, __ATOMIC_ACQ_REL );

    /* NSPA Tier 2: try the seqlock-stable shmem cache first.  On success
     * we dispatch the chain entirely client-side (no start/get/finish
     * RPCs).  On overflow / retry exhaustion / bypass not mapped, fall
     * through to the legacy RPC path. */
    if (bypass)
    {
        struct nspa_hook_walker walker;
        int n = nspa_hook_try_read_cache( &walker, id, EVENT_MIN );
        if (n >= 0)
        {
            walker.prev = nspa_hook_walker_current;
            nspa_hook_walker_current = &walker;
            if (n > 0)
            {
                WCHAR mod[MAX_PATH];
                nspa_hook_fill_info_from_entry( &info, &walker, 0, mod );
                info.code         = code;
                info.wparam       = wparam;
                info.lparam       = lparam;
                /* prev_unicode comes from outer call_hook context; for the
                 * top-level dispatch it's TRUE (Unicode), set above. */
                ret = call_hook( &info, mod, lparam_size, message_size, ansi );
            }
            nspa_hook_walker_current = walker.prev;
            /* Tier 1 dec balances the inc above; no finish_hook_chain RPC. */
            __atomic_fetch_sub( &bypass->nspa_hook_walk_counts[idx], 1, __ATOMIC_ACQ_REL );
            return ret;
        }
    }

    SERVER_START_REQ( start_hook_chain )
    {
        req->id = info.id;
        req->event = EVENT_MIN;
        wine_server_set_reply( req, module, sizeof(module)-sizeof(WCHAR) );
        if (!wine_server_call( req ))
        {
            module[wine_server_reply_size(req) / sizeof(WCHAR)] = 0;
            info.handle       = wine_server_ptr_handle( reply->handle );
            info.pid          = reply->pid;
            info.tid          = reply->tid;
            info.proc         = wine_server_get_ptr( reply->proc );
            info.next_unicode = reply->unicode;
            has_global        = reply->has_global;
            tier1_active      = reply->tier1_active;
        }
    }
    SERVER_END_REQ;

    /* Walk the chain.  Same as before — just one hook at this level; any
     * CallNextHookEx the hook proc makes re-enters via get_hook_info. */
    if (info.tid || info.proc)
    {
        info.code   = code;
        info.wparam = wparam;
        info.lparam = lparam;
        ret = call_hook( &info, module, lparam_size, message_size, ansi );
    }

    /* Release the queue-local refcount we took pre-RPC.  Always runs when
     * the inc ran; the server's deferred-free sweep is triggered lazily
     * from the next set_hook/remove_hook/finish_hook_chain on this idx. */
    if (bypass)
        __atomic_fetch_sub( &bypass->nspa_hook_walk_counts[idx], 1, __ATOMIC_ACQ_REL );

    /* Send finish_hook_chain iff the server is still counting queue-local
     * via counts[] (tier1_active=0) OR a desktop-global chain was pinned.
     * In the tier1-queue-only common case, this RPC is eliminated. */
    if (!tier1_active || has_global)
    {
        SERVER_START_REQ( finish_hook_chain )
        {
            req->id = id;
            wine_server_call( req );
        }
        SERVER_END_REQ;
    }

    return ret;
}

LRESULT call_hooks( INT id, INT code, WPARAM wparam, LPARAM lparam, size_t lparam_size )
{
    return call_message_hooks( id, code, wparam, lparam, lparam_size, 0, FALSE );
}

/***********************************************************************
 *           NtUserSetWinEventHook   (win32u.@)
 */
HWINEVENTHOOK WINAPI NtUserSetWinEventHook( DWORD event_min, DWORD event_max, HMODULE inst,
                                            UNICODE_STRING *module, WINEVENTPROC proc,
                                            DWORD pid, DWORD tid, DWORD flags )
{
    HWINEVENTHOOK handle = 0;

    if ((flags & WINEVENT_INCONTEXT) && !inst)
    {
        RtlSetLastWin32Error(ERROR_HOOK_NEEDS_HMOD);
        return 0;
    }

    if (event_min > event_max)
    {
        RtlSetLastWin32Error(ERROR_INVALID_HOOK_FILTER);
        return 0;
    }

    /* FIXME: what if the tid or pid belongs to another process? */
    if (tid) inst = 0; /* thread-local hook */

    SERVER_START_REQ( set_hook )
    {
        req->id        = WH_WINEVENT;
        req->pid       = pid;
        req->tid       = tid;
        req->event_min = event_min;
        req->event_max = event_max;
        req->flags     = flags;
        req->unicode   = 1;
        if (inst) /* make proc relative to the module base */
        {
            req->proc = wine_server_client_ptr( (void *)((char *)proc - (char *)inst) );
            wine_server_add_data( req, module->Buffer, module->Length );
        }
        else req->proc = wine_server_client_ptr( proc );

        if (!wine_server_call_err( req ))
        {
            handle = wine_server_ptr_handle( reply->handle );
        }
    }
    SERVER_END_REQ;

    TRACE("-> %p\n", handle);
    return handle;
}

/***********************************************************************
 *           NtUserUnhookWinEvent   (win32u.@)
 */
BOOL WINAPI NtUserUnhookWinEvent( HWINEVENTHOOK handle )
{
    BOOL ret;

    SERVER_START_REQ( remove_hook )
    {
        req->handle = wine_server_user_handle( handle );
        req->id     = WH_WINEVENT;
        ret = !wine_server_call_err( req );
    }
    SERVER_END_REQ;
    return ret;
}

/***********************************************************************
 *           NtUserNotifyWinEvent   (win32u.@)
 */
void WINAPI NtUserNotifyWinEvent( DWORD event, HWND hwnd, LONG object_id, LONG child_id )
{
    struct win_event_hook_params info;
    void *ret_ptr;
    ULONG ret_len;
    BOOL ret;
    int has_next = 0;
    int has_global = 0;
    int tier1_active = 0;
    const int idx = WH_WINEVENT - WH_MINHOOK;
    nspa_queue_bypass_shm_t *bypass = NULL;

    TRACE( "%04x, %p, %d, %d\n", event, hwnd, object_id, child_id );

    user_check_not_lock();

    if (!hwnd)
    {
        RtlSetLastWin32Error( ERROR_INVALID_WINDOW_HANDLE );
        return;
    }

    if (!is_hooked( WH_WINEVENT ))
    {
        TRACE( "skipping hook\n" );
        return;
    }

    info.event     = event;
    info.hwnd      = hwnd;
    info.object_id = object_id;
    info.child_id  = child_id;
    info.tid       = GetCurrentThreadId();

    /* NSPA Tier 1: pin queue-local walk refcount in bypass shm before
     * start_hook_chain.  See call_message_hooks() for the rationale. */
    bypass = (nspa_queue_bypass_shm_t *)nspa_get_own_bypass_shm_public();
    if (bypass)
        __atomic_fetch_add( &bypass->nspa_hook_walk_counts[idx], 1, __ATOMIC_ACQ_REL );

    SERVER_START_REQ( start_hook_chain )
    {
        req->id        = WH_WINEVENT;
        req->event     = event;
        req->window    = wine_server_user_handle( hwnd );
        req->object_id = object_id;
        req->child_id  = child_id;
        wine_server_set_reply( req, info.module, sizeof(info.module) - sizeof(WCHAR) );
        ret = !wine_server_call( req ) && reply->proc;
        if (ret)
        {
            info.module[wine_server_reply_size(req) / sizeof(WCHAR)] = 0;
            info.handle  = wine_server_ptr_handle( reply->handle );
            info.proc    = wine_server_get_ptr( reply->proc );
            has_next     = reply->has_next;
        }
        /* has_global / tier1_active are valid whether or not a hook
         * matched (server may have pinned tables anyway via counts[] in
         * the !tier1 branch). */
        has_global   = reply->has_global;
        tier1_active = reply->tier1_active;
    }
    SERVER_END_REQ;

    if (ret) do
    {
        TRACE( "calling WH_WINEVENT hook %p event %x hwnd %p %x %x module %s\n",
               info.proc, event, hwnd, object_id, child_id, debugstr_w(info.module) );

        info.time = NtGetTickCount();
        KeUserModeCallback( NtUserCallWinEventHook, &info,
                            FIELD_OFFSET( struct win_event_hook_params, module[lstrlenW(info.module) + 1] ),
                            &ret_ptr, &ret_len );

        /* NSPA: skip the next-hook server RPC when start_hook_chain
         * already told us there isn't one.  Saves one RTT per
         * chain-length-1 invocation (the common case). */
        if (!has_next) break;

        SERVER_START_REQ( get_hook_info )
        {
            req->handle    = wine_server_user_handle( info.handle );
            req->get_next  = 1;
            req->event     = event;
            req->window    = wine_server_user_handle( hwnd );
            req->object_id = object_id;
            req->child_id  = child_id;
            wine_server_set_reply( req, info.module, sizeof(info.module) - sizeof(WCHAR) );
            ret = !wine_server_call( req ) && reply->proc;
            if (ret)
            {
                info.module[wine_server_reply_size(req) / sizeof(WCHAR)] = 0;
                info.handle = wine_server_ptr_handle( reply->handle );
                info.proc   = wine_server_get_ptr( reply->proc );
                /* get_hook_info doesn't carry has_next; treat each
                 * continuation as potentially chain-continuing and
                 * let the next iteration's server call tell us. */
            }
        }
        SERVER_END_REQ;
    }
    while (ret);

    /* Must balance the inc whether or not the walk actually started. */
    if (bypass)
        __atomic_fetch_sub( &bypass->nspa_hook_walk_counts[idx], 1, __ATOMIC_ACQ_REL );

    if (!tier1_active || has_global)
    {
        SERVER_START_REQ( finish_hook_chain )
        {
            req->id = WH_WINEVENT;
            wine_server_call( req );
        }
        SERVER_END_REQ;
    }
}
