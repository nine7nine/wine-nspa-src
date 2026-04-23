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
    UINT status;

    while ((status = get_shared_queue( &lock, &queue_shm )) == STATUS_PENDING)
        ret = queue_shm->hooks_count[id - WH_MINHOOK] > 0;

    if (status) return TRUE;
    return ret;
}

/* ---------------------------------------------------------------------
 * NSPA hook-chain diagnostic.
 *
 * Wineserver arbitrates hook chain iteration via 3 RTTs per dispatched
 * message that has hooks installed:
 *   start_hook_chain  - returns first chain entry (bumps refcount)
 *   get_hook_info     - returns next entry (CallNextHookEx)
 *   finish_hook_chain - releases refcount
 *
 * A bypass cache was attempted (2026-04-22) but found 0/26,899 hits on
 * Ableton because every hook there is module-bearing AND most have
 * tid != self, so a safe local bypass needs both module byte storage
 * AND a refcount-protection scheme to handle dispatch races.  Cache
 * code dropped; this diag stays as standalone measurement so any
 * future hook-bypass decision can be data-driven.
 *
 * Counters atomically incremented; dump every 5 s by a background
 * thread (resilient to SIGKILL) and on clean exit via atexit, gated by
 * NSPA_SEND_DIAG=1. */

static unsigned long long nspa_hook_top_calls;        /* every call_message_hooks invocation */
static unsigned long long nspa_hook_skipped_no_hooks; /* is_hooked() returned FALSE */
static unsigned long long nspa_hook_server_dispatch;  /* reached start_hook_chain RTT */
/* NSPA Tier 1 diag counters: track the client-shmem refcount path's actual
 * engagement vs fallback so we can verify the optimisation is taking effect
 * when NSPA_HOOK_TIER1 is on.  Matched pairs (inc==dec) confirm the ++/--
 * is balanced; skipped vs forced finish counts prove the RPC saving. */
static unsigned long long nspa_hook_tier1_shmem_inc;
static unsigned long long nspa_hook_tier1_shmem_dec;
static unsigned long long nspa_hook_tier1_finish_skipped;
static unsigned long long nspa_hook_tier1_finish_forced;
/* Category counters — sampled at server-dispatch time on the conditions
 * a future safe-bypass would care about.  Together they tell us, for
 * a given workload, how big the safely-bypassable subset would be:
 *   safe_subset = pid_self && (tid_zero || tid_self) && chain_len_1 */
static unsigned long long nspa_hook_cat_pid_self;
static unsigned long long nspa_hook_cat_pid_other;
static unsigned long long nspa_hook_cat_tid_zero;
static unsigned long long nspa_hook_cat_tid_self;
static unsigned long long nspa_hook_cat_tid_other;
static unsigned long long nspa_hook_cat_chain_len_1;
static unsigned long long nspa_hook_cat_chain_len_gt1;
static unsigned long long nspa_hook_cat_module_bearing;
static unsigned long long nspa_hook_cat_safe_subset;
static time_t nspa_hook_diag_start_epoch;

static void nspa_hook_diag_dump( void )
{
    char path[128];
    char tmp[128];
    FILE *f;
    time_t now;
    unsigned long long top    = __atomic_load_n( &nspa_hook_top_calls,         __ATOMIC_RELAXED );
    unsigned long long none   = __atomic_load_n( &nspa_hook_skipped_no_hooks,  __ATOMIC_RELAXED );
    unsigned long long disp   = __atomic_load_n( &nspa_hook_server_dispatch,   __ATOMIC_RELAXED );
    unsigned long long ps     = __atomic_load_n( &nspa_hook_cat_pid_self,      __ATOMIC_RELAXED );
    unsigned long long po     = __atomic_load_n( &nspa_hook_cat_pid_other,     __ATOMIC_RELAXED );
    unsigned long long tz     = __atomic_load_n( &nspa_hook_cat_tid_zero,      __ATOMIC_RELAXED );
    unsigned long long ts     = __atomic_load_n( &nspa_hook_cat_tid_self,      __ATOMIC_RELAXED );
    unsigned long long to     = __atomic_load_n( &nspa_hook_cat_tid_other,     __ATOMIC_RELAXED );
    unsigned long long c1     = __atomic_load_n( &nspa_hook_cat_chain_len_1,   __ATOMIC_RELAXED );
    unsigned long long cg     = __atomic_load_n( &nspa_hook_cat_chain_len_gt1, __ATOMIC_RELAXED );
    unsigned long long mb     = __atomic_load_n( &nspa_hook_cat_module_bearing,__ATOMIC_RELAXED );
    unsigned long long safe   = __atomic_load_n( &nspa_hook_cat_safe_subset,   __ATOMIC_RELAXED );

    if (!getenv("NSPA_SEND_DIAG")) return;
    snprintf(tmp,  sizeof(tmp),  "/tmp/nspa_hook_diag.%d.log.tmp", (int)getpid());
    snprintf(path, sizeof(path), "/tmp/nspa_hook_diag.%d.log",     (int)getpid());
    f = fopen(tmp, "w");
    if (!f) return;
    now = time( NULL );
    fprintf(f, "NSPA hook diagnostic  pid=%d  elapsed_s=%lld\n",
            (int)getpid(), (long long)(now - nspa_hook_diag_start_epoch));
    fprintf(f, "----\n");
    fprintf(f, "[call_message_hooks]\n");
    fprintf(f, "  top_calls              %llu\n", top);
    fprintf(f, "  skipped_no_hooks       %llu  (%.1f%%)\n", none,
            top ? 100.0 * (double)none / (double)top : 0.0);
    fprintf(f, "  server_dispatch        %llu\n", disp);
    fprintf(f, "\n[server-dispatch categories]  (each call into start_hook_chain)\n");
    fprintf(f, "  pid_self               %llu  (%.1f%%)\n", ps,
            disp ? 100.0 * (double)ps / (double)disp : 0.0);
    fprintf(f, "  pid_other              %llu\n", po);
    fprintf(f, "  tid_zero               %llu  (%.1f%%)\n", tz,
            disp ? 100.0 * (double)tz / (double)disp : 0.0);
    fprintf(f, "  tid_self               %llu  (%.1f%%)\n", ts,
            disp ? 100.0 * (double)ts / (double)disp : 0.0);
    fprintf(f, "  tid_other              %llu  (%.1f%%)\n", to,
            disp ? 100.0 * (double)to / (double)disp : 0.0);
    fprintf(f, "  chain_len_1            %llu  (%.1f%%)\n", c1,
            disp ? 100.0 * (double)c1 / (double)disp : 0.0);
    fprintf(f, "  chain_len_gt1          %llu\n", cg);
    fprintf(f, "  module_bearing         %llu  (%.1f%%)\n", mb,
            disp ? 100.0 * (double)mb / (double)disp : 0.0);
    fprintf(f, "  >>> SAFE_BYPASS_SUBSET %llu  (%.1f%% of dispatch, %.1f%% of top_calls)\n", safe,
            disp ? 100.0 * (double)safe / (double)disp : 0.0,
            top  ? 100.0 * (double)safe / (double)top  : 0.0);
    {
        unsigned long long t1inc  = __atomic_load_n( &nspa_hook_tier1_shmem_inc,       __ATOMIC_RELAXED );
        unsigned long long t1dec  = __atomic_load_n( &nspa_hook_tier1_shmem_dec,       __ATOMIC_RELAXED );
        unsigned long long t1skip = __atomic_load_n( &nspa_hook_tier1_finish_skipped,  __ATOMIC_RELAXED );
        unsigned long long t1keep = __atomic_load_n( &nspa_hook_tier1_finish_forced,   __ATOMIC_RELAXED );
        fprintf(f, "\n[Tier 1 refcount]\n");
        fprintf(f, "  shmem_inc              %llu\n", t1inc);
        fprintf(f, "  shmem_dec              %llu  (balanced: %s)\n",
                t1dec, (t1inc == t1dec) ? "yes" : "NO — refcount leak");
        fprintf(f, "  finish_skipped         %llu  (%.1f%% of forced+skipped)\n",
                t1skip, (t1skip + t1keep) ? 100.0 * (double)t1skip / (double)(t1skip + t1keep) : 0.0);
        fprintf(f, "  finish_forced          %llu  (global-path or tier1 inactive)\n", t1keep);
    }
    fclose(f);
    rename(tmp, path);
}

static void *nspa_hook_diag_thread_main( void *arg )
{
    (void)arg;
    for (;;)
    {
        struct timespec ts = { 5, 0 };
        nanosleep( &ts, NULL );
        nspa_hook_diag_dump();
    }
    return NULL;
}

static pthread_once_t nspa_hook_diag_start_once = PTHREAD_ONCE_INIT;

static void nspa_hook_diag_start_once_fn( void )
{
    pthread_t th;
    nspa_hook_diag_start_epoch = time( NULL );
    atexit( nspa_hook_diag_dump );
    if (pthread_create( &th, NULL, nspa_hook_diag_thread_main, NULL ) == 0)
        pthread_detach( th );
}

static void nspa_hook_diag_lazy_start( void )
{
    pthread_once( &nspa_hook_diag_start_once, nspa_hook_diag_start_once_fn );
}

/* Categorize a server-arbitrated hook dispatch on the conditions a
 * future safe-bypass would care about.  Counter-only — does not affect
 * dispatch behaviour.  Called immediately after start_hook_chain
 * returns successfully; chain_len comes from queue_shm at that point.
 *
 * "safe subset" means a dispatch where a local cache could legitimately
 * skip the start/finish RTTs without races: pid==self (proc lifetime
 * owned by us), tid in {0, self} (no concurrent unhook on another
 * thread of this process), single-entry chain (no get_hook_info
 * iteration), regardless of module-bearing (module bytes are cacheable
 * if we choose to add storage). */
static void nspa_hook_diag_categorize( const struct win_hook_params *info,
                                       int chain_len, unsigned int module_size )
{
    DWORD self_pid = HandleToULong( NtCurrentTeb()->ClientId.UniqueProcess );
    DWORD self_tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );
    BOOL pid_self  = (info->pid == self_pid);
    BOOL tid_zero  = (info->tid == 0);
    BOOL tid_self  = (info->tid == self_tid);
    BOOL len_1     = (chain_len == 1);

    __atomic_fetch_add( &nspa_hook_server_dispatch, 1, __ATOMIC_RELAXED );
    if (pid_self) __atomic_fetch_add( &nspa_hook_cat_pid_self,  1, __ATOMIC_RELAXED );
    else          __atomic_fetch_add( &nspa_hook_cat_pid_other, 1, __ATOMIC_RELAXED );
    if (tid_zero) __atomic_fetch_add( &nspa_hook_cat_tid_zero,  1, __ATOMIC_RELAXED );
    else if (tid_self) __atomic_fetch_add( &nspa_hook_cat_tid_self, 1, __ATOMIC_RELAXED );
    else          __atomic_fetch_add( &nspa_hook_cat_tid_other, 1, __ATOMIC_RELAXED );
    if (len_1)    __atomic_fetch_add( &nspa_hook_cat_chain_len_1,   1, __ATOMIC_RELAXED );
    else          __atomic_fetch_add( &nspa_hook_cat_chain_len_gt1, 1, __ATOMIC_RELAXED );
    if (module_size > 0) __atomic_fetch_add( &nspa_hook_cat_module_bearing, 1, __ATOMIC_RELAXED );
    if (pid_self && (tid_zero || tid_self) && len_1)
        __atomic_fetch_add( &nspa_hook_cat_safe_subset, 1, __ATOMIC_RELAXED );
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
    struct win_hook_params info;
    WCHAR module[MAX_PATH];

    memset( &info, 0, sizeof(info) );

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

    /* NSPA diag: register the dump path before the is_hooked() short-
     * circuit so the diagnostic file appears even when a process never
     * actually has hooks installed (otherwise the registration would be
     * starved and you couldn't tell "no hooks" from "diag broken"). */
    nspa_hook_diag_lazy_start();
    __atomic_fetch_add( &nspa_hook_top_calls, 1, __ATOMIC_RELAXED );

    if (!is_hooked( id ))
    {
        __atomic_fetch_add( &nspa_hook_skipped_no_hooks, 1, __ATOMIC_RELAXED );
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
    {
        __atomic_fetch_add( &bypass->nspa_hook_walk_counts[idx], 1, __ATOMIC_ACQ_REL );
        __atomic_fetch_add( &nspa_hook_tier1_shmem_inc, 1, __ATOMIC_RELAXED );
    }

    SERVER_START_REQ( start_hook_chain )
    {
        unsigned int module_size = 0;
        req->id = info.id;
        req->event = EVENT_MIN;
        wine_server_set_reply( req, module, sizeof(module)-sizeof(WCHAR) );
        if (!wine_server_call( req ))
        {
            module_size = (unsigned int)(wine_server_reply_size(req) / sizeof(WCHAR));
            module[module_size] = 0;
            info.handle       = wine_server_ptr_handle( reply->handle );
            info.pid          = reply->pid;
            info.tid          = reply->tid;
            info.proc         = wine_server_get_ptr( reply->proc );
            info.next_unicode = reply->unicode;
            has_global        = reply->has_global;
            tier1_active      = reply->tier1_active;
            /* NSPA diag: read chain length from shmem to categorize this
             * dispatch on the conditions a future safe-bypass cares about. */
            if (idx >= 0 && idx < NB_HOOKS)
            {
                struct object_lock lock = OBJECT_LOCK_INIT;
                const queue_shm_t *queue_shm;
                int chain_len = 0;
                UINT status;
                while ((status = get_shared_queue( &lock, &queue_shm )) == STATUS_PENDING)
                    chain_len = queue_shm->hooks_count[idx];
                if (!status)
                    nspa_hook_diag_categorize( &info, chain_len, module_size );
            }
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
    {
        __atomic_fetch_sub( &bypass->nspa_hook_walk_counts[idx], 1, __ATOMIC_ACQ_REL );
        __atomic_fetch_add( &nspa_hook_tier1_shmem_dec, 1, __ATOMIC_RELAXED );
    }

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
        __atomic_fetch_add( &nspa_hook_tier1_finish_forced, 1, __ATOMIC_RELAXED );
    }
    else __atomic_fetch_add( &nspa_hook_tier1_finish_skipped, 1, __ATOMIC_RELAXED );

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
    {
        __atomic_fetch_add( &bypass->nspa_hook_walk_counts[idx], 1, __ATOMIC_ACQ_REL );
        __atomic_fetch_add( &nspa_hook_tier1_shmem_inc, 1, __ATOMIC_RELAXED );
    }

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
    {
        __atomic_fetch_sub( &bypass->nspa_hook_walk_counts[idx], 1, __ATOMIC_ACQ_REL );
        __atomic_fetch_add( &nspa_hook_tier1_shmem_dec, 1, __ATOMIC_RELAXED );
    }

    if (!tier1_active || has_global)
    {
        SERVER_START_REQ( finish_hook_chain )
        {
            req->id = WH_WINEVENT;
            wine_server_call( req );
        }
        SERVER_END_REQ;
        __atomic_fetch_add( &nspa_hook_tier1_finish_forced, 1, __ATOMIC_RELAXED );
    }
    else __atomic_fetch_add( &nspa_hook_tier1_finish_skipped, 1, __ATOMIC_RELAXED );
}
