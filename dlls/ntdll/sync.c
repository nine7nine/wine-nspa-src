/*
 *	Process synchronisation
 *
 * Copyright 1996, 1997, 1998 Marcus Meissner
 * Copyright 1997, 1998, 1999 Alexandre Julliard
 * Copyright 1999, 2000 Juergen Schmied
 * Copyright 2003 Eric Pouech
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

#include <limits.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"
#include "wine/list.h"
#include "wine/exception.h"
#include "ntdll_misc.h"

WINE_DEFAULT_DEBUG_CHANNEL(sync);
WINE_DECLARE_DEBUG_CHANNEL(relay);

static const char *debugstr_timeout( const LARGE_INTEGER *timeout )
{
    if (!timeout) return "(infinite)";
    return wine_dbgstr_longlong( timeout->QuadPart );
}

/******************************************************************
 *              RtlRunOnceInitialize (NTDLL.@)
 */
void WINAPI RtlRunOnceInitialize( RTL_RUN_ONCE *once )
{
    once->Ptr = NULL;
}

/******************************************************************
 *              RtlRunOnceBeginInitialize (NTDLL.@)
 */
DWORD WINAPI RtlRunOnceBeginInitialize( RTL_RUN_ONCE *once, ULONG flags, void **context )
{
    if (flags & RTL_RUN_ONCE_CHECK_ONLY)
    {
        ULONG_PTR val = (ULONG_PTR)ReadPointerAcquire( &once->Ptr );

        if (flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
        if ((val & 3) != 2) return STATUS_UNSUCCESSFUL;
        if (context) *context = (void *)(val & ~3);
        return STATUS_SUCCESS;
    }

    for (;;)
    {
        ULONG_PTR next, val = (ULONG_PTR)ReadPointerAcquire( &once->Ptr );

        switch (val & 3)
        {
        case 0:  /* first time */
            if (!InterlockedCompareExchangePointer( &once->Ptr,
                                                    (flags & RTL_RUN_ONCE_ASYNC) ? (void *)3 : (void *)1, 0 ))
                return STATUS_PENDING;
            break;

        case 1:  /* in progress, wait */
            if (flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
            next = val & ~3;
            if (InterlockedCompareExchangePointer( &once->Ptr, (void *)((ULONG_PTR)&next | 1),
                                                   (void *)val ) == (void *)val)
                NtWaitForKeyedEvent( 0, &next, FALSE, NULL );
            break;

        case 2:  /* done */
            if (context) *context = (void *)(val & ~3);
            return STATUS_SUCCESS;

        case 3:  /* in progress, async */
            if (!(flags & RTL_RUN_ONCE_ASYNC)) return STATUS_INVALID_PARAMETER;
            return STATUS_PENDING;
        }
    }
}

/******************************************************************
 *              RtlRunOnceComplete (NTDLL.@)
 */
DWORD WINAPI RtlRunOnceComplete( RTL_RUN_ONCE *once, ULONG flags, void *context )
{
    if ((ULONG_PTR)context & 3) return STATUS_INVALID_PARAMETER;

    if (flags & RTL_RUN_ONCE_INIT_FAILED)
    {
        if (context) return STATUS_INVALID_PARAMETER;
        if (flags & RTL_RUN_ONCE_ASYNC) return STATUS_INVALID_PARAMETER;
    }
    else context = (void *)((ULONG_PTR)context | 2);

    for (;;)
    {
        ULONG_PTR val = (ULONG_PTR)ReadPointerAcquire( &once->Ptr );

        switch (val & 3)
        {
        case 1:  /* in progress */
            if (InterlockedCompareExchangePointer( &once->Ptr, context, (void *)val ) != (void *)val) break;
            val &= ~3;
            while (val)
            {
                ULONG_PTR next = *(ULONG_PTR *)val;
                NtReleaseKeyedEvent( 0, (void *)val, FALSE, NULL );
                val = next;
            }
            return STATUS_SUCCESS;

        case 3:  /* in progress, async */
            if (!(flags & RTL_RUN_ONCE_ASYNC)) return STATUS_INVALID_PARAMETER;
            if (InterlockedCompareExchangePointer( &once->Ptr, context, (void *)val ) != (void *)val) break;
            return STATUS_SUCCESS;

        default:
            return STATUS_UNSUCCESSFUL;
        }
    }
}


/***********************************************************************
 * Critical sections
 ***********************************************************************/

/* ================================================================== *
 *                        NSPA RT v2.3 — CS-PI                         *
 * ================================================================== *
 *
 * Priority-inheritance fast/slow path for RTL_CRITICAL_SECTION, gated on
 * the NSPA_RT_PRIO env var (same gate as v1). When active:
 *
 *   - Fast path uses `crit->LockSemaphore` as a FUTEX_LOCK_PI-format word:
 *     low 30 bits = owner TID, bit 30 = FUTEX_OWNER_DIED, bit 31 =
 *     FUTEX_WAITERS. Uncontended acquire is a single atomic CAS of the
 *     current Linux TID into that word.
 *
 *   - Slow path (contended acquire) calls NtNspaLockCriticalSectionPI which
 *     invokes `futex(..., FUTEX_LOCK_PI_PRIVATE, ...)` on the unix side.
 *     Kernel rt_mutex PI chain boosts the holder until release. Transitive
 *     (handles nested blocks), race-free (kernel atomic), chain-safe.
 *
 *   - Release: owner CAS's futex back to 0. If the FUTEX_WAITERS bit was
 *     set, call NtNspaUnlockCriticalSectionPI to let the kernel hand off
 *     ownership to the highest-priority waiter.
 *
 *   - Kernel fallback: on first ENOSYS return from the syscall, nspa_cs_pi
 *     permanently disables and all CS ops fall through to the legacy
 *     keyed-event path. Graceful degradation for kernels without
 *     FUTEX_LOCK_PI (pre-2.6.18, extremely unlikely in 2026).
 *
 * When NSPA_RT_PRIO is unset: every CS function short-circuits to the
 * upstream legacy implementation — byte-identical behavior to upstream Wine.
 *
 * Design constraints:
 *   - GetCurrentThreadId() returns the Linux TID in Wine (verified in
 *     dlls/ntdll/unix/thread.c:1431 — teb->ClientId.UniqueThread is set to
 *     the kernel TID), so the FUTEX_LOCK_PI protocol works directly.
 *   - RTL_CRITICAL_SECTION layout is unchanged — LockSemaphore stays
 *     HANDLE-sized (PVOID). We just store a TID-in-word value there instead
 *     of a HANDLE when PI is active. Apps that `sizeof(RTL_CRITICAL_SECTION)`
 *     are unaffected; apps that introspect LockSemaphore expecting a HANDLE
 *     would see garbage (accepted — undocumented internal state).
 *   - LockCount is still maintained for external compat (apps that poll it)
 *     but is no longer the atomic-primary ownership word. OwningThread and
 *     RecursionCount are set consistently after each acquire/release.
 *
 * See memory/plan_wine_rt_v2.md section 4 for the full design rationale.
 */

/* FUTEX_WAITERS bit mirror of linux/futex.h — we need to test it from
 * PE-side code that can't include <linux/futex.h> directly. */
#define NSPA_CS_FUTEX_WAITERS  0x80000000U
#define NSPA_CS_FUTEX_TID_MASK 0x3fffffffU

/* Nt-level Unixlib entries implemented in dlls/ntdll/unix/sync.c */
ULONG    WINAPI NtNspaGetUnixTid(void);
NTSTATUS WINAPI NtNspaLockCriticalSectionPI( void *address );
NTSTATUS WINAPI NtNspaUnlockCriticalSectionPI( void *address );
NTSTATUS WINAPI NtNspaCondWaitPI( void *condvar_futex, LONG condvar_val,
                                   void *pi_mutex, const LARGE_INTEGER *timeout );
NTSTATUS WINAPI NtNspaCondSignalPI( void *condvar_futex, void *pi_mutex );
NTSTATUS WINAPI NtNspaCondBroadcastPI( void *condvar_futex, void *pi_mutex );

/* Get the Linux kernel TID for the calling thread.
 *
 * GetCurrentThreadId() returns the Win32 thread ID from
 * TEB->ClientId.UniqueThread — that's a wineserver-assigned Windows-style
 * ID, UNRELATED to the kernel TID. FUTEX_LOCK_PI validates the owner
 * against /proc/<tid>; using the Win32 TID returns ESRCH and hangs every
 * contended acquire.
 *
 * Fast path (zero syscall): read the cached DWORD from TEB->GdiTebBatch
 * at offset NSPA_UNIX_TID_OFFSET. That offset corresponds to the
 * `nspa_unix_tid` field inside `struct ntdll_thread_data` (defined in
 * dlls/ntdll/unix/unix_private.h — Unix-side only, but the memory is
 * shared between PE and Unix sides). The matching C_ASSERTs in
 * unix_private.h verify that the field is really at this offset; if the
 * struct layout ever changes, the build fails and the literal here must
 * be updated in sync.
 *
 * Slow path (first acquire per thread): the cached slot is 0, so we call
 * NtNspaGetUnixTid. The Unix-side implementation calls syscall(SYS_gettid)
 * and writes the result into the slot. Subsequent calls on this thread
 * hit the fast path with a pure memory read — no syscall dispatch, no
 * kernel transition.
 *
 * Cost on hot path: ~2 ns (one memory load + branch). vs ~5 ns for the
 * CS fast-path CAS itself, this is acceptable. vs the per-call syscall
 * version (~200-500 ns), this is ~100x faster on the steady state.
 */
#ifdef _WIN64
# define NSPA_UNIX_TID_OFFSET 0xf8
#else
# define NSPA_UNIX_TID_OFFSET 0x88
#endif

static inline DWORD nspa_get_unix_tid(void)
{
    DWORD tid = *(volatile DWORD *)((char *)&NtCurrentTeb()->GdiTebBatch + NSPA_UNIX_TID_OFFSET);
    if (tid) return tid;
    /* First acquire on this thread — populate the slot via syscall. */
    return NtNspaGetUnixTid();
}

/* Forward decls for file-scope static helpers defined below. */
static BOOL crit_section_has_debuginfo( const RTL_CRITICAL_SECTION *crit );
static const char *crit_section_get_name( const RTL_CRITICAL_SECTION *crit );

/* 0 = uninitialized, 1 = enabled, -1 = disabled (env var unset or kernel
 * returned ENOSYS on first FUTEX_LOCK_PI attempt). Lazily initialized on
 * first CS op.
 *
 * IMPORTANT — why not RtlQueryEnvironmentVariable_U:
 *
 * The obvious implementation is to call RtlQueryEnvironmentVariable_U from
 * this function. That does NOT work because RtlQueryEnvironmentVariable_U
 * internally takes CSes (the PEB lock and/or process heap lock), which
 * re-enters RtlEnterCriticalSection, which re-enters nspa_cs_pi_active,
 * which re-enters RtlQueryEnvironmentVariable_U, and so on — stack overflow
 * during very early Wine startup. Observed as err:virtual:virtual_setup_exception
 * on every PE binary launch with CS-PI built in, even with a CAS-based
 * recursion guard (still crashes with access violation deeper in the Rtl
 * call chain).
 *
 * Solution: scan the PEB's environment block directly. The env block is a
 * null-separated list of L"VAR=value\0...VAR=value\0\0" strings pointed to
 * by NtCurrentTeb()->Peb->ProcessParameters->Environment. Reading it is a
 * pure pointer dereference — no locks, no Rtl functions, no recursion risk.
 * This mirrors how the Windows loader reads its own env before kernel32 is
 * loaded.
 */
static LONG nspa_cs_pi_state;

static BOOL nspa_cs_pi_active(void)
{
    LONG state = nspa_cs_pi_state;
    LONG new_state;
    const WCHAR *env;
    PEB *peb;

    if (state) return state > 0;

    peb = NtCurrentTeb()->Peb;
    new_state = -1;

    if (peb && peb->ProcessParameters && (env = peb->ProcessParameters->Environment))
    {
        /* Target name: L"NSPA_RT_PRIO" (12 WCHARs, not counting terminator). */
        static const WCHAR target[] = { 'N','S','P','A','_','R','T','_','P','R','I','O' };
        const SIZE_T target_len = sizeof(target) / sizeof(target[0]);

        while (*env)
        {
            const WCHAR *p = env;
            SIZE_T i;

            /* Compare: env starts with "NSPA_RT_PRIO=" and the value is non-empty. */
            for (i = 0; i < target_len && p[i] == target[i]; i++) { }
            if (i == target_len && p[target_len] == '=' && p[target_len + 1] != 0)
            {
                new_state = 1;
                break;
            }

            /* Advance past this "VAR=value\0" to the next entry. */
            while (*env) env++;
            env++;
        }
    }

    /* Publish our decision. If another thread already won the race, use
     * whatever value they set. */
    InterlockedCompareExchange( &nspa_cs_pi_state, new_state, 0 );
    return nspa_cs_pi_state > 0;
}

/* Attempt uncontended acquire via CAS. Returns TRUE on success.
 * unix_tid is the Linux kernel TID — required by FUTEX_LOCK_PI. */
static inline BOOL nspa_cs_try_fast( RTL_CRITICAL_SECTION *crit, DWORD unix_tid )
{
    LONG *futex = (LONG *)&crit->LockSemaphore;
    return InterlockedCompareExchange( futex, (LONG)unix_tid, 0 ) == 0;
}

/* PI-path entry. Returns:
 *   STATUS_SUCCESS on acquire
 *   STATUS_RETRY   if PI is disabled post-hoc (kernel ENOSYS) — caller
 *                  should fall through to the legacy path
 *   other NTSTATUS on hard failure (raised via RtlRaiseStatus by caller)
 *
 * Two TIDs are tracked per-call:
 *   - win_tid  (GetCurrentThreadId)   — wineserver-assigned Win32 TID.
 *                                       Stored in OwningThread for external
 *                                       compat (apps and Rtl code that query
 *                                       RtlIsCriticalSectionLockedByThread).
 *   - unix_tid (nspa_get_unix_tid)    — Linux kernel TID from SYS_gettid.
 *                                       Stored in LockSemaphore as the futex
 *                                       word because FUTEX_LOCK_PI validates
 *                                       it against /proc/<tid>.
 */
static NTSTATUS nspa_cs_enter_pi( RTL_CRITICAL_SECTION *crit )
{
    DWORD win_tid  = GetCurrentThreadId();
    DWORD unix_tid = nspa_get_unix_tid();
    LONG *futex    = (LONG *)&crit->LockSemaphore;
    NTSTATUS status;

    /* Fast path: single CAS of our Linux TID into the futex word. */
    if (nspa_cs_try_fast( crit, unix_tid ))
    {
        InterlockedIncrement( &crit->LockCount );
        crit->OwningThread   = ULongToHandle( win_tid );
        crit->RecursionCount = 1;
        return STATUS_SUCCESS;
    }

    /* Recursive check via Win32 TID (matches what the legacy path and
     * external Rtl queries use). */
    if (crit->OwningThread == ULongToHandle( win_tid ))
    {
        crit->RecursionCount++;
        InterlockedIncrement( &crit->LockCount );
        return STATUS_SUCCESS;
    }

    /* Spin before syscall. */
    if (crit->SpinCount)
    {
        ULONG count;
        for (count = crit->SpinCount; count > 0; count--)
        {
            if (nspa_cs_try_fast( crit, unix_tid ))
            {
                InterlockedIncrement( &crit->LockCount );
                crit->OwningThread   = ULongToHandle( win_tid );
                crit->RecursionCount = 1;
                return STATUS_SUCCESS;
            }
            YieldProcessor();
        }
    }

    /* Slow path: hand the futex word to the kernel's rt_mutex PI chain.
     * The kernel boosts the current holder to our priority, runs it until
     * release, and transfers ownership to us. Returns once we hold it. */
    InterlockedIncrement( &crit->LockCount );  /* publish waiter count */
    status = NtNspaLockCriticalSectionPI( futex );

    if (status == STATUS_SUCCESS)
    {
        crit->OwningThread   = ULongToHandle( win_tid );
        crit->RecursionCount = 1;
        if (crit_section_has_debuginfo( crit )) crit->DebugInfo->ContentionCount++;
        return STATUS_SUCCESS;
    }

    /* Failure path: undo our waiter count bump and either fall back to
     * legacy (ENOSYS) or propagate the error. */
    InterlockedDecrement( &crit->LockCount );

    if (status == STATUS_NOT_SUPPORTED)
    {
        /* Kernel lacks FUTEX_LOCK_PI — disable CS-PI globally, forever. */
        InterlockedExchange( &nspa_cs_pi_state, -1 );
        return STATUS_RETRY;
    }

    return status;
}

/* PI try-enter. Returns:
 *   STATUS_SUCCESS on acquire
 *   STATUS_TIMEOUT if not acquired (non-blocking failure)
 *   STATUS_RETRY   if PI is disabled — caller should fall through
 */
static NTSTATUS nspa_cs_try_enter_pi( RTL_CRITICAL_SECTION *crit )
{
    DWORD win_tid  = GetCurrentThreadId();
    DWORD unix_tid = nspa_get_unix_tid();

    if (nspa_cs_try_fast( crit, unix_tid ))
    {
        InterlockedIncrement( &crit->LockCount );
        crit->OwningThread   = ULongToHandle( win_tid );
        crit->RecursionCount = 1;
        return STATUS_SUCCESS;
    }

    if (crit->OwningThread == ULongToHandle( win_tid ))
    {
        crit->RecursionCount++;
        InterlockedIncrement( &crit->LockCount );
        return STATUS_SUCCESS;
    }

    return STATUS_TIMEOUT;
}

/* PI release. Returns:
 *   STATUS_SUCCESS on successful release
 *   STATUS_RETRY   if PI is disabled — caller should fall through
 */
static NTSTATUS nspa_cs_leave_pi( RTL_CRITICAL_SECTION *crit )
{
    DWORD unix_tid = nspa_get_unix_tid();
    LONG *futex    = (LONG *)&crit->LockSemaphore;
    LONG old;

    /* Recursive release — not the final unlock. */
    if (crit->RecursionCount > 1)
    {
        crit->RecursionCount--;
        InterlockedDecrement( &crit->LockCount );
        return STATUS_SUCCESS;
    }

    if (crit->RecursionCount == 0)
    {
        ERR( "section %p %s is not acquired\n", crit, debugstr_a( crit_section_get_name( crit )));
        return STATUS_SUCCESS;
    }

    /* Final release. Clear bookkeeping first, then release the futex word. */
    crit->RecursionCount = 0;
    crit->OwningThread   = 0;

    /* Try uncontended release: atomically CAS our Linux TID → 0. */
    old = InterlockedCompareExchange( futex, 0, (LONG)unix_tid );
    InterlockedDecrement( &crit->LockCount );

    if (old == (LONG)unix_tid)
        return STATUS_SUCCESS;  /* uncontended — no waiters, done */

    /* FUTEX_WAITERS bit was set between our read and our CAS (or the kernel
     * set it because a PI waiter is blocked). Kernel hand-off required. */
    {
        NTSTATUS status = NtNspaUnlockCriticalSectionPI( futex );
        if (status == STATUS_SUCCESS) return STATUS_SUCCESS;
        if (status == STATUS_NOT_SUPPORTED)
        {
            /* Very unlikely — we managed to acquire via FUTEX_LOCK_PI but
             * now UNLOCK_PI says ENOSYS? Treat as fatal: futex word is
             * stuck, future acquires will hang. Disable PI for new CSes
             * and leak this one. */
            InterlockedExchange( &nspa_cs_pi_state, -1 );
            ERR( "NtNspaUnlockCriticalSectionPI returned NOT_SUPPORTED after successful LOCK_PI — kernel state inconsistent; leaking CS %p\n", crit );
            return STATUS_SUCCESS;
        }
        return status;
    }
}

/* ================================================================== *
 *                  End NSPA RT v2.3 CS-PI helpers                     *
 * ================================================================== */


/* ================================================================== *
 *           NSPA RT v3 — Win32 Condvar PI (requeue-PI)                *
 *                                                                     *
 *  RtlSleepConditionVariableCS with PI uses FUTEX_WAIT_REQUEUE_PI so  *
 *  that waiters are atomically requeued from the condvar futex onto    *
 *  the CS's PI mutex (LockSemaphore). This closes the priority        *
 *  inversion window between condvar wake and CS reacquire.            *
 *                                                                     *
 *  The signal side needs both the condvar address and the PI mutex     *
 *  address (Win32 WakeConditionVariable only takes the condvar), so   *
 *  we maintain a small mapping table set by waiters, read by signalers.*
 * ================================================================== */

#define CONDVAR_PI_MAP_SIZE 64
#define CONDVAR_PI_MAP_MASK (CONDVAR_PI_MAP_SIZE - 1)

/* Tombstone for deleted hash table entries. Probing continues past
 * tombstones but stops at NULL — this prevents open-addressing deletion
 * from breaking probe chains for colliding entries. */
#define CONDVAR_PI_TOMBSTONE ((const void *)(ULONG_PTR)~(ULONG_PTR)0)

struct condvar_pi_entry
{
    volatile const void *condvar_addr;   /* NULL=empty, TOMBSTONE=deleted, else=live */
    volatile LONG       *pi_mutex_addr;
    volatile LONG        refcount;
};

static struct condvar_pi_entry condvar_pi_map[CONDVAR_PI_MAP_SIZE];
static LONG condvar_pi_map_lock;

static inline void condvar_pi_lock( LONG *lock )
{
    while (InterlockedCompareExchange( lock, 1, 0 ))
        YieldProcessor();
}

static inline void condvar_pi_unlock( LONG *lock )
{
    InterlockedExchange( lock, 0 );
}

static inline ULONG condvar_pi_hash( const void *addr )
{
    return (ULONG)((ULONG_PTR)addr >> 4) & CONDVAR_PI_MAP_MASK;
}

/* Register condvar→mutex mapping. Called by waiters before sleeping.
 * Multiple waiters on the same condvar share one entry (refcounted). */
static void condvar_pi_register( const void *condvar_addr, LONG *pi_mutex_addr )
{
    ULONG idx = condvar_pi_hash( condvar_addr );
    ULONG first_reusable = CONDVAR_PI_MAP_SIZE;  /* sentinel: no reusable slot found */
    ULONG i;

    condvar_pi_lock( &condvar_pi_map_lock );
    for (i = 0; i < CONDVAR_PI_MAP_SIZE; i++)
    {
        ULONG slot = (idx + i) & CONDVAR_PI_MAP_MASK;
        const volatile void *addr = condvar_pi_map[slot].condvar_addr;

        if (addr == condvar_addr)
        {
            /* Existing entry for this condvar — bump refcount */
            condvar_pi_map[slot].refcount++;
            condvar_pi_unlock( &condvar_pi_map_lock );
            return;
        }
        if (!addr)
        {
            /* End of probe chain — insert here (or in earlier tombstone) */
            break;
        }
        if (addr == CONDVAR_PI_TOMBSTONE && first_reusable == CONDVAR_PI_MAP_SIZE)
            first_reusable = slot;
    }
    /* Use first available slot: prefer a tombstone earlier in the chain,
     * otherwise use the empty slot at position i. */
    {
        ULONG insert = (first_reusable < CONDVAR_PI_MAP_SIZE)
                        ? first_reusable : ((idx + i) & CONDVAR_PI_MAP_MASK);
        condvar_pi_map[insert].condvar_addr  = condvar_addr;
        condvar_pi_map[insert].pi_mutex_addr = pi_mutex_addr;
        condvar_pi_map[insert].refcount      = 1;
    }
    condvar_pi_unlock( &condvar_pi_map_lock );
}

/* Deregister condvar→mutex mapping. Called by waiters on wake/timeout.
 * Only tombstones the entry when the last waiter deregisters. */
static void condvar_pi_deregister( const void *condvar_addr )
{
    ULONG idx = condvar_pi_hash( condvar_addr );
    ULONG i;

    condvar_pi_lock( &condvar_pi_map_lock );
    for (i = 0; i < CONDVAR_PI_MAP_SIZE; i++)
    {
        ULONG slot = (idx + i) & CONDVAR_PI_MAP_MASK;
        const volatile void *addr = condvar_pi_map[slot].condvar_addr;

        if (addr == condvar_addr)
        {
            if (--condvar_pi_map[slot].refcount == 0)
            {
                condvar_pi_map[slot].condvar_addr  = CONDVAR_PI_TOMBSTONE;
                condvar_pi_map[slot].pi_mutex_addr = NULL;
            }
            break;
        }
        if (!addr) break;  /* end of chain — not found (shouldn't happen) */
        /* skip tombstones — continue probing */
    }
    condvar_pi_unlock( &condvar_pi_map_lock );
}

/* Look up the PI mutex for a condvar. Called by signalers. */
static LONG *condvar_pi_lookup( const void *condvar_addr )
{
    ULONG idx = condvar_pi_hash( condvar_addr );
    LONG *result = NULL;
    ULONG i;

    condvar_pi_lock( &condvar_pi_map_lock );
    for (i = 0; i < CONDVAR_PI_MAP_SIZE; i++)
    {
        ULONG slot = (idx + i) & CONDVAR_PI_MAP_MASK;
        const volatile void *addr = condvar_pi_map[slot].condvar_addr;

        if (addr == condvar_addr)
        {
            result = (LONG *)condvar_pi_map[slot].pi_mutex_addr;
            break;
        }
        if (!addr) break;  /* end of chain */
        /* skip tombstones — continue probing */
    }
    condvar_pi_unlock( &condvar_pi_map_lock );
    return result;
}

/* ================================================================== *
 *               End NSPA RT v3 Condvar PI helpers                     *
 * ================================================================== */


static void *no_debug_info_marker = (void *)(ULONG_PTR)-1;

static BOOL crit_section_has_debuginfo( const RTL_CRITICAL_SECTION *crit )
{
    return crit->DebugInfo != NULL && crit->DebugInfo != no_debug_info_marker;
}

static const char *crit_section_get_name( const RTL_CRITICAL_SECTION *crit )
{
    if (crit_section_has_debuginfo( crit ))
        return (char *)crit->DebugInfo->Spare[0];
    return "?";
}

static inline HANDLE get_semaphore( RTL_CRITICAL_SECTION *crit )
{
    if ((ULONG_PTR)crit->LockSemaphore > 1) return crit->LockSemaphore;
    return NULL;
}

static inline NTSTATUS wait_semaphore( RTL_CRITICAL_SECTION *crit, int timeout )
{
    LARGE_INTEGER time = {.QuadPart = timeout * (LONGLONG)-10000000};
    HANDLE sem = get_semaphore( crit );

    if (sem) return NtWaitForSingleObject( sem, FALSE, &time );
    else
    {
        LONG *lock = (LONG *)&crit->LockSemaphore;
        while (!InterlockedCompareExchange( lock, 0, 1 ))
        {
            static const LONG zero;
            /* this may wait longer than specified in case of multiple wake-ups */
            if (RtlWaitOnAddress( lock, &zero, sizeof(LONG), &time ) == STATUS_TIMEOUT)
                return STATUS_TIMEOUT;
        }
        return STATUS_WAIT_0;
    }
}

static ULONG crit_sect_default_flags(void)
{
    if (NtCurrentTeb()->Peb->OSMajorVersion > 6 ||
        (NtCurrentTeb()->Peb->OSMajorVersion == 6 && NtCurrentTeb()->Peb->OSMinorVersion >= 2)) return 0;
    return RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO;
}

/******************************************************************************
 *      RtlInitializeCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    return RtlInitializeCriticalSectionEx( crit, 0, crit_sect_default_flags() );
}


/******************************************************************************
 *      RtlInitializeCriticalSectionAndSpinCount   (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeCriticalSectionAndSpinCount( RTL_CRITICAL_SECTION *crit, ULONG spincount )
{
    return RtlInitializeCriticalSectionEx( crit, spincount, crit_sect_default_flags() );
}


/******************************************************************************
 *      RtlInitializeCriticalSectionEx   (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitializeCriticalSectionEx( RTL_CRITICAL_SECTION *crit, ULONG spincount, ULONG flags )
{
    if (flags & (RTL_CRITICAL_SECTION_FLAG_DYNAMIC_SPIN|RTL_CRITICAL_SECTION_FLAG_STATIC_INIT))
        FIXME("(%p,%lu,0x%08lx) semi-stub\n", crit, spincount, flags);

    /* FIXME: if RTL_CRITICAL_SECTION_FLAG_STATIC_INIT is given, we should use
     * memory from a static pool to hold the debug info. Then heap.c could pass
     * this flag rather than initialising the process heap CS by hand. If this
     * is done, then debug info should be managed through Rtlp[Allocate|Free]DebugInfo
     * so (e.g.) MakeCriticalSectionGlobal() doesn't free it using HeapFree().
     */
    if (!(flags & RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO))
        crit->DebugInfo = no_debug_info_marker;
    else
    {
        crit->DebugInfo = RtlAllocateHeap( GetProcessHeap(), 0, sizeof(RTL_CRITICAL_SECTION_DEBUG ));
        if (crit->DebugInfo)
        {
            crit->DebugInfo->Type = 0;
            crit->DebugInfo->CreatorBackTraceIndex = 0;
            crit->DebugInfo->CriticalSection = crit;
            crit->DebugInfo->ProcessLocksList.Blink = &crit->DebugInfo->ProcessLocksList;
            crit->DebugInfo->ProcessLocksList.Flink = &crit->DebugInfo->ProcessLocksList;
            crit->DebugInfo->EntryCount = 0;
            crit->DebugInfo->ContentionCount = 0;
            memset( crit->DebugInfo->Spare, 0, sizeof(crit->DebugInfo->Spare) );
        }
    }
    crit->LockCount      = -1;
    crit->RecursionCount = 0;
    crit->OwningThread   = 0;
    crit->LockSemaphore  = 0;
    if (NtCurrentTeb()->Peb->NumberOfProcessors <= 1) spincount = 0;
    crit->SpinCount = spincount & ~0x80000000;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlSetCriticalSectionSpinCount   (NTDLL.@)
 */
ULONG WINAPI RtlSetCriticalSectionSpinCount( RTL_CRITICAL_SECTION *crit, ULONG spincount )
{
    ULONG oldspincount = crit->SpinCount;
    if (NtCurrentTeb()->Peb->NumberOfProcessors <= 1) spincount = 0;
    crit->SpinCount = spincount;
    return oldspincount;
}


/******************************************************************************
 *      RtlDeleteCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlDeleteCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    HANDLE sem;
    BOOL pi_active = nspa_cs_pi_active();

    crit->LockCount      = -1;
    crit->RecursionCount = 0;
    crit->OwningThread   = 0;
    if (crit_section_has_debuginfo( crit ))
    {
        /* only free the ones we made in here */
        if (!crit->DebugInfo->Spare[0])
        {
            RtlFreeHeap( GetProcessHeap(), 0, crit->DebugInfo );
            crit->DebugInfo = NULL;
        }
    }
    else crit->DebugInfo = NULL;

    /* NSPA RT v2.3 — when CS-PI is active, LockSemaphore is a futex word
     * (TID in low 30 bits), NOT a HANDLE. Skip the get_semaphore/NtClose
     * path to avoid NtClose'ing a TID. */
    if (!pi_active && (sem = get_semaphore( crit ))) NtClose( sem );
    crit->LockSemaphore = 0;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlpWaitForCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlpWaitForCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    unsigned int timeout = 5;

    /* Don't allow blocking on a critical section during process termination */
    if (RtlDllShutdownInProgress())
    {
        WARN( "process %s is shutting down, returning STATUS_SUCCESS\n",
              debugstr_w(NtCurrentTeb()->Peb->ProcessParameters->ImagePathName.Buffer) );
        return STATUS_SUCCESS;
    }

    for (;;)
    {
        NTSTATUS status = wait_semaphore( crit, timeout );

        if (status == STATUS_WAIT_0) break;
        if (status != WAIT_TIMEOUT) return status;

        timeout = (TRACE_ON(relay) ? 300 : 60);

        ERR( "section %p %s wait timed out in thread %04lx, blocked by %04lx, retrying (%u sec)\n",
             crit, debugstr_a(crit_section_get_name(crit)), GetCurrentThreadId(), HandleToULong(crit->OwningThread), timeout );
    }
    if (crit_section_has_debuginfo( crit )) crit->DebugInfo->ContentionCount++;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlpUnWaitCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlpUnWaitCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    NTSTATUS ret;
    HANDLE sem = get_semaphore( crit );

    if (sem) ret = NtReleaseSemaphore( sem, 1, NULL );
    else
    {
        LONG *lock = (LONG *)&crit->LockSemaphore;
        InterlockedExchange( lock, 1 );
        RtlWakeAddressSingle( lock );
        ret = STATUS_SUCCESS;
    }
    if (ret) RtlRaiseStatus( ret );
    return ret;
}


/******************************************************************************
 *      RtlEnterCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlEnterCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    /* NSPA RT v2.3 — CS-PI path, gated on NSPA_RT_PRIO env var. */
    if (nspa_cs_pi_active())
    {
        NTSTATUS status = nspa_cs_enter_pi( crit );
        if (status == STATUS_SUCCESS) return STATUS_SUCCESS;
        if (status != STATUS_RETRY) RtlRaiseStatus( status );
        /* STATUS_RETRY = kernel lacks FUTEX_LOCK_PI, fall through to legacy. */
    }

    if (crit->SpinCount)
    {
        ULONG count;

        if (RtlTryEnterCriticalSection( crit )) return STATUS_SUCCESS;
        for (count = crit->SpinCount; count > 0; count--)
        {
            if (crit->LockCount > 0) break;  /* more than one waiter, don't bother spinning */
            if (crit->LockCount == -1)       /* try again */
            {
                if (InterlockedCompareExchange( &crit->LockCount, 0, -1 ) == -1) goto done;
            }
            YieldProcessor();
        }
    }

    if (InterlockedIncrement( &crit->LockCount ))
    {
        NTSTATUS status;

        if (crit->OwningThread == ULongToHandle(GetCurrentThreadId()))
        {
            crit->RecursionCount++;
            return STATUS_SUCCESS;
        }

        /* Now wait for it */
        if ((status = RtlpWaitForCriticalSection( crit ))) RtlRaiseStatus( status );
    }
done:
    crit->OwningThread   = ULongToHandle(GetCurrentThreadId());
    crit->RecursionCount = 1;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *      RtlTryEnterCriticalSection   (NTDLL.@)
 */
BOOL WINAPI RtlTryEnterCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    BOOL ret = FALSE;

    /* NSPA RT v2.3 — CS-PI path. */
    if (nspa_cs_pi_active())
    {
        NTSTATUS status = nspa_cs_try_enter_pi( crit );
        if (status == STATUS_SUCCESS) return TRUE;
        if (status == STATUS_TIMEOUT) return FALSE;
        /* STATUS_RETRY = fall through */
    }

    if (InterlockedCompareExchange( &crit->LockCount, 0, -1 ) == -1)
    {
        crit->OwningThread   = ULongToHandle(GetCurrentThreadId());
        crit->RecursionCount = 1;
        ret = TRUE;
    }
    else if (crit->OwningThread == ULongToHandle(GetCurrentThreadId()))
    {
        InterlockedIncrement( &crit->LockCount );
        crit->RecursionCount++;
        ret = TRUE;
    }
    return ret;
}


/******************************************************************************
 *      RtlIsCriticalSectionLocked   (NTDLL.@)
 */
BOOL WINAPI RtlIsCriticalSectionLocked( RTL_CRITICAL_SECTION *crit )
{
    return crit->RecursionCount != 0;
}


/******************************************************************************
 *      RtlIsCriticalSectionLockedByThread   (NTDLL.@)
 */
BOOL WINAPI RtlIsCriticalSectionLockedByThread( RTL_CRITICAL_SECTION *crit )
{
    return crit->OwningThread == ULongToHandle(GetCurrentThreadId()) &&
           crit->RecursionCount;
}


/******************************************************************************
 *      RtlLeaveCriticalSection   (NTDLL.@)
 */
NTSTATUS WINAPI RtlLeaveCriticalSection( RTL_CRITICAL_SECTION *crit )
{
    /* NSPA RT v2.3 — CS-PI release path. */
    if (nspa_cs_pi_active())
    {
        NTSTATUS status = nspa_cs_leave_pi( crit );
        if (status == STATUS_SUCCESS) return STATUS_SUCCESS;
        /* STATUS_RETRY = fall through to legacy (very unusual — would only
         * happen if pi_active became false between enter and leave, which
         * we do not currently support). */
    }

    if (--crit->RecursionCount)
    {
        if (crit->RecursionCount > 0) InterlockedDecrement( &crit->LockCount );
        else ERR( "section %p %s is not acquired\n", crit, debugstr_a( crit_section_get_name( crit )));
    }
    else
    {
        crit->OwningThread = 0;
        if (InterlockedDecrement( &crit->LockCount ) >= 0)
        {
            /* someone is waiting */
            RtlpUnWaitCriticalSection( crit );
        }
    }
    return STATUS_SUCCESS;
}

/******************************************************************
 *              RtlRunOnceExecuteOnce (NTDLL.@)
 */
DWORD WINAPI RtlRunOnceExecuteOnce( RTL_RUN_ONCE *once, PRTL_RUN_ONCE_INIT_FN func,
                                    void *param, void **context )
{
    DWORD ret = RtlRunOnceBeginInitialize( once, 0, context );

    if (ret != STATUS_PENDING) return ret;

    if (!func( once, param, context ))
    {
        RtlRunOnceComplete( once, RTL_RUN_ONCE_INIT_FAILED, NULL );
        return STATUS_UNSUCCESSFUL;
    }

    return RtlRunOnceComplete( once, 0, context ? *context : NULL );
}

struct srw_lock
{
    /* bit 0 - if the lock is held exclusive. bit 1.. - number of exclusive waiters. */
    short exclusive_waiters;

    /* Number of owners.
     *
     * Sadly Windows has no equivalent to FUTEX_WAIT_BITSET, so in order to wake
     * up *only* exclusive or *only* shared waiters (and thus avoid spurious
     * wakeups), we need to wait on two different addresses.
     * RtlAcquireSRWLockShared() needs to know the values of "exclusive_waiters"
     * and "owners", but RtlAcquireSRWLockExclusive() only needs to know the
     * value of "owners", so the former can wait on the entire structure, and
     * the latter waits only on the "owners" member. Note then that "owners"
     * must not be the first element in the structure.
     */
    unsigned short owners;
};
C_ASSERT( sizeof(struct srw_lock) == 4 );

/* NSPA: SRW lock spin phase.
 *
 * Windows SRW locks spin ~1024 iterations before parking via
 * NtWaitForAlertByThreadId. Wine currently does zero spinning —
 * every contended acquire is a syscall. This adds a bounded spin
 * phase matching Windows behavior.
 *
 * Spin count: 256 for normal threads. Windows uses ~1024 but our
 * futex indirection (RtlWaitOnAddress → alert → futex) is lighter
 * than Windows' kernel transition, so fewer spins suffice to catch
 * short critical sections.
 *
 * RT threads (NSPA_RT_PRIO active) skip spinning entirely. An RT
 * thread spinning at SCHED_FIFO priority starves the lock holder
 * (who may be at normal priority), making the lock slower to release.
 * Better to fall through to the futex wait immediately so the
 * scheduler can handle priority properly.
 *
 * Disabled on single-CPU systems (spinning is pointless — the holder
 * can't make progress while we're spinning on the same core).
 */
#define SRW_SPIN_COUNT 256

/***********************************************************************
 *              RtlInitializeSRWLock (NTDLL.@)
 *
 * NOTES
 *  Please note that SRWLocks do not keep track of the owner of a lock.
 *  It doesn't make any difference which thread for example unlocks an
 *  SRWLock (see corresponding tests). This implementation uses two
 *  keyed events (one for the exclusive waiters and one for the shared
 *  waiters) and is limited to 2^15-1 waiting threads.
 */
void WINAPI RtlInitializeSRWLock( RTL_SRWLOCK *lock )
{
    lock->Ptr = NULL;
}

/***********************************************************************
 *              RtlAcquireSRWLockExclusive (NTDLL.@)
 *
 * NOTES
 *  Unlike RtlAcquireResourceExclusive this function doesn't allow
 *  nested calls from the same thread. "Upgrading" a shared access lock
 *  to an exclusive access lock also doesn't seem to be supported.
 */
void WINAPI RtlAcquireSRWLockExclusive( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };

    InterlockedExchangeAdd16( &u.s->exclusive_waiters, 2 );

    for (;;)
    {
        union { struct srw_lock s; LONG l; } old, new;
        BOOL wait;

        do
        {
            old.s = *u.s;
            new.s = old.s;

            if (!old.s.owners)
            {
                /* Not locked exclusive or shared. We can try to grab it. */
                new.s.owners = 1;
                new.s.exclusive_waiters -= 2;
                new.s.exclusive_waiters |= 1;
                wait = FALSE;
            }
            else
            {
                wait = TRUE;
            }
        } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

        if (!wait) return;

        /* Spin before parking — avoids syscall for short-held locks.
         * Skip for RT threads (spinning at SCHED_FIFO starves the holder)
         * and single-CPU systems (holder can't progress while we spin). */
        if (NtCurrentTeb()->Peb->NumberOfProcessors > 1 && !nspa_cs_pi_active())
        {
            unsigned int i;

            for (i = 0; i < SRW_SPIN_COUNT; i++)
            {
                /* Re-read owners field; if it became 0, retry the CAS loop. */
                if (!*(volatile short *)&u.s->owners)
                    break;
                YieldProcessor();
            }
            /* If owners is now 0, go back to the CAS loop instead of parking. */
            if (!*(volatile short *)&u.s->owners)
                continue;
        }

        RtlWaitOnAddress( &u.s->owners, &new.s.owners, sizeof(short), NULL );
    }
}

/***********************************************************************
 *              RtlAcquireSRWLockShared (NTDLL.@)
 *
 * NOTES
 *   Do not call this function recursively - it will only succeed when
 *   there are no threads waiting for an exclusive lock!
 */
void WINAPI RtlAcquireSRWLockShared( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };

    for (;;)
    {
        union { struct srw_lock s; LONG l; } old, new;
        BOOL wait;

        do
        {
            old.s = *u.s;
            new = old;

            if (!old.s.exclusive_waiters)
            {
                /* Not locked exclusive, and no exclusive waiters.
                 * We can try to grab it. */
                ++new.s.owners;
                wait = FALSE;
            }
            else
            {
                wait = TRUE;
            }
        } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

        if (!wait) return;

        /* Spin before parking — avoids syscall for short-held locks.
         * Skip for RT threads (spinning at SCHED_FIFO starves the holder)
         * and single-CPU systems (holder can't progress while we spin). */
        if (NtCurrentTeb()->Peb->NumberOfProcessors > 1 && !nspa_cs_pi_active())
        {
            unsigned int i;

            for (i = 0; i < SRW_SPIN_COUNT; i++)
            {
                /* Re-read exclusive_waiters; if it became 0, retry the CAS loop. */
                if (!*(volatile short *)&u.s->exclusive_waiters)
                    break;
                YieldProcessor();
            }
            /* If exclusive_waiters is now 0, go back to the CAS loop. */
            if (!*(volatile short *)&u.s->exclusive_waiters)
                continue;
        }

        RtlWaitOnAddress( u.s, &new.s, sizeof(struct srw_lock), NULL );
    }
}

/***********************************************************************
 *              RtlReleaseSRWLockExclusive (NTDLL.@)
 */
void WINAPI RtlReleaseSRWLockExclusive( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;

    do
    {
        old.s = *u.s;
        new = old;

        if (!(old.s.exclusive_waiters & 1)) ERR("Lock %p is not owned exclusive!\n", lock);

        new.s.owners = 0;
        new.s.exclusive_waiters &= ~1;
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    if (new.s.exclusive_waiters)
        RtlWakeAddressSingle( &u.s->owners );
    else
        RtlWakeAddressAll( u.s );
}

/***********************************************************************
 *              RtlReleaseSRWLockShared (NTDLL.@)
 */
void WINAPI RtlReleaseSRWLockShared( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;

    do
    {
        old.s = *u.s;
        new = old;

        if (old.s.exclusive_waiters & 1) ERR("Lock %p is owned exclusive!\n", lock);
        else if (!old.s.owners) ERR("Lock %p is not owned shared!\n", lock);

        --new.s.owners;
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    if (!new.s.owners)
        RtlWakeAddressSingle( &u.s->owners );
}

/***********************************************************************
 *              RtlTryAcquireSRWLockExclusive (NTDLL.@)
 *
 * NOTES
 *  Similarly to AcquireSRWLockExclusive, recursive calls are not allowed
 *  and will fail with a FALSE return value.
 */
BOOLEAN WINAPI RtlTryAcquireSRWLockExclusive( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;
    BOOLEAN ret;

    do
    {
        old.s = *u.s;
        new.s = old.s;

        if (!old.s.owners)
        {
            /* Not locked exclusive or shared. We can try to grab it. */
            new.s.owners = 1;
            new.s.exclusive_waiters |= 1;
            ret = TRUE;
        }
        else
        {
            ret = FALSE;
        }
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    return ret;
}

/***********************************************************************
 *              RtlTryAcquireSRWLockShared (NTDLL.@)
 */
BOOLEAN WINAPI RtlTryAcquireSRWLockShared( RTL_SRWLOCK *lock )
{
    union { RTL_SRWLOCK *rtl; struct srw_lock *s; LONG *l; } u = { lock };
    union { struct srw_lock s; LONG l; } old, new;
    BOOLEAN ret;

    do
    {
        old.s = *u.s;
        new.s = old.s;

        if (!old.s.exclusive_waiters)
        {
            /* Not locked exclusive, and no exclusive waiters.
             * We can try to grab it. */
            ++new.s.owners;
            ret = TRUE;
        }
        else
        {
            ret = FALSE;
        }
    } while (InterlockedCompareExchange( u.l, new.l, old.l ) != old.l);

    return ret;
}

/***********************************************************************
 *           RtlInitializeConditionVariable   (NTDLL.@)
 *
 * Initializes the condition variable with NULL.
 *
 * PARAMS
 *  variable [O] condition variable
 *
 * RETURNS
 *  Nothing.
 */
void WINAPI RtlInitializeConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
    variable->Ptr = NULL;
}

/***********************************************************************
 *           RtlWakeConditionVariable   (NTDLL.@)
 *
 * Wakes up one thread waiting on the condition variable.
 *
 * PARAMS
 *  variable [I/O] condition variable to wake up.
 *
 * RETURNS
 *  Nothing.
 *
 * NOTES
 *  The calling thread does not have to own any lock in order to call
 *  this function.
 */
void WINAPI RtlWakeConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
    if (nspa_cs_pi_active())
    {
        LONG *pi_mutex = condvar_pi_lookup( variable );
        if (pi_mutex)
        {
            /* PI signal: unix side increments condvar + FUTEX_CMP_REQUEUE_PI */
            NTSTATUS status = NtNspaCondSignalPI( &variable->Ptr, pi_mutex );
            if (status == STATUS_SUCCESS)
                return;  /* woke a PI waiter — done */
            /* No PI waiters or error: condvar was already incremented by unix.
             * Wake one non-PI waiter if any exist. */
            RtlWakeAddressSingle( variable );
            return;
        }
    }
    InterlockedIncrement( (LONG *)&variable->Ptr );
    RtlWakeAddressSingle( variable );
}

/***********************************************************************
 *           RtlWakeAllConditionVariable   (NTDLL.@)
 *
 * See WakeConditionVariable, wakes up all waiting threads.
 */
void WINAPI RtlWakeAllConditionVariable( RTL_CONDITION_VARIABLE *variable )
{
    if (nspa_cs_pi_active())
    {
        LONG *pi_mutex = condvar_pi_lookup( variable );
        if (pi_mutex)
        {
            /* PI broadcast: unix side increments + requeues all PI waiters
             * onto PI mutex. Also wake any non-PI waiters via normal path. */
            NtNspaCondBroadcastPI( &variable->Ptr, pi_mutex );
            RtlWakeAddressAll( variable );
            return;
        }
    }
    InterlockedIncrement( (LONG *)&variable->Ptr );
    RtlWakeAddressAll( variable );
}

/***********************************************************************
 *           RtlSleepConditionVariableCS   (NTDLL.@)
 *
 * Atomically releases the critical section and suspends the thread,
 * waiting for a Wake(All)ConditionVariable event. Afterwards it enters
 * the critical section again and returns.
 *
 * PARAMS
 *  variable  [I/O] condition variable
 *  crit      [I/O] critical section to leave temporarily
 *  timeout   [I]   timeout
 *
 * RETURNS
 *  see NtWaitForKeyedEvent for all possible return values.
 */
NTSTATUS WINAPI RtlSleepConditionVariableCS( RTL_CONDITION_VARIABLE *variable, RTL_CRITICAL_SECTION *crit,
                                             const LARGE_INTEGER *timeout )
{
    /* PI path: FUTEX_WAIT_REQUEUE_PI closes the PI gap between condvar wake
     * and CS reacquire. Only used when CS-PI is active and we hold the CS
     * non-recursively (RecursionCount == 1). */
    if (nspa_cs_pi_active() && crit->RecursionCount == 1)
    {
        DWORD win_tid = GetCurrentThreadId();
        LONG *futex = (LONG *)&crit->LockSemaphore;
        int value = *(int *)&variable->Ptr;
        NTSTATUS status;

        /* Register condvar→mutex mapping so the signal side can discover
         * the PI mutex address (Win32 WakeConditionVariable only takes condvar). */
        condvar_pi_register( variable, futex );

        /* Release CS bookkeeping. The actual FUTEX_UNLOCK_PI happens on the
         * unix side, atomically before FUTEX_WAIT_REQUEUE_PI. */
        crit->RecursionCount = 0;
        crit->OwningThread   = 0;
        InterlockedDecrement( &crit->LockCount );

        status = NtNspaCondWaitPI( &variable->Ptr, (LONG)value, futex, timeout );

        /* On ANY return, the unix side ensured we own the PI mutex
         * (either via kernel requeue, manual FUTEX_LOCK_PI, or because
         * FUTEX_UNLOCK_PI never happened). Restore CS bookkeeping. */
        InterlockedIncrement( &crit->LockCount );
        crit->OwningThread   = ULongToHandle( win_tid );
        crit->RecursionCount = 1;
        condvar_pi_deregister( variable );

        if (status == STATUS_SUCCESS || status == STATUS_TIMEOUT)
            return status;

        /* Requeue-PI failed (STATUS_NOT_SUPPORTED, STATUS_UNSUCCESSFUL, etc.).
         * CS is owned and restored. Fall through to normal condvar wait
         * (PI leave/enter still works for FUTEX_LOCK_PI-based CSes). */
    }

    /* Normal (non-PI) path */
    {
        int value = *(int *)&variable->Ptr;
        NTSTATUS status;

        RtlLeaveCriticalSection( crit );
        status = RtlWaitOnAddress( &variable->Ptr, &value, sizeof(value), timeout );
        RtlEnterCriticalSection( crit );
        return status;
    }
}

/***********************************************************************
 *           RtlSleepConditionVariableSRW   (NTDLL.@)
 *
 * Atomically releases the SRWLock and suspends the thread,
 * waiting for a Wake(All)ConditionVariable event. Afterwards it enters
 * the SRWLock again with the same access rights and returns.
 *
 * PARAMS
 *  variable  [I/O] condition variable
 *  lock      [I/O] SRWLock to leave temporarily
 *  timeout   [I]   timeout
 *  flags     [I]   type of the current lock (exclusive / shared)
 *
 * RETURNS
 *  see NtWaitForKeyedEvent for all possible return values.
 *
 * NOTES
 *  the behaviour is undefined if the thread doesn't own the lock.
 */
NTSTATUS WINAPI RtlSleepConditionVariableSRW( RTL_CONDITION_VARIABLE *variable, RTL_SRWLOCK *lock,
                                              const LARGE_INTEGER *timeout, ULONG flags )
{
    int value = *(int *)&variable->Ptr;
    NTSTATUS status;

    if (flags & RTL_CONDITION_VARIABLE_LOCKMODE_SHARED)
        RtlReleaseSRWLockShared( lock );
    else
        RtlReleaseSRWLockExclusive( lock );

    status = RtlWaitOnAddress( &variable->Ptr, &value, sizeof(value), timeout );

    if (flags & RTL_CONDITION_VARIABLE_LOCKMODE_SHARED)
        RtlAcquireSRWLockShared( lock );
    else
        RtlAcquireSRWLockExclusive( lock );
    return status;
}

/* RtlWaitOnAddress() and RtlWakeAddress*(), hereafter referred to as "Win32
 * futexes", offer futex-like semantics with a variable set of address sizes,
 * but are limited to a single process. They are also fair—the documentation
 * specifies this, and tests bear it out.
 *
 * On Windows they are implemented using NtAlertThreadByThreadId and
 * NtWaitForAlertByThreadId, which manipulate a single flag (similar to an
 * auto-reset event) per thread. This can be tested by attempting to wake a
 * thread waiting in RtlWaitOnAddress() via NtAlertThreadByThreadId.
 */

struct futex_entry
{
    struct list entry;
    const void *addr;
    DWORD tid;
};

struct futex_queue
{
    struct list queue;
    LONG lock;
};

static struct futex_queue futex_queues[256];

static struct futex_queue *get_futex_queue( const void *addr )
{
    ULONG_PTR val = (ULONG_PTR)addr;

    return &futex_queues[(val >> 4) % ARRAY_SIZE(futex_queues)];
}

static void spin_lock( LONG *lock )
{
    while (InterlockedCompareExchange( lock, -1, 0 ))
        YieldProcessor();
}

static void spin_unlock( LONG *lock )
{
    InterlockedExchange( lock, 0 );
}

static BOOL compare_addr( const void *addr, const void *cmp, SIZE_T size )
{
    switch (size)
    {
        case 1:
            return (*(const UCHAR *)addr == *(const UCHAR *)cmp);
        case 2:
            return (*(const USHORT *)addr == *(const USHORT *)cmp);
        case 4:
            return (*(const ULONG *)addr == *(const ULONG *)cmp);
        case 8:
            return (*(const ULONG64 *)addr == *(const ULONG64 *)cmp);
    }

    return FALSE;
}

/***********************************************************************
 *           RtlWaitOnAddress   (NTDLL.@)
 */
NTSTATUS WINAPI RtlWaitOnAddress( const void *addr, const void *cmp, SIZE_T size,
                                  const LARGE_INTEGER *timeout )
{
    struct futex_queue *queue = get_futex_queue( addr );
    struct futex_entry entry;
    NTSTATUS ret;

    TRACE("addr %p cmp %p size %#Ix timeout %s\n", addr, cmp, size, debugstr_timeout( timeout ));

    if (size != 1 && size != 2 && size != 4 && size != 8)
        return STATUS_INVALID_PARAMETER;

    entry.addr = addr;
    entry.tid = GetCurrentThreadId();

    spin_lock( &queue->lock );

    /* Do the comparison inside of the spinlock, to reduce spurious wakeups. */

    if (!compare_addr( addr, cmp, size ))
    {
        spin_unlock( &queue->lock );
        return STATUS_SUCCESS;
    }

    if (!queue->queue.next)
        list_init( &queue->queue );
    list_add_tail( &queue->queue, &entry.entry );

    spin_unlock( &queue->lock );

    ret = NtWaitForAlertByThreadId( NULL, timeout );

    /* We may have already been removed by a call to RtlWakeAddressSingle() or RtlWakeAddressAll(). */
    if (entry.addr)
    {
        spin_lock( &queue->lock );
        if (entry.addr)
            list_remove( &entry.entry );
        spin_unlock( &queue->lock );
    }

    TRACE("returning %#lx\n", ret);

    if (ret == STATUS_ALERTED) ret = STATUS_SUCCESS;
    return ret;
}

/***********************************************************************
 *           RtlWakeAddressAll    (NTDLL.@)
 */
void WINAPI RtlWakeAddressAll( const void *addr )
{
    struct futex_queue *queue = get_futex_queue( addr );
    struct futex_entry *entry, *next;
    unsigned int count = 0;
    HANDLE tids[256];

    TRACE("%p\n", addr);

    if (!addr) return;

    spin_lock( &queue->lock );

    if (!queue->queue.next)
        list_init(&queue->queue);

    LIST_FOR_EACH_ENTRY_SAFE( entry, next, &queue->queue, struct futex_entry, entry )
    {
        if (entry->addr == addr)
        {
            entry->addr = NULL;
            list_remove( &entry->entry );
            if (count == ARRAY_SIZE(tids))
            {
                NtAlertMultipleThreadByThreadId( tids, count, NULL, NULL );
                count = 0;
            }
            tids[count++] = (HANDLE)(ULONG_PTR)entry->tid;
        }
    }

    /* Try not to make a system call while holding a spinlock (even if that can be responsible for spurious wake
     * up scenario). */
    spin_unlock( &queue->lock );
    if (count)
        NtAlertMultipleThreadByThreadId( tids, count, NULL, NULL );
}

/***********************************************************************
 *           RtlWakeAddressSingle (NTDLL.@)
 */
void WINAPI RtlWakeAddressSingle( const void *addr )
{
    struct futex_queue *queue = get_futex_queue( addr );
    struct futex_entry *entry;
    DWORD tid = 0;

    TRACE("%p\n", addr);

    if (!addr) return;

    spin_lock( &queue->lock );

    if (!queue->queue.next)
        list_init(&queue->queue);

    LIST_FOR_EACH_ENTRY( entry, &queue->queue, struct futex_entry, entry )
    {
        if (entry->addr == addr)
        {
            /* Try to buffer wakes, so that we don't make a system call while
             * holding a spinlock. */
            tid = entry->tid;

            /* Remove this entry from the queue, so that a simultaneous call to
             * RtlWakeAddressSingle() will not also wake it—two simultaneous
             * calls must wake at least two waiters if they exist. */
            entry->addr = NULL;
            list_remove( &entry->entry );
            break;
        }
    }

    spin_unlock( &queue->lock );

    if (tid) NtAlertThreadByThreadId( (HANDLE)(DWORD_PTR)tid );
}

/*************************************************************************
 *           RtlInitializeSListHead (NTDLL.@)
 */
void WINAPI RtlInitializeSListHead(PSLIST_HEADER list)
{
#ifdef _WIN64
    list->Alignment = list->Region = 0;
    list->Header16.HeaderType = 1;  /* we use the 16-byte header */
#else
    list->Alignment = 0;
#endif
}

/*************************************************************************
 *           RtlQueryDepthSList (NTDLL.@)
 */
WORD WINAPI RtlQueryDepthSList(PSLIST_HEADER list)
{
#ifdef _WIN64
    return list->Header16.Depth;
#else
    return list->Depth;
#endif
}

/*************************************************************************
 *           RtlFirstEntrySList (NTDLL.@)
 */
PSLIST_ENTRY WINAPI RtlFirstEntrySList(const SLIST_HEADER* list)
{
#ifdef _WIN64
    return (SLIST_ENTRY *)((ULONG_PTR)list->Header16.NextEntry << 4);
#else
    return list->Next.Next;
#endif
}

/*************************************************************************
 *           RtlInterlockedFlushSList (NTDLL.@)
 */
PSLIST_ENTRY WINAPI RtlInterlockedFlushSList(PSLIST_HEADER list)
{
    SLIST_HEADER old, new;

#ifdef _WIN64
    if (!list->Header16.NextEntry) return NULL;
    new.Alignment = new.Region = 0;
    new.Header16.HeaderType = 1;  /* we use the 16-byte header */
    do
    {
        old = *list;
        new.Header16.Sequence = old.Header16.Sequence + 1;
    } while (!InterlockedCompareExchange128((__int64 *)list, new.Region, new.Alignment, (__int64 *)&old));
    return (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4);
#else
    if (!list->Next.Next) return NULL;
    new.Alignment = 0;
    do
    {
        old = *list;
        new.Sequence = old.Sequence + 1;
    } while (InterlockedCompareExchange64((__int64 *)&list->Alignment, new.Alignment,
                                          old.Alignment) != old.Alignment);
    return old.Next.Next;
#endif
}

/*************************************************************************
 *           RtlInterlockedPushEntrySList (NTDLL.@)
 */
PSLIST_ENTRY WINAPI RtlInterlockedPushEntrySList(PSLIST_HEADER list, PSLIST_ENTRY entry)
{
    SLIST_HEADER old, new;

#ifdef _WIN64
    new.Header16.NextEntry = (ULONG_PTR)entry >> 4;
    do
    {
        old = *list;
        entry->Next = (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4);
        new.Header16.Depth = old.Header16.Depth + 1;
        new.Header16.Sequence = old.Header16.Sequence + 1;
    } while (!InterlockedCompareExchange128((__int64 *)list, new.Region, new.Alignment, (__int64 *)&old));
    return (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4);
#else
    new.Next.Next = entry;
    do
    {
        old = *list;
        entry->Next = old.Next.Next;
        new.Depth = old.Depth + 1;
        new.Sequence = old.Sequence + 1;
    } while (InterlockedCompareExchange64((__int64 *)&list->Alignment, new.Alignment,
                                          old.Alignment) != old.Alignment);
    return old.Next.Next;
#endif
}

/*************************************************************************
 *           RtlInterlockedPopEntrySList (NTDLL.@)
 */
PSLIST_ENTRY WINAPI RtlInterlockedPopEntrySList(PSLIST_HEADER list)
{
    SLIST_HEADER old, new;
    PSLIST_ENTRY entry;

#ifdef _WIN64
    do
    {
        old = *list;
        if (!(entry = (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4))) return NULL;
        /* entry could be deleted by another thread */
        __TRY
        {
            new.Header16.NextEntry = (ULONG_PTR)entry->Next >> 4;
            new.Header16.Depth = old.Header16.Depth - 1;
            new.Header16.Sequence = old.Header16.Sequence + 1;
        }
        __EXCEPT_PAGE_FAULT
        {
        }
        __ENDTRY
    } while (!InterlockedCompareExchange128((__int64 *)list, new.Region, new.Alignment, (__int64 *)&old));
#else
    do
    {
        old = *list;
        if (!(entry = old.Next.Next)) return NULL;
        /* entry could be deleted by another thread */
        __TRY
        {
            new.Next.Next = entry->Next;
            new.Depth = old.Depth - 1;
            new.Sequence = old.Sequence + 1;
        }
        __EXCEPT_PAGE_FAULT
        {
        }
        __ENDTRY
    } while (InterlockedCompareExchange64((__int64 *)&list->Alignment, new.Alignment,
                                          old.Alignment) != old.Alignment);
#endif
    return entry;
}

/*************************************************************************
 *           RtlInterlockedPushListSListEx (NTDLL.@)
 */
PSLIST_ENTRY WINAPI RtlInterlockedPushListSListEx(PSLIST_HEADER list, PSLIST_ENTRY first,
                                                  PSLIST_ENTRY last, ULONG count)
{
    SLIST_HEADER old, new;

#ifdef _WIN64
    new.Header16.NextEntry = (ULONG_PTR)first >> 4;
    do
    {
        old = *list;
        new.Header16.Depth = old.Header16.Depth + count;
        new.Header16.Sequence = old.Header16.Sequence + 1;
        last->Next = (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4);
    } while (!InterlockedCompareExchange128((__int64 *)list, new.Region, new.Alignment, (__int64 *)&old));
    return (SLIST_ENTRY *)((ULONG_PTR)old.Header16.NextEntry << 4);
#else
    new.Next.Next = first;
    do
    {
        old = *list;
        new.Depth = old.Depth + count;
        new.Sequence = old.Sequence + 1;
        last->Next = old.Next.Next;
    } while (InterlockedCompareExchange64((__int64 *)&list->Alignment, new.Alignment,
                                          old.Alignment) != old.Alignment);
    return old.Next.Next;
#endif
}

/*************************************************************************
 *           RtlInterlockedPushListSList (NTDLL.@)
 */
DEFINE_FASTCALL_WRAPPER(RtlInterlockedPushListSList, 16)
PSLIST_ENTRY FASTCALL RtlInterlockedPushListSList(PSLIST_HEADER list, PSLIST_ENTRY first,
                                                  PSLIST_ENTRY last, ULONG count)
{
    return RtlInterlockedPushListSListEx(list, first, last, count);
}

/***********************************************************************
 *           RtlInitializeResource  (NTDLL.@)
 *
 * xxxResource() functions implement multiple-reader-single-writer lock.
 * The code is based on information published in WDJ January 1999 issue.
 */
void WINAPI RtlInitializeResource(LPRTL_RWLOCK rwl)
{
    if (!rwl) return;
    rwl->iNumberActive = 0;
    rwl->uExclusiveWaiters = 0;
    rwl->uSharedWaiters = 0;
    rwl->hOwningThreadId = 0;
    rwl->dwTimeoutBoost = 0; /* no info on this one, default value is 0 */
    RtlInitializeCriticalSectionEx( &rwl->rtlCS, 0, RTL_CRITICAL_SECTION_FLAG_FORCE_DEBUG_INFO );
    rwl->rtlCS.DebugInfo->Spare[0] = (DWORD_PTR)(__FILE__ ": RTL_RWLOCK.rtlCS");
    NtCreateSemaphore( &rwl->hExclusiveReleaseSemaphore, SEMAPHORE_ALL_ACCESS, NULL, 0, 65535 );
    NtCreateSemaphore( &rwl->hSharedReleaseSemaphore, SEMAPHORE_ALL_ACCESS, NULL, 0, 65535 );
}

/***********************************************************************
 *           RtlDeleteResource   (NTDLL.@)
 */
void WINAPI RtlDeleteResource(LPRTL_RWLOCK rwl)
{
    if (!rwl) return;
    RtlEnterCriticalSection( &rwl->rtlCS );
    if( rwl->iNumberActive || rwl->uExclusiveWaiters || rwl->uSharedWaiters )
        ERR("Deleting active MRSW lock (%p), expect failure\n", rwl );
    rwl->hOwningThreadId = 0;
    rwl->uExclusiveWaiters = rwl->uSharedWaiters = 0;
    rwl->iNumberActive = 0;
    NtClose( rwl->hExclusiveReleaseSemaphore );
    NtClose( rwl->hSharedReleaseSemaphore );
    RtlLeaveCriticalSection( &rwl->rtlCS );
    rwl->rtlCS.DebugInfo->Spare[0] = 0;
    RtlDeleteCriticalSection( &rwl->rtlCS );
}

/***********************************************************************
 *          RtlAcquireResourceExclusive	(NTDLL.@)
 */
BYTE WINAPI RtlAcquireResourceExclusive(LPRTL_RWLOCK rwl, BYTE fWait)
{
    BYTE retVal = 0;

    if (!rwl) return 0;

    for (;;)
    {
        RtlEnterCriticalSection( &rwl->rtlCS );
        if( rwl->iNumberActive == 0 ) /* lock is free */
        {
            rwl->iNumberActive = -1;
            retVal = 1;
        }
        else if( rwl->iNumberActive < 0 ) /* exclusive lock in progress */
        {
            if( rwl->hOwningThreadId == ULongToHandle(GetCurrentThreadId()) )
            {
                retVal = 1;
                rwl->iNumberActive--;
                break;
            }
        wait:
            if( fWait )
            {
                NTSTATUS status;

                rwl->uExclusiveWaiters++;

                RtlLeaveCriticalSection( &rwl->rtlCS );
                status = NtWaitForSingleObject( rwl->hExclusiveReleaseSemaphore, FALSE, NULL );
                if( HIWORD(status) ) break;
                continue; /* restart the acquisition to avoid deadlocks */
            }
        }
        else  /* one or more shared locks are in progress */
            if( fWait )
                goto wait;

        if( retVal == 1 ) rwl->hOwningThreadId = ULongToHandle(GetCurrentThreadId());
        break;
    }
    RtlLeaveCriticalSection( &rwl->rtlCS );
    return retVal;
}

/***********************************************************************
 *          RtlAcquireResourceShared  (NTDLL.@)
 */
BYTE WINAPI RtlAcquireResourceShared(LPRTL_RWLOCK rwl, BYTE fWait)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BYTE retVal = 0;

    if (!rwl) return 0;
    for (;;)
    {
        RtlEnterCriticalSection( &rwl->rtlCS );
        if( rwl->iNumberActive < 0 )
        {
            if( rwl->hOwningThreadId == ULongToHandle(GetCurrentThreadId()) )
            {
                rwl->iNumberActive--;
                retVal = 1;
                break;
            }

            if( fWait )
            {
                rwl->uSharedWaiters++;
                RtlLeaveCriticalSection( &rwl->rtlCS );
                status = NtWaitForSingleObject( rwl->hSharedReleaseSemaphore, FALSE, NULL );
                if( HIWORD(status) ) break;
                continue;
            }
        }
        else
        {
            if( status != STATUS_WAIT_0 ) /* otherwise RtlReleaseResource() has already done it */
                rwl->iNumberActive++;
            retVal = 1;
        }
        break;
    }
    RtlLeaveCriticalSection( &rwl->rtlCS );
    return retVal;
}


/***********************************************************************
 *           RtlReleaseResource  (NTDLL.@)
 */
void WINAPI RtlReleaseResource(LPRTL_RWLOCK rwl)
{
    RtlEnterCriticalSection( &rwl->rtlCS );

    if( rwl->iNumberActive > 0 ) /* have one or more readers */
    {
	if( --rwl->iNumberActive == 0 )
	{
	    if( rwl->uExclusiveWaiters )
	    {
		rwl->uExclusiveWaiters--;
		NtReleaseSemaphore( rwl->hExclusiveReleaseSemaphore, 1, NULL );
	    }
	}
    }
    else if( rwl->iNumberActive < 0 ) /* have a writer, possibly recursive */
    {
	if( ++rwl->iNumberActive == 0 )
	{
	    rwl->hOwningThreadId = 0;
	    if( rwl->uExclusiveWaiters )
	    {
		rwl->uExclusiveWaiters--;
		NtReleaseSemaphore( rwl->hExclusiveReleaseSemaphore, 1, NULL );
	    }
	    else if( rwl->uSharedWaiters )
            {
                UINT n = rwl->uSharedWaiters;
                rwl->iNumberActive = rwl->uSharedWaiters; /* prevent new writers from joining until
                                                           * all queued readers have done their thing */
                rwl->uSharedWaiters = 0;
                NtReleaseSemaphore( rwl->hSharedReleaseSemaphore, n, NULL );
            }
	}
    }
    RtlLeaveCriticalSection( &rwl->rtlCS );
}


/***********************************************************************
 *           RtlDumpResource		(NTDLL.@)
 */
void WINAPI RtlDumpResource(LPRTL_RWLOCK rwl)
{
    if (!rwl) return;
    ERR( "%p: active count = %i waiting readers = %i waiting writers = %i owner thread = %p",
         rwl, rwl->iNumberActive, rwl->uSharedWaiters, rwl->uExclusiveWaiters, rwl->hOwningThreadId );
    ERR( "\n" );
}


struct barrier_impl
{
    LONG spin_count;
    LONG total_thread_count;
    volatile LONG reached_thread_count;
    volatile LONG structure_lock_count;
    volatile LONG waiting_thread_count;
    volatile LONG wait_barrier_complete;
};

C_ASSERT( sizeof(struct barrier_impl) <= sizeof(RTL_BARRIER) );

/***********************************************************************
 *           RtlInitBarrier  (NTDLL.@)
 */
NTSTATUS WINAPI RtlInitBarrier( RTL_BARRIER *barrier, LONG thread_count, LONG spin_count )
{
    struct barrier_impl *b = (struct barrier_impl *)barrier;

    TRACE( "barrier %p, thread_count %ld, spin_count %ld.\n", barrier, thread_count, spin_count );

    if (!barrier) return STATUS_INVALID_PARAMETER;
    b->total_thread_count = thread_count;
    b->spin_count = spin_count;
    b->reached_thread_count = 0;
    b->structure_lock_count = 0;
    b->waiting_thread_count = 0;
    b->wait_barrier_complete = 0;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *           RtlDeleteBarrier  (NTDLL.@)
 */
void WINAPI RtlDeleteBarrier( RTL_BARRIER *barrier )
{
    struct barrier_impl *b = (struct barrier_impl *)barrier;
    LONG count;

    TRACE( "barrier %p.\n", barrier );

    if (!barrier) return;
    if (ReadAcquire( &b->reached_thread_count ) < b->total_thread_count && b->structure_lock_count)
    {
        /* On Windows this case will make RtlDeleteBarrier and the threads joining after wait forever,
         * unless the threads joining after will have SYNCHRONIZATION_BARRIER_FLAGS_NO_DELETE. */
        ERR( "called before the barrier wait is satisfied.\n" );
    }
    while ((count = ReadAcquire( &b->structure_lock_count )))
        RtlWaitOnAddress( (void *)&b->structure_lock_count, &count, sizeof(b->structure_lock_count), NULL );
}


/***********************************************************************
 *           RtlBarrier  (NTDLL.@)
 */
BOOLEAN WINAPI RtlBarrier( RTL_BARRIER *barrier, ULONG flags )
{
    static unsigned int once;
    static const LONG zero;

    struct barrier_impl *b = (struct barrier_impl *)barrier;
    unsigned int spin_count, count;
    BOOL ret = FALSE;

    TRACE( "barrier %p, flags %#lx.\n", barrier, flags );

    if (flags & ~0x10000 && !once++) FIXME( "Unknown flags %#lx.\n", flags );
    if (!barrier) return FALSE;

    /* Incrementing reached_thread_count may trigger RTL_BARRIER data desrtuction from another thread,
     * so lock RtlDeleteBarrier with waiting_thread_count before that. */
    if (flags & 0x10000) InterlockedIncrement( &b->structure_lock_count );

    /* On Windows the long wait doesn't consume CPU with any spin count, so probably the spin count
     * is limited or not used at all. */
    spin_count = min( 2000, (unsigned int)b->spin_count );

    /* Wait for previous wait iteration to complete. */
    count = 0;
    while (ReadAcquire( &b->reached_thread_count ) == b->total_thread_count)
    {
        if (count < spin_count)
        {
            ++count;
            YieldProcessor();
            continue;
        }
        RtlWaitOnAddress( (void *)&b->reached_thread_count, &b->total_thread_count,
                          sizeof(b->reached_thread_count), NULL );
    }
    InterlockedIncrement( &b->waiting_thread_count );
    if (InterlockedIncrement( &b->reached_thread_count ) == b->total_thread_count)
    {
        WriteRelease( &b->wait_barrier_complete, 1 );
        RtlWakeAddressAll( (const void *)&b->wait_barrier_complete );
        ret = TRUE;
        goto done;
    }
    count = 0;
    while (ReadAcquire( &b->reached_thread_count ) < b->total_thread_count )
    {
        if (count < spin_count)
        {
            ++count;
            YieldProcessor();
            continue;
        }
        RtlWaitOnAddress( (void *)&b->wait_barrier_complete, &zero, sizeof(b->wait_barrier_complete), NULL );
    }

done:
    if (!InterlockedDecrement( &b->waiting_thread_count ))
    {
        WriteRelease( &b->wait_barrier_complete, 0 );
        WriteRelease( &b->reached_thread_count, 0 );
        RtlWakeAddressAll( (const void *)&b->reached_thread_count );
    }

    if (flags & 0x10000 && !InterlockedDecrement( &b->structure_lock_count ))
    {
        /* Now RTL_BARRIER structure contents may become invalid. Signaling on its address should be fine, the worst
         * (unlikely) case it will wake something unrelated on reused address but that should be a legitimate spurious
         * wakeup case. */
        RtlWakeAddressAll( (const void *)&b->structure_lock_count );
    }
    return ret;
}
