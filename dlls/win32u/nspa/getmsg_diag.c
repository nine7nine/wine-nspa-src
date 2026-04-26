/*
 * NSPA Phase C Stage 1 — get_message residual bucketing diagnostic.
 *
 * The msg-ring v1 receive-side fast paths (nspa_try_pop_own_ring_send,
 * nspa_try_pop_own_timer_ring, nspa_try_pop_own_ring_post) drain a known
 * subset of message traffic before the get_message RPC fires.  Whatever
 * still falls through to the RPC is the Phase C target — but which kind
 * of message dominates that residual is an empirical question.  Five
 * candidate buckets (per nspa/docs/msg-ring-v2-phase-bc-handoff.md §3.2):
 *
 *   D  pre-RPC late-binding: own bypass shm not yet bootstrapped.
 *   A  self-thread:          sender_tid == own tid (sent to self).
 *   B  system synth:         sender_tid == 0 (server-generated:
 *                            WM_PAINT / WM_QUIT / hardware / winevent / etc).
 *   C  cross-thread:         sender_tid != 0 && != own and the type is
 *                            ring-eligible — should have drained but didn't
 *                            (bypass not bootstrapped on peer at send time,
 *                            or filter mismatch).
 *   E  other:                everything else (CALLBACK / OTHER_PROCESS).
 *
 * Counters print on process exit via __attribute__((destructor)), gated
 * on total > 0 so quiet processes stay quiet.  Same shape as
 * nspa_paint_fastpath_print_stats in dlls/win32u/dce.c.
 *
 * Stage 1 is instrumentation-only — no behaviour change.  Stage 3 will
 * implement coverage extension for whichever bucket dominates.
 */

#if 0
#pragma makedep unix
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "winternl.h"
#include "../win32u_private.h"
#include "wine/server.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(msg);

static unsigned long long nspa_getmsg_diag_total;
static unsigned long long nspa_getmsg_diag_no_bypass;
static unsigned long long nspa_getmsg_diag_self;
static unsigned long long nspa_getmsg_diag_system;
static unsigned long long nspa_getmsg_diag_cross;
static unsigned long long nspa_getmsg_diag_other;

void nspa_getmsg_diag_pre_rpc( void )
{
    __atomic_fetch_add( &nspa_getmsg_diag_total, 1, __ATOMIC_RELAXED );
    if (!nspa_get_own_bypass_shm_public())
        __atomic_fetch_add( &nspa_getmsg_diag_no_bypass, 1, __ATOMIC_RELAXED );
}

void nspa_getmsg_diag_post_rpc( int reply_type, unsigned int reply_sender_tid )
{
    DWORD self_tid = HandleToULong( NtCurrentTeb()->ClientId.UniqueThread );

    if (reply_sender_tid == 0)
        __atomic_fetch_add( &nspa_getmsg_diag_system, 1, __ATOMIC_RELAXED );
    else if (reply_sender_tid == self_tid)
        __atomic_fetch_add( &nspa_getmsg_diag_self, 1, __ATOMIC_RELAXED );
    else if (reply_type == MSG_ASCII || reply_type == MSG_UNICODE ||
             reply_type == MSG_NOTIFY || reply_type == MSG_POSTED)
        __atomic_fetch_add( &nspa_getmsg_diag_cross, 1, __ATOMIC_RELAXED );
    else
        __atomic_fetch_add( &nspa_getmsg_diag_other, 1, __ATOMIC_RELAXED );
}

static void __attribute__((destructor)) nspa_getmsg_diag_print_stats( void )
{
    unsigned long long total    = __atomic_load_n( &nspa_getmsg_diag_total, __ATOMIC_RELAXED );
    unsigned long long no_byp   = __atomic_load_n( &nspa_getmsg_diag_no_bypass, __ATOMIC_RELAXED );
    unsigned long long self     = __atomic_load_n( &nspa_getmsg_diag_self, __ATOMIC_RELAXED );
    unsigned long long sys      = __atomic_load_n( &nspa_getmsg_diag_system, __ATOMIC_RELAXED );
    unsigned long long cross    = __atomic_load_n( &nspa_getmsg_diag_cross, __ATOMIC_RELAXED );
    unsigned long long other    = __atomic_load_n( &nspa_getmsg_diag_other, __ATOMIC_RELAXED );

    if (!total) return;

    ERR( "NSPA RT:GetMsgDiag: %llu fall-through | D no_bypass=%llu "
         "A self=%llu B system=%llu C cross=%llu E other=%llu\n",
         total, no_byp, self, sys, cross, other );
}
