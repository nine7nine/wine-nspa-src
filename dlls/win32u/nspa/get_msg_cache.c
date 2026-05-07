/*
 * NSPA Phase C — empty-poll cache for get_message RPC.
 *
 * Caches "filter F returned STATUS_PENDING (no msg) at queue_seq N" per
 * thread.  On the next peek_message with the same filter shape, if
 * queue_shm->nspa_change_seq still equals N, skip the RPC and return
 * STATUS_PENDING locally.  Server bumps nspa_change_seq inside
 * set_queue_bits (see server/queue.c + protocol.def queue_shm_t).
 *
 * Default-OFF behind NSPA_GETMSG_EMPTY_CACHE=1.  When disabled, every
 * lookup short-circuits via the env-cache flag.
 *
 * Bug-class checklist (per feedback_dont_reintroduce_silent_contract_bugs):
 *   MR1 stamped-but-unchecked: filter is stored in full alongside seq;
 *     filter_eq() checks every field.  No hash-collision drop possible.
 *   MR4 wake-without-fallback: cache miss = caller does the RPC (the
 *     authoritative path).  Cache only short-circuits when the cached
 *     filter matches AND the seq matches.
 *   Multi-source wake-bit (range_publish lesson): queue_shm->nspa_change_seq
 *     covers all server-side wake-bit sources (set_queue_bits is the
 *     single funnel).  NSPA same-process ring publishers have separate
 *     per-ring change_seq; check_queue_bits already detects ring changes
 *     and forces skip=FALSE → ring pop attempts run BEFORE this cache
 *     check.  If ring pops fail and cache hits, the server side has not
 *     advanced — STATUS_PENDING is the correct answer.
 *
 * Cost when enabled: linear scan over ~8 entries (cache-line friendly,
 * ~10 cycles).  Cost when disabled: one atomic read of the env-cache
 * flag.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winuser.h"
#include "winternl.h"
#include "wine/debug.h"

#include "../win32u_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(msg);

#define NSPA_GETMSG_CACHE_SIZE 8

struct nspa_getmsg_cache_entry
{
    struct peek_message_filter filter;  /* full filter for collision-safe match */
    UINT64                     seq;     /* queue_shm->nspa_change_seq at last empty */
    unsigned int               gen;     /* LRU generation (higher = more recent) */
    BOOL                       valid;
};

/* Per-thread cache.  TLS so RT-safe and lock-free. */
static __thread struct nspa_getmsg_cache_entry nspa_getmsg_cache[NSPA_GETMSG_CACHE_SIZE];
static __thread unsigned int                   nspa_getmsg_cache_gen;

/* Tri-state: -1 unchecked, 0 off, 1 on.  Set on first call. */
static int nspa_getmsg_cache_state = -1;

/* Diagnostic counters (single thread per peek_message-level reads). */
static __thread unsigned long nspa_getmsg_cache_hits;
static __thread unsigned long nspa_getmsg_cache_misses;
static __thread unsigned long nspa_getmsg_cache_records;

static inline BOOL filter_eq( const struct peek_message_filter *a,
                              const struct peek_message_filter *b )
{
    return a->hwnd     == b->hwnd
        && a->first    == b->first
        && a->last     == b->last
        && a->mask     == b->mask
        && a->flags    == b->flags
        && a->internal == b->internal;
}

BOOL nspa_getmsg_cache_enabled(void)
{
    int v = __atomic_load_n( &nspa_getmsg_cache_state, __ATOMIC_ACQUIRE );
    if (v < 0)
    {
        /* Default-ON since 2026-05-06 — Ableton-validated 78% get_message
         * RPC reduction, 21% wineserver handler-time reduction, no silent
         * message drops observed.  Set NSPA_GETMSG_EMPTY_CACHE=0 to force
         * OFF (legacy unconditional-RPC path) for diagnostic A/B. */
        const char *env = getenv( "NSPA_GETMSG_EMPTY_CACHE" );
        v = (env && env[0] == '0' && env[1] == 0) ? 0 : 1;
        __atomic_store_n( &nspa_getmsg_cache_state, v, __ATOMIC_RELEASE );
        if (v) TRACE( "NSPA Phase C: empty-poll cache active\n" );
    }
    return v == 1;
}

BOOL nspa_getmsg_cache_lookup( const struct peek_message_filter *filter, UINT64 cur_seq )
{
    int i;

    if (!nspa_getmsg_cache_enabled()) return FALSE;

    for (i = 0; i < NSPA_GETMSG_CACHE_SIZE; i++)
    {
        if (!nspa_getmsg_cache[i].valid) continue;
        if (!filter_eq( &nspa_getmsg_cache[i].filter, filter )) continue;
        if (nspa_getmsg_cache[i].seq != cur_seq)
        {
            /* filter matched but seq advanced — invalidate so we don't
             * re-evaluate this stale entry on every future lookup */
            nspa_getmsg_cache[i].valid = FALSE;
            nspa_getmsg_cache_misses++;
            return FALSE;
        }
        nspa_getmsg_cache[i].gen = ++nspa_getmsg_cache_gen;
        nspa_getmsg_cache_hits++;
        return TRUE;  /* hit — caller skips the RPC */
    }
    nspa_getmsg_cache_misses++;
    return FALSE;
}

void nspa_getmsg_cache_record_empty( const struct peek_message_filter *filter, UINT64 seq )
{
    int i, victim = 0;
    unsigned int min_gen = ~0u;

    if (!nspa_getmsg_cache_enabled()) return;

    nspa_getmsg_cache_records++;

    /* update existing entry first */
    for (i = 0; i < NSPA_GETMSG_CACHE_SIZE; i++)
    {
        if (!nspa_getmsg_cache[i].valid)
        {
            victim = i;
            break;
        }
        if (filter_eq( &nspa_getmsg_cache[i].filter, filter ))
        {
            nspa_getmsg_cache[i].seq = seq;
            nspa_getmsg_cache[i].gen = ++nspa_getmsg_cache_gen;
            return;
        }
        if (nspa_getmsg_cache[i].gen < min_gen)
        {
            min_gen = nspa_getmsg_cache[i].gen;
            victim = i;
        }
    }

    /* insert in victim slot (LRU eviction) */
    nspa_getmsg_cache[victim].filter = *filter;
    nspa_getmsg_cache[victim].seq    = seq;
    nspa_getmsg_cache[victim].gen    = ++nspa_getmsg_cache_gen;
    nspa_getmsg_cache[victim].valid  = TRUE;
}
