/*
 * NSPA — empty-poll cache for get_message RPC.
 *
 * Caches "filter F returned STATUS_PENDING (no msg) at queue_seq N" per
 * thread.  On the next peek_message with the same filter shape, if
 * queue_shm->nspa_change_seq still equals N, skip the RPC and return
 * STATUS_PENDING locally.  Server bumps nspa_change_seq inside
 * set_queue_bits (see server/queue.c + protocol.def queue_shm_t).
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
 * Cost: linear scan over 8 cache-line-friendly entries (~10 cycles).
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

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winuser.h"

#include "../win32u_private.h"

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

BOOL nspa_getmsg_cache_lookup( const struct peek_message_filter *filter, UINT64 cur_seq )
{
    int i;

    for (i = 0; i < NSPA_GETMSG_CACHE_SIZE; i++)
    {
        if (!nspa_getmsg_cache[i].valid) continue;
        if (!filter_eq( &nspa_getmsg_cache[i].filter, filter )) continue;
        if (nspa_getmsg_cache[i].seq != cur_seq)
        {
            /* filter matched but seq advanced — invalidate so we don't
             * re-evaluate this stale entry on every future lookup */
            nspa_getmsg_cache[i].valid = FALSE;
            return FALSE;
        }
        nspa_getmsg_cache[i].gen = ++nspa_getmsg_cache_gen;
        return TRUE;  /* hit — caller skips the RPC */
    }
    return FALSE;
}

void nspa_getmsg_cache_record_empty( const struct peek_message_filter *filter, UINT64 seq )
{
    int i, victim = 0;
    unsigned int min_gen = ~0u;

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
