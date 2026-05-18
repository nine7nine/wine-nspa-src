/*
 * NSPA path-attribute cache — implementation.
 *
 * See pathattr_cache.h for the contract.  Design rationale captured
 * in wine-nspa-notes/wine-nspa-pathattr-cache-design.md.
 *
 * Layout: 64 buckets × 4 slots each = 256 entries, process-local.
 * One pi_mutex_t for the whole table — readers and writers both take
 * it briefly.  Per-bucket seqlock would shave a few hundred ns off
 * the read path but adds complexity that isn't justified for the
 * expected contention pattern (single-threaded plugin hammering the
 * same hot path).  PI ensures progress under priority inversion.
 *
 * TTL: 50ms, expressed via CLOCK_MONOTONIC.  Short enough that cross-
 * process xattr writes are observable within reasonable latency; long
 * enough to amortize 60Hz access with very high hit rates.
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
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <rtpi.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/debug.h"

#include "../unix_private.h"

#include "pathattr_cache.h"

WINE_DEFAULT_DEBUG_CHANNEL(nspa_lfile);

/* nspa_rt_prio_base is the NSPA RT gate, defined in nspa/rt.c.
 * < 0 = RT disabled, fall through to upstream behaviour. */
extern int nspa_rt_prio_base;

#define NSPA_PATHATTR_BUCKETS              64
#define NSPA_PATHATTR_SLOTS_PER_BUCKET     4
#define NSPA_PATHATTR_TTL_NS               (50ULL * 1000000ULL)  /* 50ms */

struct slot
{
    unsigned long long  device;
    unsigned long long  inode;
    unsigned long long  valid_until_ns;
    unsigned int        attr;
    unsigned int        reparse_tag;
};

struct bucket
{
    struct slot slots[NSPA_PATHATTR_SLOTS_PER_BUCKET];
};

static struct bucket table[NSPA_PATHATTR_BUCKETS];
static pi_mutex_t     table_lock = PI_MUTEX_INIT(0);

static unsigned long long mono_now_ns(void)
{
    struct timespec ts;
    clock_gettime( CLOCK_MONOTONIC, &ts );
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

/* Same hash mix as nspa/local_file.c::nspa_lf_bucket_index — keep the
 * pattern consistent across NSPA inode-keyed structures.  bucket count
 * differs (64 vs 1024) because this one is process-local. */
static unsigned int bucket_index( unsigned long long device, unsigned long long inode )
{
    unsigned long long h = device * 0x9E3779B97F4A7C15ull + inode;
    h ^= h >> 33;
    h *= 0xFF51AFD7ED558CCDull;
    h ^= h >> 33;
    return (unsigned int)(h & (NSPA_PATHATTR_BUCKETS - 1));
}

static int nspa_pathattr_enabled(void)
{
    return nspa_rt_prio_base >= 0;
}

int nspa_pathattr_lookup( unsigned long long device, unsigned long long inode,
                          unsigned int *attr_out, unsigned int *reparse_tag_out )
{
    struct bucket *b;
    unsigned long long now_ns;
    int hit = 0;
    unsigned int i;

    if (!nspa_pathattr_enabled()) return 0;

    b = &table[ bucket_index( device, inode ) ];
    now_ns = mono_now_ns();

    pi_mutex_lock( &table_lock );
    for (i = 0; i < NSPA_PATHATTR_SLOTS_PER_BUCKET; i++)
    {
        struct slot *s = &b->slots[i];
        if (s->device != device || s->inode != inode) continue;
        if (s->valid_until_ns <= now_ns)
        {
            /* Stale — clear the slot so the bucket has room for a
             * fresh entry on the next store.  Treat as miss. */
            s->device = 0;
            s->inode  = 0;
            break;
        }
        *attr_out = s->attr;
        if (reparse_tag_out) *reparse_tag_out = s->reparse_tag;
        hit = 1;
        break;
    }
    pi_mutex_unlock( &table_lock );

    return hit;
}

void nspa_pathattr_store( unsigned long long device, unsigned long long inode,
                          unsigned int attr, unsigned int reparse_tag )
{
    struct bucket *b;
    struct slot *victim;
    unsigned long long now_ns, oldest;
    unsigned int i;

    if (!nspa_pathattr_enabled()) return;
    if (!device || !inode) return;       /* defensive — refuse zero key */

    b = &table[ bucket_index( device, inode ) ];
    now_ns = mono_now_ns();

    pi_mutex_lock( &table_lock );

    /* Existing entry for this (dev, ino)?  Update in place. */
    for (i = 0; i < NSPA_PATHATTR_SLOTS_PER_BUCKET; i++)
    {
        struct slot *s = &b->slots[i];
        if (s->device == device && s->inode == inode)
        {
            s->valid_until_ns = now_ns + NSPA_PATHATTR_TTL_NS;
            s->attr           = attr;
            s->reparse_tag    = reparse_tag;
            pi_mutex_unlock( &table_lock );
            return;
        }
    }

    /* Find an empty slot, else evict the one with the oldest TTL. */
    victim = &b->slots[0];
    oldest = victim->valid_until_ns;
    for (i = 0; i < NSPA_PATHATTR_SLOTS_PER_BUCKET; i++)
    {
        struct slot *s = &b->slots[i];
        if (s->device == 0 && s->inode == 0)        /* empty wins */
        {
            victim = s;
            break;
        }
        if (s->valid_until_ns < oldest)
        {
            victim = s;
            oldest = s->valid_until_ns;
        }
    }

    victim->device         = device;
    victim->inode          = inode;
    victim->valid_until_ns = now_ns + NSPA_PATHATTR_TTL_NS;
    victim->attr           = attr;
    victim->reparse_tag    = reparse_tag;

    pi_mutex_unlock( &table_lock );
}

void nspa_pathattr_invalidate( unsigned long long device, unsigned long long inode )
{
    struct bucket *b;
    unsigned int i;

    if (!nspa_pathattr_enabled()) return;
    if (!device || !inode) return;

    b = &table[ bucket_index( device, inode ) ];

    pi_mutex_lock( &table_lock );
    for (i = 0; i < NSPA_PATHATTR_SLOTS_PER_BUCKET; i++)
    {
        struct slot *s = &b->slots[i];
        if (s->device == device && s->inode == inode)
        {
            s->device = 0;
            s->inode  = 0;
            break;
        }
    }
    pi_mutex_unlock( &table_lock );
}

void nspa_pathattr_invalidate_by_fd( int fd )
{
    struct stat st;

    if (!nspa_pathattr_enabled()) return;
    if (fd < 0) return;
    if (fstat( fd, &st ) == -1) return;
    nspa_pathattr_invalidate( st.st_dev, st.st_ino );
}

void nspa_pathattr_invalidate_by_path( const char *path )
{
    struct stat st;

    if (!nspa_pathattr_enabled()) return;
    if (!path) return;
    if (lstat( path, &st ) == -1) return;
    nspa_pathattr_invalidate( st.st_dev, st.st_ino );
}
