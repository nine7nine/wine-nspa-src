/*
 * NSPA wineserver-side diagnostic for get_next_device_request.
 *
 * See nspa/docs/sechost-investigation.md §5 for the data axes
 * and §6 for the decision tree this dump feeds.
 *
 * Aggregators:
 *   - Global outcome counters (NSPA_DEV_OUTCOME_NB).
 *   - Per-caller (Linux TID) table — open-addressed hash, 64 slots.
 *     Each slot tracks count per outcome.
 *   - Per-device-name table (RETURNED_IRP only) — open-addressed hash
 *     on FNV1a of the WCHAR name, 32 slots.  Each slot tracks count
 *     plus the top-1 caller TID by count.
 *
 * Atomic discipline: counters are RELAXED fetch_add (per-call accuracy
 * not required; aggregate distribution is).  Slot claims use CAS on
 * the key field.  No allocation on the record path.
 */

#include "config.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "device_diag.h"

#define NSPA_DEV_TID_SLOTS    64
#define NSPA_DEV_NAME_SLOTS   32
#define NSPA_DEV_NAME_MAX     128   /* WCHAR units retained per device */

static int diag_enabled;

/* global outcome counters */
static uint64_t outcome_count[NSPA_DEV_OUTCOME_NB];

/* per-caller (Linux TID) breakdown */
struct nspa_dev_tid_slot
{
    int      tid;                            /* 0 = free; CAS-claimed */
    uint64_t per_outcome[NSPA_DEV_OUTCOME_NB];
};
static struct nspa_dev_tid_slot tid_slots[NSPA_DEV_TID_SLOTS];
static uint64_t tid_overflow;                 /* TIDs that didn't fit */

/* per-device-name breakdown (RETURNED_IRP only) */
struct nspa_dev_name_slot
{
    uint32_t hash;                            /* 0 = free; CAS-claimed */
    uint16_t name_len;                        /* WCHAR units */
    unsigned short  name[NSPA_DEV_NAME_MAX];
    uint64_t count;
    int      top_tid;                         /* most frequent caller TID */
    uint64_t top_tid_count;
};
static struct nspa_dev_name_slot name_slots[NSPA_DEV_NAME_SLOTS];
static uint64_t name_overflow;                /* device names that didn't fit */

static const char * const outcome_names[NSPA_DEV_OUTCOME_NB] = {
    "RETURNED_IRP",
    "BLOCKED_NO_REQUESTS",
    "HANDLE_ALLOC_FAILED",
    "BUFFER_OVERFLOW",
};

static void read_comm( int unix_tid, char *buf, size_t bufsz )
{
    char path[64];
    int fd;
    ssize_t n;

    buf[0] = '\0';
    if (unix_tid <= 0) { snprintf( buf, bufsz, "?" ); return; }
    snprintf( path, sizeof(path), "/proc/%d/comm", unix_tid );
    if ((fd = open( path, O_RDONLY )) < 0) { snprintf( buf, bufsz, "(gone)" ); return; }
    n = read( fd, buf, bufsz - 1 );
    close( fd );
    if (n <= 0) { snprintf( buf, bufsz, "?" ); return; }
    buf[n] = '\0';
    if (buf[n-1] == '\n') buf[n-1] = '\0';
}

void nspa_device_diag_init(void)
{
    diag_enabled = (getenv( "NSPA_DEVICE_DIAG" ) != NULL);
    if (diag_enabled)
        fprintf( stderr, "nspa_device_diag: active "
                 "(SIGUSR1=dump, SIGUSR2=reset, max=%d tids, %d device names)\n",
                 NSPA_DEV_TID_SLOTS, NSPA_DEV_NAME_SLOTS );
}

int nspa_device_diag_active(void)
{
    return diag_enabled;
}

/* Claim-or-find a TID slot.  Returns NULL if table is full. */
static struct nspa_dev_tid_slot *tid_slot_lookup( int tid )
{
    unsigned int h = ((unsigned)tid * 2654435761u) & (NSPA_DEV_TID_SLOTS - 1);
    int i;

    for (i = 0; i < NSPA_DEV_TID_SLOTS; i++)
    {
        struct nspa_dev_tid_slot *s = &tid_slots[(h + i) & (NSPA_DEV_TID_SLOTS - 1)];
        int cur = __atomic_load_n( &s->tid, __ATOMIC_RELAXED );
        if (cur == tid) return s;
        if (cur == 0)
        {
            int expected = 0;
            if (__atomic_compare_exchange_n( &s->tid, &expected, tid, 0,
                                             __ATOMIC_RELAXED, __ATOMIC_RELAXED ))
                return s;
            if (__atomic_load_n( &s->tid, __ATOMIC_RELAXED ) == tid) return s;
        }
    }
    return NULL;
}

static uint32_t fnv1a_wcs( const unsigned short *s, unsigned int len )
{
    uint32_t h = 2166136261u;
    unsigned int i;
    for (i = 0; i < len; i++)
    {
        h ^= (uint32_t)(uint16_t)s[i];
        h *= 16777619u;
    }
    if (h == 0) h = 1;  /* reserve 0 for "free" */
    return h;
}

static struct nspa_dev_name_slot *name_slot_lookup( const unsigned short *name, unsigned int name_len,
                                                     uint32_t hash )
{
    unsigned int h = hash & (NSPA_DEV_NAME_SLOTS - 1);
    int i;

    for (i = 0; i < NSPA_DEV_NAME_SLOTS; i++)
    {
        struct nspa_dev_name_slot *s = &name_slots[(h + i) & (NSPA_DEV_NAME_SLOTS - 1)];
        uint32_t cur = __atomic_load_n( &s->hash, __ATOMIC_RELAXED );
        if (cur == hash &&
            s->name_len == name_len &&
            !memcmp( (const void *)s->name, name, name_len * sizeof(unsigned short) ))
            return s;
        if (cur == 0)
        {
            uint32_t expected = 0;
            if (__atomic_compare_exchange_n( &s->hash, &expected, hash, 0,
                                             __ATOMIC_RELAXED, __ATOMIC_RELAXED ))
            {
                unsigned int copy = name_len > NSPA_DEV_NAME_MAX ? NSPA_DEV_NAME_MAX : name_len;
                memcpy( s->name, name, copy * sizeof(unsigned short) );
                s->name_len = copy;
                return s;
            }
            if (__atomic_load_n( &s->hash, __ATOMIC_RELAXED ) == hash)
                return s;
        }
    }
    return NULL;
}

void nspa_device_diag_record( enum nspa_device_outcome outcome,
                              int caller_unix_tid,
                              const unsigned short *device_name,
                              unsigned int device_name_len )
{
    struct nspa_dev_tid_slot *tslot;

    if (!diag_enabled) return;
    if (outcome >= NSPA_DEV_OUTCOME_NB) return;

    __atomic_fetch_add( &outcome_count[outcome], 1, __ATOMIC_RELAXED );

    if ((tslot = tid_slot_lookup( caller_unix_tid )))
        __atomic_fetch_add( &tslot->per_outcome[outcome], 1, __ATOMIC_RELAXED );
    else
        __atomic_fetch_add( &tid_overflow, 1, __ATOMIC_RELAXED );

    if (outcome == NSPA_DEV_OUTCOME_RETURNED_IRP && device_name && device_name_len)
    {
        uint32_t hash = fnv1a_wcs( device_name, device_name_len );
        struct nspa_dev_name_slot *nslot = name_slot_lookup( device_name, device_name_len, hash );
        if (nslot)
        {
            uint64_t new_count = __atomic_add_fetch( &nslot->count, 1, __ATOMIC_RELAXED );
            /* Track top caller without a lock — racy but advisory.
             * Two writers may briefly disagree on top_tid; the count
             * snapshot at dump time is authoritative on which tid
             * had how many calls. */
            uint64_t cur_top = __atomic_load_n( &nslot->top_tid_count, __ATOMIC_RELAXED );
            if (new_count > cur_top)
            {
                __atomic_store_n( &nslot->top_tid_count, new_count, __ATOMIC_RELAXED );
                __atomic_store_n( &nslot->top_tid, caller_unix_tid, __ATOMIC_RELAXED );
            }
        }
        else
            __atomic_fetch_add( &name_overflow, 1, __ATOMIC_RELAXED );
    }
}

/* Best-effort UTF-16 → ASCII for the dump.  Substitutes '?' for
 * non-ASCII printable; truncates at buf_max-1. */
static void wcs_to_ascii( const unsigned short *src, unsigned int src_len,
                          char *buf, size_t buf_max )
{
    unsigned int i, j = 0;
    if (buf_max == 0) return;
    for (i = 0; i < src_len && j < buf_max - 1; i++)
    {
        unsigned short c = src[i];
        if (c >= 0x20 && c < 0x7f) buf[j++] = (char)c;
        else                       buf[j++] = '?';
    }
    buf[j] = '\0';
}

void nspa_device_diag_dump(void)
{
    char path[128], tmp[128];
    FILE *f;
    int i;
    uint64_t total = 0;

    if (!diag_enabled) return;

    snprintf( tmp,  sizeof(tmp),  "/tmp/nspa_device_diag.%d.log.tmp", (int)getpid() );
    snprintf( path, sizeof(path), "/tmp/nspa_device_diag.%d.log",      (int)getpid() );
    if (!(f = fopen( tmp, "w" ))) return;

    fprintf( f, "NSPA device-request diagnostic  pid=%d  time=%lld\n",
             (int)getpid(), (long long)time(NULL) );
    fprintf( f, "----\n" );

    fprintf( f, "[get_next_device_request outcomes]\n" );
    for (i = 0; i < NSPA_DEV_OUTCOME_NB; i++)
        total += __atomic_load_n( &outcome_count[i], __ATOMIC_RELAXED );
    for (i = 0; i < NSPA_DEV_OUTCOME_NB; i++)
    {
        uint64_t v = __atomic_load_n( &outcome_count[i], __ATOMIC_RELAXED );
        fprintf( f, "  %-22s %10llu  %5.1f%%\n",
                 outcome_names[i], (unsigned long long)v,
                 total ? 100.0 * (double)v / (double)total : 0.0 );
    }
    fprintf( f, "  total                  %10llu\n", (unsigned long long)total );

    fprintf( f, "\n[per-caller TID breakdown]\n" );
    fprintf( f, "  %-8s %-20s %12s %12s %10s %10s\n",
             "tid", "comm", "RETURNED", "BLOCKED", "HND_FAIL", "BUF_OVF" );
    for (i = 0; i < NSPA_DEV_TID_SLOTS; i++)
    {
        struct nspa_dev_tid_slot *s = &tid_slots[i];
        char comm[32];
        int tid = __atomic_load_n( &s->tid, __ATOMIC_RELAXED );
        uint64_t r, b, h, o;
        if (!tid) continue;
        r = __atomic_load_n( &s->per_outcome[NSPA_DEV_OUTCOME_RETURNED_IRP],         __ATOMIC_RELAXED );
        b = __atomic_load_n( &s->per_outcome[NSPA_DEV_OUTCOME_BLOCKED_NO_REQUESTS],  __ATOMIC_RELAXED );
        h = __atomic_load_n( &s->per_outcome[NSPA_DEV_OUTCOME_HANDLE_ALLOC_FAILED],  __ATOMIC_RELAXED );
        o = __atomic_load_n( &s->per_outcome[NSPA_DEV_OUTCOME_BUFFER_OVERFLOW],      __ATOMIC_RELAXED );
        read_comm( tid, comm, sizeof(comm) );
        fprintf( f, "  %-8d %-20s %12llu %12llu %10llu %10llu\n",
                 tid, comm,
                 (unsigned long long)r,
                 (unsigned long long)b,
                 (unsigned long long)h,
                 (unsigned long long)o );
    }
    {
        uint64_t ov = __atomic_load_n( &tid_overflow, __ATOMIC_RELAXED );
        if (ov) fprintf( f, "  TID-table overflow bumps: %llu\n", (unsigned long long)ov );
    }

    fprintf( f, "\n[per-device-name breakdown (RETURNED_IRP only)]\n" );
    fprintf( f, "  %-12s %-8s %-20s %s\n",
             "count", "top_tid", "top_comm", "device_name" );
    for (i = 0; i < NSPA_DEV_NAME_SLOTS; i++)
    {
        struct nspa_dev_name_slot *s = &name_slots[i];
        char ascii[NSPA_DEV_NAME_MAX + 1];
        char comm[32];
        uint32_t hash = __atomic_load_n( &s->hash, __ATOMIC_RELAXED );
        uint64_t cnt;
        int top_tid;
        if (hash == 0) continue;
        cnt = __atomic_load_n( &s->count, __ATOMIC_RELAXED );
        top_tid = __atomic_load_n( &s->top_tid, __ATOMIC_RELAXED );
        wcs_to_ascii( s->name, s->name_len, ascii, sizeof(ascii) );
        read_comm( top_tid, comm, sizeof(comm) );
        fprintf( f, "  %12llu %-8d %-20s %s\n",
                 (unsigned long long)cnt, top_tid, comm, ascii );
    }
    {
        uint64_t ov = __atomic_load_n( &name_overflow, __ATOMIC_RELAXED );
        if (ov) fprintf( f, "  Name-table overflow bumps: %llu\n", (unsigned long long)ov );
    }

    fclose( f );
    rename( tmp, path );
}

void nspa_device_diag_reset(void)
{
    int i, j;
    if (!diag_enabled) return;

    for (i = 0; i < NSPA_DEV_OUTCOME_NB; i++)
        __atomic_store_n( &outcome_count[i], 0, __ATOMIC_RELAXED );

    for (i = 0; i < NSPA_DEV_TID_SLOTS; i++)
    {
        for (j = 0; j < NSPA_DEV_OUTCOME_NB; j++)
            __atomic_store_n( &tid_slots[i].per_outcome[j], 0, __ATOMIC_RELAXED );
        __atomic_store_n( &tid_slots[i].tid, 0, __ATOMIC_RELAXED );
    }
    __atomic_store_n( &tid_overflow, 0, __ATOMIC_RELAXED );

    for (i = 0; i < NSPA_DEV_NAME_SLOTS; i++)
    {
        __atomic_store_n( &name_slots[i].count, 0, __ATOMIC_RELAXED );
        __atomic_store_n( &name_slots[i].top_tid_count, 0, __ATOMIC_RELAXED );
        __atomic_store_n( &name_slots[i].top_tid, 0, __ATOMIC_RELAXED );
        __atomic_store_n( &name_slots[i].hash, 0, __ATOMIC_RELAXED );
    }
    __atomic_store_n( &name_overflow, 0, __ATOMIC_RELAXED );
}
