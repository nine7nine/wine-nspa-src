/*
 * NSPA local-file bypass — server-side shared inode aggregation table.
 *
 * Phase 1A.1 slice (a): allocate a process-global memfd-backed shmem
 * region, expose its fd to clients via the nspa_get_inode_table request.
 * Server is the sole writer; clients will read lock-free via the per-
 * bucket seqlock once we add the read API.  This commit lands ONLY the
 * region + protocol fetch + scaffold; publish/unpublish hooks at the
 * fd→inode add/remove sites land in slice (b).
 *
 * Sizing: NSPA_INODE_BUCKETS × (header + N slots) ≈ 144 KB.  Single
 * region per wineserver instance.  See nspa/docs/local-file-bypass-design.md
 * for the full design and RT-safety invariants.
 */

#include "config.h"

#ifdef HAVE_MEMFD_CREATE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "file.h"
#include "process.h"
#include "request.h"

#include <rtpi.h>

#ifdef HAVE_SYS_MEMFD_H
# include <sys/memfd.h>
#endif

/* Compile-time check: our shmem-allocated lock storage must be at least
 * as big as a pi_mutex_t.  pi_mutex_t is 64 bytes (cacheline-isolated);
 * nspa_pi_mutex_t.storage is also 64 bytes. */
typedef char nspa_pi_mutex_storage_check[
    (sizeof(((nspa_pi_mutex_t *)0)->storage) >= sizeof(pi_mutex_t)) ? 1 : -1 ];

/* Cast from shmem storage to live pi_mutex_t.  Both are 64-byte aligned
 * by virtue of the bucket layout (slots end on 8-byte boundary, pi_mutex_t
 * is at the start of the bucket).  Lock state lives in the first 12
 * bytes of the storage; the rest is cacheline pad. */
static inline pi_mutex_t *nspa_lock_of( nspa_inode_bucket_t *bucket )
{
    return (pi_mutex_t *)bucket->lock.storage;
}

/* Lazy-allocated singleton.  fd is -1 until the first request creates it
 * (or memfd_create fails permanently).  Once allocated, fd stays open
 * for the lifetime of the wineserver process; it is shared with every
 * client that calls nspa_get_inode_table. */
static int                       nspa_inode_table_fd   = -1;
static size_t                    nspa_inode_table_size = 0;
static nspa_inode_table_shm_t   *nspa_inode_table_map  = NULL;

/* Ensure the shmem region exists.  Returns 1 on success, 0 on permanent
 * failure (memfd_create unsupported, ftruncate failure, mmap failure).
 * On failure all subsequent calls also fail; clients fall back to server
 * create_file as before. */
static int nspa_inode_table_ensure( void )
{
#ifdef HAVE_MEMFD_CREATE
    int fd;
    void *map;
    const size_t size = sizeof(nspa_inode_table_shm_t);

    if (nspa_inode_table_fd >= 0)  return 1;
    if (nspa_inode_table_fd == -2) return 0;   /* sticky-failure marker */

    fd = memfd_create( "wine-nspa-inode-table", MFD_CLOEXEC );
    if (fd == -1) goto fail_sticky;

    if (ftruncate( fd, size ) == -1)
    {
        close( fd );
        goto fail_sticky;
    }

    map = mmap( NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
    if (map == MAP_FAILED)
    {
        close( fd );
        goto fail_sticky;
    }

    /* Single-threaded server context — memset before any fd is sent.
     * Magic + version are populated AFTER memset so a corrupt early read
     * (impossible here, but defensive) would see a zeroed magic and
     * reject the table. */
    memset( map, 0, size );
    {
        nspa_inode_table_shm_t *t = map;
        unsigned int b;
        t->magic        = NSPA_INODE_TABLE_MAGIC;
        t->version      = NSPA_INODE_TABLE_VERSION;
        t->bucket_count = NSPA_INODE_BUCKETS;
        /* Initialise per-bucket PI mutexes with PSHARED so they work
         * across processes.  pi_mutex_init memsets 64 bytes and sets
         * flags; our storage is exactly 64 bytes so this is in-bounds. */
        for (b = 0; b < NSPA_INODE_BUCKETS; b++)
            pi_mutex_init( nspa_lock_of( (nspa_inode_bucket_t *)&t->buckets[b] ),
                           RTPI_MUTEX_PSHARED );
    }

    nspa_inode_table_fd   = fd;
    nspa_inode_table_size = size;
    nspa_inode_table_map  = map;
    return 1;

fail_sticky:
    nspa_inode_table_fd = -2;
    return 0;
#else
    nspa_inode_table_fd = -2;
    return 0;
#endif
}

/* Hash a (device, inode) tuple into a bucket index.  Mix both halves so
 * sequential inodes don't all land in the same bucket on common
 * filesystems. */
unsigned int nspa_inode_table_bucket( unsigned __int64 device, unsigned __int64 inode )
{
    unsigned __int64 h = device * 0x9E3779B97F4A7C15ull + inode;
    h ^= h >> 33;
    h *= 0xFF51AFD7ED558CCDull;
    h ^= h >> 33;
    return (unsigned int)(h & (NSPA_INODE_BUCKETS - 1));
}

/* Server-side inspect helper for slice (b) and trace.  Returns the
 * pointer to the slot for (device, inode), or NULL if not present.  No
 * locking — server is single-threaded request context. */
nspa_inode_slot_t *nspa_inode_table_find_slot( unsigned __int64 device,
                                               unsigned __int64 inode )
{
    nspa_inode_bucket_t *bucket;
    unsigned int i;

    if (!nspa_inode_table_map) return NULL;
    bucket = (nspa_inode_bucket_t *)&nspa_inode_table_map->buckets[
        nspa_inode_table_bucket( device, inode )];
    for (i = 0; i < NSPA_INODE_SLOTS_PER_BUCKET; i++)
    {
        if (bucket->slots[i].device == device && bucket->slots[i].inode == inode)
            return (nspa_inode_slot_t *)&bucket->slots[i];
    }
    return NULL;
}

int nspa_inode_table_is_active( void )
{
    return nspa_inode_table_map != NULL;
}

/* Publish per-(device,inode) aggregated state.  See header comment for
 * contract.  Implements the seqlock-write protocol that pairs with the
 * client-side seqlock-read pattern (slice (c) — not yet built):
 *
 *   1. seq odd      = mutating (readers retry)
 *   2. write slot   = update aggregated values
 *   3. seq even     = stable
 *
 * Memory ordering: RELEASE on each seq store ensures slot writes
 * between the two stores cannot be reordered past either fence from a
 * reader's ACQUIRE on the seq value.
 */
void nspa_inode_publish_slot( unsigned long long device, unsigned long long inode_no,
                              unsigned int refcount,
                              unsigned int agg_existing_access,
                              unsigned int agg_existing_sharing )
{
    nspa_inode_bucket_t *bucket;
    int slot_idx = -1;
    int empty_idx = -1;
    unsigned int i, seq;
    nspa_inode_slot_t *slot;

    /* Defer materialising the shmem region until a client has actually
     * fetched it.  Avoids overhead on every open if no Wine process is
     * using the bypass. */
    if (!nspa_inode_table_map) return;

    bucket = (nspa_inode_bucket_t *)&nspa_inode_table_map->buckets[
        nspa_inode_table_bucket( device, inode_no )];

    /* Find existing slot for (device, inode) or note an empty slot. */
    for (i = 0; i < NSPA_INODE_SLOTS_PER_BUCKET; i++)
    {
        if (bucket->slots[i].device == device && bucket->slots[i].inode == inode_no)
        {
            slot_idx = (int)i;
            break;
        }
        if (bucket->slots[i].device == 0 && empty_idx < 0)
            empty_idx = (int)i;
    }

    /* Nothing to do: refcount==0 and no existing slot. */
    if (slot_idx < 0 && refcount == 0) return;

    /* Bucket overflow: refcount>0 but no slot for us and no empty.
     * Silent fallback — clients can't bypass this inode, but the
     * server still does check_sharing correctly. */
    if (slot_idx < 0 && empty_idx < 0) return;

    if (slot_idx < 0) slot_idx = empty_idx;
    slot = (nspa_inode_slot_t *)&bucket->slots[slot_idx];

    /* Cross-process write critical section: take the bucket's PI mutex
     * before mutating slot data + bumping seq.  Pairs with client-side
     * publishes from slice (b).  Server is single-threaded so this is
     * uncontended within wineserver, but contention with client writers
     * (1A.2.b+) requires the lock to be honoured. */
    pi_mutex_lock( nspa_lock_of( bucket ) );

    seq = bucket->seq;
    /* Seqlock begin — odd = mutating. */
    __atomic_store_n( &bucket->seq, seq + 1, __ATOMIC_RELEASE );

    if (refcount == 0)
    {
        slot->device                = 0;
        slot->inode                 = 0;
        slot->refcount              = 0;
        slot->agg_existing_access   = 0;
        slot->agg_existing_sharing  = 0;
        slot->flags                 = 0;
        if (bucket->slot_count > 0) bucket->slot_count--;
    }
    else
    {
        if (slot->device == 0) bucket->slot_count++;
        slot->device                = device;
        slot->inode                 = inode_no;
        slot->refcount              = refcount;
        slot->agg_existing_access   = agg_existing_access;
        slot->agg_existing_sharing  = agg_existing_sharing;
        /* flags reserved for FILE_MAPPING_* tracking — Phase 3. */
    }

    /* Seqlock end — even = stable.  Pairs with client ACQUIRE-load. */
    __atomic_store_n( &bucket->seq, seq + 2, __ATOMIC_RELEASE );

    pi_mutex_unlock( nspa_lock_of( bucket ) );
}

DECL_HANDLER(nspa_get_inode_table)
{
    reply->fd_sent      = 0;
    reply->bucket_count = NSPA_INODE_BUCKETS;
    reply->table_size   = (unsigned int)sizeof(nspa_inode_table_shm_t);

    if (!nspa_inode_table_ensure()) return;

    if (send_client_fd( current->process, nspa_inode_table_fd, 0 ) == 0)
        reply->fd_sent = 1;
}
