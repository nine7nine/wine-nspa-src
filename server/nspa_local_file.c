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

#ifdef HAVE_SYS_MEMFD_H
# include <sys/memfd.h>
#endif

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
        t->magic        = NSPA_INODE_TABLE_MAGIC;
        t->version      = NSPA_INODE_TABLE_VERSION;
        t->bucket_count = NSPA_INODE_BUCKETS;
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

/* Slice-(a) accessors.  Slice (b) will add publish/unpublish that walk
 * inode->open and recompute aggregated state per the algorithm in
 * server/fd.c:check_sharing. */

DECL_HANDLER(nspa_get_inode_table)
{
    reply->fd_sent      = 0;
    reply->bucket_count = NSPA_INODE_BUCKETS;
    reply->table_size   = (unsigned int)sizeof(nspa_inode_table_shm_t);

    if (!nspa_inode_table_ensure()) return;

    if (send_client_fd( current->process, nspa_inode_table_fd, 0 ) == 0)
        reply->fd_sent = 1;
}
