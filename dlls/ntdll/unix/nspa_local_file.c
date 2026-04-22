/*
 * NSPA local-file bypass — Phase 1A.0 diagnostic scaffolding.
 *
 * Categorises every NtCreateFile invocation by bypass eligibility under
 * the MVP rules in nspa/docs/local-file-bypass-design.md.  No behaviour
 * change.  The dump tells us, per workload, what fraction of file opens
 * could land on the future client-side fast path before any bypass code
 * is built.  Runs the same diag-first discipline as the hook-chain
 * categoriser (feedback_diag_first_for_bypass.md).
 *
 * Counter mutation is __atomic_fetch_add (relaxed); dump runs every 5 s
 * from a background thread + once at atexit, both gated on
 * NSPA_SEND_DIAG=1.  Output: /tmp/nspa_local_file_diag.<pid>.log
 */
#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/list.h"
#include "wine/server.h"
#include "wine/debug.h"
#include "unix_private.h"
#include <rtpi.h>

WINE_DEFAULT_DEBUG_CHANNEL(nspa_lfile);

/* Counter set — mirrors the eligibility checks in the categoriser
 * below.  ineligible_* are mutually exclusive: each ineligible call
 * bumps exactly one ineligible_* counter (the first failing condition
 * in priority order). */
static unsigned long long nspa_lf_top_calls;
static unsigned long long nspa_lf_eligible;
static unsigned long long nspa_lf_inelig_no_attr;
static unsigned long long nspa_lf_inelig_rootdir;
static unsigned long long nspa_lf_inelig_security_descriptor;
static unsigned long long nspa_lf_inelig_disposition_not_open;
static unsigned long long nspa_lf_inelig_directory;
static unsigned long long nspa_lf_inelig_delete_on_close;
static unsigned long long nspa_lf_inelig_open_by_id;
static unsigned long long nspa_lf_inelig_reparse_point;
static unsigned long long nspa_lf_inelig_write_access;
static unsigned long long nspa_lf_inelig_other_options;

static time_t nspa_lf_diag_start_epoch;

/* ---------------------------------------------------------------------
 * Phase 1A.1.c — client-side reader for the shared inode-table.
 *
 * We lazily fetch the table fd via the nspa_get_inode_table request on
 * first need, mmap it READ-ONLY, validate its magic + version, then
 * provide a seqlock-protected lookup API.  Lookup never blocks: on any
 * mid-write seq mismatch we retry up to a small bound, then fall back
 * to "not found" (caller treats as "no entry → can't bypass, use
 * server").  No allocation on the read path.
 *
 * This slice exposes the lookup but does not yet integrate it into
 * NtCreateFile.  The diag dump grows a [shared inode-table] section
 * showing whether the region is mapped and how many slots are
 * populated, so we can confirm publish/read works end-to-end before
 * 1A.2 wires in the bypass dispatch. */

static pthread_once_t           nspa_lf_table_once  = PTHREAD_ONCE_INIT;
static nspa_inode_table_shm_t  *nspa_lf_table       = NULL;   /* mmap RW (clients write own subentry under PI lock) */
static size_t                   nspa_lf_table_size  = 0;
static int                      nspa_lf_table_state = 0;      /* 0=untried, 1=ok, -1=failed */
/* Counters for the diag dump — show that the lookup path is exercised. */
static unsigned long long       nspa_lf_lookup_attempt;
static unsigned long long       nspa_lf_lookup_hit;
static unsigned long long       nspa_lf_lookup_miss;
static unsigned long long       nspa_lf_lookup_seq_retry;

static void nspa_lf_table_open_once_fn( void )
{
    int fd = -1;
    void *map;
    obj_handle_t fd_handle = 0;
    unsigned int bucket_count = 0, table_size = 0;
    int fd_sent = 0;

    SERVER_START_REQ( nspa_get_inode_table )
    {
        if (!wine_server_call( req ))
        {
            fd_sent      = reply->fd_sent;
            bucket_count = reply->bucket_count;
            table_size   = reply->table_size;
        }
    }
    SERVER_END_REQ;

    if (!fd_sent || bucket_count != NSPA_INODE_BUCKETS || !table_size)
    {
        nspa_lf_table_state = -1;
        return;
    }

    fd = wine_server_receive_fd( &fd_handle );
    if (fd < 0)
    {
        nspa_lf_table_state = -1;
        return;
    }

    /* PROT_READ | PROT_WRITE: clients write their own subentry slots
     * (Phase 1A.2.c+) under the shmem-resident per-bucket PI mutex.
     * Reads remain seqlock-protected. */
    map = mmap( NULL, table_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 );
    close( fd );  /* mmap holds the page mapping; the fd is no longer needed */
    if (map == MAP_FAILED)
    {
        nspa_lf_table_state = -1;
        return;
    }

    {
        const nspa_inode_table_shm_t *t = map;
        if (t->magic != NSPA_INODE_TABLE_MAGIC ||
            t->version != NSPA_INODE_TABLE_VERSION ||
            t->bucket_count != NSPA_INODE_BUCKETS)
        {
            munmap( map, table_size );
            nspa_lf_table_state = -1;
            return;
        }
    }

    nspa_lf_table       = (nspa_inode_table_shm_t *)map;
    nspa_lf_table_size  = table_size;
    nspa_lf_table_state = 1;
    TRACE( "NSPA local-file table: mmap ok, %u buckets × %u slots = %zu bytes\n",
           NSPA_INODE_BUCKETS, NSPA_INODE_SLOTS_PER_BUCKET, (size_t)table_size );
}

static void nspa_lf_table_open_lazy( void )
{
    pthread_once( &nspa_lf_table_once, nspa_lf_table_open_once_fn );
}

/* Same hash as server/nspa_local_file.c:nspa_inode_table_bucket — must
 * stay byte-identical to the server's bucket selection. */
static unsigned int nspa_lf_bucket_index( unsigned long long device, unsigned long long inode )
{
    unsigned long long h = device * 0x9E3779B97F4A7C15ull + inode;
    h ^= h >> 33;
    h *= 0xFF51AFD7ED558CCDull;
    h ^= h >> 33;
    return (unsigned int)(h & (NSPA_INODE_BUCKETS - 1));
}

/* Seqlock read.  Returns 1 + fills *out on hit; 0 on miss/unavailable.
 * No locks taken — bounded retry on mid-write seq mismatch.  Safe to
 * call from RT context. */
int nspa_local_file_table_lookup( unsigned long long device, unsigned long long inode,
                                  nspa_inode_slot_t *out )
{
    const nspa_inode_bucket_t *bucket;
    unsigned int seq_before, seq_after, i;
    int retries = 8;

    nspa_lf_table_open_lazy();
    if (nspa_lf_table_state != 1) return 0;

    __atomic_fetch_add( &nspa_lf_lookup_attempt, 1, __ATOMIC_RELAXED );

    bucket = &nspa_lf_table->buckets[ nspa_lf_bucket_index( device, inode ) ];

    while (retries-- > 0)
    {
        nspa_inode_slot_t snapshot;

        seq_before = __atomic_load_n( &bucket->seq, __ATOMIC_ACQUIRE );
        if (seq_before & 1u) continue;   /* writer in progress */

        for (i = 0; i < NSPA_INODE_SLOTS_PER_BUCKET; i++)
        {
            if (bucket->slots[i].device == device && bucket->slots[i].inode == inode)
            {
                snapshot = (nspa_inode_slot_t)bucket->slots[i];   /* copy */
                seq_after = __atomic_load_n( &bucket->seq, __ATOMIC_ACQUIRE );
                if (seq_after == seq_before)
                {
                    *out = snapshot;
                    __atomic_fetch_add( &nspa_lf_lookup_hit, 1, __ATOMIC_RELAXED );
                    return 1;
                }
                __atomic_fetch_add( &nspa_lf_lookup_seq_retry, 1, __ATOMIC_RELAXED );
                goto retry;
            }
        }

        /* Slot for (device, inode) not in bucket.  Verify seq stable
         * before declaring miss (bucket may have been mid-rewrite). */
        seq_after = __atomic_load_n( &bucket->seq, __ATOMIC_ACQUIRE );
        if (seq_after == seq_before)
        {
            __atomic_fetch_add( &nspa_lf_lookup_miss, 1, __ATOMIC_RELAXED );
            return 0;
        }
        __atomic_fetch_add( &nspa_lf_lookup_seq_retry, 1, __ATOMIC_RELAXED );
    retry:
        ;
    }

    /* Retry exhaustion — extremely rare (would require a writer
     * pinning the bucket faster than we can read).  Treat as miss;
     * caller falls back to server. */
    __atomic_fetch_add( &nspa_lf_lookup_miss, 1, __ATOMIC_RELAXED );
    return 0;
}

/* Standard read access subset — see local-file-bypass-design.md.  Anything
 * outside this is "write or special access" → ineligible for MVP. */
#define NSPA_LF_STD_READ_ACCESS \
    (FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | \
     READ_CONTROL | SYNCHRONIZE | GENERIC_READ)

/* Options that disqualify even within FILE_OPEN read.  FILE_DIRECTORY_FILE
 * and FILE_DELETE_ON_CLOSE get their own counters; everything else here
 * is collapsed under "other_options".  Only options that have semantic
 * implications the bypass would mishandle are listed; advisory hints
 * (RANDOM_ACCESS, SEQUENTIAL_ONLY) are intentionally NOT here. */
#define NSPA_LF_DISQUALIFYING_OPTIONS \
    (FILE_NO_INTERMEDIATE_BUFFERING | FILE_WRITE_THROUGH | \
     FILE_OPEN_FOR_BACKUP_INTENT | FILE_RESERVE_OPFILTER | \
     FILE_COMPLETE_IF_OPLOCKED)

/* Forward decl — implementation appears later in the file (Slice 1A.1.c). */
static void nspa_lf_table_open_lazy( void );

void nspa_local_file_diag_categorize( const OBJECT_ATTRIBUTES *attr, ACCESS_MASK access,
                                      ULONG sharing, ULONG disposition, ULONG options )
{
    __atomic_fetch_add( &nspa_lf_top_calls, 1, __ATOMIC_RELAXED );

    /* Trigger lazy mmap of the shared inode-table from a real Wine
     * thread context (NtCreateFile is always called from one).  The
     * background diag thread that dumps counters never calls server
     * RPCs, so it safely inspects whatever state the open reached. */
    nspa_lf_table_open_lazy();

    if (!attr || !attr->ObjectName)
    {
        __atomic_fetch_add( &nspa_lf_inelig_no_attr, 1, __ATOMIC_RELAXED );
        return;
    }
    if (attr->RootDirectory)
    {
        __atomic_fetch_add( &nspa_lf_inelig_rootdir, 1, __ATOMIC_RELAXED );
        return;
    }
    if (attr->SecurityDescriptor)
    {
        __atomic_fetch_add( &nspa_lf_inelig_security_descriptor, 1, __ATOMIC_RELAXED );
        return;
    }
    if (disposition != FILE_OPEN)
    {
        __atomic_fetch_add( &nspa_lf_inelig_disposition_not_open, 1, __ATOMIC_RELAXED );
        return;
    }
    if (options & FILE_OPEN_BY_FILE_ID)
    {
        __atomic_fetch_add( &nspa_lf_inelig_open_by_id, 1, __ATOMIC_RELAXED );
        return;
    }
    if (options & FILE_DIRECTORY_FILE)
    {
        __atomic_fetch_add( &nspa_lf_inelig_directory, 1, __ATOMIC_RELAXED );
        return;
    }
    if (options & FILE_DELETE_ON_CLOSE)
    {
        __atomic_fetch_add( &nspa_lf_inelig_delete_on_close, 1, __ATOMIC_RELAXED );
        return;
    }
    if (options & FILE_OPEN_REPARSE_POINT)
    {
        __atomic_fetch_add( &nspa_lf_inelig_reparse_point, 1, __ATOMIC_RELAXED );
        return;
    }
    if (access & ~NSPA_LF_STD_READ_ACCESS)
    {
        __atomic_fetch_add( &nspa_lf_inelig_write_access, 1, __ATOMIC_RELAXED );
        return;
    }
    if (options & NSPA_LF_DISQUALIFYING_OPTIONS)
    {
        __atomic_fetch_add( &nspa_lf_inelig_other_options, 1, __ATOMIC_RELAXED );
        return;
    }

    (void)sharing;   /* sharing is always permitted in MVP — table makes it safe */
    __atomic_fetch_add( &nspa_lf_eligible, 1, __ATOMIC_RELAXED );
}

static void nspa_lf_diag_dump( void )
{
    char path[128];
    char tmp[128];
    FILE *f;
    time_t now;
    unsigned long long top   = __atomic_load_n( &nspa_lf_top_calls,                   __ATOMIC_RELAXED );
    unsigned long long elig  = __atomic_load_n( &nspa_lf_eligible,                    __ATOMIC_RELAXED );
    unsigned long long noa   = __atomic_load_n( &nspa_lf_inelig_no_attr,              __ATOMIC_RELAXED );
    unsigned long long rd    = __atomic_load_n( &nspa_lf_inelig_rootdir,              __ATOMIC_RELAXED );
    unsigned long long sd    = __atomic_load_n( &nspa_lf_inelig_security_descriptor,  __ATOMIC_RELAXED );
    unsigned long long dno   = __atomic_load_n( &nspa_lf_inelig_disposition_not_open, __ATOMIC_RELAXED );
    unsigned long long dir   = __atomic_load_n( &nspa_lf_inelig_directory,            __ATOMIC_RELAXED );
    unsigned long long doc   = __atomic_load_n( &nspa_lf_inelig_delete_on_close,      __ATOMIC_RELAXED );
    unsigned long long obi   = __atomic_load_n( &nspa_lf_inelig_open_by_id,           __ATOMIC_RELAXED );
    unsigned long long rp    = __atomic_load_n( &nspa_lf_inelig_reparse_point,        __ATOMIC_RELAXED );
    unsigned long long wa    = __atomic_load_n( &nspa_lf_inelig_write_access,         __ATOMIC_RELAXED );
    unsigned long long oo    = __atomic_load_n( &nspa_lf_inelig_other_options,        __ATOMIC_RELAXED );

    if (!getenv("NSPA_SEND_DIAG")) return;
    snprintf(tmp,  sizeof(tmp),  "/tmp/nspa_local_file_diag.%d.log.tmp", (int)getpid());
    snprintf(path, sizeof(path), "/tmp/nspa_local_file_diag.%d.log",     (int)getpid());
    f = fopen(tmp, "w");
    if (!f) return;
    now = time( NULL );
    fprintf(f, "NSPA local-file diagnostic  pid=%d  elapsed_s=%lld\n",
            (int)getpid(), (long long)(now - nspa_lf_diag_start_epoch));
    fprintf(f, "----\n");
    fprintf(f, "[NtCreateFile]\n");
    fprintf(f, "  top_calls                       %llu\n", top);
    fprintf(f, "  >>> ELIGIBLE_FOR_BYPASS         %llu  (%.1f%% of top_calls)\n", elig,
            top ? 100.0 * (double)elig / (double)top : 0.0);
    fprintf(f, "\n[ineligibility breakdown]\n");
    fprintf(f, "  no_attr                         %llu\n", noa);
    fprintf(f, "  rootdir                         %llu\n", rd);
    fprintf(f, "  security_descriptor             %llu\n", sd);
    fprintf(f, "  disposition_not_open            %llu\n", dno);
    fprintf(f, "  directory                       %llu\n", dir);
    fprintf(f, "  delete_on_close                 %llu\n", doc);
    fprintf(f, "  open_by_file_id                 %llu\n", obi);
    fprintf(f, "  open_reparse_point              %llu\n", rp);
    fprintf(f, "  write_or_special_access         %llu\n", wa);
    fprintf(f, "  other_disqualifying_options     %llu\n", oo);

    /* Slice 1A.1.c verification — show shared-table state from this
     * client's view.  Counts populated slots so we can confirm server
     * publish reaches us.  No bypass dispatch is wired yet (1A.2). */
    {
        unsigned long long la = __atomic_load_n( &nspa_lf_lookup_attempt,   __ATOMIC_RELAXED );
        unsigned long long lh = __atomic_load_n( &nspa_lf_lookup_hit,       __ATOMIC_RELAXED );
        unsigned long long lm = __atomic_load_n( &nspa_lf_lookup_miss,      __ATOMIC_RELAXED );
        unsigned long long ls = __atomic_load_n( &nspa_lf_lookup_seq_retry, __ATOMIC_RELAXED );
        unsigned int populated_buckets = 0;
        unsigned int populated_slots   = 0;

        /* Don't trigger lazy open from the dump — it runs on a non-Wine
         * background thread that can't safely issue server RPCs.  Just
         * inspect whatever state nspa_local_file_diag_categorize() has
         * reached on the real Wine thread side. */
        fprintf(f, "\n[shared inode-table]\n");
        fprintf(f, "  state                           %s\n",
                nspa_lf_table_state == 1 ? "MAPPED" :
                nspa_lf_table_state == -1 ? "UNAVAILABLE" : "UNTRIED");
        if (nspa_lf_table_state == 1 && nspa_lf_table)
        {
            unsigned int b, s;
            for (b = 0; b < NSPA_INODE_BUCKETS; b++)
            {
                int has_any = 0;
                unsigned int seq = __atomic_load_n( &nspa_lf_table->buckets[b].seq,
                                                    __ATOMIC_ACQUIRE );
                if (seq & 1u) continue;   /* mid-write — skip for inspect */
                for (s = 0; s < NSPA_INODE_SLOTS_PER_BUCKET; s++)
                {
                    if (nspa_lf_table->buckets[b].slots[s].device != 0)
                    {
                        populated_slots++;
                        has_any = 1;
                    }
                }
                if (has_any) populated_buckets++;
            }
            fprintf(f, "  populated_buckets               %u / %u\n",
                    populated_buckets, NSPA_INODE_BUCKETS);
            fprintf(f, "  populated_slots                 %u\n", populated_slots);
        }
        fprintf(f, "  lookup_attempt                  %llu\n", la);
        fprintf(f, "  lookup_hit                      %llu\n", lh);
        fprintf(f, "  lookup_miss                     %llu\n", lm);
        fprintf(f, "  lookup_seq_retry                %llu\n", ls);
    }

    fclose(f);
    rename(tmp, path);
}

static void *nspa_lf_diag_thread_main( void *arg )
{
    (void)arg;
    for (;;)
    {
        struct timespec ts = { 5, 0 };
        nanosleep( &ts, NULL );
        nspa_lf_diag_dump();
    }
    return NULL;
}

static pthread_once_t nspa_lf_diag_start_once = PTHREAD_ONCE_INIT;

static void nspa_lf_diag_start_once_fn( void )
{
    pthread_t th;
    nspa_lf_diag_start_epoch = time( NULL );
    atexit( nspa_lf_diag_dump );
    if (pthread_create( &th, NULL, nspa_lf_diag_thread_main, NULL ) == 0)
        pthread_detach( th );
    TRACE( "NSPA local-file diag: started, dumps to /tmp/nspa_local_file_diag.<pid>.log when NSPA_SEND_DIAG=1\n" );
}

void nspa_local_file_diag_lazy_start( void )
{
    pthread_once( &nspa_lf_diag_start_once, nspa_lf_diag_start_once_fn );
}

/* ---------------------------------------------------------------------
 * Phase 1A.2.c — client-side publish API + per-process file table.
 *
 * Per-process file table tracks every file that THIS Wine process has
 * opened locally via the bypass.  Required because publish_close needs
 * to recompute this process's contribution from its remaining opens
 * (sharing aggregation cannot be undone by simple subtraction).
 *
 * Cross-process write coordination: the per-bucket PI mutex landed in
 * 1A.2.a is acquired before any slot mutation.  The seqlock around
 * the slot still bumps on writes so lock-free readers see consistent
 * snapshots.  Server publishes to subentry[0] (its view); each client
 * gets one subentry[1..N-1] keyed by its own pid. */

struct nspa_local_open
{
    struct list       entry;
    HANDLE            handle;
    int               unix_fd;
    unsigned long long device;
    unsigned long long inode;
    unsigned int      access;
    unsigned int      sharing;
};

static struct list      nspa_lf_opens          = LIST_INIT(nspa_lf_opens);
static pthread_mutex_t  nspa_lf_opens_mutex    = PTHREAD_MUTEX_INITIALIZER;

/* Linux-only TID-cached pid via getpid().  pid is process-wide so we
 * cache it in a static after first call. */
static unsigned int nspa_lf_self_pid( void )
{
    static unsigned int cached;
    if (!cached) cached = (unsigned int)getpid();
    return cached;
}

/* Cast shmem-resident pi_mutex_t storage to a usable pi_mutex_t.
 * Storage is 64 bytes inline in the bucket; pi_mutex_t is also 64
 * bytes (cacheline-isolated).  See server/nspa_local_file.c for the
 * matching server-side cast. */
static inline pi_mutex_t *nspa_lf_lock_of( nspa_inode_bucket_t *bucket )
{
    return (pi_mutex_t *)bucket->lock.storage;
}

/* Find a writable bucket pointer for (device, inode).  Returns NULL if
 * the table isn't mapped. */
static nspa_inode_bucket_t *nspa_lf_bucket_for( unsigned long long device,
                                                unsigned long long inode )
{
    if (nspa_lf_table_state != 1 || !nspa_lf_table) return NULL;
    return (nspa_inode_bucket_t *)&nspa_lf_table->buckets[
        nspa_lf_bucket_index( device, inode ) ];
}

/* Walk this process's file table to recompute the aggregated contribution
 * for one (device, inode).  Caller holds nspa_lf_opens_mutex.  Output
 * parameters: *refcount, *agg_access, *agg_sharing. */
static void nspa_lf_recompute_local_aggregate( unsigned long long device,
                                               unsigned long long inode,
                                               unsigned int *refcount,
                                               unsigned int *agg_access,
                                               unsigned int *agg_sharing )
{
    const unsigned int read_access  = FILE_READ_DATA | FILE_EXECUTE;
    const unsigned int write_access = FILE_WRITE_DATA | FILE_APPEND_DATA;
    const unsigned int all_access   = read_access | write_access | DELETE;
    struct nspa_local_open *o;
    unsigned int rc = 0, ax = 0, sh = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    LIST_FOR_EACH_ENTRY( o, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (o->device != device || o->inode != inode) continue;
        rc++;
        if (o->access & all_access) sh &= o->sharing;
        ax |= o->access;
    }

    *refcount    = rc;
    *agg_access  = ax;
    *agg_sharing = sh;
}

/* Publish that this process has just opened a new fd for (device, inode)
 * with the given access/sharing.  Does NOT add the fd to the per-process
 * file table — caller is responsible for that ordering (publish first
 * so other processes see the new state, then bump local table).  In
 * Phase 1A.2.d the NtCreateFile bypass dispatch will sequence both. */
NTSTATUS nspa_local_file_publish_open( unsigned long long device, unsigned long long inode,
                                       unsigned int access, unsigned int sharing )
{
    nspa_inode_bucket_t *bucket;
    int slot_idx = -1;
    int empty_slot_idx = -1;
    int sub_idx = -1;
    int empty_sub_idx = -1;
    unsigned int i, seq;
    unsigned int my_pid;
    nspa_inode_slot_t *slot;
    const unsigned int all_access = FILE_READ_DATA | FILE_EXECUTE
                                  | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE;

    if (!(bucket = nspa_lf_bucket_for( device, inode ))) return STATUS_NOT_SUPPORTED;
    my_pid = nspa_lf_self_pid();

    pi_mutex_lock( nspa_lf_lock_of( bucket ) );

    /* Find slot for (device, inode) or note empty. */
    for (i = 0; i < NSPA_INODE_SLOTS_PER_BUCKET; i++)
    {
        if (bucket->slots[i].device == device && bucket->slots[i].inode == inode)
        {
            slot_idx = (int)i;
            break;
        }
        if (bucket->slots[i].device == 0 && empty_slot_idx < 0)
            empty_slot_idx = (int)i;
    }
    if (slot_idx < 0)
    {
        if (empty_slot_idx < 0)
        {
            /* Bucket overflow — caller falls back to server. */
            pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        slot_idx = empty_slot_idx;
    }
    slot = (nspa_inode_slot_t *)&bucket->slots[slot_idx];

    /* Find my subentry (pids[i] == my_pid) or an empty client subentry
     * (pids[i] == 0 in indices 1..N-1; index 0 is the server slot). */
    for (i = 1; i < NSPA_INODE_SUBENTRIES; i++)
    {
        if (slot->pids[i] == my_pid)
        {
            sub_idx = (int)i;
            break;
        }
        if (slot->pids[i] == 0 && empty_sub_idx < 0)
            empty_sub_idx = (int)i;
    }
    if (sub_idx < 0)
    {
        if (empty_sub_idx < 0)
        {
            /* Subentry overflow — too many client procs hold this inode.
             * Caller falls back to server. */
            pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        sub_idx = empty_sub_idx;
    }

    seq = bucket->seq;
    __atomic_store_n( &bucket->seq, seq + 1, __ATOMIC_RELEASE );

    if (slot->device == 0)
    {
        /* New slot — initialise key fields. */
        slot->device = device;
        slot->inode  = inode;
        slot->flags  = 0;
        bucket->slot_count++;
    }

    if (slot->pids[sub_idx] != my_pid)
    {
        /* New subentry for our pid. */
        slot->pids[sub_idx]         = my_pid;
        slot->sub_refcount[sub_idx] = 1;
        slot->sub_access[sub_idx]   = access;
        slot->sub_sharing[sub_idx]  = (access & all_access) ? sharing
                                      : (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    else
    {
        /* Adding another open in the same subentry — OR access, AND
         * sharing (for opens with access != 0).  Approximate but safe;
         * publish_close recomputes from the local file table for
         * accuracy. */
        slot->sub_refcount[sub_idx]++;
        slot->sub_access[sub_idx]  |= access;
        if (access & all_access)
            slot->sub_sharing[sub_idx] &= sharing;
    }

    __atomic_store_n( &bucket->seq, seq + 2, __ATOMIC_RELEASE );
    pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
    return STATUS_SUCCESS;
}

/* Publish that this process has closed an fd for (device, inode).
 * Recomputes our subentry's aggregate from our remaining local opens
 * (caller has already removed this open from the local table).  If our
 * subentry refcount drops to 0 the subentry is cleared; if no
 * subentries remain in use the slot is cleared. */
void nspa_local_file_publish_close( unsigned long long device, unsigned long long inode )
{
    nspa_inode_bucket_t *bucket;
    int slot_idx = -1;
    int sub_idx = -1;
    unsigned int i, seq;
    unsigned int my_pid;
    unsigned int new_refcount = 0, new_access = 0, new_sharing = 0;
    nspa_inode_slot_t *slot;

    if (!(bucket = nspa_lf_bucket_for( device, inode ))) return;
    my_pid = nspa_lf_self_pid();

    /* Recompute outside the bucket lock — accesses our local table only. */
    pthread_mutex_lock( &nspa_lf_opens_mutex );
    nspa_lf_recompute_local_aggregate( device, inode, &new_refcount, &new_access, &new_sharing );
    pthread_mutex_unlock( &nspa_lf_opens_mutex );

    pi_mutex_lock( nspa_lf_lock_of( bucket ) );

    for (i = 0; i < NSPA_INODE_SLOTS_PER_BUCKET; i++)
    {
        if (bucket->slots[i].device == device && bucket->slots[i].inode == inode)
        {
            slot_idx = (int)i;
            break;
        }
    }
    if (slot_idx < 0)
    {
        pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
        return;
    }
    slot = (nspa_inode_slot_t *)&bucket->slots[slot_idx];

    for (i = 1; i < NSPA_INODE_SUBENTRIES; i++)
    {
        if (slot->pids[i] == my_pid) { sub_idx = (int)i; break; }
    }
    if (sub_idx < 0)
    {
        pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
        return;
    }

    seq = bucket->seq;
    __atomic_store_n( &bucket->seq, seq + 1, __ATOMIC_RELEASE );

    if (new_refcount == 0)
    {
        /* This process has no more local opens for this inode — clear
         * our subentry. */
        slot->pids[sub_idx]         = 0;
        slot->sub_refcount[sub_idx] = 0;
        slot->sub_access[sub_idx]   = 0;
        slot->sub_sharing[sub_idx]  = 0;

        /* If the slot is fully empty (no server opens, no client opens),
         * clear it. */
        {
            int any = 0;
            unsigned int j;
            if (slot->sub_refcount[0] > 0) any = 1;
            for (j = 1; !any && j < NSPA_INODE_SUBENTRIES; j++)
                if (slot->pids[j] != 0) any = 1;
            if (!any)
            {
                slot->device = 0;
                slot->inode  = 0;
                slot->flags  = 0;
                if (bucket->slot_count > 0) bucket->slot_count--;
            }
        }
    }
    else
    {
        slot->sub_refcount[sub_idx] = new_refcount;
        slot->sub_access[sub_idx]   = new_access;
        slot->sub_sharing[sub_idx]  = new_sharing;
    }

    __atomic_store_n( &bucket->seq, seq + 2, __ATOMIC_RELEASE );
    pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
}

/* Add an open to the per-process file table.  Used by NtCreateFile
 * bypass dispatch in Phase 1A.2.d after a successful publish_open. */
NTSTATUS nspa_local_file_table_add( HANDLE handle, int unix_fd,
                                    unsigned long long device, unsigned long long inode,
                                    unsigned int access, unsigned int sharing )
{
    struct nspa_local_open *o = malloc( sizeof(*o) );
    if (!o) return STATUS_NO_MEMORY;
    o->handle  = handle;
    o->unix_fd = unix_fd;
    o->device  = device;
    o->inode   = inode;
    o->access  = access;
    o->sharing = sharing;
    pthread_mutex_lock( &nspa_lf_opens_mutex );
    list_add_head( &nspa_lf_opens, &o->entry );
    pthread_mutex_unlock( &nspa_lf_opens_mutex );
    return STATUS_SUCCESS;
}

/* Remove an open from the per-process file table.  Returns 1 + fills
 * out-params if the handle was tracked locally; 0 otherwise.  Used by
 * NtClose dispatch — caller invokes publish_close after this returns
 * 1 to update the shared subentry. */
int nspa_local_file_table_remove( HANDLE handle, int *unix_fd_out,
                                  unsigned long long *device_out,
                                  unsigned long long *inode_out )
{
    struct nspa_local_open *o, *next;
    int found = 0;

    pthread_mutex_lock( &nspa_lf_opens_mutex );
    LIST_FOR_EACH_ENTRY_SAFE( o, next, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (o->handle == handle)
        {
            *unix_fd_out = o->unix_fd;
            *device_out  = o->device;
            *inode_out   = o->inode;
            list_remove( &o->entry );
            free( o );
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock( &nspa_lf_opens_mutex );
    return found;
}

/* Look up a tracked handle's unix fd without removing it.  Returns -1
 * if not in the local table.  Used by NtReadFile/NtWriteFile dispatch
 * in Phase 1A.2.e. */
int nspa_local_file_table_lookup_unix_fd( HANDLE handle )
{
    struct nspa_local_open *o;
    int fd = -1;
    pthread_mutex_lock( &nspa_lf_opens_mutex );
    LIST_FOR_EACH_ENTRY( o, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (o->handle == handle) { fd = o->unix_fd; break; }
    }
    pthread_mutex_unlock( &nspa_lf_opens_mutex );
    return fd;
}

/* Replicates server/fd.c:check_sharing using slot subentries.  Called
 * by NtCreateFile bypass dispatch (Phase 1A.2.d) before opening locally.
 * Returns STATUS_SUCCESS if the new open with `my_access`/`my_sharing`
 * would not violate any existing open's sharing mode, or
 * STATUS_SHARING_VIOLATION otherwise. */
NTSTATUS nspa_local_file_check_sharing( unsigned long long device, unsigned long long inode,
                                        unsigned int my_access, unsigned int my_sharing )
{
    const unsigned int read_access  = FILE_READ_DATA | FILE_EXECUTE;
    const unsigned int write_access = FILE_WRITE_DATA | FILE_APPEND_DATA;
    const unsigned int all_access   = read_access | write_access | DELETE;
    nspa_inode_slot_t snapshot;
    unsigned int agg_access = 0;
    unsigned int agg_sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    unsigned int i;

    if (!nspa_local_file_table_lookup( device, inode, &snapshot ))
    {
        /* No existing opens — nothing to conflict with. */
        return STATUS_SUCCESS;
    }

    /* Walk subentries and merge in-use ones into the running aggregate. */
    for (i = 0; i < NSPA_INODE_SUBENTRIES; i++)
    {
        unsigned int in_use = (i == 0) ? (snapshot.sub_refcount[0] > 0)
                                       : (snapshot.pids[i] != 0);
        if (!in_use) continue;
        if (snapshot.sub_access[i] & all_access)
            agg_sharing &= snapshot.sub_sharing[i];
        agg_access |= snapshot.sub_access[i];
    }

    /* Now run the same algorithm as server/fd.c:check_sharing. */
    if (((my_access & read_access)  && !(agg_sharing & FILE_SHARE_READ)) ||
        ((my_access & write_access) && !(agg_sharing & FILE_SHARE_WRITE)) ||
        ((my_access & DELETE)       && !(agg_sharing & FILE_SHARE_DELETE)))
        return STATUS_SHARING_VIOLATION;

    if (!(my_access & all_access))
        return STATUS_SUCCESS;   /* zero-access opens ignore sharing */

    if (((agg_access & read_access)  && !(my_sharing & FILE_SHARE_READ)) ||
        ((agg_access & write_access) && !(my_sharing & FILE_SHARE_WRITE)) ||
        ((agg_access & DELETE)       && !(my_sharing & FILE_SHARE_DELETE)))
        return STATUS_SHARING_VIOLATION;

    return STATUS_SUCCESS;
}
