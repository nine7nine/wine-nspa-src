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
#include <time.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
#include "wine/server.h"
#include "wine/debug.h"
#include "unix_private.h"

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
static const nspa_inode_table_shm_t *nspa_lf_table  = NULL;   /* mmap, READ-ONLY */
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

    map = mmap( NULL, table_size, PROT_READ, MAP_SHARED, fd, 0 );
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

    nspa_lf_table       = (const nspa_inode_table_shm_t *)map;
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
