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

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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
#include "../unix_private.h"
#include "debug.h"
#include "close_queue.h"
#include <rtpi.h>

WINE_DEFAULT_DEBUG_CHANNEL(nspa_lfile);

/* Diagnostic infrastructure was removed 2026-04-28 — per
 * feedback_debug_off_means_off.md, in-process counters even when
 * gated had measurable RT-jitter cost.  Use bpftrace uprobes for
 * any future diagnostics (zero in-process overhead). */

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
static nspa_inode_table_t  *nspa_lf_table       = NULL;   /* mmap RW (clients write own subentry under PI lock) */
static size_t                   nspa_lf_table_size  = 0;
static int                      nspa_lf_table_state = 0;      /* 0=untried, 1=ok, -1=failed */

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
        const nspa_inode_table_t *t = map;
        if (t->magic != NSPA_INODE_TABLE_MAGIC ||
            t->version != NSPA_INODE_TABLE_VERSION ||
            t->bucket_count != NSPA_INODE_BUCKETS)
        {
            munmap( map, table_size );
            nspa_lf_table_state = -1;
            return;
        }
    }

    nspa_lf_table       = (nspa_inode_table_t *)map;
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


    bucket = &nspa_lf_table->buckets[ nspa_lf_bucket_index( device, inode ) ];

    while (retries-- > 0)
    {
        nspa_inode_slot_t snapshot;

        /* PAUSE per audit §4.1 — relieves SMT sibling pressure during
         * the seqlock retry; the loop is already bounded at 8 with an
         * RPC fallback. */
        __builtin_ia32_pause();

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
                    return 1;
                }
                goto retry;
            }
        }

        /* Slot for (device, inode) not in bucket.  Verify seq stable
         * before declaring miss (bucket may have been mid-rewrite). */
        seq_after = __atomic_load_n( &bucket->seq, __ATOMIC_ACQUIRE );
        if (seq_after == seq_before)
        {
            return 0;
        }
    retry:
        ;
    }

    /* Retry exhaustion — extremely rare (would require a writer
     * pinning the bucket faster than we can read).  Treat as miss;
     * caller falls back to server.  lookup_miss also bumped for
     * continuity with existing dump consumers; seq_exhausted is the
     * specific signal that the retry loop gave up. */
    return 0;
}

/* Standard read access subset — see local-file-bypass-design.md.  Anything
 * outside this is "write or special access" → ineligible for MVP. */
#define NSPA_LF_STD_READ_ACCESS \
    (FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | \
     READ_CONTROL | SYNCHRONIZE | GENERIC_READ)

/* Phase 2 write extension: data-write subset.  WRITE_DAC / WRITE_OWNER
 * (security-descriptor mutation) and DELETE (file deletion path)
 * remain server-mediated — clients with those bits fall back.
 * GENERIC_WRITE is included; try_bypass expands it into the bits below
 * before any sharing arbitration or storage. */
#define NSPA_LF_STD_WRITE_ACCESS \
    (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | \
     FILE_APPEND_DATA | GENERIC_WRITE)

/* Benign permission bits allowed alongside read/write access.  These
 * bits are stored on the handle's access mask but don't affect the
 * open path — their semantics fire on later operations (which promote
 * if needed):
 *   FILE_EXECUTE      = 0x20  ("execute" on file, "traverse" on dir).
 *                       Server's check_sharing treats it as read_access.
 *   FILE_DELETE_CHILD = 0x40  (right to delete children of a dir). */
#define NSPA_LF_STD_BENIGN_ACCESS \
    (FILE_EXECUTE | FILE_DELETE_CHILD)

/* Server-internal "magic" access bits for mapping arbitration.  Mirrors
 * server/file.h FILE_MAPPING_{WRITE,IMAGE,ACCESS} — duplicated here to
 * avoid pulling server headers into ntdll.  Server's
 * nspa_publish_inode_state walks inode->open and OR's every fd's access
 * into agg_access, so server-side mappings land in subentry[0]'s
 * sub_access.  PE-side sections (Phase B-G) publish the same bits into
 * their own subentry via nspa_local_file_aggregate_publish_mapping.
 * The bits overlap GENERIC_WRITE / READ / EXECUTE in raw client access,
 * but try_bypass strips GENERIC_* before storage so the only way these
 * bits appear in sub_access is via mapping-publish (server's or PE-side). */
#define NSPA_LF_FILE_MAPPING_WRITE  0x40000000u
#define NSPA_LF_FILE_MAPPING_IMAGE  0x80000000u
#define NSPA_LF_FILE_MAPPING_ACCESS 0x20000000u

/* Options that disqualify even within FILE_OPEN read.  FILE_DIRECTORY_FILE
 * and FILE_DELETE_ON_CLOSE get their own counters; everything else here
 * is collapsed under "other_options".  Only options that have semantic
 * implications the bypass would mishandle are listed; advisory hints
 * (RANDOM_ACCESS, SEQUENTIAL_ONLY) are intentionally NOT here.
 *
 * FILE_NON_DIRECTORY_FILE re-allowed in 1A.3: NtCreateSection now
 * promotes local handles to server-mediated sections via the
 * nspa_create_mapping_from_unix_fd handler. */
#define NSPA_LF_DISQUALIFYING_OPTIONS \
    (FILE_NO_INTERMEDIATE_BUFFERING | FILE_WRITE_THROUGH | \
     FILE_OPEN_FOR_BACKUP_INTENT | FILE_RESERVE_OPFILTER | \
     FILE_COMPLETE_IF_OPLOCKED)

/* Forward decl — implementation appears later in the file (Slice 1A.1.c). */
static void nspa_lf_table_open_lazy( void );


/* Dispatch-site categorise — single source of truth for whether an
 * NtCreateFile open is eligible for the local bypass.  Called from
 * dlls/ntdll/unix/file.c::NtCreateFile.  Returns TRUE if the open
 * passes the filter (caller should call try_bypass); FALSE if any
 * criterion rejects. */
BOOL nspa_local_file_disp_categorize( BOOL loader_open,
                                      const OBJECT_ATTRIBUTES *attr,
                                      ACCESS_MASK access,
                                      ULONG disposition,
                                      ULONG options )
{
    /* Lazy-init the inode table on first dispatch (pthread_once — first
     * call mmaps the shared region, all later calls are a single load
     * + branch on the once flag). */
    nspa_lf_table_open_lazy();

    if (loader_open) return FALSE;
    if (attr && attr->RootDirectory) return FALSE;
    if (attr && attr->SecurityDescriptor) return FALSE;
    /* Allowed dispositions:
     *   FILE_OPEN          — file must exist; existing-file path.
     *   FILE_OPEN_IF       — non-existent falls back to server.
     *   FILE_OVERWRITE     — existing-file path + O_TRUNC.
     *   FILE_CREATE        — alternate `openat(O_CREAT|O_EXCL) then
     *                         fstat then publish` ordering.
     *   FILE_OVERWRITE_IF  — stat-first dispatch: existing-file path
     *                         (O_TRUNC) or alternate-order (O_CREAT|
     *                         O_EXCL|O_TRUNC); io->Information set per
     *                         path.  TOCTOU between stat + openat
     *                         falls back gracefully.
     *   FILE_SUPERSEDE     — same shape as FILE_OVERWRITE_IF; differs
     *                         only in io->Information value (FILE_SUPERSEDED
     *                         vs FILE_OVERWRITTEN) on the existing-file
     *                         path.  Server's create_file (file.c:239-241)
     *                         uses identical Linux flags for both.
     */
    if (disposition != FILE_OPEN &&
        disposition != FILE_OPEN_IF &&
        disposition != FILE_OVERWRITE &&
        disposition != FILE_CREATE &&
        disposition != FILE_OVERWRITE_IF &&
        disposition != FILE_SUPERSEDE) return FALSE;
    if (options & FILE_OPEN_BY_FILE_ID) return FALSE;
    /* FILE_DIRECTORY_FILE is NOT excluded at the gate — try_bypass's
     * dir-mint path handles directory opens.  The gate only rejects
     * the inverse case (FILE_DIRECTORY_FILE on a regular-file path),
     * which try_bypass detects after stat() and falls back so the
     * server returns STATUS_NOT_A_DIRECTORY. */
    if (options & FILE_DELETE_ON_CLOSE) return FALSE;
    if (!(options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT))) return FALSE;
    /* Eligibility = read-class | write-class | benign-permission-bits.
     * WRITE_DAC, WRITE_OWNER (security descriptor mutation) and DELETE
     * (deletion semantics) are NOT in the union; opens with those bits
     * fall back. */
    if (access & ~(NSPA_LF_STD_READ_ACCESS | NSPA_LF_STD_WRITE_ACCESS |
                   NSPA_LF_STD_BENIGN_ACCESS)) return FALSE;
    return TRUE;
}

/* Categorise the outcome of a try_bypass call.  Diagnostic only. */






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
    HANDLE            handle;            /* local-range handle returned to app */
    HANDLE            server_handle;     /* lazy-promoted server handle, 0 if not yet promoted (1A.4) */
    int               unix_fd;
    unsigned long long device;
    unsigned long long inode;
    unsigned int      access;
    unsigned int      sharing;
    unsigned int      options;           /* FILE_OPEN options the app passed (FILE_SYNCHRONOUS_IO_NONALERT etc) */
    unsigned int      attributes;        /* ObjectAttributes->Attributes (OBJ_INHERIT etc) — forwarded on lazy promote */
    /* server_fd_type for this fd — FD_TYPE_FILE for regular files,
     * FD_TYPE_DIR for directories (directory bypass).  Returned by
     * nspa_local_file_try_get_unix_fd() so callers like
     * nt_to_unix_file_name_with_root() get the correct device-type
     * classification.  Without this, a directory handle returned via
     * the bypass would be classified as FD_TYPE_FILE and rejected
     * with STATUS_BAD_DEVICE_TYPE at file.c:3859 — breaking every
     * relative-path NtCreateFile that uses the dir as RootDirectory. */
    enum server_fd_type kind;
    /* Original NT path captured at try_bypass time.  Sent to the server
     * on lazy promotion so the promoted struct fd carries fd->nt_name —
     * required by GetFinalPathNameByHandle / FileNameInformation queries
     * apps run on the handle (e.g. Ableton .als loader). */
    WCHAR            *nt_name;           /* malloc'd; NULL if no name captured */
    USHORT            nt_name_len;       /* in bytes (matches UNICODE_STRING.Length) */
    /* Unix path captured at try_bypass time.  Stashed so SIF/FileBasic
     * (file.c:NtSetInformationFile) can resolve unix_name without
     * promote + get_handle_unix_name RPC.  Also usable by any future
     * call that needs the Unix path without a server roundtrip. */
    char             *unix_name;         /* malloc'd, NUL-terminated; NULL if not captured */
};

static struct list      nspa_lf_opens          = LIST_INIT(nspa_lf_opens);
/* PI mutex — per-process file table accessed from any thread including
 * RT-promoted ones (audio threads occasionally open/close files at
 * init / library scan).  PSHARED flag NOT set — process-local. */
static DEFINE_PI_MUTEX(nspa_lf_opens_mutex, 0);

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
    pi_mutex_lock( &nspa_lf_opens_mutex );
    nspa_lf_recompute_local_aggregate( device, inode, &new_refcount, &new_access, &new_sharing );
    pi_mutex_unlock( &nspa_lf_opens_mutex );

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
 * bypass dispatch in Phase 1A.2.d after a successful publish_open.
 * `kind` distinguishes regular files from directories (added 2026-04-28
 * for directory bypass — see struct nspa_local_open's kind field). */
NTSTATUS nspa_local_file_table_add( HANDLE handle, int unix_fd,
                                    unsigned long long device, unsigned long long inode,
                                    unsigned int access, unsigned int sharing,
                                    unsigned int options,
                                    unsigned int attributes,
                                    enum server_fd_type kind,
                                    const UNICODE_STRING *nt_name,
                                    const char *unix_name )
{
    struct nspa_local_open *o;

    /* NSPA Phase 3: pre-flush any pending async closes before allocating
     * a new LF entry.  This eliminates the "close-then-reopen-same-path"
     * race window — by the time we allocate, no deferred close still
     * holds the file open.  Cheap (no-op) when queue is empty. */
    nspa_close_queue_flush();

    o = malloc( sizeof(*o) );
    if (!o) return STATUS_NO_MEMORY;
    o->handle        = handle;
    o->server_handle = 0;          /* lazy-promoted on first server-needing op */
    o->unix_fd       = unix_fd;
    o->device        = device;
    o->inode         = inode;
    o->access        = access;
    o->sharing       = sharing;
    o->options       = options;
    o->attributes    = attributes;
    o->kind          = kind;
    o->nt_name       = NULL;
    o->nt_name_len   = 0;
    o->unix_name     = NULL;
    if (nt_name && nt_name->Buffer && nt_name->Length)
    {
        o->nt_name = malloc( nt_name->Length );
        if (o->nt_name)
        {
            memcpy( o->nt_name, nt_name->Buffer, nt_name->Length );
            o->nt_name_len = nt_name->Length;
        }
        /* malloc failure leaves nt_name NULL — promotion still works,
         * just without populated FileNameInformation.  Don't fail the
         * whole add. */
    }
    if (unix_name)
    {
        size_t un_len = strlen( unix_name );
        o->unix_name = malloc( un_len + 1 );
        if (o->unix_name)
            memcpy( o->unix_name, unix_name, un_len + 1 );
        /* malloc failure leaves unix_name NULL — accessor returns
         * NOT_SUPPORTED, caller falls back to promote + server RPC. */
    }
    pi_mutex_lock( &nspa_lf_opens_mutex );
    list_add_head( &nspa_lf_opens, &o->entry );
    pi_mutex_unlock( &nspa_lf_opens_mutex );
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

    pi_mutex_lock( &nspa_lf_opens_mutex );
    LIST_FOR_EACH_ENTRY_SAFE( o, next, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (o->handle == handle)
        {
            *unix_fd_out = o->unix_fd;
            *device_out  = o->device;
            *inode_out   = o->inode;
            list_remove( &o->entry );
            free( o->nt_name );
            free( o->unix_name );
            free( o );
            found = 1;
            break;
        }
    }
    pi_mutex_unlock( &nspa_lf_opens_mutex );
    return found;
}

/* Look up a tracked handle's unix fd without removing it.  Returns -1
 * if not in the local table.  Used by NtReadFile/NtWriteFile dispatch
 * in Phase 1A.2.e. */
int nspa_local_file_table_lookup_unix_fd( HANDLE handle )
{
    struct nspa_local_open *o;
    int fd = -1;
    pi_mutex_lock( &nspa_lf_opens_mutex );
    LIST_FOR_EACH_ENTRY( o, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (o->handle == handle) { fd = o->unix_fd; break; }
    }
    pi_mutex_unlock( &nspa_lf_opens_mutex );
    return fd;
}

/* Resolve the Unix path for an LF handle from the local table without
 * a server roundtrip.  Returns:
 *   STATUS_SUCCESS         + sets *unix_name_out to a malloc'd copy
 *                            (caller must free).  String is NUL-terminated.
 *   STATUS_NOT_SUPPORTED   handle isn't local-range, OR LF entry didn't
 *                            capture a unix_name (fall back to promote +
 *                            server_get_unix_name).
 *   STATUS_NO_MEMORY       malloc failed for the copy.
 * Used by NtSetInformationFile/FileBasicInformation to skip the
 * unconditional promote that fed get_handle_unix_name. */
NTSTATUS nspa_local_file_get_unix_name( HANDLE handle, char **unix_name_out )
{
    struct nspa_local_open *o;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    *unix_name_out = NULL;

    if (!nspa_local_file_is_local_handle( handle )) return STATUS_NOT_SUPPORTED;

    pi_mutex_lock( &nspa_lf_opens_mutex );
    LIST_FOR_EACH_ENTRY( o, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (o->handle != handle) continue;
        if (o->unix_name)
        {
            size_t len = strlen( o->unix_name );
            char *copy = malloc( len + 1 );
            if (copy)
            {
                memcpy( copy, o->unix_name, len + 1 );
                *unix_name_out = copy;
                status = STATUS_SUCCESS;
            }
            else status = STATUS_NO_MEMORY;
        }
        /* Found the entry but it has no unix_name (rare — early-table
         * entries from before this accessor existed, or malloc failure
         * during table_add).  status stays NOT_SUPPORTED. */
        break;
    }
    pi_mutex_unlock( &nspa_lf_opens_mutex );
    return status;
}

/* Phase H — cross-process mapping-bit publication for the LF aggregate.
 *
 * The aggregate's sub_access field already carries FILE_MAPPING_WRITE
 * (0x40000000), FILE_MAPPING_IMAGE (0x80000000), and FILE_MAPPING_ACCESS
 * (0x20000000) bits in the high range — server-side mappings publish
 * these via nspa_publish_inode_state walking inode->open
 * (server/fd.c:287).  PE-side section bypass (Phase A-G) needs the
 * matching publication channel: when a section is created from an LF
 * unix_fd without going through wineserver, server doesn't see the
 * mapping and other LF openers' check_sharing arbitration would miss
 * it (silent NT-semantic violation when they need
 * STATUS_SHARING_VIOLATION / STATUS_USER_MAPPED_FILE).
 *
 * This helper modifies ONLY the mapping bits in our process's
 * subentry (subentry[N=this-pid]).  File-access bits (FILE_READ_DATA
 * etc.) are managed by publish_open / publish_close and unchanged.
 *
 * Caller is the source of truth for the union of bits across the
 * caller's per-section bookkeeping — this helper just stamps that
 * union into the aggregate.  Pass mapping_bits=0 to clear.
 *
 * Returns:
 *   STATUS_SUCCESS                 — subentry updated, seqlock bumped.
 *   STATUS_NOT_SUPPORTED           — aggregate table not mapped, or
 *                                    bucket lookup failed (overflow).
 *   STATUS_NOT_FOUND               — no slot for (device, inode) or
 *                                    no subentry for this pid.  Caller
 *                                    must publish_open before calling.
 *
 * Invariants:
 *   - Only the three FILE_MAPPING_* bits are touched; other bits in
 *     sub_access[sub_idx] are preserved.
 *   - Seqlock bumped before+after the write, so lock-free readers
 *     see consistent state.
 *   - Bucket PI mutex held across the write; pairs with the existing
 *     publish_open / publish_close locking discipline. */
NTSTATUS nspa_local_file_aggregate_publish_mapping( unsigned long long device,
                                                    unsigned long long inode,
                                                    unsigned int mapping_bits )
{
    static const unsigned int MAPPING_MASK =
        NSPA_LF_FILE_MAPPING_WRITE | NSPA_LF_FILE_MAPPING_IMAGE | NSPA_LF_FILE_MAPPING_ACCESS;
    nspa_inode_bucket_t *bucket;
    int slot_idx = -1, sub_idx = -1;
    unsigned int i, seq, my_pid;
    nspa_inode_slot_t *slot;

    /* Defensive — caller may pass through extra bits, but only the
     * mapping bits should land in sub_access. */
    mapping_bits &= MAPPING_MASK;

    if (!(bucket = nspa_lf_bucket_for( device, inode ))) return STATUS_NOT_SUPPORTED;
    my_pid = nspa_lf_self_pid();

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
        return STATUS_NOT_FOUND;
    }
    slot = (nspa_inode_slot_t *)&bucket->slots[slot_idx];

    for (i = 1; i < NSPA_INODE_SUBENTRIES; i++)
    {
        if (slot->pids[i] == my_pid) { sub_idx = (int)i; break; }
    }
    if (sub_idx < 0)
    {
        pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
        return STATUS_NOT_FOUND;
    }

    seq = bucket->seq;
    __atomic_store_n( &bucket->seq, seq + 1, __ATOMIC_RELEASE );
    slot->sub_access[sub_idx] = (slot->sub_access[sub_idx] & ~MAPPING_MASK) | mapping_bits;
    __atomic_store_n( &bucket->seq, seq + 2, __ATOMIC_RELEASE );

    pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
    return STATUS_SUCCESS;
}

/* Phase 1A.4 fix: also return the options the file was opened with so
 * server_get_unix_fd can return them to NtReadFile/NtWriteFile.  Without
 * this, options=0 makes those functions treat sync handles (FILE_
 * SYNCHRONOUS_IO_NONALERT — set by the loader and most apps) as async,
 * breaking downstream callers that expect synchronous semantics. */
int nspa_local_file_table_lookup_full( HANDLE handle, int *unix_fd_out, unsigned int *options_out,
                                       enum server_fd_type *kind_out )
{
    struct nspa_local_open *o;
    int found = 0;
    pi_mutex_lock( &nspa_lf_opens_mutex );
    LIST_FOR_EACH_ENTRY( o, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (o->handle == handle)
        {
            if (unix_fd_out) *unix_fd_out = o->unix_fd;
            if (options_out) *options_out = o->options;
            if (kind_out)    *kind_out    = o->kind;
            found = 1;
            break;
        }
    }
    pi_mutex_unlock( &nspa_lf_opens_mutex );
    return found;
}

/* Compute aggregate from a slot snapshot.  Helper for the standalone
 * check_sharing API and the atomic check-and-publish path. */
static void nspa_lf_aggregate_from_slot( const nspa_inode_slot_t *slot,
                                         unsigned int *agg_access,
                                         unsigned int *agg_sharing )
{
    unsigned int ax = 0;
    unsigned int sh = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    const unsigned int read_access  = FILE_READ_DATA | FILE_EXECUTE;
    const unsigned int write_access = FILE_WRITE_DATA | FILE_APPEND_DATA;
    const unsigned int all_access   = read_access | write_access | DELETE;
    unsigned int i;

    for (i = 0; i < NSPA_INODE_SUBENTRIES; i++)
    {
        unsigned int in_use = (i == 0) ? (slot->sub_refcount[0] > 0)
                                       : (slot->pids[i] != 0);
        if (!in_use) continue;
        if (slot->sub_access[i] & all_access) sh &= slot->sub_sharing[i];
        ax |= slot->sub_access[i];
    }
    *agg_access  = ax;
    *agg_sharing = sh;
}

/* Apply the same algorithm as server/fd.c:check_sharing on aggregated
 * existing state.  Phase 2 write extension: takes my_open_flags so the
 * O_TRUNC vs FILE_MAPPING_ACCESS arbitration matches the server's
 * line-1820 check.  Returns STATUS_SHARING_VIOLATION,
 * STATUS_USER_MAPPED_FILE, STATUS_CANNOT_DELETE, or STATUS_SUCCESS. */
static NTSTATUS nspa_lf_check_sharing_algorithm( unsigned int existing_access,
                                                 unsigned int existing_sharing,
                                                 unsigned int my_access,
                                                 unsigned int my_sharing,
                                                 unsigned int my_options,
                                                 int my_open_flags )
{
    const unsigned int read_access  = FILE_READ_DATA | FILE_EXECUTE;
    const unsigned int write_access = FILE_WRITE_DATA | FILE_APPEND_DATA;
    const unsigned int all_access   = read_access | write_access | DELETE;

    if (((my_access & read_access)  && !(existing_sharing & FILE_SHARE_READ)) ||
        ((my_access & write_access) && !(existing_sharing & FILE_SHARE_WRITE)) ||
        ((my_access & DELETE)       && !(existing_sharing & FILE_SHARE_DELETE)))
        return STATUS_SHARING_VIOLATION;

    /* Sync-parity with server/fd.c::check_sharing lines 1815-1820.
     * Phase 1 (read-only): only FILE_MAPPING_WRITE was reachable
     * because LF eligibility excluded write/delete/trunc.  Phase 2
     * write extension allows FILE_WRITE_DATA and O_TRUNC, so the
     * three additional clauses below are now reachable. */
    if ((existing_access & NSPA_LF_FILE_MAPPING_WRITE) && !(my_sharing & FILE_SHARE_WRITE))
        return STATUS_SHARING_VIOLATION;
    if ((existing_access & NSPA_LF_FILE_MAPPING_IMAGE) && (my_access & FILE_WRITE_DATA))
        return STATUS_SHARING_VIOLATION;
    /* FILE_DELETE_ON_CLOSE remains in the eligibility deny-list (line
     * ~258), so the FILE_MAPPING_IMAGE && FILE_DELETE_ON_CLOSE clause
     * cannot fire here — keeping it as a defensive assert via the
     * options-bit check anyway, in case eligibility ever loosens. */
    if ((existing_access & NSPA_LF_FILE_MAPPING_IMAGE) && (my_options & FILE_DELETE_ON_CLOSE))
        return STATUS_CANNOT_DELETE;
    if ((existing_access & NSPA_LF_FILE_MAPPING_ACCESS) && (my_open_flags & O_TRUNC))
        return STATUS_USER_MAPPED_FILE;

    if (!(my_access & all_access))
        return STATUS_SUCCESS;   /* zero-access opens ignore sharing */

    if (((existing_access & read_access)  && !(my_sharing & FILE_SHARE_READ)) ||
        ((existing_access & write_access) && !(my_sharing & FILE_SHARE_WRITE)) ||
        ((existing_access & DELETE)       && !(my_sharing & FILE_SHARE_DELETE)))
        return STATUS_SHARING_VIOLATION;

    return STATUS_SUCCESS;
}

/* Replicates server/fd.c:check_sharing using slot subentries.  Called
 * by NtCreateFile bypass dispatch (Phase 1A.2.d) before opening locally.
 * Phase 2 write extension: takes my_options + my_open_flags so the
 * mapping/O_TRUNC arbitration matches server-side behavior. */
NTSTATUS nspa_local_file_check_sharing( unsigned long long device, unsigned long long inode,
                                        unsigned int my_access, unsigned int my_sharing,
                                        unsigned int my_options, int my_open_flags )
{
    nspa_inode_slot_t snapshot;
    unsigned int agg_access = 0;
    unsigned int agg_sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    if (!nspa_local_file_table_lookup( device, inode, &snapshot ))
        return STATUS_SUCCESS;   /* no existing opens */

    nspa_lf_aggregate_from_slot( &snapshot, &agg_access, &agg_sharing );
    return nspa_lf_check_sharing_algorithm( agg_access, agg_sharing, my_access, my_sharing,
                                            my_options, my_open_flags );
}

/* Atomic check-sharing + publish.  Used by NtCreateFile bypass dispatch
 * to close the TOCTOU window between the standalone check_sharing call
 * and the publish_open call — both happen under the bucket's PI mutex
 * in a single critical section.
 *
 * Returns STATUS_SUCCESS on accepted publish, STATUS_SHARING_VIOLATION
 * if the new open would conflict with existing opens, or
 * STATUS_INSUFFICIENT_RESOURCES on bucket / subentry overflow (caller
 * falls back to server). */
static NTSTATUS nspa_local_file_check_and_publish_open( unsigned long long device,
                                                        unsigned long long inode,
                                                        unsigned int access,
                                                        unsigned int sharing,
                                                        unsigned int options,
                                                        int open_flags )
{
    const unsigned int all_access = FILE_READ_DATA | FILE_EXECUTE
                                  | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE;
    nspa_inode_bucket_t *bucket;
    int slot_idx = -1, empty_slot_idx = -1, sub_idx = -1, empty_sub_idx = -1;
    unsigned int i, seq, my_pid;
    unsigned int existing_access = 0, existing_sharing = 0;
    nspa_inode_slot_t *slot;
    NTSTATUS status;

    if (!(bucket = nspa_lf_bucket_for( device, inode ))) return STATUS_NOT_SUPPORTED;
    my_pid = nspa_lf_self_pid();

    pi_mutex_lock( nspa_lf_lock_of( bucket ) );

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

    /* Compute existing aggregate from current slot state, if any. */
    if (slot_idx >= 0)
    {
        nspa_inode_slot_t snap = (nspa_inode_slot_t)bucket->slots[slot_idx];
        nspa_lf_aggregate_from_slot( &snap, &existing_access, &existing_sharing );
        status = nspa_lf_check_sharing_algorithm( existing_access, existing_sharing,
                                                  access, sharing, options, open_flags );
        if (status != STATUS_SUCCESS)
        {
            pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
            return status;
        }
    }
    /* If slot_idx < 0, no existing entry → no possible conflict. */

    if (slot_idx < 0)
    {
        if (empty_slot_idx < 0)
        {
            pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        slot_idx = empty_slot_idx;
    }
    slot = (nspa_inode_slot_t *)&bucket->slots[slot_idx];

    for (i = 1; i < NSPA_INODE_SUBENTRIES; i++)
    {
        if (slot->pids[i] == my_pid) { sub_idx = (int)i; break; }
        if (slot->pids[i] == 0 && empty_sub_idx < 0) empty_sub_idx = (int)i;
    }
    if (sub_idx < 0)
    {
        if (empty_sub_idx < 0)
        {
            pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        sub_idx = empty_sub_idx;
    }

    seq = bucket->seq;
    __atomic_store_n( &bucket->seq, seq + 1, __ATOMIC_RELEASE );

    if (slot->device == 0)
    {
        slot->device = device;
        slot->inode  = inode;
        slot->flags  = 0;
        bucket->slot_count++;
    }
    if (slot->pids[sub_idx] != my_pid)
    {
        slot->pids[sub_idx]         = my_pid;
        slot->sub_refcount[sub_idx] = 1;
        slot->sub_access[sub_idx]   = access;
        slot->sub_sharing[sub_idx]  = (access & all_access) ? sharing
                                      : (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    else
    {
        slot->sub_refcount[sub_idx]++;
        slot->sub_access[sub_idx]  |= access;
        if (access & all_access) slot->sub_sharing[sub_idx] &= sharing;
    }

    __atomic_store_n( &bucket->seq, seq + 2, __ATOMIC_RELEASE );
    pi_mutex_unlock( nspa_lf_lock_of( bucket ) );
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------------
 * Phase 1A.2.d — handle minting + bypass dispatch + NtClose routing.
 *
 * Local file handles use a dedicated range above CLIENT_HANDLE_BASE
 * (sync.c) so they don't collide with NTSync handles or server handles.
 * Bump allocator with a per-process free list for closed handles. */

#define NSPA_LF_HANDLE_CAP        4096
#define NSPA_LF_HANDLE_BASE_OFF   1024     /* offset above the first NTSync client handle */

/* Cache the LOCAL_FILE_HANDLE_BASE on first use so we don't have to
 * include sync.c internals here.  We just need a number that is below
 * CLIENT_HANDLE_BASE but high enough to never collide with server-
 * allocated handles.  The exact value isn't load-bearing — the
 * is_local_file_handle check uses our own range table. */
/* Use a high fixed base.  Server handles start at 0x4 and grow; the
 * NTSync client range starts near INPROC_SYNC_CACHE_TOTAL.  Pick a
 * range disjoint from both: fixed bottom at 0x80000000 - cap*4.
 *
 * Initialised at declaration (constant expression) — previously lazy-
 * inited via pthread_once inside nspa_lf_alloc_handle, but that left
 * nspa_lf_handle_base = 0 until the first mint.  is_local_handle uses
 * `v < base` as its lower-bound check: with base=0 that's always false
 * for any positive handle, so any server handle < NSPA_LF_HANDLE_CAP*4
 * (16384) got classified as local-range before any LF mint happened.
 * Small server handles like stdio (0x14/0x18) fall in that range, and
 * e.g. the alloc_handle_list promotion path would then fire the LF
 * table lookup + lock on every PS_ATTRIBUTE_HANDLE_LIST entry — a
 * no-op but with enough contention to show as a visible menu flash on
 * CreateProcess-adjacent paths. */
static unsigned int nspa_lf_handle_base = 0x80000000u - NSPA_LF_HANDLE_CAP * 4;
static int          nspa_lf_handles_in_use[NSPA_LF_HANDLE_CAP];   /* 1 if allocated */
static unsigned int nspa_lf_handle_next;
/* PI mutex — handle allocator can be hit from RT threads. */
static DEFINE_PI_MUTEX(nspa_lf_handle_mutex, 0);

/* ABA properties (audited 2026-04-24, Item 6 of bypass-hardening-notes.md):
 *
 * Encoded HANDLE is nspa_lf_handle_base + slot*4 — no generation bits.
 * HANDLE values are reused when a slot is freed and later re-allocated.
 * This matches Win32 PEB HANDLE semantics (the NT kernel also reuses
 * handle values after NtClose), so consumers who cache a HANDLE across
 * a close boundary are already in undefined territory per the platform
 * contract.  No generation counter is added.
 *
 * Concurrent close+alloc race is prevented by the close-path ordering
 * invariant in nspa_local_file_close():
 *   1. lock nspa_lf_opens_mutex
 *   2. remove the entry from nspa_lf_opens (list is now clean for this HANDLE)
 *   3. unlock nspa_lf_opens_mutex
 *   4. publish_close / close(unix_fd) / close server_handle
 *   5. nspa_lf_free_handle(handle)  ← slot flipped to free LAST
 *
 * A concurrent nspa_lf_alloc_handle() call during steps 1-4 sees the
 * slot as in_use and picks a different one.  Only after step 5 can the
 * slot be reused, at which point every LF-side reference to the old
 * HANDLE is gone.
 *
 * LF is fully synchronous — no async completion paths can deliver a
 * stale HANDLE value to a caller after close.
 *
 * Do not reorder steps 4 and 5 in nspa_local_file_close().  Freeing
 * the slot before the list is fully cleared would allow a concurrent
 * alloc to mint a duplicate HANDLE that collides with the in-flight
 * close's list entry. */

static HANDLE nspa_lf_alloc_handle( void )
{
    unsigned int i, slot;
    HANDLE result = NULL;

    pi_mutex_lock( &nspa_lf_handle_mutex );
    for (i = 0; i < NSPA_LF_HANDLE_CAP; i++)
    {
        slot = (nspa_lf_handle_next + i) % NSPA_LF_HANDLE_CAP;
        if (!nspa_lf_handles_in_use[slot])
        {
            nspa_lf_handles_in_use[slot] = 1;
            nspa_lf_handle_next = (slot + 1) % NSPA_LF_HANDLE_CAP;
            /* Encoded handle: nspa_lf_handle_base + slot*4 (handles
             * are 4-byte aligned by Win32 convention). */
            result = (HANDLE)(ULONG_PTR)(nspa_lf_handle_base + slot * 4);
            break;
        }
    }
    pi_mutex_unlock( &nspa_lf_handle_mutex );
    return result;
}

static void nspa_lf_free_handle( HANDLE h )
{
    unsigned int v = (unsigned int)(ULONG_PTR)h;
    unsigned int slot;
    if (v < nspa_lf_handle_base) return;
    slot = (v - nspa_lf_handle_base) / 4;
    if (slot >= NSPA_LF_HANDLE_CAP) return;
    pi_mutex_lock( &nspa_lf_handle_mutex );
    nspa_lf_handles_in_use[slot] = 0;
    pi_mutex_unlock( &nspa_lf_handle_mutex );
}

/* Phase 1A.3 audit: counter bump helpers (separate functions so call
 * sites in file.c/sync.c/server.c don't need to touch our static
 * counters directly).  cause: 0=enter, 1=success, 2=fail. */


int nspa_local_file_is_local_handle( HANDLE h )
{
    unsigned int v = (unsigned int)(ULONG_PTR)h;
    unsigned int slot;
    /* Exclude pseudo-handles the kernel reserves.  The CURRENT_PROCESS
     * pseudo-handle 0x7FFFFFFF lands inside our range otherwise (range
     * is [0x7FFFC000, 0x80000000)), which would route NtClose for it
     * through our local cleanup and similar misroutes. */
    if (v == 0x7FFFFFFFu || v >= 0xFFFFFFFAu) return 0;
    if (v < nspa_lf_handle_base) return 0;
    slot = (v - nspa_lf_handle_base) / 4;
    return slot < NSPA_LF_HANDLE_CAP;
}

/* Bypass dispatch is on by default.  Set NSPA_DISABLE_LOCAL_FILES=1 to
 * fall back to the regular server create_file RPC (bisection aid). */
static int nspa_local_file_disabled( void )
{
    static int cached = -1;
    if (cached < 0)
        cached = (getenv( "NSPA_DISABLE_LOCAL_FILES" ) != NULL);
    return cached;
}

/* Directory bypass — DEFAULT-ON since 2026-04-28.  When enabled,
 * try_bypass also handles paths that stat() reveals as S_ISDIR.
 * Requires the kind plumbing through nspa_local_file_table_add /
 * nspa_local_file_try_get_unix_fd so server_get_unix_fd correctly
 * reports FD_TYPE_DIR for directory handles (without that, file.c's
 * nt_to_unix_file_name_with_root rejects with STATUS_BAD_DEVICE_TYPE
 * — the failure mode of the 2026-04-28 16:46 attempt).
 *
 * Validated 2026-04-28 — Ableton library scan: 55k dir mints,
 * 213k bypasses (77% rate), promote fail=0, no Undo popup,
 * library populates, demo song plays.  ~24% of wineserver handler
 * time retired.  Flipped default-on after the validation pass.
 *
 * Set NSPA_ENABLE_LOCAL_DIR=0 to opt out (matches paint-cache /
 * Phase B / T3 default-on convention — `=0` disables). */
static int nspa_local_dir_disabled( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv( "NSPA_ENABLE_LOCAL_DIR" );
        cached = (v && *v == '0');
    }
    return cached;
}

/* Bypass dispatch.  Returns STATUS_SUCCESS + sets *handle on bypass
 * success (caller skips the regular create_file RPC).  Returns
 * STATUS_NOT_SUPPORTED if bypass is gated off, the file isn't a regular
 * file, the table is unmappable, the bucket / subentry overflows, or
 * any other "fall back to server" condition.  Returns a real NT error
 * status for genuine open failures (sharing violation, no such file,
 * permission denied) — caller propagates to the app. */
NTSTATUS nspa_local_file_try_bypass( HANDLE *handle, const char *unix_name,
                                     const UNICODE_STRING *nt_name,
                                     ACCESS_MASK access, ULONG sharing,
                                     ULONG disposition,
                                     ULONG options, ULONG attributes,
                                     IO_STATUS_BLOCK *io )
{
    struct stat st;
    int unix_fd;
    int open_flags;
    NTSTATUS status;
    HANDLE h;

    if (nspa_local_file_disabled()) return STATUS_NOT_SUPPORTED;
    if (nspa_lf_table_state != 1)   return STATUS_NOT_SUPPORTED;

    /* Expand GENERIC_* into specific bits before any sharing arbitration
     * or storage — server's create_file does the same with map_access().
     * Without this expansion, an open with GENERIC_READ has zero
     * FILE_READ_DATA bits, which makes our sharing check skip the
     * read-vs-share-read arbitration AND makes the promoted server fd
     * lack the access needed for subsequent reads. */
    {
        const ACCESS_MASK gr = FILE_READ_DATA | FILE_READ_ATTRIBUTES |
                               FILE_READ_EA | READ_CONTROL | SYNCHRONIZE;
        const ACCESS_MASK gw = FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES |
                               FILE_WRITE_EA | READ_CONTROL | SYNCHRONIZE;
        const ACCESS_MASK ge = FILE_EXECUTE | FILE_READ_ATTRIBUTES |
                               READ_CONTROL | SYNCHRONIZE;
        const ACCESS_MASK ga = STANDARD_RIGHTS_ALL | FILE_ALL_ACCESS;
        if (access & GENERIC_READ)    access |= gr;
        if (access & GENERIC_WRITE)   access |= gw;
        if (access & GENERIC_EXECUTE) access |= ge;
        if (access & GENERIC_ALL)     access |= ga;
        access &= ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
    }

    /* Phase 2 FILE_CREATE — alternate ordering.  (dev, inode) is not
     * known pre-open because the file doesn't exist yet.  Sequence:
     *   1. derive open flags + mode from access + attributes
     *   2. openat(O_CREAT|O_EXCL, mode) — atomic create-or-fail
     *   3. fstat the resulting fd → (dev, inode)
     *   4. check_and_publish_open under bucket lock
     *
     * On openat EEXIST: STATUS_OBJECT_NAME_COLLISION (NT semantic).
     * On check_and_publish failure (sharing/mapping conflict): close fd,
     * leave file on disk — matches server/file.c::create_file behavior
     * where check_sharing failure post-create leaves the file. */
    if (disposition == FILE_CREATE)
    {
        const ACCESS_MASK unix_read  = FILE_READ_DATA  | FILE_READ_ATTRIBUTES  | FILE_READ_EA;
        const ACCESS_MASK unix_write = FILE_WRITE_DATA | FILE_APPEND_DATA |
                                       FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA;
        mode_t mode;
        size_t name_len;

        /* FILE_DIRECTORY_FILE + FILE_CREATE = mkdir.  Server handles
         * directory creation; LF doesn't.  Fall back. */
        if (options & FILE_DIRECTORY_FILE)
            return STATUS_NOT_SUPPORTED;

        /* Mode_t derivation — mirror server/file.c:256-269 (regular-file
         * branch — FILE_DIRECTORY_FILE excluded by gate). */
        mode = (attributes & FILE_ATTRIBUTE_READONLY) ? 0444 : 0666;
        name_len = strlen( unix_name );
        if (name_len >= 4 &&
            (!strcasecmp( unix_name + name_len - 4, ".exe" ) ||
             !strcasecmp( unix_name + name_len - 4, ".com" )))
        {
            if (mode & S_IRUSR) mode |= S_IXUSR;
            if (mode & S_IRGRP) mode |= S_IXGRP;
            if (mode & S_IROTH) mode |= S_IXOTH;
        }

        if (access & unix_write)
            open_flags = (access & unix_read) ? O_RDWR : O_WRONLY;
        else
            open_flags = O_RDONLY;
        open_flags |= O_CREAT | O_EXCL;
        if (options & FILE_OPEN_REPARSE_POINT) open_flags |= O_NOFOLLOW;

        unix_fd = open( unix_name, open_flags, mode );
        if (unix_fd < 0)
        {
            if (errno == EEXIST) return STATUS_OBJECT_NAME_COLLISION;
            return STATUS_NOT_SUPPORTED;   /* fall back to server */
        }

        if (fstat( unix_fd, &st ) != 0)
        {
            close( unix_fd );
            return STATUS_NOT_SUPPORTED;
        }

        status = nspa_local_file_check_and_publish_open(
            (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
            access, sharing, options, open_flags );
        if (status == STATUS_SHARING_VIOLATION ||
            status == STATUS_USER_MAPPED_FILE  ||
            status == STATUS_CANNOT_DELETE)
        {
            /* Match server semantics: file we just created remains on
             * disk; only the OPEN failed.  Caller propagates the NT
             * error to the app. */
            close( unix_fd );
            return status;
        }
        if (status != STATUS_SUCCESS)
        {
            close( unix_fd );
            return STATUS_NOT_SUPPORTED;
        }

        h = nspa_lf_alloc_handle();
        if (!h)
        {
            nspa_local_file_publish_close( (unsigned long long)st.st_dev,
                                           (unsigned long long)st.st_ino );
            close( unix_fd );
            return STATUS_NOT_SUPPORTED;
        }

        status = nspa_local_file_table_add( h, unix_fd,
                                            (unsigned long long)st.st_dev,
                                            (unsigned long long)st.st_ino,
                                            access, sharing, options, attributes,
                                            FD_TYPE_FILE, nt_name, unix_name );
        if (status != STATUS_SUCCESS)
        {
            nspa_lf_free_handle( h );
            nspa_local_file_publish_close( (unsigned long long)st.st_dev,
                                           (unsigned long long)st.st_ino );
            close( unix_fd );
            return STATUS_NOT_SUPPORTED;
        }

        *handle = h;
        if (io) io->Information = FILE_CREATED;
        NSPA_TRACE( LF_TRACE, "NSPA-LF create-mint h=%p fd=%d access=%x options=%x path=%s\n",
                    h, unix_fd, (unsigned)access, (unsigned)options, unix_name );
        return STATUS_SUCCESS;
    }

    /* stat the unix path to derive (dev, inode) for the table lookup.
     * For FILE_OPEN_REPARSE_POINT use lstat: the caller wants to
     * operate on the symlink itself, not the target.  open() below
     * uses O_NOFOLLOW for the same reason; without lstat here, stat
     * would follow the symlink and we'd register the TARGET's
     * (dev, inode) while the fd actually refers to the symlink —
     * split identity in the LF aggregate.  For non-REPARSE_POINT,
     * stat() correctly follows the symlink so (dev, inode) matches
     * what open() yields. */
    {
        int rc = (options & FILE_OPEN_REPARSE_POINT)
               ? lstat( unix_name, &st )
               : stat( unix_name, &st );
        if (rc != 0)
        {
            /* Real open failure — let caller's normal path map errno. */
            return STATUS_NOT_SUPPORTED;   /* fall back rather than guess errno mapping */
        }
    }
    if (!S_ISREG( st.st_mode ))
    {
        /* Directory bypass: caller did NtCreateFile on a path that turns
         * out to be a directory but did NOT pass FILE_DIRECTORY_FILE
         * (typical pattern: path-existence probes, attribute queries,
         * or implicit path-resolution opens by Wine's get_nt_and_unix_names
         * for a relative-path file open).
         *
         * Skip sharing arbitration entirely — directories don't have
         * read/write/share conflicts.  Open with O_RDONLY (Linux permits
         * this for dirs; only read() syscalls fail on a dir fd —
         * metadata + relative-path opens via openat() work).
         *
         * Critical: register the entry with kind=FD_TYPE_DIR so
         * nspa_local_file_try_get_unix_fd returns the correct type.
         * Without this, file.c::nt_to_unix_file_name_with_root sees
         * type==FD_TYPE_FILE for a dir fd and rejects with
         * STATUS_BAD_DEVICE_TYPE — the breaking case from the
         * 2026-04-28 16:46 attempt that broke "can't open files."
         *
         * Other operations on the dir handle promote to a server handle
         * via the existing nspa_local_file_get_or_promote_server_handle
         * path (already 98% cache hit rate for files; should work for
         * dirs since the server's nspa_create_file_from_unix_fd is
         * fd-type agnostic). */
        if (S_ISDIR( st.st_mode ) && !nspa_local_dir_disabled())
        {
            /* Sync-parity: nspa_finalise_opened_fd returns
             * STATUS_FILE_IS_A_DIRECTORY when caller passed
             * FILE_NON_DIRECTORY_FILE on a directory.  Fall back to
             * the server path, which produces that status — saves a
             * caller-visible behaviour delta vs upstream. */
            if (options & FILE_NON_DIRECTORY_FILE)
                return STATUS_NOT_SUPPORTED;

            unix_fd = open( unix_name, O_RDONLY );
            if (unix_fd < 0)
            {
                return STATUS_NOT_SUPPORTED;
            }

            h = nspa_lf_alloc_handle();
            if (!h)
            {
                close( unix_fd );
                return STATUS_NOT_SUPPORTED;
            }

            status = nspa_local_file_table_add( h, unix_fd,
                                                (unsigned long long)st.st_dev,
                                                (unsigned long long)st.st_ino,
                                                access, sharing, options, attributes,
                                                FD_TYPE_DIR, nt_name, unix_name );
            if (status != STATUS_SUCCESS)
            {
                nspa_lf_free_handle( h );
                close( unix_fd );
                return STATUS_NOT_SUPPORTED;
            }

            *handle = h;
            if (io) io->Information = FILE_OPENED;
            NSPA_TRACE( LF_TRACE, "NSPA-LF dir-mint h=%p fd=%d access=%x options=%x path=%s\n",
                        h, unix_fd, (unsigned)access, (unsigned)options, unix_name );
            return STATUS_SUCCESS;
        }

        return STATUS_NOT_SUPPORTED;
    }

    /* Caller asked for a directory but stat resolved to a regular file
     * — server returns STATUS_NOT_A_DIRECTORY for this case; fall back
     * so the upstream error path produces the correct NT status. */
    if (options & FILE_DIRECTORY_FILE)
        return STATUS_NOT_SUPPORTED;

    /* Phase 2 write extension — derive Linux open flags from access +
     * disposition + options.  Mirrors server/fd.c:2322-2327's rw_mode
     * derivation so PE-side opens use the same syscall flags as the
     * server would have.  open_flags must be computed BEFORE the
     * check_and_publish call so the O_TRUNC bit can participate in
     * the FILE_MAPPING_ACCESS arbitration (server/fd.c:1820 parity). */
    {
        const ACCESS_MASK unix_read  = FILE_READ_DATA  | FILE_READ_ATTRIBUTES  | FILE_READ_EA;
        const ACCESS_MASK unix_write = FILE_WRITE_DATA | FILE_APPEND_DATA |
                                       FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA;
        if (access & unix_write)
            open_flags = (access & unix_read) ? O_RDWR : O_WRONLY;
        else
            open_flags = O_RDONLY;
        if (disposition == FILE_OVERWRITE) open_flags |= O_TRUNC;
        if (options & FILE_OPEN_REPARSE_POINT) open_flags |= O_NOFOLLOW;
    }

    /* Atomic check-sharing + publish_open under the bucket lock.
     * options + open_flags forwarded for FILE_MAPPING_IMAGE /
     * FILE_MAPPING_ACCESS arbitration (mirrors server check_sharing). */
    status = nspa_local_file_check_and_publish_open(
        (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
        access, sharing, options, open_flags );
    if (status == STATUS_SHARING_VIOLATION ||
        status == STATUS_USER_MAPPED_FILE  ||
        status == STATUS_CANNOT_DELETE)
        return status;   /* real NT error — propagate to caller */
    if (status != STATUS_SUCCESS)
    {
        return STATUS_NOT_SUPPORTED;   /* overflow/etc → fall back */
    }

    unix_fd = open( unix_name, open_flags );
    if (unix_fd < 0)
    {
        /* Open failed — undo our publish, return fall-back. */
        nspa_local_file_publish_close( (unsigned long long)st.st_dev,
                                       (unsigned long long)st.st_ino );
        return STATUS_NOT_SUPPORTED;
    }

    h = nspa_lf_alloc_handle();
    if (!h)
    {
        nspa_local_file_publish_close( (unsigned long long)st.st_dev,
                                       (unsigned long long)st.st_ino );
        close( unix_fd );
        return STATUS_NOT_SUPPORTED;
    }

    status = nspa_local_file_table_add( h, unix_fd,
                                        (unsigned long long)st.st_dev,
                                        (unsigned long long)st.st_ino,
                                        access, sharing, options, attributes,
                                        FD_TYPE_FILE, nt_name, unix_name );
    if (status != STATUS_SUCCESS)
    {
        nspa_lf_free_handle( h );
        nspa_local_file_publish_close( (unsigned long long)st.st_dev,
                                       (unsigned long long)st.st_ino );
        close( unix_fd );
        return STATUS_NOT_SUPPORTED;
    }

    *handle = h;
    if (io) io->Information = FILE_OPENED;
    /* Phase 1A.6 debug: log mint with path so we can correlate with
     * subsequent operations on this handle.  Filtered: only log if
     * NSPA_LF_TRACE=1 to avoid spam. */
    NSPA_TRACE( LF_TRACE, "NSPA-LF mint h=%p fd=%d access=%x sharing=%x options=%x path=%s\n",
                 h, unix_fd, (unsigned)access, (unsigned)sharing, (unsigned)options, unix_name );
    return STATUS_SUCCESS;
}

/* NtClose routing.  Called from NtClose before the existing close path.
 * Returns 1 if the handle was a local-file handle and was fully cleaned
 * up; 0 if not (caller continues with normal close). */
/* Phase 1A.4: lazy server-handle promotion.  Returns the cached
 * server handle for `local_handle`, allocating one on first call via
 * the new nspa_create_file_from_unix_fd RPC.  Returns 0 if local_handle
 * isn't in our table or RPC failed.  Used by Nt*File interceptors that
 * need a server-recognised handle (NtFsControlFile, NtQueryInformationFile,
 * NtSetInformationFile, etc.) to handle local-range handles transparently. */

/* Local-file fast path for server_get_unix_fd.  For a local-range
 * handle, fills the fd + type + options from the private table and
 * returns STATUS_SUCCESS (or STATUS_INVALID_HANDLE when the handle is
 * in range but not registered).  Returns STATUS_NOT_SUPPORTED for non-
 * local-range handles so the caller falls through to the normal
 * server path.  Keeps the LF fast-path out of upstream server.c — the
 * caller sees one guarded return, all local-file logic lives here. */
int nspa_local_file_try_get_unix_fd( HANDLE handle, unsigned int wanted_access,
                                     int *unix_fd, int *needs_close,
                                     enum server_fd_type *type, unsigned int *options )
{
    int local_fd = -1;
    unsigned int local_options = 0;
    enum server_fd_type local_kind = FD_TYPE_FILE;

    if (!nspa_local_file_is_local_handle( handle )) return STATUS_NOT_SUPPORTED;

    if (!nspa_local_file_table_lookup_full( handle, &local_fd, &local_options, &local_kind ) || local_fd < 0)
    {
        NSPA_TRACE( LF_TRACE, "NSPA-LF get_unix_fd h=%p NOT-FOUND-IN-TABLE\n", handle );
        return STATUS_INVALID_HANDLE;
    }

    *unix_fd = local_fd;
    *needs_close = 0;
    if (type) *type = local_kind;   /* FD_TYPE_FILE or FD_TYPE_DIR per stored kind */
    if (options) *options = local_options;
    NSPA_TRACE( LF_TRACE, "NSPA-LF get_unix_fd h=%p fd=%d wanted=%x\n",
                handle, local_fd, wanted_access );
    return STATUS_SUCCESS;
}

/* Convenience wrapper: if `h` is a local-range handle, promote it and
 * return the server handle; otherwise return `h` unchanged.  Collapses
 * the repeated 4-line `is_local_handle + get_or_promote` idiom that
 * appeared at every NT-API intercept site down to one-liner call sites
 * and keeps upstream Wine files close to vanilla for rebase
 * friendliness. */
/* Traced variant — same as nspa_promote_if_local but emits a tagged
 * stderr line on a real promotion.  Used by NtQueryInformationFile /
 * NtQueryObject etc. so the trace emission lives here rather than
 * sprinkled through upstream file.c. */
HANDLE nspa_promote_if_local_traced( HANDLE h, const char *tag, unsigned int info )
{
    if (nspa_local_file_is_local_handle( h ))
    {
        HANDLE promoted = nspa_local_file_get_or_promote_server_handle( h );
        if (promoted)
        {
            NSPA_TRACE( LF_TRACE, "NSPA-LF %s h=%p class=%u srv=%p\n",
                        tag, h, info, promoted );
            return promoted;
        }
    }
    return h;
}

HANDLE nspa_promote_if_local( HANDLE h )
{
    if (nspa_local_file_is_local_handle( h ))
    {
        HANDLE promoted = nspa_local_file_get_or_promote_server_handle( h );
        if (promoted) return promoted;
    }
    return h;
}

HANDLE nspa_local_file_get_or_promote_server_handle( HANDLE local_handle )
{
    struct nspa_local_open *o;
    int need_promote = 0;
    int unix_fd = -1;
    unsigned int access = 0, sharing = 0, options = 0, attributes = 0;
    WCHAR *nt_name_copy = NULL;
    USHORT nt_name_len = 0;
    HANDLE result = 0;

    if (!nspa_local_file_is_local_handle( local_handle )) return 0;
    NSPA_TRACE( LF_TRACE, "NSPA-LF promote-call h=%p\n", local_handle );

    pi_mutex_lock( &nspa_lf_opens_mutex );
    LIST_FOR_EACH_ENTRY( o, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (o->handle == local_handle)
        {
            if (o->server_handle) result = o->server_handle;
            else
            {
                need_promote = 1;
                unix_fd    = o->unix_fd;
                access     = o->access;
                sharing    = o->sharing;
                options    = o->options;
                attributes = o->attributes;
                /* Snapshot NT path so we can send it after dropping the
                 * lock — wine_server_call can block. */
                if (o->nt_name && o->nt_name_len)
                {
                    nt_name_copy = malloc( o->nt_name_len );
                    if (nt_name_copy)
                    {
                        memcpy( nt_name_copy, o->nt_name, o->nt_name_len );
                        nt_name_len = o->nt_name_len;
                    }
                }
            }
            break;
        }
    }
    pi_mutex_unlock( &nspa_lf_opens_mutex );

    if (result)
    {
        return result;
    }
    if (!need_promote) { free( nt_name_copy ); return result; }

    /* RPC outside the table lock — server call can block, mustn't
     * hold the per-process file-table mutex during it. */
    {
        HANDLE promoted = 0;
        unsigned int ret;
        wine_server_send_fd( unix_fd );
        SERVER_START_REQ( nspa_create_file_from_unix_fd )
        {
            req->fd         = unix_fd;
            req->access     = access;
            req->sharing    = sharing;
            /* Phase 1A.4 fix: pass through the actual options the file
             * was opened with so the server's struct fd has the same
             * sync/async/buffering semantics as the original open. */
            req->options    = options;
            /* Forward ObjectAttributes->Attributes (esp. OBJ_INHERIT) so
             * the promoted server handle is a faithful replica of the
             * original open — required for CreateProcess inheritance. */
            req->attributes = attributes;
            /* Phase 1A.6: pass NT path so server-side struct fd carries
             * fd->nt_name — required by FileNameInformation queries
             * (GetFinalPathNameByHandle).  Apps like Ableton bail with
             * "could not be opened" when the queried path is empty. */
            if (nt_name_copy && nt_name_len)
                wine_server_add_data( req, nt_name_copy, nt_name_len );
            ret = wine_server_call( req );
            if (!ret) promoted = wine_server_ptr_handle( reply->handle );
        }
        SERVER_END_REQ;
        free( nt_name_copy );
        nt_name_copy = NULL;
        if (!promoted)
        {
            return 0;
        }

        /* Store back, racing safely with another concurrent promotion
         * (we keep whichever lands first; close our own if loser). */
        pi_mutex_lock( &nspa_lf_opens_mutex );
        LIST_FOR_EACH_ENTRY( o, &nspa_lf_opens, struct nspa_local_open, entry )
        {
            if (o->handle == local_handle)
            {
                if (o->server_handle)
                {
                    /* Lost race — keep existing, drop ours. */
                    pi_mutex_unlock( &nspa_lf_opens_mutex );
                    {
                        SERVER_START_REQ( close_handle )
                        {
                            req->handle = wine_server_obj_handle( promoted );
                            wine_server_call( req );
                        }
                        SERVER_END_REQ;
                    }
                    return o->server_handle;
                }
                o->server_handle = promoted;
                result = promoted;
                break;
            }
        }
        pi_mutex_unlock( &nspa_lf_opens_mutex );
    }
    return result;
}

/* Walk the per-process LF table and eagerly promote every entry whose
 * ObjectAttributes->Attributes carries OBJ_INHERIT.  Called from
 * NtCreateUserProcess before the new_process RPC when the parent asks
 * the server to inherit handles: the server's auto-inherit scan walks
 * *its* handle table, so an OBJ_INHERIT-flagged local-range handle
 * must already be server-visible or the child won't get it.
 *
 * Collects handle values under the table lock, then promotes outside
 * the lock since get_or_promote_server_handle itself does an RPC. */
void nspa_local_file_promote_inheritable( void )
{
    HANDLE *to_promote = NULL;
    size_t count = 0, cap = 0;
    struct nspa_local_open *o;

    pi_mutex_lock( &nspa_lf_opens_mutex );
    LIST_FOR_EACH_ENTRY( o, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (!(o->attributes & OBJ_INHERIT)) continue;
        if (o->server_handle) continue;                   /* already promoted */
        if (count == cap)
        {
            size_t new_cap = cap ? cap * 2 : 16;
            HANDLE *resized = realloc( to_promote, new_cap * sizeof(HANDLE) );
            if (!resized) { pi_mutex_unlock( &nspa_lf_opens_mutex ); free( to_promote ); return; }
            to_promote = resized;
            cap = new_cap;
        }
        to_promote[count++] = o->handle;
    }
    pi_mutex_unlock( &nspa_lf_opens_mutex );

    for (size_t i = 0; i < count; i++)
        nspa_local_file_get_or_promote_server_handle( to_promote[i] );
    free( to_promote );
}

int nspa_local_file_close( HANDLE handle )
{
    int unix_fd = -1;
    unsigned long long dev = 0, ino = 0;
    HANDLE server_handle = 0;
    unsigned int sharing = 0;
    struct nspa_local_open *o, *next;
    int found = 0;

    if (!nspa_local_file_is_local_handle( handle )) return 0;
    NSPA_TRACE( LF_TRACE, "NSPA-LF close h=%p\n", handle );

    /* Inline-extended remove that also captures server_handle for
     * 1A.4 lazy-promotion cleanup, and sharing for Phase 3 async close
     * eligibility predicate. */
    pi_mutex_lock( &nspa_lf_opens_mutex );
    LIST_FOR_EACH_ENTRY_SAFE( o, next, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (o->handle == handle)
        {
            unix_fd       = o->unix_fd;
            dev           = o->device;
            ino           = o->inode;
            server_handle = o->server_handle;
            sharing       = o->sharing;
            list_remove( &o->entry );
            free( o->nt_name );
            free( o->unix_name );
            free( o );
            found = 1;
            break;
        }
    }
    pi_mutex_unlock( &nspa_lf_opens_mutex );

    if (!found)
    {
        /* Handle is in our range but not in our table — already closed
         * or never tracked.  Treat as closed (best-effort). */
        nspa_lf_free_handle( handle );
        return 1;
    }

    nspa_local_file_publish_close( dev, ino );

    /* NSPA Phase 3: defer the actual unix_fd close + server close_handle
     * RPC to the per-process sched thread when ALL of:
     *   1. NSPA_USE_SCHED_THREAD=1 (queue push checks gate)
     *   2. there is real cleanup to do (unix_fd or server_handle present)
     *   3. handle's sharing == FULL — no exclusive lock to release, so
     *      no observable side effect for other openers if our actual
     *      close is delayed.  Restrictive sharing closes always go
     *      inline so any waiting opener unblocks immediately.
     *
     * Otherwise close inline as before.  Push returns FALSE when the
     * queue is full or the gate is OFF; caller falls back. */
    {
        BOOL deferred = FALSE;
        if ((server_handle || unix_fd >= 0) &&
            sharing == NSPA_CLOSE_QUEUE_LF_SHARE_ALL &&
            nspa_close_queue_push( server_handle, unix_fd ))
            deferred = TRUE;

        if (!deferred)
        {
            if (unix_fd >= 0) close( unix_fd );
            if (server_handle)
            {
                SERVER_START_REQ( close_handle )
                {
                    req->handle = wine_server_obj_handle( server_handle );
                    wine_server_call( req );
                }
                SERVER_END_REQ;
            }
        }
    }

    /* Free the slot LAST — ordering invariant for ABA-safety.  See the
     * comment block above nspa_lf_alloc_handle (search "ABA properties"). */
    nspa_lf_free_handle( handle );
    return 1;
}

/* ====================================================================
 * Phase A — PE-side section handle range + table foundation.
 *
 * Default-OFF (env gate NSPA_LOCAL_SECTION=1).  Phase B-G consumers
 * (NtCreateSection / NtMapViewOfSection / NtUnmapViewOfSection / NtClose
 * / NtDuplicateObject) come in subsequent commits.  This commit lands
 * only the foundation: handle range allocator, struct nspa_local_section
 * + nspa_section_view, table add / remove / lookup helpers.
 *
 * Handle range:
 *   [NSPA_LS_HANDLE_BASE, NSPA_LS_HANDLE_BASE + NSPA_LS_HANDLE_CAP*4)
 *   = [0x7FFF8000, 0x7FFFC000) — 4096 slots, 4-byte aligned.
 * Below the LF file handle range [0x7FFFC000, 0x80000000), no overlap.
 * The is_local_section predicate distinguishes from LF handles by
 * range membership.
 *
 * See wine/nspa/docs/nt-create-section-pe-side-scoping-20260503.md for
 * the full design + phase plan.
 * ==================================================================== */

#define NSPA_LS_HANDLE_CAP     4096
static unsigned int nspa_ls_handle_base = 0x80000000u
                                          - NSPA_LF_HANDLE_CAP * 4
                                          - NSPA_LS_HANDLE_CAP * 4;
static int          nspa_ls_handles_in_use[NSPA_LS_HANDLE_CAP];
static unsigned int nspa_ls_handle_next;
static DEFINE_PI_MUTEX(nspa_ls_handle_mutex, 0);

/* struct nspa_local_section defined in unix_private.h (used by Phase B-G
 * consumers in sync.c).  struct nspa_section_view stays internal — view
 * tracking is fully managed inside this file. */
struct nspa_section_view
{
    struct list   entry;        /* in section->views */
    void         *addr;         /* mmap'd virtual address */
    size_t        size;         /* view size */
    int           prot;         /* mmap PROT_* flags applied */
};

static struct list      nspa_ls_sections     = LIST_INIT(nspa_ls_sections);
/* Process-local PI mutex protecting the section table.  Cross-process
 * coordination of mapping bits goes through the LF aggregate via
 * nspa_local_file_aggregate_publish_mapping (Phase H). */
static DEFINE_PI_MUTEX(nspa_ls_sections_mutex, 0);

/* Phase A — env gate.  Set NSPA_LOCAL_SECTION=1 to enable Phase B-G
 * NtCreateSection PE-side dispatch.  Default-OFF until Phase J. */
int nspa_local_section_disabled( void )
{
    static int cached = -1;
    if (cached < 0)
    {
        const char *v = getenv( "NSPA_LOCAL_SECTION" );
        cached = !(v && *v == '1');
    }
    return cached;
}

/* Allocate a section handle from the LS range.  Same shape as
 * nspa_lf_alloc_handle; returns NULL on cap-full.  Public so Phase B's
 * NtCreateSection PE-side fast path can mint handles. */
HANDLE nspa_local_section_alloc_handle( void )
{
    unsigned int i, slot;
    HANDLE result = NULL;

    pi_mutex_lock( &nspa_ls_handle_mutex );
    for (i = 0; i < NSPA_LS_HANDLE_CAP; i++)
    {
        slot = (nspa_ls_handle_next + i) % NSPA_LS_HANDLE_CAP;
        if (!nspa_ls_handles_in_use[slot])
        {
            nspa_ls_handles_in_use[slot] = 1;
            nspa_ls_handle_next = (slot + 1) % NSPA_LS_HANDLE_CAP;
            result = (HANDLE)(ULONG_PTR)(nspa_ls_handle_base + slot * 4);
            break;
        }
    }
    pi_mutex_unlock( &nspa_ls_handle_mutex );
    return result;
}

void nspa_local_section_free_handle( HANDLE h )
{
    unsigned int v = (unsigned int)(ULONG_PTR)h;
    unsigned int slot;
    if (v < nspa_ls_handle_base) return;
    slot = (v - nspa_ls_handle_base) / 4;
    if (slot >= NSPA_LS_HANDLE_CAP) return;
    pi_mutex_lock( &nspa_ls_handle_mutex );
    nspa_ls_handles_in_use[slot] = 0;
    pi_mutex_unlock( &nspa_ls_handle_mutex );
}

/* Range membership test — distinguishes section handles from LF file
 * handles + from server handles.  Cheap range check; no table lookup. */
int nspa_local_section_is_local_handle( HANDLE h )
{
    unsigned int v = (unsigned int)(ULONG_PTR)h;
    unsigned int slot;
    if (v == 0x7FFFFFFFu || v >= 0xFFFFFFFAu) return 0;
    if (v < nspa_ls_handle_base) return 0;
    if (v >= nspa_ls_handle_base + NSPA_LS_HANDLE_CAP * 4) return 0;
    slot = (v - nspa_ls_handle_base) / 4;
    return slot < NSPA_LS_HANDLE_CAP;
}

/* Convenience wrapper — resolve (device, inode) from an LF handle and
 * call publish_mapping.  Used by Phase B NtCreateSection PE-side fast
 * path so the eligibility check + bit publication is one helper call.
 *
 * Returns STATUS_NOT_SUPPORTED if the file handle isn't local-range
 * (caller should fall back to server) or if the LF entry isn't found
 * (which shouldn't happen if is_local_handle returned true and no
 * close raced).  Other failures propagate from the underlying publish. */
NTSTATUS nspa_local_file_aggregate_publish_mapping_for_handle( HANDLE file_handle,
                                                               unsigned int mapping_bits )
{
    struct nspa_local_open *o;
    unsigned long long dev = 0, ino = 0;
    int found = 0;

    if (!nspa_local_file_is_local_handle( file_handle )) return STATUS_NOT_SUPPORTED;

    pi_mutex_lock( &nspa_lf_opens_mutex );
    LIST_FOR_EACH_ENTRY( o, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (o->handle == file_handle)
        {
            dev = o->device;
            ino = o->inode;
            found = 1;
            break;
        }
    }
    pi_mutex_unlock( &nspa_lf_opens_mutex );

    if (!found) return STATUS_NOT_SUPPORTED;
    return nspa_local_file_aggregate_publish_mapping( dev, ino, mapping_bits );
}

/* Add a freshly-allocated section to the per-process table.  Caller has
 * already nspa_ls_alloc_handle'd `handle` and populated unix_fd / size /
 * sec_flags / file_access / access / mapping_bits / file_handle.
 * On STATUS_NO_MEMORY the caller should nspa_ls_free_handle(handle). */
NTSTATUS nspa_local_section_table_add( HANDLE handle, HANDLE file_handle, int unix_fd,
                                       size_t size, unsigned int sec_flags,
                                       unsigned int file_access, unsigned int access,
                                       unsigned int mapping_bits )
{
    struct nspa_local_section *s;

    s = malloc( sizeof(*s) );
    if (!s) return STATUS_NO_MEMORY;
    s->handle       = handle;
    s->file_handle  = file_handle;
    s->unix_fd      = unix_fd;
    s->size         = size;
    s->sec_flags    = sec_flags;
    s->file_access  = file_access;
    s->access       = access;
    s->mapping_bits = mapping_bits;
    s->ref          = 1;
    list_init( &s->views );

    pi_mutex_lock( &nspa_ls_sections_mutex );
    list_add_head( &nspa_ls_sections, &s->entry );
    pi_mutex_unlock( &nspa_ls_sections_mutex );
    return STATUS_SUCCESS;
}

/* Look up a tracked section.  Returns 1 + fills `*out` with a snapshot
 * of the entry on success, 0 if not in table.  Snapshot is taken under
 * the table lock so the caller can use values without further locking,
 * but the table entry itself may have been freed by another thread by
 * the time the caller acts on the snapshot — caller must validate via
 * nspa_local_section_is_local_handle for any subsequent ops. */
int nspa_local_section_table_lookup( HANDLE handle, struct nspa_local_section *out )
{
    struct nspa_local_section *s;
    int found = 0;

    pi_mutex_lock( &nspa_ls_sections_mutex );
    LIST_FOR_EACH_ENTRY( s, &nspa_ls_sections, struct nspa_local_section, entry )
    {
        if (s->handle == handle)
        {
            *out = *s;
            list_init( &out->views );  /* don't expose views list to caller */
            found = 1;
            break;
        }
    }
    pi_mutex_unlock( &nspa_ls_sections_mutex );
    return found;
}

/* Remove a section from the table and return its data via *out (callers
 * may want unix_fd to close, etc.).  Returns 1 if removed, 0 if not
 * found.  Caller is responsible for nspa_ls_free_handle(handle) AFTER
 * any cleanup that uses the snapshot fields, to preserve ABA-safety
 * (same ordering invariant as nspa_local_file_table_remove). */
int nspa_local_section_table_remove( HANDLE handle, struct nspa_local_section *out )
{
    struct nspa_local_section *s, *next;
    int found = 0;

    pi_mutex_lock( &nspa_ls_sections_mutex );
    LIST_FOR_EACH_ENTRY_SAFE( s, next, &nspa_ls_sections, struct nspa_local_section, entry )
    {
        if (s->handle == handle)
        {
            *out = *s;
            list_init( &out->views );
            list_remove( &s->entry );
            free( s );
            found = 1;
            break;
        }
    }
    pi_mutex_unlock( &nspa_ls_sections_mutex );
    return found;
}

/* Phase E — NtClose handler for local-section handles.  Returns 1 if
 * the handle was a local section and was cleaned up; 0 if not ours.
 * Mirrors the nspa_local_file_close shape so server.c's NtClose can
 * gate on this before falling through to the regular close path.
 *
 * Cleanup sequence:
 *   1. Snapshot + remove the section table entry.
 *   2. Clear LF aggregate mapping bits for our subentry (Phase H).
 *      Best-effort — failure leaves stale bits but doesn't crash;
 *      the bits are also recomputed on file-handle publish_close.
 *   3. Free the handle slot LAST (ABA-safety; matches LF discipline). */
int nspa_local_section_close( HANDLE handle )
{
    struct nspa_local_section snap;

    if (!nspa_local_section_is_local_handle( handle )) return 0;

    if (!nspa_local_section_table_remove( handle, &snap ))
    {
        /* Handle in our range but not in table — racing close, or
         * never registered.  Free the slot anyway so future allocs
         * can reclaim it. */
        nspa_local_section_free_handle( handle );
        return 1;
    }

    /* Clear our subentry's mapping bits.  If multiple sections in
     * this process backed by the same file handle, the caller's
     * (Phase F) ref-counting would re-publish the union here.  For
     * the single-section-per-file common case, clearing is correct.
     *
     * Future Phase F dup support: change this to publish the union
     * of remaining sections' bits (computed by walking
     * nspa_ls_sections for the same file_handle). */
    if (snap.file_handle && nspa_local_file_is_local_handle( snap.file_handle ))
        nspa_local_file_aggregate_publish_mapping_for_handle( snap.file_handle, 0 );

    /* Close the section's owned unix fd.  Phase B dup()'d it from the
     * LF table at section-create so the section's lifetime is decoupled
     * from the file handle's — apps may NtClose(file) before
     * NtClose(section) (DirectWrite font loader does exactly this). */
    if (snap.unix_fd >= 0) close( snap.unix_fd );

    nspa_local_section_free_handle( handle );
    return 1;
}
