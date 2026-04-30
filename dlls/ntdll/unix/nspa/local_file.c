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
    if (disposition != FILE_OPEN && disposition != FILE_OPEN_IF) return FALSE;
    if (options & FILE_OPEN_BY_FILE_ID) return FALSE;
    if (options & FILE_DIRECTORY_FILE) return FALSE;
    if (options & FILE_DELETE_ON_CLOSE) return FALSE;
    if (!(options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT))) return FALSE;
    if (access & ~NSPA_LF_STD_READ_ACCESS) return FALSE;
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
                                    const UNICODE_STRING *nt_name )
{
    struct nspa_local_open *o = malloc( sizeof(*o) );
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

/* Server-internal "magic" access bit for writable shared mappings.
 * Mirrors server/file.h::FILE_MAPPING_WRITE — duplicated here to avoid
 * pulling server headers into ntdll.  The server's nspa_publish_inode_state
 * walks inode->open and OR's every fd's access into agg_access, so a
 * writable section mapping on the inode causes this bit to land in
 * subentry[0] (server's published view).  LF's algorithm must check it
 * to match server/fd.c::check_sharing's mapping-aware sharing
 * arbitration.  The bit overlaps GENERIC_WRITE in raw client access,
 * but try_bypass strips GENERIC_* before storage so the only way this
 * bit appears in existing_access is via the server's publish. */
#define NSPA_LF_FILE_MAPPING_WRITE 0x40000000u

/* Apply the same algorithm as server/fd.c:check_sharing on aggregated
 * existing state.  Returns STATUS_SHARING_VIOLATION on conflict. */
static NTSTATUS nspa_lf_check_sharing_algorithm( unsigned int existing_access,
                                                 unsigned int existing_sharing,
                                                 unsigned int my_access,
                                                 unsigned int my_sharing )
{
    const unsigned int read_access  = FILE_READ_DATA | FILE_EXECUTE;
    const unsigned int write_access = FILE_WRITE_DATA | FILE_APPEND_DATA;
    const unsigned int all_access   = read_access | write_access | DELETE;

    if (((my_access & read_access)  && !(existing_sharing & FILE_SHARE_READ)) ||
        ((my_access & write_access) && !(existing_sharing & FILE_SHARE_WRITE)) ||
        ((my_access & DELETE)       && !(existing_sharing & FILE_SHARE_DELETE)))
        return STATUS_SHARING_VIOLATION;

    /* Sync-parity with server/fd.c::check_sharing — a writable section
     * mapping on this inode (FILE_MAPPING_WRITE in existing_access via
     * server's subentry[0] publish) requires the new open to allow
     * FILE_SHARE_WRITE.  The other server-side mapping checks
     * (FILE_MAPPING_IMAGE && FILE_WRITE_DATA, FILE_MAPPING_IMAGE &&
     * FILE_DELETE_ON_CLOSE, FILE_MAPPING_ACCESS && O_TRUNC) are moot
     * here: LF eligibility excludes FILE_WRITE_DATA, FILE_DELETE_ON_CLOSE,
     * and any disposition that produces O_TRUNC. */
    if ((existing_access & NSPA_LF_FILE_MAPPING_WRITE) && !(my_sharing & FILE_SHARE_WRITE))
        return STATUS_SHARING_VIOLATION;

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
 * Returns STATUS_SUCCESS if the new open with `my_access`/`my_sharing`
 * would not violate any existing open's sharing mode, or
 * STATUS_SHARING_VIOLATION otherwise. */
NTSTATUS nspa_local_file_check_sharing( unsigned long long device, unsigned long long inode,
                                        unsigned int my_access, unsigned int my_sharing )
{
    nspa_inode_slot_t snapshot;
    unsigned int agg_access = 0;
    unsigned int agg_sharing = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    if (!nspa_local_file_table_lookup( device, inode, &snapshot ))
        return STATUS_SUCCESS;   /* no existing opens */

    nspa_lf_aggregate_from_slot( &snapshot, &agg_access, &agg_sharing );
    return nspa_lf_check_sharing_algorithm( agg_access, agg_sharing, my_access, my_sharing );
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
                                                        unsigned int sharing )
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
                                                  access, sharing );
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

    /* stat the unix path to derive (dev, inode) for the table lookup. */
    if (stat( unix_name, &st ) != 0)
    {
        /* Real open failure — let caller's normal path map errno. */
        return STATUS_NOT_SUPPORTED;   /* fall back rather than guess errno mapping */
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
                                                FD_TYPE_DIR, nt_name );
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

    /* Atomic check-sharing + publish_open under the bucket lock. */
    status = nspa_local_file_check_and_publish_open(
        (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
        access, sharing );
    if (status == STATUS_SHARING_VIOLATION)
        return status;   /* real error — propagate to caller */
    if (status != STATUS_SUCCESS)
    {
        return STATUS_NOT_SUPPORTED;   /* overflow/etc → fall back */
    }

    /* Open locally.  O_RDONLY for MVP read-only access; O_NOFOLLOW
     * when caller asked for FILE_OPEN_REPARSE_POINT. */
    open_flags = O_RDONLY;
    if (options & FILE_OPEN_REPARSE_POINT) open_flags |= O_NOFOLLOW;
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
                                        FD_TYPE_FILE, nt_name );
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
    struct nspa_local_open *o, *next;
    int found = 0;

    if (!nspa_local_file_is_local_handle( handle )) return 0;
    NSPA_TRACE( LF_TRACE, "NSPA-LF close h=%p\n", handle );

    /* Inline-extended remove that also captures server_handle for
     * 1A.4 lazy-promotion cleanup. */
    pi_mutex_lock( &nspa_lf_opens_mutex );
    LIST_FOR_EACH_ENTRY_SAFE( o, next, &nspa_lf_opens, struct nspa_local_open, entry )
    {
        if (o->handle == handle)
        {
            unix_fd       = o->unix_fd;
            dev           = o->device;
            ino           = o->inode;
            server_handle = o->server_handle;
            list_remove( &o->entry );
            free( o->nt_name );
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
    if (unix_fd >= 0) close( unix_fd );

    /* If we lazily promoted to a server handle, close that too. */
    if (server_handle)
    {
        SERVER_START_REQ( close_handle )
        {
            req->handle = wine_server_obj_handle( server_handle );
            wine_server_call( req );
        }
        SERVER_END_REQ;
    }

    /* Free the slot LAST — ordering invariant for ABA-safety.  See the
     * comment block above nspa_lf_alloc_handle (search "ABA properties"). */
    nspa_lf_free_handle( handle );
    return 1;
}
