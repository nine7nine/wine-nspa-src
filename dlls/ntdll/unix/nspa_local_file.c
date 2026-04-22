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
#include <time.h>
#include <unistd.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"
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

void nspa_local_file_diag_categorize( const OBJECT_ATTRIBUTES *attr, ACCESS_MASK access,
                                      ULONG sharing, ULONG disposition, ULONG options )
{
    __atomic_fetch_add( &nspa_lf_top_calls, 1, __ATOMIC_RELAXED );

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
