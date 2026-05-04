/*
 * NSPA mapping helpers — cold-path init-time helpers extracted from
 * server/mapping.c.  Anything in this file runs at server bootstrap
 * (or rare admin paths), so the function-call boundary cost is
 * negligible; live here to keep mapping.c smaller and shrink the
 * upstream-rebase conflict surface.
 */

#include "config.h"

#include <stdlib.h>
#include <sys/types.h>

#ifdef __linux__
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#endif

#include "nspa/mapping_helpers.h"

#ifdef __linux__
/* Scan /sys/kernel/mm/hugepages and return the SMALLEST configured hugepage
 * size in bytes.  Returns 0 if no hugepages are configured (or the directory
 * can't be opened, e.g. on a kernel without hugetlbfs).
 *
 * Used to populate KUSER_SHARED_DATA::LargePageMinimum so that
 * GetLargePageMinimum() in apps returns the actual smallest huge page the
 * kernel can give us, rather than the hardcoded 2 MB Wine used to return.
 * On a typical x86_64 system this returns 2*1024*1024 (2 MB) — the directory
 * "hugepages-2048kB" exists when nr_hugepages-2048kB > 0. */
size_t nspa_get_min_hugepage_size( void )
{
    DIR *sysfs_hugepages;
    struct dirent *supported_size;
    size_t min_size = 0;
    size_t total_supported_sizes = 0;

    sysfs_hugepages = opendir( "/sys/kernel/mm/hugepages" );
    if (sysfs_hugepages == NULL) return 0;

    while ((supported_size = readdir( sysfs_hugepages )) != NULL)
    {
        long hugepage_size;
        char *endptr;

        if (strncmp( supported_size->d_name, "hugepages-", 10 ) != 0)
            continue;

        errno = 0;
        hugepage_size = strtol( &supported_size->d_name[10], &endptr, 10 );
        /* Valid entry name format: "hugepages-NNNNkB". The number must
         * parse cleanly and the suffix must start with 'k' (kilobytes). */
        if (errno != 0 || endptr == &supported_size->d_name[10] || *endptr != 'k')
            continue;
        if (hugepage_size <= 0)
            continue;

        hugepage_size *= 1024;  /* directory uses kB; we want bytes */

        if (total_supported_sizes == 0 || (size_t)hugepage_size < min_size)
            min_size = hugepage_size;
        total_supported_sizes++;
    }

    closedir( sysfs_hugepages );
    return min_size;
}
#endif /* __linux__ */
