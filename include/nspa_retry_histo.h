/*
 * NSPA retry-count histogram — header-only inline primitive.
 *
 * Purpose: characterise the per-call retry-count distribution for any
 * loop that retries on contention (CAS races, seqlock readers).  Tells
 * us whether a loop is empirically bounded under workload, before we
 * decide whether it needs a yield/backoff/fallback.
 *
 * Bucketing: 16 exponential buckets on retry count.
 *   [0]=0  [1]=1  [2]=2-3  [3]=4-7  [4]=8-15  [5]=16-31  ...
 *   [15]=32768+
 *
 * Usage:
 *   static nspa_retry_histo_t my_histo;
 *
 *   for (retries = 0; ...; retries++) {
 *       ...
 *   }
 *   nspa_histo_record(&my_histo, retries);
 *
 *   // In your existing dump function:
 *   nspa_histo_dump(&my_histo, "ring_reserve_slot CAS retries", fp);
 *
 * Atomic discipline: bucket counters use RELAXED fetch_add (per-call
 * accuracy not required; aggregate distribution is).  Reads use
 * RELAXED load (snapshot may be torn between buckets but the dump is
 * advisory).  Total sum overflow at 2^64 is fine for our scales.
 *
 * Thread safety: yes, lock-free.  Multiple threads recording into the
 * same histo concurrently is supported.
 *
 * Cost: ~5 ns per record (one fls + one atomic add).  Fixed-size:
 * 16 * 8 = 128 bytes per histo.  Cache-friendly.
 */

#ifndef __WINE_NSPA_RETRY_HISTO_H
#define __WINE_NSPA_RETRY_HISTO_H

#include <stdio.h>
#include <stdint.h>

#define NSPA_HISTO_BUCKETS 16

typedef struct nspa_retry_histo
{
    uint64_t buckets[NSPA_HISTO_BUCKETS];
} nspa_retry_histo_t;

/* Map retry count to bucket index.
 *  0      → 0
 *  1      → 1
 *  2..3   → 2
 *  4..7   → 3
 *  ...
 *  >=32768 → 15
 */
static inline unsigned int nspa_histo_bucket( unsigned int n )
{
    unsigned int b;
    if (n == 0) return 0;
    if (n == 1) return 1;
    /* For n >= 2: bucket = floor(log2(n)) + 1, capped at 15. */
    b = 1;
    while (n > 1 && b < (NSPA_HISTO_BUCKETS - 1)) { n >>= 1; b++; }
    return b;
}

static inline void nspa_histo_record( nspa_retry_histo_t *h, unsigned int retries )
{
    unsigned int b = nspa_histo_bucket( retries );
    __atomic_fetch_add( &h->buckets[b], 1ull, __ATOMIC_RELAXED );
}

/* Dump human-readable distribution to fp.  Format:
 *
 *   <name>:
 *     bucket    range        count       cumulative %
 *     [ 0]    0           12345          90.1%
 *     [ 1]    1            1234          99.1%
 *     [ 2]    2-3            45          99.4%
 *     ...
 *     total                13624
 *
 * Buckets with zero count are omitted to keep the dump compact.
 * If all buckets are zero, prints "(no samples)".
 */
static inline void nspa_histo_dump( const nspa_retry_histo_t *h,
                                    const char *name, FILE *fp )
{
    static const char *labels[NSPA_HISTO_BUCKETS] = {
        "0", "1", "2-3", "4-7", "8-15", "16-31",
        "32-63", "64-127", "128-255", "256-511", "512-1023",
        "1024-2047", "2048-4095", "4096-8191", "8192-16383", "16384+"
    };
    uint64_t snapshot[NSPA_HISTO_BUCKETS];
    uint64_t total = 0;
    uint64_t cum = 0;
    unsigned int i;

    for (i = 0; i < NSPA_HISTO_BUCKETS; i++)
    {
        snapshot[i] = __atomic_load_n( &h->buckets[i], __ATOMIC_RELAXED );
        total += snapshot[i];
    }

    fprintf( fp, "[%s] retry-count histogram\n", name );
    if (total == 0)
    {
        fprintf( fp, "  (no samples)\n" );
        return;
    }

    fprintf( fp, "  bucket    range        count       cumulative %%\n" );
    for (i = 0; i < NSPA_HISTO_BUCKETS; i++)
    {
        if (snapshot[i] == 0) continue;
        cum += snapshot[i];
        fprintf( fp, "  [%2u]    %-12s %10llu       %5.1f%%\n",
                 i, labels[i],
                 (unsigned long long)snapshot[i],
                 100.0 * (double)cum / (double)total );
    }
    fprintf( fp, "  total              %10llu\n",
             (unsigned long long)total );
}

#endif  /* __WINE_NSPA_RETRY_HISTO_H */
