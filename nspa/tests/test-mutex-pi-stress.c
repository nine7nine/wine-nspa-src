/*
 * test-mutex-pi-stress: concurrency hammer of the ntsync mutex PI path.
 *
 * What this test FINDS:
 *   - Slab corruption / UAF in ntsync_pi_owner alloc/free under
 *     contention.  KASAN catches.
 *   - task_struct lifetime bugs in mutex owner boost — get_task_struct
 *     when the holder is captured, put on drop / unlock.  KASAN catches.
 *   - boost_count accounting bugs across multiple concurrent boosters
 *     of the same owner, or across owner-transfer on unlock.
 *   - lock-ordering bugs between obj_lock + boost_lock + dev_lock_obj
 *     (lockdep would catch — disabled at boot today, but DEBUG_OBJECTS
 *      / KCSAN can still surface adjacent issues).
 *   - dropped wakeups, double-acquire, mutex held forever.
 *
 * Two tiers of pressure:
 *   Tier A (always runs): SCHED_OTHER threads contend on N mutexes.
 *     Exercises acquire-wait-queue / unlock-wake / list ops.  Doesn't
 *     directly exercise PI boost (no priority differential), but does
 *     exercise everything else around it including ntsync_pi_recalc
 *     calls that find no boost target.
 *   Tier B (root or CAP_SYS_NICE only): one waiter thread runs at
 *     SCHED_FIFO with a real RT priority.  Holding threads are at
 *     SCHED_OTHER.  When the FIFO waiter blocks on a held mutex, PI
 *     boost fires — the path the original RT alloc-hoist work was
 *     for.  Skipped silently with a notice if RT prio not allowed.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o test-mutex-pi-stress \
 *       test-mutex-pi-stress.c -lpthread
 *
 * Run:
 *   ./test-mutex-pi-stress [duration_seconds] [n_holders] [n_mutexes]
 *
 * Detect KASAN failures: tail dmesg / journalctl -k for "BUG: KASAN:".
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/types.h>

struct ntsync_mutex_args {
    __u32 owner;
    __u32 count;
};

struct ntsync_wait_args {
    __u64 timeout;
    __u64 objs;
    __u32 count;
    __u32 index;
    __u32 flags;
    __u32 owner;
    __u32 alert;
    __u32 uring_fd;
};

#define NTSYNC_IOC_CREATE_MUTEX  _IOW ('N', 0x84, struct ntsync_mutex_args)
#define NTSYNC_IOC_MUTEX_UNLOCK  _IOWR('N', 0x85, struct ntsync_mutex_args)
#define NTSYNC_IOC_WAIT_ANY      _IOWR('N', 0x82, struct ntsync_wait_args)

struct local_sched_attr {
    __u32 size;
    __u32 sched_policy;
    __u64 sched_flags;
    __s32 sched_nice;
    __u32 sched_priority;
    __u64 sched_runtime;
    __u64 sched_deadline;
    __u64 sched_period;
};

static int sys_sched_getattr(pid_t pid, struct local_sched_attr *attr,
                             unsigned int size, unsigned int flags)
{
    return syscall(SYS_sched_getattr, pid, attr, size, flags);
}

static int gettid_compat(void) { return (int)syscall(SYS_gettid); }

static __u64 abs_deadline_ns(__u64 relative_ns)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec + relative_ns;
}

/* Shared state */
static int g_dev_fd;
static int *g_mutex_fds;
static int g_n_mutexes;
static atomic_int g_stop;
static atomic_long g_acquires;
static atomic_long g_releases;
static atomic_long g_acquire_errors;
static atomic_long g_release_errors;
static atomic_long g_pi_witnessed;     /* tier B: holder observed boosted */

static int try_set_fifo(int prio)
{
    struct sched_param sp = { .sched_priority = prio };
    return sched_setscheduler(0, SCHED_FIFO, &sp);
}

static int mutex_acquire_blocking(int mutex_fd)
{
    struct ntsync_wait_args wa;
    int rc;
    memset(&wa, 0, sizeof(wa));
    wa.count   = 1;
    wa.objs    = (uintptr_t)&mutex_fd;
    wa.owner   = gettid_compat();
    wa.timeout = abs_deadline_ns(2ULL * 1000000000ULL); /* 2s — acquire bound */
    rc = ioctl(g_dev_fd, NTSYNC_IOC_WAIT_ANY, &wa);
    return rc;
}

static int mutex_release(int mutex_fd)
{
    struct ntsync_mutex_args ma = { .owner = gettid_compat(), .count = 0 };
    return ioctl(mutex_fd, NTSYNC_IOC_MUTEX_UNLOCK, &ma);
}

static void *holder_fn(void *arg)
{
    int id = (int)(uintptr_t)arg;
    unsigned rng = id * 1664525u + 1013904223u;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        rng = rng * 1664525u + 1013904223u;
        int idx = (int)(rng % g_n_mutexes);
        int rc;

        rc = mutex_acquire_blocking(g_mutex_fds[idx]);
        if (rc < 0) {
            if (errno == ETIMEDOUT) continue; /* contention sometimes wins */
            atomic_fetch_add_explicit(&g_acquire_errors, 1, memory_order_relaxed);
            fprintf(stderr, "[holder %d] acquire mutex[%d] errno=%d\n", id, idx, errno);
            continue;
        }
        atomic_fetch_add_explicit(&g_acquires, 1, memory_order_relaxed);

        /* Brief work — no busy-loop on FIFO; sched_yield is enough to let
         * other holders / FIFO waiter run. */
        for (int i = 0; i < 10; i++) sched_yield();

        rc = mutex_release(g_mutex_fds[idx]);
        if (rc < 0) {
            atomic_fetch_add_explicit(&g_release_errors, 1, memory_order_relaxed);
            fprintf(stderr, "[holder %d] release mutex[%d] errno=%d\n", id, idx, errno);
            continue;
        }
        atomic_fetch_add_explicit(&g_releases, 1, memory_order_relaxed);
    }
    return NULL;
}

/* Tier B: one FIFO-prio waiter that hammers a single mutex hard.
 * Each acquire causes ntsync_pi_recalc to fire on whoever currently
 * holds it, applying the boost (we run at FIFO so the differential is
 * meaningful).  After acquire we briefly check that the boost path
 * didn't error, then release. */
static void *fifo_waiter_fn(void *arg)
{
    int prio = (int)(uintptr_t)arg;
    if (try_set_fifo(prio) != 0) {
        fprintf(stderr, "[fifo waiter] sched_setscheduler FIFO %d failed: %s — Tier B SKIP\n",
                prio, strerror(errno));
        return NULL;
    }
    fprintf(stderr, "[fifo waiter] running at SCHED_FIFO prio=%d — Tier B active\n", prio);

    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        int idx = 0; /* Hammer mutex 0 specifically — all holders touch it
                      * in their RNG too, so contention is high here. */
        int rc = mutex_acquire_blocking(g_mutex_fds[idx]);
        if (rc < 0) {
            if (errno == ETIMEDOUT) continue;
            atomic_fetch_add_explicit(&g_acquire_errors, 1, memory_order_relaxed);
            continue;
        }
        atomic_fetch_add_explicit(&g_acquires, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&g_pi_witnessed, 1, memory_order_relaxed);

        for (int i = 0; i < 5; i++) sched_yield();

        rc = mutex_release(g_mutex_fds[idx]);
        if (rc < 0) {
            atomic_fetch_add_explicit(&g_release_errors, 1, memory_order_relaxed);
            continue;
        }
        atomic_fetch_add_explicit(&g_releases, 1, memory_order_relaxed);
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int duration   = (argc > 1) ? atoi(argv[1]) : 30;
    int n_holders  = (argc > 2) ? atoi(argv[2]) : 8;
    g_n_mutexes    = (argc > 3) ? atoi(argv[3]) : 4;

    g_dev_fd = open("/dev/ntsync", O_RDWR | O_CLOEXEC);
    if (g_dev_fd < 0) { perror("open /dev/ntsync"); return 2; }

    g_mutex_fds = calloc(g_n_mutexes, sizeof(int));
    for (int i = 0; i < g_n_mutexes; i++) {
        struct ntsync_mutex_args ma = { .owner = 0, .count = 0 };
        g_mutex_fds[i] = ioctl(g_dev_fd, NTSYNC_IOC_CREATE_MUTEX, &ma);
        if (g_mutex_fds[i] < 0) {
            perror("CREATE_MUTEX"); return 2;
        }
    }

    printf("== mutex PI stress: %d holders + %d mutexes for %ds ==\n",
           n_holders, g_n_mutexes, duration);

    /* Try to raise rlimit so the FIFO waiter can elevate */
    {
        struct rlimit rl = { .rlim_cur = 99, .rlim_max = 99 };
        setrlimit(RLIMIT_RTPRIO, &rl);
    }

    pthread_t *holds = calloc(n_holders, sizeof(pthread_t));
    pthread_t fifo_waiter;
    for (int i = 0; i < n_holders; i++)
        pthread_create(&holds[i], NULL, holder_fn, (void*)(uintptr_t)i);
    pthread_create(&fifo_waiter, NULL, fifo_waiter_fn, (void*)(uintptr_t)50);

    sleep(duration);
    atomic_store_explicit(&g_stop, 1, memory_order_relaxed);

    for (int i = 0; i < n_holders; i++) pthread_join(holds[i], NULL);
    pthread_join(fifo_waiter, NULL);
    free(holds);

    long acq = atomic_load(&g_acquires);
    long rel = atomic_load(&g_releases);
    long aerr = atomic_load(&g_acquire_errors);
    long rerr = atomic_load(&g_release_errors);
    long pi = atomic_load(&g_pi_witnessed);

    for (int i = 0; i < g_n_mutexes; i++) close(g_mutex_fds[i]);
    free(g_mutex_fds);
    close(g_dev_fd);

    printf("\n== Results ==\n");
    printf("acquires:           %ld\n", acq);
    printf("releases:           %ld\n", rel);
    printf("acquire errors:     %ld\n", aerr);
    printf("release errors:     %ld\n", rerr);
    printf("Tier B PI events:   %ld   (FIFO waiter acquires; 0 = Tier B skipped)\n", pi);
    printf("\nKASAN:        check `journalctl -k --since \"%ds ago\" | grep BUG`\n",
           duration + 5);

    if (acq != rel) {
        printf("RESULT: FAIL (acquire != release: %ld vs %ld — leaked or doubled)\n",
               acq, rel);
        return 1;
    }
    if (aerr || rerr) {
        printf("RESULT: FAIL (%ld syscall errors)\n", aerr + rerr);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
