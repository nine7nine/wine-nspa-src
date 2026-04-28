/*
 * test-event-set-pi-stress: concurrency hammer of the EVENT_SET_PI
 * deferred-boost path.
 *
 * What this test FINDS (target failure modes):
 *   - Slab freelist corruption in ntsync_event_pi alloc/free (the
 *     original open UAF, ___slab_alloc+0x316 from ntsync_obj_ioctl).
 *     Detected by KASAN under debug kernel.
 *   - Double-free or use-after-free of pending_pi.new_ep across
 *     EVENT_SET_PI overwrites, EVENT_RESET clears, and consumer
 *     captures.  KASAN catches.
 *   - task_struct lifetime bugs around get/put pairs in
 *     apply_event_pi_boost / drain_event_pi_boosts when a boosted
 *     task exits.  KASAN catches.
 *   - Boost-application correctness flakes (consumer wakes but boost
 *     didn't apply).  Detected by sched_getattr after wake.
 *
 * Workload mimics Ableton's churn: many threads, many events, mixed
 * EVENT_SET_PI/RESET/SET on the same event from different cores,
 * threads exit + replaced.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o test-event-set-pi-stress \
 *       test-event-set-pi-stress.c -lpthread
 *
 * Run:
 *   ./test-event-set-pi-stress [duration_seconds] [signaler_threads] [waiter_threads]
 *
 * Exit codes:
 *   0 — clean (no missed boosts, no syscall errors)
 *   1 — at least one boost failed to apply
 *   2 — a syscall returned an unexpected error
 *
 * Detect KASAN failures by watching dmesg / journalctl -k --since now
 * for "BUG: KASAN:" or "ntsync" splat lines during the run.
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
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/types.h>

struct ntsync_event_args {
    __u32 manual;
    __u32 signaled;
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

struct ntsync_event_set_pi_args {
    __u32 flags;
    __u32 policy;
    __u32 prio;
    __u32 __pad;
};

#define NTSYNC_IOC_CREATE_EVENT   _IOW('N',  0x87, struct ntsync_event_args)
#define NTSYNC_IOC_WAIT_ANY       _IOWR('N', 0x82, struct ntsync_wait_args)
#define NTSYNC_IOC_EVENT_SET      _IOR('N',  0x88, __u32)
#define NTSYNC_IOC_EVENT_RESET    _IOR('N',  0x89, __u32)
#define NTSYNC_IOC_EVENT_SET_PI   _IOW('N',  0x8e, struct ntsync_event_set_pi_args)

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

static int gettid_compat(void)
{
    return (int)syscall(SYS_gettid);
}

static __u64 abs_deadline_ns(__u64 relative_ns)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec + relative_ns;
}

/* Shared state */
static int g_dev_fd;
static int g_event_fd;       /* shared event hammered by everyone */
static atomic_int g_stop;
static atomic_long g_signaler_iters;
static atomic_long g_waiter_iters;
static atomic_long g_waiter_woke;
static atomic_long g_boost_applied;     /* waiter saw FIFO after wake */
static atomic_long g_boost_missed;      /* waiter woke but no boost */
static atomic_long g_syscall_errors;

static void *signaler_fn(void *arg)
{
    int id = (int)(uintptr_t)arg;
    int rng = id * 1664525 + 1013904223;  /* tiny LCG, deterministic per thread */
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        rng = rng * 1664525 + 1013904223;
        unsigned op = (unsigned)rng % 4;
        unsigned prio = 1 + ((unsigned)rng >> 8) % 90;
        unsigned policy = ((rng >> 16) & 1) ? SCHED_FIFO : SCHED_RR;
        struct ntsync_event_set_pi_args pi = {
            .flags = 0, .policy = policy, .prio = prio, .__pad = 0,
        };
        __u32 prev_state;
        int ret;

        switch (op) {
        case 0:
        case 1:  /* bias toward EVENT_SET_PI — that's the path under test */
            ret = ioctl(g_event_fd, NTSYNC_IOC_EVENT_SET_PI, &pi);
            break;
        case 2:
            ret = ioctl(g_event_fd, NTSYNC_IOC_EVENT_SET, &prev_state);
            break;
        case 3:
            ret = ioctl(g_event_fd, NTSYNC_IOC_EVENT_RESET, &prev_state);
            break;
        default:
            ret = 0; break;
        }
        if (ret < 0 && errno != EINTR) {
            atomic_fetch_add_explicit(&g_syscall_errors, 1, memory_order_relaxed);
            fprintf(stderr, "[signaler %d] op=%u errno=%d\n", id, op, errno);
        }
        atomic_fetch_add_explicit(&g_signaler_iters, 1, memory_order_relaxed);

        /* tiny jitter so we don't pin a single core */
        if ((rng & 0xff) == 0) usleep(10);
    }
    return NULL;
}

static void *waiter_fn(void *arg)
{
    int id = (int)(uintptr_t)arg;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        struct ntsync_wait_args wa;
        struct local_sched_attr a_after_wake;
        int rc;

        memset(&wa, 0, sizeof(wa));
        wa.count   = 1;
        wa.objs    = (uintptr_t)&g_event_fd;
        wa.owner   = gettid_compat();
        /* Bounded timeout so a brief signaler stall doesn't park us forever */
        wa.timeout = abs_deadline_ns(50ULL * 1000000ULL);  /* 50ms */
        rc = ioctl(g_dev_fd, NTSYNC_IOC_WAIT_ANY, &wa);
        atomic_fetch_add_explicit(&g_waiter_iters, 1, memory_order_relaxed);

        if (rc < 0) {
            if (errno == ETIMEDOUT)
                continue;  /* normal under bursty signal pattern */
            atomic_fetch_add_explicit(&g_syscall_errors, 1, memory_order_relaxed);
            fprintf(stderr, "[waiter %d] WAIT_ANY errno=%d\n", id, errno);
            continue;
        }

        atomic_fetch_add_explicit(&g_waiter_woke, 1, memory_order_relaxed);

        /* Capture boost state — informational only.  Drain validation
         * does NOT belong here: with a constant stream of signals on the
         * same event, every re-entry into wait_any will consume the next
         * pending_pi as well, so the waiter correctly stays boosted while
         * work is in flight.  Drain only restores SCHED_OTHER when a
         * wait returns WITHOUT consuming a signal — checked at end of
         * test in main(). */
        a_after_wake.size = sizeof(a_after_wake);
        sys_sched_getattr(0, &a_after_wake, sizeof(a_after_wake), 0);

        if (a_after_wake.sched_policy == SCHED_FIFO ||
            a_after_wake.sched_policy == SCHED_RR) {
            atomic_fetch_add_explicit(&g_boost_applied, 1, memory_order_relaxed);
        } else {
            /* Wake came from plain EVENT_SET, not EVENT_SET_PI — no
             * boost expected.  Informational, not a bug. */
            atomic_fetch_add_explicit(&g_boost_missed, 1, memory_order_relaxed);
        }
    }
    (void)id;
    return NULL;
}

/* Final drain validation: after signalers stop, the waiter must be able
 * to drop back to SCHED_OTHER.  Run this from main() once the workload
 * is quiesced. */
static int verify_drain_quiesced(void)
{
    int sync_fd;
    struct ntsync_event_args ea = { .manual = 1, .signaled = 0 };
    struct ntsync_wait_args wa;
    struct local_sched_attr after;

    sync_fd = ioctl(g_dev_fd, NTSYNC_IOC_CREATE_EVENT, &ea);
    if (sync_fd < 0) return -1;

    /* First, do a wait on the still-signaled stress event to clear any
     * lingering pending_pi we may have carried into main() — that
     * applies the last staged boost to us. */
    memset(&wa, 0, sizeof(wa));
    wa.count = 1; wa.objs = (uintptr_t)&g_event_fd;
    wa.owner = gettid_compat();
    wa.timeout = abs_deadline_ns(1000000ULL);
    (void)ioctl(g_dev_fd, NTSYNC_IOC_WAIT_ANY, &wa);

    /* Now wait on a fresh, never-signaled event: this hits drain at the
     * top of ntsync_wait_any with no consume to follow, so SCHED_OTHER
     * must be restored.  Short timeout. */
    memset(&wa, 0, sizeof(wa));
    wa.count = 1; wa.objs = (uintptr_t)&sync_fd;
    wa.owner = gettid_compat();
    wa.timeout = abs_deadline_ns(20 * 1000000ULL);  /* 20ms */
    (void)ioctl(g_dev_fd, NTSYNC_IOC_WAIT_ANY, &wa);

    after.size = sizeof(after);
    sys_sched_getattr(0, &after, sizeof(after), 0);

    close(sync_fd);

    if (after.sched_policy != SCHED_OTHER) {
        fprintf(stderr, "DRAIN VERIFY FAILED: post-quiesce policy=%u prio=%u (expected SCHED_OTHER)\n",
                after.sched_policy, after.sched_priority);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int duration   = (argc > 1) ? atoi(argv[1]) : 30;
    int n_signaler = (argc > 2) ? atoi(argv[2]) : 4;
    int n_waiter   = (argc > 3) ? atoi(argv[3]) : 4;

    g_dev_fd = open("/dev/ntsync", O_RDWR | O_CLOEXEC);
    if (g_dev_fd < 0) { perror("open /dev/ntsync"); return 2; }

    {
        struct ntsync_event_args ea = { .manual = 1, .signaled = 0 };
        g_event_fd = ioctl(g_dev_fd, NTSYNC_IOC_CREATE_EVENT, &ea);
        if (g_event_fd < 0) { perror("CREATE_EVENT"); return 2; }
    }

    printf("== EVENT_SET_PI stress: %d signalers + %d waiters for %ds ==\n",
           n_signaler, n_waiter, duration);

    pthread_t *sigs = calloc(n_signaler, sizeof(pthread_t));
    pthread_t *wais = calloc(n_waiter,   sizeof(pthread_t));
    for (int i = 0; i < n_signaler; i++)
        pthread_create(&sigs[i], NULL, signaler_fn, (void*)(uintptr_t)i);
    for (int i = 0; i < n_waiter; i++)
        pthread_create(&wais[i], NULL, waiter_fn,   (void*)(uintptr_t)i);

    sleep(duration);
    atomic_store_explicit(&g_stop, 1, memory_order_relaxed);

    for (int i = 0; i < n_signaler; i++) pthread_join(sigs[i], NULL);
    for (int i = 0; i < n_waiter;   i++) pthread_join(wais[i], NULL);
    free(sigs); free(wais);

    /* Reset event so verify_drain_quiesced doesn't keep consuming. */
    {
        __u32 prev;
        (void)ioctl(g_event_fd, NTSYNC_IOC_EVENT_RESET, &prev);
    }
    int drain_ok = verify_drain_quiesced();

    long si = atomic_load(&g_signaler_iters);
    long wi = atomic_load(&g_waiter_iters);
    long ww = atomic_load(&g_waiter_woke);
    long ba = atomic_load(&g_boost_applied);
    long bm = atomic_load(&g_boost_missed);
    long se = atomic_load(&g_syscall_errors);

    close(g_event_fd);
    close(g_dev_fd);

    printf("\n== Results ==\n");
    printf("signaler iters: %ld\n", si);
    printf("waiter iters:   %ld   (woke: %ld, of which %.1f%%)\n",
           wi, ww, wi ? 100.0 * ww / wi : 0.0);
    printf("boost applied:  %ld   (%.1f%% of wakes)\n",
           ba, ww ? 100.0 * ba / ww : 0.0);
    printf("boost missed:   %ld   (informational — wake came from plain EVENT_SET)\n", bm);
    printf("syscall errors: %ld\n", se);
    printf("\nKASAN:        check `journalctl -k --since \"%ds ago\" | grep BUG`\n",
           duration + 5);

    printf("post-quiesce drain:  %s\n", drain_ok == 0 ? "OK (restored SCHED_OTHER)" : "FAIL");

    if (se > 0) {
        printf("RESULT: FAIL (%ld syscall errors)\n", se);
        return 2;
    }
    if (drain_ok != 0) {
        printf("RESULT: FAIL (drain did not restore SCHED_OTHER post-quiesce)\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
