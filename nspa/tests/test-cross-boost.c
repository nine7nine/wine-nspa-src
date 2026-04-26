/*
 * test-cross-boost: validates ntsync patch 1007 Claim 1 fix
 *
 *   Bug: pre-1007, mutex PI and event/channel PI snapshotted "original"
 *   sched attrs independently.  If event PI fired while a task was already
 *   mutex-PI-boosted, the event-PI snapshot captured the BOOSTED state as
 *   the baseline.  After mutex unwind, the event drain restored to the
 *   stale boosted state, leaking RT priority indefinitely.
 *
 *   Repro sequence (the bug-revealing order):
 *     1. T at SCHED_OTHER acquires mutex M.
 *     2. W at SCHED_FIFO 98 contends M -> mutex PI boosts T to FIFO 99.
 *     3. T waits on event E1 (T is currently boosted to FIFO 99).
 *     4. EVENT_SET_PI(E1, FIFO 50): apply_event_pi_boost runs.
 *        - OLD: snapshots T's CURRENT state {FIFO 99} as ep->orig_attr.
 *        - NEW: finds existing task_boost with true base {OTHER}.
 *     5. T wakes, releases M -> mutex PI drops -> T returns to "po orig".
 *        - OLD/NEW: T returns to {OTHER}.
 *     6. T re-enters wait (drain_event_pi_boosts runs).
 *        - OLD: restores T to ep->orig_attr {FIFO 99} -> LEAK.
 *        - NEW: restores T to base_attr {OTHER}.
 *
 * PASS = T at SCHED_OTHER after step 6.  FAIL = T at SCHED_FIFO.
 *
 * Build:
 *   gcc -O2 -Wall -o test-cross-boost test-cross-boost.c -lpthread
 *
 * Run (no root needed; sched_setattr_nocheck inside ntsync bypasses
 * CAP_SYS_NICE for the boost target):
 *   ./test-cross-boost
 *
 * Note: W must run at SCHED_FIFO 98, which DOES require root or
 * RLIMIT_RTPRIO.  If W can't enter FIFO, the test reports SKIP.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
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

struct ntsync_mutex_args { __u32 owner; __u32 count; };
struct ntsync_event_args { __u32 manual; __u32 signaled; };
struct ntsync_wait_args  {
    __u64 timeout; __u64 objs; __u32 count; __u32 index;
    __u32 flags; __u32 owner; __u32 alert; __u32 uring_fd;
};
struct ntsync_event_set_pi_args {
    __u32 flags; __u32 policy; __u32 prio; __u32 __pad;
};

#define NTSYNC_IOC_CREATE_MUTEX   _IOW ('N', 0x84, struct ntsync_mutex_args)
#define NTSYNC_IOC_CREATE_EVENT   _IOW ('N', 0x87, struct ntsync_event_args)
#define NTSYNC_IOC_WAIT_ANY       _IOWR('N', 0x82, struct ntsync_wait_args)
#define NTSYNC_IOC_MUTEX_UNLOCK   _IOWR('N', 0x85, struct ntsync_mutex_args)
#define NTSYNC_IOC_EVENT_SET_PI   _IOW ('N', 0x8e, struct ntsync_event_set_pi_args)

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
static int sys_sched_setattr(pid_t pid, struct local_sched_attr *attr,
                             unsigned int flags)
{
    return syscall(SYS_sched_setattr, pid, attr, flags);
}
static int gettid_compat(void) { return (int)syscall(SYS_gettid); }

static __u64 abs_deadline_ns(__u64 rel_ns)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec + rel_ns;
}

static const char *policy_name(unsigned int p)
{
    switch (p) {
    case SCHED_OTHER: return "SCHED_OTHER";
    case SCHED_FIFO:  return "SCHED_FIFO";
    case SCHED_RR:    return "SCHED_RR";
    case SCHED_BATCH: return "SCHED_BATCH";
    case SCHED_IDLE:  return "SCHED_IDLE";
    default:          return "(other)";
    }
}

/*
 * Coordination: a small step-flag protected by a mutex+cond.
 * Each step number is monotonically increased by main; threads wait
 * for "step >= my_step" then proceed.
 */
static pthread_mutex_t step_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  step_cv  = PTHREAD_COND_INITIALIZER;
static int step = 0;

static void set_step(int s)
{
    pthread_mutex_lock(&step_mtx);
    step = s;
    pthread_cond_broadcast(&step_cv);
    pthread_mutex_unlock(&step_mtx);
}
static void wait_step(int s)
{
    pthread_mutex_lock(&step_mtx);
    while (step < s) pthread_cond_wait(&step_cv, &step_mtx);
    pthread_mutex_unlock(&step_mtx);
}

/* Shared between main and target/waiter */
struct ctx {
    int dev_fd;
    int mutex_fd;
    int e1_fd;
    int e2_fd;
    pid_t target_tid;
    int   target_acquired;     /* set by T after grabbing M */
    int   waiter_blocked;      /* set by main after seeing W is in WAIT_ANY */
    int   target_woke_e1;      /* set by T after E1 wake */
    int   target_drained;      /* set by T after E2 wait completes */
    int   waiter_got_mutex;    /* set by W after acquiring M */
    int   waiter_skipped;      /* set if W couldn't enter FIFO */
    struct local_sched_attr target_attr_final;
};

static void *target_fn(void *arg)
{
    struct ctx *c = arg;
    struct ntsync_wait_args wa;
    int idx_unused;

    c->target_tid = gettid_compat();

    /* Step 1: acquire M */
    wait_step(1);
    memset(&wa, 0, sizeof(wa));
    wa.count   = 1;
    wa.objs    = (uintptr_t)&c->mutex_fd;
    wa.owner   = c->target_tid;
    wa.timeout = abs_deadline_ns(2ULL * 1000000000ULL);
    if (ioctl(c->dev_fd, NTSYNC_IOC_WAIT_ANY, &wa) < 0) {
        fprintf(stderr, "[T] mutex acquire failed: %s\n", strerror(errno));
        return NULL;
    }
    c->target_acquired = 1;
    set_step(2);

    /* Step 4: wait on E1 (mutex held; W blocked behind us; we should be
     * boosted to FIFO 99 right now via mutex PI). */
    wait_step(4);
    memset(&wa, 0, sizeof(wa));
    wa.count   = 1;
    wa.objs    = (uintptr_t)&c->e1_fd;
    wa.owner   = c->target_tid;
    wa.timeout = abs_deadline_ns(5ULL * 1000000000ULL);
    if (ioctl(c->dev_fd, NTSYNC_IOC_WAIT_ANY, &wa) < 0) {
        fprintf(stderr, "[T] E1 wait failed: %s\n", strerror(errno));
        return NULL;
    }
    c->target_woke_e1 = 1;

    /* Step 6: release M (mutex PI drops on this side via wait completion;
     * W will acquire next).  Use MUTEX_UNLOCK ioctl on the mutex object. */
    {
        struct ntsync_mutex_args mu = { .owner = c->target_tid, .count = 0 };
        if (ioctl(c->mutex_fd, NTSYNC_IOC_MUTEX_UNLOCK, &mu) < 0) {
            fprintf(stderr, "[T] MUTEX_UNLOCK failed: %s\n", strerror(errno));
        }
    }
    set_step(7);

    /* Step 8: re-enter wait on E2 with short timeout — this is the
     * drain_event_pi_boosts trigger. */
    wait_step(8);
    memset(&wa, 0, sizeof(wa));
    wa.count   = 1;
    wa.objs    = (uintptr_t)&c->e2_fd;
    wa.owner   = c->target_tid;
    wa.timeout = abs_deadline_ns(50ULL * 1000000ULL);  /* 50ms */
    (void)ioctl(c->dev_fd, NTSYNC_IOC_WAIT_ANY, &wa);
    /* Capture our own sched_attr immediately after drain. */
    c->target_attr_final.size = sizeof(c->target_attr_final);
    sys_sched_getattr(0, &c->target_attr_final, sizeof(c->target_attr_final), 0);
    c->target_drained = 1;
    set_step(9);

    (void)idx_unused;
    return NULL;
}

static void *waiter_fn(void *arg)
{
    struct ctx *c = arg;
    struct ntsync_wait_args wa;
    pid_t my_tid = gettid_compat();
    struct local_sched_attr fifo_hi = {
        .size = sizeof(fifo_hi),
        .sched_policy = SCHED_FIFO,
        .sched_priority = 98,  /* within typical @realtime group rtprio 98 cap */
    };

    /* Step 3: enter FIFO 98 then contend M */
    wait_step(3);
    if (sys_sched_setattr(0, &fifo_hi, 0) < 0) {
        fprintf(stderr, "[W] sched_setattr FIFO 98 failed: %s\n",
                strerror(errno));
        fprintf(stderr, "[W] (need RLIMIT_RTPRIO >= 98; check `ulimit -r` "
                        "and /etc/security/limits.d/*realtime*)\n");
        c->waiter_skipped = 1;
        set_step(99);
        return NULL;
    }

    memset(&wa, 0, sizeof(wa));
    wa.count   = 1;
    wa.objs    = (uintptr_t)&c->mutex_fd;
    wa.owner   = my_tid;
    wa.timeout = abs_deadline_ns(5ULL * 1000000000ULL);
    if (ioctl(c->dev_fd, NTSYNC_IOC_WAIT_ANY, &wa) < 0) {
        fprintf(stderr, "[W] mutex acquire failed: %s\n", strerror(errno));
        return NULL;
    }
    c->waiter_got_mutex = 1;
    /* Drop back to OTHER and unlock M so we don't bias the test. */
    {
        struct local_sched_attr other = {
            .size = sizeof(other), .sched_policy = SCHED_OTHER,
        };
        sys_sched_setattr(0, &other, 0);
    }
    {
        struct ntsync_mutex_args mu = { .owner = my_tid, .count = 0 };
        ioctl(c->mutex_fd, NTSYNC_IOC_MUTEX_UNLOCK, &mu);
    }
    return NULL;
}

int main(void)
{
    struct ctx c = {0};
    pthread_t target, waiter;
    int rc;

    c.dev_fd = open("/dev/ntsync", O_RDWR | O_CLOEXEC);
    if (c.dev_fd < 0) {
        fprintf(stderr, "open /dev/ntsync: %s\n", strerror(errno));
        return 1;
    }

    /* Create mutex (initially unowned) */
    {
        struct ntsync_mutex_args ma = { .owner = 0, .count = 0 };
        c.mutex_fd = ioctl(c.dev_fd, NTSYNC_IOC_CREATE_MUTEX, &ma);
        if (c.mutex_fd < 0) {
            fprintf(stderr, "CREATE_MUTEX failed: %s\n", strerror(errno));
            return 1;
        }
    }
    /* E1 = the event T blocks on; E2 = the wait T re-enters to trigger drain */
    {
        struct ntsync_event_args ea = { .manual = 1, .signaled = 0 };
        c.e1_fd = ioctl(c.dev_fd, NTSYNC_IOC_CREATE_EVENT, &ea);
        c.e2_fd = ioctl(c.dev_fd, NTSYNC_IOC_CREATE_EVENT, &ea);
        if (c.e1_fd < 0 || c.e2_fd < 0) {
            fprintf(stderr, "CREATE_EVENT failed: %s\n", strerror(errno));
            return 1;
        }
    }

    printf("== test-cross-boost (ntsync 1007 Claim 1) ==\n");

    pthread_create(&target, NULL, target_fn, &c);
    pthread_create(&waiter, NULL, waiter_fn, &c);

    /* Step 1: T acquires M */
    set_step(1);
    while (!c.target_acquired) usleep(1000);

    /* Step 3: W enters FIFO 99 and contends M */
    set_step(3);
    /* Wait for W to either block on M or skip */
    {
        int spins = 0;
        while (!c.waiter_skipped && !c.waiter_got_mutex && spins++ < 500)
            usleep(1000);  /* up to 500ms */
    }
    if (c.waiter_skipped) {
        printf("RESULT: SKIP (waiter could not enter SCHED_FIFO 98 — try sudo)\n");
        pthread_join(target, NULL);
        pthread_join(waiter, NULL);
        return 77;
    }
    if (c.waiter_got_mutex) {
        /* T released M before W contended — sequence broken; retry would be
         * needed. Bail with a clear message. */
        fprintf(stderr, "[main] sequence broke: W acquired M before T waited "
                        "on E1. The test needs T to hold M while W contends.\n");
        return 1;
    }
    /* W is blocked on M (mutex PI fired and boosted T to FIFO 99). */

    /* Step 4: T waits on E1 */
    set_step(4);
    usleep(50 * 1000);  /* let T enter wait */

    /* Step 5: EVENT_SET_PI(E1, FIFO 50) — bug-trigger */
    {
        struct ntsync_event_set_pi_args pi = {
            .flags = 0, .policy = SCHED_FIFO, .prio = 50, .__pad = 0,
        };
        if (ioctl(c.e1_fd, NTSYNC_IOC_EVENT_SET_PI, &pi) < 0) {
            fprintf(stderr, "[main] EVENT_SET_PI failed: %s\n", strerror(errno));
            return 1;
        }
    }

    /* Wait until T has woken from E1, released M, and W has grabbed M */
    wait_step(7);
    {
        int spins = 0;
        while (!c.waiter_got_mutex && spins++ < 1000) usleep(1000);
    }
    if (!c.waiter_got_mutex) {
        fprintf(stderr, "[main] W never acquired M after T released — bail\n");
        return 1;
    }

    /* Step 8: tell T to enter the drain wait */
    set_step(8);
    wait_step(9);

    /* Read T's final sched attr (T captured it locally already) */
    printf("[T] post-drain: policy=%s prio=%u nice=%d\n",
           policy_name(c.target_attr_final.sched_policy),
           c.target_attr_final.sched_priority,
           c.target_attr_final.sched_nice);

    pthread_join(target, NULL);
    pthread_join(waiter, NULL);

    rc = 0;
    if (c.target_attr_final.sched_policy != SCHED_OTHER) {
        fprintf(stderr, "FAIL: T leaked at %s prio=%u — expected SCHED_OTHER. "
                        "This is the pre-1007 cross-boost bug.\n",
                policy_name(c.target_attr_final.sched_policy),
                c.target_attr_final.sched_priority);
        rc = 1;
    }
    if (c.target_attr_final.sched_priority != 0) {
        fprintf(stderr, "FAIL: T's rt_priority is %u, expected 0\n",
                c.target_attr_final.sched_priority);
        rc = 1;
    }

    close(c.e1_fd);
    close(c.e2_fd);
    close(c.mutex_fd);
    close(c.dev_fd);

    if (rc == 0) {
        printf("RESULT: PASS\n");
    } else {
        printf("RESULT: FAIL\n");
    }
    return rc;
}
