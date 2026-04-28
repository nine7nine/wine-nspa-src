/*
 * NTSYNC_IOC_EVENT_SET_PI smoke test
 *
 * Validates:
 *   1. ioctl dispatches and returns 0 on a normal event
 *   2. First waiter on the event has its sched policy raised to the
 *      requested (policy, prio) after wake
 *   3. Auto-release on the waiter's next ntsync_wait_* entry — after
 *      re-entering a wait, the original sched attrs are restored
 *   4. Plain EVENT_SET (control) does NOT boost
 *
 * Build (native Linux, not Wine):
 *   gcc -O2 -Wall -o test-event-set-pi test-event-set-pi.c -lpthread
 *
 * Run:
 *   ./test-event-set-pi
 *   (no root required — sched_setattr_nocheck is kernel-internal and
 *   bypasses the CAP_SYS_NICE check for the boost target)
 *
 * Exit code: 0 on all tests pass, 1 on any failure.
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

/*
 * Local copy of ntsync uapi definitions — kept independent of system
 * headers so the test builds on any host where the patched kernel may
 * not yet have installed its uapi header.
 */
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

#define NTSYNC_IOC_CREATE_EVENT   _IOW('N', 0x87, struct ntsync_event_args)
#define NTSYNC_IOC_WAIT_ANY       _IOWR('N', 0x82, struct ntsync_wait_args)
#define NTSYNC_IOC_EVENT_SET      _IOR('N', 0x88, __u32)
#define NTSYNC_IOC_EVENT_RESET    _IOR('N', 0x89, __u32)
#define NTSYNC_IOC_EVENT_SET_PI   _IOW('N', 0x8e, struct ntsync_event_set_pi_args)

/*
 * sched_getattr — not exposed by glibc, syscall direct.
 */
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

/* Per-iteration thread-shared state */
struct waiter_ctx {
    int                   dev_fd;
    int                   event_fd;
    int                   sync_event_fd;      /* used to drive re-entry into wait */
    volatile int          ready;              /* set by waiter just before WAIT_ANY ioctl */
    volatile int          woke;
    struct local_sched_attr attr_after_wake;  /* captured after first wait return */
    struct local_sched_attr attr_after_reentry; /* captured after re-entering wait */
    int                   last_errno;
};

static int gettid_compat(void)
{
    return (int)syscall(SYS_gettid);
}

/* ntsync timeout is an absolute CLOCK_MONOTONIC deadline in ns
 * (without NTSYNC_WAIT_REALTIME flag).  Convert relative ns -> deadline. */
static __u64 abs_deadline_ns(__u64 relative_ns)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec + relative_ns;
}

/*
 * Waiter thread:
 *   1. Sleep until main signals the event via EVENT_SET_PI
 *   2. Capture sched_attr (should show boost)
 *   3. Re-enter wait on sync_event (short timeout) — drain triggers
 *   4. Capture sched_attr (should be restored)
 */
static void *waiter_fn(void *arg)
{
    struct waiter_ctx *ctx = arg;
    struct ntsync_wait_args wargs;
    int ret;

    /* Wait 5s max on the boost event */
    memset(&wargs, 0, sizeof(wargs));
    wargs.count   = 1;
    wargs.objs    = (uintptr_t)&ctx->event_fd;
    wargs.owner   = gettid_compat();
    wargs.timeout = abs_deadline_ns(5ULL * 1000000000ULL);  /* 5s deadline */

    /* Mark ready right before the ioctl so main can stop spinning and
     * give us a tight wait-window before signaling.  Closes the timing
     * flake observed under KASAN where main's fixed usleep(100ms) was
     * occasionally too short for the waiter to enter ntsync_wait_any. */
    __atomic_store_n(&ctx->ready, 1, __ATOMIC_RELEASE);

    ret = ioctl(ctx->dev_fd, NTSYNC_IOC_WAIT_ANY, &wargs);
    if (ret < 0) {
        ctx->last_errno = errno;
        ctx->woke = -1;
        return NULL;
    }
    ctx->woke = 1;

    /* Capture sched attrs post-wake */
    ctx->attr_after_wake.size = sizeof(ctx->attr_after_wake);
    sys_sched_getattr(0, &ctx->attr_after_wake, sizeof(ctx->attr_after_wake), 0);

    /* Re-enter wait on a DIFFERENT event with short timeout — this hits
     * drain_event_pi_boosts at the top of ntsync_wait_any.  We expect
     * timeout (ETIMEDOUT) since nothing signals sync_event. */
    memset(&wargs, 0, sizeof(wargs));
    wargs.count   = 1;
    wargs.objs    = (uintptr_t)&ctx->sync_event_fd;
    wargs.owner   = gettid_compat();
    wargs.timeout = abs_deadline_ns(50000000ULL);  /* 50ms deadline */
    (void)ioctl(ctx->dev_fd, NTSYNC_IOC_WAIT_ANY, &wargs);

    /* Capture sched attrs after drain */
    ctx->attr_after_reentry.size = sizeof(ctx->attr_after_reentry);
    sys_sched_getattr(0, &ctx->attr_after_reentry, sizeof(ctx->attr_after_reentry), 0);

    return NULL;
}

static int create_event(int dev_fd, int manual, int signaled)
{
    struct ntsync_event_args a = { .manual = manual, .signaled = signaled };
    int fd = ioctl(dev_fd, NTSYNC_IOC_CREATE_EVENT, &a);
    return fd;
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

static int run_case(int dev_fd, int use_pi, const char *label)
{
    pthread_t waiter;
    struct waiter_ctx ctx = {0};
    struct ntsync_event_set_pi_args pi_args = {
        .flags = 0, .policy = SCHED_FIFO, .prio = 80, .__pad = 0,
    };
    struct local_sched_attr start_attr;
    int fail = 0;
    unsigned int prev_state;

    ctx.dev_fd       = dev_fd;
    ctx.event_fd     = create_event(dev_fd, 1, 0);  /* manual-reset, not signaled */
    ctx.sync_event_fd = create_event(dev_fd, 1, 0);
    if (ctx.event_fd < 0 || ctx.sync_event_fd < 0) {
        fprintf(stderr, "[%s] create_event failed: %s\n", label, strerror(errno));
        return 1;
    }

    /* Record our (main thread's) sched attr for reference */
    start_attr.size = sizeof(start_attr);
    sys_sched_getattr(0, &start_attr, sizeof(start_attr), 0);

    /* Spawn waiter at default policy (SCHED_OTHER, nice 0) */
    if (pthread_create(&waiter, NULL, waiter_fn, &ctx) != 0) {
        fprintf(stderr, "[%s] pthread_create failed\n", label);
        return 1;
    }

    /* Wait until the waiter has armed itself for the WAIT_ANY ioctl.
     * The atomic ready flag closes the rendezvous, but the waiter is
     * still about to enter the kernel — give it a small extra delay
     * to actually queue itself in event->any_waiters.  Total wait is
     * O(1ms) on a healthy system, bounded at ~1s if scheduling is
     * pathological (KASAN under contention). */
    {
        int spins;
        for (spins = 0; spins < 10000; spins++) {
            if (__atomic_load_n(&ctx.ready, __ATOMIC_ACQUIRE))
                break;
            usleep(100);  /* 100us */
        }
        if (!__atomic_load_n(&ctx.ready, __ATOMIC_ACQUIRE)) {
            fprintf(stderr, "[%s] waiter failed to mark ready in 1s — bailing\n", label);
            pthread_join(waiter, NULL);
            return 1;
        }
        /* Waiter has armed; small grace period for the syscall to
         * actually queue in event->any_waiters before we signal. */
        usleep(20 * 1000);  /* 20ms */
    }

    /* Signal the event */
    if (use_pi) {
        if (ioctl(dev_fd, NTSYNC_IOC_EVENT_SET_PI, &pi_args) < 0) {
            fprintf(stderr, "[%s] EVENT_SET_PI on dev fd expected to fail "
                    "(obj ioctl on device fd): %s\n", label, strerror(errno));
            /* fallthrough — correct path is on event fd */
        }
        /* Correct path: obj ioctl on the event fd */
        if (ioctl(ctx.event_fd, NTSYNC_IOC_EVENT_SET_PI, &pi_args) < 0) {
            fprintf(stderr, "[%s] EVENT_SET_PI(event_fd) failed: %s\n",
                    label, strerror(errno));
            fail = 1;
            goto join;
        }
    } else {
        if (ioctl(ctx.event_fd, NTSYNC_IOC_EVENT_SET, &prev_state) < 0) {
            fprintf(stderr, "[%s] EVENT_SET failed: %s\n", label, strerror(errno));
            fail = 1;
            goto join;
        }
    }

join:
    pthread_join(waiter, NULL);

    if (ctx.woke != 1) {
        fprintf(stderr, "[%s] waiter did not wake (woke=%d errno=%d)\n",
                label, ctx.woke, ctx.last_errno);
        return 1;
    }

    printf("[%s] post-wake:      policy=%s prio=%u nice=%d\n", label,
           policy_name(ctx.attr_after_wake.sched_policy),
           ctx.attr_after_wake.sched_priority,
           ctx.attr_after_wake.sched_nice);
    printf("[%s] post-re-entry:  policy=%s prio=%u nice=%d\n", label,
           policy_name(ctx.attr_after_reentry.sched_policy),
           ctx.attr_after_reentry.sched_priority,
           ctx.attr_after_reentry.sched_nice);

    if (use_pi) {
        /* Post-wake must be boosted */
        if (ctx.attr_after_wake.sched_policy != SCHED_FIFO ||
            ctx.attr_after_wake.sched_priority != 80) {
            fprintf(stderr, "[%s] FAIL: expected FIFO 80 after wake, "
                    "got %s prio=%u\n", label,
                    policy_name(ctx.attr_after_wake.sched_policy),
                    ctx.attr_after_wake.sched_priority);
            fail = 1;
        }
        /* Post-re-entry must be restored */
        if (ctx.attr_after_reentry.sched_policy != SCHED_OTHER) {
            fprintf(stderr, "[%s] FAIL: expected SCHED_OTHER after re-entry "
                    "(drain), got %s prio=%u\n", label,
                    policy_name(ctx.attr_after_reentry.sched_policy),
                    ctx.attr_after_reentry.sched_priority);
            fail = 1;
        }
    } else {
        /* Control: should stay SCHED_OTHER throughout */
        if (ctx.attr_after_wake.sched_policy != SCHED_OTHER) {
            fprintf(stderr, "[%s] FAIL: EVENT_SET boosted the waiter "
                    "(policy=%s prio=%u) — should have been no-op\n",
                    label,
                    policy_name(ctx.attr_after_wake.sched_policy),
                    ctx.attr_after_wake.sched_priority);
            fail = 1;
        }
    }

    close(ctx.event_fd);
    close(ctx.sync_event_fd);
    return fail;
}

int main(void)
{
    int dev_fd;
    int fail = 0;

    dev_fd = open("/dev/ntsync", O_RDWR | O_CLOEXEC);
    if (dev_fd < 0) {
        fprintf(stderr, "open /dev/ntsync: %s\n", strerror(errno));
        fprintf(stderr, "(is the ntsync module loaded? `lsmod | grep ntsync`)\n");
        return 1;
    }

    printf("== NTSYNC_IOC_EVENT_SET_PI smoke test ==\n");

    /* Control: plain EVENT_SET should NOT change waiter's sched */
    fail |= run_case(dev_fd, 0, "control-EVENT_SET");

    /* The test: EVENT_SET_PI boosts, drain restores */
    fail |= run_case(dev_fd, 1, "EVENT_SET_PI");

    close(dev_fd);

    if (fail) {
        printf("\nRESULT: FAIL\n");
        return 1;
    }
    printf("\nRESULT: PASS\n");
    return 0;
}
