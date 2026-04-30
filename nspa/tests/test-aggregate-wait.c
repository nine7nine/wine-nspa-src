/*
 * NTSYNC_IOC_AGGREGATE_WAIT smoke test — patch 1010.
 *
 * Validates:
 *   1. basic — wait on (event, eventfd), each signaled in turn,
 *               fired_index reflects user-source-array index
 *   2. timeout — sources never fire, deadline expires, returns
 *                 -ETIMEDOUT with fired_index = NTSYNC_AGG_TIMEOUT
 *   3. PI propagation — low-prio aggregate-waiter on (event, fd);
 *                        high-prio EVENT_SET_PI on the event boosts
 *                        the waiter; chrt-visible policy/prio confirms
 *                        aggregate-waiters share the same any_waiters
 *                        list as WAIT_ANY waiters (load-bearing per
 *                        design doc §4.4)
 *   4. 32-source stress — 16 obj + 16 fd; randomly signal one;
 *                          fired_index always matches signaling source
 *                          across N iterations
 *   5. mixed obj+fd — alternate obj and fd signals; verify both types
 *                      wake correctly and fired_events bits reflect
 *                      the actual poll mask for fd sources
 *   6. cancel via signal — pthread_kill mid-wait; ioctl returns
 *                           -ERESTARTSYS, all sources cleanly
 *                           unregistered (KASAN catches leaks)
 *
 * Build (native Linux, not Wine):
 *   gcc -O2 -Wall -Wextra -o test-aggregate-wait test-aggregate-wait.c -lpthread
 *
 * Run:
 *   ./test-aggregate-wait
 *   (no root required for sub-tests 1/2/4/5/6;
 *    sub-test 3 needs the kernel's sched_setattr_nocheck path which is
 *    bypassed for the boost target — same as test-event-set-pi)
 *
 * Exit code: 0 on all tests pass, 1 on any failure.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/types.h>

/* ============================================================
 *  Local copy of ntsync uapi (independent of system header).
 *  Mirrors include/uapi/linux/ntsync.h post-1010.
 * ============================================================ */

struct ntsync_event_args {
    __u32 manual;
    __u32 signaled;
};

struct ntsync_event_set_pi_args {
    __u32 flags;
    __u32 policy;
    __u32 prio;
    __u32 __pad;
};

struct ntsync_aggregate_source {
    __u32 type;
    __u32 events;
    __u32 fd;
    __u32 __pad;
};

struct ntsync_aggregate_wait_args {
    __u64 timeout;
    __u64 sources;
    __u32 nb_sources;
    __u32 fired_index;
    __u32 flags;
    __u32 owner;
    __u32 fired_events;
    __u32 __pad;
};

#define NTSYNC_AGG_OBJECT          0x1
#define NTSYNC_AGG_FD              0x2
#define NTSYNC_AGG_MAX             64
#define NTSYNC_AGG_FLAG_REALTIME   0x1
#define NTSYNC_AGG_TIMEOUT         0xFFFFFFFFu

#define NTSYNC_IOC_CREATE_EVENT    _IOW ('N', 0x87, struct ntsync_event_args)
#define NTSYNC_IOC_EVENT_SET       _IOR ('N', 0x88, __u32)
#define NTSYNC_IOC_EVENT_RESET     _IOR ('N', 0x89, __u32)
#define NTSYNC_IOC_EVENT_SET_PI    _IOW ('N', 0x8e, struct ntsync_event_set_pi_args)
#define NTSYNC_IOC_AGGREGATE_WAIT  _IOWR('N', 0x97, struct ntsync_aggregate_wait_args)

/* Suppresses per-sub-test PASS lines in stress mode (avoids 4M stdout
 * lines at 1M iters).  Failures always go to stderr regardless. */
static int g_quiet = 0;
#define NOTE(...) do { if (!g_quiet) printf(__VA_ARGS__); } while (0)

/* sched_getattr — not exposed by glibc, syscall direct. */
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

/* Absolute CLOCK_MONOTONIC deadline ns from a relative ns offset. */
static __u64 abs_deadline_ns(__u64 relative_ns)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec + relative_ns;
}

static int create_event(int dev_fd, int manual, int signaled)
{
    struct ntsync_event_args a = { .manual = manual, .signaled = signaled };
    return ioctl(dev_fd, NTSYNC_IOC_CREATE_EVENT, &a);
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

/* ============================================================
 *  Sub-test 1: basic — wait on (event, eventfd), each fires
 * ============================================================ */
static int test_basic(int dev_fd)
{
    struct ntsync_aggregate_source srcs[2];
    struct ntsync_aggregate_wait_args args;
    int event_fd, evfd;
    __u32 prev;
    uint64_t one = 1;
    int ret, fail = 0;

    event_fd = create_event(dev_fd, 1, 0);   /* manual-reset, not signaled */
    evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (event_fd < 0 || evfd < 0) {
        fprintf(stderr, "[basic] create resources failed: %s\n", strerror(errno));
        if (event_fd >= 0) close(event_fd);
        if (evfd >= 0) close(evfd);
        return 1;
    }

    /* === Case 1.a: signal the event source === */
    if (ioctl(event_fd, NTSYNC_IOC_EVENT_SET, &prev) < 0) {
        fprintf(stderr, "[basic] EVENT_SET failed: %s\n", strerror(errno));
        fail = 1; goto cleanup;
    }

    srcs[0].type = NTSYNC_AGG_OBJECT;
    srcs[0].events = 0;
    srcs[0].fd = event_fd;
    srcs[0].__pad = 0;
    srcs[1].type = NTSYNC_AGG_FD;
    srcs[1].events = POLLIN;
    srcs[1].fd = evfd;
    srcs[1].__pad = 0;

    memset(&args, 0, sizeof(args));
    args.timeout = abs_deadline_ns(2ULL * 1000000000ULL);  /* 2s */
    args.sources = (uintptr_t)srcs;
    args.nb_sources = 2;
    args.owner = gettid_compat();

    ret = ioctl(dev_fd, NTSYNC_IOC_AGGREGATE_WAIT, &args);
    if (ret < 0) {
        fprintf(stderr, "[basic] case A AGGREGATE_WAIT failed: %s\n", strerror(errno));
        fail = 1; goto cleanup;
    }
    if (args.fired_index != 0) {
        fprintf(stderr, "[basic] case A fired_index=%u, expected 0 (event)\n",
                args.fired_index);
        fail = 1;
    }
    if (args.fired_events != 0) {
        fprintf(stderr, "[basic] case A fired_events=%u, expected 0 for OBJECT\n",
                args.fired_events);
        fail = 1;
    }
    /* event was auto-consumed (auto-reset would, but we set manual=1 — so
     * event stays signaled).  Reset for next case. */
    if (ioctl(event_fd, NTSYNC_IOC_EVENT_RESET, &prev) < 0) {
        fprintf(stderr, "[basic] EVENT_RESET failed: %s\n", strerror(errno));
        fail = 1; goto cleanup;
    }

    /* === Case 1.b: signal the eventfd source === */
    if (write(evfd, &one, sizeof(one)) != sizeof(one)) {
        fprintf(stderr, "[basic] eventfd write failed: %s\n", strerror(errno));
        fail = 1; goto cleanup;
    }

    memset(&args, 0, sizeof(args));
    args.timeout = abs_deadline_ns(2ULL * 1000000000ULL);
    args.sources = (uintptr_t)srcs;
    args.nb_sources = 2;
    args.owner = gettid_compat();

    ret = ioctl(dev_fd, NTSYNC_IOC_AGGREGATE_WAIT, &args);
    if (ret < 0) {
        fprintf(stderr, "[basic] case B AGGREGATE_WAIT failed: %s\n", strerror(errno));
        fail = 1; goto cleanup;
    }
    if (args.fired_index != 1) {
        fprintf(stderr, "[basic] case B fired_index=%u, expected 1 (eventfd)\n",
                args.fired_index);
        fail = 1;
    }
    if (!(args.fired_events & POLLIN)) {
        fprintf(stderr, "[basic] case B fired_events=%#x, expected POLLIN\n",
                args.fired_events);
        fail = 1;
    }

    if (!fail) NOTE("[basic]                      PASS\n");

cleanup:
    close(event_fd);
    close(evfd);
    return fail;
}

/* ============================================================
 *  Sub-test 2: timeout — nothing fires, deadline expires
 * ============================================================ */
static int test_timeout(int dev_fd)
{
    struct ntsync_aggregate_source srcs[2];
    struct ntsync_aggregate_wait_args args;
    int event_fd, evfd;
    int ret, fail = 0;
    struct timespec t0, t1;
    uint64_t elapsed_ns;

    event_fd = create_event(dev_fd, 1, 0);
    evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (event_fd < 0 || evfd < 0) {
        fprintf(stderr, "[timeout] create resources failed: %s\n", strerror(errno));
        if (event_fd >= 0) close(event_fd);
        if (evfd >= 0) close(evfd);
        return 1;
    }

    srcs[0].type = NTSYNC_AGG_OBJECT;
    srcs[0].events = 0;
    srcs[0].fd = event_fd;
    srcs[0].__pad = 0;
    srcs[1].type = NTSYNC_AGG_FD;
    srcs[1].events = POLLIN;
    srcs[1].fd = evfd;
    srcs[1].__pad = 0;

    memset(&args, 0, sizeof(args));
    args.timeout = abs_deadline_ns(150000000ULL);  /* 150ms */
    args.sources = (uintptr_t)srcs;
    args.nb_sources = 2;
    args.owner = gettid_compat();

    clock_gettime(CLOCK_MONOTONIC, &t0);
    ret = ioctl(dev_fd, NTSYNC_IOC_AGGREGATE_WAIT, &args);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    elapsed_ns = (uint64_t)(t1.tv_sec - t0.tv_sec) * 1000000000ULL +
                 (uint64_t)t1.tv_nsec - (uint64_t)t0.tv_nsec;

    if (ret >= 0 || errno != ETIMEDOUT) {
        fprintf(stderr, "[timeout] expected -ETIMEDOUT, got ret=%d errno=%d (%s)\n",
                ret, errno, strerror(errno));
        fail = 1;
    }
    if (args.fired_index != NTSYNC_AGG_TIMEOUT) {
        fprintf(stderr, "[timeout] fired_index=%#x, expected NTSYNC_AGG_TIMEOUT (%#x)\n",
                args.fired_index, NTSYNC_AGG_TIMEOUT);
        fail = 1;
    }
    /* Sanity: actually slept for ~150ms (allow 100..500ms window for
     * scheduler jitter under KASAN) */
    if (elapsed_ns < 100000000ULL || elapsed_ns > 500000000ULL) {
        fprintf(stderr, "[timeout] elapsed %.2f ms outside [100,500]ms window\n",
                elapsed_ns / 1e6);
        fail = 1;
    }

    if (!fail) NOTE("[timeout]                    PASS  (slept %.1fms)\n",
                      elapsed_ns / 1e6);

    close(event_fd);
    close(evfd);
    return fail;
}

/* ============================================================
 *  Sub-test 3: PI propagation — load-bearing for aggregate-wait
 *
 *  Aggregate-waiter on (event, eventfd).  Sender does EVENT_SET_PI
 *  on the event with high prio.  Aggregate-waiter must wake AND
 *  have its scheduling attrs raised (the same propagation that
 *  WAIT_ANY waiters get).
 * ============================================================ */
struct pi_ctx {
    int dev_fd;
    int event_fd;
    int evfd;
    volatile int ready;
    volatile int woke;
    int last_errno;
    struct local_sched_attr attr_after_wake;
    __u32 fired_index_out;
};

static void *pi_waiter_fn(void *arg)
{
    struct pi_ctx *c = arg;
    struct ntsync_aggregate_source srcs[2];
    struct ntsync_aggregate_wait_args args;
    int ret;

    srcs[0].type = NTSYNC_AGG_OBJECT;
    srcs[0].events = 0;
    srcs[0].fd = c->event_fd;
    srcs[0].__pad = 0;
    srcs[1].type = NTSYNC_AGG_FD;
    srcs[1].events = POLLIN;
    srcs[1].fd = c->evfd;
    srcs[1].__pad = 0;

    memset(&args, 0, sizeof(args));
    args.timeout = abs_deadline_ns(5ULL * 1000000000ULL);
    args.sources = (uintptr_t)srcs;
    args.nb_sources = 2;
    args.owner = gettid_compat();

    __atomic_store_n(&c->ready, 1, __ATOMIC_RELEASE);

    ret = ioctl(c->dev_fd, NTSYNC_IOC_AGGREGATE_WAIT, &args);
    if (ret < 0) {
        c->last_errno = errno;
        c->woke = -1;
        return NULL;
    }
    c->woke = 1;
    c->fired_index_out = args.fired_index;

    /* Capture sched attrs WHILE STILL IN BOOSTED STATE.  drain happens
     * on next wait, so don't enter another wait before reading. */
    c->attr_after_wake.size = sizeof(c->attr_after_wake);
    sys_sched_getattr(0, &c->attr_after_wake, sizeof(c->attr_after_wake), 0);
    return NULL;
}

static int test_pi_propagation(int dev_fd)
{
    struct pi_ctx ctx = {0};
    pthread_t waiter;
    struct ntsync_event_set_pi_args pi_args = {
        .flags = 0, .policy = SCHED_FIFO, .prio = 80, .__pad = 0,
    };
    int spins, fail = 0;

    ctx.dev_fd = dev_fd;
    ctx.event_fd = create_event(dev_fd, 1, 0);    /* manual, not signaled */
    ctx.evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ctx.event_fd < 0 || ctx.evfd < 0) {
        fprintf(stderr, "[pi] create resources failed: %s\n", strerror(errno));
        if (ctx.event_fd >= 0) close(ctx.event_fd);
        if (ctx.evfd >= 0) close(ctx.evfd);
        return 1;
    }

    if (pthread_create(&waiter, NULL, pi_waiter_fn, &ctx) != 0) {
        fprintf(stderr, "[pi] pthread_create failed\n");
        close(ctx.event_fd); close(ctx.evfd);
        return 1;
    }

    /* Wait for waiter to arm itself, then small grace period for the
     * ioctl to actually queue on event->any_waiters before EVENT_SET_PI
     * fires.  Same rendezvous shape as test-event-set-pi. */
    for (spins = 0; spins < 10000; spins++) {
        if (__atomic_load_n(&ctx.ready, __ATOMIC_ACQUIRE)) break;
        usleep(100);
    }
    if (!__atomic_load_n(&ctx.ready, __ATOMIC_ACQUIRE)) {
        fprintf(stderr, "[pi] waiter never armed\n");
        pthread_join(waiter, NULL);
        close(ctx.event_fd); close(ctx.evfd);
        return 1;
    }
    usleep(20 * 1000);  /* 20ms grace */

    /* Sender: EVENT_SET_PI on the event.  This must:
     *  (a) wake the aggregate-waiter (via try_wake_any_event finding
     *      our entry in event->any_waiters)
     *  (b) boost the waiter to (FIFO, 80) — the load-bearing assertion */
    if (ioctl(ctx.event_fd, NTSYNC_IOC_EVENT_SET_PI, &pi_args) < 0) {
        fprintf(stderr, "[pi] EVENT_SET_PI failed: %s\n", strerror(errno));
        fail = 1;
    }

    pthread_join(waiter, NULL);

    if (ctx.woke != 1) {
        fprintf(stderr, "[pi] waiter did not wake (woke=%d errno=%d)\n",
                ctx.woke, ctx.last_errno);
        fail = 1;
        goto cleanup;
    }

    if (ctx.fired_index_out != 0) {
        fprintf(stderr, "[pi] fired_index=%u, expected 0 (event source)\n",
                ctx.fired_index_out);
        fail = 1;
    }

    /* The load-bearing check */
    if (ctx.attr_after_wake.sched_policy != SCHED_FIFO ||
        ctx.attr_after_wake.sched_priority != 80) {
        fprintf(stderr, "[pi] FAIL: aggregate-waiter NOT boosted via "
                "EVENT_SET_PI.  Got policy=%s prio=%u, expected FIFO 80.\n"
                "       This means aggregate-wait is NOT registering on "
                "event->any_waiters — design doc §4.4 violation.\n",
                policy_name(ctx.attr_after_wake.sched_policy),
                ctx.attr_after_wake.sched_priority);
        fail = 1;
    }

    if (!fail) NOTE("[pi-propagation]             PASS  (boost %s prio=%u)\n",
                      policy_name(ctx.attr_after_wake.sched_policy),
                      ctx.attr_after_wake.sched_priority);

cleanup:
    close(ctx.event_fd);
    close(ctx.evfd);
    return fail;
}

/* ============================================================
 *  Sub-test 4: 32-source stress — random signals over many iters
 * ============================================================ */
static int test_32_source_stress(int dev_fd)
{
    enum { NB_OBJ = 16, NB_FD = 16, NB = NB_OBJ + NB_FD, ITERS = 200 };
    struct ntsync_aggregate_source srcs[NB];
    struct ntsync_aggregate_wait_args args;
    int events[NB_OBJ], evfds[NB_FD];
    unsigned seed = 0x1234abcd;
    int iter, i, ret, fail = 0;

    /* Resources */
    for (i = 0; i < NB_OBJ; i++) {
        events[i] = create_event(dev_fd, 1, 0);
        if (events[i] < 0) { fail = 1; goto cleanup; }
    }
    for (i = 0; i < NB_FD; i++) {
        evfds[i] = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (evfds[i] < 0) { fail = 1; goto cleanup; }
    }

    /* Build the source array once. */
    for (i = 0; i < NB_OBJ; i++) {
        srcs[i].type = NTSYNC_AGG_OBJECT;
        srcs[i].events = 0;
        srcs[i].fd = events[i];
        srcs[i].__pad = 0;
    }
    for (i = 0; i < NB_FD; i++) {
        srcs[NB_OBJ + i].type = NTSYNC_AGG_FD;
        srcs[NB_OBJ + i].events = POLLIN;
        srcs[NB_OBJ + i].fd = evfds[i];
        srcs[NB_OBJ + i].__pad = 0;
    }

    for (iter = 0; iter < ITERS; iter++) {
        /* Pick a random source to signal */
        unsigned pick = rand_r(&seed) % NB;
        __u32 prev;
        uint64_t one = 1;

        if (pick < NB_OBJ) {
            if (ioctl(events[pick], NTSYNC_IOC_EVENT_SET, &prev) < 0) {
                fprintf(stderr, "[stress] iter %d EVENT_SET pick=%u failed: %s\n",
                        iter, pick, strerror(errno));
                fail = 1; break;
            }
        } else {
            if (write(evfds[pick - NB_OBJ], &one, sizeof(one)) != sizeof(one)) {
                fprintf(stderr, "[stress] iter %d eventfd write pick=%u failed: %s\n",
                        iter, pick, strerror(errno));
                fail = 1; break;
            }
        }

        memset(&args, 0, sizeof(args));
        args.timeout = abs_deadline_ns(1ULL * 1000000000ULL);
        args.sources = (uintptr_t)srcs;
        args.nb_sources = NB;
        args.owner = gettid_compat();

        ret = ioctl(dev_fd, NTSYNC_IOC_AGGREGATE_WAIT, &args);
        if (ret < 0) {
            fprintf(stderr, "[stress] iter %d AGGREGATE_WAIT failed: %s\n",
                    iter, strerror(errno));
            fail = 1; break;
        }
        if (args.fired_index != pick) {
            fprintf(stderr, "[stress] iter %d fired_index=%u, expected %u\n",
                    iter, args.fired_index, pick);
            fail = 1; break;
        }
        if (pick >= NB_OBJ && !(args.fired_events & POLLIN)) {
            fprintf(stderr, "[stress] iter %d fd source pick=%u fired_events=%#x, "
                    "expected POLLIN\n", iter, pick, args.fired_events);
            fail = 1; break;
        }

        /* Drain so the next iter starts clean */
        if (pick < NB_OBJ) {
            (void)ioctl(events[pick], NTSYNC_IOC_EVENT_RESET, &prev);
        } else {
            uint64_t drain;
            (void)read(evfds[pick - NB_OBJ], &drain, sizeof(drain));
        }
    }

    if (!fail) NOTE("[32-source stress]           PASS  (%d iters)\n", ITERS);

cleanup:
    for (i = 0; i < NB_OBJ; i++) if (events[i] >= 0) close(events[i]);
    for (i = 0; i < NB_FD; i++)  if (evfds[i] >= 0) close(evfds[i]);
    return fail;
}

/* ============================================================
 *  Sub-test 5: mixed obj+fd — alternating signals, fired_events
 * ============================================================ */
static int test_mixed_obj_fd(int dev_fd)
{
    struct ntsync_aggregate_source srcs[4];
    struct ntsync_aggregate_wait_args args;
    int e0, e1;
    int evfd0, evfd1;
    __u32 prev;
    uint64_t one = 1, drain;
    int ret, fail = 0;

    e0 = create_event(dev_fd, 1, 0);
    e1 = create_event(dev_fd, 1, 0);
    evfd0 = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    evfd1 = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (e0 < 0 || e1 < 0 || evfd0 < 0 || evfd1 < 0) {
        fprintf(stderr, "[mixed] create failed: %s\n", strerror(errno));
        fail = 1; goto cleanup;
    }

    srcs[0].type = NTSYNC_AGG_OBJECT; srcs[0].events = 0;      srcs[0].fd = e0;    srcs[0].__pad = 0;
    srcs[1].type = NTSYNC_AGG_FD;     srcs[1].events = POLLIN; srcs[1].fd = evfd0; srcs[1].__pad = 0;
    srcs[2].type = NTSYNC_AGG_OBJECT; srcs[2].events = 0;      srcs[2].fd = e1;    srcs[2].__pad = 0;
    srcs[3].type = NTSYNC_AGG_FD;     srcs[3].events = POLLIN; srcs[3].fd = evfd1; srcs[3].__pad = 0;

    /* Sequence: e1 (idx 2), evfd0 (idx 1), e0 (idx 0), evfd1 (idx 3) */
    int order[] = {2, 1, 0, 3};
    int n;

    for (n = 0; n < 4; n++) {
        int idx = order[n];

        switch (idx) {
        case 0: ioctl(e0, NTSYNC_IOC_EVENT_SET, &prev); break;
        case 1: write(evfd0, &one, sizeof(one)); break;
        case 2: ioctl(e1, NTSYNC_IOC_EVENT_SET, &prev); break;
        case 3: write(evfd1, &one, sizeof(one)); break;
        }

        memset(&args, 0, sizeof(args));
        args.timeout = abs_deadline_ns(1ULL * 1000000000ULL);
        args.sources = (uintptr_t)srcs;
        args.nb_sources = 4;
        args.owner = gettid_compat();

        ret = ioctl(dev_fd, NTSYNC_IOC_AGGREGATE_WAIT, &args);
        if (ret < 0) {
            fprintf(stderr, "[mixed] step %d ioctl failed: %s\n", n, strerror(errno));
            fail = 1; goto cleanup;
        }
        if (args.fired_index != (__u32)idx) {
            fprintf(stderr, "[mixed] step %d fired_index=%u, expected %d\n",
                    n, args.fired_index, idx);
            fail = 1; goto cleanup;
        }
        /* fd sources must report POLLIN; obj sources must report 0 */
        if (idx == 1 || idx == 3) {
            if (!(args.fired_events & POLLIN)) {
                fprintf(stderr, "[mixed] step %d (fd) fired_events=%#x, expected POLLIN\n",
                        n, args.fired_events);
                fail = 1; goto cleanup;
            }
        } else {
            if (args.fired_events != 0) {
                fprintf(stderr, "[mixed] step %d (obj) fired_events=%#x, expected 0\n",
                        n, args.fired_events);
                fail = 1; goto cleanup;
            }
        }

        /* Drain */
        switch (idx) {
        case 0: ioctl(e0, NTSYNC_IOC_EVENT_RESET, &prev); break;
        case 1: read(evfd0, &drain, sizeof(drain)); break;
        case 2: ioctl(e1, NTSYNC_IOC_EVENT_RESET, &prev); break;
        case 3: read(evfd1, &drain, sizeof(drain)); break;
        }
    }

    NOTE("[mixed obj+fd]               PASS  (4 sources, 4 alternating signals)\n");

cleanup:
    if (e0 >= 0) close(e0);
    if (e1 >= 0) close(e1);
    if (evfd0 >= 0) close(evfd0);
    if (evfd1 >= 0) close(evfd1);
    return fail;
}

/* ============================================================
 *  Sub-test 6: cancel via signal — pthread_kill mid-wait
 *  (KASAN catches any leaked waitqueue entries / pollwait state)
 * ============================================================ */
struct cancel_ctx {
    int dev_fd;
    int event_fd;
    int evfd;
    volatile int ready;
    int ret;
    int err;
};

static void cancel_sigusr1(int sig) { (void)sig; /* no-op; just unblock syscall */ }

static void *cancel_waiter_fn(void *arg)
{
    struct cancel_ctx *c = arg;
    struct ntsync_aggregate_source srcs[2];
    struct ntsync_aggregate_wait_args args;

    srcs[0].type = NTSYNC_AGG_OBJECT;
    srcs[0].events = 0;
    srcs[0].fd = c->event_fd;
    srcs[0].__pad = 0;
    srcs[1].type = NTSYNC_AGG_FD;
    srcs[1].events = POLLIN;
    srcs[1].fd = c->evfd;
    srcs[1].__pad = 0;

    memset(&args, 0, sizeof(args));
    args.timeout = abs_deadline_ns(10ULL * 1000000000ULL);  /* 10s — plenty */
    args.sources = (uintptr_t)srcs;
    args.nb_sources = 2;
    args.owner = gettid_compat();

    __atomic_store_n(&c->ready, 1, __ATOMIC_RELEASE);
    c->ret = ioctl(c->dev_fd, NTSYNC_IOC_AGGREGATE_WAIT, &args);
    c->err = errno;
    return NULL;
}

static int test_cancel_via_signal(int dev_fd)
{
    struct cancel_ctx ctx = {0};
    pthread_t waiter;
    struct sigaction sa = {0};
    int spins, fail = 0;

    sa.sa_handler = cancel_sigusr1;
    sigaction(SIGUSR1, &sa, NULL);

    ctx.dev_fd = dev_fd;
    ctx.event_fd = create_event(dev_fd, 1, 0);
    ctx.evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (ctx.event_fd < 0 || ctx.evfd < 0) {
        fprintf(stderr, "[cancel] create failed: %s\n", strerror(errno));
        if (ctx.event_fd >= 0) close(ctx.event_fd);
        if (ctx.evfd >= 0) close(ctx.evfd);
        return 1;
    }

    if (pthread_create(&waiter, NULL, cancel_waiter_fn, &ctx) != 0) {
        fprintf(stderr, "[cancel] pthread_create failed\n");
        close(ctx.event_fd); close(ctx.evfd);
        return 1;
    }

    for (spins = 0; spins < 10000; spins++) {
        if (__atomic_load_n(&ctx.ready, __ATOMIC_ACQUIRE)) break;
        usleep(100);
    }
    usleep(50 * 1000);  /* 50ms — let the ioctl actually enter sleep */

    /* Cancel via signal */
    pthread_kill(waiter, SIGUSR1);
    pthread_join(waiter, NULL);

    if (ctx.ret >= 0) {
        fprintf(stderr, "[cancel] expected negative return, got %d\n", ctx.ret);
        fail = 1;
    }
    /* EINTR is what the C library typically reports for -ERESTARTSYS
     * after the signal handler runs */
    if (ctx.err != EINTR) {
        fprintf(stderr, "[cancel] expected EINTR, got %d (%s)\n",
                ctx.err, strerror(ctx.err));
        fail = 1;
    }

    if (!fail) NOTE("[cancel via signal]          PASS  (errno=EINTR)\n");

    close(ctx.event_fd);
    close(ctx.evfd);
    return fail;
}

/* ============================================================
 *  main
 *
 *  Modes:
 *    (no args)        — run 6 sub-tests once, exit 0/1
 *    --stress N       — loop sub-tests 1+4+5+6 (the bug-finders)
 *                       N times, fail-fast with iter#.  Skips
 *                       sub-tests 2 (timeout) and 3 (PI) since
 *                       they're slower and the bug-finders cover
 *                       the same code paths.  Designed for KASAN.
 * ============================================================ */
static int run_smoke(int dev_fd)
{
    int fail = 0;
    fail |= test_basic(dev_fd);
    fail |= test_timeout(dev_fd);
    fail |= test_pi_propagation(dev_fd);
    fail |= test_32_source_stress(dev_fd);
    fail |= test_mixed_obj_fd(dev_fd);
    fail |= test_cancel_via_signal(dev_fd);
    return fail;
}

static int run_stress(int dev_fd, long iters)
{
    long i;
    int sub, fail;
    long progress_step;

    progress_step = iters >= 100 ? iters / 20 : 5;  /* ~20 progress dots */
    if (progress_step < 1) progress_step = 1;

    g_quiet = 1;  /* suppress per-sub-test PASS lines (saves stdout at scale) */
    printf("[stress] looping sub-tests 1+4+5+6 for %ld iters (fail-fast)\n", iters);
    fflush(stdout);

    for (i = 0; i < iters; i++) {
        sub = i & 3;
        fail = 0;
        switch (sub) {
        case 0: fail = test_basic(dev_fd); break;
        case 1: fail = test_32_source_stress(dev_fd); break;
        case 2: fail = test_mixed_obj_fd(dev_fd); break;
        case 3: fail = test_cancel_via_signal(dev_fd); break;
        }
        if (fail) {
            fprintf(stderr, "\n[stress] FAIL at iter %ld sub=%d\n", i, sub);
            return 1;
        }
        if (i > 0 && (i % progress_step) == 0) {
            printf("  iter %ld / %ld\n", i, iters);
            fflush(stdout);
        }
    }
    printf("[stress] %ld iters PASS\n", iters);
    return 0;
}

int main(int argc, char **argv)
{
    int dev_fd;
    int rc;

    dev_fd = open("/dev/ntsync", O_RDWR | O_CLOEXEC);
    if (dev_fd < 0) {
        fprintf(stderr, "open /dev/ntsync: %s\n", strerror(errno));
        fprintf(stderr, "(is the ntsync module loaded? `lsmod | grep ntsync`)\n");
        return 1;
    }

    if (argc >= 3 && strcmp(argv[1], "--stress") == 0) {
        long iters = strtol(argv[2], NULL, 0);
        if (iters < 1) {
            fprintf(stderr, "--stress N: N must be >= 1\n");
            close(dev_fd);
            return 2;
        }
        printf("== NTSYNC_IOC_AGGREGATE_WAIT KASAN stress (patch 1010) ==\n");
        rc = run_stress(dev_fd, iters);
    } else if (argc >= 2) {
        fprintf(stderr, "usage: %s [--stress N]\n", argv[0]);
        close(dev_fd);
        return 2;
    } else {
        printf("== NTSYNC_IOC_AGGREGATE_WAIT smoke test (patch 1010) ==\n");
        rc = run_smoke(dev_fd);
        if (rc == 0)
            printf("\nRESULT: PASS  (6/6)\n");
        else
            printf("\nRESULT: FAIL\n");
    }

    close(dev_fd);
    return rc ? 1 : 0;
}
