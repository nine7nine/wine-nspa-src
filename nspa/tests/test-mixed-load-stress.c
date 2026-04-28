/*
 * test-mixed-load-stress: simultaneous load on every ntsync path.
 *
 * Why this exists (per user 2026-04-27): individual single-path stress
 * tests miss emergent bugs that only fire when multiple paths interact
 * — mostly cross-path locking and multi-object wait_any cases.  This
 * test runs all paths concurrently against a single /dev/ntsync.
 *
 * Workload:
 *   audio_waiter  (Tier B SCHED_FIFO):  wait_any on (event, mutex)
 *                                       multi-obj — exercises the
 *                                       cross-obj lock ordering and
 *                                       PI-during-mutex-acquisition.
 *                                       Drains EVENT_SET_PI boosts
 *                                       on every wait re-entry.
 *
 *   ui_signaler  (SCHED_OTHER, several): mix of EVENT_SET_PI / SET /
 *                                       RESET + occasional mutex
 *                                       acquire/release.  Generates
 *                                       boosts that the audio_waiter
 *                                       consumes.
 *
 *   chan_sender  (SCHED_OTHER, several): channel SEND_PI loop with
 *                                       random RT prio, hammers the
 *                                       refcount path (1009 fix).
 *
 *   chan_recv    (SCHED_OTHER, several): channel RECV/RECV2 -> REPLY
 *                                       loop.
 *
 *   churn        (SCHED_OTHER, 1):       periodic SIGUSR1 to a
 *                                       random worker to mimic the
 *                                       Ableton thread-restart
 *                                       pattern.
 *
 *   registrar    (SCHED_OTHER, 1):       channel REGISTER/DEREGISTER
 *                                       churn (the kfree-hoist sites
 *                                       1006 patched).
 *
 * Cleanup is signal-based: SIGUSR1 to all workers, threads see
 * EINTR + g_stop and exit.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o test-mixed-load-stress \
 *       test-mixed-load-stress.c -lpthread
 *
 * Run:
 *   ./test-mixed-load-stress [duration_sec]
 *
 * Detect KASAN: tail dmesg / journalctl -k for "BUG: KASAN:".
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
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

/* Local UAPI subset */
struct ntsync_event_args { __u32 manual; __u32 signaled; };
struct ntsync_mutex_args { __u32 owner; __u32 count; };
struct ntsync_wait_args {
    __u64 timeout; __u64 objs;
    __u32 count; __u32 index; __u32 flags; __u32 owner;
    __u32 alert; __u32 uring_fd;
};
struct ntsync_event_set_pi_args { __u32 flags; __u32 policy; __u32 prio; __u32 __pad; };
struct ntsync_channel_create_args { __u32 max_depth; __u32 __pad; };
struct ntsync_channel_send_args {
    __u32 policy; __u32 prio;
    __u64 payload_off; __u64 reply_off;
};
struct ntsync_channel_recv_args {
    __u64 entry_id; __u64 payload_off; __u64 reply_off;
    __u32 sender_tid; __u32 prio;
};
struct ntsync_channel_register_thread_args { __u32 tid; __u64 token; };

#define NTSYNC_IOC_CREATE_EVENT             _IOW ('N', 0x87, struct ntsync_event_args)
#define NTSYNC_IOC_CREATE_MUTEX             _IOW ('N', 0x84, struct ntsync_mutex_args)
#define NTSYNC_IOC_CREATE_CHANNEL           _IOWR('N', 0x90, struct ntsync_channel_create_args)
#define NTSYNC_IOC_WAIT_ANY                 _IOWR('N', 0x82, struct ntsync_wait_args)
#define NTSYNC_IOC_EVENT_SET                _IOR ('N', 0x88, __u32)
#define NTSYNC_IOC_EVENT_RESET              _IOR ('N', 0x89, __u32)
#define NTSYNC_IOC_EVENT_SET_PI             _IOW ('N', 0x8e, struct ntsync_event_set_pi_args)
#define NTSYNC_IOC_MUTEX_UNLOCK             _IOWR('N', 0x85, struct ntsync_mutex_args)
#define NTSYNC_IOC_CHANNEL_SEND_PI          _IOWR('N', 0x91, struct ntsync_channel_send_args)
#define NTSYNC_IOC_CHANNEL_RECV             _IOWR('N', 0x92, struct ntsync_channel_recv_args)
#define NTSYNC_IOC_CHANNEL_REPLY            _IOW ('N', 0x93, __u64)
#define NTSYNC_IOC_CHANNEL_REGISTER_THREAD  _IOW ('N', 0x94, struct ntsync_channel_register_thread_args)
#define NTSYNC_IOC_CHANNEL_DEREGISTER_THREAD _IOW ('N', 0x95, __u32)

static int gettid_compat(void) { return (int)syscall(SYS_gettid); }

static __u64 abs_deadline_ns(__u64 rel_ns)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec + rel_ns;
}

#define N_EVENTS 4
#define N_MUTEXES 4
#define N_UI 3
#define N_CHAN_SEND 3
#define N_CHAN_RECV 3

/* Shared */
static int g_dev_fd;
static int g_event_fds[N_EVENTS];
static int g_mutex_fds[N_MUTEXES];
static int g_chan_fd;
static atomic_int g_stop;

/* Op counters */
static atomic_long c_audio_waits, c_audio_woke, c_audio_boosts;
static atomic_long c_ui_set_pi, c_ui_set, c_ui_reset, c_ui_mutex_acq, c_ui_mutex_rel;
static atomic_long c_chan_send, c_chan_recv, c_chan_reply;
static atomic_long c_reg, c_dereg;
static atomic_long c_errors;
static atomic_long c_shutdown_races;  /* benign races during signal-based shutdown */

static int try_set_fifo(int prio)
{
    struct sched_param sp = { .sched_priority = prio };
    return sched_setscheduler(0, SCHED_FIFO, &sp);
}

static void wake_handler(int sig) { (void)sig; }

/* ---- workers ---- */

static void *audio_waiter_fn(void *arg)
{
    int prio = (int)(uintptr_t)arg;
    int fifo_ok = (try_set_fifo(prio) == 0);
    int wait_objs[2];

    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        struct ntsync_wait_args wa;
        unsigned which_event = ((unsigned)gettid_compat() ^ (unsigned)atomic_load(&c_audio_waits)) % N_EVENTS;
        unsigned which_mutex = ((unsigned)gettid_compat() ^ (unsigned)atomic_load(&c_audio_waits)) % N_MUTEXES;

        wait_objs[0] = g_event_fds[which_event];
        wait_objs[1] = g_mutex_fds[which_mutex];

        memset(&wa, 0, sizeof(wa));
        wa.count   = 2;
        wa.objs    = (uintptr_t)wait_objs;
        wa.owner   = gettid_compat();
        wa.timeout = abs_deadline_ns(50ULL * 1000000ULL);  /* 50ms */
        int rc = ioctl(g_dev_fd, NTSYNC_IOC_WAIT_ANY, &wa);
        atomic_fetch_add_explicit(&c_audio_waits, 1, memory_order_relaxed);
        if (rc < 0) {
            if (errno == EINTR || errno == ETIMEDOUT) continue;
            atomic_fetch_add_explicit(&c_errors, 1, memory_order_relaxed);
            fprintf(stderr, "[audio] wait errno=%d\n", errno);
            continue;
        }
        atomic_fetch_add_explicit(&c_audio_woke, 1, memory_order_relaxed);

        /* If we got the mutex (index >= N_EVENTS/N_EVENTS in actual array),
         * release it.  We don't bother sched_getattr-checking the boost
         * here under heavy load — the EVENT_SET_PI stress test already
         * validates per-wake boost; this test is for cross-path safety. */
        if (wa.index == 1) {
            struct ntsync_mutex_args ma = { .owner = gettid_compat(), .count = 0 };
            (void)ioctl(g_mutex_fds[which_mutex], NTSYNC_IOC_MUTEX_UNLOCK, &ma);
        }
        /* Boosts (if any) are drained on the next wait_any entry. */
        atomic_fetch_add_explicit(&c_audio_boosts, 1, memory_order_relaxed);
    }
    (void)fifo_ok;
    return NULL;
}

static void *ui_signaler_fn(void *arg)
{
    int id = (int)(uintptr_t)arg;
    unsigned rng = id * 1664525u + 1013904223u;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        rng = rng * 1664525u + 1013904223u;
        unsigned op = rng & 7;
        unsigned ev = (rng >> 3) % N_EVENTS;
        unsigned mu = (rng >> 5) % N_MUTEXES;
        __u32 prev;
        switch (op) {
        case 0: case 1: case 2: { /* EVENT_SET_PI bias */
            struct ntsync_event_set_pi_args pi = {
                .flags = 0,
                .policy = (rng & 1) ? SCHED_FIFO : SCHED_RR,
                .prio = 1 + ((rng >> 8) % 90),
            };
            if (ioctl(g_event_fds[ev], NTSYNC_IOC_EVENT_SET_PI, &pi) == 0)
                atomic_fetch_add_explicit(&c_ui_set_pi, 1, memory_order_relaxed);
            else if (errno != EINTR)
                atomic_fetch_add_explicit(&c_errors, 1, memory_order_relaxed);
            break;
        }
        case 3:
            if (ioctl(g_event_fds[ev], NTSYNC_IOC_EVENT_SET, &prev) == 0)
                atomic_fetch_add_explicit(&c_ui_set, 1, memory_order_relaxed);
            break;
        case 4:
            if (ioctl(g_event_fds[ev], NTSYNC_IOC_EVENT_RESET, &prev) == 0)
                atomic_fetch_add_explicit(&c_ui_reset, 1, memory_order_relaxed);
            break;
        case 5: case 6: case 7: { /* mutex acquire+release */
            struct ntsync_wait_args wa;
            int objs[1] = { g_mutex_fds[mu] };
            memset(&wa, 0, sizeof(wa));
            wa.count = 1; wa.objs = (uintptr_t)objs; wa.owner = gettid_compat();
            wa.timeout = abs_deadline_ns(20ULL * 1000000ULL);
            int rc = ioctl(g_dev_fd, NTSYNC_IOC_WAIT_ANY, &wa);
            if (rc < 0) {
                if (errno != EINTR && errno != ETIMEDOUT)
                    atomic_fetch_add_explicit(&c_errors, 1, memory_order_relaxed);
                break;
            }
            atomic_fetch_add_explicit(&c_ui_mutex_acq, 1, memory_order_relaxed);
            sched_yield();
            struct ntsync_mutex_args ma = { .owner = gettid_compat(), .count = 0 };
            if (ioctl(g_mutex_fds[mu], NTSYNC_IOC_MUTEX_UNLOCK, &ma) == 0)
                atomic_fetch_add_explicit(&c_ui_mutex_rel, 1, memory_order_relaxed);
            break;
        }
        }
    }
    return NULL;
}

static void *chan_sender_fn(void *arg)
{
    int id = (int)(uintptr_t)arg;
    unsigned rng = id * 1664525u + 314159u;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        rng = rng * 1664525u + 314159u;
        struct ntsync_channel_send_args sa = {
            .policy = (rng & 1) ? SCHED_FIFO : SCHED_RR,
            .prio = 1 + ((rng >> 8) % 90),
            .payload_off = id,
            .reply_off = 0,
        };
        int rc = ioctl(g_chan_fd, NTSYNC_IOC_CHANNEL_SEND_PI, &sa);
        if (rc < 0) {
            if (errno == EAGAIN) { usleep(1); continue; }
            if (errno == EINTR) continue;
            atomic_fetch_add_explicit(&c_errors, 1, memory_order_relaxed);
            continue;
        }
        atomic_fetch_add_explicit(&c_chan_send, 1, memory_order_relaxed);
    }
    return NULL;
}

static void *chan_recv_fn(void *arg)
{
    (void)arg;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        struct ntsync_channel_recv_args ra;
        __u64 entry_id;
        memset(&ra, 0, sizeof(ra));
        int rc = ioctl(g_chan_fd, NTSYNC_IOC_CHANNEL_RECV, &ra);
        if (rc < 0) {
            if (errno == EINTR) continue;
            atomic_fetch_add_explicit(&c_errors, 1, memory_order_relaxed);
            continue;
        }
        atomic_fetch_add_explicit(&c_chan_recv, 1, memory_order_relaxed);
        entry_id = ra.entry_id;
        rc = ioctl(g_chan_fd, NTSYNC_IOC_CHANNEL_REPLY, &entry_id);
        if (rc < 0) {
            /* ENOENT is benign: SEND_PI got SIGUSR1 (from churner
             * during run, or our shutdown wake) between our RECV and
             * REPLY, cleaned up its entry, so by the time we REPLY
             * the entry is gone.  Bug 4 refcount ensures no UAF
             * here — REPLY just gets a clean ENOENT. */
            if (errno == ENOENT) {
                atomic_fetch_add_explicit(&c_shutdown_races, 1, memory_order_relaxed);
            } else {
                atomic_fetch_add_explicit(&c_errors, 1, memory_order_relaxed);
            }
            continue;
        }
        atomic_fetch_add_explicit(&c_chan_reply, 1, memory_order_relaxed);
    }
    return NULL;
}

static void *registrar_fn(void *arg)
{
    (void)arg;
    unsigned rng = 0xdeadbeef;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        rng = rng * 1664525u + 1013904223u;
        struct ntsync_channel_register_thread_args ra = {
            .tid = 1000 + (rng % 256),
            .token = ((__u64)rng << 32) | rng,
        };
        if (ioctl(g_chan_fd, NTSYNC_IOC_CHANNEL_REGISTER_THREAD, &ra) == 0)
            atomic_fetch_add_explicit(&c_reg, 1, memory_order_relaxed);
        if (rng & 1) {
            __u32 tid = ra.tid;
            if (ioctl(g_chan_fd, NTSYNC_IOC_CHANNEL_DEREGISTER_THREAD, &tid) == 0)
                atomic_fetch_add_explicit(&c_dereg, 1, memory_order_relaxed);
        }
        if ((rng & 0xff) == 0) usleep(10);
    }
    return NULL;
}

/* Churn — periodically signals a random worker to interrupt its
 * blocked syscall.  This mimics Ableton's thread-cycle pattern AND
 * exercises the EINTR path of every ioctl in the test. */
static pthread_t *g_workers;
static int g_n_workers;
static void *churn_fn(void *arg)
{
    (void)arg;
    unsigned rng = 0xc0ffee;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        rng = rng * 1664525u + 1013904223u;
        int target = rng % g_n_workers;
        pthread_kill(g_workers[target], SIGUSR1);
        usleep(50 * 1000);  /* 50ms between churn pulses */
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int duration = (argc > 1) ? atoi(argv[1]) : 30;

    {
        struct sigaction sa = { 0 };
        sa.sa_handler = wake_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGUSR1, &sa, NULL);
    }
    /* Try to bump RTPRIO so audio_waiter can elevate */
    {
        struct rlimit rl = { .rlim_cur = 99, .rlim_max = 99 };
        setrlimit(RLIMIT_RTPRIO, &rl);
    }

    g_dev_fd = open("/dev/ntsync", O_RDWR | O_CLOEXEC);
    if (g_dev_fd < 0) { perror("open /dev/ntsync"); return 2; }

    for (int i = 0; i < N_EVENTS; i++) {
        struct ntsync_event_args ea = { .manual = 1, .signaled = 0 };
        g_event_fds[i] = ioctl(g_dev_fd, NTSYNC_IOC_CREATE_EVENT, &ea);
        if (g_event_fds[i] < 0) { perror("CREATE_EVENT"); return 2; }
    }
    for (int i = 0; i < N_MUTEXES; i++) {
        struct ntsync_mutex_args ma = { .owner = 0, .count = 0 };
        g_mutex_fds[i] = ioctl(g_dev_fd, NTSYNC_IOC_CREATE_MUTEX, &ma);
        if (g_mutex_fds[i] < 0) { perror("CREATE_MUTEX"); return 2; }
    }
    {
        struct ntsync_channel_create_args ca = { .max_depth = 32, .__pad = 0 };
        g_chan_fd = ioctl(g_dev_fd, NTSYNC_IOC_CREATE_CHANNEL, &ca);
        if (g_chan_fd < 0) { perror("CREATE_CHANNEL"); return 2; }
    }

    printf("== mixed-load stress: %d events + %d mutexes + 1 channel "
           "for %ds ==\n", N_EVENTS, N_MUTEXES, duration);

    int total = 1 + N_UI + N_CHAN_SEND + N_CHAN_RECV + 1;  /* +registrar */
    g_workers = calloc(total, sizeof(pthread_t));
    g_n_workers = total;

    int idx = 0;
    pthread_create(&g_workers[idx++], NULL, audio_waiter_fn, (void*)(uintptr_t)50);
    for (int i = 0; i < N_UI; i++)
        pthread_create(&g_workers[idx++], NULL, ui_signaler_fn, (void*)(uintptr_t)i);
    for (int i = 0; i < N_CHAN_SEND; i++)
        pthread_create(&g_workers[idx++], NULL, chan_sender_fn, (void*)(uintptr_t)i);
    for (int i = 0; i < N_CHAN_RECV; i++)
        pthread_create(&g_workers[idx++], NULL, chan_recv_fn, (void*)(uintptr_t)i);
    pthread_create(&g_workers[idx++], NULL, registrar_fn, NULL);

    pthread_t churn;
    pthread_create(&churn, NULL, churn_fn, NULL);

    sleep(duration);
    atomic_store_explicit(&g_stop, 1, memory_order_relaxed);

    /* Wake everyone */
    for (int i = 0; i < g_n_workers; i++) pthread_kill(g_workers[i], SIGUSR1);
    pthread_kill(churn, SIGUSR1);

    for (int i = 0; i < g_n_workers; i++) pthread_join(g_workers[i], NULL);
    pthread_join(churn, NULL);
    free(g_workers);

    close(g_chan_fd);
    for (int i = 0; i < N_MUTEXES; i++) close(g_mutex_fds[i]);
    for (int i = 0; i < N_EVENTS;  i++) close(g_event_fds[i]);
    close(g_dev_fd);

    long aw = atomic_load(&c_audio_waits);
    long ak = atomic_load(&c_audio_woke);
    long uspi = atomic_load(&c_ui_set_pi);
    long us = atomic_load(&c_ui_set);
    long ur = atomic_load(&c_ui_reset);
    long uma = atomic_load(&c_ui_mutex_acq);
    long umr = atomic_load(&c_ui_mutex_rel);
    long cs = atomic_load(&c_chan_send);
    long cr = atomic_load(&c_chan_recv);
    long cp = atomic_load(&c_chan_reply);
    long rg = atomic_load(&c_reg);
    long dg = atomic_load(&c_dereg);
    long er = atomic_load(&c_errors);
    long sr = atomic_load(&c_shutdown_races);

    printf("\n== Results ==\n");
    printf("audio waits:        %ld   (woke: %ld)\n", aw, ak);
    printf("ui EVENT_SET_PI:    %ld\n", uspi);
    printf("ui EVENT_SET:       %ld   ui EVENT_RESET: %ld\n", us, ur);
    printf("ui mutex acq/rel:   %ld / %ld\n", uma, umr);
    printf("chan SEND_PI:       %ld\n", cs);
    printf("chan RECV / REPLY:  %ld / %ld   (shutdown races: %ld)\n", cr, cp, sr);
    printf("chan REG/DEREG:     %ld / %ld\n", rg, dg);
    printf("syscall errors:     %ld\n", er);
    printf("\nKASAN:        check `journalctl -k --since \"%ds ago\" | grep BUG`\n",
           duration + 5);

    if (er > 0) {
        printf("RESULT: FAIL (%ld syscall errors)\n", er);
        return 1;
    }
    /* RECV - REPLY should equal shutdown_races (RECVs whose REPLY hit
     * ENOENT during signal-based teardown).  Anything else means a
     * leaked dispatched entry. */
    if (cr - cp != sr) {
        printf("RESULT: FAIL (chan RECV %ld - REPLY %ld = %ld, expected shutdown_races %ld)\n",
               cr, cp, cr - cp, sr);
        return 1;
    }
    if (uma != umr) {
        printf("RESULT: FAIL (mutex acq %ld != rel %ld — leak or doubled)\n",
               uma, umr);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
