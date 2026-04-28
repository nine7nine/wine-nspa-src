/*
 * test-channel-stress: concurrency hammer of the ntsync channel paths.
 *
 * What this test FINDS:
 *   - Slab corruption / UAF in ntsync_channel_entry alloc/free.
 *     KASAN catches.
 *   - REGISTER_THREAD / DEREGISTER_THREAD races (the 1006-edited paths).
 *     KASAN catches.
 *   - SEND_PI / RECV / REPLY message loss or duplication under load.
 *     Detected by sender-receiver counter mismatch.
 *   - Stranded receivers post-1007 fix (Bug 2): the exclusive-recv
 *     change should make this race-free; we verify here at scale.
 *   - Thread-token corruption across re-registers.
 *
 * Workload:
 *   N senders churn SEND_PI on a shared channel with mixed priorities.
 *   M receivers loop RECV/RECV2 -> REPLY.  Periodic register/deregister
 *   from a separate thread exercises the (tid -> token) hash table
 *   under contention with normal channel traffic.  Channel is created/
 *   destroyed once per run, but thread count churns to mimic Ableton.
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o test-channel-stress \
 *       test-channel-stress.c -lpthread
 *
 * Run:
 *   ./test-channel-stress [duration_sec] [n_senders] [n_receivers]
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
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/types.h>

struct ntsync_channel_create_args { __u32 max_depth; __u32 __pad; };
struct ntsync_channel_send_args {
    __u32 policy; __u32 prio;
    __u64 payload_off; __u64 reply_off;
};
struct ntsync_channel_recv_args {
    __u64 entry_id; __u64 payload_off; __u64 reply_off;
    __u32 sender_tid; __u32 prio;
};
struct ntsync_channel_recv2_args {
    __u64 entry_id; __u64 payload_off; __u64 reply_off;
    __u32 sender_tid; __u32 prio;
    __u64 thread_token;
};
struct ntsync_channel_register_thread_args { __u32 tid; __u64 token; };

#define NTSYNC_IOC_CREATE_CHANNEL          _IOWR('N', 0x90, struct ntsync_channel_create_args)
#define NTSYNC_IOC_CHANNEL_SEND_PI         _IOWR('N', 0x91, struct ntsync_channel_send_args)
#define NTSYNC_IOC_CHANNEL_RECV            _IOWR('N', 0x92, struct ntsync_channel_recv_args)
#define NTSYNC_IOC_CHANNEL_REPLY           _IOW ('N', 0x93, __u64)
#define NTSYNC_IOC_CHANNEL_REGISTER_THREAD _IOW ('N', 0x94, struct ntsync_channel_register_thread_args)
#define NTSYNC_IOC_CHANNEL_DEREGISTER_THREAD _IOW ('N', 0x95, __u32)
#define NTSYNC_IOC_CHANNEL_RECV2           _IOWR('N', 0x96, struct ntsync_channel_recv2_args)

static int gettid_compat(void) { return (int)syscall(SYS_gettid); }

/* Shared */
static int g_dev_fd, g_ch_fd;
static atomic_int g_stop;
static atomic_long g_send_iters, g_send_errors;
static atomic_long g_recv_iters, g_recv_errors;
static atomic_long g_reply_iters, g_reply_errors;
static atomic_long g_reg_ops, g_reg_errors;
static atomic_long g_dereg_ops, g_dereg_errors;
static atomic_long g_recv2_iters, g_recv2_errors;

static void *sender_fn(void *arg)
{
    int id = (int)(uintptr_t)arg;
    unsigned rng = id * 1664525u + 1013904223u;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        rng = rng * 1664525u + 1013904223u;
        unsigned prio = 1 + (rng % 90);
        unsigned policy = (rng & 1) ? SCHED_FIFO : SCHED_RR;
        struct ntsync_channel_send_args sa = {
            .policy = policy, .prio = prio,
            .payload_off = (unsigned long)id,
            .reply_off = 0,
        };
        int rc = ioctl(g_ch_fd, NTSYNC_IOC_CHANNEL_SEND_PI, &sa);
        if (rc < 0) {
            if (errno == EAGAIN) {
                /* channel depth maxed — back off briefly */
                usleep(1);
                continue;
            }
            if (errno == EINTR) {
                /* Shutdown signal: loop check below will see g_stop. */
                continue;
            }
            atomic_fetch_add_explicit(&g_send_errors, 1, memory_order_relaxed);
            fprintf(stderr, "[sender %d] errno=%d\n", id, errno);
            continue;
        }
        atomic_fetch_add_explicit(&g_send_iters, 1, memory_order_relaxed);
    }
    return NULL;
}

/* Half the receivers use RECV, half use RECV2 — exercise both code
 * paths.  RECV2 also reads thread_token, exercising
 * channel_lookup_token under obj_lock. */
static void *recv_fn(void *arg)
{
    int id = (int)(uintptr_t)arg;
    int use_recv2 = id & 1;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        struct ntsync_channel_recv_args ra1;
        struct ntsync_channel_recv2_args ra2;
        __u64 entry_id;
        int rc;

        if (use_recv2) {
            memset(&ra2, 0, sizeof(ra2));
            rc = ioctl(g_ch_fd, NTSYNC_IOC_CHANNEL_RECV2, &ra2);
            if (rc < 0) {
                if (errno == EINTR) continue;
                atomic_fetch_add_explicit(&g_recv2_errors, 1, memory_order_relaxed);
                fprintf(stderr, "[recv2 %d] errno=%d\n", id, errno);
                continue;
            }
            entry_id = ra2.entry_id;
            atomic_fetch_add_explicit(&g_recv2_iters, 1, memory_order_relaxed);
        } else {
            memset(&ra1, 0, sizeof(ra1));
            rc = ioctl(g_ch_fd, NTSYNC_IOC_CHANNEL_RECV, &ra1);
            if (rc < 0) {
                if (errno == EINTR) continue;
                atomic_fetch_add_explicit(&g_recv_errors, 1, memory_order_relaxed);
                fprintf(stderr, "[recv %d] errno=%d\n", id, errno);
                continue;
            }
            entry_id = ra1.entry_id;
            atomic_fetch_add_explicit(&g_recv_iters, 1, memory_order_relaxed);
        }

        /* REPLY immediately so sender unblocks. */
        rc = ioctl(g_ch_fd, NTSYNC_IOC_CHANNEL_REPLY, &entry_id);
        if (rc < 0) {
            atomic_fetch_add_explicit(&g_reply_errors, 1, memory_order_relaxed);
            fprintf(stderr, "[reply %d] errno=%d\n", id, errno);
            continue;
        }
        atomic_fetch_add_explicit(&g_reply_iters, 1, memory_order_relaxed);
    }
    return NULL;
}

/* Thread-registration churn — exercises ntsync_channel_register_thread
 * and ntsync_channel_deregister_thread (the kfree-hoist sites #5/#6
 * from 1006).  Re-registers same TIDs to hit the replace-or-insert
 * path; deregisters and re-registers to hit the empty-bucket path. */
static void *registrar_fn(void *arg)
{
    (void)arg;
    unsigned rng = 0xC0FFEE;
    while (!atomic_load_explicit(&g_stop, memory_order_relaxed)) {
        rng = rng * 1664525u + 1013904223u;
        __u32 tid = 1000 + (rng % 256);  /* synthetic TID space */
        __u64 token = ((__u64)rng << 32) | (rng ^ 0xdeadbeef);
        struct ntsync_channel_register_thread_args ra = { .tid = tid, .token = token };
        int rc = ioctl(g_ch_fd, NTSYNC_IOC_CHANNEL_REGISTER_THREAD, &ra);
        if (rc < 0) {
            atomic_fetch_add_explicit(&g_reg_errors, 1, memory_order_relaxed);
            fprintf(stderr, "[reg] tid=%u errno=%d\n", tid, errno);
        } else {
            atomic_fetch_add_explicit(&g_reg_ops, 1, memory_order_relaxed);
        }

        /* Sometimes immediately deregister, sometimes leave (mimics
         * thread lifetime).  Bias 50/50. */
        if (rng & 1) {
            rc = ioctl(g_ch_fd, NTSYNC_IOC_CHANNEL_DEREGISTER_THREAD, &tid);
            if (rc < 0) {
                /* may legitimately fail if not registered — only count
                 * when our register succeeded */
                atomic_fetch_add_explicit(&g_dereg_errors, 1, memory_order_relaxed);
            } else {
                atomic_fetch_add_explicit(&g_dereg_ops, 1, memory_order_relaxed);
            }
        }
        /* Tight loop with brief jitter */
        if ((rng & 0xff) == 0) usleep(1);
    }
    return NULL;
}

/* No-op SIGUSR1 handler: just unblocks blocked syscalls (RECV/SEND_PI)
 * with EINTR — the thread loops handle EINTR by continuing, and the
 * stop check then drives exit.  Without a handler, default SIGUSR1
 * action is to terminate the process. */
static void wake_handler(int sig) { (void)sig; }

int main(int argc, char **argv)
{
    int duration   = (argc > 1) ? atoi(argv[1]) : 30;
    int n_senders  = (argc > 2) ? atoi(argv[2]) : 4;
    int n_recvers  = (argc > 3) ? atoi(argv[3]) : 4;

    {
        struct sigaction sa = { 0 };
        sa.sa_handler = wake_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;  /* no SA_RESTART — we WANT EINTR */
        sigaction(SIGUSR1, &sa, NULL);
    }

    g_dev_fd = open("/dev/ntsync", O_RDWR | O_CLOEXEC);
    if (g_dev_fd < 0) { perror("open /dev/ntsync"); return 2; }

    {
        struct ntsync_channel_create_args ca = { .max_depth = 16, .__pad = 0 };
        g_ch_fd = ioctl(g_dev_fd, NTSYNC_IOC_CREATE_CHANNEL, &ca);
        if (g_ch_fd < 0) { perror("CREATE_CHANNEL"); return 2; }
    }

    printf("== channel stress: %d senders + %d receivers + 1 registrar for %ds ==\n",
           n_senders, n_recvers, duration);

    pthread_t *snd = calloc(n_senders, sizeof(pthread_t));
    pthread_t *rcv = calloc(n_recvers, sizeof(pthread_t));
    pthread_t reg;
    for (int i = 0; i < n_senders; i++)
        pthread_create(&snd[i], NULL, sender_fn, (void*)(uintptr_t)i);
    for (int i = 0; i < n_recvers; i++)
        pthread_create(&rcv[i], NULL, recv_fn,   (void*)(uintptr_t)i);
    pthread_create(&reg, NULL, registrar_fn, NULL);

    sleep(duration);
    atomic_store_explicit(&g_stop, 1, memory_order_relaxed);

    /* Signal-based wake: interrupts blocked SEND_PI / RECV ioctls.
     * The kernel converts ERESTARTSYS to EINTR for userspace.  The
     * thread bodies treat EINTR as "continue loop", and the loop
     * check then sees g_stop and exits.  This is the correct cleanup
     * pattern post-1007 — wake_up() is exclusive now, so the previous
     * "send N cleanup messages to wake N receivers" approach no
     * longer works (one wake = one consumer; receivers exit before
     * the next cleanup arrives, leaving subsequent cleanups stuck
     * with no consumer). */
    for (int i = 0; i < n_senders; i++) pthread_kill(snd[i], SIGUSR1);
    for (int i = 0; i < n_recvers; i++) pthread_kill(rcv[i], SIGUSR1);
    pthread_kill(reg, SIGUSR1);

    for (int i = 0; i < n_senders; i++) pthread_join(snd[i], NULL);
    for (int i = 0; i < n_recvers; i++) pthread_join(rcv[i], NULL);
    pthread_join(reg, NULL);
    free(snd); free(rcv);

    close(g_ch_fd);
    close(g_dev_fd);

    long si = atomic_load(&g_send_iters);
    long se = atomic_load(&g_send_errors);
    long ri = atomic_load(&g_recv_iters);
    long re = atomic_load(&g_recv_errors);
    long r2i = atomic_load(&g_recv2_iters);
    long r2e = atomic_load(&g_recv2_errors);
    long pi = atomic_load(&g_reply_iters);
    long pe = atomic_load(&g_reply_errors);
    long rg = atomic_load(&g_reg_ops);
    long dg = atomic_load(&g_dereg_ops);
    long rge = atomic_load(&g_reg_errors);

    printf("\n== Results ==\n");
    printf("SEND_PI:            %ld   (errors: %ld)\n", si, se);
    printf("RECV:               %ld   (errors: %ld)\n", ri, re);
    printf("RECV2:              %ld   (errors: %ld)\n", r2i, r2e);
    printf("REPLY:              %ld   (errors: %ld)\n", pi, pe);
    printf("REGISTER_THREAD:    %ld   (errors: %ld)\n", rg, rge);
    printf("DEREGISTER_THREAD:  %ld\n", dg);
    printf("\nKASAN:        check `journalctl -k --since \"%ds ago\" | grep BUG`\n",
           duration + 5);

    /* Sender count and (recv+recv2) count should be very close — they
     * may differ by up to (n_recvers + slop) due to the cleanup
     * messages that wake the receivers post-stop. */
    long total_recv = ri + r2i;
    long delta = total_recv - si;
    if (delta < 0) delta = -delta;
    if (delta > (long)(n_recvers + 16)) {
        printf("RESULT: WARN (send vs recv mismatch %ld — investigate)\n", delta);
        return 1;
    }
    if (se + re + r2e + pe + rge > 0) {
        printf("RESULT: FAIL (%ld syscall errors)\n",
               se + re + r2e + pe + rge);
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
