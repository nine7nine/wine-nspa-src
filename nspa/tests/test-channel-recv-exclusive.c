/*
 * test-channel-recv-exclusive: validates ntsync patch 1007 Claim 2 fix
 *
 *   Bug: pre-1007, CHANNEL_RECV/RECV2 used wait_event_interruptible (non-
 *   exclusive).  CHANNEL_SEND_PI's wake_up() then woke ALL recv'ers.
 *   The speculative PI boost was applied to recv_wq.head, but any recv'er
 *   could win the race to pop the entry, leaving the boost stranded on a
 *   loser thread until that thread's next RECV.
 *
 *   Fix (1007): wait_event_interruptible_exclusive in RECV/RECV2 and
 *   wake_up_interruptible in SEND_PI -> wake exactly one (the head, which
 *   matches the speculative-boost target).
 *
 * Test:
 *   1. Two recv'er threads R1 and R2 both call CHANNEL_RECV (block).
 *      R1 starts first -> R1 is at recv_wq head (exclusive insertion at tail).
 *   2. Main posts a single CHANNEL_SEND_PI.
 *   3. After 100ms, count how many recv'ers have woken.
 *      PASS = exactly 1.  FAIL_BUG = 2 (pre-1007 wake-all behaviour).
 *
 * Build:
 *   gcc -O2 -Wall -o test-channel-recv-exclusive \
 *       test-channel-recv-exclusive.c -lpthread
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

struct ntsync_channel_create_args { __u32 max_depth; __u32 __pad; };
struct ntsync_channel_send_args {
    __u32 policy; __u32 prio; __u64 payload_off; __u64 reply_off;
};
struct ntsync_channel_recv_args {
    __u64 entry_id; __u64 payload_off; __u64 reply_off;
    __u32 sender_tid; __u32 prio;
};

#define NTSYNC_IOC_CREATE_CHANNEL  _IOWR('N', 0x90, struct ntsync_channel_create_args)
#define NTSYNC_IOC_CHANNEL_SEND_PI _IOWR('N', 0x91, struct ntsync_channel_send_args)
#define NTSYNC_IOC_CHANNEL_RECV    _IOWR('N', 0x92, struct ntsync_channel_recv_args)
#define NTSYNC_IOC_CHANNEL_REPLY   _IOW ('N', 0x93, __u64)

struct recv_ctx {
    int                 dev_fd;
    int                 ch_fd;
    int                 id;        /* 1 or 2 */
    atomic_int         *wake_mask; /* main reads */
    atomic_int         *order;     /* main reads — first to wake */
    int                 woke;
    __u64               entry_id;
    int                 last_errno;
};

static void *recv_fn(void *arg)
{
    struct recv_ctx *ctx = arg;
    struct ntsync_channel_recv_args ra;
    int ret;

    memset(&ra, 0, sizeof(ra));
    ret = ioctl(ctx->ch_fd, NTSYNC_IOC_CHANNEL_RECV, &ra);
    if (ret < 0) {
        ctx->last_errno = errno;
        return NULL;
    }
    /* Record wake order */
    int prev = atomic_fetch_or(ctx->wake_mask, 1 << ctx->id);
    if (prev == 0) {
        /* We were the first */
        atomic_store(ctx->order, ctx->id);
    }
    ctx->woke = 1;
    ctx->entry_id = ra.entry_id;

    /* Acknowledge so the sender can return.  Otherwise sender blocks
     * forever and pthread_join hangs at cleanup. */
    ioctl(ctx->ch_fd, NTSYNC_IOC_CHANNEL_REPLY, &ra.entry_id);
    return NULL;
}

int main(void)
{
    int dev_fd, ch_fd;
    pthread_t r1_tid, r2_tid, sender_tid_pt;
    struct recv_ctx r1 = {0}, r2 = {0};
    atomic_int wake_mask = 0, order = 0;
    int rc = 0;

    dev_fd = open("/dev/ntsync", O_RDWR | O_CLOEXEC);
    if (dev_fd < 0) {
        fprintf(stderr, "open /dev/ntsync: %s\n", strerror(errno));
        return 1;
    }
    {
        struct ntsync_channel_create_args ca = { .max_depth = 4 };
        ch_fd = ioctl(dev_fd, NTSYNC_IOC_CREATE_CHANNEL, &ca);
        if (ch_fd < 0) {
            fprintf(stderr, "CREATE_CHANNEL failed: %s\n", strerror(errno));
            return 1;
        }
    }

    printf("== test-channel-recv-exclusive (ntsync 1007 Claim 2) ==\n");

    r1.dev_fd = dev_fd; r1.ch_fd = ch_fd; r1.id = 1;
    r1.wake_mask = &wake_mask; r1.order = &order;
    r2.dev_fd = dev_fd; r2.ch_fd = ch_fd; r2.id = 2;
    r2.wake_mask = &wake_mask; r2.order = &order;

    /* R1 blocks first => head of recv_wq.  Wait so R1 is firmly queued
     * before R2 starts (with exclusive waiters at tail, this matters). */
    pthread_create(&r1_tid, NULL, recv_fn, &r1);
    usleep(50 * 1000);
    pthread_create(&r2_tid, NULL, recv_fn, &r2);
    usleep(50 * 1000);

    /* Post a single SEND_PI.  Run from a separate thread because SEND_PI
     * is synchronous: it blocks until the recv'er REPLYs. */
    {
        /* Sender thread function inline via small struct */
        struct ntsync_channel_send_args sa = {
            .policy = SCHED_FIFO, .prio = 50,
            .payload_off = 0xCAFE, .reply_off = 0xBEEF,
        };
        struct sender_arg { int ch_fd; struct ntsync_channel_send_args *sa; };
        struct sender_arg sa_pkg = { .ch_fd = ch_fd, .sa = &sa };
        void *sender_thread(void *p) {
            struct sender_arg *a = p;
            (void)ioctl(a->ch_fd, NTSYNC_IOC_CHANNEL_SEND_PI, a->sa);
            return NULL;
        }
        pthread_create(&sender_tid_pt, NULL, sender_thread, &sa_pkg);
    }

    /* Give the wake a chance to propagate. */
    usleep(100 * 1000);

    int mask_now = atomic_load(&wake_mask);
    int order_now = atomic_load(&order);

    printf("wake_mask = 0x%x  (bit1=R1, bit2=R2)\n", mask_now);
    printf("first wake = R%d\n", order_now);

    if (mask_now == (1 << 1)) {
        printf("[PASS] exactly R1 woken — exclusive recv works\n");
    } else if (mask_now == (1 << 2)) {
        printf("[FAIL] R2 woken instead of R1 — boost target != wake winner. "
               "(speculative SEND_PI boost is applied to wq.head=R1; should match.)\n");
        rc = 1;
    } else if (mask_now == ((1 << 1) | (1 << 2))) {
        printf("[FAIL] BOTH R1 and R2 woken — wake_up wakes all, "
               "this is the pre-1007 wake-all behaviour\n");
        rc = 1;
    } else {
        printf("[FAIL] no recv'er woken (mask=0x%x). errno R1=%d R2=%d\n",
               mask_now, r1.last_errno, r2.last_errno);
        rc = 1;
    }

    /* Cleanup: send a second message so R2 can wake and join. */
    if (!r2.woke) {
        struct ntsync_channel_send_args sa2 = {
            .policy = 0, .prio = 0, .payload_off = 0, .reply_off = 0,
        };
        ioctl(ch_fd, NTSYNC_IOC_CHANNEL_SEND_PI, &sa2);
    }
    pthread_join(sender_tid_pt, NULL);
    pthread_join(r1_tid, NULL);
    pthread_join(r2_tid, NULL);

    close(ch_fd);
    close(dev_fd);

    printf("RESULT: %s\n", rc ? "FAIL" : "PASS");
    return rc;
}
