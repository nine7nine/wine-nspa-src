/*
 * test-wait-rejects-channel: validates ntsync patch 1007 Claim 3 fix
 *
 *   Bug: pre-1007, setup_wait() accepted any fd, including channels.
 *   is_signaled() returned false for NTSYNC_TYPE_CHANNEL, so a wait
 *   on a channel silently slept until timeout/alert/signal — never
 *   completed via the channel itself.
 *
 *   Fix (1007): setup_wait() rejects NTSYNC_TYPE_CHANNEL with -EINVAL.
 *
 * Test:
 *   Pass a channel fd to NTSYNC_IOC_WAIT_ANY and NTSYNC_IOC_WAIT_ALL.
 *   PASS = both ioctls return -1 with errno == EINVAL immediately.
 *   FAIL = blocks (sleeps until timeout) or returns success.
 *
 * Build:
 *   gcc -O2 -Wall -o test-wait-rejects-channel test-wait-rejects-channel.c
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/types.h>

struct ntsync_channel_create_args { __u32 max_depth; __u32 __pad; };
struct ntsync_wait_args {
    __u64 timeout; __u64 objs; __u32 count; __u32 index;
    __u32 flags; __u32 owner; __u32 alert; __u32 uring_fd;
};

#define NTSYNC_IOC_CREATE_CHANNEL  _IOWR('N', 0x90, struct ntsync_channel_create_args)
#define NTSYNC_IOC_WAIT_ANY        _IOWR('N', 0x82, struct ntsync_wait_args)
#define NTSYNC_IOC_WAIT_ALL        _IOWR('N', 0x83, struct ntsync_wait_args)

static int gettid_compat(void) { return (int)syscall(SYS_gettid); }

static __u64 abs_deadline_ns(__u64 rel_ns)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec + rel_ns;
}

static int try_wait(int dev_fd, int ch_fd, unsigned ioc, const char *name)
{
    struct ntsync_wait_args wa;
    int ret;
    struct timespec t0, t1;
    long long elapsed_ms;

    memset(&wa, 0, sizeof(wa));
    wa.count   = 1;
    wa.objs    = (uintptr_t)&ch_fd;
    wa.owner   = gettid_compat();
    wa.timeout = abs_deadline_ns(2ULL * 1000000000ULL);  /* 2s */

    clock_gettime(CLOCK_MONOTONIC, &t0);
    ret = ioctl(dev_fd, ioc, &wa);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    elapsed_ms = ((long long)(t1.tv_sec - t0.tv_sec) * 1000) +
                 ((t1.tv_nsec - t0.tv_nsec) / 1000000);

    printf("[%s] ret=%d errno=%d (%s)  elapsed=%lldms\n",
           name, ret, ret < 0 ? errno : 0,
           ret < 0 ? strerror(errno) : "OK", elapsed_ms);

    if (ret == 0) {
        fprintf(stderr, "[%s] FAIL: ioctl returned 0 (success) — channel "
                        "shouldn't be waitable via WAIT_*\n", name);
        return 1;
    }
    if (errno != EINVAL) {
        fprintf(stderr, "[%s] FAIL: expected EINVAL (22), got errno=%d (%s)\n",
                name, errno, strerror(errno));
        return 1;
    }
    if (elapsed_ms > 100) {
        fprintf(stderr, "[%s] FAIL: blocked for %lldms — should reject "
                        "immediately, not sleep until timeout\n",
                name, elapsed_ms);
        return 1;
    }
    printf("[%s] PASS: rejected immediately with EINVAL\n", name);
    return 0;
}

int main(void)
{
    int dev_fd, ch_fd;
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

    printf("== test-wait-rejects-channel (ntsync 1007 Claim 3) ==\n");

    rc |= try_wait(dev_fd, ch_fd, NTSYNC_IOC_WAIT_ANY, "WAIT_ANY");
    rc |= try_wait(dev_fd, ch_fd, NTSYNC_IOC_WAIT_ALL, "WAIT_ALL");

    close(ch_fd);
    close(dev_fd);

    printf("RESULT: %s\n", rc ? "FAIL" : "PASS");
    return rc;
}
