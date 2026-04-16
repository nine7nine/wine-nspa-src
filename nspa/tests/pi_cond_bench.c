/*
 * pi_cond requeue-PI benchmark
 *
 * Measures condvar signal-to-wake latency under RT priority contention.
 * An RT waiter (SCHED_FIFO) sleeps on a pi_cond. A normal-priority signaler
 * signals it after a delay. Background load threads compete for CPU.
 * With requeue-PI, the wake-to-mutex-reacquire is atomic (kernel-side).
 * Without it, there's a gap where no PI boost is in effect.
 *
 * Build (native Linux, not Wine):
 *   gcc -O2 -o pi_cond_bench pi_cond_bench.c -lpthread -I../../libs/librtpi
 *
 * Run:
 *   sudo chrt -f 80 ./pi_cond_bench [iterations] [load_threads]
 *   Default: 10000 iterations, 4 load threads.
 *
 * Output: wake latency histogram (avg, p50, p99, max) in nanoseconds.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "rtpi.h"

static pi_mutex_t bench_mutex = PI_MUTEX_INIT(0);
static pi_cond_t  bench_cond  = PI_COND_INIT(0);
static volatile int ready = 0;
static volatile int go = 0;
static volatile int done = 0;
static volatile int stop_load = 0;

/* Shared timestamp: signaler writes just before signaling */
static struct timespec signal_time;

static long long ts_diff_ns(struct timespec *a, struct timespec *b)
{
    return (long long)(b->tv_sec - a->tv_sec) * 1000000000LL
         + (long long)(b->tv_nsec - a->tv_nsec);
}

/* RT waiter thread: waits on condvar, measures wake latency */
struct waiter_args {
    long long *samples;
    int count;
};

static void *waiter_thread(void *arg)
{
    struct waiter_args *wa = (struct waiter_args *)arg;
    struct timespec wake_time;
    int i;

    /* Set RT priority */
    struct sched_param sp = { .sched_priority = 50 };
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp) != 0)
        fprintf(stderr, "warning: couldn't set SCHED_FIFO (run as root)\n");

    pi_mutex_lock(&bench_mutex);
    ready = 1;

    for (i = 0; i < wa->count; i++) {
        /* Wait for signal */
        pi_cond_wait(&bench_cond, &bench_mutex);

        /* Measure time from signal to here (mutex reacquired) */
        clock_gettime(CLOCK_MONOTONIC, &wake_time);
        wa->samples[i] = ts_diff_ns((struct timespec *)&signal_time, &wake_time);
    }

    pi_mutex_unlock(&bench_mutex);
    done = 1;
    return NULL;
}

/* Signaler thread: acquires mutex, signals condvar */
static void *signaler_thread(void *arg)
{
    struct waiter_args *wa = (struct waiter_args *)arg;
    int i;

    /* Normal priority — this is the thread that benefits from PI boost */
    for (i = 0; i < wa->count; i++) {
        /* Small delay to let waiter enter pi_cond_wait */
        usleep(50);

        pi_mutex_lock(&bench_mutex);
        clock_gettime(CLOCK_MONOTONIC, (struct timespec *)&signal_time);
        pi_cond_signal(&bench_cond, &bench_mutex);
        pi_mutex_unlock(&bench_mutex);
    }
    return NULL;
}

/* Load thread: busy loop to create CPU contention */
static void *load_thread(void *arg)
{
    (void)arg;
    volatile long x = 0;
    while (!stop_load)
        x++;
    return NULL;
}

static int cmp_ll(const void *a, const void *b)
{
    long long da = *(const long long *)a;
    long long db = *(const long long *)b;
    return (da > db) - (da < db);
}

int main(int argc, char **argv)
{
    int iters = 10000, load_count = 4;
    struct waiter_args wa;
    pthread_t waiter, signaler;
    pthread_t *load_threads;
    long long sum = 0;
    int i;

    if (argc > 1) iters = atoi(argv[1]);
    if (argc > 2) load_count = atoi(argv[2]);
    if (iters < 10) iters = 10;

    printf("pi_cond requeue-PI benchmark\n");
    printf("  iterations: %d, load threads: %d\n", iters, load_count);

    wa.count = iters;
    wa.samples = (long long *)malloc(iters * sizeof(long long));
    if (!wa.samples) { perror("malloc"); return 1; }

    /* Start load threads */
    load_threads = (pthread_t *)calloc(load_count, sizeof(pthread_t));
    for (i = 0; i < load_count; i++)
        pthread_create(&load_threads[i], NULL, load_thread, NULL);

    /* Start waiter and signaler */
    pthread_create(&waiter, NULL, waiter_thread, &wa);

    /* Wait for waiter to be ready */
    while (!ready) usleep(100);

    pthread_create(&signaler, NULL, signaler_thread, &wa);

    /* Wait for completion */
    pthread_join(signaler, NULL);
    pthread_join(waiter, NULL);

    /* Stop load threads */
    stop_load = 1;
    for (i = 0; i < load_count; i++)
        pthread_join(load_threads[i], NULL);

    /* Sort and compute stats */
    qsort(wa.samples, iters, sizeof(long long), cmp_ll);

    for (i = 0; i < iters; i++) sum += wa.samples[i];

    printf("\n  Results (signal-to-reacquire latency):\n");
    printf("    avg:  %8lld ns\n", sum / iters);
    printf("    p50:  %8lld ns\n", wa.samples[iters / 2]);
    printf("    p99:  %8lld ns\n", wa.samples[(int)(iters * 0.99)]);
    printf("    max:  %8lld ns\n", wa.samples[iters - 1]);
    printf("    min:  %8lld ns\n", wa.samples[0]);
    printf("\n  [PASS]\n");

    free(wa.samples);
    free(load_threads);
    return 0;
}
