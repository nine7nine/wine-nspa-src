/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * libs/librtpi/rtpi.h
 * NSPA RT v2.0 — Wine-internal implementation of the librtpi API surface.
 *
 * This is NOT a vendored copy of upstream librtpi (gitlab.com/linux-rt/librtpi).
 * Instead, it's a header-only inline implementation of the same public API
 * (pi_mutex_t, pi_cond_t, their init/lock/unlock/wait/signal/broadcast
 * functions) built directly on top of raw FUTEX_LOCK_PI / FUTEX_UNLOCK_PI
 * syscalls — the same primitives the NSPA v2.3 CS-PI patch added for
 * Win32 CRITICAL_SECTION.
 *
 * Why not vendor upstream librtpi:
 *   - Upstream is Unix-native C, no PE support. Wine's libs/ vendoring
 *     pattern is PE-cross-compiled (musl, vkd3d, faudio, lcms2, etc.),
 *     so the existing autotools glue can't build librtpi as-is.
 *   - Building a new unix-native static lib under libs/ has no Wine
 *     precedent. Every attempt during development hit autotools obstacles.
 *   - Upstream is not a fast-moving target (last release 2024, ~600 LoC).
 *     The API surface we need is small.
 *   - Wine-NSPA already has working FUTEX_LOCK_PI/UNLOCK_PI helpers from
 *     v2.3 CS-PI. Building on those avoids a redundant layer.
 *
 * Design:
 *   - Header-only. All functions inline. No .c files, no build target.
 *   - pi_mutex_t layout is compatible with upstream librtpi's (union with
 *     {futex, flags, pad[64]}) so any code written against upstream
 *     librtpi compiles against this too.
 *   - pi_cond_t uses the standard FUTEX_WAIT / FUTEX_WAKE condvar pattern
 *     with a sequence counter. TODO: upgrade to FUTEX_WAIT_REQUEUE_PI /
 *     FUTEX_CMP_REQUEUE_PI for thundering-herd avoidance under load.
 *   - The Linux kernel TID for the calling thread is cached per-thread
 *     via a `__thread` variable; the first call per thread pays the
 *     syscall cost, subsequent calls are a pure load.
 *
 * Usage:
 *   #include <rtpi.h>
 *   Then use pi_mutex_t / pi_cond_t and the pi_* functions as you would
 *   upstream librtpi. The nspa/librtpi_sweep.py tool rewrites pthread_*
 *   calls to pi_* equivalents tree-wide; consumers get this header via
 *   the -I$(top_srcdir)/libs/librtpi include path configured in each
 *   DLL's Makefile.in.
 *
 * See nspa/librtpi_sweep.py for the automated sweep tool.
 */

#ifndef RTPI_H
#define RTPI_H

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/futex.h>

#ifndef FUTEX_LOCK_PI_PRIVATE
#define FUTEX_LOCK_PI_PRIVATE    (FUTEX_LOCK_PI    | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_UNLOCK_PI_PRIVATE
#define FUTEX_UNLOCK_PI_PRIVATE  (FUTEX_UNLOCK_PI  | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_TRYLOCK_PI_PRIVATE
#define FUTEX_TRYLOCK_PI_PRIVATE (FUTEX_TRYLOCK_PI | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE       (FUTEX_WAIT       | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_WAKE_PRIVATE
#define FUTEX_WAKE_PRIVATE       (FUTEX_WAKE       | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI    11
#endif
#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI     12
#endif
#ifndef FUTEX_WAIT_REQUEUE_PI_PRIVATE
#define FUTEX_WAIT_REQUEUE_PI_PRIVATE  (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_CMP_REQUEUE_PI_PRIVATE
#define FUTEX_CMP_REQUEUE_PI_PRIVATE   (FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================== *
 *   Struct layouts (upstream-compatible)
 * ================================================================== */

typedef union pi_mutex {
    struct {
        uint32_t futex;      /* FUTEX_LOCK_PI format: low 30 bits = owner
                              * TID, bit 30 = FUTEX_OWNER_DIED, bit 31 =
                              * FUTEX_WAITERS. Zero when unowned. */
        uint32_t flags;
        /* NSPA extension — recursion counter for
         * NSPA_RTPI_MUTEX_RECURSIVE. Safely accessible only by the
         * current owner (as determined by the futex word), so no
         * atomic operations are needed. Unused when the RECURSIVE flag
         * is not set. Extends into the 64-byte pad; upstream librtpi
         * code that doesn't know about this field is unaffected. */
        uint32_t nspa_recursion;
    };
    uint8_t pad[64];
} pi_mutex_t __attribute__((aligned(64)));

/* Condvar states — upstream librtpi compatibility. */
#define RTPI_COND_STATE_READY  0

typedef union pi_cond {
    struct {
        uint32_t cond;       /* sequence counter, incremented on each
                              * signal/broadcast. Waiters FUTEX_WAIT_REQUEUE_PI
                              * on this, then the kernel requeues them onto the
                              * PI mutex's futex on signal. */
        uint32_t flags;
        uint32_t wake_id;    /* tracks signal generation to detect missed wakes
                              * on EAGAIN (value changed between unlock & wait) */
        uint32_t state;      /* RTPI_COND_STATE_READY (for EAGAIN retry logic) */
    };
    uint8_t pad[128];
} pi_cond_t __attribute__((aligned(64)));

#define RTPI_MUTEX_PSHARED       0x1
#define RTPI_COND_PSHARED        0x1
#define RTPI_COND_CLOCK_REALTIME 0x2

/* NSPA extension — recursive pi_mutex. Not present in upstream librtpi.
 * When set, pi_mutex_lock/trylock on a mutex already owned by the current
 * thread bumps nspa_recursion instead of returning EDEADLK; pi_mutex_unlock
 * decrements it and only releases the futex word when it hits zero.
 *
 * Rationale: Wine's virtual_mutex is genuinely re-entered from within
 * signal handlers (guard-page stack growth path re-enters the address-space
 * lock from virtual_setup_exception while the faulting thread already
 * holds it). Upstream librtpi deliberately doesn't support recursion —
 * not a kernel limitation, a library design choice — so we add it
 * minimally on top of the existing futex PI primitive. The recursion
 * counter is only touched by the current owner (as determined by the
 * futex word), so no atomics are needed on it.
 *
 * This is a strict extension: non-recursive pi_mutex_t behavior is
 * unchanged, and a mutex initialized without this flag behaves exactly
 * like upstream librtpi. */
#define NSPA_RTPI_MUTEX_RECURSIVE 0x10

#ifndef __cplusplus
#define PI_MUTEX_INIT(f) { .futex = 0, .flags = (f), .nspa_recursion = 0 }
#define PI_COND_INIT(f)  { .cond = 0, .flags = (f), .wake_id = 0, .state = 0 }
#else
static inline pi_mutex_t PI_MUTEX_INIT(uint32_t f) { pi_mutex_t m = {}; m.futex = 0; m.flags = f; m.nspa_recursion = 0; return m; }
static inline pi_cond_t  PI_COND_INIT(uint32_t f)  { pi_cond_t c = {}; c.cond = 0; c.flags = f; return c; }
#endif

#define DEFINE_PI_MUTEX(mutex, flags) pi_mutex_t mutex = PI_MUTEX_INIT(flags)
#define DEFINE_PI_COND(condvar, flags) pi_cond_t condvar = PI_COND_INIT(flags)

/* ================================================================== *
 *   Linux TID cache — one syscall per thread, cached in __thread var
 * ================================================================== */

static __thread uint32_t nspa_rtpi_cached_tid;

static inline uint32_t nspa_rtpi_tid(void)
{
    uint32_t tid = nspa_rtpi_cached_tid;
    if (!tid) {
        tid = (uint32_t)syscall( SYS_gettid );
        nspa_rtpi_cached_tid = tid;
    }
    return tid;
}

/* ================================================================== *
 *   pi_mutex_t — futex PI on a raw word
 * ================================================================== */

static inline int pi_mutex_init(pi_mutex_t *mutex, uint32_t flags)
{
    if (flags & ~(RTPI_MUTEX_PSHARED | NSPA_RTPI_MUTEX_RECURSIVE)) return EINVAL;
    memset(mutex, 0, sizeof(*mutex));
    mutex->flags = flags;
    return 0;
}

static inline int pi_mutex_destroy(pi_mutex_t *mutex)
{
    memset(mutex, 0, sizeof(*mutex));
    return 0;
}

static inline int pi_mutex_trylock(pi_mutex_t *mutex)
{
    uint32_t tid = nspa_rtpi_tid();
    uint32_t expected = 0;
    int op = (mutex->flags & RTPI_MUTEX_PSHARED) ? FUTEX_TRYLOCK_PI : FUTEX_TRYLOCK_PI_PRIVATE;

    /* User-space fast path */
    if (__atomic_compare_exchange_n(&mutex->futex, &expected, tid, 0,
                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return 0;
    if ((mutex->futex & 0x3fffffffu) == tid) {
        /* NSPA recursive extension: bump counter instead of EDEADLK. */
        if (mutex->flags & NSPA_RTPI_MUTEX_RECURSIVE) {
            mutex->nspa_recursion++;
            return 0;
        }
        return EDEADLK;
    }

    /* Slow path: kernel trylock */
    if (syscall(SYS_futex, &mutex->futex, op, 0, NULL, NULL, 0) == 0)
        return 0;
    return errno;
}

static inline int pi_mutex_lock(pi_mutex_t *mutex)
{
    uint32_t tid = nspa_rtpi_tid();
    uint32_t expected = 0;
    int op = (mutex->flags & RTPI_MUTEX_PSHARED) ? FUTEX_LOCK_PI : FUTEX_LOCK_PI_PRIVATE;
    int ret;

    /* User-space fast path */
    if (__atomic_compare_exchange_n(&mutex->futex, &expected, tid, 0,
                                     __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
        return 0;
    if ((mutex->futex & 0x3fffffffu) == tid) {
        /* NSPA recursive extension: bump counter instead of EDEADLK. */
        if (mutex->flags & NSPA_RTPI_MUTEX_RECURSIVE) {
            mutex->nspa_recursion++;
            return 0;
        }
        return EDEADLK;
    }

    /* Slow path: kernel lock (blocking, with PI boost) */
    do {
        ret = syscall(SYS_futex, &mutex->futex, op, 0, NULL, NULL, 0);
    } while (ret == -1 && errno == EINTR);
    return ret == 0 ? 0 : errno;
}

static inline int pi_mutex_unlock(pi_mutex_t *mutex)
{
    uint32_t tid = nspa_rtpi_tid();
    uint32_t expected = tid;
    int op = (mutex->flags & RTPI_MUTEX_PSHARED) ? FUTEX_UNLOCK_PI : FUTEX_UNLOCK_PI_PRIVATE;

    if ((mutex->futex & 0x3fffffffu) != tid)
        return EPERM;

    /* NSPA recursive extension: unwind one level if counter is non-zero.
     * The current thread owns the futex word (checked above), so reading
     * and decrementing nspa_recursion without atomics is safe — no other
     * thread can observe or modify it while we hold the lock. */
    if (mutex->flags & NSPA_RTPI_MUTEX_RECURSIVE) {
        if (mutex->nspa_recursion > 0) {
            mutex->nspa_recursion--;
            return 0;
        }
    }

    /* User-space fast path: CAS tid → 0 (only works if no waiters) */
    if (__atomic_compare_exchange_n(&mutex->futex, &expected, 0, 0,
                                     __ATOMIC_RELEASE, __ATOMIC_RELAXED))
        return 0;

    /* Slow path: kernel unlock, wakes the highest-priority waiter */
    if (syscall(SYS_futex, &mutex->futex, op, 0, NULL, NULL, 0) == 0)
        return 0;
    return errno;
}

static inline pi_mutex_t *pi_mutex_alloc(void)
{
    return (pi_mutex_t *)calloc(1, sizeof(pi_mutex_t));
}

static inline void pi_mutex_free(pi_mutex_t *mutex)
{
    free(mutex);
}

/* ================================================================== *
 *   pi_cond_t — FUTEX_WAIT_REQUEUE_PI condvar
 *
 *   Uses FUTEX_WAIT_REQUEUE_PI / FUTEX_CMP_REQUEUE_PI so that waiters
 *   are atomically requeued from the condvar futex onto the PI mutex's
 *   futex on signal. This closes the priority inversion window that
 *   existed with plain FUTEX_WAIT (where a woken thread had to manually
 *   relock the mutex, creating a gap where no PI boost was in effect).
 *
 *   Wait path:
 *     1. Increment sequence counter + record wake_id
 *     2. Unlock PI mutex
 *     3. FUTEX_WAIT_REQUEUE_PI on condvar (kernel atomically waits,
 *        then requeues us onto the mutex PI chain on wake)
 *     4. On success: we already own the mutex. Done.
 *     5. On error (EAGAIN = value changed): manually relock, retry.
 *
 *   Signal path:
 *     1. Increment sequence counter + set wake_id
 *     2. FUTEX_CMP_REQUEUE_PI: wakes 1 waiter, requeues the rest
 *        directly onto the mutex PI chain (no thundering herd)
 *
 *   Based on upstream librtpi (pi_cond.c), adapted for header-only.
 * ================================================================== */

static inline int pi_cond_init(pi_cond_t *cond, uint32_t flags)
{
    memset(cond, 0, sizeof(*cond));
    cond->flags = flags;
    cond->state = RTPI_COND_STATE_READY;
    return 0;
}

static inline int pi_cond_destroy(pi_cond_t *cond)
{
    memset(cond, 0, sizeof(*cond));
    return 0;
}

static inline int pi_cond_timedwait(pi_cond_t *cond, pi_mutex_t *mutex,
                                     const struct timespec *abstime)
{
    int ret, err;
    uint32_t wake_id, futex_id;
    int wait_op = (cond->flags & RTPI_COND_PSHARED)
                  ? FUTEX_WAIT_REQUEUE_PI : FUTEX_WAIT_REQUEUE_PI_PRIVATE;

    if (cond->flags & RTPI_COND_CLOCK_REALTIME)
        wait_op |= FUTEX_CLOCK_REALTIME;

    cond->cond++;
    wake_id = cond->wake_id;

again:
    futex_id = cond->cond;
    ret = pi_mutex_unlock(mutex);
    if (ret) return ret;

    /* FUTEX_WAIT_REQUEUE_PI: sleep on condvar, kernel requeues us onto
     * the PI mutex's futex on signal. If successful, we own the mutex. */
    ret = syscall(SYS_futex, &cond->cond, wait_op, futex_id,
                  abstime, &mutex->futex, 0);
    err = errno;

    /* Success: kernel requeued us and we now own the mutex. */
    if (ret == 0)
        return 0;

    /* Error path: must manually reacquire the mutex. */
    {
        int lret = pi_mutex_lock(mutex);
        if (lret) return lret;
    }

    /* EAGAIN = condvar value changed between unlock & wait.
     * Check if we raced with a signal. */
    if (err == EAGAIN && cond->state == RTPI_COND_STATE_READY)
    {
        /* If wake_id changed, a signal happened after us — we may have
         * missed the wake. Stay awake (don't retry). */
        if (cond->wake_id != wake_id)
            return 0;

        /* Same wake_id — genuine race. Reload and retry. */
        cond->cond++;
        goto again;
    }

    if (err == ETIMEDOUT) return ETIMEDOUT;
    return err;
}

static inline int pi_cond_wait(pi_cond_t *cond, pi_mutex_t *mutex)
{
    return pi_cond_timedwait(cond, mutex, NULL);
}

static inline int pi_cond_signal(pi_cond_t *cond, pi_mutex_t *mutex)
{
    int ret;
    uint32_t id;
    int requeue_op = (cond->flags & RTPI_COND_PSHARED)
                     ? FUTEX_CMP_REQUEUE_PI : FUTEX_CMP_REQUEUE_PI_PRIVATE;

again:
    cond->cond++;
    id = cond->cond;
    cond->wake_id = id;

    /* FUTEX_CMP_REQUEUE_PI: wake 1, requeue 0 (signal wakes exactly one). */
    ret = syscall(SYS_futex, &cond->cond, requeue_op, 1,
                  (void *)(long)0, &mutex->futex, id);
    if (ret >= 0)
        return 0;
    if (errno == EAGAIN)
        goto again;
    return errno;
}

static inline int pi_cond_broadcast(pi_cond_t *cond, pi_mutex_t *mutex)
{
    int ret;
    uint32_t id;
    int requeue_op = (cond->flags & RTPI_COND_PSHARED)
                     ? FUTEX_CMP_REQUEUE_PI : FUTEX_CMP_REQUEUE_PI_PRIVATE;

again:
    cond->cond++;
    id = cond->cond;
    cond->wake_id = id;

    /* FUTEX_CMP_REQUEUE_PI: wake 1, requeue INT_MAX (all others move
     * directly onto the PI mutex's wait queue — no thundering herd). */
    ret = syscall(SYS_futex, &cond->cond, requeue_op, 1,
                  (void *)(long)INT_MAX, &mutex->futex, id);
    if (ret >= 0)
        return 0;
    if (errno == EAGAIN)
        goto again;
    return errno;
}

static inline pi_cond_t *pi_cond_alloc(void)
{
    return (pi_cond_t *)calloc(1, sizeof(pi_cond_t));
}

static inline void pi_cond_free(pi_cond_t *cond)
{
    free(cond);
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* RTPI_H */
