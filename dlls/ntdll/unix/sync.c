/*
 * Process synchronisation
 *
 * Copyright 1996, 1997, 1998 Marcus Meissner
 * Copyright 1997, 1999 Alexandre Julliard
 * Copyright 1999, 2000 Juergen Schmied
 * Copyright 2003 Eric Pouech
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif
#include <sys/time.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <poll.h>
#include <unistd.h>
#ifdef HAVE_SCHED_H
# include <sched.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#ifdef __APPLE__
# include <mach/mach_time.h>
#endif
#ifdef HAVE_KQUEUE
# include <sys/event.h>
#endif
#ifdef HAVE_LINUX_NTSYNC_H
# include <linux/ntsync.h>
/* NSPA: uring_fd extension — compat for headers that still have 'pad' */
# ifndef NTSYNC_INDEX_URING_READY
#  define NTSYNC_INDEX_URING_READY 0xFFFFFFFEu
# endif
# ifndef NTSYNC_IOC_EVENT_SET_PI
struct ntsync_event_set_pi_args
{
    __u32 flags;
    __u32 policy;
    __u32 prio;
    __u32 __pad;
};
#  define NTSYNC_IOC_EVENT_SET_PI _IOW('N', 0x8e, struct ntsync_event_set_pi_args)
# endif
#endif

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"
#include "ddk/wdm.h"
#include "wine/server.h"
#include "wine/debug.h"
#include "unix_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(sync);

HANDLE keyed_event = 0;
int inproc_device_fd = -1;
int nspa_request_channel_fd = -1; /* NSPA gamma: ntsync channel for shm-IPC */

static const char *debugstr_timeout( const LARGE_INTEGER *timeout )
{
    if (!timeout) return "(infinite)";
    return wine_dbg_sprintf( "%lld.%07ld", (long long)(timeout->QuadPart / TICKSPERSEC),
                             (long)(timeout->QuadPart % TICKSPERSEC) );
}


/* return a monotonic time counter, in Win32 ticks */
static inline ULONGLONG monotonic_counter(void)
{
    struct timeval now;
#ifdef __APPLE__
    static mach_timebase_info_data_t timebase;

    if (!timebase.denom) mach_timebase_info( &timebase );
    return mach_continuous_time() * timebase.numer / timebase.denom / 100;
#elif defined(HAVE_CLOCK_GETTIME)
    struct timespec ts;
#ifdef CLOCK_BOOTTIME
    if (!clock_gettime( CLOCK_BOOTTIME, &ts ))
        return ts.tv_sec * (ULONGLONG)TICKSPERSEC + ts.tv_nsec / 100;
#endif
    if (!clock_gettime( CLOCK_MONOTONIC, &ts ))
        return ts.tv_sec * (ULONGLONG)TICKSPERSEC + ts.tv_nsec / 100;
#endif
    gettimeofday( &now, 0 );
    return ticks_from_time_t( now.tv_sec ) + now.tv_usec * 10 - server_start_time;
}

#ifdef __linux__

#define USE_FUTEX

#include <linux/futex.h>

static inline int futex_wait( const LONG *addr, int val, struct timespec *timeout )
{
#if (defined(__i386__) || defined(__arm__)) && _TIME_BITS==64
    if (timeout && sizeof(*timeout) != 8)
    {
        struct {
            long tv_sec;
            long tv_nsec;
        } timeout32 = { timeout->tv_sec, timeout->tv_nsec };

        return syscall( __NR_futex, addr, FUTEX_WAIT_PRIVATE, val, &timeout32, 0, 0 );
    }
#endif
    return syscall( __NR_futex, addr, FUTEX_WAIT_PRIVATE, val, timeout, 0, 0 );
}

static inline int futex_wake_one( const LONG *addr )
{
    return syscall( __NR_futex, addr, FUTEX_WAKE_PRIVATE, 1, NULL, 0, 0 );
}

/* NSPA CS-PI helpers — raw FUTEX_LOCK_PI / FUTEX_UNLOCK_PI around a word the
 * caller owns. The kernel enforces the rt_mutex PI protocol on the word: owner
 * TID in the low 30 bits, FUTEX_OWNER_DIED in bit 30, FUTEX_WAITERS in bit 31.
 * See: Documentation/locking/rt-mutex.txt, futex(2) man page.
 *
 * These are called from PE-side ntdll via Nt-style syscalls
 * (NtNspaLockCriticalSectionPI / NtNspaUnlockCriticalSectionPI) — the PE side
 * publishes its own TID in the fast path, then invokes these syscalls only on
 * contention. */
#ifndef FUTEX_LOCK_PI_PRIVATE
#define FUTEX_LOCK_PI_PRIVATE   (FUTEX_LOCK_PI   | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_UNLOCK_PI_PRIVATE
#define FUTEX_UNLOCK_PI_PRIVATE (FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI   11
#endif
#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI    12
#endif
#ifndef FUTEX_WAIT_REQUEUE_PI_PRIVATE
#define FUTEX_WAIT_REQUEUE_PI_PRIVATE  (FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#endif
#ifndef FUTEX_CMP_REQUEUE_PI_PRIVATE
#define FUTEX_CMP_REQUEUE_PI_PRIVATE   (FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG)
#endif

static inline int futex_lock_pi( LONG *addr )
{
    return syscall( __NR_futex, addr, FUTEX_LOCK_PI_PRIVATE, 0, NULL, 0, 0 );
}

static inline int futex_unlock_pi( LONG *addr )
{
    return syscall( __NR_futex, addr, FUTEX_UNLOCK_PI_PRIVATE, 0, NULL, 0, 0 );
}

static inline int futex_wait_requeue_pi( LONG *condvar, int val,
                                          const struct timespec *abstime, LONG *pi_mutex )
{
    return syscall( __NR_futex, condvar, FUTEX_WAIT_REQUEUE_PI_PRIVATE,
                    val, abstime, pi_mutex, 0 );
}

static inline int futex_cmp_requeue_pi( LONG *condvar, int nr_wake,
                                         int nr_requeue, LONG *pi_mutex, int val )
{
    return syscall( __NR_futex, condvar, FUTEX_CMP_REQUEUE_PI_PRIVATE,
                    nr_wake, (void *)(long)nr_requeue, pi_mutex, val );
}

#elif defined(__APPLE__)

#define USE_FUTEX

#include <AvailabilityMacros.h>

#ifdef MAC_OS_VERSION_14_4
#include <os/os_sync_wait_on_address.h>
#endif

#define UL_COMPARE_AND_WAIT 1

extern int __ulock_wait( uint32_t operation, void *addr, uint64_t value, uint32_t timeout );

extern int __ulock_wake( uint32_t operation, void *addr, uint64_t wake_value );

static inline int futex_wait( const LONG *addr, int val, struct timespec *timeout )
{
#ifdef MAC_OS_VERSION_14_4
    if (__builtin_available( macOS 14.4, * ))
    {
        /* 18446744073 seconds could overflow a uint64_t in nanoseconds */
        if (timeout && timeout->tv_sec < 18446744073)
        {
            uint64_t ns_timeout = (timeout->tv_sec * 1000000000) + timeout->tv_nsec;

            if (!ns_timeout)
            {
                errno = ETIMEDOUT;
                return -1;
            }
            return os_sync_wait_on_address_with_timeout( (void *)addr, (uint64_t)val, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE,
                                                         OS_CLOCK_MACH_ABSOLUTE_TIME, ns_timeout );
        }

        return os_sync_wait_on_address( (void *)addr, (uint64_t)val, 4, OS_SYNC_WAIT_ON_ADDRESS_NONE );
    }
#endif

    /* 4294 seconds could overflow a uint32_t in microseconds */
    if (timeout && timeout->tv_sec < 4294)
    {
        uint32_t us_timeout = ((uint32_t)timeout->tv_sec * 1000000) + ((uint32_t)timeout->tv_nsec / 1000);

        if (!us_timeout)
        {
            errno = ETIMEDOUT;
            return -1;
        }
        return __ulock_wait( UL_COMPARE_AND_WAIT, (void *)addr, (uint64_t)val, us_timeout );
    }

    return __ulock_wait( UL_COMPARE_AND_WAIT, (void *)addr, (uint64_t)val, 0 );
}

static inline int futex_wake_one( const LONG *addr )
{
#ifdef MAC_OS_VERSION_14_4
    if (__builtin_available( macOS 14.4, * ))
        return os_sync_wake_by_address_any( (void *)addr, 4, OS_SYNC_WAKE_BY_ADDRESS_NONE );
#endif
    return __ulock_wake( UL_COMPARE_AND_WAIT, (void *)addr, 0 );
}

#endif /* __APPLE__ */

/* create a struct security_descriptor and contained information in one contiguous piece of memory */
unsigned int alloc_object_attributes( const OBJECT_ATTRIBUTES *attr, struct object_attributes **ret,
                                      data_size_t *ret_len )
{
    unsigned int len = sizeof(**ret);
    SID *owner = NULL, *group = NULL;
    ACL *dacl = NULL, *sacl = NULL;
    SECURITY_DESCRIPTOR *sd;

    *ret = NULL;
    *ret_len = 0;

    if (!attr) return STATUS_SUCCESS;

    if (attr->Length != sizeof(*attr)) return STATUS_INVALID_PARAMETER;

    if ((sd = attr->SecurityDescriptor))
    {
        len += sizeof(struct security_descriptor);
	if (sd->Revision != SECURITY_DESCRIPTOR_REVISION) return STATUS_UNKNOWN_REVISION;
        if (sd->Control & SE_SELF_RELATIVE)
        {
            SECURITY_DESCRIPTOR_RELATIVE *rel = (SECURITY_DESCRIPTOR_RELATIVE *)sd;
            if (rel->Owner) owner = (PSID)((BYTE *)rel + rel->Owner);
            if (rel->Group) group = (PSID)((BYTE *)rel + rel->Group);
            if ((sd->Control & SE_SACL_PRESENT) && rel->Sacl) sacl = (PSID)((BYTE *)rel + rel->Sacl);
            if ((sd->Control & SE_DACL_PRESENT) && rel->Dacl) dacl = (PSID)((BYTE *)rel + rel->Dacl);
        }
        else
        {
            owner = sd->Owner;
            group = sd->Group;
            if (sd->Control & SE_SACL_PRESENT) sacl = sd->Sacl;
            if (sd->Control & SE_DACL_PRESENT) dacl = sd->Dacl;
        }

        if (owner) len += offsetof( SID, SubAuthority[owner->SubAuthorityCount] );
        if (group) len += offsetof( SID, SubAuthority[group->SubAuthorityCount] );
        if (sacl) len += sacl->AclSize;
        if (dacl) len += dacl->AclSize;

        /* fix alignment for the Unicode name that follows the structure */
        len = (len + sizeof(WCHAR) - 1) & ~(sizeof(WCHAR) - 1);
    }

    if (attr->ObjectName)
    {
        if ((ULONG_PTR)attr->ObjectName->Buffer & (sizeof(WCHAR) - 1)) return STATUS_DATATYPE_MISALIGNMENT;
        if (attr->ObjectName->Length & (sizeof(WCHAR) - 1)) return STATUS_OBJECT_NAME_INVALID;
        len += attr->ObjectName->Length;
    }
    else if (attr->RootDirectory) return STATUS_OBJECT_NAME_INVALID;

    len = (len + 3) & ~3;  /* DWORD-align the entire structure */

    if (!(*ret = calloc( len, 1 ))) return STATUS_NO_MEMORY;

    (*ret)->rootdir = wine_server_obj_handle( attr->RootDirectory );
    (*ret)->attributes = attr->Attributes;

    if (attr->SecurityDescriptor)
    {
        struct security_descriptor *descr = (struct security_descriptor *)(*ret + 1);
        unsigned char *ptr = (unsigned char *)(descr + 1);

        descr->control = sd->Control & ~SE_SELF_RELATIVE;
        if (owner) descr->owner_len = offsetof( SID, SubAuthority[owner->SubAuthorityCount] );
        if (group) descr->group_len = offsetof( SID, SubAuthority[group->SubAuthorityCount] );
        if (sacl) descr->sacl_len = sacl->AclSize;
        if (dacl) descr->dacl_len = dacl->AclSize;

        memcpy( ptr, owner, descr->owner_len );
        ptr += descr->owner_len;
        memcpy( ptr, group, descr->group_len );
        ptr += descr->group_len;
        memcpy( ptr, sacl, descr->sacl_len );
        ptr += descr->sacl_len;
        memcpy( ptr, dacl, descr->dacl_len );
        (*ret)->sd_len = (sizeof(*descr) + descr->owner_len + descr->group_len + descr->sacl_len +
                          descr->dacl_len + sizeof(WCHAR) - 1) & ~(sizeof(WCHAR) - 1);
    }

    if (attr->ObjectName)
    {
        unsigned char *ptr = (unsigned char *)(*ret + 1) + (*ret)->sd_len;
        (*ret)->name_len = attr->ObjectName->Length;
        memcpy( ptr, attr->ObjectName->Buffer, (*ret)->name_len );
    }

    *ret_len = len;
    return STATUS_SUCCESS;
}


static unsigned int validate_open_object_attributes( const OBJECT_ATTRIBUTES *attr )
{
    if (!attr || attr->Length != sizeof(*attr)) return STATUS_INVALID_PARAMETER;

    if (attr->ObjectName)
    {
        if ((ULONG_PTR)attr->ObjectName->Buffer & (sizeof(WCHAR) - 1)) return STATUS_DATATYPE_MISALIGNMENT;
        if (attr->ObjectName->Length & (sizeof(WCHAR) - 1)) return STATUS_OBJECT_NAME_INVALID;
    }
    else if (attr->RootDirectory) return STATUS_OBJECT_NAME_INVALID;

    return STATUS_SUCCESS;
}

#ifdef NTSYNC_IOC_EVENT_READ

static NTSTATUS linux_release_semaphore_obj( int obj, ULONG count, ULONG *prev_count )
{
    if (ioctl( obj, NTSYNC_IOC_SEM_RELEASE, &count ) < 0)
    {
        if (errno == EOVERFLOW) return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
        return errno_to_status( errno );
    }
    if (prev_count) *prev_count = count;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_query_semaphore_obj( int obj, SEMAPHORE_BASIC_INFORMATION *info )
{
    struct ntsync_sem_args args = {0};
    if (ioctl( obj, NTSYNC_IOC_SEM_READ, &args ) < 0) return errno_to_status( errno );
    info->CurrentCount = args.count;
    info->MaximumCount = args.max;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_set_event_obj( int obj, LONG *prev_state )
{
    __u32 prev;
    if (ioctl( obj, NTSYNC_IOC_EVENT_SET, &prev ) < 0) return errno_to_status( errno );
    if (prev_state) *prev_state = prev;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_set_event_obj_pi( int obj, unsigned int policy, unsigned int prio )
{
    struct ntsync_event_set_pi_args args = {.flags = 0, .policy = policy, .prio = prio, .__pad = 0};

    if (ioctl( obj, NTSYNC_IOC_EVENT_SET_PI, &args ) < 0) return errno_to_status( errno );
    return STATUS_SUCCESS;
}


static NTSTATUS linux_reset_event_obj( int obj, LONG *prev_state )
{
    __u32 prev;
    if (ioctl( obj, NTSYNC_IOC_EVENT_RESET, &prev ) < 0) return errno_to_status( errno );
    if (prev_state) *prev_state = prev;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_pulse_event_obj( int obj, LONG *prev_state )
{
    __u32 prev;
    if (ioctl( obj, NTSYNC_IOC_EVENT_PULSE, &prev ) < 0) return errno_to_status( errno );
    if (prev_state) *prev_state = prev;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_query_event_obj( int obj, EVENT_BASIC_INFORMATION *info )
{
    struct ntsync_event_args args = {0};
    if (ioctl( obj, NTSYNC_IOC_EVENT_READ, &args ) < 0) return errno_to_status( errno );
    info->EventType = args.manual ? NotificationEvent : SynchronizationEvent;
    info->EventState = args.signaled;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_release_mutex_obj( int obj, LONG *prev_count )
{
    struct ntsync_mutex_args args = {.owner = GetCurrentThreadId()};
    if (ioctl( obj, NTSYNC_IOC_MUTEX_UNLOCK, &args ) < 0)
    {
        if (errno == EOVERFLOW) return STATUS_MUTANT_LIMIT_EXCEEDED;
        if (errno == EPERM) return STATUS_MUTANT_NOT_OWNED;
        return errno_to_status( errno );
    }
    if (prev_count) *prev_count = 1 - args.count;
    return STATUS_SUCCESS;
}

static NTSTATUS linux_query_mutex_obj( int obj, MUTANT_BASIC_INFORMATION *info )
{
    struct ntsync_mutex_args args = {0};
    if (ioctl( obj, NTSYNC_IOC_MUTEX_READ, &args ) < 0)
    {
        if (errno == EOWNERDEAD)
        {
            info->AbandonedState = TRUE;
            info->OwnedByCaller = FALSE;
            info->CurrentCount = 1;
            return STATUS_SUCCESS;
        }
        return errno_to_status( errno );
    }
    info->AbandonedState = FALSE;
    info->OwnedByCaller = (args.owner == GetCurrentThreadId());
    info->CurrentCount = 1 - args.count;
    return STATUS_SUCCESS;
}

/* NSPA internal sentinel: ntsync returned because io_uring CQE ready.
 * Not a real NTSTATUS — used only between linux_wait_objs and callers. */
#define STATUS_URING_COMPLETION ((NTSTATUS)0xC01500FEu)

static NTSTATUS linux_wait_objs( int device, DWORD count, const int *objs, WAIT_TYPE type,
                                 int alert_fd, int uring_fd,
                                 const LARGE_INTEGER *timeout )
{
    struct ntsync_wait_args args = {0};
    unsigned long request;
    struct timespec now;
    int ret;

    if (!timeout || timeout->QuadPart == TIMEOUT_INFINITE)
    {
        args.timeout = ~(__u64)0;
    }
    else if (timeout->QuadPart <= 0)
    {
        clock_gettime( CLOCK_MONOTONIC, &now );
        args.timeout = ((ULONGLONG)now.tv_sec * NSECPERSEC) + now.tv_nsec + (-timeout->QuadPart * 100);
    }
    else
    {
        args.timeout = (timeout->QuadPart * 100) - (SECS_1601_TO_1970 * NSECPERSEC);
        args.flags |= NTSYNC_WAIT_REALTIME;
    }

    args.objs = (uintptr_t)objs;
    args.count = count;
    args.owner = GetCurrentThreadId();
    args.index = ~0u;
    args.alert = alert_fd;
    /* NSPA: pass io_uring eventfd so ntsync wakes on CQE.  The kernel
     * extension renames 'pad' to 'uring_fd' — same offset, same size. */
    args.pad = uring_fd > 0 ? uring_fd : 0;

    if (type != WaitAll || count == 1) request = NTSYNC_IOC_WAIT_ANY;
    else request = NTSYNC_IOC_WAIT_ALL;

    do { ret = ioctl( device, request, &args ); }
    while (ret < 0 && errno == EINTR);

    if (!ret)
    {
        if (args.index == NTSYNC_INDEX_URING_READY)
        {
            /* io_uring CQE arrived — consume the eventfd counter and
             * tell the caller to drain completions and retry. */
            if (uring_fd > 0)
            {
                uint64_t val;
                read( uring_fd, &val, sizeof(val) );
            }
            return STATUS_URING_COMPLETION;
        }

        if (args.index == count)
        {
            static const LARGE_INTEGER timeout;

            ret = server_wait( NULL, 0, SELECT_INTERRUPTIBLE | SELECT_ALERTABLE, &timeout );
            assert( ret == STATUS_USER_APC );
            return ret;
        }

        return type != WaitAll ? args.index : 0;
    }
    if (errno == EOWNERDEAD) return STATUS_ABANDONED + (type != WaitAll ? args.index : 0);
    if (errno == ETIMEDOUT) return STATUS_TIMEOUT;
    return errno_to_status( errno );
}

#else /* NTSYNC_IOC_EVENT_READ */

static NTSTATUS linux_release_semaphore_obj( int obj, ULONG count, ULONG *prev_count )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_query_semaphore_obj( int obj, SEMAPHORE_BASIC_INFORMATION *info )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_set_event_obj( int obj, LONG *prev_state )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_set_event_obj_pi( int obj, unsigned int policy, unsigned int prio )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_reset_event_obj( int obj, LONG *prev_state )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_pulse_event_obj( int obj, LONG *prev_state )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_query_event_obj( int obj, EVENT_BASIC_INFORMATION *info )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_release_mutex_obj( int obj, LONG *prev_count )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_query_mutex_obj( int obj, MUTANT_BASIC_INFORMATION *info )
{
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS linux_wait_objs( int device, DWORD count, const int *objs, WAIT_TYPE type,
                                 int alert_fd, int uring_fd,
                                 const LARGE_INTEGER *timeout )
{
    return STATUS_NOT_IMPLEMENTED;
}

#endif /* NTSYNC_IOC_EVENT_READ */

/* It's possible for synchronization primitives to remain alive even after being
 * closed, because a thread is still waiting on them. It's rare in practice, and
 * documented as being undefined behaviour by Microsoft, but it works, and some
 * applications rely on it. This means we need to refcount handles, and defer
 * deleting them on the server side until the refcount reaches zero. We do this
 * by having each client process hold a handle to the in-process synchronization
 * object, as well as a private refcount. When the client refcount reaches zero,
 * it closes the handle; when all handles are closed, the server deletes the
 * in-process synchronization object.
 *
 * We also need this for signal-and-wait. The signal and wait operations aren't
 * atomic, but we can't perform the signal and then return STATUS_INVALID_HANDLE
 * for the wait—we need to either do both operations or neither. That means we
 * need to grab references to both objects, and prevent them from being
 * destroyed before we're done with them.
 *
 * We want lookup of objects from the cache to be very fast; ideally, it should
 * be lock-free. We achieve this by using atomic modifications to "refcount",
 * and guaranteeing that all other fields are valid and correct *as long as*
 * refcount is nonzero, and we store the entire structure in memory which will
 * never be freed.
 *
 * This means that acquiring the object can't use a simple atomic increment; it
 * has to use a compare-and-swap loop to ensure that it doesn't try to increment
 * an object with a zero refcount. That's still leagues better than a real lock,
 * though, and release can be a single atomic decrement.
 *
 * It also means that threads modifying the cache need to take a lock, to
 * prevent other threads from writing to it concurrently.
 *
 * It's possible for an object currently in use (by a waiter) to be closed and
 * the same handle immediately reallocated to a different object. This should be
 * a very rare situation, and in that case we simply don't cache the handle.
 */
struct inproc_sync
{
    LONG           refcount;  /* reference count of the sync object */
    int            fd;        /* unix file descriptor */
    unsigned int   access;    /* handle access rights */
    unsigned short type;      /* enum inproc_sync_type as short to save space */
    unsigned short closed;    /* fd has been closed but sync is still referenced */
};

#define INPROC_SYNC_CACHE_BLOCK_SIZE  (65536 / sizeof(struct inproc_sync))
#define INPROC_SYNC_CACHE_ENTRIES     128
#define INPROC_SYNC_CACHE_TOTAL       (INPROC_SYNC_CACHE_BLOCK_SIZE * INPROC_SYNC_CACHE_ENTRIES)

/*
 * NSPA: Client-side handle allocation for anonymous sync objects.
 *
 * Server allocates handles from index 0 upward. We allocate from just below
 * the cache ceiling downward. With 524,288 cacheable positions and typical
 * server usage of <10K handles, collision is effectively impossible.
 */
#define CLIENT_HANDLE_POOL_SIZE  256
#define CLIENT_HANDLE_BASE  (INPROC_SYNC_CACHE_TOTAL - CLIENT_HANDLE_POOL_SIZE)
/* Initialised to INPROC_SYNC_CACHE_TOTAL (one above the highest valid idx)
 * so the first InterlockedDecrement returns INPROC_SYNC_CACHE_TOTAL - 1,
 * yielding handle ((INPROC_SYNC_CACHE_TOTAL - 1) + 1) << 2 = the highest
 * valid client-range handle.  is_client_handle's check
 * `idx >= CLIENT_HANDLE_BASE && idx < INPROC_SYNC_CACHE_TOTAL` then matches.
 *
 * Old code initialised this to CLIENT_HANDLE_BASE — caused the first
 * Decrement to return CLIENT_HANDLE_BASE - 1, putting every allocated
 * handle's idx one step BELOW CLIENT_HANDLE_BASE, so is_client_handle
 * returned FALSE for every client-range handle ever allocated.  Silently
 * routed mutex/sem/event closes through the server close_handle RPC,
 * which always returned STATUS_INVALID_HANDLE.  Latent because mutex/sem
 * close paths don't check CloseHandle's return; surfaced via wined3d_cs_destroy
 * (events Phase 4.6.F default-ON) which does check it. */
static LONG client_handle_next = INPROC_SYNC_CACHE_TOTAL;

/* Lock-free LIFO of recycled client-handle slot offsets.  Each entry stores
 * the next free offset (relative to CLIENT_HANDLE_BASE), or -1 for the
 * stack bottom.  client_handle_freelist_head packs (offset + 1) into the
 * low 16 bits (0 = empty stack) and a generation counter into the high 16
 * bits to defeat ABA on concurrent pop.  alloc_client_handle pops from the
 * freelist before drawing from client_handle_next; without this, the 256
 * slot pool was a one-shot — once cumulative allocations crossed the cap,
 * every subsequent anonymous create fell back to the server even though
 * most handles had since been closed. */
static LONG client_handle_freelist[CLIENT_HANDLE_POOL_SIZE];
static LONG client_handle_freelist_head;

/* NSPA: Track client-created mutexes for thread-death abandonment.
 * Protected by fd_cache_mutex. */
struct client_mutex_entry
{
    struct list entry;
    int         fd;
    HANDLE      handle;
};
static struct list client_mutex_list = LIST_INIT( client_mutex_list );

static struct inproc_sync *inproc_sync_cache[INPROC_SYNC_CACHE_ENTRIES];
static struct inproc_sync inproc_sync_cache_initial_block[INPROC_SYNC_CACHE_BLOCK_SIZE];

static inline unsigned int inproc_sync_handle_to_index( HANDLE handle, unsigned int *entry )
{
    unsigned int idx = (wine_server_obj_handle(handle) >> 2) - 1;
    *entry = idx / INPROC_SYNC_CACHE_BLOCK_SIZE;
    return idx % INPROC_SYNC_CACHE_BLOCK_SIZE;
}

static BOOL is_pseudo_handle( HANDLE handle )
{
    return ((ULONG)(ULONG_PTR)handle >= 0xfffffffa);
}

static struct inproc_sync *cache_inproc_sync( HANDLE handle, struct inproc_sync *sync )
{
    unsigned int entry, idx = inproc_sync_handle_to_index( handle, &entry );
    struct inproc_sync *cache;
    int refcount;

    /* don't cache pseudo-handles; waiting on them is pointless anyway */
    if (is_pseudo_handle( handle )) return sync;

    if (entry >= INPROC_SYNC_CACHE_ENTRIES)
    {
        FIXME( "too many allocated handles, not caching %p\n", handle );
        return sync;
    }

    if (!inproc_sync_cache[entry])  /* do we need to allocate a new block of entries? */
    {
        if (!entry) inproc_sync_cache[0] = inproc_sync_cache_initial_block;
        else
        {
            static const size_t size = INPROC_SYNC_CACHE_BLOCK_SIZE * sizeof(struct inproc_sync);
            void *ptr = anon_mmap_alloc( size, PROT_READ | PROT_WRITE, LARGE_PAGES_NONE );
            if (ptr == MAP_FAILED) return sync;
            inproc_sync_cache[entry] = ptr;
        }
    }

    cache = &inproc_sync_cache[entry][idx];

    if (InterlockedCompareExchange( &cache->refcount, 0, 0 ))
    {
        /* The handle is currently being used for another object (i.e. it was
         * closed and then reused, but some thread is waiting on the old handle
         * or otherwise simultaneously using the old object). We can't cache
         * this object until the old one is completely destroyed. */
        return sync;
    }

    cache->fd = sync->fd;
    cache->access = sync->access;
    cache->type = sync->type;
    cache->closed = sync->closed;
    /* Make sure we set the other members before the refcount; this store needs
     * release semantics [paired with the load in get_cached_inproc_sync()].
     * Set the refcount to 2 (one for the handle, one for the caller). */
    refcount = InterlockedExchange( &cache->refcount, 2 );
    assert( !refcount );

    assert( sync->refcount == 1 );
    memset( sync, 0, sizeof(*sync) );

    return cache;
}

/* returns the previous value */
static inline LONG interlocked_inc_if_nonzero( LONG *dest )
{
    LONG val, tmp;
    for (val = *dest;; val = tmp)
    {
        if (!val || (tmp = InterlockedCompareExchange( dest, val + 1, val )) == val)
            break;
    }
    return val;
}

static void release_inproc_sync( struct inproc_sync *sync )
{
    /* save the fd now; as soon as the refcount hits 0 we cannot
     * access the cache anymore */
    int fd = sync->fd;
    LONG ref = InterlockedDecrement( &sync->refcount );

    assert( ref >= 0 );
    if (!ref) close( fd );
}

static struct inproc_sync *get_cached_inproc_sync( HANDLE handle )
{
    unsigned int entry, idx = inproc_sync_handle_to_index( handle, &entry );
    struct inproc_sync *cache;

    if (entry >= INPROC_SYNC_CACHE_ENTRIES || !inproc_sync_cache[entry]) return NULL;

    cache = &inproc_sync_cache[entry][idx];

    /* this load needs acquire semantics [paired with the store in
     * cache_inproc_sync()] */
    if (!interlocked_inc_if_nonzero( &cache->refcount )) return NULL;

    if (cache->closed)
    {
        /* The object is still being used, but "handle" has been closed. The
         * handle value might have been reused for another object in the
         * meantime, in which case we have to report that valid object, so
         * force the caller to check the server. */
        release_inproc_sync( cache );
        return NULL;
    }

    return cache;
}

/* fd_cache_mutex must be held to avoid races with other thread receiving fds */
static NTSTATUS get_server_inproc_sync( HANDLE handle, struct inproc_sync *sync )
{
    NTSTATUS ret;

    SERVER_START_REQ( get_inproc_sync_fd )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            obj_handle_t fd_handle;
            sync->refcount = 1;
            sync->fd = wine_server_receive_fd( &fd_handle );
            assert( wine_server_ptr_handle(fd_handle) == handle );
            sync->access = reply->access;
            sync->type = reply->type;
            sync->closed = 0;
        }
    }
    SERVER_END_REQ;

    return ret;
}

/* returns a pointer to a cache entry; if the object could not be cached,
 * returns "cache" instead, which should be allocated on stack */
static NTSTATUS get_inproc_sync( HANDLE handle, enum inproc_sync_type desired_type, ACCESS_MASK desired_access,
                                 struct inproc_sync *stack, struct inproc_sync **out )
{
    struct inproc_sync *sync;
    sigset_t sigset;
    NTSTATUS ret;

    /* try to find it in the cache already */
    if ((sync = get_cached_inproc_sync( handle ))) ret = STATUS_SUCCESS;
    else
    {
        /* We need to use fd_cache_mutex here to protect against races with
         * other threads trying to receive fds for the fd cache,
         * and we need to use an uninterrupted section to prevent reentrancy.
         * We also need fd_cache_mutex to protect against the same race with
         * NtClose, that is, to prevent the object from being cached again between
         * close_inproc_sync() and close_handle.
         *
         * The mutex also protects cache_inproc_sync(). Accessing the cache is
         * done without a lock, but populating it currently is not. */
        server_enter_uninterrupted_section( &fd_cache_mutex, &sigset );
        if (!(sync = get_cached_inproc_sync( handle )))
        {
            if ((ret = get_server_inproc_sync( handle, stack )))
            {
                server_leave_uninterrupted_section( &fd_cache_mutex, &sigset );
                return ret;
            }
            sync = cache_inproc_sync( handle, stack );
        }
        server_leave_uninterrupted_section( &fd_cache_mutex, &sigset );
    }

    if (desired_type != INPROC_SYNC_UNKNOWN && desired_type != sync->type)
    {
        release_inproc_sync( sync );
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if ((sync->access & desired_access) != desired_access)
    {
        release_inproc_sync( sync );
        return STATUS_ACCESS_DENIED;
    }

    *out = sync;
    return STATUS_SUCCESS;
}

extern NTSTATUS check_signal_access( struct inproc_sync *sync )
{
    switch (sync->type)
    {
    case INPROC_SYNC_INTERNAL:
        return STATUS_OBJECT_TYPE_MISMATCH;
    case INPROC_SYNC_EVENT:
        if (!(sync->access & EVENT_MODIFY_STATE)) return STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    case INPROC_SYNC_MUTEX:
        if (!(sync->access & SYNCHRONIZE)) return STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    case INPROC_SYNC_SEMAPHORE:
        if (!(sync->access & SEMAPHORE_MODIFY_STATE)) return STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    }

    assert( 0 );
    return STATUS_OBJECT_TYPE_MISMATCH;
}

/* caller must hold fd_cache_mutex */
void close_inproc_sync( HANDLE handle )
{
    struct inproc_sync *cache;

    if (inproc_device_fd < 0) return;
    if ((cache = get_cached_inproc_sync( handle )))
    {
        cache->closed = 1;
        /* once for the reference we just grabbed, and once for the handle */
        release_inproc_sync( cache );
        release_inproc_sync( cache );
    }
}

/*
 * NSPA: Client-side sync object creation infrastructure.
 *
 * Anonymous sync objects bypass the wineserver entirely. The client calls
 * the ntsync ioctl directly and populates the inproc_sync cache at a handle
 * allocated from the client range (top-down, disjoint from server range).
 */

BOOL is_client_handle( HANDLE handle )
{
    unsigned int idx = (wine_server_obj_handle(handle) >> 2) - 1;
    return idx >= CLIENT_HANDLE_BASE && idx < INPROC_SYNC_CACHE_TOTAL;
}

static inline BOOL is_anonymous_attr( const OBJECT_ATTRIBUTES *attr )
{
    if (!attr) return TRUE;
    if (attr->Attributes & OBJ_INHERIT) return FALSE;
    if (attr->RootDirectory) return FALSE;
    if (!attr->ObjectName) return TRUE;
    return attr->ObjectName->Length == 0;
}

static inline BOOL allow_client_sync_creation( enum inproc_sync_type type, const OBJECT_ATTRIBUTES *attr )
{
    /* Phase 4.6: client-range events are signaled correctly across
     * server-async paths via the Option A fix (server-side fd registration
     * + completion-via-direct-ntsync-ioctl).  See plan doc
     * wine/nspa/docs/events-option-a-plan-20260502.md.  Always-on as of
     * 2026-05-04 (env-gate retired). */
    (void)type;
    return is_anonymous_attr( attr );
}

static HANDLE alloc_client_handle(void)
{
    LONG head, next_off, new_head, idx;
    unsigned int off;

    /* Pop a recycled slot before drawing from the never-allocated band.
     * Bounds total active (not cumulative) client-range handles to
     * CLIENT_HANDLE_POOL_SIZE.  Returns NULL to fall back to the legacy
     * server-allocated handle path when both the freelist and the
     * never-allocated band are empty. */
    for (;;)
    {
        head = client_handle_freelist_head;
        if (!(head & 0xffff)) break;
        off = (unsigned int)(head & 0xffff) - 1;
        next_off = client_handle_freelist[off];
        new_head = (LONG)(((unsigned int)head + 0x10000u) & 0xffff0000u);
        if (next_off >= 0) new_head |= (LONG)((unsigned int)(next_off + 1));
        if (InterlockedCompareExchange( &client_handle_freelist_head, new_head, head ) == head)
            return wine_server_ptr_handle( ((unsigned int)(CLIENT_HANDLE_BASE + off) + 1) << 2 );
    }

    idx = InterlockedDecrement( &client_handle_next );
    if (idx < CLIENT_HANDLE_BASE)
    {
        InterlockedIncrement( &client_handle_next );
        return NULL;
    }
    return wine_server_ptr_handle( (unsigned int)(idx + 1) << 2 );
}

static void free_client_handle( HANDLE handle )
{
    unsigned int idx, off;
    LONG head, new_head;

    if (!handle) return;
    idx = (wine_server_obj_handle( handle ) >> 2) - 1;
    if (idx < CLIENT_HANDLE_BASE || idx >= INPROC_SYNC_CACHE_TOTAL) return;
    off = idx - CLIENT_HANDLE_BASE;

    /* Push onto the lock-free LIFO freelist.  Caller owns the slot at
     * `off` (close paths run under fd_cache_mutex; create error paths
     * unwind before publishing the handle), so we are the only writer
     * to client_handle_freelist[off] until our CAS succeeds. */
    for (;;)
    {
        head = client_handle_freelist_head;
        client_handle_freelist[off] = (head & 0xffff)
                                      ? (LONG)((unsigned int)(head & 0xffff) - 1)
                                      : -1;
        new_head = (LONG)(((unsigned int)head + 0x10000u) & 0xffff0000u);
        new_head |= (LONG)(off + 1);
        if (InterlockedCompareExchange( &client_handle_freelist_head, new_head, head ) == head)
            return;
    }
}

/* Populate the inproc_sync cache directly for a client-created object.
 * Caller closes fd on failure. */
static NTSTATUS cache_client_inproc_sync( HANDLE handle, int fd,
                                          enum inproc_sync_type type,
                                          ACCESS_MASK access )
{
    unsigned int entry, idx = inproc_sync_handle_to_index( handle, &entry );
    struct inproc_sync *cache;
    int refcount;

    if (entry >= INPROC_SYNC_CACHE_ENTRIES)
    {
        FIXME( "client handle %p maps beyond cache, not caching\n", handle );
        return STATUS_NO_MEMORY;
    }

    if (!inproc_sync_cache[entry])
    {
        if (!entry)
        {
            InterlockedCompareExchangePointer( (void **)&inproc_sync_cache[0],
                                               inproc_sync_cache_initial_block, NULL );
        }
        else
        {
            static const size_t size = INPROC_SYNC_CACHE_BLOCK_SIZE * sizeof(struct inproc_sync);
            void *ptr = anon_mmap_alloc( size, PROT_READ | PROT_WRITE, LARGE_PAGES_NONE );
            if (ptr == MAP_FAILED) return STATUS_NO_MEMORY;
            if (InterlockedCompareExchangePointer( (void **)&inproc_sync_cache[entry],
                                                   ptr, NULL ) != NULL)
                munmap( ptr, size );
        }
    }

    cache = &inproc_sync_cache[entry][idx];
    cache->fd = fd;
    cache->access = access;
    cache->type = type;
    cache->closed = 0;
    refcount = InterlockedExchange( &cache->refcount, 1 );
    assert( !refcount );

    return STATUS_SUCCESS;
}

/* Caller must hold fd_cache_mutex. */
void close_client_inproc_sync( HANDLE handle )
{
    struct inproc_sync *cache;
    struct client_mutex_entry *mentry, *next;

    if ((cache = get_cached_inproc_sync( handle )))
    {
        /* NSPA Phase 4.6.D: drop the wineserver's fd ref before we close
         * our PE-side fd, so the kernel ntsync object refcount transitions
         * cleanly.  No-op if the handle was never registered (mutex/sem
         * paths don't register; failed-registration unwind already
         * unregistered).  Best-effort. */
        if (cache->type == INPROC_SYNC_EVENT)
            nspa_unregister_inproc_event_with_server( handle );

        if (cache->type == INPROC_SYNC_MUTEX)
        {
            LIST_FOR_EACH_ENTRY_SAFE( mentry, next, &client_mutex_list, struct client_mutex_entry, entry )
            {
                if (mentry->handle == handle)
                {
                    list_remove( &mentry->entry );
                    free( mentry );
                    break;
                }
            }
        }

        cache->closed = 1;
        release_inproc_sync( cache );
        release_inproc_sync( cache );
    }

    free_client_handle( handle );
}

/* Mark all client-created mutexes owned by the dying thread as abandoned. */
void abandon_client_mutexes( DWORD tid )
{
    struct client_mutex_entry *mentry;
    __u32 owner = tid;
    sigset_t sigset;

    server_enter_uninterrupted_section( &fd_cache_mutex, &sigset );
    LIST_FOR_EACH_ENTRY( mentry, &client_mutex_list, struct client_mutex_entry, entry )
        ioctl( mentry->fd, NTSYNC_IOC_MUTEX_KILL, &owner );
    server_leave_uninterrupted_section( &fd_cache_mutex, &sigset );
}

#ifdef NTSYNC_IOC_EVENT_READ

static NTSTATUS create_inproc_event_local( HANDLE *handle, ACCESS_MASK access,
                                           EVENT_TYPE type, BOOLEAN state )
{
    struct ntsync_event_args args = {
        .manual = (type == NotificationEvent),
        .signaled = state,
    };
    HANDLE h;
    int fd;
    NTSTATUS ret;

    h = alloc_client_handle();
    if (!h) return STATUS_NOT_IMPLEMENTED;

    fd = ioctl( inproc_device_fd, NTSYNC_IOC_CREATE_EVENT, &args );
    if (fd < 0)
    {
        free_client_handle( h );
        return errno_to_status( errno );
    }

    ret = cache_client_inproc_sync( h, fd, INPROC_SYNC_EVENT, access );
    if (ret)
    {
        close( fd );
        free_client_handle( h );
        return ret;
    }

    /* NSPA Phase 4.6.D: register the ntsync fd with the wineserver so
     * server-side async I/O completion can signal this event via direct
     * ioctl when the handle is passed to NtFsControlFile / NtRead /
     * NtWrite / etc. (the server_async chokepoint).  Without this, those
     * paths return STATUS_INVALID_HANDLE for client-range events.
     *
     * If registration fails, undo the cache + handle alloc and fall
     * through to the legacy server-event path so we don't leave a
     * half-functional client-range event in the cache. */
    if ((ret = nspa_register_inproc_event_with_server( h, fd )))
    {
        sigset_t sigset;
        server_enter_uninterrupted_section( &fd_cache_mutex, &sigset );
        close_client_inproc_sync( h );
        server_leave_uninterrupted_section( &fd_cache_mutex, &sigset );
        TRACE( "client event registration failed (%#x); falling back to server\n", ret );
        return STATUS_NOT_IMPLEMENTED;
    }

    *handle = h;
    TRACE( "client event handle %p (fd %d)\n", h, fd );
    return STATUS_SUCCESS;
}

static NTSTATUS create_inproc_semaphore_local( HANDLE *handle, ACCESS_MASK access,
                                               LONG initial, LONG max )
{
    struct ntsync_sem_args args = {
        .count = initial,
        .max = max,
    };
    HANDLE h;
    int fd;
    NTSTATUS ret;

    h = alloc_client_handle();
    if (!h) return STATUS_NOT_IMPLEMENTED;

    fd = ioctl( inproc_device_fd, NTSYNC_IOC_CREATE_SEM, &args );
    if (fd < 0)
    {
        free_client_handle( h );
        return errno_to_status( errno );
    }

    ret = cache_client_inproc_sync( h, fd, INPROC_SYNC_SEMAPHORE, access );
    if (ret)
    {
        close( fd );
        free_client_handle( h );
        return ret;
    }

    *handle = h;
    TRACE( "client semaphore handle %p (fd %d)\n", h, fd );
    return STATUS_SUCCESS;
}

static NTSTATUS create_inproc_mutex_local( HANDLE *handle, ACCESS_MASK access,
                                           BOOLEAN owned )
{
    struct ntsync_mutex_args args = {
        .owner = owned ? GetCurrentThreadId() : 0,
        .count = owned ? 1 : 0,
    };
    struct client_mutex_entry *mentry;
    HANDLE h;
    int fd;
    NTSTATUS ret;
    sigset_t sigset;

    h = alloc_client_handle();
    if (!h) return STATUS_NOT_IMPLEMENTED;

    fd = ioctl( inproc_device_fd, NTSYNC_IOC_CREATE_MUTEX, &args );
    if (fd < 0)
    {
        free_client_handle( h );
        return errno_to_status( errno );
    }

    ret = cache_client_inproc_sync( h, fd, INPROC_SYNC_MUTEX, access );
    if (ret)
    {
        close( fd );
        free_client_handle( h );
        return ret;
    }

    mentry = malloc( sizeof(*mentry) );
    if (mentry)
    {
        mentry->fd = fd;
        mentry->handle = h;
        server_enter_uninterrupted_section( &fd_cache_mutex, &sigset );
        list_add_tail( &client_mutex_list, &mentry->entry );
        server_leave_uninterrupted_section( &fd_cache_mutex, &sigset );
    }

    *handle = h;
    TRACE( "client mutex handle %p (fd %d)\n", h, fd );
    return STATUS_SUCCESS;
}

#endif /* NTSYNC_IOC_EVENT_READ */

/*
 * NSPA Phase 4.6.A: client-side wrappers that push the (handle, fd) pair to
 * the wineserver via the protocol RPCs added in this phase.  Wired into
 * create_inproc_event_local + close_client_inproc_sync in Phase D.
 *
 * The fd is sent via SCM_RIGHTS using wine_server_send_fd, then the server
 * picks it up with thread_get_inflight_fd matching the slot we pass in
 * req->fd.  Same pattern used by alloc_file_handle (server.c:1395).
 */
NTSTATUS nspa_register_inproc_event_with_server( HANDLE handle, int fd )
{
    NTSTATUS ret;

    if (!handle || fd < 0) return STATUS_INVALID_PARAMETER;

    wine_server_send_fd( fd );

    SERVER_START_REQ( nspa_register_inproc_event )
    {
        req->handle = wine_server_obj_handle( handle );
        req->fd     = fd;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}

void nspa_unregister_inproc_event_with_server( HANDLE handle )
{
    if (!handle) return;

    SERVER_START_REQ( nspa_unregister_inproc_event )
    {
        req->handle = wine_server_obj_handle( handle );
        wine_server_call( req );
    }
    SERVER_END_REQ;
}

static NTSTATUS inproc_release_semaphore( HANDLE handle, ULONG count, ULONG *prev_count )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_SEMAPHORE, SEMAPHORE_MODIFY_STATE, &stack, &sync ))) return ret;
    ret = linux_release_semaphore_obj( sync->fd, count, prev_count );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_query_semaphore( HANDLE handle, SEMAPHORE_BASIC_INFORMATION *info )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_SEMAPHORE, SEMAPHORE_QUERY_STATE, &stack, &sync ))) return ret;
    ret = linux_query_semaphore_obj( sync->fd, info );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_set_event( HANDLE handle, LONG *prev_state )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_EVENT, EVENT_MODIFY_STATE, &stack, &sync ))) return ret;
    ret = linux_set_event_obj( sync->fd, prev_state );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_reset_event( HANDLE handle, LONG *prev_state )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_EVENT, EVENT_MODIFY_STATE, &stack, &sync ))) return ret;
    ret = linux_reset_event_obj( sync->fd, prev_state );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_pulse_event( HANDLE handle, LONG *prev_state )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_EVENT, EVENT_MODIFY_STATE, &stack, &sync ))) return ret;
    ret = linux_pulse_event_obj( sync->fd, prev_state );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_query_event( HANDLE handle, EVENT_BASIC_INFORMATION *info )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_EVENT, EVENT_QUERY_STATE, &stack, &sync ))) return ret;
    ret = linux_query_event_obj( sync->fd, info );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_release_mutex( HANDLE handle, LONG *prev_count )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_MUTEX, 0, &stack, &sync ))) return ret;
    ret = linux_release_mutex_obj( sync->fd, prev_count );
    release_inproc_sync( sync );
    return ret;
}

static NTSTATUS inproc_query_mutex( HANDLE handle, MUTANT_BASIC_INFORMATION *info )
{
    struct inproc_sync stack, *sync;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( handle, INPROC_SYNC_MUTEX, MUTANT_QUERY_STATE, &stack, &sync ))) return ret;
    ret = linux_query_mutex_obj( sync->fd, info );
    release_inproc_sync( sync );
    return ret;
}

static int get_inproc_alert_fd(void)
{
    struct thread_data *data = get_thread_data();
    obj_handle_t token;
    sigset_t sigset;
    int fd;

    if ((fd = data->alert_fd) < 0)
    {
        server_enter_uninterrupted_section( &fd_cache_mutex, &sigset );

        SERVER_START_REQ( get_inproc_alert_fd )
        {
            if (!server_call_unlocked( req ))
            {
                data->alert_fd = fd = wine_server_receive_fd( &token );
                assert( token == reply->handle );
            }
        }
        SERVER_END_REQ;

        server_leave_uninterrupted_section( &fd_cache_mutex, &sigset );
    }

    return fd;
}

/* NSPA Phase 3: resolve an event handle to its ntsync fd.
 * Returns the fd (caller must NOT close it) or -1 on failure.
 * Must be called from a safe context (not CQ drain). */
int ntdll_resolve_event_sync_fd( HANDLE event )
{
    struct inproc_sync stack, *sync = &stack;

    if (inproc_device_fd < 0 || !event) return -1;
    if (get_inproc_sync( event, INPROC_SYNC_EVENT, EVENT_MODIFY_STATE, &stack, &sync )) return -1;
    {
        int fd = sync->fd;
        release_inproc_sync( sync );
        return fd;
    }
}

/* NSPA Phase 3: signal an event via direct ntsync ioctl.
 * Safe from any context (CQ drain, ntsync wait, signal handler).
 * Bypasses NtSetEvent and Wine syscall dispatch entirely.
 * Used by overlapped socket CQE completion to signal ov.hEvent. */
void ntdll_signal_event_direct( HANDLE event )
{
    struct inproc_sync stack, *sync = &stack;

    if (inproc_device_fd < 0) return;
    if (get_inproc_sync( event, INPROC_SYNC_EVENT, EVENT_MODIFY_STATE, &stack, &sync )) return;
    linux_set_event_obj( sync->fd, NULL );
    release_inproc_sync( sync );
}

static BOOL nspa_get_current_rt_params( unsigned int *policy, unsigned int *prio )
{
#if defined(HAVE_SCHED_H) && defined(SCHED_FIFO) && defined(SCHED_RR)
    struct ntdll_thread_data *data = ntdll_get_thread_data();
    struct sched_param param;
    int cached_policy = data->nspa_rt_cached_policy;
    int cached_prio = data->nspa_rt_cached_prio;

    if ((cached_policy == SCHED_FIFO || cached_policy == SCHED_RR) && cached_prio > 0)
    {
        *policy = cached_policy;
        *prio = cached_prio;
        return TRUE;
    }

    cached_policy = sched_getscheduler( 0 );
    if (cached_policy != SCHED_FIFO && cached_policy != SCHED_RR) return FALSE;
    if (sched_getparam( 0, &param ) < 0 || param.sched_priority <= 0) return FALSE;

    data->nspa_rt_cached_policy = cached_policy;
    data->nspa_rt_cached_prio = param.sched_priority;
    *policy = cached_policy;
    *prio = param.sched_priority;
    return TRUE;
#else
    return FALSE;
#endif
}

NTSTATUS CDECL wine_server_signal_internal_sync( HANDLE handle )
{
    struct wine_server_signal_internal_sync_params params = { handle };

    return unixcall_wine_server_signal_internal_sync( &params );
}

NTSTATUS unixcall_wine_server_signal_internal_sync( void *args )
{
    const struct wine_server_signal_internal_sync_params *params = args;
    struct inproc_sync stack, *sync = &stack;
    unsigned int policy, prio;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;
    if ((ret = get_inproc_sync( params->handle, INPROC_SYNC_UNKNOWN, EVENT_MODIFY_STATE, &stack, &sync )))
        return ret;

    switch (sync->type)
    {
    case INPROC_SYNC_EVENT:
    case INPROC_SYNC_INTERNAL:
        if (nspa_get_current_rt_params( &policy, &prio ))
        {
            ret = linux_set_event_obj_pi( sync->fd, policy, prio );
            if (ret == STATUS_NOT_IMPLEMENTED || ret == STATUS_INVALID_DEVICE_REQUEST || ret == STATUS_INVALID_PARAMETER)
                ret = linux_set_event_obj( sync->fd, NULL );
        }
        else ret = linux_set_event_obj( sync->fd, NULL );
        break;
    default:
        ret = STATUS_OBJECT_TYPE_MISMATCH;
        break;
    }

    release_inproc_sync( sync );
    return ret;
}

#ifdef _WIN64
NTSTATUS wow64_wine_server_signal_internal_sync( void *args )
{
    struct
    {
        ULONG handle;
    } const *params32 = args;
    struct wine_server_signal_internal_sync_params params = { ULongToHandle( params32->handle ) };

    return unixcall_wine_server_signal_internal_sync( &params );
}
#endif

static NTSTATUS inproc_wait( DWORD count, const HANDLE *handles, WAIT_TYPE type,
                             BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    struct inproc_sync *syncs[64], stack[ARRAY_SIZE(syncs)];
    int objs[ARRAY_SIZE(syncs)], alert_fd = 0, uring_fd;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;

    assert( count <= ARRAY_SIZE(syncs) );
    objs[0] = -1;  /* make gcc happy, otherwise it thinks objs is not initialized */
    for (int i = 0; i < count; ++i)
    {
        if ((ret = get_inproc_sync( handles[i], INPROC_SYNC_UNKNOWN, SYNCHRONIZE, &stack[i], &syncs[i] )))
        {
            while (i--) release_inproc_sync( syncs[i] );
            return ret;
        }
        objs[i] = syncs[i]->fd;
    }

    if (alertable) alert_fd = get_inproc_alert_fd();
    uring_fd = ntdll_io_uring_get_eventfd();

    /* Retry loop: if ntsync wakes because the io_uring eventfd fired,
     * drain CQEs (which may signal wait objects) and re-enter the wait.
     * The retry is bounded — CQE count is finite per drain cycle.
     * Note: for relative timeouts, each retry recomputes now+offset in
     * linux_wait_objs. The drift is negligible (microseconds per retry). */
    do {
        ret = linux_wait_objs( inproc_device_fd, count, objs, type,
                               alert_fd, uring_fd, timeout );
        if (ret == STATUS_URING_COMPLETION)
            ntdll_io_uring_process_completions();
    } while (ret == STATUS_URING_COMPLETION);

    while (count--) release_inproc_sync( syncs[count] );
    return ret;
}

static NTSTATUS inproc_signal_and_wait( HANDLE signal, HANDLE wait,
                                        BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    struct inproc_sync stack_signal, stack_wait, *signal_sync = &stack_signal, *wait_sync = &stack_wait;
    int alert_fd = 0;
    NTSTATUS ret;

    if (inproc_device_fd < 0) return STATUS_NOT_IMPLEMENTED;

    if ((ret = get_inproc_sync( signal, INPROC_SYNC_UNKNOWN, 0, &stack_signal, &signal_sync ))) return ret;
    if ((ret = check_signal_access( signal_sync ))) goto done;

    if ((ret = get_inproc_sync( wait, INPROC_SYNC_UNKNOWN, SYNCHRONIZE, &stack_wait, &wait_sync ))) goto done;

    switch (signal_sync->type)
    {
    case INPROC_SYNC_EVENT:     ret = linux_set_event_obj( signal_sync->fd, NULL ); break;
    case INPROC_SYNC_MUTEX:     ret = linux_release_mutex_obj( signal_sync->fd, NULL ); break;
    case INPROC_SYNC_SEMAPHORE: ret = linux_release_semaphore_obj( signal_sync->fd, 1, NULL ); break;
    default: assert( 0 ); break;
    }

    if (!ret)
    {
        int uring_fd = ntdll_io_uring_get_eventfd();

        if (alertable) alert_fd = get_inproc_alert_fd();
        do {
            ret = linux_wait_objs( inproc_device_fd, 1, &wait_sync->fd, WaitAny,
                                   alert_fd, uring_fd, timeout );
            if (ret == STATUS_URING_COMPLETION)
            {
                ntdll_io_uring_process_completions();
                ntdll_io_uring_flush_deferred();
            }
        } while (ret == STATUS_URING_COMPLETION);
    }

    release_inproc_sync( wait_sync );
done:
    release_inproc_sync( signal_sync );
    return ret;
}


/******************************************************************************
 *              NtCreateSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSemaphore( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                   LONG initial, LONG max )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, initial %d, max %d\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", initial, max );

    *handle = 0;
    if (max <= 0 || initial < 0 || initial > max) return STATUS_INVALID_PARAMETER;

#ifdef NTSYNC_IOC_EVENT_READ
    if (inproc_device_fd >= 0 && allow_client_sync_creation( INPROC_SYNC_SEMAPHORE, attr ))
    {
        ret = create_inproc_semaphore_local( handle, access, initial, max );
        if (ret != STATUS_NOT_IMPLEMENTED) return ret;
    }
#endif

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_semaphore )
    {
        req->access  = access;
        req->initial = initial;
        req->max     = max;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/******************************************************************************
 *              NtOpenSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenSemaphore( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_semaphore )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtQuerySemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySemaphore( HANDLE handle, SEMAPHORE_INFORMATION_CLASS class,
                                  void *info, ULONG len, ULONG *ret_len )
{
    unsigned int ret;
    SEMAPHORE_BASIC_INFORMATION *out = info;

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != SemaphoreBasicInformation)
    {
        FIXME("(%p,%d,%u) Unknown class\n", handle, class, len);
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(SEMAPHORE_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

    if ((ret = inproc_query_semaphore( handle, out )) != STATUS_NOT_IMPLEMENTED)
    {
        if (!ret && ret_len) *ret_len = sizeof(SEMAPHORE_BASIC_INFORMATION);
        return ret;
    }

    SERVER_START_REQ( query_semaphore )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->CurrentCount = reply->current;
            out->MaximumCount = reply->max;
            if (ret_len) *ret_len = sizeof(SEMAPHORE_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtReleaseSemaphore (NTDLL.@)
 */
NTSTATUS WINAPI NtReleaseSemaphore( HANDLE handle, ULONG count, ULONG *previous )
{
    unsigned int ret;

    TRACE( "handle %p, count %u, prev_count %p\n", handle, count, previous );

    if ((ret = inproc_release_semaphore( handle, count, previous )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( release_semaphore )
    {
        req->handle = wine_server_obj_handle( handle );
        req->count  = count;
        if (!(ret = wine_server_call( req )))
        {
            if (previous) *previous = reply->prev_count;
        }
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *              NtCreateEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                               EVENT_TYPE type, BOOLEAN state )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, type %u, state %u\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", type, state );

    *handle = 0;
    if (type != NotificationEvent && type != SynchronizationEvent) return STATUS_INVALID_PARAMETER;

#ifdef NTSYNC_IOC_EVENT_READ
    if (inproc_device_fd >= 0 && allow_client_sync_creation( INPROC_SYNC_EVENT, attr ))
    {
        ret = create_inproc_event_local( handle, access, type, state );
        if (ret != STATUS_NOT_IMPLEMENTED) return ret;
    }
#endif

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_event )
    {
        req->access = access;
        req->manual_reset = (type == NotificationEvent);
        req->initial_state = state;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/******************************************************************************
 *              NtOpenEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_event )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtSetEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtSetEvent( HANDLE handle, LONG *prev_state )
{
    unsigned int ret;

    TRACE( "handle %p, prev_state %p\n", handle, prev_state );

    if ((ret = inproc_set_event( handle, prev_state )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        req->op     = SET_EVENT;
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtSetEventBoostPriority (NTDLL.@)
 */
NTSTATUS WINAPI NtSetEventBoostPriority( HANDLE handle )
{
    return NtSetEvent( handle, NULL );
}


/******************************************************************************
 *              NtResetEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtResetEvent( HANDLE handle, LONG *prev_state )
{
    unsigned int ret;

    TRACE( "handle %p, prev_state %p\n", handle, prev_state );

    if ((ret = inproc_reset_event( handle, prev_state )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        req->op     = RESET_EVENT;
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtClearEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtClearEvent( HANDLE handle )
{
    /* FIXME: same as NtResetEvent ??? */
    return NtResetEvent( handle, NULL );
}


/******************************************************************************
 *              NtPulseEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtPulseEvent( HANDLE handle, LONG *prev_state )
{
    unsigned int ret;

    TRACE( "handle %p, prev_state %p\n", handle, prev_state );

    if ((ret = inproc_pulse_event( handle, prev_state )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( event_op )
    {
        req->handle = wine_server_obj_handle( handle );
        req->op     = PULSE_EVENT;
        ret = wine_server_call( req );
        if (!ret && prev_state) *prev_state = reply->state;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtQueryEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryEvent( HANDLE handle, EVENT_INFORMATION_CLASS class,
                              void *info, ULONG len, ULONG *ret_len )
{
    unsigned int ret;
    EVENT_BASIC_INFORMATION *out = info;

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != EventBasicInformation)
    {
        FIXME("(%p, %d, %d) Unknown class\n", handle, class, len);
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(EVENT_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

    if ((ret = inproc_query_event( handle, out )) != STATUS_NOT_IMPLEMENTED)
    {
        if (!ret && ret_len) *ret_len = sizeof(EVENT_BASIC_INFORMATION);
        return ret;
    }

    SERVER_START_REQ( query_event )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->EventType  = reply->manual_reset ? NotificationEvent : SynchronizationEvent;
            out->EventState = reply->state;
            if (ret_len) *ret_len = sizeof(EVENT_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *              NtCreateMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                BOOLEAN owned )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, owned %u\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", owned );

    *handle = 0;

#ifdef NTSYNC_IOC_EVENT_READ
    if (inproc_device_fd >= 0 && allow_client_sync_creation( INPROC_SYNC_MUTEX, attr ))
    {
        ret = create_inproc_mutex_local( handle, access, owned );
        if (ret != STATUS_NOT_IMPLEMENTED) return ret;
    }
#endif

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_mutex )
    {
        req->access  = access;
        req->owned   = owned;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/**************************************************************************
 *              NtOpenMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenMutant( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_mutex )
    {
        req->access  = access;
        req->attributes = attr->Attributes;
        req->rootdir = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *              NtReleaseMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtReleaseMutant( HANDLE handle, LONG *prev_count )
{
    unsigned int ret;

    TRACE( "handle %p, prev_count %p\n", handle, prev_count );

    if ((ret = inproc_release_mutex( handle, prev_count )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    SERVER_START_REQ( release_mutex )
    {
        req->handle = wine_server_obj_handle( handle );
        ret = wine_server_call( req );
        if (prev_count) *prev_count = 1 - reply->prev_count;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************
 *              NtQueryMutant (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryMutant( HANDLE handle, MUTANT_INFORMATION_CLASS class,
                               void *info, ULONG len, ULONG *ret_len )
{
    unsigned int ret;
    MUTANT_BASIC_INFORMATION *out = info;

    TRACE("(%p, %u, %p, %u, %p)\n", handle, class, info, len, ret_len);

    if (class != MutantBasicInformation)
    {
        FIXME( "(%p, %d, %d) Unknown class\n", handle, class, len );
        return STATUS_INVALID_INFO_CLASS;
    }

    if (len != sizeof(MUTANT_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

    if ((ret = inproc_query_mutex( handle, out )) != STATUS_NOT_IMPLEMENTED)
    {
        if (!ret && ret_len) *ret_len = sizeof(MUTANT_BASIC_INFORMATION);
        return ret;
    }

    SERVER_START_REQ( query_mutex )
    {
        req->handle = wine_server_obj_handle( handle );
        if (!(ret = wine_server_call( req )))
        {
            out->CurrentCount   = 1 - reply->count;
            out->OwnedByCaller  = reply->owned;
            out->AbandonedState = reply->abandoned;
            if (ret_len) *ret_len = sizeof(MUTANT_BASIC_INFORMATION);
        }
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtCreateJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateJobObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    *handle = 0;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_job )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**************************************************************************
 *		NtOpenJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenJobObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_job )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtTerminateJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtTerminateJobObject( HANDLE handle, NTSTATUS status )
{
    unsigned int ret;

    TRACE( "(%p, %d)\n", handle, status );

    SERVER_START_REQ( terminate_job )
    {
        req->handle = wine_server_obj_handle( handle );
        req->status = status;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;

    return ret;
}


/**************************************************************************
 *		NtQueryInformationJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class, void *info,
                                             ULONG len, ULONG *ret_len )
{
    unsigned int ret;

    TRACE( "semi-stub: %p %u %p %u %p\n", handle, class, info, len, ret_len );

    if (class >= MaxJobObjectInfoClass) return STATUS_INVALID_PARAMETER;

    switch (class)
    {
    case JobObjectBasicAccountingInformation:
    {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION *accounting = info;

        if (len < sizeof(*accounting)) return STATUS_INFO_LENGTH_MISMATCH;
        SERVER_START_REQ(get_job_info)
        {
            req->handle = wine_server_obj_handle( handle );
            if (!(ret = wine_server_call( req )))
            {
                memset( accounting, 0, sizeof(*accounting) );
                accounting->TotalProcesses = reply->total_processes;
                accounting->ActiveProcesses = reply->active_processes;
            }
        }
        SERVER_END_REQ;
        if (ret_len) *ret_len = sizeof(*accounting);
        return ret;
    }
    case JobObjectBasicProcessIdList:
    {
        JOBOBJECT_BASIC_PROCESS_ID_LIST *process = info;
        DWORD count, i;

        if (len < sizeof(*process)) return STATUS_INFO_LENGTH_MISMATCH;

        count  = len - offsetof( JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList );
        count /= sizeof(process->ProcessIdList[0]);

        SERVER_START_REQ( get_job_info )
        {
            req->handle = wine_server_user_handle(handle);
            wine_server_set_reply(req, process->ProcessIdList, count * sizeof(process_id_t));
            if (!(ret = wine_server_call(req)))
            {
                process->NumberOfAssignedProcesses = reply->active_processes;
                process->NumberOfProcessIdsInList = min(count, reply->active_processes);
            }
        }
        SERVER_END_REQ;

        if (ret != STATUS_SUCCESS) return ret;

        if (sizeof(process_id_t) < sizeof(process->ProcessIdList[0]))
        {
            /* start from the end to not overwrite */
            for (i = process->NumberOfProcessIdsInList; i--;)
            {
                ULONG_PTR id = ((process_id_t *)process->ProcessIdList)[i];
                process->ProcessIdList[i] = id;
            }
        }

        if (ret_len)
            *ret_len = offsetof( JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList[process->NumberOfProcessIdsInList] );
        return count < process->NumberOfAssignedProcesses ? STATUS_MORE_ENTRIES : STATUS_SUCCESS;
    }
    case JobObjectExtendedLimitInformation:
    {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION *extended_limit = info;

        if (len < sizeof(*extended_limit)) return STATUS_INFO_LENGTH_MISMATCH;
        memset( extended_limit, 0, sizeof(*extended_limit) );
        if (ret_len) *ret_len = sizeof(*extended_limit);
        return STATUS_SUCCESS;
    }
    case JobObjectBasicLimitInformation:
    {
        JOBOBJECT_BASIC_LIMIT_INFORMATION *basic_limit = info;

        if (len < sizeof(*basic_limit)) return STATUS_INFO_LENGTH_MISMATCH;
        memset( basic_limit, 0, sizeof(*basic_limit) );
        if (ret_len) *ret_len = sizeof(*basic_limit);
        return STATUS_SUCCESS;
    }
    default:
        return STATUS_NOT_IMPLEMENTED;
    }
}


/**************************************************************************
 *		NtSetInformationJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationJobObject( HANDLE handle, JOBOBJECTINFOCLASS class, void *info, ULONG len )
{
    unsigned int status = STATUS_NOT_IMPLEMENTED;
    JOBOBJECT_BASIC_LIMIT_INFORMATION *basic_limit;
    ULONG info_size = sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION);
    DWORD limit_flags = JOB_OBJECT_BASIC_LIMIT_VALID_FLAGS;

    TRACE( "(%p, %u, %p, %u)\n", handle, class, info, len );

    if (class >= MaxJobObjectInfoClass) return STATUS_INVALID_PARAMETER;

    switch (class)
    {

    case JobObjectExtendedLimitInformation:
        info_size = sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
        limit_flags = JOB_OBJECT_EXTENDED_LIMIT_VALID_FLAGS;
        /* fall through */
    case JobObjectBasicLimitInformation:
        if (len != info_size) return STATUS_INVALID_PARAMETER;
        basic_limit = info;
        if (basic_limit->LimitFlags & ~limit_flags) return STATUS_INVALID_PARAMETER;
        SERVER_START_REQ( set_job_limits )
        {
            req->handle = wine_server_obj_handle( handle );
            req->limit_flags = basic_limit->LimitFlags;
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
        break;
    case JobObjectAssociateCompletionPortInformation:
        if (len != sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT)) return STATUS_INVALID_PARAMETER;
        SERVER_START_REQ( set_job_completion_port )
        {
            JOBOBJECT_ASSOCIATE_COMPLETION_PORT *port_info = info;
            req->job = wine_server_obj_handle( handle );
            req->port = wine_server_obj_handle( port_info->CompletionPort );
            req->key = wine_server_client_ptr( port_info->CompletionKey );
            status = wine_server_call( req );
        }
        SERVER_END_REQ;
        break;
    case JobObjectBasicUIRestrictions:
        status = STATUS_SUCCESS;
        /* fall through */
    default:
        FIXME( "stub: %p %u %p %u\n", handle, class, info, len );
    }
    return status;
}


/**************************************************************************
 *		NtIsProcessInJob (NTDLL.@)
 */
NTSTATUS WINAPI NtIsProcessInJob( HANDLE process, HANDLE job )
{
    unsigned int status;

    TRACE( "(%p %p)\n", job, process );

    SERVER_START_REQ( process_in_job )
    {
        req->job     = wine_server_obj_handle( job );
        req->process = wine_server_obj_handle( process );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}


/**************************************************************************
 *		NtAssignProcessToJobObject (NTDLL.@)
 */
NTSTATUS WINAPI NtAssignProcessToJobObject( HANDLE job, HANDLE process )
{
    unsigned int status;

    TRACE( "(%p %p)\n", job, process );

    SERVER_START_REQ( assign_job )
    {
        req->job     = wine_server_obj_handle( job );
        req->process = wine_server_obj_handle( process );
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}


/**********************************************************************
 *           NtCreateDebugObject  (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateDebugObject( HANDLE *handle, ACCESS_MASK access,
                                     OBJECT_ATTRIBUTES *attr, ULONG flags )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    *handle = 0;
    if (flags & ~DEBUG_KILL_ON_CLOSE) return STATUS_INVALID_PARAMETER;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_debug_obj )
    {
        req->access = access;
        req->flags  = flags;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**********************************************************************
 *           NtSetInformationDebugObject  (NTDLL.@)
 */
NTSTATUS WINAPI NtSetInformationDebugObject( HANDLE handle, DEBUGOBJECTINFOCLASS class,
                                             void *info, ULONG len, ULONG *ret_len )
{
    unsigned int ret;
    ULONG flags;

    if (class != DebugObjectKillProcessOnExitInformation) return STATUS_INVALID_PARAMETER;
    if (len != sizeof(ULONG))
    {
        if (ret_len) *ret_len = sizeof(ULONG);
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    flags = *(ULONG *)info;
    if (flags & ~DEBUG_KILL_ON_CLOSE) return STATUS_INVALID_PARAMETER;

    SERVER_START_REQ( set_debug_obj_info )
    {
        req->debug = wine_server_obj_handle( handle );
        req->flags = flags;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    if (!ret && ret_len) *ret_len = 0;
    return ret;
}


/* convert the server event data to an NT state change; helper for NtWaitForDebugEvent */
static NTSTATUS event_data_to_state_change( const union debug_event_data *data, DBGUI_WAIT_STATE_CHANGE *state )
{
    int i;

    switch (data->code)
    {
    case DbgIdle:
    case DbgReplyPending:
        return STATUS_PENDING;
    case DbgCreateThreadStateChange:
    {
        DBGUI_CREATE_THREAD *info = &state->StateInfo.CreateThread;
        info->HandleToThread         = wine_server_ptr_handle( data->create_thread.handle );
        info->NewThread.StartAddress = wine_server_get_ptr( data->create_thread.start );
        return STATUS_SUCCESS;
    }
    case DbgCreateProcessStateChange:
    {
        DBGUI_CREATE_PROCESS *info = &state->StateInfo.CreateProcessInfo;
        info->HandleToProcess                       = wine_server_ptr_handle( data->create_process.process );
        info->HandleToThread                        = wine_server_ptr_handle( data->create_process.thread );
        info->NewProcess.FileHandle                 = wine_server_ptr_handle( data->create_process.file );
        info->NewProcess.BaseOfImage                = wine_server_get_ptr( data->create_process.base );
        info->NewProcess.DebugInfoFileOffset        = data->create_process.dbg_offset;
        info->NewProcess.DebugInfoSize              = data->create_process.dbg_size;
        info->NewProcess.InitialThread.StartAddress = wine_server_get_ptr( data->create_process.start );
        return STATUS_SUCCESS;
    }
    case DbgExitThreadStateChange:
        state->StateInfo.ExitThread.ExitStatus = data->exit.exit_code;
        return STATUS_SUCCESS;
    case DbgExitProcessStateChange:
        state->StateInfo.ExitProcess.ExitStatus = data->exit.exit_code;
        return STATUS_SUCCESS;
    case DbgExceptionStateChange:
    case DbgBreakpointStateChange:
    case DbgSingleStepStateChange:
    {
        DBGKM_EXCEPTION *info = &state->StateInfo.Exception;
        info->FirstChance = data->exception.first;
        info->ExceptionRecord.ExceptionCode    = data->exception.exc_code;
        info->ExceptionRecord.ExceptionFlags   = data->exception.flags;
        info->ExceptionRecord.ExceptionRecord  = wine_server_get_ptr( data->exception.record );
        info->ExceptionRecord.ExceptionAddress = wine_server_get_ptr( data->exception.address );
        info->ExceptionRecord.NumberParameters = data->exception.nb_params;
        for (i = 0; i < data->exception.nb_params; i++)
            info->ExceptionRecord.ExceptionInformation[i] = data->exception.params[i];
        return STATUS_SUCCESS;
    }
    case DbgLoadDllStateChange:
    {
        DBGKM_LOAD_DLL *info = &state->StateInfo.LoadDll;
        info->FileHandle          = wine_server_ptr_handle( data->load_dll.handle );
        info->BaseOfDll           = wine_server_get_ptr( data->load_dll.base );
        info->DebugInfoFileOffset = data->load_dll.dbg_offset;
        info->DebugInfoSize       = data->load_dll.dbg_size;
        info->NamePointer         = wine_server_get_ptr( data->load_dll.name );
        if ((DWORD_PTR)data->load_dll.base != data->load_dll.base)
            return STATUS_PARTIAL_COPY;
        return STATUS_SUCCESS;
    }
    case DbgUnloadDllStateChange:
        state->StateInfo.UnloadDll.BaseAddress = wine_server_get_ptr( data->unload_dll.base );
        if ((DWORD_PTR)data->unload_dll.base != data->unload_dll.base)
            return STATUS_PARTIAL_COPY;
        return STATUS_SUCCESS;
    }
    return STATUS_INTERNAL_ERROR;
}

#ifndef _WIN64
/* helper to NtWaitForDebugEvent; retrieve machine from PE image */
static NTSTATUS get_image_machine( HANDLE handle, USHORT *machine )
{
    IMAGE_DOS_HEADER dos_hdr;
    IMAGE_NT_HEADERS nt_hdr;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER offset;
    FILE_POSITION_INFORMATION pos_info;
    NTSTATUS status;

    offset.QuadPart = 0;
    status = NtReadFile( handle, NULL, NULL, NULL,
                         &iosb, &dos_hdr, sizeof(dos_hdr), &offset, NULL );
    if (!status)
    {
        offset.QuadPart = dos_hdr.e_lfanew;
        status = NtReadFile( handle, NULL, NULL, NULL, &iosb,
                             &nt_hdr, FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader), &offset, NULL );
        if (!status)
            *machine = nt_hdr.FileHeader.Machine;
        /* Reset file pos at beginning of file */
        pos_info.CurrentByteOffset.QuadPart = 0;
        NtSetInformationFile( handle, &iosb, &pos_info, sizeof(pos_info), FilePositionInformation );
    }
    return status;
}
#endif

/**********************************************************************
 *           NtWaitForDebugEvent  (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForDebugEvent( HANDLE handle, BOOLEAN alertable, LARGE_INTEGER *timeout,
                                     DBGUI_WAIT_STATE_CHANGE *state )
{
    union debug_event_data data;
    unsigned int ret;
    BOOL wait = TRUE;

    for (;;)
    {
        SERVER_START_REQ( wait_debug_event )
        {
            req->debug = wine_server_obj_handle( handle );
            wine_server_set_reply( req, &data, sizeof(data) );
            ret = wine_server_call( req );
            if (!ret)
            {
                ret = event_data_to_state_change( &data, state );
                state->NewState = data.code;
                state->AppClientId.UniqueProcess = ULongToHandle( reply->pid );
                state->AppClientId.UniqueThread  = ULongToHandle( reply->tid );
            }
        }
        SERVER_END_REQ;

#ifndef _WIN64
        /* don't pass 64bit load events to 32bit callers */
        if (!ret && state->NewState == DbgLoadDllStateChange)
        {
            USHORT machine;
            if (!get_image_machine( state->StateInfo.LoadDll.FileHandle, &machine ) &&
                machine != current_machine)
                ret = STATUS_PARTIAL_COPY;
        }
        if (ret == STATUS_PARTIAL_COPY)
        {
            if (state->NewState == DbgLoadDllStateChange)
                NtClose( state->StateInfo.LoadDll.FileHandle );
            NtDebugContinue( handle, &state->AppClientId, DBG_CONTINUE );
            wait = TRUE;
            continue;
        }
#endif
        if (ret != STATUS_PENDING) return ret;
        if (!wait) return STATUS_TIMEOUT;
        wait = FALSE;
        ret = NtWaitForSingleObject( handle, alertable, timeout );
        if (ret != STATUS_WAIT_0) return ret;
    }
}


/**************************************************************************
 *           NtCreateDirectoryObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateDirectoryObject( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    *handle = 0;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_directory )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**************************************************************************
 *           NtOpenDirectoryObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenDirectoryObject( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_directory )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *           NtQueryDirectoryObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryDirectoryObject( HANDLE handle, DIRECTORY_BASIC_INFORMATION *buffer,
                                        ULONG size, BOOLEAN single_entry, BOOLEAN restart,
                                        ULONG *context, ULONG *ret_size )
{
    unsigned int status, i, count, total_len, pos, used_size, used_count, strpool_head;
    ULONG index = restart ? 0 : *context;
    struct directory_entry *entries;

    if (!(entries = malloc( size ))) return STATUS_NO_MEMORY;

    SERVER_START_REQ( get_directory_entries )
    {
        req->handle = wine_server_obj_handle( handle );
        req->index = index;
        req->max_count = single_entry ? 1 : UINT_MAX;
        wine_server_set_reply( req, entries, size );
        status = wine_server_call( req );
        count = reply->count;
        total_len = reply->total_len;
    }
    SERVER_END_REQ;

    if (status && status != STATUS_MORE_ENTRIES)
    {
        free( entries );
        return status;
    }

    used_count = 0;
    used_size = sizeof(*buffer);  /* "null terminator" entry */
    for (i = pos = 0; i < count; i++)
    {
        const struct directory_entry *entry = (const struct directory_entry *)((char *)entries + pos);
        unsigned int entry_size = sizeof(*buffer) + entry->name_len + entry->type_len + 2 * sizeof(WCHAR);

        if (used_size + entry_size > size)
        {
            status = STATUS_MORE_ENTRIES;
            break;
        }
        used_count++;
        used_size += entry_size;
        pos += sizeof(*entry) + ((entry->name_len + entry->type_len + 3) & ~3);
    }

    /*
     * Avoid making strpool_head a pointer, since it can point beyond end
     * of the buffer.  Out-of-bounds pointers trigger undefined behavior
     * just by existing, even when they are never dereferenced.
     */
    strpool_head = sizeof(*buffer) * (used_count + 1);  /* after the "null terminator" entry */
    for (i = pos = 0; i < used_count; i++)
    {
        const struct directory_entry *entry = (const struct directory_entry *)((char *)entries + pos);

        buffer[i].ObjectName.Buffer = (WCHAR *)((char *)buffer + strpool_head);
        buffer[i].ObjectName.Length = entry->name_len;
        buffer[i].ObjectName.MaximumLength = entry->name_len + sizeof(WCHAR);
        memcpy( buffer[i].ObjectName.Buffer, (entry + 1), entry->name_len );
        buffer[i].ObjectName.Buffer[entry->name_len / sizeof(WCHAR)] = 0;
        strpool_head += entry->name_len + sizeof(WCHAR);

        buffer[i].ObjectTypeName.Buffer = (WCHAR *)((char *)buffer + strpool_head);
        buffer[i].ObjectTypeName.Length = entry->type_len;
        buffer[i].ObjectTypeName.MaximumLength = entry->type_len + sizeof(WCHAR);
        memcpy( buffer[i].ObjectTypeName.Buffer, (char *)(entry + 1) + entry->name_len, entry->type_len );
        buffer[i].ObjectTypeName.Buffer[entry->type_len / sizeof(WCHAR)] = 0;
        strpool_head += entry->type_len + sizeof(WCHAR);

        pos += sizeof(*entry) + ((entry->name_len + entry->type_len + 3) & ~3);
    }

    if (size >= sizeof(*buffer))
        memset( &buffer[used_count], 0, sizeof(buffer[used_count]) );

    free( entries );

    if (!count && !status)
    {
        if (ret_size) *ret_size = sizeof(*buffer);
        return STATUS_NO_MORE_ENTRIES;
    }

    if (single_entry && !used_count)
    {
        if (ret_size) *ret_size = 2 * sizeof(*buffer) + 2 * sizeof(WCHAR) + total_len;
        return STATUS_BUFFER_TOO_SMALL;
    }

    *context = index + used_count;
    if (ret_size) *ret_size = strpool_head;
    return status;
}


/**************************************************************************
 *           NtCreateSymbolicLinkObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSymbolicLinkObject( HANDLE *handle, ACCESS_MASK access,
                                            OBJECT_ATTRIBUTES *attr, UNICODE_STRING *target )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    *handle = 0;
    if (!target->MaximumLength) return STATUS_INVALID_PARAMETER;
    if (!target->Buffer) return STATUS_ACCESS_VIOLATION;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_symlink )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        wine_server_add_data( req, target->Buffer, target->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    free( objattr );
    return ret;
}


/**************************************************************************
 *           NtOpenSymbolicLinkObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenSymbolicLinkObject( HANDLE *handle, ACCESS_MASK access,
                                          const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_symlink )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *           NtQuerySymbolicLinkObject   (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySymbolicLinkObject( HANDLE handle, UNICODE_STRING *target, ULONG *length )
{
    unsigned int ret;

    if (!target) return STATUS_ACCESS_VIOLATION;

    SERVER_START_REQ( query_symlink )
    {
        req->handle = wine_server_obj_handle( handle );
        if (target->MaximumLength >= sizeof(WCHAR))
            wine_server_set_reply( req, target->Buffer, target->MaximumLength - sizeof(WCHAR) );
        if (!(ret = wine_server_call( req )))
        {
            target->Length = wine_server_reply_size(reply);
            target->Buffer[target->Length / sizeof(WCHAR)] = 0;
            if (length) *length = reply->total + sizeof(WCHAR);
        }
        else if (length && ret == STATUS_BUFFER_TOO_SMALL) *length = reply->total + sizeof(WCHAR);
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtMakePermanentObject (NTDLL.@)
 */
NTSTATUS WINAPI NtMakePermanentObject( HANDLE handle )
{
    unsigned int ret;

    TRACE("%p\n", handle);

    /* NSPA local-file: promote so the server sees something it knows. */
    handle = nspa_promote_if_local( handle );

    SERVER_START_REQ( set_object_permanence )
    {
        req->handle = wine_server_obj_handle( handle );
        req->permanent = 1;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtMakeTemporaryObject (NTDLL.@)
 */
NTSTATUS WINAPI NtMakeTemporaryObject( HANDLE handle )
{
    unsigned int ret;

    TRACE("%p\n", handle);

    /* NSPA local-file: promote so the server sees something it knows. */
    handle = nspa_promote_if_local( handle );

    SERVER_START_REQ( set_object_permanence )
    {
        req->handle = wine_server_obj_handle( handle );
        req->permanent = 0;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtCreateTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateTimer( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                               TIMER_TYPE type )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, type %u\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", type );

    *handle = 0;
    if (type != NotificationTimer && type != SynchronizationTimer) return STATUS_INVALID_PARAMETER;

    /* NSPA: try the local timer dispatcher first.  Only anonymous timers
     * eligible; STATUS_NOT_IMPLEMENTED falls through to the server path. */
    ret = nspa_local_timer_create( handle, access, attr, type );
    if (ret != STATUS_NOT_IMPLEMENTED) return ret;

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_timer )
    {
        req->access  = access;
        req->manual  = (type == NotificationTimer);
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;

}


/**************************************************************************
 *		NtOpenTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenTimer( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_timer )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/**************************************************************************
 *		NtSetTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtSetTimer( HANDLE handle, const LARGE_INTEGER *when, PTIMER_APC_ROUTINE callback,
                            void *arg, BOOLEAN resume, ULONG period, BOOLEAN *state )
{
    unsigned int ret = STATUS_SUCCESS;

    TRACE( "(%p,%p,%p,%p,%08x,0x%08x,%p)\n", handle, when, callback, arg, resume, period, state );

    /* NSPA: local dispatcher if this is a managed timer. */
    ret = nspa_local_timer_set( handle, when, callback, arg, period, state );
    if (ret != STATUS_NOT_IMPLEMENTED)
    {
        if (resume && ret == STATUS_SUCCESS) return STATUS_TIMER_RESUME_IGNORED;
        return ret;
    }

    SERVER_START_REQ( set_timer )
    {
        req->handle   = wine_server_obj_handle( handle );
        req->period   = period;
        req->expire   = when->QuadPart;
        req->callback = wine_server_client_ptr( callback );
        req->arg      = wine_server_client_ptr( arg );
        ret = wine_server_call( req );
        if (state) *state = reply->signaled;
    }
    SERVER_END_REQ;

    /* set error but can still succeed */
    if (resume && ret == STATUS_SUCCESS) return STATUS_TIMER_RESUME_IGNORED;
    return ret;
}


/**************************************************************************
 *		NtCancelTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtCancelTimer( HANDLE handle, BOOLEAN *state )
{
    unsigned int ret;

    TRACE( "handle %p, state %p\n", handle, state );

    /* NSPA: local dispatcher if this is a managed timer. */
    ret = nspa_local_timer_cancel( handle, state );
    if (ret != STATUS_NOT_IMPLEMENTED) return ret;

    SERVER_START_REQ( cancel_timer )
    {
        req->handle = wine_server_obj_handle( handle );
        ret = wine_server_call( req );
        if (state) *state = reply->signaled;
    }
    SERVER_END_REQ;
    return ret;
}


/******************************************************************************
 *		NtQueryTimer (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryTimer( HANDLE handle, TIMER_INFORMATION_CLASS class,
                              void *info, ULONG len, ULONG *ret_len )
{
    TIMER_BASIC_INFORMATION *basic_info = info;
    unsigned int ret;
    LARGE_INTEGER now;

    TRACE( "(%p,%d,%p,0x%08x,%p)\n", handle, class, info, len, ret_len );

    switch (class)
    {
    case TimerBasicInformation:
        if (len < sizeof(TIMER_BASIC_INFORMATION)) return STATUS_INFO_LENGTH_MISMATCH;

        /* NSPA: local dispatcher if this is a managed timer.  The local
         * path returns RemainingTime in the relative-negative-100ns shape
         * the caller expects; skip the server conversion dance. */
        ret = nspa_local_timer_query( handle, basic_info );
        if (ret != STATUS_NOT_IMPLEMENTED)
        {
            if (ret_len) *ret_len = sizeof(TIMER_BASIC_INFORMATION);
            return ret;
        }

        SERVER_START_REQ( get_timer_info )
        {
            req->handle = wine_server_obj_handle( handle );
            ret = wine_server_call(req);
            /* convert server time to absolute NTDLL time */
            basic_info->RemainingTime.QuadPart = reply->when;
            basic_info->TimerState = reply->signaled;
        }
        SERVER_END_REQ;

        /* convert into relative time */
        if (basic_info->RemainingTime.QuadPart > 0) NtQuerySystemTime( &now );
        else
        {
            NtQueryPerformanceCounter( &now, NULL );
            basic_info->RemainingTime.QuadPart = -basic_info->RemainingTime.QuadPart;
        }

        if (now.QuadPart > basic_info->RemainingTime.QuadPart)
            basic_info->RemainingTime.QuadPart = 0;
        else
            basic_info->RemainingTime.QuadPart -= now.QuadPart;

        if (ret_len) *ret_len = sizeof(TIMER_BASIC_INFORMATION);
        return ret;
    }

    FIXME( "Unhandled class %d\n", class );
    return STATUS_INVALID_INFO_CLASS;
}


/******************************************************************
 *		NtWaitForMultipleObjects (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForMultipleObjects( DWORD count, const HANDLE *handles, WAIT_TYPE type,
                                          BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    union select_op select_op;
    UINT i, flags = SELECT_INTERRUPTIBLE;
    unsigned int ret;

    if (!count || count > MAXIMUM_WAIT_OBJECTS) return STATUS_INVALID_PARAMETER_1;
    if (type != WaitAll && type != WaitAny) FIXME( "Unsupported wait type %u\n", type );

    if (TRACE_ON(sync))
    {
        TRACE( "type %u, alertable %u, handles {%p", type, alertable, handles[0] );
        for (i = 1; i < count; i++) TRACE( ", %p", handles[i] );
        TRACE( "}, timeout %s\n", debugstr_timeout(timeout) );
    }

    /* Reject pseudo-handles up front. These are not valid for multi-object waits. */
    for (i = 0; i < count; i++)
    {
        if (is_pseudo_handle( handles[i] )) return STATUS_INVALID_HANDLE;
    }

    if ((ret = inproc_wait( count, handles, type, alertable, timeout )) != STATUS_NOT_IMPLEMENTED)
    {
        ntdll_io_uring_flush_deferred();
        TRACE( "-> %#x\n", ret );
        return ret;
    }

    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.wait.op = type == WaitAll ? SELECT_WAIT_ALL : SELECT_WAIT;
    for (i = 0; i < count; i++) select_op.wait.handles[i] = wine_server_obj_handle( handles[i] );
    ret = server_wait( &select_op, offsetof( union select_op, wait.handles[count] ), flags, timeout );
    TRACE( "-> %#x\n", ret );
    return ret;
}


/******************************************************************
 *		NtWaitForSingleObject (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForSingleObject( HANDLE handle, BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    union select_op select_op;
    UINT flags = SELECT_INTERRUPTIBLE;
    unsigned int ret;

    TRACE( "handle %p, alertable %u, timeout %s\n", handle, alertable, debugstr_timeout(timeout) );

    if ((ret = inproc_wait( 1, &handle, WaitAny, alertable, timeout )) != STATUS_NOT_IMPLEMENTED)
    {
        /* NSPA Phase 3: flush deferred socket completions AFTER inproc_wait
         * returns — safe context, fully outside the ntsync ioctl stack. */
        ntdll_io_uring_flush_deferred();
        TRACE( "-> %#x\n", ret );
        return ret;
    }

    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.wait.op = SELECT_WAIT;
    select_op.wait.handles[0] = wine_server_obj_handle( handle );
    ret = server_wait( &select_op, offsetof( union select_op, wait.handles[1] ), flags, timeout );
    TRACE( "-> %#x\n", ret );
    return ret;
}


/******************************************************************
 *		NtSignalAndWaitForSingleObject (NTDLL.@)
 */
NTSTATUS WINAPI NtSignalAndWaitForSingleObject( HANDLE signal, HANDLE wait,
                                                BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    union select_op select_op;
    UINT flags = SELECT_INTERRUPTIBLE;
    NTSTATUS ret;

    TRACE( "signal %p, wait %p, alertable %u, timeout %s\n", signal, wait, alertable, debugstr_timeout(timeout) );

    if (!signal) return STATUS_INVALID_HANDLE;

    if ((ret = inproc_signal_and_wait( signal, wait, alertable, timeout )) != STATUS_NOT_IMPLEMENTED)
        return ret;

    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.signal_and_wait.op = SELECT_SIGNAL_AND_WAIT;
    select_op.signal_and_wait.wait = wine_server_obj_handle( wait );
    select_op.signal_and_wait.signal = wine_server_obj_handle( signal );
    return server_wait( &select_op, sizeof(select_op.signal_and_wait), flags, timeout );
}


/******************************************************************
 *		NtYieldExecution (NTDLL.@)
 */
NTSTATUS WINAPI NtYieldExecution(void)
{
#ifdef HAVE_SCHED_YIELD
#ifdef RUSAGE_THREAD
    struct rusage u1, u2;
    int ret;

    ret = getrusage( RUSAGE_THREAD, &u1 );
#endif
    sched_yield();
#ifdef RUSAGE_THREAD
    if (!ret) ret = getrusage( RUSAGE_THREAD, &u2 );
    if (!ret && u1.ru_nvcsw == u2.ru_nvcsw && u1.ru_nivcsw == u2.ru_nivcsw) return STATUS_NO_YIELD_PERFORMED;
#endif
    return STATUS_SUCCESS;
#else
    return STATUS_NO_YIELD_PERFORMED;
#endif
}


/******************************************************************
 *		NtDelayExecution (NTDLL.@)
 */
NTSTATUS WINAPI NtDelayExecution( BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    unsigned int status = STATUS_SUCCESS;

    /* if alertable, we need to query the server */
    if (alertable)
    {
        /* Since server_wait will result in an unconditional implicit yield,
           we never return STATUS_NO_YIELD_PERFORMED */
        if ((status = server_wait( NULL, 0, SELECT_INTERRUPTIBLE | SELECT_ALERTABLE, timeout )) == STATUS_TIMEOUT)
            status = STATUS_SUCCESS;
        return status;
    }

    if (!timeout || timeout->QuadPart == TIMEOUT_INFINITE)  /* sleep forever */
    {
        for (;;) select( 0, NULL, NULL, NULL, NULL );
    }
    else
    {
        LONGLONG ticks = timeout->QuadPart;
        LARGE_INTEGER now;
        timeout_t when = ticks, diff;

#if defined(HAVE_CLOCK_GETTIME) && defined(HAVE_CLOCK_NANOSLEEP)
        /* NSPA: use clock_nanosleep FIRST for sub-ms precision.
         * Relative NT timeouts (ticks < 0) are interval intent — compute the
         * deadline on CLOCK_MONOTONIC so NTP steps cannot shift or skip the
         * wake. Absolute NT filetimes (ticks > 0) are wall-clock intent —
         * keep CLOCK_REALTIME. */
        if (ticks != 0)
        {
            struct timespec ts;
            clockid_t clock_id;
            int err;

            if (ticks < 0)
            {
                clock_id = CLOCK_MONOTONIC;
                clock_gettime( CLOCK_MONOTONIC, &ts );
                ts.tv_sec += (time_t)(-ticks / TICKSPERSEC);
                ts.tv_nsec += (long)((-ticks % TICKSPERSEC) * 100);
                if (ts.tv_nsec >= 1000000000) { ts.tv_sec++; ts.tv_nsec -= 1000000000; }
            }
            else
            {
                clock_id = CLOCK_REALTIME;
                ts.tv_sec = (time_t)((ticks / TICKSPERSEC) - SECS_1601_TO_1970);
                ts.tv_nsec = (long)((ticks % TICKSPERSEC) * 100);
            }

            while ((err = clock_nanosleep( clock_id, TIMER_ABSTIME, &ts, NULL )) == EINTR);
            if (!err) return STATUS_SUCCESS;
        }
#endif

        if (when < 0)
        {
            NtQuerySystemTime( &now );
            when = now.QuadPart - when;
        }

        /* Note that we yield after establishing the desired timeout, but
           we only care about the result of the yield for zero timeouts */
        status = NtYieldExecution();
        if (!when) return status;

        for (;;)
        {
            struct timeval tv;
            NtQuerySystemTime( &now );
            diff = (when - now.QuadPart + 9) / 10;
            if (diff <= 0) break;
            tv.tv_sec  = diff / 1000000;
            tv.tv_usec = diff % 1000000;
            if (select( 0, NULL, NULL, NULL, &tv ) != -1) break;
        }
    }
    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtQueryPerformanceCounter (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryPerformanceCounter( LARGE_INTEGER *counter, LARGE_INTEGER *frequency )
{
    counter->QuadPart = monotonic_counter();
    if (frequency) frequency->QuadPart = TICKSPERSEC;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtQuerySystemTime (NTDLL.@)
 */
NTSTATUS WINAPI NtQuerySystemTime( LARGE_INTEGER *time )
{
#ifdef HAVE_CLOCK_GETTIME
    struct timespec ts;
    static clockid_t clock_id = CLOCK_MONOTONIC; /* placeholder */

    if (clock_id == CLOCK_MONOTONIC)
    {
#ifdef CLOCK_REALTIME_COARSE
        struct timespec res;

        /* Use CLOCK_REALTIME_COARSE if it has 1 ms or better resolution */
        if (!clock_getres( CLOCK_REALTIME_COARSE, &res ) && res.tv_sec == 0 && res.tv_nsec <= 1000000)
            clock_id = CLOCK_REALTIME_COARSE;
        else
#endif /* CLOCK_REALTIME_COARSE */
            clock_id = CLOCK_REALTIME;
    }

    if (!clock_gettime( clock_id, &ts ))
    {
        time->QuadPart = ticks_from_time_t( ts.tv_sec ) + (ts.tv_nsec + 50) / 100;
    }
    else
#endif /* HAVE_CLOCK_GETTIME */
    {
        struct timeval now;

        gettimeofday( &now, 0 );
        time->QuadPart = ticks_from_time_t( now.tv_sec ) + now.tv_usec * 10;
    }
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtSetSystemTime (NTDLL.@)
 */
NTSTATUS WINAPI NtSetSystemTime( const LARGE_INTEGER *new, LARGE_INTEGER *old )
{
    LARGE_INTEGER now;
    LONGLONG diff;

    NtQuerySystemTime( &now );
    if (old) *old = now;
    diff = new->QuadPart - now.QuadPart;
    if (diff > -TICKSPERSEC / 2 && diff < TICKSPERSEC / 2) return STATUS_SUCCESS;
    ERR( "not allowed: difference %d ms\n", (int)(diff / 10000) );
    return STATUS_PRIVILEGE_NOT_HELD;
}


/***********************************************************************
 *              NtQueryTimerResolution (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryTimerResolution( ULONG *min_res, ULONG *max_res, ULONG *current_res )
{
    TRACE( "(%p,%p,%p)\n", min_res, max_res, current_res );
    *max_res = *current_res = 10000; /* See NtSetTimerResolution() */
    *min_res = 156250;
    return STATUS_SUCCESS;
}


/***********************************************************************
 *              NtSetTimerResolution (NTDLL.@)
 */
NTSTATUS WINAPI NtSetTimerResolution( ULONG res, BOOLEAN set, ULONG *current_res )
{
    static BOOL has_request = FALSE;

    TRACE( "(%u,%u,%p)\n", res, set, current_res );

#ifdef __linux__
    /* NSPA: set Linux timer slack to match requested resolution.
     * PR_SET_TIMERSLACK controls the maximum additional delay the kernel
     * adds to timer expirations (select, poll, nanosleep, futex waits).
     * Default is 50us; setting to 1ns gives sub-ms timer precision.
     * This is what makes DPC timers, Sleep(1), and threadpool timers
     * actually fire at their requested time. */
    if (set)
    {
        unsigned long slack_ns = (unsigned long)res * 100;  /* 100ns units → ns */
        if (slack_ns < 1) slack_ns = 1;
        prctl( PR_SET_TIMERSLACK, slack_ns );
    }
    else
        prctl( PR_SET_TIMERSLACK, 0 );  /* reset to default */
#endif

    *current_res = res < 5000 ? 5000 : res;  /* clamp to 0.5ms minimum */

    if (!has_request && !set)
        return STATUS_TIMER_RESOLUTION_NOT_SET;
    has_request = set;

    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtSetIntervalProfile (NTDLL.@)
 */
NTSTATUS WINAPI NtSetIntervalProfile( ULONG interval, KPROFILE_SOURCE source )
{
    FIXME( "%u,%d\n", interval, source );
    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtGetTickCount (NTDLL.@)
 */
ULONG WINAPI NtGetTickCount(void)
{
    /* note: we ignore TickCountMultiplier */
    return user_shared_data->TickCount.LowPart;
}


/******************************************************************************
 *              RtlGetSystemTimePrecise (NTDLL.@)
 */
NTSTATUS system_time_precise( void *args )
{
    LONGLONG *ret = args;
    struct timeval now;
#ifdef HAVE_CLOCK_GETTIME
    struct timespec ts;

    if (!clock_gettime( CLOCK_REALTIME, &ts ))
    {
        *ret = ticks_from_time_t( ts.tv_sec ) + (ts.tv_nsec + 50) / 100;
        return STATUS_SUCCESS;
    }
#endif
    gettimeofday( &now, 0 );
    *ret = ticks_from_time_t( now.tv_sec ) + now.tv_usec * 10;
    return STATUS_SUCCESS;
}


/******************************************************************************
 *              NtCreateKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateKeyedEvent( HANDLE *handle, ACCESS_MASK access,
                                    const OBJECT_ATTRIBUTES *attr, ULONG flags )
{
    unsigned int ret;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "access %#x, name %s, flags %#x\n", access,
           attr ? debugstr_us(attr->ObjectName) : "(null)", flags );

    *handle = 0;
    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    SERVER_START_REQ( create_keyed_event )
    {
        req->access = access;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/******************************************************************************
 *              NtOpenKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenKeyedEvent( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    TRACE( "access %#x, name %s\n", access, attr ? debugstr_us(attr->ObjectName) : "(null)" );

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_keyed_event )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}

/******************************************************************************
 *              NtWaitForKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForKeyedEvent( HANDLE handle, const void *key,
                                     BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    union select_op select_op;
    UINT flags = SELECT_INTERRUPTIBLE;

    TRACE( "handle %p, key %p, alertable %u, timeout %s\n", handle, key, alertable, debugstr_timeout(timeout) );

    if (!handle) handle = keyed_event;
    if ((ULONG_PTR)key & 1) return STATUS_INVALID_PARAMETER_1;
    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.keyed_event.op     = SELECT_KEYED_EVENT_WAIT;
    select_op.keyed_event.handle = wine_server_obj_handle( handle );
    select_op.keyed_event.key    = wine_server_client_ptr( key );
    return server_wait( &select_op, sizeof(select_op.keyed_event), flags, timeout );
}


/******************************************************************************
 *              NtReleaseKeyedEvent (NTDLL.@)
 */
NTSTATUS WINAPI NtReleaseKeyedEvent( HANDLE handle, const void *key,
                                     BOOLEAN alertable, const LARGE_INTEGER *timeout )
{
    union select_op select_op;
    UINT flags = SELECT_INTERRUPTIBLE;

    TRACE( "handle %p, key %p, alertable %u, timeout %s\n", handle, key, alertable, debugstr_timeout(timeout) );

    if (!handle) handle = keyed_event;
    if ((ULONG_PTR)key & 1) return STATUS_INVALID_PARAMETER_1;
    if (alertable) flags |= SELECT_ALERTABLE;
    select_op.keyed_event.op     = SELECT_KEYED_EVENT_RELEASE;
    select_op.keyed_event.handle = wine_server_obj_handle( handle );
    select_op.keyed_event.key    = wine_server_client_ptr( key );
    return server_wait( &select_op, sizeof(select_op.keyed_event), flags, timeout );
}


/***********************************************************************
 *             NtCreateIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateIoCompletion( HANDLE *handle, ACCESS_MASK access, OBJECT_ATTRIBUTES *attr,
                                      ULONG threads )
{
    unsigned int status;
    data_size_t len;
    struct object_attributes *objattr;

    TRACE( "(%p, %x, %p, %d)\n", handle, access, attr, threads );

    *handle = 0;
    if ((status = alloc_object_attributes( attr, &objattr, &len ))) return status;

    SERVER_START_REQ( create_completion )
    {
        req->access     = access;
        req->concurrent = threads;
        wine_server_add_data( req, objattr, len );
        status = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return status;
}


/***********************************************************************
 *             NtOpenIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenIoCompletion( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int status;

    *handle = 0;
    if ((status = validate_open_object_attributes( attr ))) return status;

    SERVER_START_REQ( open_completion )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        status = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return status;
}


/***********************************************************************
 *             NtSetIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtSetIoCompletion( HANDLE handle, ULONG_PTR key, ULONG_PTR value,
                                   NTSTATUS status, SIZE_T count )
{
    unsigned int ret;

    TRACE( "(%p, %lx, %lx, %x, %lx)\n", handle, key, value, status, count );

    SERVER_START_REQ( add_completion )
    {
        req->handle      = wine_server_obj_handle( handle );
        req->ckey        = key;
        req->cvalue      = value;
        req->status      = status;
        req->information = count;
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}

/***********************************************************************
 *             NtSetIoCompletionEx (NTDLL.@)
 *
 * completion_reserve_handle is a handle allocated by NtAllocateReserveObject() for pre-allocating
 * memory for completion objects to deal with low-memory situations. It's not in use for now.
 */
NTSTATUS WINAPI NtSetIoCompletionEx( HANDLE completion_handle, HANDLE completion_reserve_handle,
                                     ULONG_PTR key, ULONG_PTR value, NTSTATUS status, SIZE_T count )
{
    unsigned int ret;

    TRACE( "(%p, %p, %lx, %lx, %x, %lx)\n", completion_handle, completion_reserve_handle,
           key, value, status, count );

    if (!completion_reserve_handle) return STATUS_INVALID_HANDLE;

    SERVER_START_REQ( add_completion )
    {
        req->handle         = wine_server_obj_handle( completion_handle );
        req->ckey           = key;
        req->cvalue         = value;
        req->status         = status;
        req->information    = count;
        req->reserve_handle = wine_server_obj_handle( completion_reserve_handle );
        ret = wine_server_call( req );
    }
    SERVER_END_REQ;
    return ret;
}

/***********************************************************************
 *             NtRemoveIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtRemoveIoCompletion( HANDLE handle, ULONG_PTR *key, ULONG_PTR *value,
                                      IO_STATUS_BLOCK *io, LARGE_INTEGER *timeout )
{
    HANDLE wait_handle = NULL;
    unsigned int status;

    TRACE( "(%p, %p, %p, %p, %p)\n", handle, key, value, io, timeout );

    if (timeout && !timeout->QuadPart && inproc_device_fd >= 0)
    {
        status = NtWaitForSingleObject( handle, FALSE, timeout );
        if (status != WAIT_OBJECT_0) return status;
    }

    SERVER_START_REQ( remove_completion )
    {
        req->handle = wine_server_obj_handle( handle );
        req->alertable = 0;
        if (!(status = wine_server_call( req )))
        {
            *key            = reply->ckey;
            *value          = reply->cvalue;
            io->Information = reply->information;
            io->Status      = reply->status;
        }
        else wait_handle = wine_server_ptr_handle( reply->wait_handle );
    }
    SERVER_END_REQ;
    if (status != STATUS_PENDING) return status;
    if (!timeout || timeout->QuadPart) status = server_wait_for_object( wait_handle, FALSE, timeout );
    else                               status = STATUS_TIMEOUT;
    if (status != WAIT_OBJECT_0) return status;

    SERVER_START_REQ( get_thread_completion )
    {
        if (!(status = wine_server_call( req )))
        {
            *key            = reply->ckey;
            *value          = reply->cvalue;
            io->Information = reply->information;
            io->Status      = reply->status;
        }
    }
    SERVER_END_REQ;

    return status;
}


/***********************************************************************
 *             NtRemoveIoCompletionEx (NTDLL.@)
 */
NTSTATUS WINAPI NtRemoveIoCompletionEx( HANDLE handle, FILE_IO_COMPLETION_INFORMATION *info, ULONG count,
                                        ULONG *written, LARGE_INTEGER *timeout, BOOLEAN alertable )
{
    HANDLE wait_handle = NULL;
    unsigned int status;
    ULONG i = 0;

    TRACE( "%p %p %u %p %p %u\n", handle, info, count, written, timeout, alertable );

    if (!count) return STATUS_INVALID_PARAMETER;

    if (timeout && !timeout->QuadPart && inproc_device_fd >= 0)
    {
        status = NtWaitForSingleObject( handle, alertable, timeout );
        if (status != WAIT_OBJECT_0) goto done;
    }

    while (i < count)
    {
        SERVER_START_REQ( remove_completion )
        {
            req->handle = wine_server_obj_handle( handle );
            req->alertable = alertable;
            if (!(status = wine_server_call( req )))
            {
                info[i].CompletionKey             = reply->ckey;
                info[i].CompletionValue           = reply->cvalue;
                info[i].IoStatusBlock.Information = reply->information;
                info[i].IoStatusBlock.Status      = reply->status;
            }
            else wait_handle = wine_server_ptr_handle( reply->wait_handle );
        }
        SERVER_END_REQ;
        if (status != STATUS_SUCCESS) break;
        ++i;
    }
    if (i || (status != STATUS_PENDING && status != STATUS_USER_APC))
    {
        if (i) status = STATUS_SUCCESS;
        goto done;
    }
    if (status == STATUS_USER_APC)
    {
        status = NtDelayExecution( TRUE, NULL );
        assert( status == STATUS_USER_APC );
        goto done;
    }
    if (!timeout || timeout->QuadPart) status = server_wait_for_object( wait_handle, alertable, timeout );
    else                               status = STATUS_TIMEOUT;
    if (status != WAIT_OBJECT_0) goto done;

    SERVER_START_REQ( get_thread_completion )
    {
        if (!(status = wine_server_call( req )))
        {
            info[i].CompletionKey             = reply->ckey;
            info[i].CompletionValue           = reply->cvalue;
            info[i].IoStatusBlock.Information = reply->information;
            info[i].IoStatusBlock.Status      = reply->status;
            ++i;
        }
    }
    SERVER_END_REQ;

done:
    *written = i ? i : 1;
    return status;
}


/***********************************************************************
 *             NtQueryIoCompletion (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryIoCompletion( HANDLE handle, IO_COMPLETION_INFORMATION_CLASS class,
                                     void *buffer, ULONG len, ULONG *ret_len )
{
    unsigned int status;

    TRACE( "(%p, %d, %p, 0x%x, %p)\n", handle, class, buffer, len, ret_len );

    if (!buffer) return STATUS_INVALID_PARAMETER;

    switch (class)
    {
    case IoCompletionBasicInformation:
    {
        ULONG *info = buffer;
        if (ret_len) *ret_len = sizeof(*info);
        if (len == sizeof(*info))
        {
            SERVER_START_REQ( query_completion )
            {
                req->handle = wine_server_obj_handle( handle );
                if (!(status = wine_server_call( req ))) *info = reply->depth;
            }
            SERVER_END_REQ;
        }
        else status = STATUS_INFO_LENGTH_MISMATCH;
        break;
    }
    default:
        return STATUS_INVALID_PARAMETER;
    }
    return status;
}


/***********************************************************************
 *             NtCreateSection (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                 const LARGE_INTEGER *size, ULONG protect,
                                 ULONG sec_flags, HANDLE file )
{
    unsigned int ret;
    unsigned int file_access;
    data_size_t len;
    struct object_attributes *objattr;

    *handle = 0;

    /* NSPA: SEC_LARGE_PAGES validation per Windows semantics:
     *  - The size argument is required (not NULL)
     *  - The size must be a multiple of LargePageMinimum
     *  - The mapping cannot be backed by a file (anonymous only).
     *    "No file" can be expressed as either NULL or INVALID_HANDLE_VALUE
     *    (kernel32's CreateFileMapping passes INVALID_HANDLE_VALUE for
     *    pagefile-backed mappings; both are valid here).
     *  - LargePageMinimum must be non-zero (host has hugepages configured)
     * The wineserver-side check (commit 0074 cmt 1/8) handles
     * SeLockMemoryPrivilege; this is the client-side parameter sanity. */
    if (sec_flags & SEC_LARGE_PAGES)
    {
        extern struct _KUSER_SHARED_DATA *user_shared_data;
        SIZE_T min_size = user_shared_data->LargePageMinimum;

        if (file != NULL && file != INVALID_HANDLE_VALUE)
            return STATUS_INVALID_PARAMETER;
        if (size == NULL) return STATUS_INVALID_PARAMETER;
        if (min_size == 0 || size->QuadPart == 0 ||
            (size->QuadPart % min_size) != 0)
            return STATUS_INVALID_PARAMETER;
    }

    switch (protect & 0xff)
    {
    case PAGE_READONLY:
    case PAGE_EXECUTE_READ:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_WRITECOPY:
        file_access = FILE_READ_DATA;
        break;
    case PAGE_READWRITE:
    case PAGE_EXECUTE_READWRITE:
        if (sec_flags & SEC_IMAGE) file_access = FILE_READ_DATA;
        else file_access = FILE_READ_DATA | FILE_WRITE_DATA;
        break;
    case PAGE_EXECUTE:
    case PAGE_NOACCESS:
        file_access = 0;
        break;
    default:
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    if ((ret = alloc_object_attributes( attr, &objattr, &len ))) return ret;

    /* NSPA local-section bypass + LF-promote dispatch.  See
     * dlls/ntdll/unix/nspa/local_file.c::nspa_local_section_create_from_lf_file
     * for the full eligibility check + PE-side bypass attempt + server
     * RPC fallback (Phase B + H + dup-fd lifetime fix).  Returns
     * STATUS_NOT_SUPPORTED if file isn't actually LF (rare race window);
     * caller falls through to the regular create_mapping RPC. */
    if (file && nspa_local_file_is_local_handle( file ))
    {
        BOOL has_name = (attr && attr->ObjectName && attr->ObjectName->Length > 0);
        ULONGLONG size_arg = size ? size->QuadPart : 0;
        ret = nspa_local_section_create_from_lf_file( handle, file, access, sec_flags,
                                                      file_access, size_arg, has_name,
                                                      objattr, len );
        if (ret != STATUS_NOT_SUPPORTED)
        {
            free( objattr );
            return ret;
        }
        /* fall through to server-direct create_mapping path */
    }

    SERVER_START_REQ( create_mapping )
    {
        req->access      = access;
        req->flags       = sec_flags;
        req->file_handle = wine_server_obj_handle( file );
        req->file_access = file_access;
        req->size        = size ? size->QuadPart : 0;
        wine_server_add_data( req, objattr, len );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;

    free( objattr );
    return ret;
}


/***********************************************************************
 *             NtCreateSectionEx (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateSectionEx( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr,
                                   const LARGE_INTEGER *size, ULONG protect, ULONG sec_flags,
                                   HANDLE file, MEM_EXTENDED_PARAMETER *parameters, ULONG count )
{
    if (count) FIXME( "extended params not supported\n" );
    return NtCreateSection( handle, access, attr, size, protect, sec_flags, file );
}


/***********************************************************************
 *             NtOpenSection (NTDLL.@)
 */
NTSTATUS WINAPI NtOpenSection( HANDLE *handle, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr )
{
    unsigned int ret;

    *handle = 0;
    if ((ret = validate_open_object_attributes( attr ))) return ret;

    SERVER_START_REQ( open_mapping )
    {
        req->access     = access;
        req->attributes = attr->Attributes;
        req->rootdir    = wine_server_obj_handle( attr->RootDirectory );
        if (attr->ObjectName)
            wine_server_add_data( req, attr->ObjectName->Buffer, attr->ObjectName->Length );
        ret = wine_server_call( req );
        *handle = wine_server_ptr_handle( reply->handle );
    }
    SERVER_END_REQ;
    return ret;
}


/***********************************************************************
 *             NtCreatePort (NTDLL.@)
 */
NTSTATUS WINAPI NtCreatePort( HANDLE *handle, OBJECT_ATTRIBUTES *attr, ULONG info_len,
                              ULONG data_len, ULONG *reserved )
{
    FIXME( "(%p,%p,%u,%u,%p),stub!\n", handle, attr, info_len, data_len, reserved );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtConnectPort( HANDLE *handle, UNICODE_STRING *name, SECURITY_QUALITY_OF_SERVICE *qos,
                               LPC_SECTION_WRITE *write, LPC_SECTION_READ *read, ULONG *max_len,
                               void *info, ULONG *info_len )
{
    FIXME( "(%p,%s,%p,%p,%p,%p,%p,%p),stub!\n", handle, debugstr_us(name), qos,
           write, read, max_len, info, info_len );
    if (info && info_len) TRACE("msg = %s\n", debugstr_an( info, *info_len ));
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtSecureConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtSecureConnectPort( HANDLE *handle, UNICODE_STRING *name, SECURITY_QUALITY_OF_SERVICE *qos,
                                     LPC_SECTION_WRITE *write, PSID sid, LPC_SECTION_READ *read,
                                     ULONG *max_len, void *info, ULONG *info_len )
{
    FIXME( "(%p,%s,%p,%p,%p,%p,%p,%p,%p),stub!\n", handle, debugstr_us(name), qos,
           write, sid, read, max_len, info, info_len );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtListenPort (NTDLL.@)
 */
NTSTATUS WINAPI NtListenPort( HANDLE handle, LPC_MESSAGE *msg )
{
    FIXME("(%p,%p),stub!\n", handle, msg );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtAcceptConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtAcceptConnectPort( HANDLE *handle, ULONG id, LPC_MESSAGE *msg, BOOLEAN accept,
                                     LPC_SECTION_WRITE *write, LPC_SECTION_READ *read )
{
    FIXME("(%p,%u,%p,%d,%p,%p),stub!\n", handle, id, msg, accept, write, read );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtCompleteConnectPort (NTDLL.@)
 */
NTSTATUS WINAPI NtCompleteConnectPort( HANDLE handle )
{
    FIXME( "(%p),stub!\n", handle );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtImpersonateClientOfPort (NTDLL.@)
 */
NTSTATUS WINAPI NtImpersonateClientOfPort( HANDLE handle, LPC_MESSAGE *request )
{
    FIXME( "(%p,%p),stub!\n", handle, request );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtReadRequestData (NTDLL.@)
 */
NTSTATUS WINAPI NtReadRequestData( HANDLE handle, LPC_MESSAGE *request, ULONG id,
                                   void *buffer, ULONG len, ULONG *retlen )
{
    FIXME( "(%p,%p,%u,%p,%u,%p),stub!\n", handle, request, id, buffer, len, retlen );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtRegisterThreadTerminatePort (NTDLL.@)
 */
NTSTATUS WINAPI NtRegisterThreadTerminatePort( HANDLE handle )
{
    FIXME( "(%p),stub!\n", handle );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtRequestWaitReplyPort (NTDLL.@)
 */
NTSTATUS WINAPI NtRequestWaitReplyPort( HANDLE handle, LPC_MESSAGE *msg_in, LPC_MESSAGE *msg_out )
{
    FIXME( "(%p,%p,%p),stub!\n", handle, msg_in, msg_out );
    if (msg_in)
        TRACE("datasize %u msgsize %u type %u ranges %u client %p/%p msgid %lu size %lu data %s\n",
              msg_in->DataSize, msg_in->MessageSize, msg_in->MessageType, msg_in->VirtualRangesOffset,
              msg_in->ClientId.UniqueProcess, msg_in->ClientId.UniqueThread, msg_in->MessageId,
              msg_in->SectionSize, debugstr_an( (const char *)msg_in->Data, msg_in->DataSize ));
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtReplyPort (NTDLL.@)
 */
NTSTATUS WINAPI NtReplyPort( HANDLE handle, LPC_MESSAGE *reply )
{
    FIXME("(%p,%p),stub!\n", handle, reply );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtReplyWaitReceivePort (NTDLL.@)
 */
NTSTATUS WINAPI NtReplyWaitReceivePort( HANDLE handle, ULONG *id, LPC_MESSAGE *reply, LPC_MESSAGE *msg )
{
    FIXME("(%p,%p,%p,%p),stub!\n", handle, id, reply, msg );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtReplyWaitReceivePortEx (NTDLL.@)
 */
NTSTATUS WINAPI NtReplyWaitReceivePortEx( HANDLE handle, ULONG *id, LPC_MESSAGE *reply, LPC_MESSAGE *msg,
                                          LARGE_INTEGER *timeout )
{
    FIXME("(%p,%p,%p,%p,%p),stub!\n", handle, id, reply, msg, timeout );
    return STATUS_NOT_IMPLEMENTED;
}


/***********************************************************************
 *             NtWriteRequestData (NTDLL.@)
 */
NTSTATUS WINAPI NtWriteRequestData( HANDLE handle, LPC_MESSAGE *request, ULONG id,
                                    void *buffer, ULONG len, ULONG *retlen )
{
    FIXME( "(%p,%p,%u,%p,%u,%p),stub!\n", handle, request, id, buffer, len, retlen );
    return STATUS_NOT_IMPLEMENTED;
}

#define MAX_ATOM_LEN  255
#define IS_INTATOM(x) (((ULONG_PTR)(x) >> 16) == 0)

static unsigned int is_integral_atom( const WCHAR *atomstr, ULONG len, RTL_ATOM *ret_atom )
{
    RTL_ATOM atom;

    if ((ULONG_PTR)atomstr >> 16)
    {
        const WCHAR* ptr = atomstr;
        if (!len) return STATUS_OBJECT_NAME_INVALID;

        if (*ptr++ == '#')
        {
            atom = 0;
            while (ptr < atomstr + len && *ptr >= '0' && *ptr <= '9')
            {
                atom = atom * 10 + *ptr++ - '0';
            }
            if (ptr > atomstr + 1 && ptr == atomstr + len) goto done;
        }
        if (len > MAX_ATOM_LEN) return STATUS_INVALID_PARAMETER;
        return STATUS_MORE_ENTRIES;
    }
    else if ((atom = LOWORD( atomstr )) >= MAXINTATOM) return STATUS_INVALID_PARAMETER;
done:
    if (atom >= MAXINTATOM) atom = 0;
    if (!(*ret_atom = atom)) return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

static ULONG integral_atom_name( WCHAR *buffer, ULONG len, RTL_ATOM atom )
{
    char tmp[16];
    int ret = snprintf( tmp, sizeof(tmp), "#%u", atom );

    len /= sizeof(WCHAR);
    if (len)
    {
        if (len <= ret) ret = len - 1;
        ascii_to_unicode( buffer, tmp, ret );
        buffer[ret] = 0;
    }
    return ret * sizeof(WCHAR);
}


/***********************************************************************
 *             NtAddAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtAddAtom( const WCHAR *name, ULONG length, RTL_ATOM *atom )
{
    unsigned int status = is_integral_atom( name, length / sizeof(WCHAR), atom );

    if (status == STATUS_MORE_ENTRIES)
    {
        SERVER_START_REQ( add_atom )
        {
            wine_server_add_data( req, name, length );
            status = wine_server_call( req );
            *atom = reply->atom;
        }
        SERVER_END_REQ;
    }
    TRACE( "%s -> %x\n", debugstr_wn(name, length/sizeof(WCHAR)), status == STATUS_SUCCESS ? *atom : 0 );
    return status;
}


/***********************************************************************
 *             NtDeleteAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtDeleteAtom( RTL_ATOM atom )
{
    unsigned int status;

    if (!atom) status = STATUS_INVALID_HANDLE;
    else if (atom < MAXINTATOM) status = STATUS_SUCCESS;
    else SERVER_START_REQ( delete_atom )
    {
        req->atom = atom;
        status = wine_server_call( req );
    }
    SERVER_END_REQ;
    return status;
}


/***********************************************************************
 *             NtFindAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtFindAtom( const WCHAR *name, ULONG length, RTL_ATOM *atom )
{
    unsigned int status = is_integral_atom( name, length / sizeof(WCHAR), atom );

    if (status == STATUS_MORE_ENTRIES)
    {
        SERVER_START_REQ( find_atom )
        {
            wine_server_add_data( req, name, length );
            status = wine_server_call( req );
            *atom = reply->atom;
        }
        SERVER_END_REQ;
    }
    TRACE( "%s -> %x\n", debugstr_wn(name, length/sizeof(WCHAR)), status == STATUS_SUCCESS ? *atom : 0 );
    return status;
}


/***********************************************************************
 *             NtQueryInformationAtom (NTDLL.@)
 */
NTSTATUS WINAPI NtQueryInformationAtom( RTL_ATOM atom, ATOM_INFORMATION_CLASS class,
                                        void *ptr, ULONG size, ULONG *retsize )
{
    unsigned int status;

    switch (class)
    {
    case AtomBasicInformation:
    {
        ULONG name_len;
        ATOM_BASIC_INFORMATION *abi = ptr;

        if (size < sizeof(ATOM_BASIC_INFORMATION)) return STATUS_INVALID_PARAMETER;
        name_len = size - sizeof(ATOM_BASIC_INFORMATION);

        if (atom < MAXINTATOM)
        {
            if (atom)
            {
                abi->NameLength = integral_atom_name( abi->Name, name_len, atom );
                status = name_len ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
                abi->ReferenceCount = 1;
                abi->Pinned = 1;
            }
            else status = STATUS_INVALID_PARAMETER;
        }
        else
        {
            SERVER_START_REQ( get_atom_information )
            {
                req->atom = atom;
                if (name_len) wine_server_set_reply( req, abi->Name, name_len );
                status = wine_server_call( req );
                if (status == STATUS_SUCCESS)
                {
                    name_len = wine_server_reply_size( reply );
                    if (name_len)
                    {
                        abi->NameLength = name_len;
                        abi->Name[name_len / sizeof(WCHAR)] = 0;
                    }
                    else
                    {
                        name_len = reply->total;
                        abi->NameLength = name_len;
                        status = STATUS_BUFFER_TOO_SMALL;
                    }
                    abi->ReferenceCount = reply->count;
                    abi->Pinned = reply->pinned;
                }
                else name_len = 0;
            }
            SERVER_END_REQ;
        }
        TRACE( "%x -> %s (%u)\n", atom, debugstr_wn(abi->Name, abi->NameLength / sizeof(WCHAR)), status );
        if (retsize) *retsize = sizeof(ATOM_BASIC_INFORMATION) + name_len;
        break;
    }

    default:
        FIXME( "Unsupported class %u\n", class );
        status = STATUS_INVALID_INFO_CLASS;
        break;
    }
    return status;
}


union tid_alert_entry
{
#ifdef USE_FUTEX
    LONG futex;
#elif defined(HAVE_KQUEUE)
    int kq;
#else
    HANDLE event;
#endif
};

#define TID_ALERT_BLOCK_SIZE (65536 / sizeof(union tid_alert_entry))
static union tid_alert_entry *tid_alert_blocks[4096];

static unsigned int handle_to_index( HANDLE handle, unsigned int *block_idx )
{
    unsigned int idx = (wine_server_obj_handle(handle) >> 2) - 1;
    *block_idx = idx / TID_ALERT_BLOCK_SIZE;
    return idx % TID_ALERT_BLOCK_SIZE;
}

static BOOL is_alert_tid_valid( HANDLE tid )
{
    unsigned int block_idx;

    handle_to_index( tid, &block_idx );
    return block_idx <= ARRAY_SIZE(tid_alert_blocks);
}

static union tid_alert_entry *get_tid_alert_entry( HANDLE tid )
{
    unsigned int block_idx, idx = handle_to_index( tid, &block_idx );
    union tid_alert_entry *entry;

    if (block_idx > ARRAY_SIZE(tid_alert_blocks))
    {
        FIXME( "tid %p is too high\n", tid );
        return NULL;
    }

    if (!tid_alert_blocks[block_idx])
    {
        static const size_t size = TID_ALERT_BLOCK_SIZE * sizeof(union tid_alert_entry);
        void *ptr = anon_mmap_alloc( size, PROT_READ | PROT_WRITE, LARGE_PAGES_NONE );
        if (ptr == MAP_FAILED) return NULL;
        if (InterlockedCompareExchangePointer( (void **)&tid_alert_blocks[block_idx], ptr, NULL ))
            munmap( ptr, size ); /* someone beat us to it */
    }

    entry = &tid_alert_blocks[block_idx][idx % TID_ALERT_BLOCK_SIZE];

#ifdef USE_FUTEX
    return entry;
#elif defined(HAVE_KQUEUE)
    if (!entry->kq)
    {
        int kq = kqueue();
        static const struct kevent init_event =
        {
            .ident = 1,
            .filter = EVFILT_USER,
            .flags = EV_ADD | EV_CLEAR,
            .fflags = 0,
            .data = 0,
            .udata = NULL
        };

        if (kq == -1)
        {
            ERR( "kqueue failed with error: %d (%s)\n", errno, strerror( errno ) );
            return NULL;
        }

        if (kevent( kq, &init_event, 1, NULL, 0, NULL) == -1)
        {
            ERR( "kevent creation failed with error: %d (%s)\n", errno, strerror( errno ) );
            close( kq );
            return NULL;
        }

        if (InterlockedCompareExchange( (LONG *)&entry->kq, kq, 0 ))
            close( kq );
    }
#else
    if (!entry->event)
    {
        HANDLE event;

        if (NtCreateEvent( &event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ))
            return NULL;
        if (InterlockedCompareExchangePointer( &entry->event, event, NULL ))
            NtClose( event );
    }
#endif

    return entry;
}


/***********************************************************************
 *             NtAlertMultipleThreadByThreadId (NTDLL.@)
 */
NTSTATUS WINAPI NtAlertMultipleThreadByThreadId( HANDLE *tids, ULONG count, void *unk1, void *unk2 )
{
    unsigned int i;

    TRACE( "%p %d %p %p\n", tids, (int)count, unk1, unk2 );

    if (unk1 || unk2) FIXME( "unk1 %p, unk2 %p.\n", unk1, unk2 );
    for (i = 0; i < count; ++i)
    {
        if (!is_alert_tid_valid( tids[i] )) return STATUS_INVALID_CID;
    }
    for (i = 0; i < count; ++i) NtAlertThreadByThreadId( tids[i] );
    return STATUS_SUCCESS;
}


/***********************************************************************
 *             NtAlertThreadByThreadId (NTDLL.@)
 */
NTSTATUS WINAPI NtAlertThreadByThreadId( HANDLE tid )
{
    union tid_alert_entry *entry = get_tid_alert_entry( tid );

    TRACE( "%p\n", tid );

    if (!entry) return STATUS_INVALID_CID;

#ifdef USE_FUTEX
    {
        LONG *futex = &entry->futex;
        if (!InterlockedExchange( futex, 1 ))
            futex_wake_one( futex );
        return STATUS_SUCCESS;
    }
#elif defined(HAVE_KQUEUE)
    {
        static const struct kevent signal_event =
        {
            .ident = 1,
            .filter = EVFILT_USER,
            .flags = 0,
            .fflags = NOTE_TRIGGER,
            .data = 0,
            .udata = NULL
        };

        kevent( entry->kq, &signal_event, 1, NULL, 0, NULL );
        return STATUS_SUCCESS;
    }
#else
    return NtSetEvent( entry->event, NULL );
#endif
}


#if defined(USE_FUTEX) || defined(HAVE_KQUEUE)
static LONGLONG get_absolute_timeout( const LARGE_INTEGER *timeout )
{
    LARGE_INTEGER now;

    if (timeout->QuadPart >= 0) return timeout->QuadPart;
    NtQuerySystemTime( &now );
    return now.QuadPart - timeout->QuadPart;
}

static LONGLONG update_timeout( ULONGLONG end )
{
    LARGE_INTEGER now;
    LONGLONG timeleft;

    NtQuerySystemTime( &now );
    timeleft = end - now.QuadPart;
    if (timeleft < 0) timeleft = 0;
    return timeleft;
}
#endif


/***********************************************************************
 *             NtNspaGetUnixTid (NTDLL.@)
 *
 * NSPA RT v2.3 — return the calling thread's Linux kernel TID.
 *
 * The PE side cannot call syscall(SYS_gettid) directly (no libc, no raw
 * syscall access). CS-PI's fast-path CAS needs the kernel TID (not the
 * Win32 TID, which is wineserver-assigned and unrelated) because
 * FUTEX_LOCK_PI validates the owner field against the kernel's task list.
 *
 * PE side caches this in a __thread variable per thread, so this syscall
 * fires at most once per thread (on first CS acquire).
 */
ULONG WINAPI NtNspaGetUnixTid(void)
{
#ifdef __linux__
    struct ntdll_thread_data *thread_data = ntdll_get_thread_data();
    if (!thread_data->nspa_unix_tid)
        thread_data->nspa_unix_tid = (DWORD)syscall( SYS_gettid );
    return thread_data->nspa_unix_tid;
#else
    return 0;
#endif
}


/***********************************************************************
 *             NtNspaLockCriticalSectionPI (NTDLL.@)
 *
 * NSPA RT v2.3 — slow-path entry for CS-PI. The caller (PE-side
 * RtlEnterCriticalSection) has already tried to claim the futex word via a
 * user-space CAS of its Linux TID and failed (contention). Hand the word to
 * the kernel's rt_mutex PI chain via FUTEX_LOCK_PI_PRIVATE — the kernel will
 * temporarily boost the current holder to the caller's scheduling priority,
 * run it until it releases the CS, then transfer ownership to us.
 *
 * On return, the futex word holds our TID (possibly with FUTEX_WAITERS set if
 * further waiters have arrived while we were blocked). The PE side then sets
 * OwningThread/RecursionCount bookkeeping and returns to the app.
 *
 * Return values:
 *   STATUS_SUCCESS      — lock acquired
 *   STATUS_NOT_SUPPORTED— kernel lacks FUTEX_LOCK_PI (old/stripped kernel)
 *   STATUS_UNSUCCESSFUL — any other futex(2) error
 *
 * On NOT_SUPPORTED the PE-side caller falls back to the legacy keyed-event
 * wait path, making CS-PI a soft dependency on kernel FUTEX_LOCK_PI support.
 */
NTSTATUS WINAPI NtNspaLockCriticalSectionPI( void *address )
{
#ifdef USE_FUTEX
    LONG *futex = address;
    int ret;

    if (!futex) return STATUS_INVALID_PARAMETER;

    do {
        ret = futex_lock_pi( futex );
    } while (ret == -1 && errno == EINTR);

    if (ret == 0) return STATUS_SUCCESS;
    if (errno == ENOSYS) return STATUS_NOT_SUPPORTED;
    return STATUS_UNSUCCESSFUL;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}


/***********************************************************************
 *             NtNspaUnlockCriticalSectionPI (NTDLL.@)
 *
 * NSPA RT v2.3 — release-path entry for CS-PI. Called from PE-side
 * RtlLeaveCriticalSection when we are releasing a PI-locked CS and the
 * FUTEX_WAITERS bit is set (i.e. at least one thread is blocked on us via
 * FUTEX_LOCK_PI). Hands off ownership to the highest-priority waiter via
 * FUTEX_UNLOCK_PI_PRIVATE — the kernel drops our priority boost and transfers
 * the futex word's TID field to the chosen waiter.
 *
 * Uncontended release (no waiters) is handled entirely in user space on the
 * PE side via a direct CAS on the futex word; this syscall is only used when
 * the kernel needs to be involved for the PI chain hand-off.
 */
NTSTATUS WINAPI NtNspaUnlockCriticalSectionPI( void *address )
{
#ifdef USE_FUTEX
    LONG *futex = address;
    int ret;

    if (!futex) return STATUS_INVALID_PARAMETER;

    ret = futex_unlock_pi( futex );

    if (ret == 0) return STATUS_SUCCESS;
    if (errno == ENOSYS) return STATUS_NOT_SUPPORTED;
    return STATUS_UNSUCCESSFUL;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}


/***********************************************************************
 *             NtNspaCondWaitPI (NTDLL.@)
 *
 * NSPA RT v3 — condvar wait with PI via FUTEX_WAIT_REQUEUE_PI.
 *
 * Atomically releases the PI mutex (FUTEX_UNLOCK_PI), then sleeps on the
 * condvar futex via FUTEX_WAIT_REQUEUE_PI. On signal, the kernel requeues
 * the waiter directly onto the PI mutex's wait chain — zero gap.
 *
 * Contract: on ANY return, the caller owns the PI mutex.
 *   STATUS_SUCCESS       — signaled, own via kernel requeue or manual relock
 *   STATUS_TIMEOUT       — timed out, reacquired via FUTEX_LOCK_PI
 *   STATUS_NOT_SUPPORTED — kernel lacks requeue-PI; CS was never released
 *   STATUS_UNSUCCESSFUL  — other futex error; reacquired via FUTEX_LOCK_PI
 */
NTSTATUS WINAPI NtNspaCondWaitPI( void *condvar_futex, LONG condvar_val,
                                   void *pi_mutex, const LARGE_INTEGER *timeout )
{
#ifdef USE_FUTEX
    LONG *condvar = condvar_futex;
    LONG *mutex   = pi_mutex;
    struct timespec abstime;
    struct timespec *pts = NULL;
    int ret, err;

    if (!condvar || !mutex) return STATUS_INVALID_PARAMETER;

    /* Convert NT timeout to absolute CLOCK_MONOTONIC timespec */
    if (timeout && timeout->QuadPart != TIMEOUT_INFINITE)
    {
        LONGLONG relative_100ns;

        if (timeout->QuadPart < 0)
            relative_100ns = -timeout->QuadPart;
        else
        {
            LARGE_INTEGER now;
            NtQuerySystemTime( &now );
            relative_100ns = timeout->QuadPart - now.QuadPart;
            if (relative_100ns < 0) relative_100ns = 0;
        }

        clock_gettime( CLOCK_MONOTONIC, &abstime );
        abstime.tv_nsec += (relative_100ns % TICKSPERSEC) * 100;
        abstime.tv_sec  += relative_100ns / TICKSPERSEC;
        if (abstime.tv_nsec >= 1000000000L)
        {
            abstime.tv_sec++;
            abstime.tv_nsec -= 1000000000L;
        }
        pts = &abstime;
    }

    /* Release the PI mutex — equivalent to RtlLeaveCriticalSection's
     * FUTEX_UNLOCK_PI, but done here to keep it close to the WAIT. */
    ret = futex_unlock_pi( mutex );
    if (ret == -1)
    {
        if (errno == ENOSYS) return STATUS_NOT_SUPPORTED;
        /* Unlock failed for another reason — CS state is inconsistent.
         * Best we can do is return with the mutex still held. */
        return STATUS_NOT_SUPPORTED;
    }

    /* Sleep on the condvar futex. The kernel atomically checks
     * *condvar == condvar_val, then sleeps. On signal via
     * FUTEX_CMP_REQUEUE_PI, we get requeued onto the PI mutex. */
    do {
        ret = futex_wait_requeue_pi( condvar, condvar_val, pts, mutex );
        err = errno;
    } while (ret == -1 && err == EINTR);

    if (ret == 0)
        return STATUS_SUCCESS;  /* kernel requeued us — we own the PI mutex */

    /* Error path: must manually reacquire the PI mutex before returning. */
    {
        int lret;
        do {
            lret = futex_lock_pi( mutex );
        } while (lret == -1 && errno == EINTR);
    }

    if (err == EAGAIN)
        return STATUS_SUCCESS;  /* condvar value changed — signal raced with us */
    if (err == ETIMEDOUT)
        return STATUS_TIMEOUT;
    if (err == ENOSYS)
        return STATUS_NOT_SUPPORTED;

    return STATUS_UNSUCCESSFUL;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}


/***********************************************************************
 *             NtNspaCondSignalPI (NTDLL.@)
 *
 * NSPA RT v3 — condvar signal with PI via FUTEX_CMP_REQUEUE_PI.
 *
 * Increments the condvar generation counter and wakes one PI waiter,
 * requeuing it onto the PI mutex. If no PI waiters are queued, returns
 * STATUS_NO_MORE_ENTRIES so the PE side can fall back to RtlWakeAddressSingle.
 *
 *   STATUS_SUCCESS        — woke/requeued at least one PI waiter
 *   STATUS_NO_MORE_ENTRIES— no PI waiters on condvar futex queue
 *   STATUS_NOT_SUPPORTED  — kernel lacks FUTEX_CMP_REQUEUE_PI
 */
NTSTATUS WINAPI NtNspaCondSignalPI( void *condvar_futex, void *pi_mutex )
{
#ifdef USE_FUTEX
    LONG *condvar = condvar_futex;
    LONG *mutex   = pi_mutex;
    int ret;
    LONG val;

    if (!condvar || !mutex) return STATUS_INVALID_PARAMETER;

    /* Increment the condvar generation counter exactly once per signal.
     * On EAGAIN (concurrent signal changed the value between our read and
     * the kernel's check), just re-read the current value and retry — do
     * NOT re-increment, or we'll burn N generation numbers per signal. */
    InterlockedIncrement( condvar );

    for (;;)
    {
        val = *(volatile LONG *)condvar;

        /* Wake 1, requeue 0 — exactly one waiter moves to the PI mutex. */
        ret = futex_cmp_requeue_pi( condvar, 1, 0, mutex, val );

        if (ret > 0)
            return STATUS_SUCCESS;      /* woke a PI waiter */
        if (ret == 0)
            return STATUS_NO_MORE_ENTRIES; /* no PI waiters on queue */
        if (errno == EAGAIN)
            continue;                   /* value changed, re-read and retry */
        if (errno == ENOSYS)
            return STATUS_NOT_SUPPORTED;
        return STATUS_UNSUCCESSFUL;
    }
#else
    return STATUS_NOT_SUPPORTED;
#endif
}


/***********************************************************************
 *             NtNspaCondBroadcastPI (NTDLL.@)
 *
 * NSPA RT v3 — condvar broadcast with PI via FUTEX_CMP_REQUEUE_PI.
 *
 * Increments the condvar counter, wakes one PI waiter, and requeues all
 * remaining PI waiters directly onto the PI mutex — no thundering herd.
 *
 *   STATUS_SUCCESS        — woke/requeued PI waiters (or none queued)
 *   STATUS_NOT_SUPPORTED  — kernel lacks FUTEX_CMP_REQUEUE_PI
 */
NTSTATUS WINAPI NtNspaCondBroadcastPI( void *condvar_futex, void *pi_mutex )
{
#ifdef USE_FUTEX
    LONG *condvar = condvar_futex;
    LONG *mutex   = pi_mutex;
    int ret;
    LONG val;

    if (!condvar || !mutex) return STATUS_INVALID_PARAMETER;

    /* Increment once, then retry by re-reading on EAGAIN. */
    InterlockedIncrement( condvar );

    for (;;)
    {
        val = *(volatile LONG *)condvar;

        /* Wake 1, requeue all remaining onto PI mutex. */
        ret = futex_cmp_requeue_pi( condvar, 1, INT_MAX, mutex, val );

        if (ret >= 0)
            return STATUS_SUCCESS;
        if (errno == EAGAIN)
            continue;
        if (errno == ENOSYS)
            return STATUS_NOT_SUPPORTED;
        return STATUS_UNSUCCESSFUL;
    }
#else
    return STATUS_NOT_SUPPORTED;
#endif
}


/***********************************************************************
 *             NtWaitForAlertByThreadId (NTDLL.@)
 */
NTSTATUS WINAPI NtWaitForAlertByThreadId( const void *address, const LARGE_INTEGER *timeout )
{
    union tid_alert_entry *entry = get_tid_alert_entry( ULongToHandle(get_thread_data()->tid) );

    TRACE( "%p %s\n", address, debugstr_timeout( timeout ) );

    if (!entry) return STATUS_INVALID_CID;

#ifdef USE_FUTEX
    {
        LONG *futex = &entry->futex;
        ULONGLONG end;
        int ret;

        if (timeout)
        {
            if (timeout->QuadPart == TIMEOUT_INFINITE)
                timeout = NULL;
            else
                end = get_absolute_timeout( timeout );
        }

        while (!InterlockedExchange( futex, 0 ))
        {
            if (timeout)
            {
                LONGLONG timeleft = update_timeout( end );
                struct timespec timespec;

                timespec.tv_sec = timeleft / (ULONGLONG)TICKSPERSEC;
                timespec.tv_nsec = (timeleft % TICKSPERSEC) * 100;
                ret = futex_wait( futex, 0, &timespec );
            }
            else
                ret = futex_wait( futex, 0, NULL );

            if (ret == -1 && errno == ETIMEDOUT) return STATUS_TIMEOUT;
        }
        return STATUS_ALERTED;
    }
#elif defined(HAVE_KQUEUE)
    {
        ULONGLONG end;
        int ret;
        struct timespec timespec;
        struct kevent wait_event;

        if (timeout)
        {
            if (timeout->QuadPart == TIMEOUT_INFINITE)
                timeout = NULL;
            else
                end = get_absolute_timeout( timeout );
        }

        do
        {
            if (timeout)
            {
                LONGLONG timeleft = update_timeout( end );

                timespec.tv_sec = timeleft / (ULONGLONG)TICKSPERSEC;
                timespec.tv_nsec = (timeleft % TICKSPERSEC) * 100;
                if (timespec.tv_sec > 0x7FFFFFFF) timeout = NULL;
            }

            ret = kevent( entry->kq, NULL, 0, &wait_event, 1, timeout ? &timespec : NULL );
        } while (ret == -1 && errno == EINTR);

        switch (ret)
        {
        case 1:
            return STATUS_ALERTED;
        case 0:
            return STATUS_TIMEOUT;
        default:
            ERR( "kevent failed with error: %d (%s)\n", errno, strerror( errno ) );
            return STATUS_INVALID_HANDLE;
        }
    }
#else
    {
        NTSTATUS status = NtWaitForSingleObject( entry->event, FALSE, timeout );
        if (!status) return STATUS_ALERTED;
        return status;
    }
#endif
}


/***********************************************************************
 *           NtCreateTransaction (NTDLL.@)
 */
NTSTATUS WINAPI NtCreateTransaction( HANDLE *handle, ACCESS_MASK mask, OBJECT_ATTRIBUTES *obj_attr, GUID *guid, HANDLE tm,
        ULONG options, ULONG isol_level, ULONG isol_flags, PLARGE_INTEGER timeout, UNICODE_STRING *description )
{
    FIXME( "%p, %#x, %p, %s, %p, 0x%08x, 0x%08x, 0x%08x, %p, %p stub.\n", handle, mask, obj_attr, debugstr_guid(guid), tm,
            options, isol_level, isol_flags, timeout, description );

    *handle = ULongToHandle(1);

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           NtCommitTransaction (NTDLL.@)
 */
NTSTATUS WINAPI NtCommitTransaction( HANDLE transaction, BOOLEAN wait )
{
    FIXME( "%p, %d stub.\n", transaction, wait );

    return STATUS_SUCCESS;
}

/***********************************************************************
 *           NtRollbackTransaction (NTDLL.@)
 */
NTSTATUS WINAPI NtRollbackTransaction( HANDLE transaction, BOOLEAN wait )
{
    FIXME( "%p, %d stub.\n", transaction, wait );

    return STATUS_ACCESS_VIOLATION;
}

/***********************************************************************
 *           NtConvertBetweenAuxiliaryCounterAndPerformanceCounter (NTDLL.@)
 */
NTSTATUS WINAPI NtConvertBetweenAuxiliaryCounterAndPerformanceCounter( ULONG flag, ULONGLONG *from, ULONGLONG *to, ULONGLONG *error )
{
    FIXME( "%#x, %p, %p, %p.\n",  flag, from, to, error );

    if (!from) return STATUS_ACCESS_VIOLATION;

    return STATUS_NOT_SUPPORTED;
}
