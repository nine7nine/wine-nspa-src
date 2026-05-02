/*
 * Copyright 2026 Rémi Bernon for CodeWeavers
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
#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <poll.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"

#include "unix_private.h"
#include "wine/list.h"
#include "wine/debug.h"

/* NSPA: dedicated debug channel so WINEDEBUG=+sched selectively enables
 * dispatch traces without the broader ntdll firehose. */
WINE_DEFAULT_DEBUG_CHANNEL(sched);

/* NSPA: track sched thread identity so ntdll_sched_call can detect a
 * self-call (which would deadlock — the sched thread can't dispatch
 * its own pending work while blocked on its own alert). */
static pthread_t sched_pthread_id;
static volatile int sched_thread_alive;

#ifdef __APPLE__

#include <CoreFoundation/CoreFoundation.h>

static struct list poll_users = LIST_INIT( poll_users );

struct poll_user
{
    struct list         entry;
    CFFileDescriptorRef descriptor;
    CFRunLoopSourceRef  source;
    poll_callback       callback;
    void               *private;
};

static void set_descriptor_callbacks( CFFileDescriptorRef descriptor, int events )
{
    if (events & POLLIN) CFFileDescriptorEnableCallBacks( descriptor, kCFFileDescriptorReadCallBack );
    else CFFileDescriptorDisableCallBacks( descriptor, kCFFileDescriptorReadCallBack );
    if (events & POLLOUT) CFFileDescriptorEnableCallBacks( descriptor, kCFFileDescriptorWriteCallBack );
    else CFFileDescriptorDisableCallBacks( descriptor, kCFFileDescriptorWriteCallBack );
}

static void free_poll_user( struct poll_user *user )
{
    CFRunLoopRemoveSource( CFRunLoopGetMain(), user->source, kCFRunLoopCommonModes );
    CFRelease( user->source );
    CFRelease( user->descriptor );
    list_remove( &user->entry );
    free( user );
}

static void descriptor_cb( CFFileDescriptorRef descriptor, CFOptionFlags options, void *context )
{
    struct poll_user *user = context;
    int events = 0;

    if (options & kCFFileDescriptorReadCallBack) events |= POLLIN;
    if (options & kCFFileDescriptorWriteCallBack) events |= POLLOUT;
    events = user->callback( user->private, events );

    if (events) set_descriptor_callbacks( descriptor, events );
    else free_poll_user( user );
}

static void set_poll_user( struct poll_user *user, int events, poll_callback callback, void *private )
{
    user->private = private;
    user->callback = callback;
    set_descriptor_callbacks( user->descriptor, events );
}

static struct poll_user *alloc_poll_user( int fd )
{
    CFFileDescriptorContext descriptor_context = {0};
    struct poll_user *user;

    if (!(descriptor_context.info = user = malloc( sizeof(*user) )) ||
        !(user->descriptor = CFFileDescriptorCreate( NULL, fd, false, descriptor_cb, &descriptor_context )) ||
        !(user->source = CFFileDescriptorCreateRunLoopSource( NULL, user->descriptor, 0 )))
    {
        if (user->descriptor) CFRelease( user->descriptor );
        free( user );
        return NULL;
    }

    set_descriptor_callbacks( user->descriptor, 0 );
    CFRunLoopAddSource( CFRunLoopGetMain(), user->source, kCFRunLoopCommonModes );
    return user;
}

static struct poll_user *get_poll_user( int fd, bool create )
{
    struct poll_user *user;

    LIST_FOR_EACH_ENTRY( user, &poll_users, struct poll_user, entry )
        if (CFFileDescriptorGetNativeDescriptor( user->descriptor ) == fd) return user;

    return create ? alloc_poll_user( fd ) : NULL;
}

struct add_poll_user_params
{
    int             fd;
    int             events;
    poll_callback   callback;
    void           *private;
};

static NTSTATUS add_poll_user( void *private )
{
    struct add_poll_user_params *params = private;
    struct poll_user *user;

    if (!(user = get_poll_user( params->fd, !!params->events ))) return params->events ? STATUS_NO_MEMORY : STATUS_SUCCESS;
    if (params->events) set_poll_user( user, params->events, params->callback, params->private );
    else if (user) free_poll_user( user );

    return STATUS_SUCCESS;
}

NTSTATUS ntdll_sched_poll( int fd, int events, poll_callback callback, void *private )
{
    struct add_poll_user_params params = { .fd = fd, .events = events, .callback = callback, .private = private };
    TRACE( "fd %d, events %d, callback %p, private %p\n", fd, events, callback, private );
    return ntdll_sched_call( add_poll_user, &params );
}

struct timer_params
{
    async_callback callback;
    void          *private;
};

static void timer_cb( CFRunLoopTimerRef timer, void *context )
{
    struct timer_params *params = context;
    params->callback( params->private );
}

NTSTATUS ntdll_sched_timer( const LARGE_INTEGER *timeout, async_callback callback, void *private )
{
    CFRunLoopTimerContext timer_context = {0};
    struct timer_params *params;
    CFRunLoopTimerRef timer;
    LARGE_INTEGER rel;

    TRACE( "timeout %jd, callback %p, private %p\n", (intmax_t)timeout->QuadPart, callback, private );

    if (timeout->QuadPart > 0)
    {
        NtQueryPerformanceCounter( &rel, NULL );
        rel.QuadPart -= timeout->QuadPart;
        timeout = &rel;
    }

    if (!(params = malloc( sizeof(*params) ))) goto failed;
    params->callback = callback;
    params->private = private;
    timer_context.info = params;
    timer_context.release = (void *)free;

    if (!(timer = CFRunLoopTimerCreate( NULL, CFAbsoluteTimeGetCurrent() - timeout->QuadPart / 10000000.0,
                                        0.0, 0, 0, timer_cb, &timer_context ))) goto failed;
    CFRunLoopAddTimer( CFRunLoopGetMain(), timer, kCFRunLoopCommonModes );
    CFRelease( timer );
    return STATUS_SUCCESS;

failed:
    free( params );
    return STATUS_NO_MEMORY;
}

NTSTATUS ntdll_sched_async( async_callback callback, void *private )
{
    CFRunLoopSourceContext source_context = { .perform = callback, .info = private };
    CFRunLoopSourceRef source;

    if (!(source = CFRunLoopSourceCreate( NULL, 0, &source_context ))) return STATUS_NO_MEMORY;
    CFRunLoopAddSource( CFRunLoopGetMain(), source, kCFRunLoopCommonModes );
    CFRunLoopSourceSignal( source );
    CFRelease( source );
    return STATUS_SUCCESS;
}

/* NSPA Phase 2.5: macOS not a target — stubs satisfy unixlib symbol resolution. */
NTSTATUS ntdll_sched_register_poll( int fd, int events, poll_callback callback,
                                    void *private, sched_handle_t *handle )
{
    ERR( "not implemented on macOS\n" );
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS ntdll_sched_register_timer( const LARGE_INTEGER *timeout, async_callback callback,
                                     void *private, sched_handle_t *handle )
{
    ERR( "not implemented on macOS\n" );
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS ntdll_sched_cancel( sched_handle_t handle )
{
    ERR( "not implemented on macOS\n" );
    return STATUS_NOT_IMPLEMENTED;
}

void sched_run(void)
{
/*
    CFRunLoopSourceRef source = CFRunLoopSourceCreate( NULL, 0, NULL );
    CFRunLoopAddSource( CFRunLoopGetCurrent(), source, kCFRunLoopCommonModes );
    CFRelease( source );
*/

    CFRunLoopRun(); /* Should never return, except on error. */
    assert( 0 );
}

#else

struct array
{
    const size_t size;
    void        *data;
    unsigned int count;
    unsigned int alloc;
    char         buf[256];
};

static void *array_get( struct array *array, size_t index )
{
    if (index >= array->count) return NULL;
    return (char *)array->data + index * array->size;
}

static void *array_append( struct array *array, void *data )
{
    /* NSPA: parens fix.  Without them, operator precedence parses this as
     * `(count == alloc) ? alloc : initial_cap`, which evaluates to a truthy
     * `initial_cap` whenever count != alloc and alloc == 0 — forcing a
     * realloc on every append after the first while the inline buffer is
     * still completely unused.  Reported upstream-WIP. */
    if (array->count == (array->alloc ? array->alloc : sizeof(array->buf) / array->size))
    {
        void *ptr = array->data == array->buf ? NULL : array->data;
        size_t alloc = max( 64, array->count * 3 / 2 );
        if (!(ptr = realloc( ptr, alloc * array->size ))) return NULL;
        if (array->data == array->buf) memcpy( ptr, array->buf, array->count * array->size );
        array->alloc = alloc;
        array->data = ptr;
    }

    return memcpy( array_get( array, array->count++ ), data, array->size );
}

static inline void array_remove( struct array *array, size_t index )
{
    char *ptr = array_get( array, index ), *last = array_get( array, array->count - 1 );
    memmove( ptr, ptr + array->size, last - ptr );
    array->count--;
}

#define ARRAY_INIT( array, type ) { .size = sizeof(type), .data = (array).buf }

#define ARRAY_FOR_EACH( cursor, array, type ) \
    for (type *__p = (array)->data, *cursor = NULL; \
         __p - (type *)(array)->data < (array)->count && (cursor = __p, 1); __p++)

/* NSPA Phase 3 ABA-safe cancel: every alloc bumps a process-wide
 * generation counter and embeds the value in the user struct.  The
 * sched_handle_t carries the same gen at register_* time.  On cancel,
 * we compare both pointer AND gen — if the slot has been freed and
 * recycled for a new registration, the stale cancel sees a gen
 * mismatch and returns STATUS_NOT_FOUND instead of incorrectly
 * canceling the new registration.  Counter overflow is benign: the
 * cancel-during-window probability after 4G allocations is vanishing. */
static unsigned long sched_user_gen;     /* atomic; bumped per alloc */

struct poll_user
{
    struct list     entry;      /* entry in queue / polls list */
    int             fd;         /* file descriptor to poll */
    int             events;     /* events to poll */
    poll_callback   callback;   /* callback function */
    void           *private;    /* callback private data */
    unsigned long   gen;        /* NSPA Phase 3: ABA-safe cancel gen */
};

static struct poll_user *alloc_poll_user( int fd, int events, poll_callback callback, void *private )
{
    struct poll_user *user;

    if (!(user = malloc( sizeof(*user) ))) return NULL;
    user->fd       = fd;
    user->events   = events;
    user->callback = callback;
    user->private  = private;
    user->gen      = __atomic_add_fetch( &sched_user_gen, 1, __ATOMIC_RELAXED );

    return user;
}

static void free_poll_user( struct poll_user *user )
{
    list_remove( &user->entry );
    free( user );
}

struct timer_user
{
    struct list     entry;      /* entry in sorted timeout list */
    LONGLONG        when;       /* absolute timeout expiry */
    async_callback  callback;   /* callback function */
    void           *private;    /* callback private data */
    int             canceled;   /* NSPA Phase 2.5: set by ntdll_sched_cancel; skip dispatch + free in next sweep */
    unsigned long   gen;        /* NSPA Phase 3: ABA-safe cancel gen */
};

static struct timer_user *alloc_timer_user( const LARGE_INTEGER *timeout, async_callback callback, void *private )
{
    struct timer_user *user;
    LARGE_INTEGER now;

    if (timeout->QuadPart <= 0)
    {
        NtQueryPerformanceCounter( &now, NULL );
        now.QuadPart -= timeout->QuadPart;
        timeout = &now;
    }

    if (!(user = malloc( sizeof(*user) ))) return NULL;
    user->when     = timeout->QuadPart;
    user->callback = callback;
    user->private  = private;
    user->canceled = 0;
    user->gen      = __atomic_add_fetch( &sched_user_gen, 1, __ATOMIC_RELAXED );

    return user;
}

static void free_timer_user( struct timer_user *user )
{
    list_remove( &user->entry );
    free( user );
}

static pthread_mutex_t sched_lock = PTHREAD_MUTEX_INITIALIZER;
static struct list poll_users = LIST_INIT( poll_users );
static struct list timer_users = LIST_INIT( timer_users );
static int signal_fd;

static void add_poll_user( struct poll_user *user )
{
    static int64_t value = 1;
    struct poll_user *other;

    pthread_mutex_lock( &sched_lock );
    LIST_FOR_EACH_ENTRY( other, &poll_users, struct poll_user, entry )
        if (other->fd == user->fd) other->fd = -1; /* invalidate previous user */
    list_add_tail( &poll_users, &user->entry );
    pthread_mutex_unlock( &sched_lock );

    write( signal_fd, &value, sizeof(value) );
}

static void add_timer_user( struct timer_user *user )
{
    static int64_t value = 1;
    struct timer_user *next;

    pthread_mutex_lock( &sched_lock );
    LIST_FOR_EACH_ENTRY( next, &timer_users, struct timer_user, entry )
        if (next->when >= user->when) break;
    list_add_before( &next->entry, &user->entry );
    pthread_mutex_unlock( &sched_lock );

    write( signal_fd, &value, sizeof(value) );
}

static int get_next_timeout(void)
{
    struct list expired = LIST_INIT(expired);
    struct timer_user *user, *next;
    long long ret = -1;
    LARGE_INTEGER now;

    NtQueryPerformanceCounter( &now, NULL );

    pthread_mutex_lock( &sched_lock );
    LIST_FOR_EACH_ENTRY_SAFE( user, next, &timer_users, struct timer_user, entry )
    {
        /* NSPA Phase 2.5: drop canceled timers without dispatch.  We can
         * see them at the head of the list (when < cutoff) or interleaved
         * with non-canceled later entries; only the head ones matter for
         * the timeout calculation, but we may as well clean a head run. */
        if (user->canceled)
        {
            free_timer_user( user );
            continue;
        }
        if ((ret = user->when - now.QuadPart) > 0) break;
        list_remove( &user->entry );
        list_add_tail( &expired, &user->entry );
    }
    pthread_mutex_unlock( &sched_lock );

    LIST_FOR_EACH_ENTRY_SAFE( user, next, &expired, struct timer_user, entry )
    {
        user->callback( user->private );
        free_timer_user( user );
    }

    if (ret <= 0) return -1;

    /* convert to milliseconds, ceil to avoid spinning with 0 timeout */
    ret = (ret + 9999) / 10000;
    if (ret > INT_MAX) ret = INT_MAX;
    return ret;
}

static int signal_cb( void *private, int events )
{
    int *wait_fd = private;
    int64_t value;
    while (read( *wait_fd, &value, sizeof(value) ) > 0) { /* nothing */ }
    return POLLIN;
}

static void init_context_fds( int *wait, int *signal )
{
    static int fds[2];

#ifdef HAVE_PIPE2
    if (pipe2( fds, O_CLOEXEC ) == -1)
#endif
    {
        if (pipe( fds ) == -1) perror( "pipe" );
        fcntl( fds[0], F_SETFD, FD_CLOEXEC );
        fcntl( fds[1], F_SETFD, FD_CLOEXEC );
    }
    fcntl( fds[0], F_SETFL, O_NONBLOCK );

    *wait = fds[0];
    *signal = fds[1];
}

void sched_run(void)
{
    struct array users = ARRAY_INIT( users, struct poll_user * );
    struct array pfds = ARRAY_INIT( pfds, struct pollfd );
    struct poll_user *user, *next;
    int ret, wait_fd;

    /* NSPA: name the sched thread for debugability + record identity so
     * ntdll_sched_call can detect self-call.  Order matters: identity
     * must be visible before sched_thread_alive is set. */
    sched_pthread_id = pthread_self();
    pthread_setname_np( sched_pthread_id, "wine-sched" );
    __atomic_store_n( &sched_thread_alive, 1, __ATOMIC_RELEASE );

    init_context_fds( &wait_fd, &signal_fd );
    ntdll_sched_poll( wait_fd, POLLIN, signal_cb, &wait_fd );

    /* NSPA Phase 3 consumer #2: queue the periodic observability
     * sampler.  No-op unless NSPA_SCHED_OBS_INTERVAL_MS is set.
     * Registered after init_context_fds so the signal_fd is wired
     * for cross-thread submissions. */
    {
        extern void nspa_sched_obs_init( void );
        nspa_sched_obs_init();
    }

    for (;;)
    {
        users.count = pfds.count = 0;
        pthread_mutex_lock( &sched_lock );
        LIST_FOR_EACH_ENTRY_SAFE( user, next, &poll_users, struct poll_user, entry )
        {
            struct pollfd pfd = { user->fd, user->events };
            if (user->fd == -1 || !user->events) free_poll_user( user );
            else if (!array_append( &users, &user )) ERR( "user pointer allocation failed\n" );
            else if (!array_append( &pfds, &pfd )) ERR( "pollfd allocation failed\n" );
        }
        pthread_mutex_unlock( &sched_lock );

        if ((ret = poll( pfds.data, pfds.count, get_next_timeout() )) < 0)
        {
            WARN( "poll returned %d, error %d\n", ret, errno );
            continue;
        }

        for (unsigned int i = 0; i < pfds.count; i++)
        {
            struct pollfd *pfd = array_get( &pfds, i );
            if (!pfd->revents) continue;

            user = *(struct poll_user **)array_get( &users, i );
            user->events = user->callback( user->private, pfd->revents );
            if (pfd->revents & (POLLHUP | POLLERR)) user->events = 0;

            if (!--ret) break;
        }
    }
}

NTSTATUS ntdll_sched_register_poll( int fd, int events, poll_callback callback,
                                    void *private, sched_handle_t *handle )
{
    struct poll_user *user;

    TRACE( "fd %d, events %d, callback %p, private %p, handle %p\n",
           fd, events, callback, private, handle );

    if (!(user = alloc_poll_user( fd, events, callback, private ))) return STATUS_NO_MEMORY;
    add_poll_user( user );
    if (handle) { handle->priv = user; handle->gen = user->gen; }
    return STATUS_SUCCESS;
}

NTSTATUS ntdll_sched_poll( int fd, int events, poll_callback callback, void *private )
{
    return ntdll_sched_register_poll( fd, events, callback, private, NULL );
}

NTSTATUS ntdll_sched_register_timer( const LARGE_INTEGER *timeout, async_callback callback,
                                     void *private, sched_handle_t *handle )
{
    struct timer_user *user;

    TRACE( "timeout %jd, callback %p, private %p, handle %p\n",
           (intmax_t)timeout->QuadPart, callback, private, handle );

    if (!(user = alloc_timer_user( timeout, callback, private ))) return STATUS_NO_MEMORY;
    add_timer_user( user );
    if (handle) { handle->priv = user; handle->gen = user->gen; }
    return STATUS_SUCCESS;
}

NTSTATUS ntdll_sched_timer( const LARGE_INTEGER *timeout, async_callback callback, void *private )
{
    return ntdll_sched_register_timer( timeout, callback, private, NULL );
}

/* NSPA Phase 2.5/3: cancel a previously-registered poll or timer.
 *
 * Walks both poll_users and timer_users under sched_lock; matches by
 * (pointer, generation).  Generation match is the ABA-safe element:
 * if the slot has been freed and recycled for a new registration, the
 * stale cancel sees gen mismatch and returns STATUS_NOT_FOUND
 * harmlessly instead of incorrectly canceling the new registration.
 *
 * For polls: invalidates fd to -1 (existing "free on next iteration"
 * pattern).
 * For timers: marks canceled flag (skip-and-free in get_next_timeout's
 * next sweep).
 *
 * Lifetime contract per include/wine/unixlib.h — handle is single-use,
 * but double-cancel is now a benign STATUS_NOT_FOUND (was an ABA risk
 * before Phase 3). */
NTSTATUS ntdll_sched_cancel( sched_handle_t handle )
{
    static int64_t value = 1;
    struct poll_user *poll_u, *poll_next;
    struct timer_user *timer_u, *timer_next;
    int found = 0;

    TRACE( "handle priv=%p gen=%lu\n", handle.priv, handle.gen );

    if (!handle.priv) return STATUS_INVALID_PARAMETER;

    pthread_mutex_lock( &sched_lock );
    LIST_FOR_EACH_ENTRY_SAFE( poll_u, poll_next, &poll_users, struct poll_user, entry )
    {
        if ((void *)poll_u != handle.priv) continue;
        if (poll_u->gen != handle.gen) break;   /* ABA: slot recycled — stop, don't cancel new entry */
        poll_u->fd = -1;
        found = 1;
        break;
    }
    if (!found) LIST_FOR_EACH_ENTRY_SAFE( timer_u, timer_next, &timer_users, struct timer_user, entry )
    {
        if ((void *)timer_u != handle.priv) continue;
        if (timer_u->gen != handle.gen) break;  /* ABA: slot recycled — stop, don't cancel new entry */
        timer_u->canceled = 1;
        found = 1;
        break;
    }
    pthread_mutex_unlock( &sched_lock );

    if (found) write( signal_fd, &value, sizeof(value) );  /* wake sched thread to process the cancel */
    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS ntdll_sched_async( async_callback callback, void *private )
{
    static LARGE_INTEGER zero;
    return ntdll_sched_timer( &zero, callback, private );
}

#endif

struct call_params
{
    call_callback  callback;
    void          *private;
    HANDLE         tid;
    NTSTATUS       status;
};

static void execute_call( void *context )
{
    struct call_params *params = context;
    NTSTATUS status = params->callback( params->private );
    assert( status != STATUS_PENDING );
    InterlockedExchange( &params->status, status );
    NtAlertThreadByThreadId( params->tid );
}

NTSTATUS ntdll_sched_call( call_callback callback, void *private )
{
    struct call_params *params;
    NTSTATUS status;

    TRACE( "callback %p, private %p\n", callback, private );

    /* NSPA: detect self-call from the sched thread itself.  Without this
     * fast path, async dispatch would post the callback to the sched
     * thread and the same thread would block in NtWaitForAlertByThreadId
     * waiting for itself to dispatch — guaranteed deadlock since the
     * sched thread is the dispatcher.  Run inline instead. */
    if (__atomic_load_n( &sched_thread_alive, __ATOMIC_ACQUIRE ) &&
        pthread_equal( pthread_self(), sched_pthread_id ))
        return callback( private );

    if (!(params = malloc( sizeof(*params) ))) return STATUS_NO_MEMORY;
    params->callback = callback;
    params->private = private;
    params->tid = NtCurrentTeb()->ClientId.UniqueThread;
    params->status = STATUS_PENDING;

    if ((status = ntdll_sched_async( execute_call, params ))) ERR( "failed to schedule call, status %#x\n", status );
    else while ((status = ReadNoFence( &params->status )) == STATUS_PENDING) NtWaitForAlertByThreadId( NULL, NULL );

    free( params );
    return status;
}
