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

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

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
    if (array->count == array->alloc ? array->alloc : sizeof(array->buf) / array->size)
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

struct poll_user
{
    struct list     entry;      /* entry in queue / polls list */
    int             fd;         /* file descriptor to poll */
    int             events;     /* events to poll */
    poll_callback   callback;   /* callback function */
    void           *private;    /* callback private data */
};

static struct poll_user *alloc_poll_user( int fd, int events, poll_callback callback, void *private )
{
    struct poll_user *user;

    if (!(user = malloc( sizeof(*user) ))) return NULL;
    user->fd       = fd;
    user->events   = events;
    user->callback = callback;
    user->private  = private;

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

    init_context_fds( &wait_fd, &signal_fd );
    ntdll_sched_poll( wait_fd, POLLIN, signal_cb, &wait_fd );

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

NTSTATUS ntdll_sched_poll( int fd, int events, poll_callback callback, void *private )
{
    struct poll_user *user;

    TRACE( "fd %d, events %d, callback %p, private %p\n", fd, events, callback, private );

    if (!(user = alloc_poll_user( fd, events, callback, private ))) return STATUS_NO_MEMORY;
    add_poll_user( user );
    return STATUS_SUCCESS;
}

NTSTATUS ntdll_sched_timer( const LARGE_INTEGER *timeout, async_callback callback, void *private )
{
    struct timer_user *user;

    TRACE( "timeout %jd, callback %p, private %p\n", (intmax_t)timeout->QuadPart, callback, private );

    if (!(user = alloc_timer_user( timeout, callback, private ))) return STATUS_NO_MEMORY;
    add_timer_user( user );
    return STATUS_SUCCESS;
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
