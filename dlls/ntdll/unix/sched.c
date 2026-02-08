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

#include <errno.h>
#include <fcntl.h>
#include <poll.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "unix_private.h"

#include "wine/list.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ntdll);

#ifdef __APPLE__

#include <CoreFoundation/CoreFoundation.h>

NTSTATUS ntdll_sched_poll( int fd, int events, poll_callback callback, void *private )
{
    ERR( "not implemented!\n" );
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

static pthread_mutex_t sched_lock = PTHREAD_MUTEX_INITIALIZER;
static struct list poll_users = LIST_INIT( poll_users );
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

        if ((ret = poll( pfds.data, pfds.count, -1 )) < 0)
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

#endif
