/*
 * NSPA msg-ring v2 Phase A — redraw_window push ring (server side).
 *
 * Client (dlls/win32u/dce.c::redraw_window_rects) appends entries to
 * nspa_queue_bypass_shm_t::nspa_redraw_ring; this drain runs on every
 * request handler dispatched from the queue's thread, applies pending
 * entries to the window state via nspa_redraw_apply (server/window.c),
 * and advances the consumer tail.  SPSC: single producer (queue
 * thread), single consumer (wineserver main thread).
 */

#include "config.h"

#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winuser.h"

#include "../object.h"
#include "../thread.h"
#include "../user.h"
#include "redraw_ring.h"

void nspa_redraw_ring_drain( struct thread *thread )
{
    nspa_queue_bypass_shm_t *shm;
    nspa_redraw_ring_t *ring;
    unsigned int tail, head;
    unsigned int saved_error;

    if (!thread) return;
    if (!(shm = nspa_queue_bypass_shm( thread ))) return;
    ring = (nspa_redraw_ring_t *)&shm->nspa_redraw_ring;

    head = __atomic_load_n( &ring->head, __ATOMIC_ACQUIRE );
    tail = ring->tail;
    if (tail == head) return;  /* empty-ring fast path: no save/restore needed */

    /* The drain runs at the top of the request dispatcher with current==thread,
     * BEFORE clear_error() has reached the actual handler.  Any apply that hits
     * a stale handle (window destroyed between client push and drain), a region
     * validation failure, or a server alloc failure will set_error() — and that
     * error then leaks into the otherwise-successful reply of the unrelated
     * request that triggered the drain.  Symptoms: caller sees STATUS_INVALID_
     * WINDOW_HANDLE / STATUS_INVALID_PARAMETER on a successful get_update_region
     * / get_visible_region / get_message; treats valid reply data as failed,
     * tight-loops repaint, eventually wedges KWin/X11.  Same end picture as the
     * gamma offset corruption fix — different mechanism.  Snapshot here, restore
     * after the loop. */
    saved_error = thread->error;

    while (tail != head)
    {
        nspa_redraw_slot_t *slot = (nspa_redraw_slot_t *)&ring->slots[tail % NSPA_REDRAW_RING_SLOTS];
        unsigned int state = __atomic_load_n( &slot->state, __ATOMIC_ACQUIRE );
        unsigned int flags;
        user_handle_t window;
        unsigned int rect_count;
        struct rectangle local_rects[NSPA_REDRAW_INLINE_RECTS];
        unsigned int i;

        /* Producer is mid-write — stop here; the slot will be ready
         * by the time the next request triggers another drain. */
        if (state != NSPA_REDRAW_STATE_READY) break;

        /* Snapshot under the READY barrier we just acquired. */
        window     = slot->window;
        flags      = slot->flags;
        rect_count = slot->rect_count;
        if (rect_count > NSPA_REDRAW_INLINE_RECTS) rect_count = 0;
        for (i = 0; i < rect_count; i++) local_rects[i] = slot->rects[i];

        nspa_redraw_apply( thread, window, flags,
                           rect_count ? local_rects : NULL,
                           rect_count * sizeof(struct rectangle) );

        __atomic_store_n( &slot->state, NSPA_REDRAW_STATE_EMPTY, __ATOMIC_RELEASE );
        tail++;
        __atomic_store_n( &ring->tail, tail, __ATOMIC_RELEASE );
    }

    thread->error = saved_error;
    if (thread == current) global_error = saved_error;
}
