/*
 * Wayland core handling
 *
 * Copyright (c) 2020 Alexandros Frantzis for Collabora Ltd
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

#include "waylanddrv.h"

#include "wine/debug.h"
#include "wine/nspa_wayland_embed.h"

#include <stdlib.h>
#include <unistd.h>

WINE_DEFAULT_DEBUG_CHANNEL(waylanddrv);

struct wayland process_wayland =
{
    .seat.mutex = PTHREAD_MUTEX_INITIALIZER,
    .keyboard.mutex = PTHREAD_MUTEX_INITIALIZER,
    .pointer.mutex = PTHREAD_MUTEX_INITIALIZER,
    .text_input.mutex = PTHREAD_MUTEX_INITIALIZER,
    .data_device.mutex = PTHREAD_MUTEX_INITIALIZER,
    .output_list = {&process_wayland.output_list, &process_wayland.output_list},
    .output_mutex = PTHREAD_MUTEX_INITIALIZER
};

/**********************************************************************
 *          xdg_wm_base handling
 */

static void xdg_wm_base_handle_ping(void *data, struct xdg_wm_base *shell,
                                    uint32_t serial)
{
    xdg_wm_base_pong(shell, serial);
}

static const struct xdg_wm_base_listener xdg_wm_base_listener =
{
    xdg_wm_base_handle_ping
};

/**********************************************************************
 *          wl_seat handling
 */

static void wl_seat_handle_capabilities(void *data, struct wl_seat *seat,
                                        enum wl_seat_capability caps)
{
    if ((caps & WL_SEAT_CAPABILITY_POINTER) && !process_wayland.pointer.wl_pointer)
        wayland_pointer_init(wl_seat_get_pointer(seat));
    else if (!(caps & WL_SEAT_CAPABILITY_POINTER) && process_wayland.pointer.wl_pointer)
        wayland_pointer_deinit();

    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !process_wayland.keyboard.wl_keyboard)
        wayland_keyboard_init(wl_seat_get_keyboard(seat));
    else if (!(caps & WL_SEAT_CAPABILITY_KEYBOARD) && process_wayland.keyboard.wl_keyboard)
        wayland_keyboard_deinit();
}

static void wl_seat_handle_name(void *data, struct wl_seat *seat, const char *name)
{
}

static const struct wl_seat_listener seat_listener =
{
    wl_seat_handle_capabilities,
    wl_seat_handle_name
};

/**********************************************************************
 *          Registry handling
 */

static void registry_handle_global(void *data, struct wl_registry *registry,
                                   uint32_t id, const char *interface,
                                   uint32_t version)
{
    TRACE("interface=%s version=%u id=%u\n", interface, version, id);

    if (strcmp(interface, "wl_output") == 0)
    {
        if (!wayland_output_create(id, version))
            ERR("Failed to create wayland_output for global id=%u\n", id);
    }
    else if (strcmp(interface, "zxdg_output_manager_v1") == 0)
    {
        struct wayland_output *output;

        process_wayland.zxdg_output_manager_v1 =
            wl_registry_bind(registry, id, &zxdg_output_manager_v1_interface,
                             version < 3 ? version : 3);

        /* Add zxdg_output_v1 to existing outputs. */
        wl_list_for_each(output, &process_wayland.output_list, link)
            wayland_output_use_xdg_extension(output);
    }
    else if (strcmp(interface, "wl_compositor") == 0)
    {
        process_wayland.wl_compositor =
            wl_registry_bind(registry, id, &wl_compositor_interface, 4);
    }
    else if (strcmp(interface, "xdg_wm_base") == 0)
    {
        /* Bind version 2 so that compositors (e.g., sway) can properly send tiled
         * states, instead of falling back to (ab)using the maximized state. */
        process_wayland.xdg_wm_base =
            wl_registry_bind(registry, id, &xdg_wm_base_interface,
                             version < 2 ? version : 2);
        xdg_wm_base_add_listener(process_wayland.xdg_wm_base, &xdg_wm_base_listener, NULL);
    }
    else if (strcmp(interface, "wl_shm") == 0)
    {
        process_wayland.wl_shm = wl_registry_bind(registry, id, &wl_shm_interface, 1);
    }
    else if (strcmp(interface, "wl_seat") == 0)
    {
        struct wayland_seat *seat = &process_wayland.seat;
        if (seat->wl_seat)
        {
            WARN("Only a single seat is currently supported, ignoring additional seats.\n");
            return;
        }
        pthread_mutex_lock(&seat->mutex);
        seat->wl_seat = wl_registry_bind(registry, id, &wl_seat_interface,
                                         version < 8 ? version : 8);
        seat->global_id = id;
        wl_seat_add_listener(seat->wl_seat, &seat_listener, NULL);
        pthread_mutex_unlock(&seat->mutex);
        if (process_wayland.zwp_text_input_manager_v3) wayland_text_input_init();
        /* Recreate the data device for the new seat. */
        if (process_wayland.data_device.zwlr_data_control_device_v1 ||
            process_wayland.data_device.wl_data_device)
        {
            wayland_data_device_init();
        }
    }
    else if (strcmp(interface, "wp_viewporter") == 0)
    {
        process_wayland.wp_viewporter =
            wl_registry_bind(registry, id, &wp_viewporter_interface, 1);
    }
    else if (strcmp(interface, "wl_subcompositor") == 0)
    {
        process_wayland.wl_subcompositor =
            wl_registry_bind(registry, id, &wl_subcompositor_interface, 1);
    }
    else if (strcmp(interface, "zwp_pointer_constraints_v1") == 0)
    {
        process_wayland.zwp_pointer_constraints_v1 =
            wl_registry_bind(registry, id, &zwp_pointer_constraints_v1_interface, 1);
    }
    else if (strcmp(interface, "zwp_relative_pointer_manager_v1") == 0)
    {
        process_wayland.zwp_relative_pointer_manager_v1 =
            wl_registry_bind(registry, id, &zwp_relative_pointer_manager_v1_interface, 1);
    }
    else if (strcmp(interface, "zwp_text_input_manager_v3") == 0)
    {
        process_wayland.zwp_text_input_manager_v3 =
            wl_registry_bind(registry, id, &zwp_text_input_manager_v3_interface, 1);
        if (process_wayland.seat.wl_seat) wayland_text_input_init();
    }
    else if (strcmp(interface, "zwlr_data_control_manager_v1") == 0)
    {
        process_wayland.zwlr_data_control_manager_v1 =
            wl_registry_bind(registry, id, &zwlr_data_control_manager_v1_interface, 1);
    }
    else if (strcmp(interface, "wl_data_device_manager") == 0)
    {
        process_wayland.wl_data_device_manager =
            wl_registry_bind(registry, id, &wl_data_device_manager_interface, 2);
    }
    else if (strcmp(interface, "xdg_toplevel_icon_manager_v1") == 0)
    {
        process_wayland.xdg_toplevel_icon_manager_v1 =
            wl_registry_bind(registry, id, &xdg_toplevel_icon_manager_v1_interface, 1);
    }
    else if (strcmp(interface, "wp_cursor_shape_manager_v1") == 0)
    {
        process_wayland.wp_cursor_shape_manager_v1 =
            wl_registry_bind(registry, id, &wp_cursor_shape_manager_v1_interface,
                             version < 2 ? version : 2);
    }
}

static void registry_handle_global_remove(void *data, struct wl_registry *registry,
                                          uint32_t id)
{
    struct wayland_output *output, *tmp;
    struct wayland_seat *seat;

    TRACE("id=%u\n", id);

    wl_list_for_each_safe(output, tmp, &process_wayland.output_list, link)
    {
        if (output->global_id == id)
        {
            TRACE("removing output->name=%s\n", output->current.name);
            wayland_output_destroy(output);
            return;
        }
    }

    seat = &process_wayland.seat;
    if (seat->wl_seat && seat->global_id == id)
    {
        TRACE("removing seat\n");
        if (process_wayland.pointer.wl_pointer) wayland_pointer_deinit();
        if (process_wayland.text_input.zwp_text_input_v3) wayland_text_input_deinit();
        pthread_mutex_lock(&seat->mutex);
        wl_seat_release(seat->wl_seat);
        seat->wl_seat = NULL;
        seat->global_id = 0;
        pthread_mutex_unlock(&seat->mutex);
    }
}

static const struct wl_registry_listener registry_listener = {
    registry_handle_global,
    registry_handle_global_remove
};

/**********************************************************************
 *          nspa_get_host_display
 *
 *  wine-nspa: returns the host's wl_display when a winelib host (Element/JUCE)
 *  has published one via WINE_NSPA_WAYLAND_DISPLAY.  Only consulted in host
 *  mode.  The host and winewayland.drv share one process and one
 *  libwayland-client.so, so the pointer is valid here.  NULL means the host
 *  has not connected yet (we stay deferred).
 */
static struct wl_display *nspa_get_host_display(void)
{
    const char *env = getenv(NSPA_WAYLAND_DISPLAY_ENV);
    if (!env || !env[0]) return NULL;
    return (struct wl_display *)(UINT_PTR)strtoull(env, NULL, 0);
}

/**********************************************************************
 *          wayland_bind_globals
 *
 *  Create the registry, bind globals and verify the required ones, on the
 *  already-set process_wayland.wl_display.  When process_wayland.wl_event_queue
 *  is set (standalone), the registry lives on our own queue (dispatched by our
 *  reader thread); when it is NULL (host mode), the registry lives on the
 *  host display's DEFAULT queue, which the host's event loop dispatches.
 */
static BOOL wayland_bind_globals(void)
{
    struct wl_display *wl_display_wrapper;

    TRACE("wl_display=%p own_queue=%p\n",
          process_wayland.wl_display, process_wayland.wl_event_queue);

    if (process_wayland.wl_event_queue)
    {
        if (!(wl_display_wrapper = wl_proxy_create_wrapper(process_wayland.wl_display)))
        {
            ERR("Failed to create proxy wrapper for wl_display\n");
            return FALSE;
        }
        wl_proxy_set_queue((struct wl_proxy *) wl_display_wrapper,
                           process_wayland.wl_event_queue);
        process_wayland.wl_registry = wl_display_get_registry(wl_display_wrapper);
        wl_proxy_wrapper_destroy(wl_display_wrapper);
    }
    else
    {
        /* Host mode: bind on the host display's default queue. */
        process_wayland.wl_registry = wl_display_get_registry(process_wayland.wl_display);
    }
    if (!process_wayland.wl_registry)
    {
        ERR("Failed to get to wayland registry\n");
        return FALSE;
    }

    /* Populate registry */
    wl_registry_add_listener(process_wayland.wl_registry, &registry_listener, NULL);

    /* We need two roundtrips. One to get and bind globals, one to handle all
     * initial events produced from registering the globals. */
    if (process_wayland.wl_event_queue)
    {
        wl_display_roundtrip_queue(process_wayland.wl_display, process_wayland.wl_event_queue);
        wl_display_roundtrip_queue(process_wayland.wl_display, process_wayland.wl_event_queue);
    }
    else
    {
        wl_display_roundtrip(process_wayland.wl_display);
        wl_display_roundtrip(process_wayland.wl_display);
    }

    /* Check for required protocol globals. */
    if (!process_wayland.wl_compositor)
    {
        ERR("Wayland compositor doesn't support wl_compositor\n");
        return FALSE;
    }
    if (!process_wayland.xdg_wm_base)
    {
        ERR("Wayland compositor doesn't support xdg_wm_base\n");
        return FALSE;
    }
    if (!process_wayland.wl_shm)
    {
        ERR("Wayland compositor doesn't support wl_shm\n");
        return FALSE;
    }
    if (!process_wayland.wl_subcompositor)
    {
        ERR("Wayland compositor doesn't support wl_subcompositor\n");
        return FALSE;
    }
    if (!process_wayland.wp_viewporter)
    {
        ERR("Wayland compositor doesn't support wp_viewporter\n");
        return FALSE;
    }

    /* Check for optional globals. */
    if (!process_wayland.zwp_pointer_constraints_v1)
        ERR("Wayland compositor doesn't support optional zwp_pointer_constraints_v1 (pointer locking/confining won't work)\n");

    if (!process_wayland.zwp_relative_pointer_manager_v1)
        ERR("Wayland compositor doesn't support optional zwp_relative_pointer_manager_v1 (relative motion won't work)\n");

    if (!process_wayland.zwp_text_input_manager_v3)
        ERR("Wayland compositor doesn't support optional zwp_text_input_manager_v3 (host input methods won't work)\n");

    if (!process_wayland.zwlr_data_control_manager_v1)
    {
        if (!process_wayland.wl_data_device_manager)
            ERR("Wayland compositor doesn't support optional wl_data_device_manager (clipboard won't work)\n");
        else
            ERR("Wayland compositor doesn't support optional zwlr_data_control_manager_v1 (clipboard functionality will be limited)\n");
    }

    if (!process_wayland.xdg_toplevel_icon_manager_v1)
        ERR("Wayland compositor doesn't support xdg_toplevel_icon_manager_v1 (window icons will not be supported)\n");

    process_wayland.initialized = TRUE;

    return TRUE;
}

/**********************************************************************
 *          wayland_process_init
 *
 *  Initialise the per process wayland objects.
 *
 *  In host mode (a winelib host owns the connection) we DEFER: no connect, no
 *  own queue, no reader thread.  The real init happens lazily in
 *  wayland_ensure_init once the host has published its wl_display.  Standalone
 *  (no host) is the upstream path: connect + own queue + bind.
 */
BOOL wayland_process_init(void)
{
    const char *host = getenv(NSPA_WAYLAND_HOST_ENV);

    if (host && host[0])
    {
        process_wayland.host_mode = TRUE;
        TRACE("nspa: host mode -- deferring wayland connection (host owns it)\n");
        return TRUE;
    }

    process_wayland.wl_display = wl_display_connect(NULL);
    if (!process_wayland.wl_display)
        return FALSE;

    if (!(process_wayland.wl_event_queue = wl_display_create_queue(process_wayland.wl_display)))
    {
        ERR("Failed to create event queue\n");
        return FALSE;
    }

    return wayland_bind_globals();
}

/**********************************************************************
 *          wayland_ensure_init
 *
 *  Complete the deferred host-mode init by adopting the host's wl_display.
 *  Idempotent.  Returns TRUE once initialized; FALSE while the host has not
 *  yet published a display (caller should treat wayland as unavailable for
 *  now).  Outside host mode it just reports the existing init state.
 */
BOOL wayland_ensure_init(void)
{
    /* One-shot init guard.  Lock-free CAS, NOT a mutex: this can run on the
     * SCHED_FIFO message thread and bind_globals below does blocking wayland
     * roundtrips -- a raw pthread mutex is not priority-inheriting (inversion
     * risk), and wine-nspa avoids holding plain pthread locks on RT threads.
     * No lock is held across the init work, so there is nothing to invert. */
    static int initializing; /* 0 = free, 1 = a thread owns the init */
    struct wl_display *host;
    BOOL ret;

    if (process_wayland.initialized) return TRUE;
    if (!process_wayland.host_mode) return FALSE;

    if (!__sync_bool_compare_and_swap(&initializing, 0, 1))
        return process_wayland.initialized; /* another thread owns the init */

    if (process_wayland.initialized) /* a peer finished between our checks */
    {
        __sync_lock_release(&initializing);
        return TRUE;
    }

    if (!(host = nspa_get_host_display()))
    {
        __sync_lock_release(&initializing); /* retry on a later call */
        TRACE("nspa: host display not published yet; staying deferred\n");
        return FALSE;
    }

    /* Adopt the host's display, but keep our OWN event queue + reader thread
     * (like standalone, just on the adopted connection).  This is essential:
     * a plugin's modal loops (TrackPopupMenu, dialogs) bypass the host's event
     * loop, so the host's reader is NOT pumping wayland while a menu is up --
     * our own reader thread must keep dispatching our queue (winex11.drv reads
     * X11 independently for exactly this reason).  Our reader and the host's
     * loop coordinate via libwayland's prepare_read/read_events barrier and
     * dispatch separate queues, so they coexist without wrong-thread handlers. */
    process_wayland.wl_display = host;
    if (!(process_wayland.wl_event_queue = wl_display_create_queue(host)))
    {
        __sync_lock_release(&initializing);
        ERR("nspa: failed to create event queue on adopted display\n");
        return FALSE;
    }
    ERR("nspa: adopting host wl_display=%p (own queue + reader thread)\n",
        (void *)host);

    ret = wayland_bind_globals(); /* sets process_wayland.initialized on success */
    if (!ret) __sync_lock_release(&initializing); /* failed -- allow a retry */
    /* On success leave `initializing` held: init is one-shot. */
    return ret;
}
