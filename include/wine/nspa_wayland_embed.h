/*
 * wine-nspa: native Wayland embedding for winelib hosts.
 *
 * This is the Wayland counterpart to nspa_x11_embed.h.  Where the X11
 * path reparents a wine X11 window under a host X11 window, the Wayland
 * path makes the plugin's wl_surface a wl_subsurface of the host's
 * wl_surface.  wl_subsurface only works when both surfaces live on the
 * SAME wayland client connection, so the host and wine must share one
 * wl_display.  That is only possible because Element and the wine
 * plugins run in a single winelib process (one address space, one
 * libwayland-client.so), which lets the host hand its wl_display to
 * winewayland.drv.
 *
 *
 * 1. Display injection (process-global, once, before any wine GUI)
 * ----------------------------------------------------------------
 *
 * The host calls:
 *
 *     wine_nspa_wayland_set_display(host_wl_display);
 *
 * BEFORE the first wine HWND / NtUser graphics call -- typically very
 * early in main(), before the JUCE MessageManager spins up.  After this,
 * winewayland.drv binds its own wayland proxies (wl_compositor,
 * wl_subcompositor, wl_shm, xdg_wm_base, wp_viewporter, wl_seat) on the
 * host's connection instead of opening its own with wl_display_connect.
 *
 * Transport: rather than a driver export (which would lose the load-order
 * race -- winewayland.drv's DllMain runs its init, and thus
 * wl_display_connect, the instant the DLL loads, before any host call
 * could run), the pointer is published via an environment variable that
 * winewayland.drv reads inside wayland_process_init.  Because the host
 * sets it before the driver is ever loaded, the driver sees it on its
 * very first init and never opens a second connection.
 *
 * The value is "<pid>:<hexptr>".  winewayland.drv honours it ONLY when
 * <pid> equals its own getpid(), so child wine helper processes
 * (services.exe, plugplay.exe, ...) that inherit the environment do not
 * try to dereference a pointer from the parent's address space; they
 * fall back to a normal wl_display_connect.
 *
 * The wl_display pointer must come from the SAME libwayland-client.so the
 * wine driver uses.  In a single winelib process there is exactly one
 * such library mapped, so the host's wl_display (e.g. from JUCE's
 * WaylandWindowSystem) is directly usable by winewayland.drv.
 *
 * If the variable is unset (normal wayland session, no host injection),
 * winewayland.drv behaves exactly as upstream.  There is no behavioural
 * change for non-injected processes -- this is an all-or-nothing,
 * per-process opt-in.
 *
 *
 * 2. Per-window embed (mirrors WM_X11DRV_NSPA_EMBED_WINDOW)
 * --------------------------------------------------------
 *
 * Once a plugin HWND exists, send WM_WAYLANDDRV_NSPA_EMBED_WINDOW to it:
 *
 *     WPARAM = (uintptr_t) host parent wl_surface*
 *     LPARAM = packed parent-relative position:
 *               low  16 bits = (int16_t) peerX
 *               bits 16..31  = (int16_t) peerY
 *              (MAKELPARAM-style packing; pass 0 for parent origin)
 *
 * Wine makes the HWND's wayland_surface a wl_subsurface of the given
 * foreign wl_surface at (peerX, peerY) and flips data->nspa_embedded.
 * Subsequent SetWindowPos position changes translate to
 * wl_subsurface_set_position only -- no xdg_toplevel reconfigure.
 *
 * Surface-role timing contract: the plugin's wl_surface must NOT have
 * committed a buffer in xdg_toplevel role before this message lands.
 * The host sends it in componentPeerChanged, before IPlugView::attached
 * / effEditOpen, so no buffer has been committed yet -- same ordering as
 * the X11 path.
 *
 * Completion: after wine has installed the subsurface it posts
 * WM_WAYLANDDRV_NSPA_EMBED_DONE to the same HWND via NtUserPostMessage
 * (async; wparam = lparam = 0 reserved).  Consumers that need a settled
 * "embed handshake done" signal can wait for it in their WndProc.
 *
 *
 * Consumer pump discipline (identical to the X11 path): the message pump
 * draining the embedded HWND's thread queue MUST be bounded (time or
 * count) and SHOULD dispatch input messages ahead of the general drain,
 * or a heavy plugin WM_TIMER handler can starve the host's event loop.
 * See nspa_x11_embed.h for the full discussion and reference pumps.
 *
 * Copyright 2026 Wine-NSPA contributors
 */

#ifndef __WINE_NSPA_WAYLAND_EMBED_H
#define __WINE_NSPA_WAYLAND_EMBED_H

/* Host-mode flag.  Set in the environment by a winelib host's launcher
 * BEFORE wine starts.  When set, winewayland.drv does NOT open its own
 * wayland connection or run its own event-loop reader thread; it adopts the
 * host's wl_display (Element owns the connection and drives the event loop,
 * wine only renders plugin surfaces into it).  When UNSET, winewayland.drv
 * behaves exactly as upstream -- so standalone wine is unaffected. */
#define NSPA_WAYLAND_HOST_ENV "WINE_NSPA_WAYLAND_HOST"

/* Environment variable the host (JUCE) uses to hand its wl_display to
 * winewayland.drv (only consulted in host mode).  Value: "<hexptr>". */
#define NSPA_WAYLAND_DISPLAY_ENV "WINE_NSPA_WAYLAND_DISPLAY"

/* Driver-private window messages.  Mirror WM_X11DRV_NSPA_EMBED_*.  They
 * sit in Wine's documented WM_WINE_FIRST_DRIVER_MSG range (0x80001000+)
 * so they cannot collide with application-defined WM_USER messages, and
 * they are distinct from the X11 values (0x80001004/0x80001005). */
#define WM_WAYLANDDRV_NSPA_EMBED_WINDOW 0x80001006
#define WM_WAYLANDDRV_NSPA_EMBED_DONE   0x80001007

#ifndef NSPA_WAYLAND_EMBED_NO_HELPER

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Host-side helper.  Publishes the wl_display pointer (PID-stamped) into
 * the environment so winewayland.drv can adopt it at init.  Call once,
 * before the first wine GUI / NtUser call. */
static inline void wine_nspa_wayland_set_display(void *wl_display)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "%ld:%p", (long)getpid(), wl_display);
    setenv(NSPA_WAYLAND_DISPLAY_ENV, buf, 1);
}

#endif /* NSPA_WAYLAND_EMBED_NO_HELPER */

#endif /* __WINE_NSPA_WAYLAND_EMBED_H */
