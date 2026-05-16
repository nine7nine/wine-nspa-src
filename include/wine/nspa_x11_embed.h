/*
 * wine-nspa: atomic X11 embedding for winelib hosts.
 *
 * Send WM_X11DRV_NSPA_EMBED_WINDOW to a top-level HWND with
 * WPARAM = X11 Window of the external parent.  Wine atomically:
 *   - XReparents the HWND's wine_x11_window under the given parent
 *   - Flips managed=TRUE, embedded=TRUE, override_redirect=FALSE
 *   - Sets data->embedder and data->parent for XEMBED + host_window
 *     tracking
 *
 * After embedding, position changes via SetWindowPos() update Wine's
 * internal WND rect (so USER32 mouse hit-testing remains correct) but
 * are NOT issued as XConfigureWindow at the X11 level — the embedder
 * owns positioning.  This replaces the wrapper-window +
 * SubstructureRedirect + synthetic-ConfigureNotify pattern that
 * winelib hosts (Element, yabridge, LinVst, ...) would otherwise need
 * to reimplement.
 *
 * Size changes still propagate to X11 normally; the embedder is
 * responsible for sizing its own parent window such that the embedded
 * wine_x11_window can render at the size the plugin reports.
 *
 * Example:
 *   HWND hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, ..., WS_POPUP, ...);
 *   Window parent = (Window) juce_peer->getNativeHandle();
 *   SendMessageW(hwnd, WM_X11DRV_NSPA_EMBED_WINDOW, (WPARAM)parent, 0);
 *
 * Idempotent: a second call on an already-embedded HWND is a no-op.
 *
 * Copyright 2026 Wine-NSPA contributors
 */

#ifndef __WINE_NSPA_X11_EMBED_H
#define __WINE_NSPA_X11_EMBED_H

/* The numeric value is reserved in winex11.drv's
 * enum x11drv_window_messages (x11drv.h).  It sits in Wine's
 * documented WM_WINE_FIRST_DRIVER_MSG range (0x80001000+) so it
 * cannot collide with application-defined WM_USER messages.
 *
 * Consumers don't need to (and can't) include winex11.drv's private
 * x11drv.h — this define is the supported interface. */
#define WM_X11DRV_NSPA_EMBED_WINDOW 0x80001004

#endif /* __WINE_NSPA_X11_EMBED_H */
