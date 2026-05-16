/*
 * wine-nspa: atomic X11 embedding for winelib hosts.
 *
 * Send WM_X11DRV_NSPA_EMBED_WINDOW to a top-level HWND with:
 *   WPARAM = X11 Window of the external parent
 *   LPARAM = packed parent-relative position:
 *             low  16 bits = (int16_t) peerX
 *             bits 16..31  = (int16_t) peerY
 *            (use MAKELPARAM-style packing; pass 0 to embed at
 *             parent origin)
 *
 * Wine atomically:
 *   - XReparents the HWND's wine_x11_window under the given parent
 *     at (peerX, peerY)
 *   - Flips managed=TRUE, embedded=TRUE, override_redirect=FALSE
 *   - Sets data->embedder and data->parent for XEMBED + host_window
 *     tracking
 *
 * The position parameter is critical: Wine's embedded-mode position
 * lock (window_set_config in dlls/winex11.drv/window.c) clamps
 * subsequent SetWindowPos position changes to whatever pending_state.
 * rect.position was when data->embedded flipped TRUE.  Reparenting at
 * the correct (peerX, peerY) before the flag flip ensures the locked
 * position matches the host's intended layout.  Passing 0 is fine
 * only if you intend the embedded window to live at parent's origin
 * for its full lifetime.
 *
 * After embedding, position changes via SetWindowPos() update Wine's
 * internal WND rect (so USER32 mouse hit-testing remains correct in
 * its absolute-coords; the LOCKED position is what plugin GDI uses
 * for its own coord math) but are NOT issued as XConfigureWindow at
 * the X11 level — the embedder owns positioning.  This replaces the
 * wrapper-window + SubstructureRedirect + synthetic-ConfigureNotify
 * pattern that winelib hosts (Element, yabridge, LinVst, ...) would
 * otherwise need to reimplement.
 *
 * Size changes still propagate to X11 normally.
 *
 * Reparent re-runs on each call (handles host peer-change scenarios
 * like alwaysOnTop reparent).  The embedded-flag flip happens once.
 *
 * Completion signal:
 *   After Wine has reparented + mapped wine_x11_window and flushed
 *   the wm_state cycle, it posts WM_X11DRV_NSPA_EMBED_DONE to the
 *   same HWND (via NtUserPostMessage).  Consumers that need a
 *   deterministic "embed handshake is settled" signal can listen for
 *   this in their WndProc instead of guessing timing.  The message
 *   is async — it lands on the HWND's message queue and is delivered
 *   the next time the consumer's message pump runs.  Payload is
 *   reserved (wparam = lparam = 0).
 *
 * Example:
 *   HWND hwnd = CreateWindowExW(WS_EX_TOOLWINDOW, ..., WS_POPUP, ...);
 *   Window parent = (Window) juce_peer->getNativeHandle();
 *   LPARAM pos = MAKELPARAM(peerX, peerY);
 *   SendMessageW(hwnd, WM_X11DRV_NSPA_EMBED_WINDOW, (WPARAM)parent, pos);
 *
 *   // ... in your WndProc:
 *   case WM_X11DRV_NSPA_EMBED_DONE:
 *       // Embed handshake settled.  Safe to call format-specific
 *       // attach hooks if you didn't already (effEditOpen /
 *       // IPlugView::attached / CLAP set_parent).
 *       return 0;
 *
 * Copyright 2026 Wine-NSPA contributors
 */

#ifndef __WINE_NSPA_X11_EMBED_H
#define __WINE_NSPA_X11_EMBED_H

/* The numeric values are reserved in winex11.drv's
 * enum x11drv_window_messages (x11drv.h).  They sit in Wine's
 * documented WM_WINE_FIRST_DRIVER_MSG range (0x80001000+) so they
 * cannot collide with application-defined WM_USER messages.
 *
 * Consumers don't need to (and can't) include winex11.drv's private
 * x11drv.h — these defines are the supported interface. */
#define WM_X11DRV_NSPA_EMBED_WINDOW 0x80001004
#define WM_X11DRV_NSPA_EMBED_DONE   0x80001005

#endif /* __WINE_NSPA_X11_EMBED_H */
