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
 * Size changes are NOT issued as XConfigureWindow on wine_x11_window
 * for nspa-embedded windows either — the embedder also owns sizing.
 * Bridges already get plugin resize signals via format-specific
 * callbacks (audioMasterSizeWindow / IPlugFrame::resizeView / CLAP
 * request_resize), so the X11 ConfigureNotify path was never the
 * canonical signal anyway.  Suppressing it prevents resize-related
 * misbehavior from hosts that subscribe to SubStructureNotify on the
 * parent (e.g., older Carla versions).
 *
 * **Consumer contract:** because Wine no longer emits XConfigureWindow
 * for size changes on wine_x11_window, hosts MUST drive X11 sizing
 * themselves when they want the embedded surface to match the
 * plugin's reported size.  Typically this means calling
 * XMoveResizeWindow / xcb_configure_window directly on the wine
 * X11 window using the size received via the format-specific resize
 * callback.  JUCE's syncHwndScreenPosition and yabridge's
 * Editor::resize already do this; new hosts should follow the same
 * pattern.
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
 * **Consumer pump discipline:** the message pump that drains the
 * embedded HWND's thread queue MUST be bounded — either by message
 * count or by elapsed time — and SHOULD dispatch input messages
 * (WM_MOUSEFIRST..WM_MOUSELAST, WM_KEYFIRST..WM_KEYLAST) ahead of
 * the general drain on each pump invocation.  An unbounded
 * `while (PeekMessage)` loop will deadlock the host's event-polling
 * thread whenever a plugin's WM_TIMER handler is heavy enough that
 * the handler runtime equals or exceeds the plugin's own SetTimer
 * period: the queue never goes empty, the pump never returns, the
 * host can't poll X11, and X11 mouse/key events queued at the WM
 * never reach the plugin.  The symptom is a UI that appears frozen
 * even though the plugin is happily redrawing at full tilt.
 *
 *   Reference implementations of the bounded pump:
 *     - JUCE-NSPA WineHWNDEmbedComponent (juce_gui_extra) — 4ms
 *       time-cap + input-first peek pass.
 *     - yabridge HostBridge::handle_events (wine-host/bridges/
 *       common.cpp) — 20 message count cap, JUCE-detected
 *       8192-extension via WM_USER+123 heuristic.  Cap covers the
 *       deadlock class; lacks input-first prioritization, so
 *       redraw-heavy plugin pages can still feel laggy on input.
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
