/*
 * NSPA msg-ring v2 Phase C Stage 3b — client-side hardware-message cache.
 *
 * Per-thread cache populated from the nspa_get_hw_msg_batch RPC; drained
 * by peek_message_internal before falling through to the existing
 * single-msg get_message path.
 *
 * See wine/nspa/docs/msg-ring-v2-phase-c-audit.md for design + lockup-
 * bug-class audit (MR1/MR2/MR4 family).
 */

#ifndef __WINE_WIN32U_NSPA_HW_MSG_CACHE_H
#define __WINE_WIN32U_NSPA_HW_MSG_CACHE_H

#include "wine/server.h"
#include "wine/server_protocol.h"

/* Single env-var gate.  Default-OFF until validated; per
 * feedback_validate_before_default_on.md. */
extern BOOL nspa_hw_batch_enabled( void );

/* Try to pop one cached entry matching the given filter.  Returns TRUE
 * on hit (out filled).  On miss (cache empty OR filter snapshot
 * differs OR filter mismatch on individual entry), returns FALSE
 * without consuming any state — caller decides whether to refill. */
extern BOOL nspa_hw_msg_cache_try_pop( HWND filter_hwnd, UINT first, UINT last,
                                       UINT flags,
                                       struct nspa_hw_msg_batch_entry *out );

/* Issue an nspa_get_hw_msg_batch RPC, populating the per-thread cache
 * with the returned entries.  Returns the number of entries loaded
 * (0 on empty list, on error, or if the gate is disabled).  On 0,
 * caller should fall through to single-msg path.
 *
 * On success the filter snapshot in the cache is updated to the
 * passed-in values; subsequent try_pop calls with the same filter
 * will hit. */
extern unsigned int nspa_hw_msg_cache_refill( HWND filter_hwnd, UINT first, UINT last,
                                              UINT flags, UINT continuation_hw_id );

#endif /* __WINE_WIN32U_NSPA_HW_MSG_CACHE_H */
