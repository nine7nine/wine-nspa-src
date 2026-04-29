/*
 * NSPA: msg-ring v2 Phase C Stage 3b — hardware-message batched fetch.
 *
 * Server-side handler for the new nspa_get_hw_msg_batch RPC.  Returns
 * up to req->max_count fully-resolved hardware messages in a single
 * round-trip; each entry has the same shape get_message would have
 * produced for MSG_HARDWARE.
 *
 * Server applies all side-effects (unique_id stamping, find_hardware_
 * message_window resolution, key-state tracking, wrong-thread/process
 * cleanup) at fetch time, identical to the existing single-msg path.
 * Client just delivers what server prepared, so cross-thread input
 * sharing and accept_hardware_message interlocks behave the same as
 * today's single-msg flow.
 *
 * Design and audit:
 *   wine/nspa/docs/msg-ring-v2-phase-c-audit.md
 *
 * STATUS 2026-04-28: stub implementation — returns 0 messages, falls
 * through to the existing get_message RPC path.  Real walker logic is
 * staged in a follow-up commit so the protocol wiring can be validated
 * (build clean + handler reachable) without behaviour change.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS

#include "../object.h"
#include "../process.h"
#include "../request.h"
#include "../thread.h"

DECL_HANDLER(nspa_get_hw_msg_batch)
{
    /* Phase 1 stub: return zero messages.  Caller falls through to
     * the existing get_message RPC.  No behaviour change relative
     * to mainline. */
    reply->returned = 0;
}
