/*
 * NSPA: msg-ring v2 Phase C Stage 3b — hardware-message batched fetch.
 *
 * Server-side handler for the nspa_get_hw_msg_batch RPC.  The walker
 * itself lives in queue.c next to its sibling get_hardware_message
 * (it needs access to msg_queue/thread_input/message struct internals
 * which are queue.c-local); this file holds only the RPC seam.
 *
 * Walker invariants and audit:
 *   wine/nspa/docs/msg-ring-v2-phase-c-audit.md
 */

#include "config.h"

#include <string.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS

#include "../object.h"
#include "../process.h"
#include "../request.h"
#include "../thread.h"

#include "hw_msg_batch.h"

/* Server-side cap on batch size.  Caps client-supplied max_count
 * defensively: 16 keeps the worst-case reply payload under 2 KiB
 * and bounds the stack buffer in the walker. */
#define NSPA_HW_BATCH_SERVER_CAP 16

DECL_HANDLER(nspa_get_hw_msg_batch)
{
    struct nspa_hw_msg_batch_entry entries[NSPA_HW_BATCH_SERVER_CAP];
    unsigned int max_count = req->max_count;
    unsigned int bytes_used = 0;
    int returned;

    reply->returned = 0;

    if (!max_count) return;
    if (max_count > NSPA_HW_BATCH_SERVER_CAP) max_count = NSPA_HW_BATCH_SERVER_CAP;

    returned = nspa_get_hardware_msg_batch_walk( current,
                                                 max_count,
                                                 req->hw_id,
                                                 req->filter_win,
                                                 req->first,
                                                 req->last,
                                                 req->flags,
                                                 entries,
                                                 get_reply_max_size(),
                                                 &bytes_used );

    if (returned < 0) return;  /* walker set_error already */
    if (bytes_used) set_reply_data( entries, bytes_used );
    reply->returned = returned;
}
