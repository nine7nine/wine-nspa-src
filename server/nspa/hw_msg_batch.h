/*
 * NSPA msg-ring v2 Phase C Stage 3b — hardware-message batched fetch.
 *
 * Bridge between the NSPA-namespaced DECL_HANDLER in nspa/hw_msg_batch.c
 * and the walker that lives in queue.c next to its sibling
 * get_hardware_message.
 */

#ifndef __WINE_SERVER_NSPA_HW_MSG_BATCH_H
#define __WINE_SERVER_NSPA_HW_MSG_BATCH_H

#include "../object.h"
#include "../thread.h"
#include "wine/server_protocol.h"

/* Walker entry point.  Walks the calling thread's input msg_list,
 * collecting up to max_count fully-resolved hardware messages into
 * batch_buf.  Returns the number of entries written; *bytes_used set
 * to the number of bytes consumed in batch_buf.  Applies all
 * side-effects identically to get_hardware_message — see
 * wine/nspa/docs/msg-ring-v2-phase-c-audit.md and the comment block
 * above the function in queue.c. */
extern int nspa_get_hardware_msg_batch_walk( struct thread *thread,
                                             unsigned int max_count,
                                             unsigned int hw_id,
                                             user_handle_t filter_win,
                                             unsigned int first,
                                             unsigned int last,
                                             unsigned int flags,
                                             struct nspa_hw_msg_batch_entry *out_entries,
                                             unsigned int max_reply_bytes,
                                             unsigned int *bytes_used );

#endif /* __WINE_SERVER_NSPA_HW_MSG_BATCH_H */
