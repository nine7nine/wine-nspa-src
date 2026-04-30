/*
 * NSPA Phase 4 — async-completing handler for req_create_file.
 *
 * Eligibility-narrow first cut: regular files, FILE_OPEN disposition,
 * read-only access, no rootdir, no security descriptor, no
 * FILE_DELETE_ON_CLOSE, name + nt_name fit inline.  Everything else
 * falls through to the existing synchronous create_file path (which
 * still uses Phase B's lock-drop around openat).
 *
 * Gated by NSPA_ENABLE_ASYNC_CREATE_FILE=1 (default OFF).
 *
 * RT-safety + lifetime:
 *   - per-process io_uring instance owned by gamma dispatcher pthread
 *     (Phase 2/3); CQE callback runs from nspa_uring_drain on that
 *     same thread under global_lock (Phase 4 wraps drain in the lock)
 *   - IOSQE_ASYNC on every SQE — kernel iowq does the openat, the
 *     RT dispatcher pthread is freed immediately
 *   - submit grabs a ref on `current` so the requesting thread
 *     can't be freed mid-flight (closes a UAF window the original
 *     Phase C had); release happens after signal_reply
 *   - inline name + nt_name buffers — no heap on the submit path
 */

#ifndef __WINE_SERVER_NSPA_URING_CREATE_FILE_H
#define __WINE_SERVER_NSPA_URING_CREATE_FILE_H

#include "wine/server_protocol.h"  /* struct create_file_request, object_attributes */

struct unicode_str;
struct security_descriptor;
struct request_shm;

/* Attempt to dispatch this create_file request asynchronously via
 * io_uring.  Caller is DECL_HANDLER(create_file).
 *
 * Returns 1 if the request was dispatched async — caller MUST return
 * immediately; the CQE callback owns reply completion.
 *
 * Returns 0 if the request was not dispatched (gate off, ineligible,
 * pool exhausted, SQ full, etc.) — caller MUST fall through to the
 * existing synchronous path. */
extern int nspa_uring_create_file_try_async(
    const struct create_file_request *req,
    const struct object_attributes *objattr,
    const struct security_descriptor *sd,
    struct unicode_str nt_name,
    const char *name, unsigned int name_len );

#endif /* __WINE_SERVER_NSPA_URING_CREATE_FILE_H */
