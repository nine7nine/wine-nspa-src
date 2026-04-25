/*
 * NSPA: in-wineserver state for relocated rpcss interfaces.
 *
 * Phase 1.A — irpcss (COM class-factory registry).  See
 * nspa/docs/rpc-fast-and-solid-plan.md for the full design.
 */

#ifndef __WINE_SERVER_NSPA_RPC_STATE_H
#define __WINE_SERVER_NSPA_RPC_STATE_H

struct process;

/* Called from server/process.c's destroy_process_classes() neighbourhood.
 * Releases all class-factory registrations owned by the dying process,
 * matching the per-client cleanup that rpcss does today via the RPC
 * [context_handle] ownership model. */
extern void nspa_rpc_state_release( struct process *process );

#endif /* __WINE_SERVER_NSPA_RPC_STATE_H */
