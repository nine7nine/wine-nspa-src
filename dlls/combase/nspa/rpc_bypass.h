/*
 * NSPA RPC Phase 1.A — irpcss bypass entrypoints.
 *
 * Replaces four irpcss_* RPC calls in dlls/combase/rpc.c with direct
 * wineserver requests when the NSPA_RPC_BYPASS gate is enabled.
 *
 * See nspa/docs/rpc-fast-and-solid-plan.md.
 */

#ifndef __WINE_COMBASE_NSPA_RPC_BYPASS_H
#define __WINE_COMBASE_NSPA_RPC_BYPASS_H

#include <windef.h>
#include <objidl.h>
#include "irpcss.h"

/* Gate predicate.  Returns non-zero iff the irpcss bypass should be used.
 * Reads NSPA_RPC_BYPASS env var on first call (memoised); bit 0 = irpcss.
 * Default off — when off, dlls/combase/rpc.c falls through to the legacy
 * ncalrpc path unchanged. */
extern int nspa_rpc_bypass_irpcss(void);

/* Bypass entrypoints — semantics identical to the corresponding
 * irpcss_* methods in programs/rpcss/rpcss_main.c. */

extern HRESULT nspa_irpcss_register_class_factory( REFCLSID clsid, DWORD flags,
                                                   MInterfacePointer *object,
                                                   unsigned int *cookie );

extern HRESULT nspa_irpcss_revoke_class_factory( unsigned int cookie );

extern HRESULT nspa_irpcss_get_class_factory( REFCLSID clsid,
                                              PMInterfacePointer *object );

extern HRESULT nspa_irpcss_alloc_thread_seq_id( DWORD *id );

#endif /* __WINE_COMBASE_NSPA_RPC_BYPASS_H */
