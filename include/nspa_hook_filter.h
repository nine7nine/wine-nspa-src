/*
 * NSPA Tier 2 hook cache — shared filter predicates.
 *
 * Pure functions over the fields stored in nspa_hook_entry_t plus the
 * caller's identity.  Designed to be inlinable in both
 * server/nspa/hook_cache.c (when populating / forced-overflow checks)
 * and dlls/win32u/hook.c (when reading the cache before dispatch).
 *
 * Contract: these match server/hook.c run_hook_in_thread() bit-for-bit.
 * Divergence between server and client predicates is a silent
 * correctness bug — keep both sides going through this header.
 */
#ifndef __WINE_NSPA_HOOK_FILTER_H
#define __WINE_NSPA_HOOK_FILTER_H

/* Returns 1 iff a hook entry recorded for `(hook_pid, hook_tid, hook_flags)`
 * should fire on a thread identified by `(my_pid, my_tid)`.
 *
 * Mirror of server/hook.c:run_hook_in_thread.  hook_pid==0 means
 * "not bound to a process"; hook_tid==0 means "not bound to a thread"
 * — those are the global / per-desktop variants. */
static inline int nspa_hook_match_thread( unsigned int hook_pid, unsigned int hook_tid,
                                           unsigned int hook_flags,
                                           unsigned int my_pid, unsigned int my_tid )
{
    if (hook_pid && hook_pid != my_pid) return 0;
    if ((hook_flags & WINEVENT_SKIPOWNPROCESS) && hook_pid == my_pid) return 0;
    if (hook_tid && hook_tid != my_tid) return 0;
    if ((hook_flags & WINEVENT_SKIPOWNTHREAD) && hook_tid == my_tid) return 0;
    return 1;
}

/* Returns 1 iff `event` is in [event_min, event_max].  Used by the
 * server's get_first_valid_hook for WINEVENT-class hooks; for
 * non-WINEVENT hooks the bounds are [0, INT_MAX] so any event passes. */
static inline int nspa_hook_match_event( int event, int event_min, int event_max )
{
    return event >= event_min && event <= event_max;
}

#endif /* __WINE_NSPA_HOOK_FILTER_H */
