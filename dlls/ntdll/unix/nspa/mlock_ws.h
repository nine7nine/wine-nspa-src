/*
 * NSPA working-set page locking — Phase 1.
 *
 * mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) at process startup,
 * gated by NSPA_MLOCK_WORKINGSET env or NSPA_RT_PRIO presence.  Pins
 * touched pages in RAM so first-touch fault overhead is paid at
 * allocation time, not on the audio path.
 *
 * Design doc:
 *   wine/nspa/docs/working-set-and-hugetlb-design-20260505.md
 *
 * NT semantics: transparent — no Win32 API surface change.  VirtualLock
 * already calls mlock(); becomes harmlessly redundant.  VirtualUnlock
 * still calls munlock() but pages stay locked process-wide via
 * MCL_FUTURE (Win32 docs allow the system not to swap).
 *
 * RT semantics: single setup call at process start, off the RT path.
 * MCL_ONFAULT keeps RSS proportional to actually-touched memory —
 * Wine reserves large PROT_NONE ranges that should NOT be force-
 * committed to RAM.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __NSPA_MLOCK_WS_H
#define __NSPA_MLOCK_WS_H

/* Initialise process-wide working-set locking.  Called once from
 * start_main_thread() after server_init_process() has populated the
 * environment.  Idempotent — second call is a no-op.
 *
 * Gate: NSPA_RT_PRIO presence.  No separate env override — RT processes
 * get the RT defaults; non-RT processes get vanilla behaviour.
 *
 * Failure (EPERM, ENOMEM, EINVAL) is non-fatal — logs a one-shot WARN
 * and leaves the process unlocked.  RLIMIT_MEMLOCK is raised to
 * RLIM_INFINITY (or the hard cap if EPERM) before mlockall to avoid
 * hitting low systemd defaults.
 */
extern void nspa_mlock_ws_init( void );

#endif /* __NSPA_MLOCK_WS_H */
