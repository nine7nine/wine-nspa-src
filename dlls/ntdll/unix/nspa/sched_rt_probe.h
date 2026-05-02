/*
 * NSPA RT sched-class validation probe.
 *
 * A small synthetic consumer of NTDLL_SCHED_CLASS_RT used to validate
 * the RT-class sched thread end-to-end before any production consumer
 * (wm_timer migration etc.) routes work onto it.
 *
 * Default OFF.  Engaged via NSPA_SCHED_RT_PROBE=1 (env).
 *
 * Requires NSPA_SCHED_OBS_INTERVAL_MS to also be set so the probe's
 * counters surface in the /dev/shm/nspa-obs.<pid> snapshot for
 * external monitoring.  Without OBS, the probe still runs (validates
 * RT thread spawn + dispatch) but its counters are inaccessible.
 *
 * What the probe measures:
 *   - rt_probe.alive            : 1 if the RT sched thread is alive
 *                                  (i.e. nspa_sched_rt_available())
 *   - rt_probe.fires            : count of dispatched RT timer
 *                                  callbacks since process start
 *   - rt_probe.jitter_last_us   : actual-vs-expected wake jitter for
 *                                  the most recent fire
 *   - rt_probe.jitter_max_us    : max observed jitter since start
 *
 * Sampling cadence: 100ms.  Modest (avoids stress; just validates).
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __NSPA_SCHED_RT_PROBE_H
#define __NSPA_SCHED_RT_PROBE_H

/* Init.  Called from sched_run() entry after the OBS init.  No-op if
 * NSPA_SCHED_RT_PROBE is unset or the RT class is unavailable. */
extern void nspa_sched_rt_probe_init( void );

#endif /* __NSPA_SCHED_RT_PROBE_H */
