/*
 * NSPA periodic observability sampler — sched-hosted.
 *
 * Phase 3 consumer #2: a sched-hosted timer that periodically
 * snapshots NSPA-internal stats and writes them to a /dev/shm file
 * for external monitoring without enabling Wine's tracing firehose.
 *
 * Why on sched: read-only sampling, no precision required, no audio
 * impact (SCHED_OTHER + PI), exactly the niche the sched API is
 * designed for.  Validates the timer + cancel paths in production
 * (consumer #1 only used async).
 *
 * Designed with future wineserver decomposition in mind: the stat-
 * collector registration pattern is open-ended so PE-migrated services
 * can plug their stats in without changing the sampler core.
 *
 * Default OFF.  Set NSPA_SCHED_OBS_INTERVAL_MS=N (positive integer) to
 * enable, sampling every N milliseconds.  Output goes to
 *   /dev/shm/nspa-obs.<pid>
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __NSPA_SCHED_OBS_H
#define __NSPA_SCHED_OBS_H

#include <stdio.h>

/* Stat collector callback.  Invoked from the sampler timer with `out`
 * pointing at the open obs file (truncated + at offset 0 each tick).
 * Collector writes one or more `key value\n` lines via fprintf.  The
 * sampler does NOT lock the file; collectors should not block, should
 * not allocate, and should not call into wineserver. */
typedef void (*nspa_obs_collector_t)( FILE *out );

/* Register a stat collector.  Idempotent: same callback registered
 * twice is only invoked once.  Cap is small (NSPA_SCHED_OBS_MAX_COLLECTORS,
 * defined in sched_obs.c).  Safe to call before nspa_sched_obs_init. */
extern void nspa_sched_obs_register_collector( nspa_obs_collector_t cb );

/* Init.  Called once at sched_run() entry.  Reads the env, opens the
 * obs file, registers the periodic timer.  No-op if env is unset or
 * sched is disabled. */
extern void nspa_sched_obs_init( void );

#endif /* __NSPA_SCHED_OBS_H */
