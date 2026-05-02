/*
 * NSPA sched helpers — implementation.
 *
 * Phase 2.5: env gate read-once for NSPA_USE_SCHED_THREAD.
 *
 * Copyright 2026 NSPA contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"

#include "sched_helpers.h"

/* Cached value: 0 = unknown, 1 = explicitly OFF, 2 = ON.  Three states
 * so a concurrent first call can't re-read the env (cheap monotonic
 * transition, no lock needed since the env is process-wide constant). */
static int nspa_sched_enabled_cached;

BOOL nspa_sched_enabled(void)
{
    int v = __atomic_load_n( &nspa_sched_enabled_cached, __ATOMIC_ACQUIRE );
    if (!v)
    {
        const char *env = getenv( "NSPA_USE_SCHED_THREAD" );
        v = (env && env[0] == '1' && env[1] == 0) ? 2 : 1;
        __atomic_store_n( &nspa_sched_enabled_cached, v, __ATOMIC_RELEASE );
    }
    return v == 2;
}
