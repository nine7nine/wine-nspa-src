/*
 * JACK audio/MIDI driver for Wine (unix library)
 *
 * Phase 1: MIDI via JACK MIDI (fully functional)
 * Phase 2+: Audio via JACK audio (stubs for now)
 *
 * Copyright 2025 jordan Johnston (Wine-NSPA)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <jack/jack.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "initguid.h"
#include "mmdeviceapi.h"

#include "wine/debug.h"
#include "wine/unixlib.h"

#include "unixlib.h"

WINE_DEFAULT_DEBUG_CHANNEL(jack);

/* ════════════════════════════════════════════════════════════════════════
 *   Forward declarations for jackmidi.c
 * ════════════════════════════════════════════════════════════════════════ */

extern BOOL jack_midi_available;
extern NTSTATUS jack_midi_release(void *args);
extern NTSTATUS jack_midi_out_message(void *args);
extern NTSTATUS jack_midi_in_message(void *args);
extern NTSTATUS jack_midi_notify_wait(void *args);

/* ════════════════════════════════════════════════════════════════════════
 *   Stubs — audio functions for Phase 2+
 * ════════════════════════════════════════════════════════════════════════ */

static NTSTATUS jack_not_implemented(void *args)
{
    return STATUS_SUCCESS;
}

static NTSTATUS jack_process_attach(void *args)
{
#ifdef _WIN64
    if (NtCurrentTeb()->WowTebOffset)
    {
        SYSTEM_BASIC_INFORMATION info;
        NtQuerySystemInformation(SystemEmulationBasicInformation, &info, sizeof(info), NULL);
    }
#endif
    return STATUS_SUCCESS;
}

static NTSTATUS jack_main_loop(void *args)
{
    struct main_loop_params *params = args;
    NtSetEvent(params->event, NULL);
    return STATUS_SUCCESS;
}

static NTSTATUS jack_test_connect(void *args)
{
    struct test_connect_params *params = args;
    jack_client_t *client;
    jack_status_t status;

    /* Try to connect to JACK to determine priority */
    client = jack_client_open("wine-probe", JackNoStartServer, &status);
    if (client)
    {
        jack_client_close(client);
        /* JACK is running — we're the preferred driver */
        params->priority = Priority_Preferred;
        TRACE("JACK is running, reporting Priority_Preferred\n");
    }
    else
    {
        /* JACK not available — mark unavailable so mmdevapi skips us */
        params->priority = Priority_Unavailable;
        TRACE("JACK not available (status %d), reporting Priority_Unavailable\n", status);
    }

    return STATUS_SUCCESS;
}

/* Audio endpoint stubs — return empty/no-device until Phase 2 */
static NTSTATUS jack_get_endpoint_ids(void *args)
{
    struct get_endpoint_ids_params *params = args;
    params->num = 0;
    params->default_idx = 0;
    params->result = S_OK;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_create_stream(void *args)
{
    struct create_stream_params *params = args;
    params->result = E_NOTIMPL;
    return STATUS_SUCCESS;
}

/* midi_get_driver: tell mmdevapi to use us for MIDI too (no separate MIDI driver needed) */
static NTSTATUS jack_midi_get_driver(void *args)
{
    /* args is a WCHAR buffer — return empty string to indicate "use same driver for MIDI" */
    WCHAR *name = args;
    name[0] = 0;
    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Function table — matches enum unix_funcs in mmdevapi/unixlib.h
 * ════════════════════════════════════════════════════════════════════════ */

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    jack_process_attach,            /* process_attach */
    jack_not_implemented,           /* process_detach */
    jack_main_loop,                 /* main_loop */
    jack_get_endpoint_ids,          /* get_endpoint_ids */
    jack_create_stream,             /* create_stream */
    jack_not_implemented,           /* release_stream */
    jack_not_implemented,           /* start */
    jack_not_implemented,           /* stop */
    jack_not_implemented,           /* reset */
    jack_not_implemented,           /* timer_loop */
    jack_not_implemented,           /* get_render_buffer */
    jack_not_implemented,           /* release_render_buffer */
    jack_not_implemented,           /* get_capture_buffer */
    jack_not_implemented,           /* release_capture_buffer */
    jack_not_implemented,           /* is_format_supported */
    jack_not_implemented,           /* get_loopback_capture_device */
    jack_not_implemented,           /* get_mix_format */
    jack_not_implemented,           /* get_device_period */
    jack_not_implemented,           /* get_buffer_size */
    jack_not_implemented,           /* get_latency */
    jack_not_implemented,           /* get_current_padding */
    jack_not_implemented,           /* get_next_packet_size */
    jack_not_implemented,           /* get_frequency */
    jack_not_implemented,           /* get_position */
    jack_not_implemented,           /* set_volumes */
    jack_not_implemented,           /* set_event_handle */
    jack_not_implemented,           /* set_sample_rate */
    jack_test_connect,              /* test_connect */
    jack_not_implemented,           /* is_started */
    jack_not_implemented,           /* get_prop_value */
    jack_midi_get_driver,           /* midi_get_driver */
    jack_not_implemented,           /* midi_init (handled inside midi_*_message DRVM_INIT) */
    jack_midi_release,              /* midi_release */
    jack_midi_out_message,          /* midi_out_message */
    jack_midi_in_message,           /* midi_in_message */
    jack_midi_notify_wait,          /* midi_notify_wait */
    jack_not_implemented,           /* aux_message */
};

C_ASSERT(ARRAYSIZE(__wine_unix_call_funcs) == funcs_count);

#ifdef _WIN64

typedef UINT PTR32;

/* WoW64 thunks would go here for 32-bit app support.
 * For Phase 1 (MIDI only), 32-bit MIDI apps go through the
 * standard wow64 translation in mmdevapi. Full thunks needed
 * for Phase 2 audio streams. */

#endif /* _WIN64 */
