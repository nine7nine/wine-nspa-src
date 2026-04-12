/*
 * Copyright 2025 jordan Johnston (Wine-NSPA)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "../mmdevapi/unixlib.h"

NTSTATUS jack_midi_release(void *args);
NTSTATUS jack_midi_out_message(void *args);
NTSTATUS jack_midi_in_message(void *args);
NTSTATUS jack_midi_notify_wait(void *args);

extern BOOL jack_midi_available;
