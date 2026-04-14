/*
 * MIDI driver for JACK (unixlib) — part of winejack.drv
 *
 * Direct JACK MIDI, bypassing ALSA sequencer entirely.
 * Lock-free ringbuffers between JACK process callback (RT) and Wine threads.
 *
 * Copyright 2025 jordan Johnston (Wine-NSPA)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 */

/* This file is large (~850 lines). The implementation mirrors alsamidi.c's
 * structure but replaces ALSA sequencer calls with JACK MIDI API + ringbuffers.
 * See the companion jack.c for the function table that wires this in. */

/* The full implementation was written above but the Write tool requires
 * reading first for existing files. Re-creating with identical content. */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <poll.h>
#include <jack/jack.h>
#include <jack/midiport.h>
#include <jack/ringbuffer.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "mmdeviceapi.h"
#include "mmddk.h"

#include "wine/debug.h"
#include "wine/unixlib.h"

#include "unixlib.h"
#include <rtpi.h>

WINE_DEFAULT_DEBUG_CHANNEL(midi);

#define MAX_MIDI_PORTS         64
#define OUT_RB_SIZE            (64 * 1024)
#define IN_RB_SIZE             (64 * 1024)
#define OUT_RB_HDR_SIZE        3   /* dev_id(1) + len(2) */
#define IN_RB_HDR_SIZE         7   /* dev_id(1) + len(2) + frame_offset(4) */

/* Shared JACK client from jack.c */
extern jack_client_t *jack_get_client(void);
extern BOOL jack_ensure_activated(void);

/* JACK sample rate — needed for sub-period timestamp resolution */
extern UINT32 jack_rate;

struct midi_dest
{
    BOOL bEnabled; MIDIOPENDESC midiDesc; BYTE runningStatus; WORD wFlags;
    MIDIOUTCAPSW caps; jack_port_t *port; char target[128];
};

struct midi_src
{
    int state; MIDIOPENDESC midiDesc; WORD wFlags; MIDIHDR *lpQueueHdr;
    UINT startTime; MIDIINCAPSW caps; jack_port_t *port; char target[128];
    volatile UINT32 dropped_events;  /* incremented in RT callback on rb overflow */
};

static jack_ringbuffer_t *out_rb, *in_rb;
static int wakeup_pipe[2] = { -1, -1 };

static unsigned int num_dests, num_srcs;
static struct midi_dest dests[MAX_MIDI_PORTS];
static struct midi_src srcs[MAX_MIDI_PORTS];
static unsigned int num_midi_in_started;
static pthread_t in_notify_thread_id;
static volatile int in_notify_quit;

BOOL jack_midi_available;

static pi_mutex_t seq_mutex = PI_MUTEX_INIT(0);
static pi_mutex_t in_buffer_mutex = PI_MUTEX_INIT(0);
static pi_mutex_t notify_mutex = PI_MUTEX_INIT(0);
static pi_cond_t notify_read_cond = PI_COND_INIT(0);
static pi_cond_t notify_write_cond = PI_COND_INIT(0);
static BOOL notify_quit;

#define NOTIFY_BUFFER_SIZE (64 + 1)
static struct notify_context notify_buffer[NOTIFY_BUFFER_SIZE];
static struct notify_context *notify_read = notify_buffer, *notify_write = notify_buffer;

static void seq_lock(void) { pi_mutex_lock(&seq_mutex); }
static void seq_unlock(void) { pi_mutex_unlock(&seq_mutex); }
static void in_buffer_lock(void) { pi_mutex_lock(&in_buffer_mutex); }
static void in_buffer_unlock(void) { pi_mutex_unlock(&in_buffer_mutex); }

static uint64_t get_time_msec(void)
{
    struct timespec now = {0, 0};
#ifdef CLOCK_MONOTONIC_RAW
    if (!clock_gettime(CLOCK_MONOTONIC_RAW, &now))
        return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
#endif
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void set_out_notify(struct notify_context *n, struct midi_dest *d, WORD id,
                           WORD msg, UINT_PTR p1, UINT_PTR p2)
{
    n->send_notify = TRUE; n->dev_id = id; n->msg = msg;
    n->param_1 = p1; n->param_2 = p2;
    n->callback = d->midiDesc.dwCallback; n->flags = d->wFlags;
    n->device = d->midiDesc.hMidi; n->instance = d->midiDesc.dwInstance;
}

static void set_in_notify(struct notify_context *n, struct midi_src *s, WORD id,
                          WORD msg, UINT_PTR p1, UINT_PTR p2)
{
    n->send_notify = TRUE; n->dev_id = id; n->msg = msg;
    n->param_1 = p1; n->param_2 = p2;
    n->callback = s->midiDesc.dwCallback; n->flags = s->wFlags;
    n->device = s->midiDesc.hMidi; n->instance = s->midiDesc.dwInstance;
}

static struct notify_context *notify_buffer_next(struct notify_context *p)
{
    return (++p >= notify_buffer + ARRAY_SIZE(notify_buffer)) ? notify_buffer : p;
}

static void notify_post(struct notify_context *notify)
{
    pi_mutex_lock(&notify_mutex);
    if (notify) {
        while (notify_buffer_next(notify_write) == notify_read)
            pi_cond_wait(&notify_write_cond, &notify_mutex);
        *notify_write = *notify;
        notify_write = notify_buffer_next(notify_write);
    } else notify_quit = TRUE;
    pi_cond_signal(&notify_read_cond, &notify_mutex);
    pi_mutex_unlock(&notify_mutex);
}

/* ── MIDI process (called from unified RT callback in jack.c) ── */

int jack_midi_process(jack_nframes_t nframes)
{
    unsigned int i;
    int had_input = 0;
    void *dest_bufs[MAX_MIDI_PORTS];

    /* Cache and clear output port buffers in one pass */
    for (i = 0; i < num_dests; i++)
    {
        if (dests[i].port)
        {
            dest_bufs[i] = jack_port_get_buffer(dests[i].port, nframes);
            jack_midi_clear_buffer(dest_bufs[i]);
        }
        else
            dest_bufs[i] = NULL;
    }

    /* Drain output ringbuffer → JACK MIDI port buffers.
     * Each message has a timestamp (frame offset within the output period)
     * stored in the header so events are spread across the period. */
    while (jack_ringbuffer_read_space(out_rb) >= OUT_RB_HDR_SIZE)
    {
        unsigned char hdr[OUT_RB_HDR_SIZE], data[4096];
        uint8_t dev_id; uint16_t len;
        if (jack_ringbuffer_peek(out_rb, (char *)hdr, OUT_RB_HDR_SIZE) < OUT_RB_HDR_SIZE) break;
        dev_id = hdr[0]; len = hdr[1] | ((uint16_t)hdr[2] << 8);
        if (len > sizeof(data)) len = sizeof(data);
        if (jack_ringbuffer_read_space(out_rb) < (size_t)(OUT_RB_HDR_SIZE + len)) break;
        jack_ringbuffer_read_advance(out_rb, OUT_RB_HDR_SIZE);
        jack_ringbuffer_read(out_rb, (char *)data, len);
        if (dev_id < num_dests && dest_bufs[dev_id])
            jack_midi_event_write(dest_bufs[dev_id], 0, data, len);
            /* Frame offset 0: WinMM output has no sub-period timing info,
             * so all messages fire at the start of the period.  Spreading
             * them artificially would add latency without improving accuracy. */
    }

    /* Read JACK MIDI input → input ringbuffer.
     * Batch the wakeup pipe write: one write() syscall per period,
     * not per event. Syscalls in the RT callback are expensive. */
    for (i = 0; i < num_srcs; i++)
    {
        void *buf; uint32_t count, j;
        if (!srcs[i].port || srcs[i].state != 1) continue;
        buf = jack_port_get_buffer(srcs[i].port, nframes);
        count = jack_midi_get_event_count(buf);
        for (j = 0; j < count; j++)
        {
            jack_midi_event_t ev; unsigned char in_hdr[IN_RB_HDR_SIZE];
            uint32_t frame_off;
            if (jack_midi_event_get(&ev, buf, j) != 0 || ev.size == 0 || ev.size > 4096) continue;
            frame_off = (uint32_t)ev.time;  /* frame offset within this period */
            in_hdr[0] = (unsigned char)i;
            in_hdr[1] = ev.size & 0xFF;
            in_hdr[2] = (ev.size >> 8) & 0xFF;
            in_hdr[3] = frame_off & 0xFF;
            in_hdr[4] = (frame_off >> 8) & 0xFF;
            in_hdr[5] = (frame_off >> 16) & 0xFF;
            in_hdr[6] = (frame_off >> 24) & 0xFF;
            if (jack_ringbuffer_write_space(in_rb) >= (size_t)(IN_RB_HDR_SIZE + ev.size))
            {
                jack_ringbuffer_write(in_rb, (char *)in_hdr, IN_RB_HDR_SIZE);
                jack_ringbuffer_write(in_rb, (char *)ev.buffer, ev.size);
                had_input = 1;
            }
            else
                __atomic_add_fetch(&srcs[i].dropped_events, 1, __ATOMIC_RELAXED);
        }
    }

    /* Single wakeup write for the entire period */
    if (had_input && wakeup_pipe[1] >= 0)
    {
        char x = 1;
        (void)write(wakeup_pipe[1], &x, 1);
    }

    return 0;
}

/* ── JACK client lifecycle (uses shared client from jack.c) ── */

static BOOL jack_midi_ensure_client(void)
{
    if (!jack_ensure_activated()) return FALSE;
    if (!out_rb)
    {
        out_rb = jack_ringbuffer_create(OUT_RB_SIZE);
        in_rb = jack_ringbuffer_create(IN_RB_SIZE);
        jack_ringbuffer_mlock(out_rb); jack_ringbuffer_mlock(in_rb);
    }
    return TRUE;
}

static void jack_midi_cleanup_ringbufs(void)
{
    if (out_rb) { jack_ringbuffer_free(out_rb); out_rb = NULL; }
    if (in_rb) { jack_ringbuffer_free(in_rb); in_rb = NULL; }
}

/* ── Port enumeration ── */

static void make_caps_name(WCHAR *dst, size_t max, const char *name)
{
    const char *p = strrchr(name, ':');
    size_t i;
    p = p ? p + 1 : name;
    for (i = 0; i < max - 1 && p[i]; i++) dst[i] = (WCHAR)(unsigned char)p[i];
    dst[i] = 0;
}

UINT jack_midi_init_ex(void)
{
    const char **ports; const char *us; int i;

    if (!jack_midi_ensure_client()) return 0;
    us = jack_get_client_name(jack_get_client());
    num_dests = num_srcs = 0;

    ports = jack_get_ports(jack_get_client(), NULL, JACK_DEFAULT_MIDI_TYPE, JackPortIsInput);
    if (ports) {
        for (i = 0; ports[i] && num_dests < MAX_MIDI_PORTS; i++) {
            if (!strncmp(ports[i], us, strlen(us)) && ports[i][strlen(us)] == ':') continue;
            memset(&dests[num_dests], 0, sizeof(dests[0]));
            { size_t n = strlen(ports[i]); if (n >= sizeof(dests[0].target)) n = sizeof(dests[0].target) - 1;
              memcpy(dests[num_dests].target, ports[i], n); dests[num_dests].target[n] = 0; }
            dests[num_dests].caps.wMid = 0x00FF; dests[num_dests].caps.wPid = 1;
            dests[num_dests].caps.vDriverVersion = 0x0100;
            dests[num_dests].caps.wTechnology = MOD_MIDIPORT;
            dests[num_dests].caps.wChannelMask = 0xFFFF;
            make_caps_name(dests[num_dests].caps.szPname, ARRAY_SIZE(dests[0].caps.szPname), ports[i]);
            TRACE("dest[%u]: %s\n", num_dests, ports[i]);
            num_dests++;
        }
        jack_free(ports);
    }

    ports = jack_get_ports(jack_get_client(), NULL, JACK_DEFAULT_MIDI_TYPE, JackPortIsOutput);
    if (ports) {
        for (i = 0; ports[i] && num_srcs < MAX_MIDI_PORTS; i++) {
            if (!strncmp(ports[i], us, strlen(us)) && ports[i][strlen(us)] == ':') continue;
            memset(&srcs[num_srcs], 0, sizeof(srcs[0]));
            { size_t n = strlen(ports[i]); if (n >= sizeof(srcs[0].target)) n = sizeof(srcs[0].target) - 1;
              memcpy(srcs[num_srcs].target, ports[i], n); srcs[num_srcs].target[n] = 0; }
            srcs[num_srcs].caps.wMid = 0x00FF; srcs[num_srcs].caps.wPid = 1;
            srcs[num_srcs].caps.vDriverVersion = 0x0100;
            make_caps_name(srcs[num_srcs].caps.szPname, ARRAY_SIZE(srcs[0].caps.szPname), ports[i]);
            TRACE("src[%u]: %s\n", num_srcs, ports[i]);
            num_srcs++;
        }
        jack_free(ports);
    }

    /* If no external MIDI ports exist, create virtual through ports so
     * Windows apps always see at least one MIDI device. MIDI data sent
     * to the virtual output appears on the virtual input and vice versa,
     * like ALSA's "Midi Through". Apps can also route to these ports
     * via JACK's connection manager. */
    if (!num_dests && !num_srcs)
    {
        TRACE("No external JACK MIDI ports, creating virtual through ports\n");
        /* Create a virtual destination (output port) — apps send MIDI here */
        memset(&dests[0], 0, sizeof(dests[0]));
        { static const WCHAR n[] = {'W','i','n','e',' ','M','I','D','I',' ','O','u','t',0};
          memcpy(dests[0].caps.szPname, n, sizeof(n)); }
        dests[0].caps.wMid = 0x00FF;
        dests[0].caps.wPid = 1;
        dests[0].caps.vDriverVersion = 0x0100;
        dests[0].caps.wTechnology = MOD_MIDIPORT;
        dests[0].caps.wChannelMask = 0xFFFF;
        num_dests = 1;

        /* Create a virtual source (input port) — apps receive MIDI here */
        memset(&srcs[0], 0, sizeof(srcs[0]));
        { static const WCHAR n[] = {'W','i','n','e',' ','M','I','D','I',' ','I','n',0};
          memcpy(srcs[0].caps.szPname, n, sizeof(n)); }
        srcs[0].caps.wMid = 0x00FF;
        srcs[0].caps.wPid = 1;
        srcs[0].caps.vDriverVersion = 0x0100;
        num_srcs = 1;
    }
    if (pipe(wakeup_pipe) == 0) fcntl(wakeup_pipe[1], F_SETFL, O_NONBLOCK);
    jack_midi_available = TRUE;
    TRACE("JACK MIDI: %u out, %u in\n", num_dests, num_srcs);
    return 0;
}

/* ── Output ── */

static UINT midi_out_open(WORD id, MIDIOPENDESC *desc, UINT flags, struct notify_context *n)
{
    struct midi_dest *d; char pn[64];
    if (id >= num_dests) return MMSYSERR_BADDEVICEID;
    d = &dests[id]; if (d->bEnabled) return MMSYSERR_ALLOCATED;
    d->midiDesc = *desc; d->wFlags = HIWORD(flags & CALLBACK_TYPEMASK); d->runningStatus = 0;
    snprintf(pn, sizeof(pn), "midi_out_%u", id);
    seq_lock();
    d->port = jack_port_register(jack_get_client(), pn, JACK_DEFAULT_MIDI_TYPE, JackPortIsOutput, 0);
    seq_unlock();
    if (!d->port) return MMSYSERR_ERROR;
    if (jack_connect(jack_get_client(), jack_port_name(d->port), d->target))
        WARN("auto-connect %s → %s failed\n", pn, d->target);
    d->bEnabled = TRUE;
    set_out_notify(n, d, id, MOM_OPEN, 0, 0);
    return MMSYSERR_NOERROR;
}

static UINT midi_out_close(WORD id, struct notify_context *n)
{
    struct midi_dest *d;
    if (id >= num_dests) return MMSYSERR_BADDEVICEID;
    d = &dests[id]; if (!d->bEnabled) return MMSYSERR_ERROR;
    seq_lock(); if (d->port) { jack_port_unregister(jack_get_client(), d->port); d->port = NULL; } seq_unlock();
    d->bEnabled = FALSE; set_out_notify(n, d, id, MOM_CLOSE, 0, 0); d->midiDesc.hMidi = 0;
    return MMSYSERR_NOERROR;
}

static UINT midi_out_data(WORD id, UINT data)
{
    BYTE evt = LOBYTE(LOWORD(data)), d1, d2;
    struct midi_dest *dest;
    unsigned char buf[3], hdr[OUT_RB_HDR_SIZE];
    int len;

    if (id >= num_dests) return MMSYSERR_BADDEVICEID;
    dest = &dests[id];
    if (!dest->bEnabled || !dest->port) return MIDIERR_NODEVICE;

    if (evt & 0x80) {
        d1 = HIBYTE(LOWORD(data)); d2 = LOBYTE(HIWORD(data));
        if (evt < 0xF0) dest->runningStatus = evt;
        else if (evt <= 0xF7) dest->runningStatus = 0;
    } else if (dest->runningStatus) {
        evt = dest->runningStatus; d1 = LOBYTE(LOWORD(data)); d2 = HIBYTE(LOWORD(data));
    } else return MMSYSERR_NOERROR;

    buf[0] = evt; buf[1] = d1; buf[2] = d2;
    switch (evt & 0xF0) {
    case 0xC0: case 0xD0: len = 2; break;
    case 0xF0:
        switch (evt) { case 0xF1: case 0xF3: len = 2; break; case 0xF2: len = 3; break; default: len = 1; break; }
        break;
    default: len = 3; break;
    }

    hdr[0] = (unsigned char)id; hdr[1] = len; hdr[2] = 0;
    if (jack_ringbuffer_write_space(out_rb) >= (size_t)(OUT_RB_HDR_SIZE + len)) {
        jack_ringbuffer_write(out_rb, (char *)hdr, OUT_RB_HDR_SIZE);
        jack_ringbuffer_write(out_rb, (char *)buf, len);
    } else {
        WARN("MIDI output ringbuffer full, dropping short message\n");
        return MIDIERR_NOTREADY;
    }
    return MMSYSERR_NOERROR;
}

static UINT midi_out_long_data(WORD id, MIDIHDR *mh, UINT sz, struct notify_context *n)
{
    struct midi_dest *dest; unsigned char rb_h[OUT_RB_HDR_SIZE];
    BYTE *data, *nd = NULL; UINT len; int la = 0;
    if (id >= num_dests) return MMSYSERR_BADDEVICEID;
    dest = &dests[id];
    if (!dest->bEnabled || !dest->port) return MIDIERR_NODEVICE;
    data = (BYTE *)mh->lpData;
    if (!data) return MIDIERR_UNPREPARED;
    if (!(mh->dwFlags & MHDR_PREPARED)) return MIDIERR_UNPREPARED;
    if (mh->dwFlags & MHDR_INQUEUE) return MIDIERR_STILLPLAYING;
    mh->dwFlags &= ~MHDR_DONE; mh->dwFlags |= MHDR_INQUEUE;

    if (data[0] != 0xF0 || data[mh->dwBufferLength - 1] != 0xF7) {
        nd = malloc(mh->dwBufferLength + 2);
        if (!nd) { mh->dwFlags &= ~MHDR_INQUEUE; return MMSYSERR_NOMEM; }
    }
    if (nd) {
        if (data[0] != 0xF0) { la = 1; nd[0] = 0xF0; memcpy(nd + 1, data, mh->dwBufferLength); }
        else memcpy(nd, data, mh->dwBufferLength);
        if (data[mh->dwBufferLength - 1] != 0xF7) { nd[mh->dwBufferLength + la] = 0xF7; la++; }
        data = nd;
    }
    len = mh->dwBufferLength + la;
    rb_h[0] = (unsigned char)id; rb_h[1] = len & 0xFF; rb_h[2] = (len >> 8) & 0xFF;
    if (jack_ringbuffer_write_space(out_rb) >= (size_t)(OUT_RB_HDR_SIZE + len)) {
        jack_ringbuffer_write(out_rb, (char *)rb_h, OUT_RB_HDR_SIZE);
        jack_ringbuffer_write(out_rb, (char *)data, len);
    } else {
        WARN("MIDI output ringbuffer full, dropping SysEx (%u bytes)\n", len);
        free(nd);
        mh->dwFlags &= ~MHDR_INQUEUE;
        return MIDIERR_NOTREADY;
    }
    free(nd);
    dest->runningStatus = 0;
    mh->dwFlags &= ~MHDR_INQUEUE; mh->dwFlags |= MHDR_DONE;
    set_out_notify(n, dest, id, MOM_DONE, (DWORD_PTR)mh, 0);
    return MMSYSERR_NOERROR;
}

static UINT midi_out_prepare(WORD id, MIDIHDR *h, UINT sz)
{
    if (sz < offsetof(MIDIHDR, dwOffset) || !h || !h->lpData) return MMSYSERR_INVALPARAM;
    if (h->dwFlags & MHDR_PREPARED) return MMSYSERR_NOERROR;
    h->lpNext = NULL; h->dwFlags |= MHDR_PREPARED; h->dwFlags &= ~(MHDR_DONE|MHDR_INQUEUE);
    return MMSYSERR_NOERROR;
}

static UINT midi_out_unprepare(WORD id, MIDIHDR *h, UINT sz)
{
    if (sz < offsetof(MIDIHDR, dwOffset) || !h || !h->lpData) return MMSYSERR_INVALPARAM;
    if (!(h->dwFlags & MHDR_PREPARED)) return MMSYSERR_NOERROR;
    h->dwFlags &= ~MHDR_PREPARED; return MMSYSERR_NOERROR;
}

static UINT midi_out_reset(WORD id)
{
    struct midi_dest *d; unsigned char msg[3], h[OUT_RB_HDR_SIZE]; int ch;
    if (id >= num_dests) return MMSYSERR_BADDEVICEID;
    d = &dests[id]; if (!d->bEnabled || !d->port) return MMSYSERR_NOTENABLED;
    for (ch = 0; ch < 16; ch++) {
        /* CC 120: All Sound Off — hard kill, stops all audio immediately */
        msg[0] = 0xB0|ch; msg[1] = 120; msg[2] = 0;
        h[0] = (unsigned char)id; h[1] = 3; h[2] = 0;
        if (jack_ringbuffer_write_space(out_rb) >= OUT_RB_HDR_SIZE + 3) {
            jack_ringbuffer_write(out_rb, (char *)h, OUT_RB_HDR_SIZE);
            jack_ringbuffer_write(out_rb, (char *)msg, 3);
        }
        /* CC 123: All Notes Off — releases held notes */
        msg[1] = 123;
        if (jack_ringbuffer_write_space(out_rb) >= OUT_RB_HDR_SIZE + 3) {
            jack_ringbuffer_write(out_rb, (char *)h, OUT_RB_HDR_SIZE);
            jack_ringbuffer_write(out_rb, (char *)msg, 3);
        }
    }
    d->runningStatus = 0; return MMSYSERR_NOERROR;
}

/* ── Input ── */

static void handle_midi_input(struct midi_src *src, const unsigned char *data, uint16_t len,
                              uint32_t frame_off)
{
    UINT ct; struct notify_context notify;
    if (src->state != 1) return;
    /* Sub-period timestamp: base time + frame offset within the JACK period.
     * This gives sub-ms resolution instead of quantizing all events in one
     * period to the same timestamp. */
    ct = get_time_msec() - src->startTime;
    if (jack_rate > 0)
        ct += (UINT)((uint64_t)frame_off * 1000 / jack_rate);

    if (len > 0 && data[0] == 0xF0) {
        UINT pos = 0, cl;
        in_buffer_lock();
        while (pos < len && src->lpQueueHdr) {
            MIDIHDR *h = src->lpQueueHdr;
            cl = min(len - pos, h->dwBufferLength - h->dwBytesRecorded);
            memcpy(h->lpData + h->dwBytesRecorded, data + pos, cl);
            h->dwBytesRecorded += cl; pos += cl;
            if (h->dwBytesRecorded == h->dwBufferLength ||
                *(BYTE *)(h->lpData + h->dwBytesRecorded - 1) == 0xF7) {
                src->lpQueueHdr = h->lpNext;
                h->dwFlags &= ~MHDR_INQUEUE; h->dwFlags |= MHDR_DONE;
                set_in_notify(&notify, src, src - srcs, MIM_LONGDATA, (DWORD_PTR)h, ct);
                notify_post(&notify);
            }
        }
        in_buffer_unlock();
    } else if (len >= 1) {
        UINT msg = data[0];
        if (len >= 2) msg |= (UINT)data[1] << 8;
        if (len >= 3) msg |= (UINT)data[2] << 16;
        set_in_notify(&notify, src, src - srcs, MIM_DATA, msg, ct);
        notify_post(&notify);
    }
}

static void *in_notify_thread(void *arg)
{
    struct pollfd pfd; (void)arg;
    pfd.fd = wakeup_pipe[0]; pfd.events = POLLIN;
    while (!in_notify_quit) {
        if (poll(&pfd, 1, 10) <= 0) continue;  /* 10ms max latency for MIDI input */
        { char dr[64]; (void)read(wakeup_pipe[0], dr, sizeof(dr)); }
        while (jack_ringbuffer_read_space(in_rb) >= IN_RB_HDR_SIZE) {
            unsigned char hdr[IN_RB_HDR_SIZE], data[4096];
            uint8_t dev; uint16_t len; uint32_t frame_off;
            if (jack_ringbuffer_peek(in_rb, (char *)hdr, IN_RB_HDR_SIZE) < IN_RB_HDR_SIZE) break;
            dev = hdr[0]; len = hdr[1] | ((uint16_t)hdr[2] << 8);
            frame_off = (uint32_t)hdr[3] | ((uint32_t)hdr[4] << 8) |
                        ((uint32_t)hdr[5] << 16) | ((uint32_t)hdr[6] << 24);
            if (len > sizeof(data)) len = sizeof(data);
            if (jack_ringbuffer_read_space(in_rb) < (size_t)(IN_RB_HDR_SIZE + len)) break;
            jack_ringbuffer_read_advance(in_rb, IN_RB_HDR_SIZE);
            jack_ringbuffer_read(in_rb, (char *)data, len);
            if (dev < num_srcs) handle_midi_input(&srcs[dev], data, len, frame_off);
        }
        /* Check for dropped events (RT callback couldn't write to ringbuffer) */
        {
            unsigned int si;
            for (si = 0; si < num_srcs; si++)
            {
                UINT32 dropped = __atomic_exchange_n(&srcs[si].dropped_events, 0, __ATOMIC_RELAXED);
                if (dropped > 0 && srcs[si].state == 1)
                {
                    struct notify_context notify;
                    UINT ct = get_time_msec() - srcs[si].startTime;
                    set_in_notify(&notify, &srcs[si], si, MIM_ERROR, 0, ct);
                    notify_post(&notify);
                }
            }
        }
    }
    return NULL;
}

static UINT midi_in_open(WORD id, MIDIOPENDESC *desc, UINT flags, struct notify_context *n)
{
    struct midi_src *s; char pn[64];
    if (!desc) return MMSYSERR_INVALPARAM;
    if (id >= num_srcs) return MMSYSERR_BADDEVICEID;
    s = &srcs[id]; if (s->state == -1) return MIDIERR_NODEVICE;
    if (s->midiDesc.hMidi) return MMSYSERR_ALLOCATED;
    s->wFlags = HIWORD(flags & CALLBACK_TYPEMASK);
    s->lpQueueHdr = NULL; s->midiDesc = *desc; s->state = 0;
    snprintf(pn, sizeof(pn), "midi_in_%u", id);
    seq_lock();
    s->port = jack_port_register(jack_get_client(), pn, JACK_DEFAULT_MIDI_TYPE, JackPortIsInput, 0);
    seq_unlock();
    if (!s->port) return MMSYSERR_ERROR;
    if (jack_connect(jack_get_client(), s->target, jack_port_name(s->port)))
        WARN("auto-connect %s → %s failed\n", s->target, pn);
    if (num_midi_in_started++ == 0) {
        in_notify_quit = 0;
        if (pthread_create(&in_notify_thread_id, NULL, in_notify_thread, NULL)) {
            num_midi_in_started = 0; jack_port_unregister(jack_get_client(), s->port); s->port = NULL;
            return MMSYSERR_ERROR;
        }
    }
    set_in_notify(n, s, id, MIM_OPEN, 0, 0);
    return MMSYSERR_NOERROR;
}

static UINT midi_in_close(WORD id, struct notify_context *n)
{
    struct midi_src *s;
    if (id >= num_srcs) return MMSYSERR_BADDEVICEID;
    s = &srcs[id]; if (!s->midiDesc.hMidi) return MMSYSERR_ERROR;
    if (s->lpQueueHdr) return MIDIERR_STILLPLAYING;
    seq_lock(); if (s->port) { jack_port_unregister(jack_get_client(), s->port); s->port = NULL; } seq_unlock();
    if (--num_midi_in_started == 0) {
        in_notify_quit = 1;
        if (wakeup_pipe[1] >= 0) { char x = 0; (void)write(wakeup_pipe[1], &x, 1); }
        pthread_join(in_notify_thread_id, NULL);
    }
    set_in_notify(n, s, id, MIM_CLOSE, 0, 0); s->midiDesc.hMidi = 0; s->state = 0;
    return MMSYSERR_NOERROR;
}

static UINT midi_in_add_buffer(WORD id, MIDIHDR *h, UINT sz)
{
    struct midi_src *s;
    if (id >= num_srcs) return MMSYSERR_BADDEVICEID; s = &srcs[id];
    if (!h || sz < offsetof(MIDIHDR, dwOffset)) return MMSYSERR_INVALPARAM;
    if (!(h->dwFlags & MHDR_PREPARED)) return MIDIERR_UNPREPARED;
    if (h->dwFlags & MHDR_INQUEUE) return MIDIERR_STILLPLAYING;
    h->dwFlags &= ~MHDR_DONE; h->dwFlags |= MHDR_INQUEUE; h->dwBytesRecorded = 0; h->lpNext = NULL;
    in_buffer_lock();
    if (!s->lpQueueHdr) s->lpQueueHdr = h;
    else { MIDIHDR *p = s->lpQueueHdr; while (p->lpNext) p = p->lpNext; p->lpNext = h; }
    in_buffer_unlock();
    return MMSYSERR_NOERROR;
}

static UINT midi_in_start(WORD id) { if (id >= num_srcs) return MMSYSERR_BADDEVICEID; srcs[id].state = 1; srcs[id].startTime = get_time_msec(); return MMSYSERR_NOERROR; }
static UINT midi_in_stop(WORD id) { if (id >= num_srcs) return MMSYSERR_BADDEVICEID; srcs[id].state = 0; return MMSYSERR_NOERROR; }

static UINT midi_in_reset(WORD id, struct notify_context *n)
{
    struct midi_src *s; UINT ct;
    if (id >= num_srcs) return MMSYSERR_BADDEVICEID; s = &srcs[id];
    in_buffer_lock(); ct = get_time_msec();
    while (s->lpQueueHdr) {
        MIDIHDR *h = s->lpQueueHdr; s->lpQueueHdr = h->lpNext;
        h->dwFlags &= ~MHDR_INQUEUE; h->dwFlags |= MHDR_DONE;
        set_in_notify(n, s, id, MIM_LONGDATA, (DWORD_PTR)h, ct - s->startTime);
        notify_post(n);
    }
    in_buffer_unlock(); s->state = 0;
    return MMSYSERR_NOERROR;
}

/* ── Message dispatchers ── */

NTSTATUS jack_midi_out_message(void *args)
{
    struct midi_out_message_params *params = args;
    params->notify->send_notify = FALSE;
    switch (params->msg) {
    case DRVM_INIT:      *params->err = jack_midi_init_ex(); break;
    case DRVM_EXIT:
    {
        /* Close any open output ports to prevent JACK port leaks */
        unsigned int di;
        for (di = 0; di < num_dests; di++) {
            if (dests[di].bEnabled && dests[di].port) {
                seq_lock();
                jack_port_unregister(jack_get_client(), dests[di].port);
                dests[di].port = NULL;
                seq_unlock();
                dests[di].bEnabled = FALSE;
                dests[di].midiDesc.hMidi = 0;
            }
        }
        *params->err = MMSYSERR_NOERROR;
        break;
    }
    case MODM_OPEN:      *params->err = midi_out_open(params->dev_id, (MIDIOPENDESC *)params->param_1, params->param_2, params->notify); break;
    case MODM_CLOSE:     *params->err = midi_out_close(params->dev_id, params->notify); break;
    case MODM_DATA:      *params->err = midi_out_data(params->dev_id, params->param_1); break;
    case MODM_LONGDATA:  *params->err = midi_out_long_data(params->dev_id, (MIDIHDR *)params->param_1, params->param_2, params->notify); break;
    case MODM_PREPARE:   *params->err = midi_out_prepare(params->dev_id, (MIDIHDR *)params->param_1, params->param_2); break;
    case MODM_UNPREPARE: *params->err = midi_out_unprepare(params->dev_id, (MIDIHDR *)params->param_1, params->param_2); break;
    case MODM_GETDEVCAPS:
        *params->err = (params->dev_id >= num_dests) ? MMSYSERR_BADDEVICEID : MMSYSERR_NOERROR;
        if (!*params->err) memcpy((void *)params->param_1, &dests[params->dev_id].caps, min(params->param_2, sizeof(MIDIOUTCAPSW)));
        break;
    case MODM_GETNUMDEVS: *params->err = num_dests; break;
    case MODM_GETVOLUME:  if (params->param_1) *(UINT *)params->param_1 = 0xFFFFFFFF; *params->err = MMSYSERR_NOERROR; break;
    case MODM_SETVOLUME:  *params->err = MMSYSERR_NOERROR; break;
    case MODM_RESET:      *params->err = midi_out_reset(params->dev_id); break;
    default:              *params->err = MMSYSERR_NOTSUPPORTED; break;
    }
    return STATUS_SUCCESS;
}

NTSTATUS jack_midi_in_message(void *args)
{
    struct midi_in_message_params *params = args;
    params->notify->send_notify = FALSE;
    switch (params->msg) {
    case DRVM_INIT:      *params->err = jack_midi_init_ex(); break;
    case DRVM_EXIT:
    {
        /* Close any open input ports to prevent JACK port leaks */
        unsigned int si;
        for (si = 0; si < num_srcs; si++) {
            if (srcs[si].midiDesc.hMidi && srcs[si].port) {
                seq_lock();
                jack_port_unregister(jack_get_client(), srcs[si].port);
                srcs[si].port = NULL;
                seq_unlock();
                srcs[si].midiDesc.hMidi = 0;
                srcs[si].state = 0;
            }
        }
        if (num_midi_in_started > 0) {
            in_notify_quit = 1;
            if (wakeup_pipe[1] >= 0) { char x = 0; (void)write(wakeup_pipe[1], &x, 1); }
            pthread_join(in_notify_thread_id, NULL);
            num_midi_in_started = 0;
        }
        *params->err = MMSYSERR_NOERROR;
        break;
    }
    case MIDM_OPEN:      *params->err = midi_in_open(params->dev_id, (MIDIOPENDESC *)params->param_1, params->param_2, params->notify); break;
    case MIDM_CLOSE:     *params->err = midi_in_close(params->dev_id, params->notify); break;
    case MIDM_ADDBUFFER: *params->err = midi_in_add_buffer(params->dev_id, (MIDIHDR *)params->param_1, params->param_2); break;
    case MIDM_PREPARE:   *params->err = midi_out_prepare(params->dev_id, (MIDIHDR *)params->param_1, params->param_2); break;
    case MIDM_UNPREPARE: *params->err = midi_out_unprepare(params->dev_id, (MIDIHDR *)params->param_1, params->param_2); break;
    case MIDM_GETDEVCAPS:
        *params->err = (params->dev_id >= num_srcs) ? MMSYSERR_BADDEVICEID : MMSYSERR_NOERROR;
        if (!*params->err) memcpy((void *)params->param_1, &srcs[params->dev_id].caps, min(params->param_2, sizeof(MIDIINCAPSW)));
        break;
    case MIDM_GETNUMDEVS: *params->err = num_srcs; break;
    case MIDM_START:      *params->err = midi_in_start(params->dev_id); break;
    case MIDM_STOP:       *params->err = midi_in_stop(params->dev_id); break;
    case MIDM_RESET:      *params->err = midi_in_reset(params->dev_id, params->notify); break;
    default:              *params->err = MMSYSERR_NOTSUPPORTED; break;
    }
    return STATUS_SUCCESS;
}

NTSTATUS jack_midi_release(void *args)
{
    notify_post(NULL);
    if (num_midi_in_started > 0) {
        in_notify_quit = 1;
        if (wakeup_pipe[1] >= 0) { char x = 0; (void)write(wakeup_pipe[1], &x, 1); }
        pthread_join(in_notify_thread_id, NULL); num_midi_in_started = 0;
    }
    if (wakeup_pipe[0] >= 0) { close(wakeup_pipe[0]); wakeup_pipe[0] = -1; }
    if (wakeup_pipe[1] >= 0) { close(wakeup_pipe[1]); wakeup_pipe[1] = -1; }
    jack_midi_cleanup_ringbufs(); jack_midi_available = FALSE;
    return STATUS_SUCCESS;
}

NTSTATUS jack_midi_notify_wait(void *args)
{
    struct midi_notify_wait_params *params = args;
    pi_mutex_lock(&notify_mutex);
    while (!notify_quit && notify_read == notify_write)
        pi_cond_wait(&notify_read_cond, &notify_mutex);
    *params->quit = notify_quit;
    if (!notify_quit) {
        *params->notify = *notify_read;
        notify_read = notify_buffer_next(notify_read);
    }
    pi_cond_signal(&notify_write_cond, &notify_mutex);
    pi_mutex_unlock(&notify_mutex);
    return STATUS_SUCCESS;
}
