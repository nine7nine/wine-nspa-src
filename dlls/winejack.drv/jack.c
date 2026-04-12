/*
 * JACK audio/MIDI driver for Wine (unix library)
 *
 * Phase 1: MIDI via JACK MIDI (fully functional)
 * Phase 2: Audio via JACK WASAPI (in progress)
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
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <math.h>
#include <sys/mman.h>
#include <jack/jack.h>

#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "initguid.h"
#include "audioclient.h"
#include "mmdeviceapi.h"

#include "wine/debug.h"
#include "wine/list.h"
#include "wine/unixlib.h"

#include "unixlib.h"
#include <rtpi.h>

WINE_DEFAULT_DEBUG_CHANNEL(jack);

/* ════════════════════════════════════════════════════════════════════════
 *   Forward declarations for jackmidi.c
 * ════════════════════════════════════════════════════════════════════════ */

extern BOOL jack_midi_available;
extern NTSTATUS jack_midi_release(void *args);
extern NTSTATUS jack_midi_out_message(void *args);
extern NTSTATUS jack_midi_in_message(void *args);
extern NTSTATUS jack_midi_notify_wait(void *args);

/* Called by jackmidi.c to get the shared JACK client + ensure activation */
extern jack_client_t *jack_get_client(void);
extern BOOL jack_ensure_activated(void);

/* Called from the unified process callback to handle MIDI I/O */
extern int jack_midi_process(jack_nframes_t nframes);

/* ════════════════════════════════════════════════════════════════════════
 *   JACK audio client (singleton, shared by all streams)
 * ════════════════════════════════════════════════════════════════════════ */

static jack_client_t *audio_client;
static pi_mutex_t     audio_client_lock = PI_MUTEX_INIT(0);
static UINT32         jack_buf_frames;   /* JACK period in frames */
static UINT32         jack_rate;         /* JACK sample rate */
static ULONG_PTR      zero_bits;

/* ════════════════════════════════════════════════════════════════════════
 *   Format enum (needed by stream struct)
 * ════════════════════════════════════════════════════════════════════════ */

enum sample_format { FMT_F32, FMT_S32, FMT_S24, FMT_S16 };

/* ════════════════════════════════════════════════════════════════════════
 *   Stream structure (per WASAPI stream)
 * ════════════════════════════════════════════════════════════════════════ */

#define MAX_AUDIO_STREAMS 64

struct jack_stream
{
    /* JACK */
    jack_port_t        **ports;
    int                  nports;

    /* Format */
    WAVEFORMATEXTENSIBLE *fmt;
    DWORD                flags;
    AUDCLNT_SHAREMODE    share;
    EDataFlow            flow;

    /* Buffer geometry */
    UINT32  bufsize_frames;
    UINT32  mmdev_period_frames;
    REFERENCE_TIME mmdev_period_rt;

    /* Ring buffer — RT callback reads lcl_offs/held, app writes wri_offs/held.
     * For lock-free RT access, the RT side reads these atomically without
     * taking the lock (see jack_process_render/capture). */
    BYTE   *local_buffer;
    volatile UINT32  lcl_offs_frames;
    volatile UINT32  wri_offs_frames;
    volatile UINT32  held_frames;
    UINT64  written_frames;
    UINT64  last_pos_frames;

    /* GetBuffer/ReleaseBuffer */
    BYTE   *tmp_buffer;
    UINT32  tmp_buffer_frames;
    LONG    getbuf_last;  /* >0 direct, <0 tmp, 0 none */

    /* Volumes — pre-scaled for each format (set in set_volumes):
     * For F32: vols[ch] = raw volume (multiply in inner loop, skip if 1.0)
     * For S16: vols[ch] = raw_vol / 32768.0f
     * For S32: vols[ch] = raw_vol / 2147483648.0f
     * For S24: vols[ch] = raw_vol / 8388608.0f
     * render_chunk just multiplies — no division in inner loop. */
    float  *vols;
    float  *vols_raw;  /* un-scaled volumes for format-change recalc */
    int     nchannels;

    /* Cached format for RT fast-path (set once at creation, no branches in inner loop) */
    enum sample_format sfmt;

    /* Timing */
    LARGE_INTEGER last_period_time;

    /* Event-driven mode */
    HANDLE  event;

    /* State */
    volatile BOOL    started;
    BOOL    please_quit;

    /* Sync — app-side only; RT callback is lock-free */
    pi_mutex_t lock;
};

static struct jack_stream *active_streams[MAX_AUDIO_STREAMS];

/* Forward declaration — defined near set_volumes */
static void recalc_vols_for_format(struct jack_stream *stream);
static int num_active_streams;
static pi_mutex_t streams_lock = PI_MUTEX_INIT(0);

/* ════════════════════════════════════════════════════════════════════════
 *   Stream lock helpers
 * ════════════════════════════════════════════════════════════════════════ */

static void stream_lock(struct jack_stream *s) { pi_mutex_lock(&s->lock); }
static void stream_unlock(struct jack_stream *s) { pi_mutex_unlock(&s->lock); }

static NTSTATUS stream_unlock_result(struct jack_stream *s, HRESULT *result, HRESULT hr)
{
    *result = hr;
    stream_unlock(s);
    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Helpers
 * ════════════════════════════════════════════════════════════════════════ */

static DWORD get_channel_mask(unsigned int channels)
{
    switch (channels) {
    case 0:  return 0;
    case 1:  return KSAUDIO_SPEAKER_MONO;
    case 2:  return KSAUDIO_SPEAKER_STEREO;
    case 3:  return KSAUDIO_SPEAKER_STEREO | SPEAKER_LOW_FREQUENCY;
    case 4:  return KSAUDIO_SPEAKER_QUAD;
    case 5:  return KSAUDIO_SPEAKER_QUAD | SPEAKER_LOW_FREQUENCY;
    case 6:  return KSAUDIO_SPEAKER_5POINT1;
    case 7:  return KSAUDIO_SPEAKER_5POINT1 | SPEAKER_BACK_CENTER;
    case 8:  return KSAUDIO_SPEAKER_7POINT1_SURROUND;
    }
    FIXME("Unknown speaker configuration: %u\n", channels);
    return 0;
}

static inline UINT32 muldiv(UINT32 a, UINT32 b, UINT32 c)
{
    return (UINT32)(((UINT64)a * b + c / 2) / c);
}

static void silence_buffer(const WAVEFORMATEX *fmt, BYTE *buf, UINT32 frames)
{
    /* PCM 8-bit is unsigned (silence = 0x80), everything else is zero */
    WAVEFORMATEXTENSIBLE *fmtex = (WAVEFORMATEXTENSIBLE *)fmt;
    if ((fmt->wFormatTag == WAVE_FORMAT_PCM ||
         (fmt->wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
          IsEqualGUID(&fmtex->SubFormat, &KSDATAFORMAT_SUBTYPE_PCM))) &&
        fmt->wBitsPerSample == 8)
        memset(buf, 128, frames * fmt->nBlockAlign);
    else
        memset(buf, 0, frames * fmt->nBlockAlign);
}

static WAVEFORMATEXTENSIBLE *clone_format(const WAVEFORMATEX *fmt)
{
    WAVEFORMATEXTENSIBLE *ret;
    size_t size = (fmt->wFormatTag == WAVE_FORMAT_EXTENSIBLE)
        ? sizeof(WAVEFORMATEXTENSIBLE) : sizeof(WAVEFORMATEX);
    ret = malloc(size);
    if (!ret) return NULL;
    memcpy(ret, fmt, size);
    ret->Format.cbSize = size - sizeof(WAVEFORMATEX);
    return ret;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Format detection helper
 * ════════════════════════════════════════════════════════════════════════ */

static enum sample_format get_sample_format(const WAVEFORMATEXTENSIBLE *fmt)
{
    if (fmt->Format.wFormatTag == WAVE_FORMAT_IEEE_FLOAT)
        return FMT_F32;
    if (fmt->Format.wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
        IsEqualGUID(&fmt->SubFormat, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT))
        return FMT_F32;
    /* PCM */
    switch (fmt->Format.wBitsPerSample)
    {
    case 32: return FMT_S32;
    case 24: return FMT_S24;
    default: return FMT_S16;
    }
}

/* ════════════════════════════════════════════════════════════════════════
 *   Format conversion: interleaved app-format ↔ deinterleaved float32
 *
 *   These run inside the JACK process callback (RT context).
 *   No allocation, no branching in inner loops, volume applied inline.
 * ════════════════════════════════════════════════════════════════════════ */

/* ════════════════════════════════════════════════════════════════════════
 *   JACK audio process callback (RT context — no blocking, no alloc)
 *
 *   Optimized for the hot path:
 *   - Format switch is OUTSIDE the inner loop (one branch per chunk,
 *     not per sample)
 *   - Float32 fast path: unity volume skips the multiply entirely
 *   - Volume scaling folded into the format conversion constant
 *   - Port buffer pointers gathered once, not per-channel-per-chunk
 * ════════════════════════════════════════════════════════════════════════ */

/* Render one contiguous chunk from local_buffer to JACK port buffers.
 * Separate loops per format avoid branches in the inner loop. */
static void render_chunk(struct jack_stream *s, UINT32 src_offs,
                         float **jack_bufs, UINT32 dst_offs, UINT32 frames)
{
    const UINT32 block = s->fmt->Format.nBlockAlign;
    const BYTE *base = s->local_buffer + src_offs * block;
    UINT32 ch, j;

    /* Volume is pre-scaled in set_volumes() — no division here.
     * For F32: vols[ch] = raw_vol (1.0 at unity)
     * For S16: vols[ch] = raw_vol / 32768
     * For S32: vols[ch] = raw_vol / 2147483648
     * For S24: vols[ch] = raw_vol / 8388608
     * Unity-volume fast path: skip multiply entirely (all formats). */
    switch (s->sfmt)
    {
    case FMT_F32:
        for (ch = 0; ch < (UINT32)s->nports; ch++)
        {
            float *out = jack_bufs[ch] + dst_offs;
            float vol = s->vols[ch];
            const float *src = (const float *)base;
            if (vol == 1.0f)
                for (j = 0; j < frames; j++)
                    out[j] = src[j * s->nchannels + ch];
            else
                for (j = 0; j < frames; j++)
                    out[j] = src[j * s->nchannels + ch] * vol;
        }
        break;

    case FMT_S16:
    {
        float unity = 1.0f / 32768.0f;
        for (ch = 0; ch < (UINT32)s->nports; ch++)
        {
            float *out = jack_bufs[ch] + dst_offs;
            float vol = s->vols[ch];
            const INT16 *src = (const INT16 *)base;
            if (vol == unity)
                for (j = 0; j < frames; j++)
                    out[j] = (float)src[j * s->nchannels + ch] * unity;
            else
                for (j = 0; j < frames; j++)
                    out[j] = (float)src[j * s->nchannels + ch] * vol;
        }
        break;
    }

    case FMT_S32:
    {
        float unity = 1.0f / 2147483648.0f;
        for (ch = 0; ch < (UINT32)s->nports; ch++)
        {
            float *out = jack_bufs[ch] + dst_offs;
            float vol = s->vols[ch];
            const INT32 *src = (const INT32 *)base;
            if (vol == unity)
                for (j = 0; j < frames; j++)
                    out[j] = (float)src[j * s->nchannels + ch] * unity;
            else
                for (j = 0; j < frames; j++)
                    out[j] = (float)src[j * s->nchannels + ch] * vol;
        }
        break;
    }

    case FMT_S24:
        for (ch = 0; ch < (UINT32)s->nports; ch++)
        {
            float *out = jack_bufs[ch] + dst_offs;
            float vol = s->vols[ch];
            for (j = 0; j < frames; j++)
            {
                const BYTE *p = base + (j * s->nchannels + ch) * 3;
                INT32 v = (INT32)((UINT32)p[0] | ((UINT32)p[1] << 8) | ((UINT32)p[2] << 16));
                if (v & 0x800000) v |= 0xFF000000;
                out[j] = (float)v * vol;
            }
        }
        break;
    }
}

/* Lock-free render: the RT callback reads lcl_offs_frames and held_frames
 * without taking the lock. The app side (GetBuffer/ReleaseBuffer) only
 * modifies wri_offs_frames and held_frames under the lock. The RT side
 * is the sole writer of lcl_offs_frames. held_frames is updated atomically
 * by both sides (RT decrements, app increments). This is safe because:
 *   - lcl_offs_frames is only written by RT, read by app (no conflict)
 *   - wri_offs_frames is only written by app, read by RT (no conflict)
 *   - held_frames: worst case RT reads a stale (higher) value → renders
 *     slightly more data than available → still correct, no underrun
 *   - local_buffer contents: app writes ahead of wri_offs, RT reads
 *     behind at lcl_offs — they never overlap if bufsize >= 2 periods
 */
static void jack_process_render(struct jack_stream *s, jack_nframes_t nframes)
{
    UINT32 avail, offs, chunk1;
    int i;
    float *jack_bufs[64];

    /* Gather port buffer pointers once */
    for (i = 0; i < s->nports; i++)
        jack_bufs[i] = (float *)jack_port_get_buffer(s->ports[i], nframes);

    avail = s->held_frames;
    if (avail > nframes) avail = nframes;

    if (avail > 0)
    {
        offs = s->lcl_offs_frames;
        chunk1 = s->bufsize_frames - offs;

        if (chunk1 > avail) chunk1 = avail;

        render_chunk(s, offs, jack_bufs, 0, chunk1);
        if (avail > chunk1)
            render_chunk(s, 0, jack_bufs, chunk1, avail - chunk1);

        if (avail < nframes)
            for (i = 0; i < s->nports; i++)
                memset(jack_bufs[i] + avail, 0, (nframes - avail) * sizeof(float));

        s->lcl_offs_frames = (offs + avail) % s->bufsize_frames;
        __sync_sub_and_fetch(&s->held_frames, avail);
    }
    else
    {
        for (i = 0; i < s->nports; i++)
            memset(jack_bufs[i], 0, nframes * sizeof(float));
    }
}

/* Capture one contiguous chunk from JACK port buffers to local_buffer. */
static void capture_chunk(struct jack_stream *s, const float **jack_bufs,
                          UINT32 src_offs, UINT32 dst_offs, UINT32 frames)
{
    const UINT32 block = s->fmt->Format.nBlockAlign;
    BYTE *base = s->local_buffer + dst_offs * block;
    UINT32 ch, j;

    switch (s->sfmt)
    {
    case FMT_F32:
        for (ch = 0; ch < (UINT32)s->nports; ch++)
        {
            const float *in = jack_bufs[ch] + src_offs;
            float *dst = (float *)base;
            for (j = 0; j < frames; j++)
                dst[j * s->nchannels + ch] = in[j];
        }
        break;

    case FMT_S16:
        for (ch = 0; ch < (UINT32)s->nports; ch++)
        {
            const float *in = jack_bufs[ch] + src_offs;
            INT16 *dst = (INT16 *)base;
            for (j = 0; j < frames; j++)
            {
                INT32 v = (INT32)(in[j] * 32768.0f);
                if (v > 32767) v = 32767; else if (v < -32768) v = -32768;
                dst[j * s->nchannels + ch] = (INT16)v;
            }
        }
        break;

    case FMT_S32:
        for (ch = 0; ch < (UINT32)s->nports; ch++)
        {
            const float *in = jack_bufs[ch] + src_offs;
            INT32 *dst = (INT32 *)base;
            for (j = 0; j < frames; j++)
            {
                INT64 v = (INT64)(in[j] * 2147483648.0);
                if (v > 2147483647) v = 2147483647;
                else if (v < -2147483648LL) v = -2147483648LL;
                dst[j * s->nchannels + ch] = (INT32)v;
            }
        }
        break;

    case FMT_S24:
        for (ch = 0; ch < (UINT32)s->nports; ch++)
        {
            const float *in = jack_bufs[ch] + src_offs;
            for (j = 0; j < frames; j++)
            {
                INT32 v = (INT32)(in[j] * 8388608.0f);
                BYTE *p = base + (j * s->nchannels + ch) * 3;
                if (v > 8388607) v = 8388607; else if (v < -8388608) v = -8388608;
                p[0] = (BYTE)(v & 0xFF);
                p[1] = (BYTE)((v >> 8) & 0xFF);
                p[2] = (BYTE)((v >> 16) & 0xFF);
            }
        }
        break;
    }
}

/* Lock-free capture: RT callback writes at wri_offs_frames, app reads at
 * lcl_offs_frames. Same lock-free reasoning as render (reversed roles). */
static void jack_process_capture(struct jack_stream *s, jack_nframes_t nframes)
{
    UINT32 space, offs, chunk1;
    int i;
    const float *jack_bufs[64];

    for (i = 0; i < s->nports; i++)
        jack_bufs[i] = (const float *)jack_port_get_buffer(s->ports[i], nframes);

    space = s->bufsize_frames - s->held_frames;
    if (space > nframes) space = nframes;

    if (space > 0)
    {
        offs = s->wri_offs_frames;
        chunk1 = s->bufsize_frames - offs;

        if (chunk1 > space) chunk1 = space;

        capture_chunk(s, jack_bufs, 0, offs, chunk1);
        if (space > chunk1)
            capture_chunk(s, jack_bufs, chunk1, 0, space - chunk1);

        s->wri_offs_frames = (offs + space) % s->bufsize_frames;
        __sync_add_and_fetch(&s->held_frames, space);
    }
}

static int jack_audio_process_cb(jack_nframes_t nframes, void *arg)
{
    int i;
    (void)arg;

    /* Audio streams */
    for (i = 0; i < num_active_streams; i++)
    {
        struct jack_stream *s = active_streams[i];
        if (!s || !s->started) continue;

        if (s->flow == eRender)
            jack_process_render(s, nframes);
        else
            jack_process_capture(s, nframes);
    }

    /* Signal event-driven streams from the RT callback.
     * This gives the tightest possible wakeup timing — the app gets
     * signaled exactly when JACK has consumed/produced a buffer,
     * rather than relying on the timer thread's NtDelayExecution
     * which has kernel scheduling jitter. The timer thread still
     * runs (for apps that depend on periodic wakeups in push mode)
     * but event-driven apps will see the RT-sourced signal first. */
    for (i = 0; i < num_active_streams; i++)
    {
        struct jack_stream *s = active_streams[i];
        if (s && s->started && s->event)
            NtSetEvent(s->event, NULL);
    }

    /* MIDI ports (shared client — same RT callback) */
    if (jack_midi_available)
        jack_midi_process(nframes);

    return 0;
}

static int jack_bufsize_changed_cb(jack_nframes_t nframes, void *arg)
{
    (void)arg;
    jack_buf_frames = nframes;
    /* No TRACE here — this callback runs on a JACK thread with no TEB,
     * so Wine debug functions would segfault. */
    return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *   JACK audio client lifecycle (lazy init)
 * ════════════════════════════════════════════════════════════════════════ */

static BOOL ensure_audio_client(void)
{
    jack_status_t status;

    TRACE("ensure_audio_client: locking\n");
    pi_mutex_lock(&audio_client_lock);
    if (audio_client) { pi_mutex_unlock(&audio_client_lock); return TRUE; }

    TRACE("ensure_audio_client: opening client\n");
    audio_client = jack_client_open("wine-nspa", JackNoStartServer, &status);
    if (!audio_client)
    {
        WARN("Cannot connect to JACK for audio (%d)\n", status);
        pi_mutex_unlock(&audio_client_lock);
        return FALSE;
    }
    jack_buf_frames = jack_get_buffer_size(audio_client);
    jack_rate = jack_get_sample_rate(audio_client);
    ERR("NSPA RT:JACK: audio client connected (rate=%u, bufsize=%u frames)\n",
        jack_rate, jack_buf_frames);
    /* NOTE: we do NOT activate here.  jack_activate() starts the process
     * callback thread, which can conflict with Wine's threading/signal
     * model if called too early (e.g. during DLL_PROCESS_ATTACH driver
     * probing).  Activation is deferred to jack_activate_audio_client()
     * which is called from create_stream. */
    pi_mutex_unlock(&audio_client_lock);
    return TRUE;
}

static BOOL audio_client_activated;

static BOOL activate_audio_client(void)
{
    if (audio_client_activated) return TRUE;

    pi_mutex_lock(&audio_client_lock);
    if (audio_client_activated) { pi_mutex_unlock(&audio_client_lock); return TRUE; }
    if (!audio_client) { pi_mutex_unlock(&audio_client_lock); return FALSE; }

    jack_set_process_callback(audio_client, jack_audio_process_cb, NULL);
    jack_set_buffer_size_callback(audio_client, jack_bufsize_changed_cb, NULL);

    TRACE("activating JACK audio client\n");
    if (jack_activate(audio_client))
    {
        ERR("jack_activate failed for audio client\n");
        jack_client_close(audio_client);
        audio_client = NULL;
        pi_mutex_unlock(&audio_client_lock);
        return FALSE;
    }

    audio_client_activated = TRUE;
    TRACE("JACK audio client activated: rate=%u bufsize=%u\n", jack_rate, jack_buf_frames);
    pi_mutex_unlock(&audio_client_lock);
    return TRUE;
}

/* Accessors for jackmidi.c — shared JACK client */
jack_client_t *jack_get_client(void)
{
    return audio_client;
}

BOOL jack_ensure_activated(void)
{
    return ensure_audio_client() && activate_audio_client();
}

/* ════════════════════════════════════════════════════════════════════════
 *   Endpoint enumeration
 * ════════════════════════════════════════════════════════════════════════ */

/* Group JACK ports by client prefix, count channels per group.
 * For render: physical input ports (JackPortIsInput) = speakers
 * For capture: physical output ports (JackPortIsOutput) = mics */

struct jack_ep
{
    WCHAR name[64];        /* display name e.g. "system" */
    char  device[128];     /* JACK port prefix e.g. "system:playback_" */
    int   channels;
};

static void count_physical_ports(EDataFlow flow, struct jack_ep *eps, int *num_eps, int max_eps)
{
    const char **ports;
    unsigned long flags;
    int i;
    const char *suffix;

    TRACE("count_physical_ports flow=%d\n", flow);

    *num_eps = 0;

    if (!ensure_audio_client()) { TRACE("ensure_audio_client failed\n"); return; }
    TRACE("audio client ready, querying ports\n");

    /* For render we send TO physical input ports; for capture we read FROM physical output ports */
    flags = JackPortIsPhysical | (flow == eRender ? JackPortIsInput : JackPortIsOutput);
    suffix = flow == eRender ? "playback_" : "capture_";

    ports = jack_get_ports(audio_client, NULL, JACK_DEFAULT_AUDIO_TYPE, flags);
    TRACE("jack_get_ports returned %p\n", ports);
    if (!ports) return;

    for (i = 0; ports[i] && *num_eps < max_eps; i++)
    {
        const char *colon = strchr(ports[i], ':');
        size_t prefix_len;
        int found = -1, j;

        if (!colon) continue;
        prefix_len = colon - ports[i];

        /* Find existing group or create new */
        for (j = 0; j < *num_eps; j++)
        {
            if (!memcmp(eps[j].device, ports[i], prefix_len) &&
                eps[j].device[prefix_len] == ':')
            {
                found = j;
                break;
            }
        }

        if (found >= 0)
        {
            eps[found].channels++;
        }
        else if (*num_eps < max_eps)
        {
            struct jack_ep *ep = &eps[*num_eps];
            size_t k;

            memset(ep, 0, sizeof(*ep));
            ep->channels = 1;

            /* Build device string: "client:suffix" pattern */
            memcpy(ep->device, ports[i], prefix_len);
            ep->device[prefix_len] = ':';
            {
                size_t slen = strlen(suffix);
                if (prefix_len + 1 + slen < sizeof(ep->device))
                    memcpy(ep->device + prefix_len + 1, suffix, slen + 1);
                else
                    ep->device[prefix_len + 1] = 0;
            }

            /* Display name = client prefix */
            for (k = 0; k < prefix_len && k < ARRAY_SIZE(ep->name) - 1; k++)
                ep->name[k] = (WCHAR)(unsigned char)ports[i][k];
            ep->name[k] = 0;

            (*num_eps)++;
        }
    }

    jack_free(ports);
    TRACE("count_physical_ports done: %d endpoints\n", *num_eps);
}

static NTSTATUS jack_get_endpoint_ids(void *args)
{
    struct get_endpoint_ids_params *params = args;
    struct jack_ep eps[16];
    int num_eps = 0;
    unsigned int i, needed, offset;
    struct endpoint *ep_out;

    count_physical_ports(params->flow, eps, &num_eps, ARRAY_SIZE(eps));

    /* Compute needed buffer size */
    offset = needed = num_eps * sizeof(struct endpoint);
    ep_out = params->endpoints;

    for (i = 0; i < (unsigned)num_eps; i++)
    {
        unsigned int name_len = wcslen(eps[i].name) + 1;
        unsigned int dev_len = strlen(eps[i].device) + 1;
        needed += name_len * sizeof(WCHAR) + ((dev_len + 1) & ~1);

        if (needed <= params->size)
        {
            ep_out->name = offset;
            memcpy((char *)params->endpoints + offset, eps[i].name, name_len * sizeof(WCHAR));
            offset += name_len * sizeof(WCHAR);
            ep_out->device = offset;
            memcpy((char *)params->endpoints + offset, eps[i].device, dev_len);
            offset += (dev_len + 1) & ~1;
            ep_out++;
        }
    }

    params->num = num_eps;
    params->default_idx = 0;

    if (needed > params->size)
    {
        params->size = needed;
        params->result = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }
    else
        params->result = S_OK;

    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Format reporting
 * ════════════════════════════════════════════════════════════════════════ */

static NTSTATUS jack_get_mix_format(void *args)
{
    struct get_mix_format_params *params = args;
    WAVEFORMATEXTENSIBLE *fmt = params->fmt;
    struct jack_ep eps[16];
    int num_eps = 0, i;
    int channels = 2; /* default stereo */

    if (!ensure_audio_client())
    {
        params->result = AUDCLNT_E_DEVICE_INVALIDATED;
        return STATUS_SUCCESS;
    }

    /* Find channel count for this device */
    count_physical_ports(params->flow, eps, &num_eps, ARRAY_SIZE(eps));
    for (i = 0; i < num_eps; i++)
    {
        if (!strcmp(eps[i].device, params->device))
        {
            channels = eps[i].channels;
            break;
        }
    }

    if (channels > 6)
        channels = 2; /* Match ALSA behavior */
    if (channels > 1 && (channels & 1))
    {
        if (channels < 8) channels++;
        else WARN("Odd channel count %d\n", channels);
    }

    /* JACK is always float32 at its native rate */
    fmt->Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
    fmt->Format.nChannels = channels;
    fmt->Format.nSamplesPerSec = jack_rate;
    fmt->Format.wBitsPerSample = 32;
    fmt->Format.nBlockAlign = (fmt->Format.wBitsPerSample * fmt->Format.nChannels) / 8;
    fmt->Format.nAvgBytesPerSec = fmt->Format.nSamplesPerSec * fmt->Format.nBlockAlign;
    fmt->Format.cbSize = sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX);
    fmt->Samples.wValidBitsPerSample = 32;
    fmt->SubFormat = KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;
    fmt->dwChannelMask = get_channel_mask(channels);

    params->result = S_OK;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_get_device_period(void *args)
{
    struct get_device_period_params *params = args;
    REFERENCE_TIME jack_period;

    if (!ensure_audio_client())
    {
        params->result = AUDCLNT_E_DEVICE_INVALIDATED;
        return STATUS_SUCCESS;
    }

    /* JACK period in 100ns units */
    jack_period = (REFERENCE_TIME)jack_buf_frames * 10000000 / jack_rate;

    if (params->def_period)
    {
        /* Default period: 10ms (standard Windows default).  If JACK's period
         * is larger than 10ms, use JACK's period directly since that's the
         * real hardware constraint and we can't service faster. */
        if (jack_period > 100000)
            *params->def_period = jack_period;
        else
            *params->def_period = 100000;
    }
    if (params->min_period)
    {
        /* Minimum period: JACK's actual period, but never > default */
        *params->min_period = jack_period;
    }

    params->result = S_OK;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_is_format_supported(void *args)
{
    struct is_format_supported_params *params = args;
    const WAVEFORMATEX *fmt = params->fmt_in;

    TRACE("rate=%u bits=%u ch=%u tag=%u share=%d\n",
          (unsigned)fmt->nSamplesPerSec, (unsigned)fmt->wBitsPerSample,
          (unsigned)fmt->nChannels, (unsigned)fmt->wFormatTag, params->share);

    if (!ensure_audio_client())
    {
        params->result = AUDCLNT_E_DEVICE_INVALIDATED;
        return STATUS_SUCCESS;
    }

    /* Check format tag */
    if (fmt->wFormatTag == WAVE_FORMAT_EXTENSIBLE)
    {
        WAVEFORMATEXTENSIBLE *fmtex = (WAVEFORMATEXTENSIBLE *)fmt;
        if (!IsEqualGUID(&fmtex->SubFormat, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT) &&
            !IsEqualGUID(&fmtex->SubFormat, &KSDATAFORMAT_SUBTYPE_PCM))
        {
            params->result = AUDCLNT_E_UNSUPPORTED_FORMAT;
            return STATUS_SUCCESS;
        }
    }
    else if (fmt->wFormatTag != WAVE_FORMAT_PCM &&
             fmt->wFormatTag != WAVE_FORMAT_IEEE_FLOAT)
    {
        params->result = AUDCLNT_E_UNSUPPORTED_FORMAT;
        return STATUS_SUCCESS;
    }

    /* Sample rate must match JACK's rate */
    if (fmt->nSamplesPerSec != jack_rate)
    {
        if (params->share == AUDCLNT_SHAREMODE_EXCLUSIVE)
        {
            params->result = AUDCLNT_E_UNSUPPORTED_FORMAT;
            return STATUS_SUCCESS;
        }
        /* Shared mode: return S_FALSE (mmdevapi will suggest mix format) */
        params->result = S_FALSE;
        return STATUS_SUCCESS;
    }

    /* Bits per sample: accept 16, 24, 32 for PCM; 32 for float */
    if (fmt->wFormatTag == WAVE_FORMAT_IEEE_FLOAT ||
        (fmt->wFormatTag == WAVE_FORMAT_EXTENSIBLE &&
         IsEqualGUID(&((WAVEFORMATEXTENSIBLE *)fmt)->SubFormat, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT)))
    {
        if (fmt->wBitsPerSample != 32)
        {
            params->result = AUDCLNT_E_UNSUPPORTED_FORMAT;
            return STATUS_SUCCESS;
        }
    }
    else
    {
        if (fmt->wBitsPerSample != 16 && fmt->wBitsPerSample != 24 && fmt->wBitsPerSample != 32)
        {
            params->result = AUDCLNT_E_UNSUPPORTED_FORMAT;
            return STATUS_SUCCESS;
        }
    }

    params->result = S_OK;
    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Stub / not-implemented helpers
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
        zero_bits = (ULONG_PTR)info.HighestUserAddress | 0x7fffffff;
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

    client = jack_client_open("wine-probe", JackNoStartServer, &status);
    if (client)
    {
        jack_client_close(client);
        params->priority = Priority_Preferred;
        TRACE("JACK running, Priority_Preferred\n");
    }
    else
    {
        params->priority = Priority_Unavailable;
        TRACE("JACK not available (%d), Priority_Unavailable\n", status);
    }
    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Stream lifecycle
 * ════════════════════════════════════════════════════════════════════════ */

static inline struct jack_stream *handle_get_stream(stream_handle h)
{
    return (struct jack_stream *)(UINT_PTR)h;
}

static NTSTATUS jack_create_stream(void *args)
{
    struct create_stream_params *params = args;
    struct jack_stream *stream;
    WAVEFORMATEXTENSIBLE *fmtex;
    SIZE_T size;
    unsigned int i;
    struct jack_ep eps[16];
    int num_eps = 0, ch, target_channels = 2;
    char port_name[64];

    if (!ensure_audio_client() || !activate_audio_client())
    {
        params->result = AUDCLNT_E_ENDPOINT_CREATE_FAILED;
        return STATUS_SUCCESS;
    }

    /* Exclusive mode: reject formats that don't match JACK's native config.
     * JACK is fixed-rate float32.  In exclusive mode the app must use the
     * device's native format — no conversion or resampling. */
    if (params->share == AUDCLNT_SHAREMODE_EXCLUSIVE)
    {
        if (params->fmt->nSamplesPerSec != jack_rate)
        {
            WARN("exclusive: rejecting rate %u (JACK rate is %u)\n",
                 (unsigned)params->fmt->nSamplesPerSec, jack_rate);
            params->result = AUDCLNT_E_UNSUPPORTED_FORMAT;
            return STATUS_SUCCESS;
        }

        /* Exclusive event-driven mode requires period == duration */
        if ((params->flags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK) &&
            params->period != 0 && params->duration != params->period)
        {
            WARN("exclusive event-driven: duration %lld != period %lld\n",
                 (long long)params->duration, (long long)params->period);
            params->result = AUDCLNT_E_BUFDURATION_PERIOD_NOT_EQUAL;
            return STATUS_SUCCESS;
        }
    }

    stream = calloc(1, sizeof(*stream));
    if (!stream) { params->result = E_OUTOFMEMORY; return STATUS_SUCCESS; }

    stream->flow = params->flow;
    stream->share = params->share;
    stream->flags = params->flags;

    /* Compute period and buffer geometry */
    stream->mmdev_period_rt = params->period;
    stream->mmdev_period_frames = muldiv(params->fmt->nSamplesPerSec,
                                          params->period, 10000000);

    if (!stream->mmdev_period_frames)
    {
        free(stream);
        params->result = E_INVALIDARG;
        return STATUS_SUCCESS;
    }

    stream->bufsize_frames = muldiv(params->duration, params->fmt->nSamplesPerSec, 10000000);
    if (params->share == AUDCLNT_SHAREMODE_EXCLUSIVE)
        stream->bufsize_frames -= stream->bufsize_frames % stream->mmdev_period_frames;
    if (stream->bufsize_frames < stream->mmdev_period_frames * 2)
        stream->bufsize_frames = stream->mmdev_period_frames * 2;

    /* Clone format */
    fmtex = clone_format(params->fmt);
    if (!fmtex) { free(stream); params->result = E_OUTOFMEMORY; return STATUS_SUCCESS; }
    stream->fmt = fmtex;
    stream->nchannels = params->fmt->nChannels;
    stream->sfmt = get_sample_format(fmtex);

    /* Find target channel count from endpoint */
    count_physical_ports(params->flow, eps, &num_eps, ARRAY_SIZE(eps));
    for (i = 0; i < (unsigned)num_eps; i++)
    {
        if (!strcmp(eps[i].device, params->device))
        {
            target_channels = eps[i].channels;
            break;
        }
    }
    stream->nports = stream->nchannels < target_channels ? stream->nchannels : target_channels;

    /* Register JACK ports */
    stream->ports = calloc(stream->nports, sizeof(jack_port_t *));
    if (!stream->ports)
    {
        free(fmtex);
        free(stream);
        params->result = E_OUTOFMEMORY;
        return STATUS_SUCCESS;
    }

    for (ch = 0; ch < stream->nports; ch++)
    {
        snprintf(port_name, sizeof(port_name), "%s_%p_ch%d",
                 params->flow == eRender ? "out" : "in", stream, ch);
        stream->ports[ch] = jack_port_register(audio_client, port_name,
                                                JACK_DEFAULT_AUDIO_TYPE,
                                                params->flow == eRender ? JackPortIsOutput : JackPortIsInput, 0);
        if (!stream->ports[ch])
        {
            ERR("Failed to register JACK port %s\n", port_name);
            while (--ch >= 0)
                jack_port_unregister(audio_client, stream->ports[ch]);
            free(stream->ports);
            free(fmtex);
            free(stream);
            params->result = AUDCLNT_E_ENDPOINT_CREATE_FAILED;
            return STATUS_SUCCESS;
        }
    }

    /* Connect to physical ports */
    {
        const char **phys_ports;
        unsigned long port_flags = JackPortIsPhysical |
            (params->flow == eRender ? JackPortIsInput : JackPortIsOutput);

        phys_ports = jack_get_ports(audio_client, params->device, JACK_DEFAULT_AUDIO_TYPE, port_flags);
        if (phys_ports)
        {
            for (ch = 0; ch < stream->nports && phys_ports[ch]; ch++)
            {
                int err;
                if (params->flow == eRender)
                    err = jack_connect(audio_client, jack_port_name(stream->ports[ch]), phys_ports[ch]);
                else
                    err = jack_connect(audio_client, phys_ports[ch], jack_port_name(stream->ports[ch]));
                if (err && err != EEXIST)
                    WARN("jack_connect failed for ch%d: %d\n", ch, err);
            }
            jack_free(phys_ports);
        }
    }

    /* Allocate ring buffer */
    size = stream->bufsize_frames * params->fmt->nBlockAlign;
    if (NtAllocateVirtualMemory(GetCurrentProcess(), (void **)&stream->local_buffer,
                                 zero_bits, &size, MEM_COMMIT, PAGE_READWRITE))
    {
        params->result = E_OUTOFMEMORY;
        goto fail;
    }
    mlock(stream->local_buffer, size);  /* Pin audio buffer in RAM — prevent page faults in RT */
    silence_buffer(&fmtex->Format, stream->local_buffer, stream->bufsize_frames);

    /* Pre-allocate tmp_buffer to max period size (avoids allocation in GetBuffer hot path) */
    {
        SIZE_T tmp_size = stream->bufsize_frames * params->fmt->nBlockAlign;
        if (NtAllocateVirtualMemory(GetCurrentProcess(), (void **)&stream->tmp_buffer,
                                     zero_bits, &tmp_size, MEM_COMMIT, PAGE_READWRITE))
        {
            params->result = E_OUTOFMEMORY;
            goto fail;
        }
        mlock(stream->tmp_buffer, tmp_size);
        stream->tmp_buffer_frames = stream->bufsize_frames;
    }

    /* Allocate volumes (raw + pre-scaled) */
    stream->vols = malloc(stream->nchannels * sizeof(float));
    stream->vols_raw = malloc(stream->nchannels * sizeof(float));
    if (!stream->vols || !stream->vols_raw) { params->result = E_OUTOFMEMORY; goto fail; }
    for (i = 0; i < (unsigned)stream->nchannels; i++)
        stream->vols_raw[i] = 1.0f;
    recalc_vols_for_format(stream);

    pi_mutex_init(&stream->lock, 0);

    /* Register in active streams list */
    pi_mutex_lock(&streams_lock);
    if (num_active_streams < MAX_AUDIO_STREAMS)
        active_streams[num_active_streams++] = stream;
    else
        WARN("Too many active streams\n");
    pi_mutex_unlock(&streams_lock);

    TRACE("Created stream: %u frames, period %u frames, %d ports, fmt %u/%u/%u\n",
          stream->bufsize_frames, stream->mmdev_period_frames, stream->nports,
          (unsigned)fmtex->Format.nSamplesPerSec, (unsigned)fmtex->Format.wBitsPerSample,
          (unsigned)fmtex->Format.nChannels);

    *params->channel_count = params->fmt->nChannels;
    *params->stream = (stream_handle)(UINT_PTR)stream;
    params->result = S_OK;
    return STATUS_SUCCESS;

fail:
    for (ch = 0; ch < stream->nports; ch++)
        if (stream->ports[ch])
            jack_port_unregister(audio_client, stream->ports[ch]);
    free(stream->ports);
    if (stream->local_buffer)
    {
        size = 0;
        NtFreeVirtualMemory(GetCurrentProcess(), (void **)&stream->local_buffer, &size, MEM_RELEASE);
    }
    if (stream->tmp_buffer)
    {
        size = 0;
        NtFreeVirtualMemory(GetCurrentProcess(), (void **)&stream->tmp_buffer, &size, MEM_RELEASE);
    }
    free(stream->vols);
    free(stream->vols_raw);
    free(fmtex);
    free(stream);
    return STATUS_SUCCESS;
}

static NTSTATUS jack_release_stream(void *args)
{
    struct release_stream_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    SIZE_T size;
    int i;

    if (params->timer_thread)
    {
        stream->please_quit = TRUE;
        NtWaitForSingleObject(params->timer_thread, FALSE, NULL);
        NtClose(params->timer_thread);
    }

    /* Remove from active streams */
    pi_mutex_lock(&streams_lock);
    for (i = 0; i < num_active_streams; i++)
    {
        if (active_streams[i] == stream)
        {
            active_streams[i] = active_streams[--num_active_streams];
            active_streams[num_active_streams] = NULL;
            break;
        }
    }
    pi_mutex_unlock(&streams_lock);

    /* Unregister JACK ports */
    for (i = 0; i < stream->nports; i++)
        if (stream->ports[i])
            jack_port_unregister(audio_client, stream->ports[i]);
    free(stream->ports);

    if (stream->local_buffer)
    {
        size = 0;
        NtFreeVirtualMemory(GetCurrentProcess(), (void **)&stream->local_buffer, &size, MEM_RELEASE);
    }
    if (stream->tmp_buffer)
    {
        size = 0;
        NtFreeVirtualMemory(GetCurrentProcess(), (void **)&stream->tmp_buffer, &size, MEM_RELEASE);
    }
    free(stream->fmt);
    free(stream->vols);
    free(stream->vols_raw);
    pi_mutex_destroy(&stream->lock);
    free(stream);

    params->result = S_OK;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_start(void *args)
{
    struct start_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);

    stream_lock(stream);

    if ((stream->flags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK) && !stream->event)
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_EVENTHANDLE_NOT_SET);

    if (stream->started)
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_NOT_STOPPED);

    stream->started = TRUE;

    return stream_unlock_result(stream, &params->result, S_OK);
}

static NTSTATUS jack_stop(void *args)
{
    struct stop_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);

    stream_lock(stream);

    if (!stream->started)
        return stream_unlock_result(stream, &params->result, S_FALSE);

    stream->started = FALSE;

    return stream_unlock_result(stream, &params->result, S_OK);
}

static NTSTATUS jack_reset(void *args)
{
    struct reset_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);

    stream_lock(stream);

    if (stream->started)
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_NOT_STOPPED);

    if (stream->getbuf_last)
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_BUFFER_OPERATION_PENDING);

    if (stream->flow == eRender)
    {
        stream->written_frames = 0;
        stream->last_pos_frames = 0;
    }
    else
        stream->written_frames += stream->held_frames;

    stream->held_frames = 0;
    stream->lcl_offs_frames = 0;
    stream->wri_offs_frames = 0;

    return stream_unlock_result(stream, &params->result, S_OK);
}

/* ════════════════════════════════════════════════════════════════════════
 *   Timer loop — drives event signaling at WASAPI period cadence
 * ════════════════════════════════════════════════════════════════════════ */

static NTSTATUS jack_timer_loop(void *args)
{
    struct timer_loop_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    LARGE_INTEGER delay, next;
    int adjust;

    stream_lock(stream);

    delay.QuadPart = -stream->mmdev_period_rt;
    NtQueryPerformanceCounter(&stream->last_period_time, NULL);
    next.QuadPart = stream->last_period_time.QuadPart + stream->mmdev_period_rt;

    while (!stream->please_quit)
    {
        /* Signal event for event-driven clients */
        if (stream->event)
            NtSetEvent(stream->event, NULL);

        stream_unlock(stream);

        NtDelayExecution(FALSE, &delay);

        stream_lock(stream);
        NtQueryPerformanceCounter(&stream->last_period_time, NULL);

        /* Adaptive jitter correction (same as ALSA driver) */
        adjust = next.QuadPart - stream->last_period_time.QuadPart;
        if (adjust > stream->mmdev_period_rt / 2)
            adjust = stream->mmdev_period_rt / 2;
        else if (adjust < -stream->mmdev_period_rt / 2)
            adjust = -stream->mmdev_period_rt / 2;
        delay.QuadPart = -(stream->mmdev_period_rt + adjust);
        next.QuadPart += stream->mmdev_period_rt;
    }

    stream_unlock(stream);
    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Buffer management — GetBuffer / ReleaseBuffer
 * ════════════════════════════════════════════════════════════════════════ */

static void wrap_buffer(struct jack_stream *stream, BYTE *buffer, UINT32 written_frames)
{
    UINT32 wri_offs = stream->wri_offs_frames;
    UINT32 block = stream->fmt->Format.nBlockAlign;
    UINT32 chunk_frames = stream->bufsize_frames - wri_offs;
    UINT32 chunk_bytes = chunk_frames * block;
    UINT32 written_bytes = written_frames * block;

    if (written_bytes <= chunk_bytes)
        memcpy(stream->local_buffer + wri_offs * block, buffer, written_bytes);
    else
    {
        memcpy(stream->local_buffer + wri_offs * block, buffer, chunk_bytes);
        memcpy(stream->local_buffer, buffer + chunk_bytes, written_bytes - chunk_bytes);
    }
}

static NTSTATUS jack_get_render_buffer(void *args)
{
    struct get_render_buffer_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    UINT32 write_pos, frames = params->frames;

    stream_lock(stream);

    if (stream->getbuf_last)
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_OUT_OF_ORDER);

    if (!frames)
        return stream_unlock_result(stream, &params->result, S_OK);

    if (stream->held_frames + frames > stream->bufsize_frames)
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_BUFFER_TOO_LARGE);

    write_pos = stream->wri_offs_frames;
    if (write_pos + frames > stream->bufsize_frames)
    {
        /* Wraparound — use pre-allocated temp buffer (no allocation in hot path) */
        *params->data = stream->tmp_buffer;
        stream->getbuf_last = -(LONG)frames;
    }
    else
    {
        *params->data = stream->local_buffer + write_pos * stream->fmt->Format.nBlockAlign;
        stream->getbuf_last = frames;
    }

    silence_buffer(&stream->fmt->Format, *params->data, frames);

    return stream_unlock_result(stream, &params->result, S_OK);
}

static NTSTATUS jack_release_render_buffer(void *args)
{
    struct release_render_buffer_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    UINT32 written_frames = params->written_frames;
    BYTE *buffer;

    stream_lock(stream);

    if (!written_frames)
    {
        stream->getbuf_last = 0;
        return stream_unlock_result(stream, &params->result, S_OK);
    }

    if (!stream->getbuf_last)
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_OUT_OF_ORDER);

    if (written_frames > (UINT32)(stream->getbuf_last >= 0 ? stream->getbuf_last : -stream->getbuf_last))
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_INVALID_SIZE);

    if (stream->getbuf_last >= 0)
        buffer = stream->local_buffer + stream->wri_offs_frames * stream->fmt->Format.nBlockAlign;
    else
        buffer = stream->tmp_buffer;

    if (params->flags & AUDCLNT_BUFFERFLAGS_SILENT)
        silence_buffer(&stream->fmt->Format, buffer, written_frames);

    if (stream->getbuf_last < 0)
        wrap_buffer(stream, buffer, written_frames);

    stream->wri_offs_frames += written_frames;
    stream->wri_offs_frames %= stream->bufsize_frames;
    __sync_add_and_fetch(&stream->held_frames, written_frames);
    stream->written_frames += written_frames;
    stream->getbuf_last = 0;

    return stream_unlock_result(stream, &params->result, S_OK);
}

static NTSTATUS jack_get_capture_buffer(void *args)
{
    struct get_capture_buffer_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    UINT32 *frames = params->frames;
    SIZE_T size;

    stream_lock(stream);

    if (stream->getbuf_last)
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_OUT_OF_ORDER);

    if (stream->held_frames < stream->mmdev_period_frames)
    {
        *frames = 0;
        return stream_unlock_result(stream, &params->result, AUDCLNT_S_BUFFER_EMPTY);
    }
    *frames = stream->mmdev_period_frames;

    if (stream->lcl_offs_frames + *frames > stream->bufsize_frames)
    {
        UINT32 chunk_bytes, offs_bytes, frames_bytes;
        if (stream->tmp_buffer_frames < *frames)
        {
            if (stream->tmp_buffer)
            {
                size = 0;
                NtFreeVirtualMemory(GetCurrentProcess(), (void **)&stream->tmp_buffer, &size, MEM_RELEASE);
                stream->tmp_buffer = NULL;
            }
            size = *frames * stream->fmt->Format.nBlockAlign;
            if (NtAllocateVirtualMemory(GetCurrentProcess(), (void **)&stream->tmp_buffer,
                                         zero_bits, &size, MEM_COMMIT, PAGE_READWRITE))
            {
                stream->tmp_buffer_frames = 0;
                return stream_unlock_result(stream, &params->result, E_OUTOFMEMORY);
            }
            stream->tmp_buffer_frames = *frames;
        }
        *params->data = stream->tmp_buffer;
        chunk_bytes = (stream->bufsize_frames - stream->lcl_offs_frames) * stream->fmt->Format.nBlockAlign;
        offs_bytes = stream->lcl_offs_frames * stream->fmt->Format.nBlockAlign;
        frames_bytes = *frames * stream->fmt->Format.nBlockAlign;
        memcpy(stream->tmp_buffer, stream->local_buffer + offs_bytes, chunk_bytes);
        memcpy(stream->tmp_buffer + chunk_bytes, stream->local_buffer, frames_bytes - chunk_bytes);
    }
    else
        *params->data = stream->local_buffer + stream->lcl_offs_frames * stream->fmt->Format.nBlockAlign;

    stream->getbuf_last = *frames;
    *params->flags = 0;

    if (params->devpos) *params->devpos = stream->written_frames;
    if (params->qpcpos)
    {
        LARGE_INTEGER stamp, freq;
        NtQueryPerformanceCounter(&stamp, &freq);
        *params->qpcpos = (stamp.QuadPart * (INT64)10000000) / freq.QuadPart;
    }

    return stream_unlock_result(stream, &params->result, *frames ? S_OK : AUDCLNT_S_BUFFER_EMPTY);
}

static NTSTATUS jack_release_capture_buffer(void *args)
{
    struct release_capture_buffer_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    UINT32 done = params->done;

    stream_lock(stream);

    if (!done)
    {
        stream->getbuf_last = 0;
        return stream_unlock_result(stream, &params->result, S_OK);
    }

    if (!stream->getbuf_last)
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_OUT_OF_ORDER);

    if ((UINT32)stream->getbuf_last != done)
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_INVALID_SIZE);

    stream->written_frames += done;
    stream->held_frames -= done;
    stream->lcl_offs_frames += done;
    stream->lcl_offs_frames %= stream->bufsize_frames;
    stream->getbuf_last = 0;

    return stream_unlock_result(stream, &params->result, S_OK);
}

/* ════════════════════════════════════════════════════════════════════════
 *   Reporting — padding, latency, position, etc.
 * ════════════════════════════════════════════════════════════════════════ */

static NTSTATUS jack_stream_get_buffer_size(void *args)
{
    struct get_buffer_size_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    stream_lock(stream);
    *params->frames = stream->bufsize_frames;
    return stream_unlock_result(stream, &params->result, S_OK);
}

static NTSTATUS jack_get_latency(void *args)
{
    struct get_latency_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    stream_lock(stream);
    /* One WASAPI period + one JACK period */
    *params->latency = stream->mmdev_period_rt +
        (REFERENCE_TIME)jack_buf_frames * 10000000 / jack_rate;
    return stream_unlock_result(stream, &params->result, S_OK);
}

static NTSTATUS jack_get_current_padding(void *args)
{
    struct get_current_padding_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    stream_lock(stream);
    *params->padding = stream->held_frames;
    return stream_unlock_result(stream, &params->result, S_OK);
}

static NTSTATUS jack_get_next_packet_size(void *args)
{
    struct get_next_packet_size_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    stream_lock(stream);
    *params->frames = stream->held_frames < stream->mmdev_period_frames
        ? 0 : stream->mmdev_period_frames;
    return stream_unlock_result(stream, &params->result, S_OK);
}

static NTSTATUS jack_get_frequency(void *args)
{
    struct get_frequency_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    stream_lock(stream);
    if (stream->share == AUDCLNT_SHAREMODE_SHARED)
        *params->freq = (UINT64)stream->fmt->Format.nSamplesPerSec * stream->fmt->Format.nBlockAlign;
    else
        *params->freq = stream->fmt->Format.nSamplesPerSec;
    return stream_unlock_result(stream, &params->result, S_OK);
}

static UINT32 interp_elapsed_frames(struct jack_stream *stream)
{
    LARGE_INTEGER time_freq, current_time, diff;
    NtQueryPerformanceCounter(&current_time, &time_freq);
    diff.QuadPart = current_time.QuadPart - stream->last_period_time.QuadPart;
    return muldiv(diff.QuadPart, stream->fmt->Format.nSamplesPerSec, time_freq.QuadPart);
}

static NTSTATUS jack_get_position(void *args)
{
    struct get_position_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    UINT64 position;

    stream_lock(stream);

    if (stream->flow == eRender)
    {
        position = stream->written_frames - stream->held_frames;
        if (stream->started && stream->held_frames)
        {
            UINT32 interp = interp_elapsed_frames(stream);
            if (interp > stream->mmdev_period_frames)
                interp = stream->mmdev_period_frames;
            position += interp;
        }
    }
    else
        position = stream->written_frames + stream->held_frames;

    /* Enforce monotonicity */
    if (position < stream->last_pos_frames)
        position = stream->last_pos_frames;
    stream->last_pos_frames = position;

    /* Shared mode: byte position; exclusive: frame position */
    if (stream->share == AUDCLNT_SHAREMODE_SHARED)
        *params->pos = position * stream->fmt->Format.nBlockAlign;
    else
        *params->pos = position;

    if (params->qpctime)
    {
        LARGE_INTEGER stamp, freq;
        NtQueryPerformanceCounter(&stamp, &freq);
        *params->qpctime = (stamp.QuadPart * (INT64)10000000) / freq.QuadPart;
    }

    return stream_unlock_result(stream, &params->result, S_OK);
}

static void recalc_vols_for_format(struct jack_stream *stream)
{
    float scale;
    unsigned int i;
    switch (stream->sfmt) {
    case FMT_F32: scale = 1.0f; break;
    case FMT_S16: scale = 1.0f / 32768.0f; break;
    case FMT_S32: scale = 1.0f / 2147483648.0f; break;
    case FMT_S24: scale = 1.0f / 8388608.0f; break;
    default:      scale = 1.0f; break;
    }
    for (i = 0; i < (unsigned)stream->nchannels; i++)
        stream->vols[i] = stream->vols_raw[i] * scale;
}

static NTSTATUS jack_set_volumes(void *args)
{
    struct set_volumes_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);
    unsigned int i;

    stream_lock(stream);
    for (i = 0; i < (unsigned)stream->nchannels; i++)
        stream->vols_raw[i] = params->volumes[i] * params->session_volumes[i] * params->master_volume;
    recalc_vols_for_format(stream);
    stream_unlock(stream);

    return STATUS_SUCCESS;
}

static NTSTATUS jack_set_event_handle(void *args)
{
    struct set_event_handle_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);

    stream_lock(stream);

    if (!(stream->flags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK))
        return stream_unlock_result(stream, &params->result, AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED);

    if (stream->event)
        return stream_unlock_result(stream, &params->result, HRESULT_FROM_WIN32(ERROR_INVALID_NAME));

    stream->event = params->event;

    return stream_unlock_result(stream, &params->result, S_OK);
}

static NTSTATUS jack_is_started(void *args)
{
    struct is_started_params *params = args;
    struct jack_stream *stream = handle_get_stream(params->stream);

    stream_lock(stream);
    params->result = stream->started ? S_OK : S_FALSE;
    stream_unlock(stream);

    return STATUS_SUCCESS;
}

static NTSTATUS jack_get_prop_value(void *args)
{
    struct get_prop_value_params *params = args;
    const GUID *guid = params->guid;
    const PROPERTYKEY *prop = params->prop;
    PROPVARIANT *out = params->value;
    static const PROPERTYKEY devicepath_key = {
        {0xb3f8fa53, 0x0004, 0x438e, {0x90, 0x03, 0x51, 0xa4, 0x6e, 0x13, 0x9b, 0xfc}}, 2
    };

    if (IsEqualPropertyKey(*prop, devicepath_key))
    {
        UINT serial_number;
        char buf[128];
        int len;

        serial_number = (guid->Data4[4] << 24) | (guid->Data4[5] << 16) |
                        (guid->Data4[6] << 8) | guid->Data4[7];
        sprintf(buf, "{1}.JACK\\%08X", serial_number);

        len = strlen(buf) + 1;
        if (*params->buffer_size < (unsigned)(len * sizeof(WCHAR)))
        {
            params->result = E_NOT_SUFFICIENT_BUFFER;
            *params->buffer_size = len * sizeof(WCHAR);
            return STATUS_SUCCESS;
        }
        out->vt = VT_LPWSTR;
        out->pwszVal = params->buffer;
        ntdll_umbstowcs(buf, len, out->pwszVal, len);
        params->result = S_OK;
        return STATUS_SUCCESS;
    }
    else if (params->flow != eCapture &&
             IsEqualPropertyKey(*prop, PKEY_AudioEndpoint_PhysicalSpeakers))
    {
        struct jack_ep eps[16];
        int num_eps = 0, i, channels = 2;

        count_physical_ports(params->flow, eps, &num_eps, ARRAY_SIZE(eps));
        for (i = 0; i < num_eps; i++)
        {
            if (!strcmp(eps[i].device, params->device))
            {
                channels = eps[i].channels;
                break;
            }
        }

        out->vt = VT_UI4;
        out->ulVal = get_channel_mask(channels > 8 ? 2 : channels);
        params->result = S_OK;
        return STATUS_SUCCESS;
    }

    TRACE("Unimplemented property %s,%u\n", wine_dbgstr_guid(&prop->fmtid), (unsigned)prop->pid);
    params->result = E_NOTIMPL;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_midi_get_driver(void *args)
{
    WCHAR *name = args;
    name[0] = 0; /* same driver for MIDI */
    return STATUS_SUCCESS;
}

extern UINT jack_midi_init_ex(void);  /* in jackmidi.c */

static NTSTATUS jack_midi_init_handler(void *args)
{
    struct midi_init_params *params = args;
    *params->err = jack_midi_init_ex();
    return STATUS_SUCCESS;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Function table
 * ════════════════════════════════════════════════════════════════════════ */

const unixlib_entry_t __wine_unix_call_funcs[] =
{
    jack_process_attach,            /* process_attach */
    jack_not_implemented,           /* process_detach */
    jack_main_loop,                 /* main_loop */
    jack_get_endpoint_ids,          /* get_endpoint_ids */
    jack_create_stream,             /* create_stream */
    jack_release_stream,            /* release_stream */
    jack_start,                     /* start */
    jack_stop,                      /* stop */
    jack_reset,                     /* reset */
    jack_timer_loop,                /* timer_loop */
    jack_get_render_buffer,         /* get_render_buffer */
    jack_release_render_buffer,     /* release_render_buffer */
    jack_get_capture_buffer,        /* get_capture_buffer */
    jack_release_capture_buffer,    /* release_capture_buffer */
    jack_is_format_supported,       /* is_format_supported */
    jack_not_implemented,           /* get_loopback_capture_device */
    jack_get_mix_format,            /* get_mix_format */
    jack_get_device_period,         /* get_device_period */
    jack_stream_get_buffer_size,    /* get_buffer_size */
    jack_get_latency,               /* get_latency */
    jack_get_current_padding,       /* get_current_padding */
    jack_get_next_packet_size,      /* get_next_packet_size */
    jack_get_frequency,             /* get_frequency */
    jack_get_position,              /* get_position */
    jack_set_volumes,               /* set_volumes */
    jack_set_event_handle,          /* set_event_handle */
    jack_not_implemented,           /* set_sample_rate */
    jack_test_connect,              /* test_connect */
    jack_is_started,                /* is_started */
    jack_get_prop_value,            /* get_prop_value */
    jack_midi_get_driver,           /* midi_get_driver */
    jack_midi_init_handler,         /* midi_init */
    jack_midi_release,              /* midi_release */
    jack_midi_out_message,          /* midi_out_message */
    jack_midi_in_message,           /* midi_in_message */
    jack_midi_notify_wait,          /* midi_notify_wait */
    jack_not_implemented,           /* aux_message */
};

C_ASSERT(ARRAYSIZE(__wine_unix_call_funcs) == funcs_count);

#ifdef _WIN64

typedef UINT PTR32;

static NTSTATUS jack_wow64_main_loop(void *args)
{
    struct { PTR32 event; } *params32 = args;
    struct main_loop_params params = { .event = ULongToHandle(params32->event) };
    return jack_main_loop(&params);
}

static NTSTATUS jack_wow64_get_endpoint_ids(void *args)
{
    struct { EDataFlow flow; PTR32 endpoints; unsigned int size; HRESULT result;
             unsigned int num; unsigned int default_idx; } *params32 = args;
    struct get_endpoint_ids_params params = { .flow = params32->flow,
        .endpoints = ULongToPtr(params32->endpoints), .size = params32->size };
    jack_get_endpoint_ids(&params);
    params32->size = params.size; params32->result = params.result;
    params32->num = params.num; params32->default_idx = params.default_idx;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_create_stream(void *args)
{
    struct { PTR32 name; PTR32 device; EDataFlow flow; AUDCLNT_SHAREMODE share; DWORD flags;
             REFERENCE_TIME duration; REFERENCE_TIME period; PTR32 fmt; HRESULT result;
             PTR32 channel_count; PTR32 stream; } *params32 = args;
    struct create_stream_params params = {
        .name = ULongToPtr(params32->name), .device = ULongToPtr(params32->device),
        .flow = params32->flow, .share = params32->share, .flags = params32->flags,
        .duration = params32->duration, .period = params32->period,
        .fmt = ULongToPtr(params32->fmt), .channel_count = ULongToPtr(params32->channel_count),
        .stream = ULongToPtr(params32->stream) };
    jack_create_stream(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_release_stream(void *args)
{
    struct { stream_handle stream; PTR32 timer_thread; HRESULT result; } *params32 = args;
    struct release_stream_params params = { .stream = params32->stream,
        .timer_thread = ULongToHandle(params32->timer_thread) };
    jack_release_stream(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_get_render_buffer(void *args)
{
    struct { stream_handle stream; UINT32 frames; HRESULT result; PTR32 data; } *params32 = args;
    BYTE *data = NULL;
    struct get_render_buffer_params params = { .stream = params32->stream,
        .frames = params32->frames, .data = &data };
    jack_get_render_buffer(&params);
    params32->result = params.result;
    *(unsigned int *)ULongToPtr(params32->data) = PtrToUlong(data);
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_get_capture_buffer(void *args)
{
    struct { stream_handle stream; HRESULT result; PTR32 data; PTR32 frames;
             PTR32 flags; PTR32 devpos; PTR32 qpcpos; } *params32 = args;
    BYTE *data = NULL;
    struct get_capture_buffer_params params = { .stream = params32->stream,
        .data = &data, .frames = ULongToPtr(params32->frames),
        .flags = ULongToPtr(params32->flags), .devpos = ULongToPtr(params32->devpos),
        .qpcpos = ULongToPtr(params32->qpcpos) };
    jack_get_capture_buffer(&params);
    params32->result = params.result;
    *(unsigned int *)ULongToPtr(params32->data) = PtrToUlong(data);
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_is_format_supported(void *args)
{
    struct { PTR32 device; EDataFlow flow; AUDCLNT_SHAREMODE share; PTR32 fmt_in;
             HRESULT result; } *params32 = args;
    struct is_format_supported_params params = { .device = ULongToPtr(params32->device),
        .flow = params32->flow, .share = params32->share,
        .fmt_in = ULongToPtr(params32->fmt_in) };
    jack_is_format_supported(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_get_mix_format(void *args)
{
    struct { PTR32 device; EDataFlow flow; PTR32 fmt; HRESULT result; } *params32 = args;
    struct get_mix_format_params params = { .device = ULongToPtr(params32->device),
        .flow = params32->flow, .fmt = ULongToPtr(params32->fmt) };
    jack_get_mix_format(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_get_device_period(void *args)
{
    struct { PTR32 device; EDataFlow flow; HRESULT result; PTR32 def_period;
             PTR32 min_period; } *params32 = args;
    struct get_device_period_params params = { .device = ULongToPtr(params32->device),
        .flow = params32->flow, .def_period = ULongToPtr(params32->def_period),
        .min_period = ULongToPtr(params32->min_period) };
    jack_get_device_period(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_get_buffer_size(void *args)
{
    struct { stream_handle stream; HRESULT result; PTR32 frames; } *params32 = args;
    struct get_buffer_size_params params = { .stream = params32->stream,
        .frames = ULongToPtr(params32->frames) };
    jack_stream_get_buffer_size(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_get_latency(void *args)
{
    struct { stream_handle stream; HRESULT result; PTR32 latency; } *params32 = args;
    struct get_latency_params params = { .stream = params32->stream,
        .latency = ULongToPtr(params32->latency) };
    jack_get_latency(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_get_current_padding(void *args)
{
    struct { stream_handle stream; HRESULT result; PTR32 padding; } *params32 = args;
    struct get_current_padding_params params = { .stream = params32->stream,
        .padding = ULongToPtr(params32->padding) };
    jack_get_current_padding(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_get_next_packet_size(void *args)
{
    struct { stream_handle stream; HRESULT result; PTR32 frames; } *params32 = args;
    struct get_next_packet_size_params params = { .stream = params32->stream,
        .frames = ULongToPtr(params32->frames) };
    jack_get_next_packet_size(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_get_frequency(void *args)
{
    struct { stream_handle stream; HRESULT result; PTR32 freq; } *params32 = args;
    struct get_frequency_params params = { .stream = params32->stream,
        .freq = ULongToPtr(params32->freq) };
    jack_get_frequency(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_get_position(void *args)
{
    struct { stream_handle stream; BOOL device; HRESULT result; PTR32 pos;
             PTR32 qpctime; } *params32 = args;
    struct get_position_params params = { .stream = params32->stream,
        .device = params32->device, .pos = ULongToPtr(params32->pos),
        .qpctime = ULongToPtr(params32->qpctime) };
    jack_get_position(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_set_volumes(void *args)
{
    struct { stream_handle stream; float master_volume; PTR32 volumes;
             PTR32 session_volumes; } *params32 = args;
    struct set_volumes_params params = { .stream = params32->stream,
        .master_volume = params32->master_volume,
        .volumes = ULongToPtr(params32->volumes),
        .session_volumes = ULongToPtr(params32->session_volumes) };
    return jack_set_volumes(&params);
}

static NTSTATUS jack_wow64_set_event_handle(void *args)
{
    struct { stream_handle stream; PTR32 event; HRESULT result; } *params32 = args;
    struct set_event_handle_params params = { .stream = params32->stream,
        .event = ULongToHandle(params32->event) };
    jack_set_event_handle(&params);
    params32->result = params.result;
    return STATUS_SUCCESS;
}

static NTSTATUS jack_wow64_get_prop_value(void *args)
{
    struct propvariant32 { WORD vt; WORD pad1, pad2, pad3;
        union { ULONG ulVal; PTR32 ptr; ULARGE_INTEGER uhVal; }; } *value32;
    struct { PTR32 device; EDataFlow flow; PTR32 guid; PTR32 prop; HRESULT result;
             PTR32 value; PTR32 buffer; PTR32 buffer_size; } *params32 = args;
    PROPVARIANT value;
    struct get_prop_value_params params = {
        .device = ULongToPtr(params32->device), .flow = params32->flow,
        .guid = ULongToPtr(params32->guid), .prop = ULongToPtr(params32->prop),
        .value = &value, .buffer = ULongToPtr(params32->buffer),
        .buffer_size = ULongToPtr(params32->buffer_size) };
    jack_get_prop_value(&params);
    params32->result = params.result;
    if (SUCCEEDED(params.result)) {
        value32 = ULongToPtr(params32->value);
        value32->vt = value.vt;
        switch (value.vt) {
        case VT_UI4: value32->ulVal = value.ulVal; break;
        case VT_LPWSTR: value32->ptr = params32->buffer; break;
        default: FIXME("Unhandled vt %04x\n", value.vt);
        }
    }
    return STATUS_SUCCESS;
}

const unixlib_entry_t __wine_unix_call_wow64_funcs[] =
{
    jack_process_attach,
    jack_not_implemented,
    jack_wow64_main_loop,
    jack_wow64_get_endpoint_ids,
    jack_wow64_create_stream,
    jack_wow64_release_stream,
    jack_start,
    jack_stop,
    jack_reset,
    jack_timer_loop,
    jack_wow64_get_render_buffer,
    jack_release_render_buffer,
    jack_wow64_get_capture_buffer,
    jack_release_capture_buffer,
    jack_wow64_is_format_supported,
    jack_not_implemented,
    jack_wow64_get_mix_format,
    jack_wow64_get_device_period,
    jack_wow64_get_buffer_size,
    jack_wow64_get_latency,
    jack_wow64_get_current_padding,
    jack_wow64_get_next_packet_size,
    jack_wow64_get_frequency,
    jack_wow64_get_position,
    jack_wow64_set_volumes,
    jack_wow64_set_event_handle,
    jack_not_implemented,               /* set_sample_rate */
    jack_test_connect,
    jack_is_started,
    jack_wow64_get_prop_value,
    jack_midi_get_driver,
    jack_midi_init_handler,             /* midi_init */
    jack_midi_release,
    jack_midi_out_message,              /* TODO: wow64 midi thunks */
    jack_midi_in_message,
    jack_midi_notify_wait,
    jack_not_implemented,               /* aux_message */
};

C_ASSERT(ARRAYSIZE(__wine_unix_call_wow64_funcs) == funcs_count);

#endif /* _WIN64 */
