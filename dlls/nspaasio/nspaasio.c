/*
 * nspaASIO — ASIO driver backed by WASAPI exclusive mode
 *
 * Apps see a standard ASIO driver. Internally it opens a WASAPI
 * exclusive+event stream, which routes through winejack.drv → JACK.
 *
 *   DAW → nspaASIO (IASIO COM) → WASAPI exclusive → winejack.drv → JACK
 *
 * Copyright 2025 jordan Johnston (Wine-NSPA)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 */

#define COBJMACROS
#include <windows.h>
#include <initguid.h>
#include <objbase.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <avrt.h>
#include <process.h>

#include "asio.h"

#include "wine/asm.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(asio);

/* ════════════════════════════════════════════════════════════════════════
 *   CLSID — unique to nspaASIO
 * ════════════════════════════════════════════════════════════════════════ */

/* {E3226090-1E1A-4F32-B455-7E5D3B4A1A04} */
DEFINE_GUID(CLSID_nspaASIO,
    0xe3226090, 0x1e1a, 0x4f32,
    0xb4, 0x55, 0x7e, 0x5d, 0x3b, 0x4a, 0x1a, 0x04);

static const char DRIVER_NAME[] = "nspaASIO";
static const long DRIVER_VERSION = 1;

/* ════════════════════════════════════════════════════════════════════════
 *   IASIO interface (COM vtable layout)
 *
 *   ASIO is a C++ COM interface — MSVC-compiled hosts call vtable methods
 *   using __thiscall (this in ECX on i386), NOT __stdcall.  On MinGW we
 *   must declare our methods as __thiscall so the compiler generates code
 *   that reads ECX correctly.
 * ════════════════════════════════════════════════════════════════════════ */

#ifdef __i386__
#define ASIOMETHODCALLTYPE __thiscall
#else
#define ASIOMETHODCALLTYPE STDMETHODCALLTYPE
#endif

typedef struct IASIO IASIO;
typedef struct IASIOVtbl {
    void *QueryInterface;
    void *AddRef;
    void *Release;
    void *init;
    void *getDriverName;
    void *getDriverVersion;
    void *getErrorMessage;
    void *start;
    void *stop;
    void *getChannels;
    void *getLatencies;
    void *getBufferSize;
    void *canSampleRate;
    void *getSampleRate;
    void *setSampleRate;
    void *getClockSources;
    void *setClockSource;
    void *getSamplePosition;
    void *getChannelInfo;
    void *createBuffers;
    void *disposeBuffers;
    void *controlPanel;
    void *future;
    void *outputReady;
} IASIOVtbl;

struct IASIO { IASIOVtbl *lpVtbl; };

/* ════════════════════════════════════════════════════════════════════════
 *   Driver state
 * ════════════════════════════════════════════════════════════════════════ */

enum driver_state { STATE_LOADED, STATE_INITIALIZED, STATE_PREPARED, STATE_RUNNING };

typedef struct nspaASIODriver {
    IASIOVtbl        *lpVtbl;
    LONG              ref;

    enum driver_state state;
    char              error_msg[124];

    /* WASAPI */
    IMMDevice        *render_device;
    IMMDevice        *capture_device;
    IAudioClient     *audio_client;
    IAudioRenderClient *render_client;
    WAVEFORMATEXTENSIBLE wfx;
    UINT32            wasapi_buf_frames;
    HANDLE            event;

    /* ASIO buffers (double-buffered, per-channel) */
    BYTE            **buf_a;     /* buffer set 0, one allocation per channel */
    BYTE            **buf_b;     /* buffer set 1 */
    int              *out_map;   /* indices into buf_a/b for output channels */
    int               out_map_count; /* number of output channels in the map */
    int               buf_index; /* which set the host is filling (0 or 1) */
    long              buf_size;  /* frames per buffer */
    int               num_channels;  /* total channels (in + out) */
    int               num_inputs;
    int               num_outputs;
    int               wasapi_channels; /* real WASAPI/JACK channel count */
    ASIOSampleType    sample_type;
    int               bytes_per_sample;

    /* Callbacks */
    ASIOCallbacks    *callbacks;

    /* Playback thread */
    HANDLE            thread;
    HANDLE            stop_event;

    /* Timing */
    long long         sample_position;
    LARGE_INTEGER     system_time;
    LARGE_INTEGER     perf_freq;
    ASIOSampleRate    sample_rate;
} nspaASIODriver;

static nspaASIODriver *g_driver;
static HINSTANCE g_hinstance;
static LONG g_lock_count;

/* ════════════════════════════════════════════════════════════════════════
 *   Helpers
 * ════════════════════════════════════════════════════════════════════════ */

static int sample_type_size(ASIOSampleType t)
{
    switch (t) {
    case ASIOSTInt16LSB:   return 2;
    case ASIOSTInt24LSB:   return 3;
    case ASIOSTInt32LSB:
    case ASIOSTFloat32LSB: return 4;
    case ASIOSTFloat64LSB: return 8;
    default:               return 4;
    }
}

static ASIOSampleType wasapi_to_asio_type(const WAVEFORMATEXTENSIBLE *wfx)
{
    if (IsEqualGUID(&wfx->SubFormat, &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT))
        return ASIOSTFloat32LSB;
    switch (wfx->Format.wBitsPerSample) {
    case 16: return ASIOSTInt16LSB;
    case 24: return ASIOSTInt24LSB;
    case 32: return wfx->Samples.wValidBitsPerSample == 24 ? ASIOSTInt32LSB24 : ASIOSTInt32LSB;
    default: return ASIOSTFloat32LSB;
    }
}

static void get_nanotime(LARGE_INTEGER *freq, ASIOTimeStamp *ts)
{
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    *ts = (now.QuadPart * 1000000000LL) / freq->QuadPart;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Playback thread — waits on WASAPI event, calls ASIO host callback
 * ════════════════════════════════════════════════════════════════════════ */

static unsigned __stdcall play_thread(void *arg)
{
    nspaASIODriver *d = arg;
    HANDLE events[2];
    BYTE *wasapi_buf;
    HRESULT hr;
    DWORD task_idx = 0;
    HANDLE avrt;

    /* Boost to pro-audio priority */
    avrt = AvSetMmThreadCharacteristicsW(L"Pro Audio", &task_idx);
    if (avrt)
        AvSetMmThreadPriority(avrt, AVRT_PRIORITY_CRITICAL);

    events[0] = d->stop_event;
    events[1] = d->event;

    /* Pre-fill first buffer with silence and start */
    hr = IAudioRenderClient_GetBuffer(d->render_client, d->wasapi_buf_frames, &wasapi_buf);
    if (SUCCEEDED(hr))
        IAudioRenderClient_ReleaseBuffer(d->render_client, d->wasapi_buf_frames, AUDCLNT_BUFFERFLAGS_SILENT);

    IAudioClient_Start(d->audio_client);

    QueryPerformanceCounter(&d->system_time);
    d->sample_position = 0;

    /* Initial callback so host fills buffer 0 */
    if (d->callbacks->bufferSwitch)
        d->callbacks->bufferSwitch(d->buf_index, ASIOTrue);

    while (WaitForMultipleObjects(2, events, FALSE, INFINITE) == WAIT_OBJECT_0 + 1)
    {
        int src_idx = d->buf_index;  /* host just filled this one */
        BYTE **src_bufs = src_idx == 0 ? d->buf_a : d->buf_b;

        /* Copy ASIO per-channel buffers → interleaved WASAPI buffer */
        hr = IAudioRenderClient_GetBuffer(d->render_client, d->buf_size, &wasapi_buf);
        if (SUCCEEDED(hr))
        {
            long i;
            int ch;
            BYTE *dst = wasapi_buf;

            for (i = 0; i < d->buf_size; i++)
            {
                for (ch = 0; ch < d->wasapi_channels; ch++)
                {
                    if (ch < d->out_map_count)
                        memcpy(dst, src_bufs[d->out_map[ch]] + i * d->bytes_per_sample, d->bytes_per_sample);
                    else
                        memset(dst, 0, d->bytes_per_sample);
                    dst += d->bytes_per_sample;
                }
            }
            IAudioRenderClient_ReleaseBuffer(d->render_client, d->buf_size, 0);
        }

        /* Toggle buffer index */
        d->buf_index = 1 - d->buf_index;

        /* Update timing */
        QueryPerformanceCounter(&d->system_time);
        d->sample_position += d->buf_size;

        /* Call host to fill the next buffer */
        if (d->callbacks->bufferSwitch)
            d->callbacks->bufferSwitch(d->buf_index, ASIOTrue);
    }

    IAudioClient_Stop(d->audio_client);

    if (avrt)
        AvRevertMmThreadCharacteristics(avrt);

    return 0;
}

/* ════════════════════════════════════════════════════════════════════════
 *   IASIO implementation
 * ════════════════════════════════════════════════════════════════════════ */

static ULONG ASIOMETHODCALLTYPE asio_AddRef(IASIO *iface);

static HRESULT ASIOMETHODCALLTYPE asio_QueryInterface(IASIO *iface, REFIID riid, void **ppv)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &CLSID_nspaASIO))
    {
        *ppv = iface;
        asio_AddRef(iface);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG ASIOMETHODCALLTYPE asio_AddRef(IASIO *iface)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    nspaASIODriver *d = (nspaASIODriver *)iface;
    return InterlockedIncrement(&d->ref);
}

static ULONG ASIOMETHODCALLTYPE asio_Release(IASIO *iface)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    nspaASIODriver *d = (nspaASIODriver *)iface;
    ULONG ref = InterlockedDecrement(&d->ref);
    if (ref == 0)
    {
        /* ASIO drivers are singletons — apps expect the driver to persist
         * across property detection cycles. Don't free the object; just
         * release WASAPI resources. The driver can be re-initialized. */
        if (d->audio_client) { IAudioClient_Release(d->audio_client); d->audio_client = NULL; }
        if (d->render_device) { IMMDevice_Release(d->render_device); d->render_device = NULL; }
        if (d->capture_device) { IMMDevice_Release(d->capture_device); d->capture_device = NULL; }
        if (d->event) { CloseHandle(d->event); d->event = NULL; }
        d->state = STATE_LOADED;
        d->ref = 0;
    }
    return ref;
}

static ASIOBool ASIOMETHODCALLTYPE asio_init(IASIO *iface, void *sysHandle)
{
    nspaASIODriver *d = (nspaASIODriver *)iface;
    IMMDeviceEnumerator *enumerator = NULL;
    WAVEFORMATEX *mix_fmt = NULL;
    WAVEFORMATEX *cap_fmt = NULL;
    IAudioClient *cap_client = NULL;
    HRESULT hr;

    if (d->state != STATE_LOADED)
        return ASIOFalse;

    hr = CoCreateInstance(&CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL,
                          &IID_IMMDeviceEnumerator, (void **)&enumerator);
    if (FAILED(hr)) { strcpy(d->error_msg, "Cannot create device enumerator"); return ASIOFalse; }

    /* Get render endpoint */
    hr = IMMDeviceEnumerator_GetDefaultAudioEndpoint(enumerator, eRender, eConsole, &d->render_device);
    if (FAILED(hr)) { IMMDeviceEnumerator_Release(enumerator); strcpy(d->error_msg, "No render endpoint"); return ASIOFalse; }

    hr = IMMDevice_Activate(d->render_device, &IID_IAudioClient, CLSCTX_ALL, NULL, (void **)&d->audio_client);
    if (FAILED(hr)) { IMMDeviceEnumerator_Release(enumerator); strcpy(d->error_msg, "Cannot activate render client"); return ASIOFalse; }

    hr = IAudioClient_GetMixFormat(d->audio_client, &mix_fmt);
    if (FAILED(hr)) { IMMDeviceEnumerator_Release(enumerator); strcpy(d->error_msg, "Cannot get mix format"); return ASIOFalse; }

    /* Copy render format */
    if (mix_fmt->wFormatTag == WAVE_FORMAT_EXTENSIBLE)
        d->wfx = *(WAVEFORMATEXTENSIBLE *)mix_fmt;
    else
    {
        memset(&d->wfx, 0, sizeof(d->wfx));
        d->wfx.Format = *mix_fmt;
        d->wfx.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
        d->wfx.Format.cbSize = sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX);
        d->wfx.SubFormat = KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;
        d->wfx.Samples.wValidBitsPerSample = mix_fmt->wBitsPerSample;
        d->wfx.dwChannelMask = (1u << mix_fmt->nChannels) - 1;
    }

    d->sample_rate = d->wfx.Format.nSamplesPerSec;
    d->sample_type = wasapi_to_asio_type(&d->wfx);
    d->bytes_per_sample = sample_type_size(d->sample_type);
    d->num_outputs = d->wfx.Format.nChannels;
    d->wasapi_channels = d->wfx.Format.nChannels;

    /* Get capture endpoint for input channels */
    d->num_inputs = 0;
    hr = IMMDeviceEnumerator_GetDefaultAudioEndpoint(enumerator, eCapture, eConsole, &d->capture_device);
    if (SUCCEEDED(hr))
    {
        hr = IMMDevice_Activate(d->capture_device, &IID_IAudioClient, CLSCTX_ALL, NULL, (void **)&cap_client);
        if (SUCCEEDED(hr))
        {
            hr = IAudioClient_GetMixFormat(cap_client, &cap_fmt);
            if (SUCCEEDED(hr))
            {
                d->num_inputs = cap_fmt->nChannels;
                CoTaskMemFree(cap_fmt);
            }
            IAudioClient_Release(cap_client);
        }
    }

    /* Allow channel count override via environment variables.
     * Only changes what ASIO reports to the app — the WASAPI stream
     * stays at the real device channel count.  Extra channels are
     * zero-filled / silenced in the audio callback. */
    {
        const char *env;
        env = getenv("NSPA_ASIO_OUTPUTS");
        if (env)
        {
            int n = atoi(env);
            if (n > 0 && n <= 64)
            {
                TRACE("nspaASIO: overriding outputs %d -> %d (NSPA_ASIO_OUTPUTS)\n", d->num_outputs, n);
                d->num_outputs = n;
            }
        }
        env = getenv("NSPA_ASIO_INPUTS");
        if (env)
        {
            int n = atoi(env);
            if (n >= 0 && n <= 64)
            {
                TRACE("nspaASIO: overriding inputs %d -> %d (NSPA_ASIO_INPUTS)\n", d->num_inputs, n);
                d->num_inputs = n;
            }
        }
    }

    IMMDeviceEnumerator_Release(enumerator);
    CoTaskMemFree(mix_fmt);
    QueryPerformanceFrequency(&d->perf_freq);

    d->event = CreateEventW(NULL, FALSE, FALSE, NULL);
    d->state = STATE_INITIALIZED;

    TRACE("nspaASIO init: %u Hz, %u out, %u in, type %ld\n",
          (unsigned)d->sample_rate, d->num_outputs, d->num_inputs, d->sample_type);

    return ASIOTrue;
}

static void ASIOMETHODCALLTYPE asio_getDriverName(IASIO *iface, char *name)
{
    TRACE("getDriverName called\n");
    strcpy(name, DRIVER_NAME);
}

static long ASIOMETHODCALLTYPE asio_getDriverVersion(IASIO *iface)
{
    return DRIVER_VERSION;
}

static void ASIOMETHODCALLTYPE asio_getErrorMessage(IASIO *iface, char *string)
{
    nspaASIODriver *d = (nspaASIODriver *)iface;
    strcpy(string, d->error_msg);
}

static ASIOError ASIOMETHODCALLTYPE asio_start(IASIO *iface)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    nspaASIODriver *d = (nspaASIODriver *)iface;

    if (d->state != STATE_PREPARED)
        return ASE_InvalidMode;

    d->stop_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    d->thread = (HANDLE)_beginthreadex(NULL, 0, play_thread, d, 0, NULL);
    if (!d->thread)
    {
        CloseHandle(d->stop_event);
        d->stop_event = NULL;
        return ASE_HWMalfunction;
    }

    d->state = STATE_RUNNING;
    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_stop(IASIO *iface)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    nspaASIODriver *d = (nspaASIODriver *)iface;

    if (d->state != STATE_RUNNING)
        return ASE_OK;

    /* Stop the audio client first — this unblocks the event wait
     * in the play thread so it can see the stop_event. */
    if (d->audio_client)
        IAudioClient_Stop(d->audio_client);

    SetEvent(d->stop_event);

    if (WaitForSingleObject(d->thread, 1000) == WAIT_TIMEOUT)
    {
        WARN("play thread did not exit in 1s, terminating\n");
        TerminateThread(d->thread, 0);
    }

    CloseHandle(d->thread);
    CloseHandle(d->stop_event);
    d->thread = NULL;
    d->stop_event = NULL;
    d->state = STATE_PREPARED;

    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_getChannels(IASIO *iface, long *numIn, long *numOut)
{
    nspaASIODriver *d = (nspaASIODriver *)iface;
    TRACE("getChannels called (iface=%p)\n", iface);
    if (numIn) *numIn = d->num_inputs;
    if (numOut) *numOut = d->num_outputs;
    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_getLatencies(IASIO *iface, long *inLat, long *outLat)
{
    nspaASIODriver *d = (nspaASIODriver *)iface;
    /* Two buffers of latency (double-buffered) */
    if (inLat) *inLat = d->buf_size * 2;
    if (outLat) *outLat = d->buf_size * 2;
    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_getBufferSize(IASIO *iface, long *minSize, long *maxSize,
                                                       long *preferredSize, long *granularity)
{
    nspaASIODriver *d = (nspaASIODriver *)iface;
    TRACE("getBufferSize called (iface=%p)\n", iface);
    REFERENCE_TIME def_period = 0, min_period = 0;
    long min_frames, pref;

    if (d->audio_client)
        IAudioClient_GetDevicePeriod(d->audio_client, &def_period, &min_period);

    /* Use minimum period (= JACK buffer size) as the preferred ASIO buffer.
     * This gives the tightest latency — one JACK period per ASIO callback. */
    min_frames = (long)(min_period * d->sample_rate / 10000000.0 + 0.5);
    if (min_frames < 32) min_frames = 32;

    /* Round to nearest power of 2 for ASIO convention */
    pref = 32;
    while (pref < min_frames) pref *= 2;

    if (minSize) *minSize = pref;
    if (maxSize) *maxSize = pref * 8;
    if (preferredSize) *preferredSize = pref;
    if (granularity) *granularity = -1; /* power-of-2 steps */

    TRACE("getBufferSize: min=%ld pref=%ld max=%ld (min_period=%lld, rate=%u)\n",
          pref, pref, pref * 8, (long long)min_period, (unsigned)d->sample_rate);

    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_canSampleRate(IASIO *iface, ASIOSampleRate rate)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    nspaASIODriver *d = (nspaASIODriver *)iface;
    /* We only support the WASAPI device's native rate */
    return (long)rate == (long)d->sample_rate ? ASE_OK : ASE_NoClock;
}

static ASIOError ASIOMETHODCALLTYPE asio_getSampleRate(IASIO *iface, ASIOSampleRate *rate)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    nspaASIODriver *d = (nspaASIODriver *)iface;
    if (rate) *rate = d->sample_rate;
    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_setSampleRate(IASIO *iface, ASIOSampleRate rate)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    nspaASIODriver *d = (nspaASIODriver *)iface;
    if ((long)rate != (long)d->sample_rate)
        return ASE_NoClock;
    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_getClockSources(IASIO *iface, ASIOClockSource *clocks, long *numSources)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    if (clocks && numSources && *numSources > 0)
    {
        clocks[0].index = 0;
        clocks[0].associatedChannel = -1;
        clocks[0].associatedGroup = -1;
        clocks[0].isCurrentSource = ASIOTrue;
        strcpy(clocks[0].name, "Internal");
        *numSources = 1;
    }
    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_setClockSource(IASIO *iface, long reference)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    return reference == 0 ? ASE_OK : ASE_InvalidParameter;
}

static ASIOError ASIOMETHODCALLTYPE asio_getSamplePosition(IASIO *iface, ASIOSamples *sPos, ASIOTimeStamp *tStamp)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    nspaASIODriver *d = (nspaASIODriver *)iface;
    if (sPos) *sPos = d->sample_position;
    if (tStamp)
    {
        ASIOTimeStamp ts;
        get_nanotime(&d->perf_freq, &ts);
        *tStamp = ts;
    }
    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_getChannelInfo(IASIO *iface, ASIOChannelInfo *info)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    nspaASIODriver *d = (nspaASIODriver *)iface;

    if (info->isInput)
    {
        if (info->channel >= d->num_inputs) return ASE_InvalidParameter;
        info->type = d->sample_type;
        info->isActive = ASIOFalse;
        info->channelGroup = 0;
        sprintf(info->name, "Input %ld", info->channel + 1);
    }
    else
    {
        if (info->channel >= d->num_outputs) return ASE_InvalidParameter;
        info->type = d->sample_type;
        info->isActive = ASIOFalse;
        info->channelGroup = 0;
        sprintf(info->name, "Output %ld", info->channel + 1);
    }

    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_createBuffers(IASIO *iface, ASIOBufferInfo *infos,
                                                       long numChannels, long bufferSize,
                                                       ASIOCallbacks *callbacks)
{
    nspaASIODriver *d = (nspaASIODriver *)iface;
    HRESULT hr;
    REFERENCE_TIME duration;
    int i;

    if (d->state != STATE_INITIALIZED)
        return ASE_InvalidMode;
    if (!callbacks || !callbacks->bufferSwitch)
        return ASE_InvalidParameter;

    d->buf_size = bufferSize;
    d->callbacks = callbacks;
    d->num_channels = numChannels;

    /* Allocate per-channel double buffers */
    d->buf_a = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numChannels * sizeof(BYTE *));
    d->buf_b = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numChannels * sizeof(BYTE *));
    if (!d->buf_a || !d->buf_b) return ASE_NoMemory;

    d->out_map = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, numChannels * sizeof(int));
    d->out_map_count = 0;

    for (i = 0; i < numChannels; i++)
    {
        int sz = bufferSize * d->bytes_per_sample;
        d->buf_a[i] = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        d->buf_b[i] = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (!d->buf_a[i] || !d->buf_b[i]) return ASE_NoMemory;

        infos[i].buffers[0] = d->buf_a[i];
        infos[i].buffers[1] = d->buf_b[i];

        /* Track which buffer indices are outputs */
        if (!infos[i].isInput)
            d->out_map[d->out_map_count++] = i;
    }

    TRACE("createBuffers: %ld channels total, %d outputs mapped\n",
          numChannels, d->out_map_count);

    /* Open WASAPI exclusive stream */
    duration = (REFERENCE_TIME)(10000000.0 * bufferSize / d->sample_rate + 0.5);

    hr = IAudioClient_Initialize(d->audio_client, AUDCLNT_SHAREMODE_EXCLUSIVE,
                                  AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
                                  duration, duration, &d->wfx.Format, NULL);
    if (FAILED(hr))
    {
        /* Fallback: try shared mode */
        WARN("Exclusive mode failed (%08lx), trying shared\n", hr);

        /* Need a fresh audio client for retry */
        IAudioClient_Release(d->audio_client);
        d->audio_client = NULL;
        IMMDevice_Activate(d->render_device, &IID_IAudioClient, CLSCTX_ALL, NULL, (void **)&d->audio_client);

        hr = IAudioClient_Initialize(d->audio_client, AUDCLNT_SHAREMODE_SHARED,
                                      AUDCLNT_STREAMFLAGS_EVENTCALLBACK,
                                      duration, 0, &d->wfx.Format, NULL);
        if (FAILED(hr))
        {
            strcpy(d->error_msg, "WASAPI Initialize failed");
            ERR("WASAPI Initialize failed: %08lx\n", hr);
            return ASE_HWMalfunction;
        }
    }

    IAudioClient_GetBufferSize(d->audio_client, &d->wasapi_buf_frames);
    IAudioClient_SetEventHandle(d->audio_client, d->event);
    IAudioClient_GetService(d->audio_client, &IID_IAudioRenderClient, (void **)&d->render_client);

    d->buf_index = 0;
    d->state = STATE_PREPARED;

    TRACE("nspaASIO createBuffers: %ld frames, wasapi buf %u frames\n",
          bufferSize, d->wasapi_buf_frames);

    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_disposeBuffers(IASIO *iface)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    nspaASIODriver *d = (nspaASIODriver *)iface;
    int i;

    if (d->state == STATE_RUNNING)
        asio_stop(iface);

    if (d->render_client) { IAudioRenderClient_Release(d->render_client); d->render_client = NULL; }

    /* Release the audio client so the next createBuffers gets a fresh one.
     * IAudioClient cannot be re-initialized once initialized — must re-activate. */
    if (d->audio_client) { IAudioClient_Release(d->audio_client); d->audio_client = NULL; }
    if (d->render_device)
        IMMDevice_Activate(d->render_device, &IID_IAudioClient, CLSCTX_ALL, NULL, (void **)&d->audio_client);

    if (d->buf_a)
    {
        for (i = 0; i < d->num_channels; i++)
            HeapFree(GetProcessHeap(), 0, d->buf_a[i]);
        HeapFree(GetProcessHeap(), 0, d->buf_a);
        d->buf_a = NULL;
    }
    if (d->buf_b)
    {
        for (i = 0; i < d->num_channels; i++)
            HeapFree(GetProcessHeap(), 0, d->buf_b[i]);
        HeapFree(GetProcessHeap(), 0, d->buf_b);
        d->buf_b = NULL;
    }

    if (d->out_map) { HeapFree(GetProcessHeap(), 0, d->out_map); d->out_map = NULL; }
    d->out_map_count = 0;

    d->callbacks = NULL;
    d->state = STATE_INITIALIZED;
    return ASE_OK;
}

static ASIOError ASIOMETHODCALLTYPE asio_controlPanel(IASIO *iface)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    return ASE_OK; /* no control panel */
}

static ASIOError ASIOMETHODCALLTYPE asio_future(IASIO *iface, long selector, void *opt)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    return ASE_InvalidParameter;
}

static ASIOError ASIOMETHODCALLTYPE asio_outputReady(IASIO *iface)
{ TRACE("'%s' called (iface=%p)\n", __FUNCTION__, iface);
    return ASE_NotPresent;
}

/* ════════════════════════════════════════════════════════════════════════
 *   Vtable — PE DLL uses stdcall (standard COM calling convention)
 * ════════════════════════════════════════════════════════════════════════ */

static IASIOVtbl nspaASIO_vtbl = {
    (void *)asio_QueryInterface,
    (void *)asio_AddRef,
    (void *)asio_Release,
    (void *)asio_init,
    (void *)asio_getDriverName,
    (void *)asio_getDriverVersion,
    (void *)asio_getErrorMessage,
    (void *)asio_start,
    (void *)asio_stop,
    (void *)asio_getChannels,
    (void *)asio_getLatencies,
    (void *)asio_getBufferSize,
    (void *)asio_canSampleRate,
    (void *)asio_getSampleRate,
    (void *)asio_setSampleRate,
    (void *)asio_getClockSources,
    (void *)asio_setClockSource,
    (void *)asio_getSamplePosition,
    (void *)asio_getChannelInfo,
    (void *)asio_createBuffers,
    (void *)asio_disposeBuffers,
    (void *)asio_controlPanel,
    (void *)asio_future,
    (void *)asio_outputReady,
};

/* ════════════════════════════════════════════════════════════════════════
 *   COM Class Factory
 * ════════════════════════════════════════════════════════════════════════ */

typedef struct {
    IClassFactory IClassFactory_iface;
    LONG ref;
} nspaASIOFactory;

static inline nspaASIOFactory *impl_from_IClassFactory(IClassFactory *iface)
{
    return CONTAINING_RECORD(iface, nspaASIOFactory, IClassFactory_iface);
}

static HRESULT STDMETHODCALLTYPE factory_QueryInterface(IClassFactory *iface, REFIID riid, void **ppv)
{
    if (IsEqualIID(riid, &IID_IUnknown) || IsEqualIID(riid, &IID_IClassFactory))
    {
        *ppv = iface;
        IClassFactory_AddRef(iface);
        return S_OK;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE factory_AddRef(IClassFactory *iface) { return 2; }
static ULONG STDMETHODCALLTYPE factory_Release(IClassFactory *iface) { return 1; }

static HRESULT STDMETHODCALLTYPE factory_CreateInstance(IClassFactory *iface, IUnknown *outer,
                                                         REFIID riid, void **ppv)
{
    nspaASIODriver *d;

    if (outer) return CLASS_E_NOAGGREGATION;

    if (g_driver)
    {
        *ppv = g_driver;
        g_driver->ref++;
        return S_OK;
    }

    d = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*d));
    if (!d) return E_OUTOFMEMORY;

    d->lpVtbl = &nspaASIO_vtbl;
    d->ref = 1;
    d->state = STATE_LOADED;

    g_driver = d;
    *ppv = d;

    TRACE("nspaASIO: created driver instance at %p\n", d);
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE factory_LockServer(IClassFactory *iface, BOOL lock)
{
    if (lock) InterlockedIncrement(&g_lock_count);
    else InterlockedDecrement(&g_lock_count);
    return S_OK;
}

static const IClassFactoryVtbl factory_vtbl = {
    factory_QueryInterface,
    factory_AddRef,
    factory_Release,
    factory_CreateInstance,
    factory_LockServer,
};

static nspaASIOFactory g_factory = { { &factory_vtbl }, 0 };

/* ════════════════════════════════════════════════════════════════════════
 *   DLL exports
 * ════════════════════════════════════════════════════════════════════════ */

HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void **ppv)
{
    if (IsEqualCLSID(rclsid, &CLSID_nspaASIO))
        return IClassFactory_QueryInterface(&g_factory.IClassFactory_iface, riid, ppv);

    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DllCanUnloadNow(void)
{
    return (g_lock_count == 0 && !g_driver) ? S_OK : S_FALSE;
}

HRESULT WINAPI DllRegisterServer(void)
{
    HKEY key;
    WCHAR path[MAX_PATH];
    char clsid_str[] = "{E3226090-1E1A-4F32-B455-7E5D3B4A1A04}";
    LONG r;

    /* Register COM CLSID */
    r = RegCreateKeyExA(HKEY_CLASSES_ROOT,
                        "CLSID\\{E3226090-1E1A-4F32-B455-7E5D3B4A1A04}\\InProcServer32",
                        0, NULL, 0, KEY_WRITE, NULL, &key, NULL);
    if (r == ERROR_SUCCESS)
    {
        GetModuleFileNameW(g_hinstance, path, MAX_PATH);
        RegSetValueExW(key, NULL, 0, REG_SZ, (BYTE *)path, (lstrlenW(path) + 1) * sizeof(WCHAR));
        RegSetValueExA(key, "ThreadingModel", 0, REG_SZ, (BYTE *)"Apartment", 10);
        RegCloseKey(key);
    }

    /* Register ASIO driver */
    r = RegCreateKeyExA(HKEY_LOCAL_MACHINE, "Software\\ASIO\\nspaASIO", 0, NULL, 0, KEY_WRITE, NULL, &key, NULL);
    if (r == ERROR_SUCCESS)
    {
        RegSetValueExA(key, "CLSID", 0, REG_SZ, (BYTE *)clsid_str, sizeof(clsid_str));
        RegSetValueExA(key, "Description", 0, REG_SZ, (BYTE *)"nspaASIO - WASAPI/JACK bridge", 30);
        RegCloseKey(key);
    }

    TRACE("nspaASIO registered\n");
    return S_OK;
}

HRESULT WINAPI DllUnregisterServer(void)
{
    RegDeleteKeyA(HKEY_CLASSES_ROOT, "CLSID\\{E3226090-1E1A-4F32-B455-7E5D3B4A1A04}\\InProcServer32");
    RegDeleteKeyA(HKEY_CLASSES_ROOT, "CLSID\\{E3226090-1E1A-4F32-B455-7E5D3B4A1A04}");
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, "Software\\ASIO\\nspaASIO");
    return S_OK;
}

BOOL WINAPI DllMain(HINSTANCE hinstance, DWORD reason, void *reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        HKEY key;
        g_hinstance = hinstance;
        DisableThreadLibraryCalls(hinstance);
        TRACE("NSPA RT:ASIO: nspaASIO driver loaded\n");

        /* Auto-register if ASIO key is missing — avoids needing regsvr32 */
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\ASIO\\nspaASIO",
                          0, KEY_READ, &key) != ERROR_SUCCESS)
            DllRegisterServer();
        else
            RegCloseKey(key);
    }
    return TRUE;
}
