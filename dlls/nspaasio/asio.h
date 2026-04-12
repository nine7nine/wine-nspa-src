/*
 * Clean-room ASIO type definitions
 *
 * These define the binary interface layout for ASIO audio drivers.
 * Written from public documentation of the ASIO protocol — no
 * Steinberg SDK code is used or required.
 *
 * Copyright 2025 jordan Johnston (Wine-NSPA)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#ifndef __NSPA_ASIO_H__
#define __NSPA_ASIO_H__

#include <windef.h>

/* ── Scalar types ── */

typedef long ASIOBool;
#define ASIOFalse 0
#define ASIOTrue  1

typedef double ASIOSampleRate;
typedef long long ASIOSamples;
typedef long long ASIOTimeStamp;

typedef long ASIOError;
enum {
    ASE_OK               =  0,
    ASE_SUCCESS          =  0x3f4847a0,
    ASE_NotPresent       = -1000,
    ASE_HWMalfunction    = -1001,
    ASE_InvalidParameter = -1002,
    ASE_InvalidMode      = -1003,
    ASE_SPNotAdvancing   = -1004,
    ASE_NoClock          = -1005,
    ASE_NoMemory         = -1006
};

typedef long ASIOSampleType;
enum {
    ASIOSTInt16MSB   = 0,
    ASIOSTInt24MSB   = 1,
    ASIOSTInt32MSB   = 2,
    ASIOSTFloat32MSB = 3,
    ASIOSTFloat64MSB = 4,
    ASIOSTInt32MSB16 = 8,
    ASIOSTInt32MSB18 = 9,
    ASIOSTInt32MSB20 = 10,
    ASIOSTInt32MSB24 = 11,
    ASIOSTInt16LSB   = 16,
    ASIOSTInt24LSB   = 17,
    ASIOSTInt32LSB   = 18,
    ASIOSTFloat32LSB = 19,
    ASIOSTFloat64LSB = 20,
    ASIOSTInt32LSB16 = 24,
    ASIOSTInt32LSB18 = 25,
    ASIOSTInt32LSB20 = 26,
    ASIOSTInt32LSB24 = 27,
    ASIOSTLastEntry
};

/* ── Structures ── */

typedef struct ASIODriverInfo {
    long  asioVersion;
    long  driverVersion;
    char  name[32];
    char  errorMessage[124];
    void *sysRef;
} ASIODriverInfo;

typedef struct ASIOBufferInfo {
    ASIOBool isInput;
    long     channelNum;
    void    *buffers[2];
} ASIOBufferInfo;

typedef struct ASIOChannelInfo {
    long          channel;
    ASIOBool      isInput;
    ASIOBool      isActive;
    long          channelGroup;
    ASIOSampleType type;
    char          name[32];
} ASIOChannelInfo;

typedef struct ASIOClockSource {
    long     index;
    long     associatedChannel;
    long     associatedGroup;
    ASIOBool isCurrentSource;
    char     name[32];
} ASIOClockSource;

/* ── Time info ── */

enum {
    kSystemTimeValid     = 1,
    kSamplePositionValid = 1 << 1,
    kSampleRateValid     = 1 << 2,
    kSpeedValid          = 1 << 3,
    kSampleRateChanged   = 1 << 4,
    kClockSourceChanged  = 1 << 5
};

typedef struct AsioTimeInfo {
    double         speed;
    ASIOTimeStamp  systemTime;
    ASIOSamples    samplePosition;
    ASIOSampleRate sampleRate;
    unsigned long  flags;
    char           reserved[12];
} AsioTimeInfo;

enum {
    kTcValid      = 1,
    kTcRunning    = 1 << 1,
    kTcReverse    = 1 << 2,
    kTcOnspeed    = 1 << 3,
    kTcStill      = 1 << 4,
    kTcSpeedValid = 1 << 8
};

typedef struct ASIOTimeCode {
    double        speed;
    ASIOSamples   timeCodeSamples;
    unsigned long flags;
    char          future[64];
} ASIOTimeCode;

typedef struct ASIOTime {
    long          reserved[4];
    AsioTimeInfo  timeInfo;
    ASIOTimeCode  timeCode;
} ASIOTime;

/* ── Callbacks (host → driver) ── */

typedef struct ASIOCallbacks {
    void      (CALLBACK *bufferSwitch)(long doubleBufferIndex, ASIOBool directProcess);
    void      (CALLBACK *sampleRateDidChange)(ASIOSampleRate sRate);
    long      (CALLBACK *asioMessage)(long selector, long value, void *message, double *opt);
    ASIOTime *(CALLBACK *bufferSwitchTimeInfo)(ASIOTime *params, long doubleBufferIndex, ASIOBool directProcess);
} ASIOCallbacks;

/* ── Message selectors ── */

enum {
    kAsioSelectorSupported  = 1,
    kAsioEngineVersion      = 2,
    kAsioResetRequest       = 3,
    kAsioBufferSizeChange   = 4,
    kAsioResyncRequest      = 5,
    kAsioLatenciesChanged   = 6,
    kAsioSupportsTimeInfo   = 7,
    kAsioSupportsTimeCode   = 8,
    kAsioSupportsInputMonitor = 10,
    kAsioOverload           = 15
};

/* ── Future selectors ── */

enum {
    kAsioSetIoFormat   = 0x23111961,
    kAsioGetIoFormat   = 0x23111983,
    kAsioCanDoIoFormat = 0x23112004
};

#endif /* __NSPA_ASIO_H__ */
