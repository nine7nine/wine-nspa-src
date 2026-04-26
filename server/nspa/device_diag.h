/*
 * NSPA wineserver-side diagnostic for get_next_device_request.
 *
 * Captures per-call dispatch outcome + per-caller (Linux TID)
 * breakdown + per-device-name breakdown (RETURNED_IRP only) so
 * we can disambiguate Shape A/B/C/D as defined in
 * nspa/docs/sechost-investigation.md §4.
 *
 * Runtime-gated via NSPA_DEVICE_DIAG=1 env var.  Dumps on
 * SIGUSR1 alongside nspa_profile; resets on SIGUSR2.
 *
 * Output: /tmp/nspa_device_diag.<pid>.log
 *
 * Counters use relaxed atomics; per-thread/per-device hash tables
 * use CAS-claimed slots.  No allocation on the record path.
 */

#ifndef __WINE_SERVER_NSPA_DEVICE_DIAG_H
#define __WINE_SERVER_NSPA_DEVICE_DIAG_H

enum nspa_device_outcome
{
    NSPA_DEV_OUTCOME_RETURNED_IRP,
    NSPA_DEV_OUTCOME_BLOCKED_NO_REQUESTS,
    NSPA_DEV_OUTCOME_HANDLE_ALLOC_FAILED,
    NSPA_DEV_OUTCOME_BUFFER_OVERFLOW,
    NSPA_DEV_OUTCOME_NB
};

extern void nspa_device_diag_init(void);
extern int  nspa_device_diag_active(void);

/* Record one call.
 *  outcome           — one of NSPA_DEV_OUTCOME_*.
 *  caller_unix_tid   — current->unix_tid (the caller's wineserver-side
 *                      proxy TID).  /proc/<tid>/comm is read at dump
 *                      time for human-readable identity.
 *  device_name       — UTF-16 device name (Win32 WCHAR, 16-bit); NULL
 *                      if outcome != RETURNED.  Type is `unsigned short *`
 *                      to avoid pulling Win32 typedefs into the header
 *                      (server-internal C uses Win32 WCHAR, not Linux
 *                      wchar_t which is 32-bit).
 *  device_name_len   — WCHAR count (NOT bytes).
 */
extern void nspa_device_diag_record( enum nspa_device_outcome outcome,
                                     int caller_unix_tid,
                                     const unsigned short *device_name,
                                     unsigned int device_name_len );

extern void nspa_device_diag_dump(void);
extern void nspa_device_diag_reset(void);

#endif  /* __WINE_SERVER_NSPA_DEVICE_DIAG_H */
