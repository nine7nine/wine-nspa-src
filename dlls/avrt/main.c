/* Avrt dll implementation
 *
 * Copyright (C) 2009 Maarten Lankhorst
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "wine/debug.h"
#include "avrt.h"

WINE_DEFAULT_DEBUG_CHANNEL(avrt);

static inline WCHAR *strdupAW(const char *src)
{
    int len;
    WCHAR *dst;
    if (!src) return NULL;
    len = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
    if ((dst = malloc(len * sizeof(*dst)))) MultiByteToWideChar(CP_ACP, 0, src, -1, dst, len);
    return dst;
}

HANDLE WINAPI AvSetMmThreadCharacteristicsA(const char *name, DWORD *index)
{
    WCHAR *nameW = NULL;
    HANDLE ret;

    if (name && !(nameW = strdupAW(name)))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    ret = AvSetMmThreadCharacteristicsW(nameW, index);

    free(nameW);
    return ret;
}

HANDLE WINAPI AvSetMmThreadCharacteristicsW(const WCHAR *name, DWORD *index)
{
    if (!name)
    {
        SetLastError(ERROR_INVALID_TASK_NAME);
        return NULL;
    }

    if (!index)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }

    /* NSPA RT call-site hint: MCSS task classes that correspond to audio
     * workloads get promoted to TIME_CRITICAL. Under NSPA_RT_PRIO, this
     * hits the Tier 1 self-promotion fast path in ntdll and lands the
     * calling thread on SCHED_FIFO. Window Manager is explicitly clamped
     * to NORMAL because MCSS classifies it as non-audio-critical and
     * leaving it at whatever the caller had can cause it to compete with
     * real audio threads. */
    if (!wcscmp(name, L"Audio") || !wcscmp(name, L"Pro Audio"))
    {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        TRACE("NSPA RT:Avrt: %s -> TIME_CRITICAL (tid=%04lx)\n",
              debugstr_w(name), GetCurrentThreadId());
    }
    else if (!wcscmp(name, L"Window Manager"))
    {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
        TRACE("NSPA RT:Avrt: %s -> NORMAL (tid=%04lx)\n",
              debugstr_w(name), GetCurrentThreadId());
    }
    else
    {
        FIXME("NSPA RT:Avrt: unhandled task class %s (tid=%04lx)\n",
              debugstr_w(name), GetCurrentThreadId());
    }

    return (HANDLE)0x12345678;
}

BOOL WINAPI AvQuerySystemResponsiveness(HANDLE AvrtHandle, ULONG *value)
{
    FIXME("(%p, %p): stub\n", AvrtHandle, value);
    return FALSE;
}

BOOL WINAPI AvRevertMmThreadCharacteristics(HANDLE AvrtHandle)
{
    /* NSPA RT: revert the call-site hint from AvSetMmThreadCharacteristicsW.
     * SetThreadPriority(NORMAL) will go through the standard wineserver path;
     * Tier 2 in server/thread.c will demote the thread back to SCHED_OTHER
     * via nspa_rt_maybe_demote() when the NT priority drops out of the RT
     * band. No special handling needed here. */
    TRACE("NSPA RT:Avrt: revert -> NORMAL (tid=%04lx)\n", GetCurrentThreadId());
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

    return TRUE;
}

BOOL WINAPI AvSetMmThreadPriority(HANDLE AvrtHandle, AVRT_PRIORITY prio)
{
    TRACE("NSPA RT:Avrt: SetMmThreadPriority(%u) (tid=%04lx)\n", prio, GetCurrentThreadId());
    return TRUE;
}

HANDLE WINAPI AvSetMmMaxThreadCharacteristicsA(const char *task1, const char *task2, DWORD *index)
{
    WCHAR *task1W = NULL, *task2W = NULL;
    HANDLE ret;

    if (task1 && !(task1W = strdupAW(task1)))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    if (task2 && !(task2W = strdupAW(task2)))
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    ret = AvSetMmMaxThreadCharacteristicsW(task1W, task2W, index);

    free(task2W);
    free(task1W);
    return ret;
}

HANDLE WINAPI AvSetMmMaxThreadCharacteristicsW(const WCHAR *task1, const WCHAR *task2, DWORD *index)
{
    FIXME("(%s,%s,%p): stub\n", debugstr_w(task1), debugstr_w(task2), index);

    if (!task1 || task2)
    {
        SetLastError(ERROR_INVALID_TASK_NAME);
        return NULL;
    }

    if (!index)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }

    return (HANDLE)0x12345678;
}
