/* SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * include/rtpi.h — Wine-NSPA forwarder header
 *
 * This file exists so that any Wine compile line that has -Iinclude
 * -I../include (which is every DLL under the Wine build system) can
 * find <rtpi.h> and pick up the NSPA header-only implementation at
 * libs/librtpi/rtpi.h, NOT the system-installed upstream librtpi
 * header at /usr/include/rtpi.h.
 *
 * Why this matters: upstream librtpi does not have
 * NSPA_RTPI_MUTEX_RECURSIVE or the nspa_recursion extension field.
 * If any Wine DLL accidentally compiled against upstream (because
 * -Iinclude/-I../include didn't shadow /usr/include), the resulting
 * object code would mis-lay out pi_mutex_t and silently misbehave
 * at runtime — different parts of Wine would see different pi_mutex_t
 * layouts and the recursive path through virtual_mutex would break.
 *
 * By forwarding through this file, every Wine DLL in the tree
 * automatically picks up the NSPA version — no per-Makefile.in
 * -I$(top_srcdir)/libs/librtpi hacks needed. The include/ directory
 * is searched first by every compile line, so our version wins
 * before the system search path is consulted.
 */

#ifndef __WINE_INCLUDE_RTPI_H
#define __WINE_INCLUDE_RTPI_H

#include "../libs/librtpi/rtpi.h"

#endif /* __WINE_INCLUDE_RTPI_H */
