#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# test-mlock-ws.sh — smoke + functional test for Phase 1 mlockall hook.
#
# Single gate: NSPA_RT_PRIO presence.  Validates:
#   1. Wine loads under NSPA_RT_PRIO without crash.
#   2. TRACE confirms mlockall fires.
#   3. VmLck > 0 on a running Wine process under RT.
#   4. Without NSPA_RT_PRIO, no Phase 1 activation (VmLck stays at the
#      JACK/nspaASIO baseline residual).
#
# Uses non-GUI commands (cmd /c echo) for fast exit + notepad for the
# longer-lived VmLck checks.

set -u

WINEPREFIX=${WINEPREFIX:-/home/ninez/Winebox/winebox-master}
export WINEPREFIX
unset WINEDEBUG

PASS=0
FAIL=0

note() { printf "  %s\n" "$*"; }
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$*"; PASS=$((PASS+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$*"; FAIL=$((FAIL+1)); }

cleanup() {
    pkill -KILL -x notepad.exe 2>/dev/null || true
    wineserver -k -w 2>/dev/null || true
    pkill -x wineserver 2>/dev/null || true
    sleep 1
}
trap cleanup EXIT

cleanup
sleep 1

echo "================================================================"
echo "  Phase 1: NSPA mlock-ws — smoke + presence test"
echo "================================================================"
echo

# --- [1/4] level-0 smoke ---------------------------------------------------
echo "[1/4] level-0 smoke (Wine loads with NSPA_RT_PRIO=80)..."
out=$(NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF WINEPRELOADREMAPVDSO=force \
        timeout 15 /usr/bin/wine cmd /c echo hello 2>/dev/null)
rc=$?
if [[ $rc -eq 0 ]] && echo "$out" | grep -q '\bhello\b'; then
    ok "wine cmd echoed 'hello' (rc=$rc)"
else
    bad "wine cmd failed (rc=$rc): '$out'"
fi
cleanup
sleep 1

# --- [2/4] mlockall TRACE confirms it fires --------------------------------
echo
echo "[2/4] mlockall fires under NSPA_RT_PRIO..."
trace=$(WINEDEBUG=+virtual NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF \
          WINEPRELOADREMAPVDSO=force \
          timeout 15 /usr/bin/wine cmd /c echo hello 2>&1 \
          | grep -E "nspa_mlock_ws_init|RLIMIT_MEMLOCK|working-set" || true)
if echo "$trace" | grep -qE "mlockall\(CURRENT\|FUTURE\|ONFAULT\) ok|MCL_ONFAULT unsupported"; then
    note "$(echo "$trace" | head -2)"
    ok "TRACE confirms mlockall path executed"
else
    bad "no mlockall TRACE found:"
    echo "$trace" | sed 's/^/      /'
fi
cleanup
sleep 1

# --- [3/4] VmLck > 0 with NSPA_RT_PRIO -------------------------------------
echo
echo "[3/4] VmLck > 0 on a process running under NSPA_RT_PRIO..."
NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF WINEPRELOADREMAPVDSO=force \
    /usr/bin/wine notepad >/dev/null 2>&1 &
sleep 4
TPID=$(pgrep -af 'notepad\.exe$' 2>/dev/null | awk '{print $1}' | head -1)
if [[ -z "$TPID" ]] || [[ ! -d /proc/$TPID ]]; then
    bad "could not locate notepad.exe PE process"
    VmLck_on=0
else
    VmLck_on=$(awk '/^VmLck:/{print $2}' /proc/$TPID/status)
    VmRSS_on=$(awk '/^VmRSS:/{print $2}' /proc/$TPID/status)
    note "PID=$TPID  VmLck=${VmLck_on} kB  VmRSS=${VmRSS_on} kB"
    if [[ "${VmLck_on:-0}" -gt 0 ]]; then
        ok "VmLck > 0 (process is pinning pages)"
    else
        bad "VmLck = 0 — pages not pinned"
    fi
fi
pkill -KILL -x notepad.exe 2>/dev/null || true
wineserver -k -w 2>/dev/null || true
sleep 2

# --- [4/4] no NSPA_RT_PRIO → no Phase 1 ------------------------------------
echo
echo "[4/4] without NSPA_RT_PRIO, VmLck stays at baseline residual..."
env -u NSPA_RT_PRIO WINEPRELOADREMAPVDSO=force \
    /usr/bin/wine notepad >/dev/null 2>&1 &
sleep 4
TPID=$(pgrep -af 'notepad\.exe$' 2>/dev/null | awk '{print $1}' | head -1)
if [[ -z "$TPID" ]] || [[ ! -d /proc/$TPID ]]; then
    bad "could not locate notepad.exe PE process (no-RT run)"
    VmLck_off=0
else
    VmLck_off=$(awk '/^VmLck:/{print $2}' /proc/$TPID/status)
    VmRSS_off=$(awk '/^VmRSS:/{print $2}' /proc/$TPID/status)
    note "PID=$TPID  VmLck=${VmLck_off} kB  VmRSS=${VmRSS_off} kB"
    if [[ "${VmLck_on:-0}" -gt 0 ]] && [[ "${VmLck_off:-0}" -lt "${VmLck_on:-0}" ]]; then
        ok "ON-gate VmLck (${VmLck_on}) >> OFF-gate VmLck (${VmLck_off}) — gate works"
    elif [[ "${VmLck_off:-0}" -lt 4096 ]]; then
        ok "OFF-gate VmLck under 4MB (${VmLck_off} kB) — gate appears respected"
    else
        bad "OFF-gate VmLck = ${VmLck_off} kB suspiciously high"
    fi
fi
pkill -KILL -x notepad.exe 2>/dev/null || true
wineserver -k -w 2>/dev/null || true

echo
echo "================================================================"
echo "  result: $PASS pass / $FAIL fail"
echo "================================================================"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
