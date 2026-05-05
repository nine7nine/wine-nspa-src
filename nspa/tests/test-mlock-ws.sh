#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# test-mlock-ws.sh — smoke + functional test for Phase 1 mlockall hook.
#
# Validates that nspa_mlock_ws_init():
#   1. Doesn't break Wine startup.
#   2. Actually fires mlockall when NSPA_MLOCK_WORKINGSET=1 (visible via
#      WINEDEBUG=+virtual TRACE).
#   3. Pins pages (VmLck > 0) on a running Wine process.
#   4. Respects the env gate: with NSPA_MLOCK_WORKINGSET=0, no pinning.
#
# Uses non-GUI commands (cmd /c timeout) for tests 3/4 — they exit
# cleanly on their own, no GUI to stall the harness.

set -u

WINEPREFIX=${WINEPREFIX:-/home/ninez/Winebox/winebox-master}
export WINEPREFIX

# Ensure we don't inherit a noisy WINEDEBUG from the parent shell.
unset WINEDEBUG

PASS=0
FAIL=0

note() { printf "  %s\n" "$*"; }
ok()   { printf "  \033[32mPASS\033[0m  %s\n" "$*"; PASS=$((PASS+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %s\n" "$*"; FAIL=$((FAIL+1)); }

cleanup() {
    pkill -x cmd.exe 2>/dev/null || true
    pkill -x timeout.exe 2>/dev/null || true
    wineserver -k 2>/dev/null || true
    sleep 1
    pkill -x wineserver 2>/dev/null || true
}
trap cleanup EXIT

cleanup
sleep 1

echo "================================================================"
echo "  Phase 1: NSPA mlock-ws smoke + functional test"
echo "================================================================"
echo "  WINEPREFIX = $WINEPREFIX"
echo

# ---------------------------------------------------------------------------
# Test 1: level-0 smoke — Wine still loads with NSPA_RT_PRIO set.
# Just check exit status + that "hello" appears anywhere in stdout
# (stderr will be full of NSPA RT banner messages — not a failure).
# ---------------------------------------------------------------------------
echo "[1/4] level-0 smoke (Wine loads with NSPA_RT_PRIO=80)..."
out=$(NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF WINEPRELOADREMAPVDSO=force \
        timeout 15 /usr/bin/wine cmd /c echo hello 2>/dev/null)
rc=$?
if [[ $rc -eq 0 ]] && echo "$out" | grep -q '\bhello\b'; then
    ok "wine cmd echoed 'hello' (rc=$rc)"
else
    bad "wine cmd failed (rc=$rc) or no 'hello' in stdout: '$out'"
fi
cleanup
sleep 1

# ---------------------------------------------------------------------------
# Test 2: TRACE message confirms mlockall fired.
# ---------------------------------------------------------------------------
echo
echo "[2/4] mlockall fires with NSPA_MLOCK_WORKINGSET=1..."
trace=$(WINEDEBUG=+virtual NSPA_MLOCK_WORKINGSET=1 \
          timeout 15 /usr/bin/wine cmd /c echo hello 2>&1 \
          | grep -E "nspa_mlock_ws_init|RLIMIT_MEMLOCK|working-set" || true)
if echo "$trace" | grep -qE "mlockall\(CURRENT\|FUTURE\|ONFAULT\) ok|MCL_ONFAULT unsupported"; then
    note "$(echo "$trace" | head -3)"
    ok "TRACE confirms mlockall path executed"
elif echo "$trace" | grep -q "mlockall failed"; then
    bad "mlockall returned failure:"
    echo "$trace" | sed 's/^/      /'
else
    bad "no mlockall TRACE found — channel muted or hook not wired"
    note "raw trace lines: $trace"
fi
cleanup
sleep 1

# ---------------------------------------------------------------------------
# Test 3: VmLck > 0 with gate ON. Use cmd /c timeout (non-GUI, self-exits).
# ---------------------------------------------------------------------------
read_vmlck_for() {
    local pidpat="$1"
    local pid=$(pgrep -fx "$pidpat" 2>/dev/null | head -1)
    [[ -z "$pid" ]] && { echo "0 0"; return; }
    awk '/^VmLck:/{lck=$2} /^VmRSS:/{rss=$2} END {print lck+0, rss+0}' \
        /proc/$pid/status 2>/dev/null
    echo "$pid" >&2
}

echo
echo "[3/4] VmLck > 0 with NSPA_MLOCK_WORKINGSET=1 (cmd /c timeout)..."
NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF WINEPRELOADREMAPVDSO=force \
    NSPA_MLOCK_WORKINGSET=1 \
    /usr/bin/wine notepad >/dev/null 2>&1 &
LPID=$!
sleep 4
TPID=$(pgrep -af 'notepad\.exe$' 2>/dev/null | awk '{print $1}' | head -1)
if [[ -z "$TPID" ]] || [[ ! -d /proc/$TPID ]]; then
    bad "could not locate notepad.exe PE process"
    VmLck_on=0
else
    VmLck_on=$(awk '/^VmLck:/{print $2}' /proc/$TPID/status 2>/dev/null)
    VmRSS_on=$(awk '/^VmRSS:/{print $2}' /proc/$TPID/status 2>/dev/null)
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

# ---------------------------------------------------------------------------
# Test 4: gate respected — NSPA_MLOCK_WORKINGSET=0 → VmLck near zero.
# ---------------------------------------------------------------------------
echo
echo "[4/4] VmLck baseline with NSPA_MLOCK_WORKINGSET=0 (gate respected)..."
NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF WINEPRELOADREMAPVDSO=force \
    NSPA_MLOCK_WORKINGSET=0 \
    /usr/bin/wine notepad >/dev/null 2>&1 &
LPID=$!
sleep 4
TPID=$(pgrep -af 'notepad\.exe$' 2>/dev/null | awk '{print $1}' | head -1)
if [[ -z "$TPID" ]] || [[ ! -d /proc/$TPID ]]; then
    bad "could not locate timeout.exe PE process (off-gate run)"
    VmLck_off=0
else
    VmLck_off=$(awk '/^VmLck:/{print $2}' /proc/$TPID/status 2>/dev/null)
    VmRSS_off=$(awk '/^VmRSS:/{print $2}' /proc/$TPID/status 2>/dev/null)
    note "PID=$TPID  VmLck=${VmLck_off} kB  VmRSS=${VmRSS_off} kB"
    if [[ "${VmLck_on:-0}" -gt 0 ]] && [[ "${VmLck_off:-0}" -lt "${VmLck_on:-0}" ]]; then
        ok "ON-gate VmLck (${VmLck_on}) >> OFF-gate VmLck (${VmLck_off}) — gate works"
    elif [[ "${VmLck_off:-0}" -lt 4096 ]]; then
        ok "OFF-gate VmLck under 4MB (${VmLck_off} kB) — gate appears respected"
    else
        bad "OFF-gate VmLck = ${VmLck_off} kB suspiciously high — gate not respected?"
    fi
fi
pkill -KILL -x notepad.exe 2>/dev/null || true
wineserver -k -w 2>/dev/null || true
sleep 2

echo
echo "================================================================"
echo "  result: $PASS pass / $FAIL fail"
echo "================================================================"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
