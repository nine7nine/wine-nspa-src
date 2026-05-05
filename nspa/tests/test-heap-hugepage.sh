#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# test-heap-hugepage.sh — smoke + presence test for Phase 3 heap arena
# hugetlb backing.
#
# Single gate: NSPA_RT_PRIO presence.  When active, heap.c::allocate_region
# rounds arena allocations to LargePageMinimum and merges the two-call
# RES+COMMIT pattern into a single shot, which Phase 2's huge_auto
# eligibility check then catches and routes through MAP_HUGETLB.
#
# Validates:
#   1. Wine boots clean under NSPA_RT_PRIO (Phase 3 active).
#   2. notepad with NSPA_RT_PRIO produces hugepage-backed regions
#      (process heap is rounded + promoted).
#   3. notepad WITHOUT NSPA_RT_PRIO produces fewer / no hugepage regions.

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

count_hugepages_for() {
    awk '/^KernelPageSize:.*2048 kB/{c++} END{print c+0}' /proc/$1/smaps 2>/dev/null
}

echo "================================================================"
echo "  Phase 3: heap arena hugetlb backing — smoke + presence test"
echo "================================================================"
echo

# --- [1/3] level-0 smoke ---------------------------------------------------
echo "[1/3] level-0 smoke under NSPA_RT_PRIO..."
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

# --- [2/3] notepad with Phase 3 active produces hugepage regions ----------
echo
echo "[2/3] notepad with NSPA_RT_PRIO produces hugepage regions..."
NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF WINEPRELOADREMAPVDSO=force \
    /usr/bin/wine notepad >/dev/null 2>&1 &
sleep 4
TPID=$(pgrep -af 'notepad\.exe$' 2>/dev/null | awk '{print $1}' | head -1)
if [[ -z "$TPID" ]] || [[ ! -d /proc/$TPID ]]; then
    bad "could not locate notepad.exe PE process"
    huge_on=0
else
    huge_on=$(count_hugepages_for "$TPID")
    note "PID=$TPID  hugepage-backed regions: $huge_on"
    if [[ "$huge_on" -gt 0 ]]; then
        ok "Phase 3 produces hugepage regions ($huge_on)"
    else
        bad "no hugepage regions — Phase 3 should at least promote process heap"
    fi
fi
pkill -KILL -x notepad.exe 2>/dev/null || true
wineserver -k -w 2>/dev/null || true
sleep 2

# --- [3/3] OFF baseline: no NSPA_RT_PRIO → fewer regions -------------------
echo
echo "[3/3] notepad WITHOUT NSPA_RT_PRIO (Phase 3 inactive)..."
env -u NSPA_RT_PRIO WINEPRELOADREMAPVDSO=force \
    /usr/bin/wine notepad >/dev/null 2>&1 &
sleep 4
TPID=$(pgrep -af 'notepad\.exe$' 2>/dev/null | awk '{print $1}' | head -1)
if [[ -z "$TPID" ]] || [[ ! -d /proc/$TPID ]]; then
    bad "could not locate notepad.exe PE process (off baseline)"
    huge_off=0
else
    huge_off=$(count_hugepages_for "$TPID")
    note "PID=$TPID  hugepage-backed regions: $huge_off"
    if [[ "$huge_off" -lt "${huge_on:-0}" ]]; then
        ok "OFF baseline ($huge_off) < ON ($huge_on) — gate respected"
    elif [[ "$huge_off" -eq 0 ]]; then
        ok "OFF baseline 0 — gate respected"
    else
        bad "OFF baseline $huge_off vs ON $huge_on — gate not honored"
    fi
fi
pkill -KILL -x notepad.exe 2>/dev/null || true
wineserver -k -w 2>/dev/null || true

echo
echo "================================================================"
echo "  result: $PASS pass / $FAIL fail"
echo "================================================================"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
