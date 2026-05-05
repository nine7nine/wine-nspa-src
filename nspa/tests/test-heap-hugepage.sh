#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# test-heap-hugepage.sh — smoke + functional test for Phase 3 heap arena
# hugetlb backing.
#
# Validates:
#   1. Bootstrap with default off (no NSPA_HEAP_HUGEPAGE_ARENAS, no
#      NSPA_RT_PRIO).
#   2. Bootstrap with NSPA_HEAP_HUGEPAGE_ARENAS=0 (explicit off).
#   3. Bootstrap with NSPA_HEAP_HUGEPAGE_ARENAS=1 (explicit on).
#   4. NSPA_RT_PRIO triggers Phase 3 default-on.
#   5. Notepad with Phase 3 active produces hugepage-backed regions
#      (it has at least a process heap → at least one Phase 3 promote).
#   6. Phase 3 OFF + NSPA_RT_PRIO=ON yields fewer hugepage regions
#      than Phase 3 ON.
#
# A workload-driven dTLB validation (Ableton) is separate — this is
# just smoke + presence checks.

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

run_smoke() {
    local label="$1"; shift
    local rc
    out=$(env "$@" \
              NSPA_RT_POLICY=FF WINEPRELOADREMAPVDSO=force \
              timeout 15 /usr/bin/wine cmd /c echo hello 2>&1)
    rc=$?
    if [[ $rc -eq 0 ]] && echo "$out" | grep -q '\bhello\b'; then
        ok "$label"
    else
        bad "$label (rc=$rc):"
        echo "$out" | tail -8 | sed 's/^/      /'
    fi
    cleanup
    sleep 1
}

count_hugepages_for() {
    local pid="$1"
    awk '/^KernelPageSize:.*2048 kB/{c++} END{print c+0}' /proc/$pid/smaps 2>/dev/null
}

echo "================================================================"
echo "  Phase 3: heap arena hugetlb backing — smoke + presence test"
echo "================================================================"
echo

echo "[1/6] bootstrap: default off (NSPA_HEAP_HUGEPAGE_ARENAS unset, NSPA_RT_PRIO unset)..."
run_smoke "default-off boot" \
    -u WINEDEBUG -u NSPA_RT_PRIO -u NSPA_HEAP_HUGEPAGE_ARENAS

echo
echo "[2/6] bootstrap: NSPA_HEAP_HUGEPAGE_ARENAS=0 (explicit off)..."
run_smoke "explicit-off boot" \
    -u WINEDEBUG -u NSPA_RT_PRIO NSPA_HEAP_HUGEPAGE_ARENAS=0

echo
echo "[3/6] bootstrap: NSPA_HEAP_HUGEPAGE_ARENAS=1 (explicit on)..."
run_smoke "explicit-on boot" \
    -u WINEDEBUG -u NSPA_RT_PRIO NSPA_HEAP_HUGEPAGE_ARENAS=1

echo
echo "[4/6] bootstrap: NSPA_RT_PRIO=80 (auto-on default)..."
run_smoke "auto-on boot" \
    -u WINEDEBUG NSPA_RT_PRIO=80

echo
echo "[5/6] notepad with Phase 3 active produces hugepage regions..."
NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF WINEPRELOADREMAPVDSO=force \
    NSPA_HEAP_HUGEPAGE_ARENAS=1 \
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

echo
echo "[6/6] OFF baseline: notepad with Phase 3=0 produces fewer regions..."
NSPA_RT_POLICY=FF WINEPRELOADREMAPVDSO=force \
    NSPA_HEAP_HUGEPAGE_ARENAS=0 NSPA_HEAP_HUGEPAGE=0 \
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
        ok "OFF baseline 0 — gate respected (no Phase 3 + no Phase 2)"
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
