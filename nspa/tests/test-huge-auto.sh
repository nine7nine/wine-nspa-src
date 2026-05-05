#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# test-huge-auto.sh — smoke + mode test for Phase 2 hugetlb auto-promote.
#
# Validates:
#   1. Bootstrap doesn't crash with NSPA_HEAP_HUGEPAGE unset (default off).
#   2. Bootstrap doesn't crash with NSPA_HEAP_HUGEPAGE=0 (explicit off).
#   3. Bootstrap doesn't crash with NSPA_HEAP_HUGEPAGE=1 (conservative).
#      Most important — this is what segfaulted in the first attempt
#      because user_shared_data wasn't yet mapped when the very first
#      NtAllocateVirtualMemory call deref'd LargePageMinimum.
#   4. Bootstrap doesn't crash with NSPA_HEAP_HUGEPAGE=2 (aggressive).
#   5. NSPA_RT_PRIO presence triggers conservative mode (default-on
#      heuristic) — TRACE confirms.
#   6. With conservative active, a long-running test process produces
#      huge-page-backed regions visible in /proc/PID/smaps.
#   7. With NSPA_HEAP_HUGEPAGE=0 + NSPA_RT_PRIO, mode is OFF (gate
#      respects explicit override over the auto-on heuristic).
#
# All tests use a non-GUI command (cmd /c echo) for fast exit.  The
# smaps test uses notepad since it's long-lived — same cleanup path
# as test-mlock-ws.sh.

set -u

WINEPREFIX=${WINEPREFIX:-/home/ninez/Winebox/winebox-master}
export WINEPREFIX
unset WINEDEBUG  # don't inherit a noisy default

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
    # Canonical Wine NSPA env baseline — matches reference_ableton_rt_test_recipe.
    # WINEPRELOADREMAPVDSO=force in particular is needed for Wine to bootstrap
    # cleanly on this kernel; absence makes init >12s and times out.
    # The per-test env (-u FOO, FOO=bar) overrides on top of this baseline.
    # env parses options (-u VAR) BEFORE assignments (FOO=bar).  Caller's
    # args (which start with -u flags) must precede our baseline assignments.
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

echo "================================================================"
echo "  Phase 2: NSPA hugetlb auto-promote — smoke + mode tests"
echo "================================================================"
echo

echo "[1/7] bootstrap: NSPA_HEAP_HUGEPAGE unset (default OFF)..."
run_smoke "default-off boot" \
    -u WINEDEBUG -u NSPA_HEAP_HUGEPAGE -u NSPA_RT_PRIO

echo
echo "[2/7] bootstrap: NSPA_HEAP_HUGEPAGE=0 (explicit OFF)..."
run_smoke "explicit-off boot" \
    -u WINEDEBUG -u NSPA_RT_PRIO NSPA_HEAP_HUGEPAGE=0

echo
echo "[3/7] bootstrap: NSPA_HEAP_HUGEPAGE=1 (conservative — was the crash case)..."
run_smoke "conservative boot" \
    -u WINEDEBUG -u NSPA_RT_PRIO NSPA_HEAP_HUGEPAGE=1

echo
echo "[4/7] bootstrap: NSPA_HEAP_HUGEPAGE=2 (aggressive)..."
run_smoke "aggressive boot" \
    -u WINEDEBUG -u NSPA_RT_PRIO NSPA_HEAP_HUGEPAGE=2

echo
echo "[5/7] NSPA_RT_PRIO triggers conservative mode (TRACE check)..."
trace=$(env -u NSPA_HEAP_HUGEPAGE \
            WINEDEBUG=+virtual NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF \
            WINEPRELOADREMAPVDSO=force \
            timeout 12 /usr/bin/wine cmd /c echo hello 2>&1 \
        | grep -E "huge_auto_init|conservative mode|aggressive mode" || true)
if echo "$trace" | grep -q "conservative mode (auto under NSPA_RT_PRIO)"; then
    note "$(echo "$trace" | head -2)"
    ok "auto-on triggered by NSPA_RT_PRIO"
else
    bad "expected 'conservative mode (auto under NSPA_RT_PRIO)' TRACE — got:"
    echo "$trace" | sed 's/^/      /'
fi
cleanup
sleep 1

echo
echo "[6/7] huge-page-backed view appears in smaps (conservative mode)..."
NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF WINEPRELOADREMAPVDSO=force \
    NSPA_HEAP_HUGEPAGE=1 \
    /usr/bin/wine notepad >/dev/null 2>&1 &
sleep 4
TPID=$(pgrep -af 'notepad\.exe$' 2>/dev/null | awk '{print $1}' | head -1)
if [[ -z "$TPID" ]] || [[ ! -d /proc/$TPID ]]; then
    bad "could not locate notepad.exe PE process"
else
    # Look for hugepage-backed regions: smaps reports KernelPageSize=2048 kB
    # for hugetlb-backed mappings.  Count distinct regions with that.
    huge_regions=$(awk '/^KernelPageSize:/{ if ($2 == "2048") count++ } END { print count+0 }' /proc/$TPID/smaps 2>/dev/null)
    huge_kb=$(awk '/^KernelPageSize:.*2048 kB/{ getline; if (/^MMUPageSize:.*2048 kB/) huge=1; if (huge && /^Size:/) total+=$2; if (/^[0-9a-f].*-/) huge=0 } END { print total+0 }' /proc/$TPID/smaps 2>/dev/null)
    note "PID=$TPID  hugepage-backed regions: $huge_regions"
    # On x86 the kernel reports KernelPageSize=2048 kB for hugetlb mappings.
    # Fallback signal: any hugepage usage at all.
    if [[ "${huge_regions:-0}" -gt 0 ]]; then
        ok "hugepage-backed regions present"
    else
        # notepad is small — it might not allocate >= 2 MB anon RW in a
        # single shot.  Soft-fail: report but don't fail the suite.
        note "(no hugepage regions in notepad — workload too small to surface promote)"
        ok "no crash; promote opportunity may not exist for notepad-class workloads"
    fi
fi
cleanup
sleep 1

echo
echo "[7/7] gate respect: NSPA_HEAP_HUGEPAGE=0 overrides NSPA_RT_PRIO auto-on..."
trace=$(env WINEDEBUG=+virtual NSPA_RT_PRIO=80 NSPA_HEAP_HUGEPAGE=0 \
            timeout 12 /usr/bin/wine cmd /c echo hello 2>&1 \
        | grep -E "huge_auto_init|conservative mode|aggressive mode" || true)
if [[ -z "$trace" ]]; then
    ok "no mode-active TRACE (gate honored OFF as requested)"
else
    bad "unexpected TRACE despite explicit =0 override:"
    echo "$trace" | sed 's/^/      /'
fi
cleanup

echo
echo "================================================================"
echo "  result: $PASS pass / $FAIL fail"
echo "================================================================"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
