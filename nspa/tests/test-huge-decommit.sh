#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# test-huge-decommit.sh — NT semantics regression for Phase 2 auto-promote.
#
# Validates that partial ops on auto-promoted hugetlb-backed views don't
# corrupt NT semantics (correctness > everything per NSPA constraint
# priority).  Catches the C1 bug from audit 2026-05-06: sub-2 MiB
# MEM_DECOMMIT silently failed on hugetlb VMA, leaving stale data
# visible after MEM_COMMIT.
#
# Builds the probe with winegcc on first run; subsequent runs reuse the
# .exe.  Runs once under NSPA_RT_PRIO (Phase 2 active, exercises the fix)
# and once without (sanity check, vanilla path).

set -u

WINE=${WINE:-/usr/bin/wine}
WINEPREFIX=${WINEPREFIX:-/home/ninez/Winebox/winebox-master}
export WINEPREFIX
unset WINEDEBUG

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
src="$script_dir/test-huge-decommit.c"
exe="$script_dir/test-huge-decommit.exe"

PASS=0
FAIL=0

ok()  { printf "  \033[32mPASS\033[0m  %s\n" "$*"; PASS=$((PASS+1)); }
bad() { printf "  \033[31mFAIL\033[0m  %s\n" "$*"; FAIL=$((FAIL+1)); }

cleanup() { wineserver -k -w 2>/dev/null || true; pkill -x wineserver 2>/dev/null || true; sleep 1; }
trap cleanup EXIT

if [[ ! -f "$exe" || "$src" -nt "$exe" ]]; then
    if ! winegcc -m64 -o "$exe" "$src" 2>/dev/null; then
        echo "FAIL: winegcc build failed for $src"; exit 2
    fi
fi

run_probe() {
    local label="$1"; shift
    cleanup
    local out
    # Wine sometimes propagates rc=3 from wineserver disconnect noise
    # at process teardown even when the test itself returned 0.  Trust
    # the "ALL PASS" string from the probe rather than the wrapper rc.
    out=$(env "$@" timeout 30 "$WINE" "$exe" 2>&1)
    if echo "$out" | grep -q "ALL PASS"; then
        ok "$label"
    else
        bad "$label"
        echo "$out" | grep -E "T[0-9]|FAIL|PASS" | sed 's/^/      /'
    fi
}

echo "================================================================"
echo "  C1 regression: partial ops on auto-promoted hugetlb views"
echo "================================================================"
echo

echo "[1/2] under NSPA_RT_PRIO (Phase 2 active)..."
run_probe "RT-mode probe" NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF \
                          WINEPRELOADREMAPVDSO=force

echo
echo "[2/2] without NSPA_RT_PRIO (vanilla path)..."
run_probe "vanilla probe" -u NSPA_RT_PRIO -u NSPA_RT_POLICY

echo
echo "================================================================"
echo "  result: $PASS pass / $FAIL fail"
echo "================================================================"
[[ $FAIL -eq 0 ]] || exit 1
