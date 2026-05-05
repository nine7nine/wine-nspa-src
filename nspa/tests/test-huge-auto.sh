#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# test-huge-auto.sh — smoke + activation test for Phase 2 hugetlb opt-in.
#
# Single gate: NSPA_RT_PRIO presence.  Phase 2 catches single-shot
# ≥ 2 MB anonymous RW allocations.  Most app-direct VirtualAlloc
# patterns won't qualify; Phase 3 reshapes Wine heap.c arenas to do.
#
# Validates:
#   1. Wine boots clean under NSPA_RT_PRIO (Phase 2 active).
#   2. TRACE confirms huge_auto activation.
#   3. Wine boots clean WITHOUT NSPA_RT_PRIO (Phase 2 inactive).

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

echo "================================================================"
echo "  Phase 2: NSPA huge auto-promote — smoke + activation test"
echo "================================================================"
echo

echo "[1/3] bootstrap with NSPA_RT_PRIO=80 (Phase 2 active)..."
run_smoke "RT boot" NSPA_RT_PRIO=80

echo
echo "[2/3] TRACE confirms huge_auto activation under NSPA_RT_PRIO..."
trace=$(env -u WINEDEBUG NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF \
            WINEPRELOADREMAPVDSO=force WINEDEBUG=+virtual \
            timeout 15 /usr/bin/wine cmd /c echo hello 2>&1 \
        | grep -E "huge auto-promote active" || true)
if echo "$trace" | grep -q "huge auto-promote active"; then
    note "$(echo "$trace" | head -1)"
    ok "auto-promote activated under NSPA_RT_PRIO"
else
    bad "expected 'huge auto-promote active' TRACE — got:"
    echo "$trace" | sed 's/^/      /'
fi
cleanup
sleep 1

echo
echo "[3/3] bootstrap WITHOUT NSPA_RT_PRIO (Phase 2 inactive)..."
run_smoke "non-RT boot" -u NSPA_RT_PRIO

echo
echo "================================================================"
echo "  result: $PASS pass / $FAIL fail"
echo "================================================================"

[[ $FAIL -eq 0 ]] && exit 0 || exit 1
