#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# test-huge-rwx.sh — verifies Phase 2 auto-promote covers
# PAGE_EXECUTE_READWRITE (JIT code blobs) under NSPA_RT_PRIO.
#
# Trigger: VirtualAlloc(>=2 MiB, RES+COMMIT, PAGE_EXECUTE_READWRITE).
# Under NSPA_RT_PRIO with the eligibility extension, the resulting view
# is hugetlb-backed (KernelPageSize=2048 kB) and remains executable.
# Without NSPA_RT_PRIO, the view falls back to regular 4 kB pages.

set -u

WINE=${WINE:-/usr/bin/wine}
WINEPREFIX=${WINEPREFIX:-/home/ninez/Winebox/winebox-master}
export WINEPREFIX
unset WINEDEBUG

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
src="$script_dir/test-huge-rwx.c"
exe="$script_dir/test-huge-rwx.exe"

PASS=0; FAIL=0
ok()  { printf "  \033[32mPASS\033[0m  %s\n" "$*"; PASS=$((PASS+1)); }
bad() { printf "  \033[31mFAIL\033[0m  %s\n" "$*"; FAIL=$((FAIL+1)); }

cleanup() { wineserver -k -w 2>/dev/null || true; pkill -x wineserver 2>/dev/null || true; sleep 1; }
trap cleanup EXIT

if [[ ! -f "$exe" || "$src" -nt "$exe" ]]; then
    if ! winegcc -m64 -o "$exe" "$src" 2>/dev/null; then
        echo "FAIL: winegcc build failed for $src"; exit 2
    fi
fi

run() {
    local label="$1" want="$2"; shift 2
    cleanup
    local out
    out=$(env "$@" timeout 30 "$WINE" "$exe" 2>&1)
    local kps=$(echo "$out" | grep -oE "KernelPageSize: [0-9]+" | grep -oE "[0-9]+$" | head -1)
    if [[ "$kps" == "$want" ]]; then
        ok "$label (KernelPageSize=$kps kB)"
    else
        bad "$label (got KernelPageSize=$kps, want $want)"
        echo "$out" | tail -5 | sed 's/^/      /'
    fi
}

echo "================================================================"
echo "  Phase 2 RWX auto-promote (PAGE_EXECUTE_READWRITE)"
echo "================================================================"
echo

echo "[1/2] under NSPA_RT_PRIO -> expect hugepage backing (2048 kB)..."
run "RWX hugepage-backed under RT_PRIO" 2048 \
    NSPA_RT_PRIO=80 NSPA_RT_POLICY=FF WINEPRELOADREMAPVDSO=force

echo
echo "[2/2] without NSPA_RT_PRIO -> expect regular pages (4 kB)..."
run "RWX falls back to regular pages without RT_PRIO" 4 \
    -u NSPA_RT_PRIO -u NSPA_RT_POLICY

echo
echo "================================================================"
echo "  result: $PASS pass / $FAIL fail"
echo "================================================================"
[[ $FAIL -eq 0 ]] || exit 1
