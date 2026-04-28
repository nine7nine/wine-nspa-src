#!/bin/bash
#
# run-rt-suite.sh — full RT + ntsync test suite driver.
#
# Layer 1: native /dev/ntsync ioctl tests (wine/nspa/tests/test-*.c).
#   - Validate kernel-level invariants the Win32 layer can't reach
#     (channels, EVENT_SET_PI, raw sched attrs).
# Layer 2: PE Wine binary nspa_rt_test.exe.
#   - Validate full Wine -> ntsync stack via Win32 APIs.
#
# Usage: ./run-rt-suite.sh [layer]
#   layer = "native" | "wine" | "all"  (default: all)

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LAYER="${1:-all}"

CC=${CC:-gcc}
CFLAGS=${CFLAGS:--O2 -Wall -Wextra}
LDFLAGS=${LDFLAGS:--lpthread}

NATIVE_TESTS=(
    test-event-set-pi
    test-channel-recv-exclusive
)

# Tests skipped by design (assert ntsync 1007 behaviour we rolled back —
# 1007-1011 didn't fix the EVENT_SET_PI slab UAF and were unstable):
#   test-cross-boost           — asserts 1007 cross-boost cleanup
#   test-wait-rejects-channel  — asserts 1007 channel-reject in setup_wait
# Re-enable only if a future ntsync change makes these invariants real.
#
# test-channel-recv-exclusive is KEPT — even though it was originally
# written as a 1007 exclusive-recv assertion, on the post-1006 baseline
# it deterministically hangs in ntsync_obj_ioctl, which appears to
# reproduce the kernel-side channel bug behind production gamma-
# dispatcher lockups (Phase B, msg-ring v2 B1.0).  Treat as a
# regression repro for the channel hang, not as a 1007 assertion.
SKIPPED_BY_DESIGN=(
    test-cross-boost
    test-wait-rejects-channel
)

PE_RUNNER="/home/ninez/pkgbuilds/Wine-NSPA/wine-rt-claude/wine/nspa/run_rt_tests.sh"

red()    { printf '\033[31m%s\033[0m' "$*"; }
green()  { printf '\033[32m%s\033[0m' "$*"; }
yellow() { printf '\033[33m%s\033[0m' "$*"; }
bold()   { printf '\033[1m%s\033[0m' "$*"; }

build_native() {
    local name=$1
    local src="$HERE/$name.c"
    local out="$HERE/$name"
    if [[ ! -f "$src" ]]; then
        echo "  $(yellow SKIP): no source $src"
        return 2
    fi
    if [[ ! -f "$out" || "$src" -nt "$out" ]]; then
        echo "  building $name ..."
        if ! $CC $CFLAGS -o "$out" "$src" $LDFLAGS 2>&1; then
            echo "  $(red BUILD-FAIL): $name"
            return 1
        fi
    fi
    return 0
}

run_native() {
    local pass=0 fail=0 skip=0
    echo
    echo "$(bold "=== Layer 1: native /dev/ntsync ioctl tests ===")"
    if [[ ! -e /dev/ntsync ]]; then
        echo "  $(red FATAL): /dev/ntsync missing — is the ntsync module loaded?"
        return 1
    fi
    if [[ ! -r /dev/ntsync ]]; then
        echo "  $(red FATAL): /dev/ntsync not readable — check perms or run with sudo"
        return 1
    fi
    if [[ ${#SKIPPED_BY_DESIGN[@]} -gt 0 ]]; then
        echo "  $(yellow "SKIPPED BY DESIGN:") ${SKIPPED_BY_DESIGN[*]}"
    fi
    for t in "${NATIVE_TESTS[@]}"; do
        echo
        echo "--- $t ---"
        build_native "$t"
        case $? in
            1) fail=$((fail+1)); continue ;;
            2) skip=$((skip+1)); continue ;;
        esac
        if "$HERE/$t"; then
            pass=$((pass+1))
        else
            local rc=$?
            if [[ $rc -eq 77 ]]; then
                echo "  $(yellow SKIP): test reported skip (rc=77)"
                skip=$((skip+1))
            else
                fail=$((fail+1))
            fi
        fi
    done
    echo
    echo "Layer 1 summary: $(green "$pass pass") / $(red "$fail fail") / $(yellow "$skip skip")"
    return $fail
}

run_wine() {
    echo
    echo "$(bold "=== Layer 2: Wine PE nspa_rt_test (delegating to run_rt_tests.sh) ===")"
    if [[ ! -x "$PE_RUNNER" ]]; then
        echo "  $(red FATAL): $PE_RUNNER not found"
        return 1
    fi
    "$PE_RUNNER"
}

case "$LAYER" in
    native)
        run_native ;;
    wine)
        run_wine ;;
    all)
        run_native || true
        run_wine ;;
    *)
        echo "usage: $0 [native|wine|all]" >&2
        exit 2
        ;;
esac
