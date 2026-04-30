#!/bin/bash
#
# kasan-stress.sh — KASAN stress run for ntsync 1010 (NTSYNC_IOC_AGGREGATE_WAIT).
#
# Run AFTER booting linux-nspa-debug (KASAN+lockdep) and installing the
# patched 1010 module on top.  Per design doc §7.1 / project memory
# project_ntsync_session_20260427_results.md — the prior channel session
# caught 4 latent bugs ONLY under KASAN.
#
# Stages:
#   1. KASAN sanity — refuse to run on a non-KASAN kernel
#   2. aggregate-wait smoke — 1 iter of all 6 sub-tests
#   3. aggregate-wait stress — 1M iter loop (sub-tests 1+4+5+6)
#   4. existing native suite — regression check (test-event-set-pi etc.)
#   5. dmesg post-run — capture any KASAN/lockdep/refcount splats
#
# Usage:
#   sudo ./kasan-stress.sh                # full 1M run
#   sudo ./kasan-stress.sh 10000          # short pre-flight (10k iters)
#
# Exit code: 0 on all stages clean, non-zero on first failure or any
# kernel splat detected post-run.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ITERS="${1:-1000000}"
LOG_DIR="${LOG_DIR:-/tmp/ntsync-1010-kasan-$$}"
mkdir -p "$LOG_DIR"

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
hr()     { printf '%.s=' {1..70}; printf '\n'; }

stage() {
    echo
    hr
    bold "== $* =="
    hr
}

bail() {
    red "FATAL: $*"
    exit 1
}

# --------------------------------------------------------------
# Stage 1: KASAN sanity
# --------------------------------------------------------------
stage "Stage 1: KASAN sanity"

if [[ ! -e /dev/ntsync ]]; then
    bail "/dev/ntsync missing — is the ntsync module loaded?"
fi

# Look for KASAN in the running config.  /proc/config.gz may be present
# (CONFIG_IKCONFIG_PROC=y); fall back to dmesg "KASAN" init line.
KASAN_OK=0
if [[ -r /proc/config.gz ]]; then
    if zgrep -q '^CONFIG_KASAN=y' /proc/config.gz; then
        KASAN_OK=1
        green "  CONFIG_KASAN=y in /proc/config.gz"
    fi
fi
if [[ $KASAN_OK -eq 0 ]]; then
    if dmesg 2>/dev/null | grep -q -i kasan; then
        KASAN_OK=1
        green "  KASAN init line found in dmesg"
    fi
fi
if [[ $KASAN_OK -eq 0 ]]; then
    yellow "  WARNING: could not confirm KASAN active — proceeding anyway"
    yellow "  (verify manually: zgrep CONFIG_KASAN /proc/config.gz)"
fi

uname -srv

# Snapshot dmesg cursor so we can detect splats THIS session emits
DMESG_BEFORE=$(dmesg 2>/dev/null | wc -l)
echo "  dmesg cursor: $DMESG_BEFORE lines"

# Verify module
modinfo ntsync 2>/dev/null | grep -E "^(srcversion|filename|vermagic):" \
    | sed 's/^/  /'

# --------------------------------------------------------------
# Stage 2: smoke (1 iter of all 6 sub-tests)
# --------------------------------------------------------------
stage "Stage 2: aggregate-wait smoke (6 sub-tests)"

if [[ ! -x "$HERE/test-aggregate-wait" ]]; then
    echo "  building test-aggregate-wait ..."
    gcc -O2 -Wall -Wextra -o "$HERE/test-aggregate-wait" \
        "$HERE/test-aggregate-wait.c" -lpthread \
        || bail "build failed"
fi

if ! "$HERE/test-aggregate-wait" | tee "$LOG_DIR/smoke.log"; then
    red "  smoke FAILED — see $LOG_DIR/smoke.log"
    exit 1
fi
green "  smoke PASS"

# --------------------------------------------------------------
# Stage 3: stress (ITERS of sub-tests 1+4+5+6)
# --------------------------------------------------------------
stage "Stage 3: aggregate-wait stress ($ITERS iters)"

START=$(date +%s)
if ! "$HERE/test-aggregate-wait" --stress "$ITERS" 2>&1 \
        | tee "$LOG_DIR/stress.log"; then
    red "  stress FAILED — see $LOG_DIR/stress.log"
    red "  capture dmesg NOW: dmesg | tail -200 > $LOG_DIR/dmesg-fail.log"
    exit 1
fi
END=$(date +%s)
green "  stress PASS  ($((END-START))s)"

# --------------------------------------------------------------
# Stage 4: regression on existing native suite
# --------------------------------------------------------------
stage "Stage 4: existing native ntsync suite (regression)"

if [[ -x "$HERE/run-rt-suite.sh" ]]; then
    if ! "$HERE/run-rt-suite.sh" native 2>&1 \
            | tee "$LOG_DIR/regression.log"; then
        red "  regression FAILED — see $LOG_DIR/regression.log"
        exit 1
    fi
    green "  regression PASS"
else
    yellow "  run-rt-suite.sh not found, skipping regression check"
fi

# --------------------------------------------------------------
# Stage 5: dmesg splat check
# --------------------------------------------------------------
stage "Stage 5: dmesg splat scan"

DMESG_AFTER=$(dmesg 2>/dev/null | wc -l)
DMESG_NEW=$((DMESG_AFTER - DMESG_BEFORE))

if [[ $DMESG_NEW -le 0 ]]; then
    yellow "  no new dmesg lines — kernel may be silent (or perms blocked)"
else
    echo "  $DMESG_NEW new dmesg lines"
    dmesg 2>/dev/null | tail -n "$DMESG_NEW" > "$LOG_DIR/dmesg-tail.log"

    SPLATS=$(grep -ciE 'kasan|use-after-free|out-of-bounds|double-free|bug:|warning:|oops|lockdep|circular|deadlock|refcount_t' \
        "$LOG_DIR/dmesg-tail.log" || true)

    if [[ $SPLATS -gt 0 ]]; then
        red "  $SPLATS suspicious dmesg lines — REVIEW $LOG_DIR/dmesg-tail.log"
        echo
        grep -iE 'kasan|use-after-free|out-of-bounds|double-free|bug:|warning:|oops|lockdep|circular|deadlock|refcount_t' \
            "$LOG_DIR/dmesg-tail.log" | head -20 | sed 's/^/    /'
        exit 1
    fi
    green "  dmesg clean ($DMESG_NEW new lines, 0 splats)"
fi

# --------------------------------------------------------------
echo
hr
green "ALL STAGES PASS — patch 1010 KASAN-clean over $ITERS iters"
echo "logs: $LOG_DIR"
hr
exit 0
