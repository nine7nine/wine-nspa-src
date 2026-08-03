#!/bin/bash
#
# run-rt-suite.sh — full RT + ntsync test suite driver.
#
# Layer 1: native /dev/ntsync ioctl tests (wine/nspa/tests/test-*.c).
#   - Validate kernel-level invariants the Win32 layer can't reach
#     (channels, EVENT_SET_PI, raw sched attrs).
# Layer 2: PE Wine binary nspa_rt_test.exe.
#   - Validate full Wine -> ntsync stack via Win32 APIs.
# Layer 3: NSPA regression exes (standalone mingw-built reproducers for
#   fixed NSPA bugs — see REGRESSION_TESTS below).  Each must keep
#   passing across builds/releases; exit 77 = SKIP (environment cannot
#   exercise the path).
#
# Usage: ./run-rt-suite.sh [layer]
#   layer = "native" | "wine" | "regression" | "all"  (default: all)
#
# Default behavior:
#   - runs Layer 1 native + Layer 2 PE
#   - cleans up its own Wine processes + wineserver after the suite
#     (CLEANUP_AFTER=0 to disable)
#   - archives logs to wine/nspa/docs/logs/v<N>-<timestamp>/
#     (NO_ARCHIVE=1 to disable)
#   - auto-compares against the most recent prior archive
#     (NO_COMPARE=1 to disable)
#
# Optional observability (opt-in, requires sudo for bpftrace/perf):
#   WITH_BPF_RPC=1       run bpf-rpc-counts.sh in background during Layer 2
#   WITH_BPF_GAMMA=1     run bpf-gamma.sh in background during Layer 2
#   WITH_BPF_WS=1        run bpf-wineserver.sh in background during Layer 2
#   WITH_PERF=1          capture perf-wineserver during Layer 2 (sudo)
#
#   OBS_OUT_DIR          base dir for observability captures
#                        (default: /tmp/nspa-obs-<timestamp>)
#
# Opt-in heavy tests (default: off — this is a validation suite):
#   WITH_NATIVE_STRESS=1       enable concurrency hammer tests in Layer 1
#                              (test-channel-stress, test-event-set-pi-stress,
#                              test-mixed-load-stress, test-mutex-pi-stress).
#                              These are KASAN-bug repros, NOT validation.
#   WITH_BENCH=1               enable CPU-bound PE benchmarks (srw-bench,
#                              seqlock-bound).  Set via the PE runner env;
#                              passed through to run_rt_tests.sh.
#
# Tunables (only meaningful when stress is on):
#   NATIVE_STRESS_DURATION     per-test seconds for the *-stress family
#                              (default 3; raise to 30+ for soak runs)
#   LAYER_COOLDOWN_SECS        sleep between Layer 1 + Layer 2 (default 0;
#                              set to 5+ if stress was on, to let kernel
#                              drain before PE tests begin)
#
# Log retention:
#   KEEP_LAST_LOGS             keep last N timestamped archives in
#                              ARCHIVE_BASE (default 20).  Set to 0 to
#                              keep everything.  Untimestamped historical
#                              archives (v4, v5, v6, v6-full, v7-today,
#                              v9-validation-default) are always preserved.
#
# Install layout (auto-detected from $0 path):
#   - source tree:  archives -> wine/nspa/docs/logs/v<N>-<ts>/
#   - installed   : archives -> $XDG_CACHE_HOME/wine-nspa/logs/v<N>-<ts>/
#                   builds   -> $XDG_CACHE_HOME/wine-nspa/build/

set -u
# Resolve symlinks so $HERE always points to the actual script location,
# not /usr/bin when invoked via the wine-nspa-rt-suite symlink.
SELF="$(readlink -f "$0" 2>/dev/null || echo "$0")"
HERE="$(cd "$(dirname "$SELF")" && pwd)"
LAYER="${1:-all}"

# ─── runtime location detection ───────────────────────────────────────
#
# Two install modes:
#   1. Source tree (dev)     — $HERE = .../wine/nspa/tests
#                              archives -> wine/nspa/docs/logs/v<N>/
#                              builds   -> in-source-tree
#   2. /usr/share install    — $HERE = /usr/share/wine-nspa/tests
#                              archives -> $XDG_CACHE_HOME/wine-nspa/logs/v<N>/
#                              builds   -> $XDG_CACHE_HOME/wine-nspa/build/
#
# Detection: if $HERE/../docs/logs exists + is writable, we're in source
# tree.  Otherwise we're installed system-wide and use the cache dir.
XDG_CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/wine-nspa"
if [[ -d "$HERE/../docs/logs" && -w "$HERE/../docs/logs" ]]; then
    INSTALL_MODE=source
    ARCHIVE_BASE="$HERE/../docs/logs"
    NATIVE_BUILD_DIR="$HERE"          # build natives in-tree (existing behavior)
else
    INSTALL_MODE=installed
    ARCHIVE_BASE="$XDG_CACHE_DIR/logs"
    NATIVE_BUILD_DIR="$XDG_CACHE_DIR/build"
    mkdir -p "$ARCHIVE_BASE" "$NATIVE_BUILD_DIR"
fi

WITH_BPF_RPC=${WITH_BPF_RPC:-0}
WITH_BPF_GAMMA=${WITH_BPF_GAMMA:-0}
WITH_BPF_WS=${WITH_BPF_WS:-0}
WITH_PERF=${WITH_PERF:-0}
OBS_OUT_DIR=${OBS_OUT_DIR:-}

# Default-ON behaviors.  Set to 0 to skip.
CLEANUP_AFTER=${CLEANUP_AFTER:-1}     # wineserver -k + reap stragglers
ARCHIVE_RUN=${ARCHIVE_RUN:-1}         # snapshot logs to ARCHIVE_BASE/<vN>/
COMPARE_RUN=${COMPARE_RUN:-1}         # diff vs most recent prior archive

# Log retention.  By default keep the last KEEP_LAST_LOGS archives;
# older ones are pruned to keep cache size bounded.  Set to 0 to keep
# all archives.  Pruning happens after archive_run + compare_run so
# the just-archived run + the comparator's chosen baseline are safe.
KEEP_LAST_LOGS=${KEEP_LAST_LOGS:-20}

LOG_DIR_DEFAULT=/tmp/nspa_rt_test_logs

CC=${CC:-gcc}
CFLAGS=${CFLAGS:--O2 -Wall -Wextra}
LDFLAGS=${LDFLAGS:--lpthread}

# Native stress tests are OPT-IN.  This is a validation suite by default
# (per user 2026-05-03: "rt test suite isn't intended to be a harsh stress
# test — it's intended to validate, not lockup or cook my CPU").  The
# stress hammers (test-channel-stress, test-event-set-pi-stress,
# test-mixed-load-stress, test-mutex-pi-stress) are concurrency hammers
# that exist for KASAN runs / regression repros, not routine validation.
#
# Set WITH_NATIVE_STRESS=1 to enable them.  NATIVE_STRESS_DURATION (default
# 3s) controls per-test seconds when enabled; raise to 30s+ for soak runs.
WITH_NATIVE_STRESS=${WITH_NATIVE_STRESS:-0}
NATIVE_STRESS_DURATION=${NATIVE_STRESS_DURATION:-3}

# Quick functional + scenario tests (no duration arg).
NATIVE_TESTS=(
    test-event-set-pi
    test-channel-recv-exclusive
    test-aggregate-wait
)

# Concurrency hammers — each takes a [duration_sec] first arg. They emit
# `RESULT: PASS` / `RESULT: FAIL` and rc=0/1 on completion. KASAN splats
# (if any) land in dmesg, not the test stdout — check `journalctl -k`
# after a run if something looks off.
NATIVE_STRESS_TESTS=(
    test-channel-stress
    test-event-set-pi-stress
    test-mixed-load-stress
    test-mutex-pi-stress
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

# PE_RUNNER location:
#   - source tree:   $HERE/../run_rt_tests.sh  (sibling to docs/, tests/)
#   - installed:     $HERE/run_rt_tests.sh     (flattened next to suite driver)
# Try both; first existing wins.  PE_RUNNER env var overrides.
if [[ -n "${PE_RUNNER:-}" ]]; then
    : # honor explicit override
elif [[ -x "$HERE/../run_rt_tests.sh" ]]; then
    PE_RUNNER="$HERE/../run_rt_tests.sh"
elif [[ -x "$HERE/run_rt_tests.sh" ]]; then
    PE_RUNNER="$HERE/run_rt_tests.sh"
else
    PE_RUNNER="$HERE/run_rt_tests.sh"  # will fail in run_wine() with a clear message
fi

red()    { printf '\033[31m%s\033[0m' "$*"; }
green()  { printf '\033[32m%s\033[0m' "$*"; }
yellow() { printf '\033[33m%s\033[0m' "$*"; }
bold()   { printf '\033[1m%s\033[0m' "$*"; }

build_native() {
    local name=$1
    local src="$HERE/$name.c"
    local out="$NATIVE_BUILD_DIR/$name"
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
        if "$NATIVE_BUILD_DIR/$t"; then
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
    if [[ "$WITH_NATIVE_STRESS" == "1" ]]; then
        echo
        echo "$(bold "--- stress tests (opt-in via WITH_NATIVE_STRESS=1, duration=${NATIVE_STRESS_DURATION}s each) ---")"
        for t in "${NATIVE_STRESS_TESTS[@]}"; do
            echo
            echo "--- $t ---"
            build_native "$t"
            case $? in
                1) fail=$((fail+1)); continue ;;
                2) skip=$((skip+1)); continue ;;
            esac
            if "$NATIVE_BUILD_DIR/$t" "$NATIVE_STRESS_DURATION"; then
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
    else
        echo
        echo "  $(yellow "stress tests SKIPPED") (set WITH_NATIVE_STRESS=1 to enable;"
        echo "  hammers ntsync paths under load — concurrency-bug repros, not validation)"
    fi
    echo
    echo "Layer 1 summary: $(green "$pass pass") / $(red "$fail fail") / $(yellow "$skip skip")"
    return $fail
}

obs_pids=()
obs_setup() {
    [[ "$WITH_BPF_RPC$WITH_BPF_GAMMA$WITH_BPF_WS$WITH_PERF" == "0000" ]] && return 0
    if [[ -z "$OBS_OUT_DIR" ]]; then
        OBS_OUT_DIR=/tmp/nspa-obs-$(date +%Y%m%d-%H%M%S)
    fi
    mkdir -p "$OBS_OUT_DIR"
    echo "  $(bold "observability ON"), out=$OBS_OUT_DIR"

    if [[ "$WITH_BPF_RPC" == "1" ]]; then
        echo "  starting bpf-rpc-counts (background)..."
        sudo "$HERE/bpf-rpc-counts.sh" > "$OBS_OUT_DIR/bpf-rpc.log" 2>&1 &
        obs_pids+=($!)
    fi
    if [[ "$WITH_BPF_GAMMA" == "1" ]]; then
        echo "  starting bpf-gamma (background)..."
        sudo "$HERE/bpf-gamma.sh" > "$OBS_OUT_DIR/bpf-gamma.log" 2>&1 &
        obs_pids+=($!)
    fi
    if [[ "$WITH_BPF_WS" == "1" ]]; then
        echo "  starting bpf-wineserver (background)..."
        sudo "$HERE/bpf-wineserver.sh" > "$OBS_OUT_DIR/bpf-wineserver.log" 2>&1 &
        obs_pids+=($!)
    fi
}

obs_teardown() {
    [[ ${#obs_pids[@]} -eq 0 ]] && return 0
    echo
    echo "  stopping observability (SIGINT to ${#obs_pids[@]} probe(s))..."
    for pid in "${obs_pids[@]}"; do
        # SIGINT triggers bpftrace's END block which prints accumulated maps.
        sudo kill -INT "$pid" 2>/dev/null || true
    done
    # Give probes a moment to flush.
    sleep 2
    for pid in "${obs_pids[@]}"; do
        sudo kill -KILL "$pid" 2>/dev/null || true
    done
    obs_pids=()

    # Capture perf snapshot now (synchronous; runs at end so other probes
    # aren't competing).
    if [[ "$WITH_PERF" == "1" ]]; then
        echo "  capturing perf snapshot (10s)..."
        OUT_DIR="$OBS_OUT_DIR/perf" sudo "$HERE/perf-wineserver.sh" -d 10 \
            -o "$OBS_OUT_DIR/perf" \
            > "$OBS_OUT_DIR/perf-driver.log" 2>&1 || \
            echo "  $(yellow WARN): perf-wineserver returned non-zero"
    fi

    echo "  observability captures saved to $OBS_OUT_DIR"
}

run_wine() {
    echo
    echo "$(bold "=== Layer 2: Wine PE nspa_rt_test (delegating to run_rt_tests.sh) ===")"
    if [[ ! -x "$PE_RUNNER" ]]; then
        echo "  $(red FATAL): $PE_RUNNER not found"
        return 1
    fi
    obs_setup
    "$PE_RUNNER"
    local rc=$?
    obs_teardown
    return $rc
}

# ---------------------------------------------------------------------------
# Layer 3: NSPA regression exes.
#
# Standalone mingw-built reproducers for fixed NSPA bugs — regression gates
# that must keep passing across builds/releases (NSPA features have no
# upstream wine tests).  Contract: exit 0 = PASS, 77 = SKIP (environment
# cannot exercise the path — e.g. io_uring absent), anything else = FAIL.
# To add one: drop test-<name>.c/.exe in this directory, list it in
# REGRESSION_TESTS, and add any per-test setup/teardown below.
# ---------------------------------------------------------------------------
REGRESSION_TESTS=(
    "test-send-timeout-dup"     # M1-A/M1-B msg-ring SEND timeout dup delivery (wine 674358cb093)
    "test-uring-sleep-stall"    # U3 io_uring completion stall in non-alertable sleeps
    "test-uring-exit-cancel"    # U2 io_uring thread-exit cancel/complete + fd-leak sentinel
)

regression_setup() {
    case "$1" in
        test-uring-sleep-stall)
            rm -f /tmp/nspa-u3-1.fifo /tmp/nspa-u3-2.fifo
            mkfifo /tmp/nspa-u3-1.fifo /tmp/nspa-u3-2.fifo 2>/dev/null || true
            ;;
        test-uring-exit-cancel)
            rm -f /tmp/nspa-u2-1.fifo
            mkfifo /tmp/nspa-u2-1.fifo 2>/dev/null || true
            ;;
    esac
}

regression_teardown() {
    case "$1" in
        test-uring-sleep-stall)
            rm -f /tmp/nspa-u3-1.fifo /tmp/nspa-u3-2.fifo
            ;;
        test-uring-exit-cancel)
            rm -f /tmp/nspa-u2-1.fifo
            ;;
    esac
}

run_regression() {
    local wine_bin=${WINE:-/usr/bin/wine}
    local prefix=${WINEPREFIX:-/home/ninez/Winebox/winebox-master}
    local log_dir=${LOG_DIR:-$LOG_DIR_DEFAULT}
    local mingw=x86_64-w64-mingw32-gcc
    local fails=0 skips=0 passes=0
    local t

    echo
    echo "$(bold "=== Layer 3: NSPA regression exes ===")"
    mkdir -p "$log_dir"

    for t in "${REGRESSION_TESTS[@]}"; do
        local src="$HERE/$t.c" exe="$HERE/$t.exe" log="$log_dir/regression_$t.log"
        local rc

        # (Re)build when the source is newer than the exe.  Extra import
        # libs are picked up from the test's "Build:" header comment.
        if [[ -f "$src" && ( ! -f "$exe" || "$src" -nt "$exe" ) ]]; then
            if command -v "$mingw" >/dev/null 2>&1; then
                local libs
                libs=$(grep -m1 -oE '(\-l[a-z0-9_]+ ?)+' "$src" | head -1)
                "$mingw" -O2 -o "$exe" "$src" $libs >/dev/null 2>&1 || true
            fi
        fi
        if [[ ! -x "$exe" ]]; then
            printf '  %-28s %s\n' "$t" "$(yellow SKIP) (no exe / no mingw)"
            skips=$((skips + 1)); continue
        fi

        regression_setup "$t"
        WINEPREFIX="$prefix" timeout --kill-after=5 120 "$wine_bin" "$exe" > "$log" 2>&1
        rc=$?
        regression_teardown "$t"

        if [[ $rc -eq 0 ]]; then
            printf '  %-28s %s\n' "$t" "$(green PASS)"
            passes=$((passes + 1))
        elif [[ $rc -eq 77 ]]; then
            printf '  %-28s %s\n' "$t" "$(yellow SKIP) (path unavailable — see $(basename "$log"))"
            skips=$((skips + 1))
        else
            printf '  %-28s %s (rc=%d, see %s)\n' "$t" "$(red FAIL)" "$rc" "$log"
            fails=$((fails + 1))
        fi
    done

    echo "  regression: $passes pass, $skips skip, $fails fail"
    return $fails
}

post_cleanup() {
    [[ "$CLEANUP_AFTER" == "1" ]] || return 0
    echo
    echo "$(bold "=== post-suite cleanup ===")"

    # Step 1: let Wine attempt clean shutdown.  `wineserver -k` sends
    # SIGQUIT to every Wine PE process via the kill_thread chain
    # (server/thread.c:1745).  Fix A (sched.c::sched_run +
    # sched_helpers.c::rt_thread_main) ensures the sched thread receives
    # SIGQUIT and triggers abort_process → _exit() so PE processes exit
    # cleanly with rc=0.  This is the preferred path; force-kill is a
    # fallback for stragglers.
    if pgrep -x wineserver >/dev/null 2>&1 || pgrep -x nspa_rt_test.exe >/dev/null 2>&1; then
        echo "  wineserver -k (graceful shutdown)..."
        wineserver -k 2>/dev/null || true
        # Give the SIGQUIT chain time to land + processes to exit cleanly.
        # 3s is enough for Fix-A-enabled trees; pre-Fix-A trees never
        # exit anyway and step 3 reaps them.
        sleep 3
    fi

    # Step 2: report what survived clean shutdown.  If Fix A is in place,
    # this should be empty.  If not, this is the canary that the
    # sched-shutdown bug is biting (memory:
    # project_sched_thread_no_shutdown_20260503).
    #
    # NOTE on `pgrep -cx`: it exits 1 when the count is 0, AND prints "0"
    # to stdout.  The `|| echo 0` fallback would then double-print the
    # zero, giving us "0\n0" instead of "0".  Use `|| true` instead so we
    # keep pgrep's own count output regardless of exit status.
    local pe_alive ws_alive sched_alive
    pe_alive=$(pgrep -cx nspa_rt_test.exe 2>/dev/null || true)
    ws_alive=$(pgrep -cx wineserver 2>/dev/null || true)
    sched_alive=$(ls /proc/*/comm 2>/dev/null | xargs grep -lE '^wine-sched(-rt)?$' 2>/dev/null | wc -l)
    : "${pe_alive:=0}"
    : "${ws_alive:=0}"

    if [[ "$pe_alive" == "0" && "$ws_alive" == "0" && "$sched_alive" == "0" ]]; then
        echo "  $(green "clean") — all Wine processes exited via SIGQUIT chain"
        return 0
    fi

    # Step 3: force-kill survivors.  Order: PE processes first (they're
    # the ones doing actual work), then wineserver, then any orphaned
    # sched threads.
    echo "  survivors after graceful shutdown:"
    [[ "$pe_alive" != "0"    ]] && echo "    nspa_rt_test.exe : $pe_alive"
    [[ "$ws_alive" != "0"    ]] && echo "    wineserver       : $ws_alive"
    [[ "$sched_alive" != "0" ]] && echo "    wine-sched       : $sched_alive (sched-shutdown bug)"

    if [[ "$pe_alive" != "0" ]]; then
        pkill -TERM -x nspa_rt_test.exe 2>/dev/null || true
        sleep 1
        pkill -KILL -x nspa_rt_test.exe 2>/dev/null || true
    fi
    if [[ "$ws_alive" != "0" ]]; then
        pkill -KILL -x wineserver 2>/dev/null || true
        sleep 1
    fi
    # Match by /proc/*/comm — pgrep -f wine-sched is a self-match trap
    # (any shell command containing "wine-sched" in its cmdline matches).
    local pids
    pids=$(ls /proc/*/comm 2>/dev/null | xargs grep -lE '^wine-sched(-rt)?$' 2>/dev/null | sed 's|^/proc/||;s|/comm$||' | tr '\n' ' ')
    if [[ -n "$pids" ]]; then
        for pid in $pids; do
            kill -KILL "$pid" 2>/dev/null || true
        done
        sleep 1
    fi

    # Final check.
    pe_alive=$(pgrep -cx nspa_rt_test.exe 2>/dev/null || true)
    ws_alive=$(pgrep -cx wineserver 2>/dev/null || true)
    sched_alive=$(ls /proc/*/comm 2>/dev/null | xargs grep -lE '^wine-sched(-rt)?$' 2>/dev/null | wc -l)
    : "${pe_alive:=0}"
    : "${ws_alive:=0}"
    if [[ "$pe_alive" == "0" && "$ws_alive" == "0" && "$sched_alive" == "0" ]]; then
        echo "  cleanup done"
    else
        echo "  $(red "WARN") — survivors after force-kill: pe=$pe_alive ws=$ws_alive sched=$sched_alive"
    fi
}

cooldown() {
    [[ "${LAYER_COOLDOWN_SECS:-0}" -gt 0 ]] || return 0
    echo
    echo "  cooldown ${LAYER_COOLDOWN_SECS}s (kernel/userland drain after Layer 1)"
    sleep "$LAYER_COOLDOWN_SECS"
}

# Archive log dir to docs/logs/v<N>-<timestamp>/.  Returns the archive
# path on stdout (empty if archive disabled or no logs to archive).
archive_run() {
    [[ "$ARCHIVE_RUN" == "1" ]] || return 0
    local log_dir=${LOG_DIR:-$LOG_DIR_DEFAULT}
    if ! ls "$log_dir"/baseline_*.log >/dev/null 2>&1; then
        echo "  $(yellow "no PE logs to archive at $log_dir")" >&2
        return 0
    fi

    # Find the next v<N> tag.  Existing archives have names like v4, v5,
    # v6, v6-full, v7-today, v8-today, v9-validation-default.  Bump the
    # numeric prefix, append a stable date suffix.
    local max_n=0
    for d in "$ARCHIVE_BASE"/v[0-9]* "$ARCHIVE_BASE"/v[0-9][0-9]*; do
        [[ -d "$d" ]] || continue
        local n=${d##*/v}
        n=${n%%[!0-9]*}
        [[ -n "$n" ]] || continue
        (( n > max_n )) && max_n=$n
    done
    local next_n=$((max_n + 1))
    local stamp
    stamp=$(date +%Y%m%d-%H%M%S)
    local dest="$ARCHIVE_BASE/v${next_n}-${stamp}"

    mkdir -p "$dest"
    cp "$log_dir"/*.log "$dest/" 2>/dev/null
    echo "  archived to: $dest" >&2
    printf '%s' "$dest"
}

# Compare just-archived run against the most recent prior archive.
# Skips silently if no prior archive exists or the comparator is missing.
compare_run() {
    local current=$1
    [[ -n "$current" && -d "$current" ]] || return 0
    [[ "$COMPARE_RUN" == "1" ]] || return 0
    local cmp="$HERE/compare-rt-suite.sh"
    [[ -x "$cmp" ]] || { echo "  $(yellow "compare-rt-suite.sh missing")"; return 0; }

    # Find the most recent prior archive (lexicographically — timestamps
    # sort right with YYYYMMDD-HHMMSS).  Exclude the current one.
    local prev=""
    local current_base
    current_base=$(basename "$current")
    while read -r d; do
        [[ "$(basename "$d")" == "$current_base" ]] && continue
        prev=$d
    done < <(ls -d "$ARCHIVE_BASE"/v[0-9]* "$ARCHIVE_BASE"/v[0-9][0-9]* 2>/dev/null | sort)
    if [[ -z "$prev" ]]; then
        echo "  $(yellow "no prior archive to compare against")"
        return 0
    fi

    echo
    echo "$(bold "=== auto-compare ===")"
    echo "  baseline: $(basename "$prev")"
    echo "  current : $(basename "$current")"
    echo
    "$cmp" "$prev" "$current" || true
}

archive_path=""
prune_old_archives() {
    [[ "$KEEP_LAST_LOGS" -gt 0 ]] || return 0
    [[ -d "$ARCHIVE_BASE" ]] || return 0
    # List vN-* archives sorted by name (timestamps make this stable),
    # newest first, drop the first KEEP_LAST_LOGS, rm the rest.  Old
    # historical archives without a timestamp suffix (v4, v5, v6,
    # v6-full, v7-today) are preserved unless KEEP_LAST_LOGS itself
    # is small enough to encompass them.
    local victims
    victims=$(ls -d "$ARCHIVE_BASE"/v[0-9]*-[0-9]*/ 2>/dev/null | sort -r | tail -n +$((KEEP_LAST_LOGS + 1)))
    if [[ -n "$victims" ]]; then
        local count
        count=$(wc -l <<< "$victims")
        echo "  pruning $count old archive(s) (keeping last $KEEP_LAST_LOGS)"
        while IFS= read -r d; do
            [[ -n "$d" && -d "$d" ]] || continue
            rm -rf "$d"
        done <<< "$victims"
    fi
}

render_report() {
    local current=$1
    local baseline=${2:-}
    local rep="$HERE/report-rt-suite.sh"
    [[ -x "$rep" ]] || return 0
    [[ -n "$current" && -d "$current" ]] || return 0
    echo
    "$rep" "$current" "$baseline" || true
}

post_run() {
    post_cleanup
    archive_path=$(archive_run)
    if [[ -n "$archive_path" ]]; then
        # Render the full stats + deltas tables (replaces the terse
        # compare_run output, which was only a regression-checker).
        # Find prior archive same way compare_run did.
        local prev=""
        local current_base
        current_base=$(basename "$archive_path")
        while read -r d; do
            [[ "$(basename "$d")" == "$current_base" ]] && continue
            prev=$d
        done < <(ls -d "$ARCHIVE_BASE"/v[0-9]* "$ARCHIVE_BASE"/v[0-9][0-9]* 2>/dev/null | sort)
        render_report "$archive_path" "$prev"
    fi
    prune_old_archives
}

case "$LAYER" in
    native)
        run_native
        post_run ;;
    wine)
        run_wine
        run_regression || true
        post_run ;;
    regression)
        run_regression
        post_run ;;
    all)
        run_native || true
        cooldown   # no-op unless LAYER_COOLDOWN_SECS=N (e.g. after stress)
        run_wine
        run_regression || true
        post_run ;;
    *)
        echo "usage: $0 [native|wine|regression|all]" >&2
        exit 2
        ;;
esac
