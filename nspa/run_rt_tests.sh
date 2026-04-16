#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# nspa/run_rt_tests.sh — Wine-NSPA RT test harness runner
#
# Runs every nspa_rt_test subcommand twice (baseline + rt mode), captures
# per-run logs to $LOG_DIR, parses the test binary's PASS/FAIL verdict
# line, and prints a summary matrix. Exits 0 only if every run passed.
#
# This is a thin driver around the in-tree nspa_rt_test.exe. All the real
# test logic lives inside the PE binary (programs/nspa_rt_test/main.c);
# this script just orchestrates runs, captures output, and summarizes.
#
# Environment overrides (all optional):
#   WINE           Wine binary (default: /usr/bin/wine)
#   WINEPREFIX     Wine prefix (default: /home/ninez/Winebox/winebox-master)
#   TEST_EXE       Path to nspa_rt_test.exe (default: nspa_rt_test.exe, found via PATH)
#   LOG_DIR        Where to write per-run logs (default: /tmp/nspa_rt_test_logs)
#   TIMEOUT_SECS   Per-test timeout in seconds (default: 120)
#   RT_PRIO        NSPA_RT_PRIO for rt mode (default: 80)
#   RT_POLICY      NSPA_RT_POLICY for rt mode (default: FF)
#   INCLUDE_PRIORITY    Set to 1 to include the `priority` subcommand
#                       (skipped by default because it sleeps 10 s for
#                       external ps/chrt observation)
#
# Usage:
#   nspa/run_rt_tests.sh                    # full matrix, default settings
#   TIMEOUT_SECS=60 nspa/run_rt_tests.sh    # tighter per-test timeout
#   INCLUDE_PRIORITY=1 nspa/run_rt_tests.sh # also run priority subcommand
#
# Exit codes:
#   0    all runs PASS
#   1    at least one run FAIL, TIMEOUT, or UNKNOWN
#   2    prerequisites missing (test binary not built, etc.)

set -u

# ─── configuration ───────────────────────────────────────────────────────

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
WINE=${WINE:-/usr/bin/wine}
WINEPREFIX=${WINEPREFIX:-/home/ninez/Winebox/winebox-master}
export WINEPREFIX
TEST_EXE=${TEST_EXE:-nspa_rt_test.exe}
LOG_DIR=${LOG_DIR:-/tmp/nspa_rt_test_logs}
TIMEOUT_SECS=${TIMEOUT_SECS:-120}
RT_PRIO=${RT_PRIO:-80}
RT_POLICY=${RT_POLICY:-FF}
INCLUDE_PRIORITY=${INCLUDE_PRIORITY:-0}

# Test list. Each line is: "name arg1 arg2 ..." — args passed verbatim
# to the subcommand. Add new tests here as they're implemented.
# Format: "display_name subcmd [args...]"
# display_name is used for log filenames and summary; subcmd is passed to wine.
tests=(
    "rapidmutex rapidmutex 4 500000"
    "philosophers philosophers 50 4"
    "fork-mutex fork-mutex 100"
    "cs-contention cs-contention"
    "signal-recursion signal-recursion 4 500"
    "large-pages large-pages"
    # ntsync scaling: subcmd chain_depth rapid_threads rapid_iters pi_iters prio_waiters
    "ntsync-d4 ntsync 4 4 100000 8 5"
    "ntsync-d8 ntsync 8 4 100000 3 10"
    "ntsync-d12 ntsync 12 8 50000 3 16"
    "socket-io socket-io"
    "condvar-pi condvar-pi"
)
if [[ "$INCLUDE_PRIORITY" == "1" ]]; then
    tests+=("priority")
fi

# ─── helpers ─────────────────────────────────────────────────────────────

BANNER_W=72
banner() {
    local title=$1
    printf '\n'
    printf '=%.0s' $(seq 1 $BANNER_W); printf '\n'
    printf '  %s\n' "$title"
    printf '=%.0s' $(seq 1 $BANNER_W); printf '\n'
}

section() {
    printf '\n-- %s --\n' "$1"
}

# Kill any lingering nspa_rt_test.exe processes. Uses the bracket trick
# to avoid self-matching (pgrep pattern containing its own text) — see
# memory/feedback_pkill_self_match.md and feedback_cleanup_stale_procs_specifically.md.
# Matches `nspa_rt_test.exe` at end of cmdline (.exe$ suffix).
cleanup_stale() {
    if pgrep -f '[n]spa_rt_test\.exe$' >/dev/null 2>&1; then
        printf '  [cleanup] killing stale nspa_rt_test processes\n'
        pkill -f '[n]spa_rt_test\.exe$' 2>/dev/null || true
        sleep 1
        # Second pass in case pkill missed some
        pkill -9 -f '[n]spa_rt_test\.exe$' 2>/dev/null || true
        sleep 1
    fi
}

# Run a single test in a given mode. Writes log to $LOG_DIR/${mode}_${name}.log.
# Echoes a one-line status, appends "${mode}:${name}=${verdict}" to the
# global `results` array.
results=()
run_one() {
    local mode=$1
    local display_name=$2
    local subcmd=$3
    shift 3
    local args=("$@")
    local name="$display_name"

    local log_file="$LOG_DIR/${mode}_${name}.log"
    local env_extra=()
    if [[ "$mode" == "rt" ]]; then
        env_extra=("NSPA_RT_PRIO=$RT_PRIO" "NSPA_RT_POLICY=$RT_POLICY" "WINEPRELOADREMAPVDSO=force")
    fi

    printf '  %-16s  ' "$name"

    # Build the env + timeout command. `env VAR=val ...` is the clean way
    # to pass env vars without polluting the current shell's environment.
    # --kill-after=5 ensures we SIGKILL if SIGTERM isn't honored.
    timeout --kill-after=5 "$TIMEOUT_SECS" \
        env WINEDEBUG=-all WINEPREFIX="$WINEPREFIX" "${env_extra[@]}" \
        "$WINE" "$TEST_EXE" "$subcmd" "${args[@]}" \
        > "$log_file" 2>&1
    local rc=$?

    local verdict
    # Verdict resolution priority:
    #   1. timeout exit code (124 / 128+SIGKILL) -> TIMEOUT
    #   2. explicit PASS line in output          -> PASS
    #   3. explicit FAIL line in output          -> FAIL
    #   4. fall back to rc (for tests that don't emit a verdict line,
    #      like cs-contention and priority): rc=0 -> PASS*, else -> FAIL*
    # The `*` marker distinguishes implicit verdicts from explicit ones.
    #
    # NOTE: nspa_rt_test.exe is a PE console program so its stdout uses
    # CRLF line endings. We match PASS with trailing whitespace to tolerate
    # the \r. The FAIL pattern isn't end-anchored, so it already tolerates.
    if [[ $rc -eq 124 || $rc -eq 137 ]]; then
        verdict="TIMEOUT"
    elif grep -q '^  PASS[[:space:]]*$' "$log_file"; then
        verdict="PASS"
    elif grep -q '^  FAIL' "$log_file"; then
        verdict="FAIL"
    elif [[ $rc -eq 0 ]]; then
        verdict="PASS*"
    else
        verdict="FAIL* (rc=$rc)"
    fi

    printf '%s\n' "$verdict"
    results+=("${mode}:${name}=${verdict}")

    # Clean up any leftover children between tests so the next run starts
    # from a clean process state.
    cleanup_stale
}

# Look up a verdict from the results array.
verdict_for() {
    local key="$1"
    local entry
    for entry in "${results[@]}"; do
        if [[ "$entry" == "${key}="* ]]; then
            printf '%s' "${entry#*=}"
            return
        fi
    done
    printf '?'
}

# ─── preflight ───────────────────────────────────────────────────────────

banner "NSPA RT test harness runner"

printf '  wine        : %s\n' "$WINE"
printf '  prefix      : %s\n' "$WINEPREFIX"
printf '  test exe    : %s\n' "$TEST_EXE"
printf '  log dir     : %s\n' "$LOG_DIR"
printf '  timeout     : %s s / test\n' "$TIMEOUT_SECS"
printf '  rt mode     : NSPA_RT_PRIO=%s NSPA_RT_POLICY=%s\n' "$RT_PRIO" "$RT_POLICY"
printf '  tests       : %s\n' "${#tests[@]}"

if [[ ! -x "$WINE" ]]; then
    printf '\nERROR: wine not found or not executable: %s\n' "$WINE" >&2
    exit 2
fi

# Resolve TEST_EXE: PE binaries live in Wine's own search path
# (/usr/lib/wine/{arch}-windows/), not in the Linux PATH. If the
# given path doesn't exist as a regular file, search Wine's lib dirs.
if [[ ! -f "$TEST_EXE" ]]; then
    found=""
    for d in /usr/lib/wine/x86_64-windows /usr/lib/wine/i386-windows; do
        if [[ -f "$d/$TEST_EXE" ]]; then
            found="$d/$TEST_EXE"
            break
        fi
    done
    if [[ -n "$found" ]]; then
        TEST_EXE="$found"
    else
        printf '\nERROR: test binary not found: %s\n' "$TEST_EXE" >&2
        printf 'Ensure nspa_rt_test.exe is installed or provide TEST_EXE=/path/to/it\n' >&2
        exit 2
    fi
fi

mkdir -p "$LOG_DIR"

section "preflight cleanup"
cleanup_stale
printf '  done\n'

# ─── run matrix ──────────────────────────────────────────────────────────

for mode in baseline rt; do
    section "mode: $mode"
    for test_line in "${tests[@]}"; do
        # shellcheck disable=SC2206  # intentional word splitting for args
        parts=($test_line)
        display_name="${parts[0]}"
        subcmd="${parts[1]}"
        args=("${parts[@]:2}")
        run_one "$mode" "$display_name" "$subcmd" "${args[@]}"
    done
done

# ─── summary ─────────────────────────────────────────────────────────────

section "summary"
printf '  %-16s  %-14s  %-14s\n' "test" "baseline" "rt"
printf '  %-16s  %-14s  %-14s\n' "----" "--------" "--"

pass=0
fail=0
timeout_count=0
unknown=0
has_implicit=0
for test_line in "${tests[@]}"; do
    parts=($test_line)
    name="${parts[0]}"
    bl=$(verdict_for "baseline:$name")
    rt=$(verdict_for "rt:$name")
    printf '  %-16s  %-14s  %-14s\n' "$name" "$bl" "$rt"
    for v in "$bl" "$rt"; do
        case "$v" in
            PASS)          ((pass++)) ;;
            'PASS*')       ((pass++)); has_implicit=1 ;;
            FAIL)          ((fail++)) ;;
            'FAIL*'*)      ((fail++)); has_implicit=1 ;;
            TIMEOUT)       ((timeout_count++)) ;;
            *)             ((unknown++)) ;;
        esac
    done
done
if [[ $has_implicit -eq 1 ]]; then
    printf '\n  * = implicit verdict from exit code (test did not emit PASS/FAIL line)\n'
fi

section "totals"
printf '  total PASS    : %d\n' "$pass"
printf '  total FAIL    : %d\n' "$fail"
printf '  total TIMEOUT : %d\n' "$timeout_count"
printf '  total UNKNOWN : %d\n' "$unknown"
printf '\n'
printf '  logs in       : %s\n' "$LOG_DIR"

if [[ $fail -gt 0 || $timeout_count -gt 0 || $unknown -gt 0 ]]; then
    printf '  verdict       : FAIL\n\n'
    exit 1
fi
printf '  verdict       : PASS\n\n'
exit 0
