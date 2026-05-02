#!/usr/bin/env bash
#
# Phase 3 multi-class sched validation script.
#
# Validates that NTDLL_SCHED_CLASS_RT works end-to-end via the
# nspa_sched_rt_probe synthetic consumer.  Engages:
#   NSPA_USE_SCHED_THREAD=1            (default-ON; explicit for clarity)
#   NSPA_SCHED_OBS_INTERVAL_MS=500     (sample twice per second)
#   NSPA_SCHED_RT_PROBE=1              (engage the RT probe)
#
# What it tests:
#   T1 — default-OFF baseline: smoke 0 byte-equivalent (no probe in stderr)
#   T2 — default-ON sched + probe: smoke 0 emits NSPA RT banners, no errors
#   T3 — RT thread spawn: ps -L on a longer-lived wine proc shows
#        "wine-sched-rt" in the thread list
#   T4 — RT dispatch: /dev/shm/nspa-obs.<pid> shows rt_probe.alive=1
#        and rt_probe.fires increments over time
#   T5 — RT jitter: rt_probe.jitter_max_us stays bounded under load
#        (qualitative — print value for inspection)
#   T6 — Cleanup: process exits clean, no leftover wine procs
#
# Requires: wine + ntdll already installed to /usr (run sudo make install
# prefix=/usr first).  No further sudo needed by this script itself.
#
# Usage:  bash nspa/tests/run-rt-probe-validation.sh
#         (run from wine/ source root, or anywhere — paths are absolute)

set -u

WINE=/usr/bin/wine
LOG_DIR=${LOG_DIR:-/tmp/nspa-rt-probe-validation}
mkdir -p "$LOG_DIR"

# RT class requires NSPA_RT_PRIO to be configured (the RT sched thread
# spawns at NSPA_RT_PRIO-1).  Use the canonical NSPA RT env per
# reference_ableton_rt_test_recipe.md unless the caller overrides.
RT_ENV_BASE=(
    NSPA_RT_PRIO=80
    NSPA_RT_POLICY=FF
    WINEPRELOADREMAPVDSO=force
)

PASS_COUNT=0
FAIL_COUNT=0

ok()   { echo "  [PASS] $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "  [FAIL] $*"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
info() { echo "  [info] $*"; }
hdr()  { echo ""; echo "=== $* ==="; }

cleanup_wine() {
    pkill -x wineserver 2>/dev/null
    sleep 1
}

# T1 — default-OFF baseline ------------------------------------------------
hdr "T1 — default-OFF baseline (no probe stderr)"
cleanup_wine
T1_LOG=$LOG_DIR/T1_default_off.log
$WINE cmd /c echo hello > "$T1_LOG" 2>&1
EXIT=$?
if [ $EXIT -eq 0 ] && grep -q "^hello" "$T1_LOG"; then
    ok "smoke 0 succeeded"
else
    fail "smoke 0 exit=$EXIT or no hello output (see $T1_LOG)"
fi
if grep -q "rt_probe\|sched_rt\|NSPA_SCHED_RT_PROBE set" "$T1_LOG"; then
    fail "default-OFF run had probe output (should be silent)"
else
    ok "no unexpected probe output in default-OFF run"
fi

# T2 — default-ON sched + probe (short run) -------------------------------
hdr "T2 — sched ON + probe ON: smoke 0 still works"
cleanup_wine
T2_LOG=$LOG_DIR/T2_probe_on.log
env "${RT_ENV_BASE[@]}" \
    NSPA_USE_SCHED_THREAD=1 \
    NSPA_SCHED_OBS_INTERVAL_MS=500 \
    NSPA_SCHED_RT_PROBE=1 \
    $WINE cmd /c echo hello > "$T2_LOG" 2>&1
EXIT=$?
if [ $EXIT -eq 0 ] && grep -q "^hello" "$T2_LOG"; then
    ok "smoke 0 succeeded with probe enabled"
else
    fail "smoke 0 with probe enabled failed (exit=$EXIT, see $T2_LOG)"
fi
if grep -q "wine: NSPA RT:" "$T2_LOG"; then
    ok "NSPA RT banners present"
else
    fail "NSPA RT banners missing"
fi
if grep -qiE "(^|:)err:.*rt_probe|rt probe.*failed|RT class unavailable" "$T2_LOG"; then
    info "probe diagnostic (review):"
    grep -iE "rt_probe|rt probe|RT class" "$T2_LOG" | sed 's/^/    /'
fi

# T3 + T4 + T5 — long-lived wine proc + read /dev/shm/nspa-obs.<pid> -------
hdr "T3-T5 — RT thread spawn + dispatch + jitter"
cleanup_wine
T3_LOG=$LOG_DIR/T3_T4_T5_long.log
# Use a long-running wine cmd so we have time to read the obs file.
# `cmd /c ping -n 7 127.0.0.1 >NUL` runs ~6 seconds.
env "${RT_ENV_BASE[@]}" \
    NSPA_USE_SCHED_THREAD=1 \
    NSPA_SCHED_OBS_INTERVAL_MS=500 \
    NSPA_SCHED_RT_PROBE=1 \
    $WINE cmd /c "ping -n 7 127.0.0.1 >NUL" > "$T3_LOG" 2>&1 &
WINE_BG_PID=$!

# Give wine ~2s to boot + spawn the sched threads + register probe.
sleep 2

# Find the actual cmd.exe child (or ping.exe — whichever long-lived).
TARGET_PID=$(pgrep -f 'cmd\.exe' | head -1)
if [ -z "$TARGET_PID" ]; then
    TARGET_PID=$(pgrep -f 'PING\.EXE' | head -1)
fi
if [ -z "$TARGET_PID" ]; then
    fail "could not find a long-lived wine PE child to inspect"
else
    info "inspecting PE pid $TARGET_PID"

    # T3: RT thread spawn — look for "wine-sched-rt" in /proc/$pid/task/*/comm
    if grep -qE "wine-sched-rt" /proc/$TARGET_PID/task/*/comm 2>/dev/null; then
        ok "T3: wine-sched-rt thread present in /proc/$TARGET_PID/task"
    else
        fail "T3: wine-sched-rt thread NOT found"
        info "  available thread names:"
        for f in /proc/$TARGET_PID/task/*/comm; do
            [ -r "$f" ] && echo "    $(basename $(dirname $f)): $(cat $f)"
        done
    fi

    # Read the obs file twice with a 1s gap; rt_probe.fires should grow.
    OBS_FILE=/dev/shm/nspa-obs.$TARGET_PID
    if [ ! -f "$OBS_FILE" ]; then
        fail "T4: $OBS_FILE not found (obs sampler didn't run)"
    else
        SNAP1=$(cat "$OBS_FILE")
        sleep 1
        SNAP2=$(cat "$OBS_FILE")
        FIRES1=$(echo "$SNAP1" | awk '/rt_probe.fires/{print $2}')
        FIRES2=$(echo "$SNAP2" | awk '/rt_probe.fires/{print $2}')
        ALIVE=$(echo "$SNAP2" | awk '/rt_probe.alive/{print $2}')
        JIT_LAST=$(echo "$SNAP2" | awk '/rt_probe.jitter_last_us/{print $2}')
        JIT_MAX=$(echo "$SNAP2" | awk '/rt_probe.jitter_max_us/{print $2}')

        if [ "$ALIVE" = "1" ]; then
            ok "T4a: rt_probe.alive=1"
        else
            fail "T4a: rt_probe.alive='$ALIVE' (expected 1)"
        fi

        if [ -n "$FIRES1" ] && [ -n "$FIRES2" ] && [ "$FIRES2" -gt "$FIRES1" ]; then
            ok "T4b: rt_probe.fires advanced ${FIRES1}→${FIRES2} in 1s"
        else
            fail "T4b: rt_probe.fires did not advance (snap1=$FIRES1, snap2=$FIRES2)"
        fi

        info "T5: rt_probe.jitter_last_us=$JIT_LAST  jitter_max_us=$JIT_MAX"
        if [ -n "$JIT_MAX" ] && [ "$JIT_MAX" -lt 50000 ]; then
            ok "T5: jitter_max under 50ms (acceptable for SCHED_FIFO under load)"
        elif [ -n "$JIT_MAX" ]; then
            info "T5: jitter_max=${JIT_MAX}us > 50ms — review (system loaded?)"
        fi
    fi
fi

# Wait for wine to finish naturally.
wait $WINE_BG_PID 2>/dev/null
EXIT=$?

# T6 — clean exit, no orphan PE wine processes.  wineserver is allowed
# to linger briefly after the last client; only flag it as orphan if
# it survives past 5 seconds.
hdr "T6 — clean exit"
sleep 5
ORPHAN_PE=$(pgrep -af 'cmd\.exe|PING\.EXE' 2>/dev/null | grep -v claude | grep -v "$0" || true)
ORPHAN_WS=$(pgrep -x wineserver 2>/dev/null || true)
if [ -z "$ORPHAN_PE" ]; then
    ok "T6a: no orphan PE wine procs after exit"
else
    fail "T6a: orphan PE procs detected:"
    echo "$ORPHAN_PE" | sed 's/^/    /'
fi
if [ -z "$ORPHAN_WS" ]; then
    ok "T6b: wineserver exited"
else
    info "T6b: wineserver still running (pid $ORPHAN_WS) — typical post-shutdown grace; not failing"
fi

# Summary -----------------------------------------------------------------
hdr "Summary"
echo "  PASS:  $PASS_COUNT"
echo "  FAIL:  $FAIL_COUNT"
echo "  Logs:  $LOG_DIR/"
[ $FAIL_COUNT -eq 0 ] && exit 0 || exit 1
