#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# bpf-rpc-counts.sh — count wineserver RPCs by handler name.
#
# Attaches a uprobe to every `req_*` symbol in wineserver and bins by
# probe name.  Each handler in the wineserver corresponds to one
# request type (per server/request.h:33-34 DECL_HANDLER macro:
# "void req_##name(...)"), so the bin name = the RPC type.
#
# Useful for:
#   - "what RPCs is Ableton actually making?"
#   - "did Phase X change the RPC mix?"
#   - "is the empty-poll bucket really 96%?" (compare get_message
#     vs every other request)
#
# Requires: bpftrace, root (sudo).
#
# Usage:
#   sudo ./bpf-rpc-counts.sh                    # forever, ctrl-c to print
#   sudo ./bpf-rpc-counts.sh -d 30             # 30s window then print
#   sudo ./bpf-rpc-counts.sh -d 30 -p 12345    # filter to one PID
#   sudo WINESERVER=/path/to/wineserver ./bpf-rpc-counts.sh
#
# Output: histogram of req_<name> -> count, sorted highest first.

set -u

WINESERVER=${WINESERVER:-/usr/bin/wineserver}
DURATION=${DURATION:-0}
TARGET_PID=${TARGET_PID:-0}

while getopts "d:hp:w:" opt; do
    case "$opt" in
        d) DURATION=$OPTARG ;;
        p) TARGET_PID=$OPTARG ;;
        w) WINESERVER=$OPTARG ;;
        h|*)
            cat <<EOF
usage: sudo $(basename "$0") [-d SECONDS] [-p PID] [-w /path/to/wineserver]

  -d N    run for N seconds, then print + exit (default: forever)
  -p PID  filter to one PID (default: all wineservers)
  -w P    wineserver binary path (default: /usr/bin/wineserver)

Counts wineserver RPCs by handler name (req_*) via uprobes.  The bin
name is the request name (req_get_message, req_close_handle, etc.) —
maps 1:1 with REQ_* enum in include/wine/server_protocol.h.
EOF
            exit 2 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo) for bpftrace uprobes" >&2
    exit 2
fi
if ! command -v bpftrace >/dev/null 2>&1; then
    echo "ERROR: bpftrace not installed" >&2
    exit 2
fi
if [[ ! -x "$WINESERVER" ]]; then
    echo "ERROR: wineserver not found or not executable: $WINESERVER" >&2
    exit 2
fi

# Build PID filter clause.
PID_FILTER=""
if [[ "$TARGET_PID" -gt 0 ]]; then
    PID_FILTER="/ pid == $TARGET_PID /"
fi

# Use wildcard uprobe — matches every req_* symbol in wineserver.
# bpftrace's `probe` builtin gives us the symbol name we hit, which
# is exactly "uprobe:/usr/bin/wineserver:req_<name>".
PROG='
uprobe:'"$WINESERVER"':req_*
'"$PID_FILTER"'
{
    @counts[probe] = count();
    @total = count();
}

interval:s:5
{
    printf("[5s tick: %d req] ", @total);
    print(@counts, 5);
    clear(@counts);
    clear(@total);
}

END
{
    printf("\n=== final counts ===\n");
    print(@counts);
    printf("total: ");
    print(@total);
}
'

if [[ "$DURATION" -gt 0 ]]; then
    echo "[bpf-rpc-counts] running for ${DURATION}s${TARGET_PID:+ on PID $TARGET_PID}..."
    timeout "$DURATION" bpftrace -e "$PROG" || true
else
    echo "[bpf-rpc-counts] running until ctrl-c${TARGET_PID:+ (PID $TARGET_PID)}..."
    bpftrace -e "$PROG"
fi
