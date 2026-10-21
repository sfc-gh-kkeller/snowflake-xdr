#!/usr/bin/env bash
# ============================================================================
# Snowflake XDR - reset the demo clock before a demo
# ============================================================================
# Moves all demo timestamps forward so the newest telemetry is "now", emits a
# few fresh live-tail events, and rebuilds the attack graph over the shifted
# window. Takes about a minute; safe to run as often as you like.
#
# Usage: scripts/reset_demo_clock.sh [--connection NAME]   (default aws_demo_kevin)
# ============================================================================

set -euo pipefail

CONN="aws_demo_kevin"
[[ "${1:-}" == "--connection" ]] && CONN="${2:?--connection needs a name}"
SNOW="${SNOW:-snow}"

run() {
    echo "-> $1"
    "$SNOW" sql -q "USE WAREHOUSE XDR_WH; CALL $1" -c "$CONN" --enable-templating NONE \
        | grep -E '^\| [A-Za-z]' | tail -1
}

run "SNOWFLAKE_XDR.REFERENCE.SHIFT_DEMO_TIME()"
run "SNOWFLAKE_XDR.RAW_LOGS.EMIT_LIVE_EVENTS(3)"
run "SNOWFLAKE_XDR.DETECTIONS.BUILD_ATTACK_GRAPH()"
echo "Demo clock is current."
