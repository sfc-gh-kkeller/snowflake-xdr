#!/usr/bin/env bash
# ============================================================================
# Snowflake XDR - end-to-end demo builder
# ============================================================================
# Builds (or refreshes) the whole demo on one Snowflake account with the
# Snowflake CLI: schemas and code, CTF dataset, synthetic telemetry, the
# multi-stage campaign, the detection/correlation/AI pipeline, the Cortex
# Agent, and the XDR Console (Snowflake App Runtime).
#
# Default mode is idempotent: every step is safe to re-run and existing demo
# state (cases, notes, dispositions, IOCs, playbooks) is kept.
#
# Usage:
#   scripts/deploy_demo.sh [options]
#
# Options:
#   --connection NAME       snow CLI connection (default: aws_demo_kevin)
#   --fresh                 drop SNOWFLAKE_XDR + CTF and rebuild from zero
#   --yes-drop-everything   required together with --fresh
#   --skip-app              don't deploy the XDR Console
#   --skip-ai               skip Cortex AI pipeline steps (triage, classify)
#   --legacy-streamlit      also redeploy the deprecated XDR_SOC Streamlit app
#                           (implied by --fresh, which would otherwise lose it)
#   --with-notifications    evaluate response playbooks (sends real email /
#                           webhook / API calls)
#   --events-per-day N      synthetic telemetry volume (default: 5000)
#   -h, --help              show this help
#
# Environment:
#   SNOW                    snow CLI command (default: snow)
#   SLACK_WEBHOOK_TOKEN     Slack webhook path token, used only when the
#                           RESPONSE.SLACK_WEBHOOK secret has to be created
# ============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CONN="aws_demo_kevin"
FRESH=0
CONFIRM_DROP=0
SKIP_APP=0
SKIP_AI=0
LEGACY=0
NOTIFY=0
EVENTS_PER_DAY=5000
SNOW="${SNOW:-snow}"

usage() { sed -n '2,37p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --connection)          CONN="$2"; shift 2 ;;
        --fresh)               FRESH=1; shift ;;
        --yes-drop-everything) CONFIRM_DROP=1; shift ;;
        --skip-app)            SKIP_APP=1; shift ;;
        --skip-ai)             SKIP_AI=1; shift ;;
        --legacy-streamlit)    LEGACY=1; shift ;;
        --with-notifications)  NOTIFY=1; shift ;;
        --events-per-day)      EVENTS_PER_DAY="$2"; shift 2 ;;
        -h|--help)             usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

if [[ $FRESH -eq 1 && $CONFIRM_DROP -ne 1 ]]; then
    echo "--fresh drops SNOWFLAKE_XDR and CTF (all cases, notes and dispositions)." >&2
    echo "Re-run with --fresh --yes-drop-everything to confirm." >&2
    exit 2
fi
[[ "$EVENTS_PER_DAY" =~ ^[0-9]+$ ]] || { echo "--events-per-day must be an integer" >&2; exit 2; }
# A fresh build drops the database that holds XDR_SOC; keep the deprecated app
[[ $FRESH -eq 1 ]] && LEGACY=1

LOG_DIR="$REPO_ROOT/output/deploy_logs"
mkdir -p "$LOG_DIR"
RUN_LOG="$LOG_DIR/deploy_$(date +%Y%m%d_%H%M%S).log"
START_EPOCH=$(date +%s)
APP_URL=""

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
elapsed() { echo "$(( $(date +%s) - START_EPOCH ))s"; }
log()     { printf '[%6s] %s\n' "$(elapsed)" "$*" | tee -a "$RUN_LOG"; }
phase()   { printf '\n== %s ==\n' "$*" | tee -a "$RUN_LOG"; }
fail()    { log "FAILED: $*"; log "Full log: $RUN_LOG"; exit 1; }

# Run a SQL file. Fails fast and prints the snow error on failure.
sql_file() {
    local file="$1" out
    log "sql  $file"
    if ! out=$("$SNOW" sql -f "$file" -c "$CONN" --enable-templating NONE 2>&1); then
        echo "$out" >> "$RUN_LOG"
        echo "$out" | grep -A8 "Error" | head -12 >&2
        fail "$file"
    fi
    echo "$out" >> "$RUN_LOG"
}

# Run one SQL statement (on XDR_WH) and log its first result value.
sql_call() {
    local label="$1" stmt="$2" out
    log "call $label"
    if ! out=$("$SNOW" sql --format json -q "USE WAREHOUSE XDR_WH; $stmt" -c "$CONN" 2>&1); then
        echo "$out" >> "$RUN_LOG"
        echo "$out" | grep -A8 "Error" | head -12 >&2
        fail "$label"
    fi
    echo "$out" >> "$RUN_LOG"
    local val
    val=$(printf '%s' "$out" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    rows = data[-1] if data and isinstance(data[0], list) else data
    v = list(rows[0].values())[0] if rows else ""
    print(str(v)[:160])
except Exception:
    print("")
')
    [[ -n "$val" ]] && log "     -> $val"
    return 0
}

# Return the first column of the first row of a query, or empty string.
scalar() {
    "$SNOW" sql --format json -q "$1" -c "$CONN" 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    rows = data[-1] if data and isinstance(data[0], list) else data
    print(list(rows[0].values())[0] if rows else "")
except Exception:
    print("")
'
}

# ---------------------------------------------------------------------------
# 1. preflight
# ---------------------------------------------------------------------------
phase "1/8 Preflight"
command -v "$SNOW" >/dev/null || fail "snow CLI not found (set SNOW=...)"
command -v python3 >/dev/null || fail "python3 not found"
log "snow: $("$SNOW" --version 2>&1 | tail -1)"
"$SNOW" connection test -c "$CONN" >> "$RUN_LOG" 2>&1 \
    || fail "connection '$CONN' failed 'snow connection test'"
ROLE=$(scalar "SELECT CURRENT_ROLE()")
ACCOUNT=$(scalar "SELECT CURRENT_ORGANIZATION_NAME() || '-' || CURRENT_ACCOUNT_NAME()")
log "account: $ACCOUNT   role: $ROLE   connection: $CONN"
[[ "$ROLE" == "ACCOUNTADMIN" ]] \
    || fail "role is '$ROLE'; integrations and the agent need ACCOUNTADMIN"
log "mode: $([[ $FRESH -eq 1 ]] && echo 'FRESH rebuild' || echo 'idempotent refresh')"

# ---------------------------------------------------------------------------
# 2. fresh: tear down
# ---------------------------------------------------------------------------
phase "2/8 Teardown"
if [[ $FRESH -eq 1 ]]; then
    if [[ -f xdr-console/app.yml ]] && \
       [[ -n "$(scalar "SHOW APPLICATION SERVICES LIKE 'XDR_CONSOLE' IN SCHEMA SNOWFLAKE_XDR.DASHBOARDS")" ]]; then
        log "tearing down XDR Console app service"
        (cd xdr-console && "$SNOW" app teardown --force -c "$CONN") >> "$RUN_LOG" 2>&1 \
            || log "warning: app teardown reported an error (continuing)"
    fi
    # These reference objects inside SNOWFLAKE_XDR; recreate them cleanly
    sql_call "drop XDR_WEBHOOK" "DROP INTEGRATION IF EXISTS XDR_WEBHOOK"
    sql_call "drop XDR_API_EAI" "DROP INTEGRATION IF EXISTS XDR_API_EAI"
    sql_call "drop SNOWFLAKE_XDR" "DROP DATABASE IF EXISTS SNOWFLAKE_XDR"
    sql_call "drop CTF" "DROP DATABASE IF EXISTS CTF"
else
    log "idempotent mode - nothing dropped"
fi

# ---------------------------------------------------------------------------
# 3. schema and code
# ---------------------------------------------------------------------------
phase "3/8 Schemas, tables and code"
sql_file setup/01_database_and_schemas.sql
sql_file setup/00_ctf_schema.sql
for f in 02_raw_log_tables 02b_splunk_views 03_detection_tables \
         04_incident_ontology_tables 05_reference_data \
         06_synthetic_log_generators 07_detection_procedures \
         08_incident_correlation 09_scheduled_tasks 10_ai_agents \
         11_custom_rules; do
    sql_file "setup/$f.sql"
done

# Response channels: substitute the Slack token (only used if the secret is new)
CHANNELS_SQL="$(mktemp -t xdr_channels.XXXXXX).sql"
trap 'rm -f "$CHANNELS_SQL"' EXIT
# Snowflake validates the resolved Slack URL, so the placeholder must be
# shaped like a real T.../B.../... path
TOKEN="${SLACK_WEBHOOK_TOKEN:-T00000000/B00000000/PLACEHOLDER0000000000000}"
# Token is a URL path (letters, digits, slashes); reject anything that could
# break out of the SQL string literal
[[ "$TOKEN" =~ ^[A-Za-z0-9/_-]+$ ]] || fail "SLACK_WEBHOOK_TOKEN contains unexpected characters"
sed "s|__SLACK_WEBHOOK_TOKEN__|$TOKEN|" setup/11b_response_channels.sql > "$CHANNELS_SQL"
if [[ -z "${SLACK_WEBHOOK_TOKEN:-}" && -z "$(scalar "SHOW SECRETS LIKE 'SLACK_WEBHOOK' IN SCHEMA SNOWFLAKE_XDR.RESPONSE")" ]]; then
    log "note: SLACK_WEBHOOK_TOKEN not set - webhook secret gets a placeholder value"
fi
sql_file "$CHANNELS_SQL"

for f in 12_api_udf 13_response_playbooks 14_platform_ops 15_platform_pro \
         16_attack_graph 18_controls 19_fp_suppression 20_live_feed \
         24_agent_actions 21_cortex_agent 22_demo_seed 23_time_shift; do
    sql_file "setup/$f.sql"
done

# ---------------------------------------------------------------------------
# 4. data
# ---------------------------------------------------------------------------
phase "4/8 Data"
CTF_ROWS=$(scalar "SELECT COUNT(*) FROM CTF.PUBLIC.ACCESS_LOGS")
if [[ "${CTF_ROWS:-0}" -gt 0 ]]; then
    log "CTF dataset already loaded ($CTF_ROWS access-log rows) - skipped"
else
    log "uploading CTF dataset (data/ctf/*.csv.gz)"
    "$SNOW" stage copy "data/ctf/" "@CTF.PUBLIC.CTF_UPLOAD_STAGE" -c "$CONN" --overwrite --recursive >> "$RUN_LOG" 2>&1 \
        || fail "snow stage copy data/ctf"
    sql_file setup/00b_ctf_load.sql
    log "     -> CTF access logs: $(scalar "SELECT COUNT(*) FROM CTF.PUBLIC.ACCESS_LOGS")"
fi

FRESH_TELEMETRY=0
AUTH_ROWS=$(scalar "SELECT COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION")
if [[ "${AUTH_ROWS:-0}" -gt 0 ]]; then
    log "synthetic telemetry already present ($AUTH_ROWS auth events) - skipped"
else
    sql_call "GENERATE_SYNTHETIC_LOGS" \
        "CALL SNOWFLAKE_XDR.RAW_LOGS.GENERATE_SYNTHETIC_LOGS(7, $EVENTS_PER_DAY)"
    FRESH_TELEMETRY=1
fi
sql_file setup/17_campaign_data.sql
sql_call "SEED_DEMO_GEO"   "CALL SNOWFLAKE_XDR.REFERENCE.SEED_DEMO_GEO()"
sql_call "SHIFT_DEMO_TIME" "CALL SNOWFLAKE_XDR.REFERENCE.SHIFT_DEMO_TIME()"

# ---------------------------------------------------------------------------
# 5. pipeline
# ---------------------------------------------------------------------------
phase "5/8 Detection, correlation and AI pipeline"
sql_call "RUN_ALL_DETECTIONS"        "CALL SNOWFLAKE_XDR.DETECTIONS.RUN_ALL_DETECTIONS()"
# The built-in rules look back 15-60 minutes, so freshly generated telemetry
# needs a replay over its historical hot hours (findings keep their true times)
if [[ $FRESH_TELEMETRY -eq 1 ]]; then
    sql_call "REPLAY_DETECTIONS"     "CALL SNOWFLAKE_XDR.DETECTIONS.REPLAY_DETECTIONS(7)"
fi
sql_call "BUILD_BASELINES"           "CALL SNOWFLAKE_XDR.REFERENCE.BUILD_BASELINES()"
sql_call "RUN_ML_ANOMALY_DETECTION"  "CALL SNOWFLAKE_XDR.DETECTIONS.RUN_ML_ANOMALY_DETECTION()"
sql_call "BUILD_ATTACK_GRAPH"        "CALL SNOWFLAKE_XDR.DETECTIONS.BUILD_ATTACK_GRAPH()"
sql_call "DOOR_RATTLING_SCAN"        "CALL SNOWFLAKE_XDR.DETECTIONS.DOOR_RATTLING_SCAN()"
sql_call "DETECT_PROTECTED_ACCESS"   "CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_PROTECTED_ACCESS()"
# Built-in rules re-flag their lookback window on every manual run
sql_call "DEDUPE_FINDINGS"           "CALL SNOWFLAKE_XDR.DETECTIONS.DEDUPE_FINDINGS()"
sql_call "APPLY_CONTROL_ASSESSMENT"  "CALL SNOWFLAKE_XDR.DETECTIONS.APPLY_CONTROL_ASSESSMENT()"
sql_call "CORRELATE_INCIDENTS"       "CALL SNOWFLAKE_XDR.INCIDENTS.CORRELATE_INCIDENTS()"
sql_call "SEED_ANALYST_DISPOSITIONS" "CALL SNOWFLAKE_XDR.REFERENCE.SEED_ANALYST_DISPOSITIONS()"
sql_call "TRAIN_FP_MODEL"            "CALL SNOWFLAKE_XDR.DETECTIONS.TRAIN_FP_MODEL()"
sql_call "SCORE_FINDINGS_FP"         "CALL SNOWFLAKE_XDR.DETECTIONS.SCORE_FINDINGS_FP()"
if [[ $SKIP_AI -eq 1 ]]; then
    log "--skip-ai: AI triage and classification skipped"
else
    sql_call "AI_TRIAGE_AGENT"       "CALL SNOWFLAKE_XDR.DETECTIONS.AI_TRIAGE_AGENT(10)"
    sql_call "AI_CLASSIFY_FINDINGS"  "CALL SNOWFLAKE_XDR.DETECTIONS.AI_CLASSIFY_FINDINGS(20)"
fi
sql_call "EMIT_LIVE_EVENTS"          "CALL SNOWFLAKE_XDR.RAW_LOGS.EMIT_LIVE_EVENTS(3)"
if [[ $NOTIFY -eq 1 ]]; then
    sql_call "EVALUATE_ALL_NEW_FINDINGS" "CALL SNOWFLAKE_XDR.RESPONSE.EVALUATE_ALL_NEW_FINDINGS()"
else
    log "playbook evaluation skipped (pass --with-notifications to send alerts)"
fi

# ---------------------------------------------------------------------------
# 6. XDR Console (Snowflake App Runtime)
# ---------------------------------------------------------------------------
phase "6/8 XDR Console"
if [[ $SKIP_APP -eq 1 ]]; then
    log "--skip-app: console deploy skipped"
elif [[ ! -f xdr-console/app.yml ]]; then
    log "warning: xdr-console/app.yml not found - console deploy skipped"
else
    log "snow app deploy (builds in Snowflake; typically a few minutes)"
    APP_LOG="$LOG_DIR/app_deploy_$(date +%Y%m%d_%H%M%S).log"
    if ! (cd xdr-console && "$SNOW" app deploy --verbose -c "$CONN") > "$APP_LOG" 2>&1; then
        tail -30 "$APP_LOG" >&2
        fail "snow app deploy (log: $APP_LOG)"
    fi
    APP_URL=$(cd xdr-console && "$SNOW" app open --print-only -c "$CONN" 2>/dev/null \
        | grep -oE 'https://[A-Za-z0-9.-]+\.snowflakecomputing\.app' | tail -1 || true)
    if [[ -n "$APP_URL" ]]; then
        # The deprecated XDR_SOC app reads this for its "moved to the console" banner
        [[ "$APP_URL" =~ ^https://[A-Za-z0-9.-]+$ ]] || fail "unexpected console URL: $APP_URL"
        sql_call "record console URL" "MERGE INTO SNOWFLAKE_XDR.REFERENCE.PLATFORM_SETTINGS t
            USING (SELECT 'xdr_console_url' AS k, '$APP_URL' AS v) s ON t.setting_key = s.k
            WHEN MATCHED THEN UPDATE SET setting_value = s.v, updated_at = CURRENT_TIMESTAMP()
            WHEN NOT MATCHED THEN INSERT (setting_key, setting_value) VALUES (s.k, s.v)"
    fi
    log "     -> console deployed ${APP_URL:+at $APP_URL}"
fi

# ---------------------------------------------------------------------------
# 7. legacy Streamlit (deprecated)
# ---------------------------------------------------------------------------
phase "7/8 Legacy XDR_SOC Streamlit (deprecated)"
if [[ $LEGACY -eq 1 ]]; then
    # --prune removes stale page files; pyproject.toml is in the artifact list
    (cd streamlit && "$SNOW" streamlit deploy xdr_soc --replace --prune -c "$CONN") >> "$RUN_LOG" 2>&1 \
        || fail "snow streamlit deploy xdr_soc"
    log "     -> XDR_SOC redeployed (shows a deprecation banner)"
else
    log "skipped (pass --legacy-streamlit to redeploy the deprecated app)"
fi

# ---------------------------------------------------------------------------
# 8. verify
# ---------------------------------------------------------------------------
phase "8/8 Verify"
FAILS=0
check() {   # check <label> <value> <min>
    local label="$1" value="${2:-0}" min="$3" status="ok"
    [[ "$value" =~ ^[0-9]+$ ]] || value=0
    if (( value < min )); then status="FAIL"; FAILS=$((FAILS + 1)); fi
    printf '  %-4s %-42s %s\n' "$status" "$label" "$value" | tee -a "$RUN_LOG"
}
check "CTF access logs"                 "$(scalar "SELECT COUNT(*) FROM CTF.PUBLIC.ACCESS_LOGS")" 1
check "auth events"                     "$(scalar "SELECT COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION")" 1
check "detection rules enabled"         "$(scalar "SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES WHERE enabled")" 30
check "findings (last 7 days)"          "$(scalar "SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())")" 1
check "incidents"                       "$(scalar "SELECT COUNT(*) FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS")" 1
check "attack graph edges"              "$(scalar "SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.ATTACK_PATH_EDGES")" 1
check "findings mitigated by controls"  "$(scalar "SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE disposition = 'mitigated_by_control'")" 1
check "findings auto-suppressed (FP)"   "$(scalar "SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE triage_notes LIKE '%Auto-suppressed by FP model%'")" 1
check "live-feed events (last hour)"    "$(scalar "SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.V_LIVE_FEED")" 1
HOPS=$(scalar "CALL SNOWFLAKE_XDR.DETECTIONS.TRACE_ATTACK_PATHS('host:10.1.5.107')" | python3 -c '
import json, sys
try:
    v = json.loads(sys.stdin.read() or "{}")
    print(max([p.get("hops", 0) for p in v.get("paths", [])] or [0]))
except Exception:
    print(0)
')
check "campaign path depth (hops)"      "$HOPS" 4
AGENT_OK=$(scalar "SELECT IFF(REGEXP_LIKE(SNOWFLAKE.CORTEX.DATA_AGENT_RUN('SNOWFLAKE_XDR.DASHBOARDS.XDR_ANALYST', '{\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"How many detection findings are there in the last 7 days? Answer with the number.\"}]}]}', TRUE), '.*\"status\":\"completed\".*', 's'), 1, 0)")
check "XDR_ANALYST agent answers"       "$AGENT_OK" 1
if [[ -n "$APP_URL" ]]; then
    CODE=$(curl -s -o /dev/null -w '%{http_code}' "$APP_URL" || echo 0)
    # The console sits behind Snowflake auth: 200 or a 302 to login means it is up
    [[ "$CODE" == "200" || "$CODE" == "302" ]] && UP=1 || UP=0
    check "console endpoint reachable (HTTP $CODE)" "$UP" 1
fi

phase "Done in $(elapsed)"
[[ -n "$APP_URL" ]] && log "XDR Console: $APP_URL"
log "Log: $RUN_LOG"
if (( FAILS > 0 )); then
    log "$FAILS verification check(s) failed"
    exit 1
fi
log "All verification checks passed"
