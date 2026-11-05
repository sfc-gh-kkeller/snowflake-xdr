-- ============================================================================
-- Snowflake XDR - Phase 5.6: near-real-time lane
-- ============================================================================
-- The standard path is batch: TASK_APPLY_CIM_MAPPINGS (1 min) then
-- TASK_RUN_DETECTIONS (5 min), so a detection can take ~6 minutes after the
-- event arrives. The fast lane is for the alerts where minutes matter:
--
--   RAW_LOGS.HOT_EDR_ALERTS    dynamic table, TARGET_LAG 1 minute, over OTEL_LOGS:
--                              CrowdStrike / Defender / SentinelOne native alerts in
--                              one normalised shape, kept fresh by Snowflake with no
--                              mapping task in between
--   CUSTOM_RULES.fast          the FAST rule class: RT-001 on the hot table plus
--                              high-severity EDR pack rules and critical Sigma rules
--   TASK_FAST_LANE             serverless, triggered by new rows on the OTEL_LOGS stream:
--                              refreshes the hot table, runs RT-001, then maps the new data
--                              and runs the other FAST rules
--   V_DETECTION_LATENCY        per rule: median / p95 seconds from event to finding
--   RUN_FAST_LANE_PROBE()      end-to-end SLO check: sends a real OTLP alert through
--                              ingest -> dynamic table -> fast run, and passes only if
--                              a FAST rule matches it within 120 seconds; the result is
--                              recorded as RT-001's canary
--
-- Ingest itself: the OTLP receiver writes to OTEL_LOGS as records arrive. For
-- sub-second ingest at very high volume, Snowpipe Streaming (high-performance
-- architecture) can write the same table; nothing downstream changes.
--
-- Timing: TASK_FAST_LANE is a serverless *triggered* task on a stream over OTEL_LOGS
-- (streams on dynamic tables cannot trigger tasks), so it starts within ~10-30 s of
-- new data, refreshes HOT_EDR_ALERTS on demand, and runs RT-001 before the broader
-- mapping and the other FAST rules.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES ADD COLUMN IF NOT EXISTS fast BOOLEAN;

-- ---------------------------------------------------------------------------
-- 1. The hot table (dynamic, 1-minute lag)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE DYNAMIC TABLE SNOWFLAKE_XDR.RAW_LOGS.HOT_EDR_ALERTS
    TARGET_LAG = '1 minute'
    WAREHOUSE = XDR_WH
    REFRESH_MODE = INCREMENTAL
    COMMENT = 'Near-real-time lane: EDR native alerts from OTEL_LOGS, normalised (setup/46_realtime.sql)'
AS
SELECT otel_id, event_time AS _time, received_at, 'CrowdStrike Falcon' AS vendor_product,
       body:event:ComputerName::VARCHAR AS host, LOWER(body:event:UserName::VARCHAR) AS user_name,
       COALESCE(body:event:DetectName, body:event:Name)::VARCHAR || ': ' || COALESCE(body:event:Description::VARCHAR, '') AS signature,
       TRY_TO_NUMBER(body:event:Severity::VARCHAR) AS severity, body:event:Tactic::VARCHAR AS category, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'crowdstrike' AND body:metadata:eventType::VARCHAR IN ('DetectionSummaryEvent', 'EppDetectionSummaryEvent')
UNION ALL
SELECT otel_id, event_time, received_at, 'Microsoft Defender for Endpoint',
       body:properties:DeviceName::VARCHAR, LOWER(body:properties:AccountName::VARCHAR),
       body:properties:Title::VARCHAR,
       DECODE(LOWER(body:properties:Severity::VARCHAR), 'high', 4, 'medium', 3, 'low', 2, 'informational', 1, 3),
       body:properties:Category::VARCHAR, body
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'defender' AND body:category::VARCHAR = 'AdvancedHunting-AlertInfo' AND body:properties:Title IS NOT NULL
UNION ALL
SELECT otel_id, event_time, received_at, 'SentinelOne',
       body:agentRealtimeInfo:agentComputerName::VARCHAR, LOWER(REGEXP_SUBSTR(body:threatInfo:processUser::VARCHAR, '[^\\\\]+$')),
       body:threatInfo:threatName::VARCHAR || ': ' || COALESCE(body:threatInfo:classification::VARCHAR, ''),
       DECODE(LOWER(body:threatInfo:confidenceLevel::VARCHAR), 'malicious', 5, 'suspicious', 3, 3),
       body:threatInfo:classification::VARCHAR, body
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'sentinelone' AND body:threatInfo:threatName IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 2. FAST rules
-- ---------------------------------------------------------------------------
MERGE INTO SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES t
USING (SELECT 'RT-001' AS rule_id) s ON t.rule_id = s.rule_id
WHEN NOT MATCHED THEN INSERT (rule_id, name, description, category, severity, mitre_tactic_id, mitre_technique_id,
    language, source_table, code, threshold_count, threshold_window_minutes, lookback_minutes, enabled, test_mode,
    version, created_by, managed_by, fast)
VALUES ('RT-001', 'EDR high-severity alert (real-time lane)',
    'Any CrowdStrike, Defender or SentinelOne alert of severity 4+, detected from the 1-minute dynamic table.',
    'INTRUSION_DETECTION', 5, 'TA0002', 'T1204', 'sql', 'RAW_LOGS.HOT_EDR_ALERTS',
    'SELECT _time, user_name, host AS src, host AS dest, vendor_product || '': '' || signature AS description
FROM SNOWFLAKE_XDR.RAW_LOGS.HOT_EDR_ALERTS
WHERE severity >= 4',
    1, 5, 30, TRUE, FALSE, 1, 'xdr', 'builtin', TRUE);

-- High-severity EDR pack rules and critical Sigma rules join the FAST class (pack updates keep the flag)
UPDATE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES c SET fast = TRUE
FROM SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES p
WHERE p.rule_id = c.rule_id AND COALESCE(c.fast, FALSE) = FALSE
  AND ((p.pack_id IN ('crowdstrike', 'defender', 'sentinelone') AND p.severity >= 4)
       OR (p.pack_id LIKE 'sigma%' AND p.severity = 5));
UPDATE SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES SET expected_latency_seconds = 120
WHERE rule_id IN (SELECT rule_id FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE fast);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.FAST_LANE_RUNS (
    run_id        VARCHAR DEFAULT UUID_STRING(),
    started_at    TIMESTAMP_LTZ,
    finished_at   TIMESTAMP_LTZ,
    new_rows      NUMBER,
    oldest_new    TIMESTAMP_LTZ,
    rules_run     NUMBER,
    findings      NUMBER,
    errors        VARIANT
);
ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.FAST_LANE_RUNS ADD COLUMN IF NOT EXISTS hot_done_at TIMESTAMP_LTZ;  -- RT-001 finished

CREATE STREAM IF NOT EXISTS SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS_FAST_STREAM
    ON TABLE SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS APPEND_ONLY = TRUE
    COMMENT = 'Wakes TASK_FAST_LANE when new OTel records arrive';

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RUN_FAST_RULES()
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import json
import re

DB = "SNOWFLAKE_XDR"


def now_ms(s):
    # epoch milliseconds: session time zones differ between the task and callers, strings would skew
    return int(s.sql("SELECT DATE_PART(epoch_millisecond, CURRENT_TIMESTAMP()) AS t").collect()[0]["T"])


def main(s):
    # Detection is not autonomy: the kill switch stops changes and response, never detection
    started = now_ms(s)
    # Consume the stream (a DML read advances it) and remember how much arrived
    s.sql(f"""CREATE OR REPLACE TEMPORARY TABLE XDR_FAST_BATCH AS
              SELECT COUNT(*) AS n, DATE_PART(epoch_millisecond, MIN(received_at)) AS oldest
              FROM {DB}.RAW_LOGS.OTEL_LOGS_FAST_STREAM""").collect()
    b = s.sql("SELECT n, oldest FROM XDR_FAST_BATCH").collect()[0]
    errors, found = {}, 0

    def run(rid):
        nonlocal found
        try:
            r = s.sql(f"CALL {DB}.DETECTIONS.RUN_CUSTOM_RULE_SQL(?, FALSE)", params=[rid]).collect()[0][0]
            m = re.search(r"OK: (\d+)", str(r))
            found += int(m.group(1)) if m else 0
            if not m:
                errors[rid] = str(r)[:200]
        except Exception as e:
            errors[rid] = str(e)[:200]

    # 1. Hot path first: refresh the dynamic table now (its 1-minute lag is the backstop) and run RT-001
    try:
        s.sql(f"ALTER DYNAMIC TABLE {DB}.RAW_LOGS.HOT_EDR_ALERTS REFRESH").collect()
    except Exception as e:
        errors["hot_refresh"] = str(e)[:300]
    run("RT-001")
    hot_done = now_ms(s)
    # 2. Then map the new data into the CIM tables and run the other FAST rules
    try:
        s.sql(f"CALL {DB}.REFERENCE.APPLY_CIM_MAPPINGS()").collect()
    except Exception as e:
        errors["mapping"] = str(e)[:300]
    rules = [r["RULE_ID"] for r in s.sql(f"""SELECT rule_id FROM {DB}.DETECTIONS.CUSTOM_RULES
                                             WHERE fast AND (enabled OR test_mode) AND language = 'sql'
                                               AND rule_id <> 'RT-001'
                                             ORDER BY severity DESC, rule_id""").collect()]
    for rid in rules:
        run(rid)
    s.sql(f"""INSERT INTO {DB}.DETECTIONS.FAST_LANE_RUNS (started_at, hot_done_at, finished_at, new_rows, oldest_new,
                                                          rules_run, findings, errors)
              SELECT TO_TIMESTAMP_LTZ(?, 3), TO_TIMESTAMP_LTZ(?, 3), CURRENT_TIMESTAMP(), ?, TO_TIMESTAMP_LTZ(?, 3), ?, ?,
                     PARSE_JSON(NULLIF(?, 'null'))""",
          params=[started, hot_done, b["N"], b["OLDEST"], len(rules) + 1, found, json.dumps(errors or None)]).collect()
    return {"ok": not errors, "new_rows": b["N"], "rules_run": len(rules) + 1, "findings": found, "errors": errors}
$$;

-- Triggered (no schedule): runs as soon as new OTel records land, at most every 10 seconds.
-- Serverless triggered tasks require TARGET_COMPLETION_INTERVAL.
CREATE OR REPLACE TASK SNOWFLAKE_XDR.DETECTIONS.TASK_FAST_LANE
    TARGET_COMPLETION_INTERVAL = '1 MINUTE'
    USER_TASK_MINIMUM_TRIGGER_INTERVAL_IN_SECONDS = 10
    COMMENT = 'Near-real-time lane: refreshes the hot table and runs FAST rules whenever new OTel records arrive'
    WHEN SYSTEM$STREAM_HAS_DATA('SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS_FAST_STREAM')
AS
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_FAST_RULES();
ALTER TASK SNOWFLAKE_XDR.DETECTIONS.TASK_FAST_LANE RESUME;

-- ---------------------------------------------------------------------------
-- 3. Latency, measured
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_DETECTION_LATENCY AS
SELECT f.rule_id, ANY_VALUE(r.name) AS name, COALESCE(ANY_VALUE(r.fast), FALSE) AS fast,
       IFF(COALESCE(ANY_VALUE(r.fast), FALSE), 120, 600) AS slo_seconds,
       COUNT(*) AS findings_7d,
       MEDIAN(DATEDIFF('second', f.event_time, f.detection_time)) AS median_seconds,
       APPROX_PERCENTILE(DATEDIFF('second', f.event_time, f.detection_time), 0.95) AS p95_seconds
FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES r ON r.rule_id = f.rule_id
WHERE f.detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP()) AND f.event_time <= f.detection_time
  AND f.event_time > DATEADD('day', -8, CURRENT_TIMESTAMP())   -- late backfills are not detection latency
GROUP BY f.rule_id;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RUN_FAST_LANE_PROBE(P_TIMEOUT_SECONDS NUMBER)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import json
import time
import uuid

DB = "SNOWFLAKE_XDR"
SLO = 120


def one(s, sql, params=None):
    r = s.sql(sql, params=params).collect()
    return r[0].as_dict() if r else None


def main(s, P_TIMEOUT_SECONDS):
    timeout = min(max(int(P_TIMEOUT_SECONDS or 180), 30), 600)
    host = "xdrcanaryprobe" + uuid.uuid4().hex[:10]   # 'xdrcanary' rows never become findings
    now = int(time.time() * 1000)
    body = {"metadata": {"eventType": "DetectionSummaryEvent", "eventCreationTime": now},
            "event": {"ComputerName": host, "UserName": "probe", "Severity": 5, "DetectName": "LatencyProbe",
                      "Description": "near-real-time lane probe", "Tactic": "Execution"}}
    payload = {"resourceLogs": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "crowdstrike"}}]},
                                 "scopeLogs": [{"scope": {"name": "xdr-fast-probe"}, "logRecords": [
                                     {"timeUnixNano": str(now * 1000000), "severityText": "INFO",
                                      "body": {"stringValue": json.dumps(body)}}]}]}]}
    t0 = time.time()
    s.sql(f"CALL {DB}.RAW_LOGS.INGEST_OTLP_LOGS(?, NULL)", params=[json.dumps(payload)]).collect()
    sent = int(one(s, "SELECT DATE_PART(epoch_millisecond, CURRENT_TIMESTAMP()) AS t")["T"])
    rule = one(s, f"SELECT code FROM {DB}.DETECTIONS.CUSTOM_RULES WHERE rule_id = 'RT-001'")["CODE"]
    visible = detected = None
    while time.time() - t0 < timeout:
        if visible is None and one(s, f"SELECT 1 AS x FROM {DB}.RAW_LOGS.HOT_EDR_ALERTS WHERE host = ?", [host]):
            visible = round(time.time() - t0, 1)
        if visible is not None and one(s, f"SELECT COUNT(*) AS n FROM ({rule}) WHERE src = ?", [host])["N"]:
            # detected = RT-001 finished in a fast-lane run whose batch included the probe (run started after it landed),
            # measured on the database clock from the moment ingest returned
            r = one(s, f"""SELECT (DATE_PART(epoch_millisecond, MIN(hot_done_at)) - ?) / 1000 AS s
                           FROM {DB}.DETECTIONS.FAST_LANE_RUNS WHERE started_at >= TO_TIMESTAMP_LTZ(?, 3)""", [sent, sent])
            if r and r["S"] is not None:
                detected = round(float(r["S"]), 1)
                break
        time.sleep(3)
    s.sql(f"DELETE FROM {DB}.RAW_LOGS.OTEL_LOGS WHERE body:event:ComputerName::VARCHAR = ?", params=[host]).collect()
    s.sql(f"DELETE FROM {DB}.RAW_LOGS.INTRUSION_DETECTION WHERE src = ?", params=[host]).collect()
    status = "pass" if detected is not None and detected <= SLO else "fail"
    detail = {"mode": "fast_lane_probe", "slo_seconds": SLO, "visible_in_hot_table_s": visible, "detected_s": detected,
              "message": "ok" if status == "pass" else
                         (f"not detected within {timeout}s" if detected is None else f"detected in {detected}s, over the {SLO}s SLO")
                         + ("" if visible is not None else " (never reached HOT_EDR_ALERTS: is the dynamic table refreshing?)")}
    s.sql(f"""INSERT INTO {DB}.DETECTIONS.CANARY_RUNS (batch_id, rule_id, status, positive_fired, negative_fired,
                latency_seconds, detail) SELECT ?, 'RT-001', ?, ?, FALSE, ?, PARSE_JSON(?)""",
          params=["probe-" + host[-10:], status, detected is not None, detected if detected is not None else -1,
                  json.dumps(detail)]).collect()
    return {"ok": status == "pass", "status": status, **detail}
$$;

CREATE OR REPLACE TASK SNOWFLAKE_XDR.DETECTIONS.TASK_FAST_LANE_PROBE
    WAREHOUSE = XDR_WH
    SCHEDULE = 'USING CRON 30 */6 * * * UTC'
    COMMENT = 'Every 6 hours: prove the near-real-time lane detects within 120 seconds'
AS
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_FAST_LANE_PROBE(180);
ALTER TASK SNOWFLAKE_XDR.DETECTIONS.TASK_FAST_LANE_PROBE RESUME;
