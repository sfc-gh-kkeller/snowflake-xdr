-- ============================================================================
-- Snowflake XDR - 26: Detection Autopilot
-- ============================================================================
-- A self-maintaining detection engineering loop with a human in the loop.
--
--   assess   -> MITRE backlog gaps, broken rules, noisy rules (analyst FP
--               verdicts), silent rules
--   propose  -> Cortex writes or rewrites rule SQL (or a deterministic tune)
--   validate -> RULE_SQL_VIOLATION guard, execution, regression metrics
--               against labelled attack ground truth (V_ATTACK_GROUND_TRUTH)
--   decide   -> AUTOPILOT_POLICY per change type:
--                 auto_live | shadow_then_promote | propose_only | off
--   promote  -> shadow rules (CUSTOM_RULES.test_mode, findings go to
--               SHADOW_FINDINGS) go live once they meet the policy criteria
--   guard    -> live autopilot changes that error or flood are rolled back
--   notify   -> AUTOPILOT_CHANGES feed (console), webhook, daily email digest
--
-- Humans approve / reject / roll back / pin through AUTOPILOT_DECIDE, the
-- console's Detection Autopilot view, or the Ask XDR agent.
-- Hard limits (not policy): never deletes data, never edits pinned rules,
-- never auto-disables severity >= 4, built-in DET rules only via proposals.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Ground truth: attack events of the synthetic campaigns, labelled by
--    their campaign indicators (works on already-generated data).
--    entity_keys = identities a matching finding would carry.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.REFERENCE.V_ATTACK_GROUND_TRUTH AS
WITH gt AS (
    -- C1 brute force -> discovery -> lateral movement
    SELECT 'C1' AS campaign_id, 'T1110' AS technique_id, 'AUTHENTICATION' AS source_table,
           _time, user_name, src, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE src = '185.220.101.42'
    UNION ALL
    SELECT 'C1', 'T1087.002', 'ENDPOINT_PROCESSES', _time, user_name, NULL, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE user_name = 'jsmith' AND dest = 'WKS-001' AND parent_process_name = 'cmd.exe'
    UNION ALL
    SELECT 'C1', 'T1021.002', 'NETWORK_TRAFFIC', _time, NULL, src, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    WHERE src = 'WKS-001' AND dest_port = 445
    UNION ALL
    SELECT 'C1', 'T1021.001', 'AUTHENTICATION', _time, user_name, src, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE app = 'rdp' AND user_name = 'jsmith' AND src = '10.1.5.101'
    -- C2 phishing -> PowerShell -> credential dump -> ransomware prep
    UNION ALL
    SELECT 'C2',
           CASE WHEN process_name = 'cmd.exe' THEN 'T1566.001'
                WHEN process_name = 'powershell.exe' THEN 'T1059.001'
                WHEN process_name = 'rundll32.exe' THEN 'T1003.001'
                ELSE 'T1490' END,
           'ENDPOINT_PROCESSES', _time, NULLIF(user_name, 'SYSTEM'), NULL, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE dest = 'WKS-003'
      AND (process ILIKE '%-enc %' OR process ILIKE '%DownloadString%'
           OR process ILIKE '%lsass.dmp%' OR process ILIKE '%Delete Shadows%')
    UNION ALL
    SELECT 'C2', 'T1547.001', 'ENDPOINT_REGISTRY', _time, user_name, NULL, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_REGISTRY
    WHERE registry_value_data ILIKE '%svchost_update.exe%'
    -- attack steps map to several techniques: the same C2 events, extra labels
    UNION ALL
    SELECT 'C2', 'T1027', 'ENDPOINT_PROCESSES', _time, user_name, NULL, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE dest = 'WKS-003' AND process ILIKE '%-enc %'
    UNION ALL
    SELECT 'C2', 'T1105', 'ENDPOINT_PROCESSES', _time, user_name, NULL, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE dest = 'WKS-003' AND process ILIKE '%DownloadString%'
    -- C3 cloud privilege escalation
    UNION ALL
    SELECT 'C3',
           CASE WHEN action IN ('CreateRole', 'AttachRolePolicy') THEN 'T1098'
                WHEN action = 'AssumeRole' THEN 'T1078.004'
                WHEN action = 'StopLogging' THEN 'T1562.008'
                ELSE 'T1530' END,
           'CLOUD_API', _time, user_name, src, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API
    WHERE user_name = 'compromised-dev-user'
    -- C4 insider: bulk confidential reads + exfiltration
    UNION ALL
    SELECT 'C4', 'T1005', 'ENDPOINT_FILESYSTEM', _time, user_name, NULL, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_FILESYSTEM
    WHERE user_name = 'dwilson' AND file_path ILIKE '%Confidential%'
    UNION ALL
    SELECT 'C4', 'T1048', 'NETWORK_TRAFFIC', _time, NULL, src, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    WHERE dest_ip = '91.219.236.222'
    -- C5 web exploitation -> web shell -> C2
    UNION ALL
    SELECT 'C5', IFF(threat_category = 'webshell', 'T1505.003', 'T1190'),
           'WEB_ACTIVITY', _time, NULL, src, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY
    WHERE src = '23.106.215.100'
    UNION ALL
    SELECT 'C5', 'T1071.001', 'NETWORK_TRAFFIC', _time, NULL, src, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    WHERE dest_ip = '185.220.101.42' AND dest_port = 443
    -- C6 scripted campaign (17_campaign_data): credential theft tooling
    UNION ALL
    SELECT 'C6', 'T1003', 'ENDPOINT_PROCESSES', _time, user_name, NULL, dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE LOWER(process_name) IN ('mimikatz.exe', 'psexec.exe')
)
SELECT campaign_id, technique_id, source_table, _time, user_name, src, dest,
       -- identity of the attacker-side entity; fall back to the host when no user/src
       IFF(user_name IS NULL AND src IS NULL, ARRAY_CONSTRUCT(dest),
           ARRAY_CONSTRUCT_COMPACT(user_name, src)) AS entity_keys
FROM gt;

-- ---------------------------------------------------------------------------
-- 2. Technique backlog: what the autopilot may write rules for, with the
--    telemetry it can use. A technique is a gap while no enabled built-in or
--    custom (live / shadow / proposed) rule maps to it.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG (
    technique_id   VARCHAR(20) PRIMARY KEY,
    technique_name VARCHAR(200),
    tactic_id      VARCHAR(10),
    source_tables  VARCHAR(500),
    hint           VARCHAR(1000),
    priority       NUMBER DEFAULT 3
);

MERGE INTO SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG t
USING (
    SELECT * FROM VALUES
    ('T1027',     'Obfuscated Files or Information: encoded commands', 'TA0005', 'ENDPOINT_PROCESSES',
     'Command lines with base64-encoded PowerShell (-enc / -EncodedCommand) or similar obfuscation.', 1),
    ('T1105',     'Ingress Tool Transfer', 'TA0011', 'ENDPOINT_PROCESSES',
     'Processes downloading payloads: PowerShell DownloadString/DownloadFile/Invoke-WebRequest, certutil -urlcache, bitsadmin /transfer.', 1),
    ('T1566.001', 'Phishing: Spearphishing Attachment', 'TA0001', 'ENDPOINT_PROCESSES',
     'Office applications (WINWORD.EXE, EXCEL.EXE, OUTLOOK.EXE) spawning cmd.exe, powershell.exe, wscript.exe or mshta.exe.', 1),
    ('T1005',     'Data from Local System: bulk sensitive file reads', 'TA0009', 'ENDPOINT_FILESYSTEM',
     'One user reading many files under confidential/sensitive paths within an hour, especially outside 07:00-19:00.', 2),
    ('T1112',     'Modify Registry', 'TA0005', 'ENDPOINT_REGISTRY',
     'Registry values pointing at executables in temp/user-writable paths (\\Temp\\, \\AppData\\, \\Users\\Public\\).', 2),
    ('T1136.003', 'Create Account: Cloud Account', 'TA0003', 'CLOUD_API',
     'Cloud API CreateUser / CreateLoginProfile / CreateAccessKey by a non-admin identity.', 3),
    ('T1562.001', 'Impair Defenses: Disable or Modify Tools', 'TA0005', 'ENDPOINT_PROCESSES',
     'Commands that disable security tooling: Set-MpPreference -Disable*, sc stop/config for defender or EDR services, taskkill of AV processes.', 3),
    ('T1595',     'Active Scanning', 'TA0043', 'NETWORK_TRAFFIC',
     'One external (non-RFC1918) source reaching 25+ distinct internal destination host/port pairs within 10 minutes.', 4)
    AS v(technique_id, technique_name, tactic_id, source_tables, hint, priority)
) s ON t.technique_id = s.technique_id
WHEN NOT MATCHED THEN INSERT (technique_id, technique_name, tactic_id, source_tables, hint, priority)
    VALUES (s.technique_id, s.technique_name, s.tactic_id, s.source_tables, s.hint, s.priority);

-- ---------------------------------------------------------------------------
-- 3. Policy, settings and the change feed
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_POLICY (
    change_type          VARCHAR(30) PRIMARY KEY,
    mode                 VARCHAR(30),   -- auto_live | shadow_then_promote | propose_only | off
    max_per_cycle        NUMBER,
    promote_after_hours  NUMBER,        -- minimum time in shadow before promotion
    min_recall           FLOAT,         -- required ground-truth recall when ground truth exists
    max_benign_matches   NUMBER,        -- max matches outside ground truth over the 7-day backtest
    description          VARCHAR(500),
    updated_by           VARCHAR(255),
    updated_at           TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

MERGE INTO SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_POLICY t
USING (
    SELECT * FROM VALUES
    ('new_rule',       'shadow_then_promote', 2, 24, 0.5, 10, 'Write a rule for an uncovered MITRE technique'),
    ('fix_broken',     'shadow_then_promote', 3, 6,  0.5, 25, 'Repair a custom rule that errors at runtime'),
    ('tune_filter',    'shadow_then_promote', 2, 24, 0.5, 25, 'Add exclusions learned from analyst false-positive verdicts'),
    ('tune_threshold', 'auto_live',           3, 0,  0.0, 0,  'Raise the threshold of a noisy custom rule'),
    ('disable_noisy',  'propose_only',        3, 0,  0.0, 0,  'Disable a rule whose findings are almost all false positives'),
    ('retire_silent',  'propose_only',        3, 0,  0.0, 0,  'Disable a custom rule that has produced nothing for 30 days'),
    ('new_parser',     'propose_only',        2, 24, 0.0, 0,  'Map a new log source into the CIM tables (OTel phase)')
    AS v(change_type, mode, max_per_cycle, promote_after_hours, min_recall, max_benign_matches, description)
) s ON t.change_type = s.change_type
WHEN NOT MATCHED THEN INSERT (change_type, mode, max_per_cycle, promote_after_hours, min_recall,
                              max_benign_matches, description, updated_by)
    VALUES (s.change_type, s.mode, s.max_per_cycle, s.promote_after_hours, s.min_recall,
            s.max_benign_matches, s.description, 'default');

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_SETTINGS (
    setting VARCHAR(50) PRIMARY KEY,
    value   VARIANT
);

MERGE INTO SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_SETTINGS t
USING (
    SELECT 'model' k, TO_VARIANT('claude-sonnet-4-5') v
    UNION ALL SELECT 'digest_email', TO_VARIANT('')          -- empty: the email of the user who runs the digest
    UNION ALL SELECT 'noisy_findings_7d', TO_VARIANT(50)
    UNION ALL SELECT 'fp_rate_disable', TO_VARIANT(0.8)
    UNION ALL SELECT 'fp_min_verdicts', TO_VARIANT(10)
    UNION ALL SELECT 'fp_filter_min', TO_VARIANT(3)
    UNION ALL SELECT 'silent_days', TO_VARIANT(30)
    UNION ALL SELECT 'guardrail_findings_per_day', TO_VARIANT(200)
    UNION ALL SELECT 'console_url', TO_VARIANT('')
) s ON t.setting = s.k
WHEN NOT MATCHED THEN INSERT (setting, value) VALUES (s.k, s.v);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES (
    change_id       VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    created_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    change_type     VARCHAR(30),
    mode            VARCHAR(30),     -- policy mode in force when proposed
    status          VARCHAR(20),     -- proposed | shadow | applied | promoted | approved | rejected | rolled_back | failed
    title           VARCHAR(500),
    rationale       VARCHAR(4000),
    technique_id    VARCHAR(20),
    rule_id         VARCHAR,         -- rule that carries the change (new rule or candidate)
    target_rule_id  VARCHAR,         -- existing rule being changed (fix / tune / disable)
    severity        NUMBER,
    evidence        VARIANT,         -- metrics, before/after, attempts, SQL
    decided_by      VARCHAR(255),
    decision_note   VARCHAR(1000)
);

-- ---------------------------------------------------------------------------
-- 4. Rule authoring context shared by every autopilot prompt
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.DETECTIONS.RULE_AUTHORING_CONTEXT()
RETURNS VARCHAR
AS
$$
'SQL contract: one read-only SELECT (CTEs allowed, no semicolon) returning exactly the columns
_time, user_name, src, dest, description (use NULL AS <col> where not applicable). Reference tables
only as fully qualified SNOWFLAKE_XDR.RAW_LOGS.<TABLE>. The platform applies the lookback filter on
_time itself; for aggregations return MAX(_time) AS _time and do the grouping/threshold in the query.
_time is TIMESTAMP_LTZ: use DATE_TRUNC, or cast with _time::TIMESTAMP_NTZ before TIME_SLICE.
Internal addresses are RFC1918 (10.x, 172.16-31.x, 192.168.x). Keep matches specific: a good rule
returns a handful of rows per week, not hundreds.
Snowflake string literals treat backslash as an escape character: inside a regex write \\\\s, \\\\d, \\\\.
(double backslash) or use POSIX classes such as [[:space:]] and [[:digit:]]. Prefer ILIKE, CONTAINS
and simple patterns over complex regexes. The full command line is in process; process_name may be
a launcher such as cmd.exe, so match on process when the command matters.
Many columns are often NULL (parent_process, user_name, src): NOT (...) and comparisons on NULL drop the
row silently, so wrap optional columns in COALESCE(col, '') inside exclusion filters.
Tables and columns (all have _time, action, vendor_product):
AUTHENTICATION: app, authentication_method, authentication_service, dest, reason, signature, signature_id, src, src_user, user_name, user_type, user_role, user_agent, geo_city, geo_country.
ENDPOINT_PROCESSES: dest, user_name, process (full command line), process_name, process_path, process_hash, parent_process, parent_process_name, original_file_name, os.
ENDPOINT_FILESYSTEM: dest, user_name, file_name, file_path, file_hash, file_size, process_name.
ENDPOINT_REGISTRY: dest, user_name, registry_path, registry_key_name, registry_value_name, registry_value_data, process_name.
ENDPOINT_SERVICES: dest, user_name, service_name, service_path, start_mode, status.
NETWORK_TRAFFIC: src, src_ip, src_port, dest, dest_ip, dest_port, transport, protocol, app, bytes, bytes_in, bytes_out, packets, direction, rule, geo_src_country, geo_dest_country.
INTRUSION_DETECTION: src, src_ip, dest, dest_ip, dest_port, signature, signature_id, severity, category.
DNS_ACTIVITY: src, dest, query, query_type, answer, reply_code, query_length, answer_count, ttl.
WEB_ACTIVITY: src, dest, url, uri_path, uri_query, http_method, status, http_user_agent, http_referrer, bytes_in, bytes_out, category, threat_category.
CLOUD_API: command, user_name, user_type, src, dest, object, object_category, result, reason, app, vendor_account, vendor_region.'
$$;

-- ---------------------------------------------------------------------------
-- 5. The autopilot engine (one Python procedure, several commands)
--    P_COMMAND: cycle | evaluate | decide | digest | set_policy
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT(
    P_COMMAND VARCHAR, P_ARG VARCHAR, P_NOTE VARCHAR
)
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
CR = DB + ".DETECTIONS.CUSTOM_RULES"
CH = DB + ".DETECTIONS.AUTOPILOT_CHANGES"
GT = DB + ".REFERENCE.V_ATTACK_GROUND_TRUTH"
BACKTEST_MIN = 10080          # regression backtest window: 7 days
OPEN = ("proposed", "shadow")
LIVE = ("applied", "promoted", "approved")
MODES = ("auto_live", "shadow_then_promote", "propose_only", "off")
TECH_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
TACTIC_RE = re.compile(r"^TA[0-9]{4}$")
CATEGORIES = ("identity", "endpoint", "network", "cloud", "application", "custom")


# ---------------------------------------------------------------- helpers
def rows(s, sql, params=None):
    return [r.as_dict() for r in s.sql(sql, params=params).collect()]


def one(s, sql, params=None):
    r = rows(s, sql, params)
    return r[0] if r else None


def settings(s):
    out = {}
    for r in rows(s, f"SELECT setting, value FROM {DB}.DETECTIONS.AUTOPILOT_SETTINGS"):
        v = r["VALUE"]
        out[r["SETTING"]] = json.loads(v) if isinstance(v, str) else v
    return out


def policy(s):
    return {r["CHANGE_TYPE"]: r for r in rows(s, f"SELECT * FROM {DB}.DETECTIONS.AUTOPILOT_POLICY")}


def record(s, change_type, mode, status, title, rationale, technique=None, rule_id=None,
           target=None, severity=None, evidence=None):
    cid = one(s, "SELECT UUID_STRING() AS id")["ID"]
    s.sql(f"""INSERT INTO {CH} (change_id, change_type, mode, status, title, rationale, technique_id,
                rule_id, target_rule_id, severity, evidence, decided_by)
              SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, PARSE_JSON(?), ?""",
          params=[cid, change_type, mode, status, title[:500], (rationale or "")[:4000], technique,
                  rule_id, target, severity, json.dumps(evidence or {}, default=str),
                  "autopilot" if status not in OPEN else None]).collect()
    return cid


def set_status(s, cid, status, by, note=None, evidence_patch=None):
    s.sql(f"""UPDATE {CH} SET status = ?, decided_by = ?, decision_note = COALESCE(?, decision_note),
                updated_at = CURRENT_TIMESTAMP() WHERE change_id = ?""",
          params=[status, by, note, cid]).collect()
    if evidence_patch:
        patch_evidence(s, cid, "decision", evidence_patch)


def patch_evidence(s, cid, key, value):
    s.sql(f"""UPDATE {CH} SET evidence = OBJECT_INSERT(COALESCE(evidence, OBJECT_CONSTRUCT()), ?, PARSE_JSON(?), TRUE),
                updated_at = CURRENT_TIMESTAMP() WHERE change_id = ?""",
          params=[key, json.dumps(value, default=str), cid]).collect()


def complete(s, model, prompt):
    txt = one(s, "SELECT SNOWFLAKE.CORTEX.COMPLETE(?, ?) AS r", [model, prompt])["R"] or ""
    a, b = txt.find("{"), txt.rfind("}")
    if a < 0 or b <= a:
        raise ValueError("model did not return JSON")
    return json.loads(txt[a:b + 1])


def violation(s, sql):
    return one(s, f"SELECT {DB}.DASHBOARDS.RULE_SQL_VIOLATION(?) AS v", [sql])["V"]


def snapshot(s, rule_id):
    s.sql(f"""INSERT INTO {DB}.DETECTIONS.CUSTOM_RULE_HISTORY
                (rule_id, version, name, code, language, severity, threshold_count, enabled, changed_by)
              SELECT rule_id, version, name, code, language, severity, threshold_count, enabled, 'autopilot'
              FROM {CR} WHERE rule_id = ?""", params=[rule_id]).collect()


def rule(s, rule_id):
    return one(s, f"SELECT * FROM {CR} WHERE rule_id = ?", [rule_id])


def drop_candidate(s, rule_id):
    s.sql(f"DELETE FROM {DB}.DETECTIONS.SHADOW_FINDINGS WHERE rule_id = ?", params=[rule_id]).collect()
    s.sql(f"DELETE FROM {CR} WHERE rule_id = ? AND managed_by = 'autopilot_candidate'", params=[rule_id]).collect()


# ---------------------------------------------------------------- evaluation
def evaluate(s, rule_id, fp_keys=None):
    """Backtest a rule over 7 days against ground truth. Never writes findings."""
    r = rule(s, rule_id)
    if not r:
        return {"error": "rule not found"}
    tech = (r.get("MITRE_TECHNIQUE_ID") or "").strip().upper()
    root = tech.split(".")[0] if TECH_RE.match(tech) else ""
    try:
        if r["LANGUAGE"] == "sql":
            v = violation(s, r["CODE"])
            if v and r.get("MANAGED_BY") != "human":
                return {"error": "unsafe SQL: " + v}
            match_sql = (f"SELECT _time, user_name::VARCHAR AS user_name, src::VARCHAR AS src, dest::VARCHAR AS dest "
                         f"FROM ({r['CODE']}) WHERE _time > DATEADD('minute', -{BACKTEST_MIN}, CURRENT_TIMESTAMP())")
        else:
            src = (r.get("SOURCE_TABLE") or "").upper()
            if not re.match(r"^[A-Z_]+$", src):
                return {"error": "invalid source table"}
            status = one(s, f"CALL {DB}.DETECTIONS.COMPILE_CUSTOM_RULE_UDF(?)", [rule_id])
            short = one(s, "SELECT SUBSTR(SHA1(?), 0, 12) AS h", [rule_id])["H"]
            match_sql = (f"SELECT _time, user_name::VARCHAR AS user_name, src::VARCHAR AS src, dest::VARCHAR AS dest FROM "
                         f"(SELECT t.*, OBJECT_CONSTRUCT(*) AS XDR_ROW FROM {DB}.RAW_LOGS.{src} t "
                         f"WHERE t._time > DATEADD('minute', -{BACKTEST_MIN}, CURRENT_TIMESTAMP())) "
                         f"WHERE {DB}.DETECTIONS.CUSTOM_R{short}(XDR_ROW) = 1")
        fp_arr = json.dumps(sorted({k for k in (fp_keys or []) if k}))
        m = one(s, f"""
            WITH mm AS (SELECT ROW_NUMBER() OVER (ORDER BY _time) AS id, * FROM ({match_sql})),
            gt AS (SELECT * FROM {GT}
                   WHERE _time > DATEADD('minute', -{BACKTEST_MIN + 180}, CURRENT_TIMESTAMP())),
            hits AS (
                SELECT DISTINCT mm.id, gt.campaign_id, gt.technique_id
                FROM mm JOIN gt
                  ON ARRAYS_OVERLAP(ARRAY_CONSTRUCT_COMPACT(mm.user_name, mm.src, mm.dest), gt.entity_keys)
                 AND ABS(DATEDIFF('minute', mm._time, gt._time)) <= 180)
            SELECT
              (SELECT COUNT(*) FROM mm) AS matches,
              (SELECT COUNT(DISTINCT id) FROM hits) AS tp,
              (SELECT ARRAY_AGG(DISTINCT campaign_id) FROM hits) AS hit_campaigns,
              (SELECT ARRAY_AGG(DISTINCT campaign_id) FROM gt
                WHERE '{root}' <> '' AND SPLIT_PART(technique_id, '.', 1) = '{root}') AS expected,
              (SELECT ARRAY_AGG(DISTINCT campaign_id) FROM hits
                WHERE '{root}' <> '' AND SPLIT_PART(technique_id, '.', 1) = '{root}') AS hit_expected,
              (SELECT COUNT(*) FROM mm
                WHERE ARRAYS_OVERLAP(ARRAY_CONSTRUCT_COMPACT(user_name, src, dest), PARSE_JSON(?))) AS fp_overlap,
              (SELECT ARRAY_AGG(OBJECT_CONSTRUCT('time', _time, 'user', user_name, 'src', src, 'dest', dest))
                 WITHIN GROUP (ORDER BY _time DESC) FROM (SELECT * FROM mm ORDER BY _time DESC LIMIT 5)) AS sample_rows
        """, [fp_arr])
    except Exception as e:
        return {"error": str(e)[:500]}

    def arr(v):
        return json.loads(v) if isinstance(v, str) else (v or [])

    expected, hit_expected = arr(m["EXPECTED"]), arr(m["HIT_EXPECTED"])
    matches, tp = int(m["MATCHES"]), int(m["TP"])
    return {
        "matches": matches,
        "true_positive": tp,
        "benign": matches - tp,
        "hit_campaigns": arr(m["HIT_CAMPAIGNS"]),
        "expected_campaigns": expected,
        "recall": round(len(hit_expected) / len(expected), 2) if expected else None,
        "precision": round(tp / matches, 2) if matches else None,
        "fp_overlap": int(m["FP_OVERLAP"]),
        "shadow_findings": int(one(s, f"SELECT COUNT(*) AS n FROM {DB}.DETECTIONS.SHADOW_FINDINGS WHERE rule_id = ?",
                                   [rule_id])["N"]),
        "sample": arr(m["SAMPLE_ROWS"]),
        "backtest_days": BACKTEST_MIN // 1440,
    }


def passes(metrics, pol, baseline=None):
    """Policy gate. Returns (ok, reason)."""
    if metrics.get("error"):
        return False, "error: " + metrics["error"][:200]
    if baseline is not None:
        if baseline.get("recall") is not None and (metrics.get("recall") or 0) < baseline["recall"]:
            return False, "recall dropped vs current version"
        if not (metrics["fp_overlap"] < baseline.get("fp_overlap", 0) or metrics["benign"] < baseline.get("benign", 0)):
            return False, "no reduction in noise vs current version"
        return True, (f"no recall loss; FP-entity matches {baseline.get('fp_overlap', 0)} -> {metrics['fp_overlap']}, "
                      f"benign {baseline.get('benign', 0)} -> {metrics['benign']}")
    if metrics["recall"] is None:
        if metrics["matches"] == 0:
            return False, "no ground truth for this technique and no matches yet - waiting for evidence"
        if metrics["benign"] > (pol.get("MAX_BENIGN_MATCHES") or 0):
            return False, f"{metrics['benign']} matches outside ground truth (max {pol.get('MAX_BENIGN_MATCHES')})"
        hit = metrics.get("hit_campaigns") or []
        return True, ("no ground truth for this technique; match volume within policy"
                      + (f"; also caught campaign(s) {', '.join(hit)}" if hit else ""))
    if metrics["recall"] < (pol.get("MIN_RECALL") or 0):
        return False, f"recall {metrics['recall']} below {pol.get('MIN_RECALL')}"
    if metrics["benign"] > (pol.get("MAX_BENIGN_MATCHES") or 0):
        return False, f"{metrics['benign']} benign matches (max {pol.get('MAX_BENIGN_MATCHES')})"
    return True, f"recall {metrics['recall']}, {metrics['benign']} benign matches"


def to_int(v, default, lo, hi):
    try:
        return max(lo, min(hi, int(float(v))))
    except (TypeError, ValueError):
        return default


def cap(pol):
    v = pol.get("MAX_PER_CYCLE")
    return 1 if v is None else int(v)


def evidence_of(change):
    ev = change.get("EVIDENCE")
    return ev if isinstance(ev, dict) else json.loads(ev or "{}")


# ---------------------------------------------------------------- authoring
def author(s, cfg, task, base_rule=None, attempts=3):
    """Ask Cortex for rule SQL, save it as a disabled candidate, evaluate, self-repair."""
    ctx = one(s, f"SELECT {DB}.DETECTIONS.RULE_AUTHORING_CONTEXT() AS c")["C"]
    feedback, history = "", []
    for attempt in range(1, attempts + 1):
        prompt = (
            "You are a senior detection engineer maintaining a Snowflake-native XDR. "
            + task
            + "\n\n" + ctx
            + ("\n\nCurrent rule SQL:\n" + base_rule["CODE"] if base_rule else "")
            + feedback
            + '\n\nReturn ONLY JSON: {"name": "...", "description": "one sentence", "category": '
              '"identity|endpoint|network|cloud|application|custom", "severity": 1-5, "mitre_tactic_id": "TA00XX", '
              '"mitre_technique_id": "TXXXX or TXXXX.XXX", "rule_sql": "...", "lookback_minutes": 1440, '
              '"rationale": "why this logic, what it will and will not catch"}'
        )
        try:
            j = complete(s, cfg.get("model", "claude-sonnet-4-5"), prompt)
        except Exception as e:
            history.append({"attempt": attempt, "error": str(e)[:300]})
            feedback = "\n\nYour previous answer was not valid JSON. Return only the JSON object."
            continue
        sql = re.sub(r";\s*$", "", (j.get("rule_sql") or "").strip())
        v = violation(s, sql)
        if v:
            history.append({"attempt": attempt, "error": "guard: " + v})
            feedback = f"\n\nYour previous SQL was rejected: it {v}. Fix that."
            continue
        tech = (j.get("mitre_technique_id") or "").upper()
        tac = (j.get("mitre_tactic_id") or "").upper()
        cat = (j.get("category") or "custom").lower()
        rid = one(s, "SELECT UUID_STRING() AS id")["ID"]
        s.sql(f"""INSERT INTO {CR} (rule_id, name, description, category, severity, mitre_tactic_id,
                    mitre_technique_id, language, source_table, code, threshold_count, threshold_window_minutes,
                    lookback_minutes, enabled, test_mode, created_by, managed_by)
                  SELECT ?, ?, ?, ?, ?, ?, ?, 'sql', NULL, ?, 1, 60, ?, FALSE, FALSE, 'autopilot', ?""",
              params=[rid, (j.get("name") or "Autopilot rule")[:200], (j.get("description") or "")[:2000],
                      cat if cat in CATEGORIES else "custom",
                      to_int(j.get("severity"), 3, 1, 5),
                      tac if TACTIC_RE.match(tac) else None, tech if TECH_RE.match(tech) else None,
                      sql, to_int(j.get("lookback_minutes"), 1440, 60, 20160),
                      "autopilot_candidate" if base_rule else "autopilot"]).collect()
        metrics = evaluate(s, rid)
        if metrics.get("error"):
            history.append({"attempt": attempt, "error": metrics["error"][:300]})
            s.sql(f"DELETE FROM {CR} WHERE rule_id = ?", params=[rid]).collect()
            feedback = f"\n\nYour previous SQL failed when executed: {metrics['error'][:400]}\nFix it."
            continue
        history.append({"attempt": attempt, "ok": True})
        return rid, j, metrics, history
    return None, None, None, history


# ---------------------------------------------------------------- self-correction
def missed_examples(s, rule_id, limit=3):
    """Raw events of the rule's technique that the rule does not match (for revision prompts)."""
    r = rule(s, rule_id)
    root = (r.get("MITRE_TECHNIQUE_ID") or "").split(".")[0]
    if not TECH_RE.match(root):
        return []
    out = []
    for g in rows(s, f"""SELECT source_table, _time, user_name, src, dest FROM {GT}
                         WHERE SPLIT_PART(technique_id, '.', 1) = ?
                           AND _time > DATEADD('minute', -{BACKTEST_MIN}, CURRENT_TIMESTAMP())
                         ORDER BY _time LIMIT {limit}""", [root]):
        tbl = g["SOURCE_TABLE"]
        if not re.match(r"^[A-Z_]+$", tbl or ""):
            continue
        raw = one(s, f"""SELECT OBJECT_CONSTRUCT(*) AS o FROM {DB}.RAW_LOGS.{tbl}
                         WHERE _time = ?::TIMESTAMP_LTZ AND COALESCE(dest, '') = COALESCE(?, '') LIMIT 1""",
                  [str(g["_TIME"]), g["DEST"]])
        if raw:
            o = raw["O"] if isinstance(raw["O"], dict) else json.loads(raw["O"])
            keep = {k: v for k, v in o.items() if v not in (None, "") and k not in
                    ("_RAW", "EVENT_ID", "INGESTION_TIME", "SOURCE", "SOURCETYPE", "INDEX_NAME", "HOST")}
            out.append({"table": tbl, **keep})
    return out


def revise(s, cfg, ch, metrics):
    """Rewrite a shadow rule that misses labelled attacks, feeding it the missed events."""
    ev = evidence_of(ch)
    n = int(ev.get("revisions", 0))
    base = rule(s, ch["RULE_ID"])
    missed = missed_examples(s, ch["RULE_ID"])
    if n >= 2 or not base or not missed:
        return None
    task = (f"This shadow rule '{base['NAME']}' ({base.get('MITRE_TECHNIQUE_ID')}) misses labelled attack activity "
            f"(recall {metrics.get('recall')}, {metrics.get('matches')} matches). These real attack events must match:\n"
            + json.dumps(missed, default=str)[:3000]
            + "\nGeneralise the logic so they match (for example the encoded command may run under a parent like "
              "cmd.exe /c), without becoming noisy. Keep the technique mapping.")
    rid, j, m2, hist = author(s, cfg, task, base_rule=base)
    if rid and (m2.get("recall") or 0) <= (metrics.get("recall") or 0):
        # Not an improvement: one more try with the concrete result as feedback
        drop_candidate(s, rid)
        task += (f"\n\nYour previous rewrite still matched {m2.get('matches')} rows and none of the events above. "
                 "Check backslash escaping in regexes (use \\\\s or [[:space:]]) or use ILIKE instead.")
        rid, j, m2, hist2 = author(s, cfg, task, base_rule=base, attempts=2)
        hist += hist2
        if rid and (m2.get("recall") or 0) <= (metrics.get("recall") or 0):
            drop_candidate(s, rid)
            rid = None
    if not rid:
        patch_evidence(s, ch["CHANGE_ID"], "revisions", n + 1)
        return {"revised": False, "attempts": hist}
    new_code = rule(s, rid)["CODE"]
    drop_candidate(s, rid)
    snapshot(s, ch["RULE_ID"])
    s.sql(f"""UPDATE {CR} SET code = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP()
              WHERE rule_id = ?""", params=[new_code, ch["RULE_ID"]]).collect()
    s.sql(f"DELETE FROM {DB}.DETECTIONS.SHADOW_FINDINGS WHERE rule_id = ?", params=[ch["RULE_ID"]]).collect()
    after = evaluate(s, ch["RULE_ID"])
    log = ev.get("revision_log", []) + [{"revision": n + 1, "missed_examples": len(missed),
                                          "before": {k: metrics.get(k) for k in ("recall", "matches", "benign")},
                                          "after": {k: after.get(k) for k in ("recall", "matches", "benign")},
                                          "why": (j.get("rationale") or "")[:600]}]
    patch_evidence(s, ch["CHANGE_ID"], "revisions", n + 1)
    patch_evidence(s, ch["CHANGE_ID"], "revision_log", log)
    patch_evidence(s, ch["CHANGE_ID"], "sql", new_code)
    return {"revised": True, "metrics": after}


# ---------------------------------------------------------------- apply / revert
def apply_candidate(s, change):
    """Copy a candidate's SQL onto its target rule (snapshotting history) and drop the candidate."""
    cand, target = rule(s, change["RULE_ID"]), change["TARGET_RULE_ID"]
    if not cand or not target:
        return "candidate or target missing"
    snapshot(s, target)
    s.sql(f"""UPDATE {CR} SET code = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP()
              WHERE rule_id = ? AND NOT COALESCE(pinned, FALSE)""", params=[cand["CODE"], target]).collect()
    drop_candidate(s, cand["RULE_ID"])
    return "applied to " + target


def set_rule_enabled(s, rule_id, enabled):
    n = s.sql(f"UPDATE {DB}.DETECTIONS.DETECTION_RULES SET enabled = ? WHERE rule_id = ?",
              params=[enabled, rule_id]).collect()[0][0]
    if not n:
        s.sql(f"UPDATE {CR} SET enabled = ?, test_mode = FALSE, updated_at = CURRENT_TIMESTAMP() WHERE rule_id = ?",
              params=[enabled, rule_id]).collect()


def go_live(s, change):
    ct = change["CHANGE_TYPE"]
    if ct == "new_rule":
        s.sql(f"UPDATE {CR} SET enabled = TRUE, test_mode = FALSE, updated_at = CURRENT_TIMESTAMP() WHERE rule_id = ?",
              params=[change["RULE_ID"]]).collect()
        return "rule enabled"
    if ct in ("fix_broken", "tune_filter"):
        return apply_candidate(s, change)
    if ct in ("disable_noisy", "retire_silent"):
        set_rule_enabled(s, change["TARGET_RULE_ID"], False)
        return "rule disabled"
    if ct == "tune_threshold":
        ev = evidence_of(change)
        snapshot(s, change["TARGET_RULE_ID"])
        s.sql(f"""UPDATE {CR} SET threshold_count = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP()
                  WHERE rule_id = ? AND NOT COALESCE(pinned, FALSE)""",
              params=[ev["after"]["threshold_count"], change["TARGET_RULE_ID"]]).collect()
        return "threshold raised"
    if ct == "suppress_entity":
        ev = evidence_of(change)
        sid = one(s, "SELECT UUID_STRING() AS id")["ID"]
        s.sql(f"""INSERT INTO {DB}.DETECTIONS.SUPPRESSION_RULES (suppression_id, rule_id, entity, reason, created_by, expires_at)
                  SELECT ?, ?, ?, ?, ?, DATEADD('day', ?, CURRENT_TIMESTAMP())""",
              params=[sid, change["TARGET_RULE_ID"], ev["entity"], ev.get("reason", "approved autopilot suppression")[:500],
                      change.get("DECIDED_BY") or "autopilot", int(ev.get("expires_days", 30))]).collect()
        patch_evidence(s, change["CHANGE_ID"], "suppression_id", sid)
        return f"suppression created for {ev['entity']} ({ev.get('expires_days', 30)} days, spot-checked)"
    if ct == "intel_allowlist":
        ev = evidence_of(change)
        s.sql(f"""INSERT INTO {DB}.REFERENCE.INTEL_WARNINGLIST (list_name, entry_type, value, ip_start, ip_end, reason, added_by)
                  SELECT 'local', IFF(? = 'ip', 'cidr', IFF(? IN ('domain', 'url'), 'hostname', 'string')), LOWER(?),
                         IFF(? = 'ip', TRY_CAST(PARSE_IP(? || '/32', 'INET', 1):ipv4_range_start::VARCHAR AS NUMBER), NULL),
                         IFF(? = 'ip', TRY_CAST(PARSE_IP(? || '/32', 'INET', 1):ipv4_range_end::VARCHAR AS NUMBER), NULL),
                         ?, ?""",
              params=[ev["ioc_type"], ev["ioc_type"], ev["ioc_value"], ev["ioc_type"], ev["ioc_value"],
                      ev["ioc_type"], ev["ioc_value"], ev.get("reason", "analyst false positives")[:500],
                      change.get("DECIDED_BY") or "autopilot"]).collect()
        s.sql(f"""UPDATE {DB}.REFERENCE.THREAT_INTEL_IOCS SET status = 'allowlisted', active = FALSE,
                    status_reason = 'allowlisted after analyst false positives', updated_at = CURRENT_TIMESTAMP()
                  WHERE ioc_type = ? AND LOWER(ioc_value) = LOWER(?)""", params=[ev["ioc_type"], ev["ioc_value"]]).collect()
        return f"{ev['ioc_value']} allowlisted"
    if ct == "recheck_verdicts":
        ev = evidence_of(change)
        n = s.sql(f"""UPDATE {DB}.DETECTIONS.DETECTION_FINDINGS SET status = 'new', disposition = NULL,
                        disposition_source = NULL, triage_notes = COALESCE(triage_notes || ' | ', '')
                        || 'Re-opened for re-check: other detections now corroborate this entity'
                      WHERE rule_id = ? AND COALESCE(user_name, src, dest, 'unknown') = ?
                        AND disposition = 'false_positive'""",
                  params=[change["TARGET_RULE_ID"], ev["entity"]]).collect()[0][0]
        s.sql(f"CALL {DB}.DETECTIONS.TRAIN_FP_MODEL()").collect()
        return f"re-opened {n} finding(s) for re-check; FP model retrained"
    return "nothing to apply"


def revert(s, change):
    ct = change["CHANGE_TYPE"]
    ev = evidence_of(change)
    if ct == "new_rule":
        s.sql(f"UPDATE {CR} SET enabled = FALSE, test_mode = FALSE WHERE rule_id = ?",
              params=[change["RULE_ID"]]).collect()
        return "rule disabled"
    before = ev.get("before") or {}
    target = change["TARGET_RULE_ID"]
    if ct in ("disable_noisy", "retire_silent"):
        set_rule_enabled(s, target, True)
        return "rule re-enabled"
    if ct == "suppress_entity":
        s.sql(f"UPDATE {DB}.DETECTIONS.SUPPRESSION_RULES SET expires_at = CURRENT_TIMESTAMP() WHERE suppression_id = ?",
              params=[ev.get("suppression_id")]).collect()
        return "suppression ended"
    if ct == "intel_allowlist":
        s.sql(f"DELETE FROM {DB}.REFERENCE.INTEL_WARNINGLIST WHERE list_name = 'local' AND value = LOWER(?)",
              params=[ev["ioc_value"]]).collect()
        s.sql(f"""UPDATE {DB}.REFERENCE.THREAT_INTEL_IOCS SET status = 'active', status_reason = NULL
                  WHERE ioc_type = ? AND LOWER(ioc_value) = LOWER(?)""", params=[ev["ioc_type"], ev["ioc_value"]]).collect()
        s.sql(f"CALL {DB}.REFERENCE.SCORE_IOCS()").collect()
        return "indicator restored"
    if ct == "recheck_verdicts":
        return "re-check cannot be rolled back; record new verdicts in Triage"
    if before:
        snapshot(s, target)
        s.sql(f"""UPDATE {CR} SET code = ?, threshold_count = ?, version = version + 1,
                    updated_at = CURRENT_TIMESTAMP() WHERE rule_id = ?""",
              params=[before.get("code"), before.get("threshold_count"), target]).collect()
        return "restored previous version"
    return "no previous version stored"


# ---------------------------------------------------------------- cycle
def open_targets(s):
    r = rows(s, f"""SELECT target_rule_id, technique_id, change_type FROM {CH}
                   WHERE status IN ('proposed', 'shadow')
                      OR (status = 'rejected' AND updated_at > DATEADD('day', -30, CURRENT_TIMESTAMP()))
                      OR (status = 'rolled_back' AND decided_by NOT LIKE 'autopilot%'
                          AND updated_at > DATEADD('day', -30, CURRENT_TIMESTAMP()))
                      OR (status = 'failed' AND updated_at > DATEADD('day', -2, CURRENT_TIMESTAMP()))""")
    return {x["TARGET_RULE_ID"] for x in r if x["TARGET_RULE_ID"]}, {x["TECHNIQUE_ID"] for x in r if x["TECHNIQUE_ID"]}


def decide_mode(change_type, pol, severity=None, target=None):
    mode = (pol.get(change_type) or {}).get("MODE", "propose_only")
    # Hard limits: never auto-disable severity >= 4; built-in rules only via proposals
    if change_type in ("disable_noisy", "retire_silent") and ((severity or 0) >= 4 or (target or "").startswith("DET-")):
        mode = "propose_only" if mode != "off" else "off"
    # Overturning human verdicts is always a human decision
    if change_type == "recheck_verdicts":
        mode = "propose_only"
    # Suppressing a high-severity rule needs a human too
    if change_type == "suppress_entity" and (severity or 0) >= 4 and mode == "auto_live":
        mode = "propose_only"
    return mode


def cycle(s):
    cfg, pol = settings(s), policy(s)
    summary = {"promoted": [], "rolled_back": [], "created": [], "skipped": [], "failed": []}

    # 1. Guardrails on recent live changes: errors or floods roll back automatically
    for ch in rows(s, f"""SELECT * FROM {CH} WHERE status IN ('applied', 'promoted', 'approved')
                          AND updated_at > DATEADD('day', -7, CURRENT_TIMESTAMP())"""):
        rid = ch["TARGET_RULE_ID"] if ch["CHANGE_TYPE"] != "new_rule" else ch["RULE_ID"]
        if not rid or ch["CHANGE_TYPE"] in ("disable_noisy", "retire_silent"):
            continue
        errs = one(s, f"""SELECT COUNT(*) AS n, MAX(LEFT(error_message, 200)) AS e
                          FROM {DB}.DETECTIONS.CUSTOM_RULE_ERRORS WHERE rule_id = ? AND error_time > ?""",
                   [rid, str(ch["UPDATED_AT"])])
        flood = one(s, f"""SELECT COUNT(*) AS n FROM {DB}.DETECTIONS.DETECTION_FINDINGS
                           WHERE rule_id = ? AND detection_time > DATEADD('day', -1, CURRENT_TIMESTAMP())""", [rid])
        limit = int(cfg.get("guardrail_findings_per_day", 200))
        if errs["N"] or flood["N"] > limit:
            reason = (f"runtime errors after the change: {errs['E']}" if errs["N"]
                      else f"{flood['N']} findings in 24h exceeds guardrail {limit}")
            result = revert(s, ch)
            set_status(s, ch["CHANGE_ID"], "rolled_back", "autopilot:guardrail", reason, {"result": result})
            summary["rolled_back"].append({"title": ch["TITLE"], "reason": reason})

    # 2. Promote shadow changes that met their policy criteria
    for ch in rows(s, f"SELECT * FROM {CH} WHERE status = 'shadow'"):
        p = pol.get(ch["CHANGE_TYPE"]) or {}
        age_h = one(s, "SELECT DATEDIFF('minute', ?::TIMESTAMP_LTZ, CURRENT_TIMESTAMP()) / 60 AS h",
                    [str(ch["CREATED_AT"])])["H"]
        ev = evidence_of(ch)
        if ch["CHANGE_TYPE"] == "tune_filter":
            metrics = evaluate(s, ch["RULE_ID"], ev.get("fp_entities"))
            baseline = ev.get("baseline_metrics")
        else:
            metrics, baseline = evaluate(s, ch["RULE_ID"]), None
        ok, reason = passes(metrics, p, baseline)
        # Self-correction: a shadow rule that misses labelled attacks gets rewritten with the misses
        if (not ok and ch["CHANGE_TYPE"] in ("new_rule", "fix_broken")
                and (metrics.get("recall") is not None and metrics["recall"] < float(p.get("MIN_RECALL") or 0))):
            rv = revise(s, cfg, ch, metrics)
            if rv and rv.get("revised"):
                metrics = rv["metrics"]
                ok, reason = passes(metrics, p, baseline)
                reason = "revised after missing labelled attacks; " + reason
                summary.setdefault("revised", []).append({"title": ch["TITLE"], "recall": metrics.get("recall")})
        patch_evidence(s, ch["CHANGE_ID"], "last_evaluation", {"metrics": metrics, "ok": ok, "reason": reason,
                                                                "age_hours": float(age_h)})
        if (not ok and ch["CHANGE_TYPE"] in ("new_rule", "fix_broken") and metrics.get("recall") is not None
                and int(evidence_of(one(s, f"SELECT evidence FROM {CH} WHERE change_id = ?",
                                        [ch["CHANGE_ID"]])).get("revisions", 0)) >= 2):
            # Revision budget spent and still missing attacks: retire the shadow rule, retry fresh later
            s.sql(f"UPDATE {CR} SET test_mode = FALSE, enabled = FALSE WHERE rule_id = ?",
                  params=[ch["RULE_ID"]]).collect()
            set_status(s, ch["CHANGE_ID"], "failed", "autopilot",
                       "still " + reason + " after 2 revisions; shadow rule retired, technique will be retried")
            summary["failed"].append(ch["TITLE"])
            continue
        if ok and float(age_h) >= float(p.get("PROMOTE_AFTER_HOURS") or 0):
            result = go_live(s, ch)
            set_status(s, ch["CHANGE_ID"], "promoted", "autopilot", reason, {"result": result})
            summary["promoted"].append({"title": ch["TITLE"], "reason": reason})

    busy_targets, busy_techniques = open_targets(s)

    def handle(change_type, title, rationale, rid=None, target=None, technique=None, severity=None,
               evidence=None, ok=True, reason=""):
        mode = decide_mode(change_type, pol, severity, target)
        if mode == "off":
            if rid:
                drop_candidate(s, rid) if target else s.sql(f"DELETE FROM {CR} WHERE rule_id = ?", params=[rid]).collect()
            return
        status = "proposed"
        if mode == "shadow_then_promote" and rid:
            s.sql(f"UPDATE {CR} SET test_mode = TRUE WHERE rule_id = ?", params=[rid]).collect()
            status = "shadow"
        cid = record(s, change_type, mode, status, title, rationale, technique, rid, target, severity, evidence)
        if mode == "auto_live":
            if ok:
                change = one(s, f"SELECT * FROM {CH} WHERE change_id = ?", [cid])
                result = go_live(s, change)
                set_status(s, cid, "applied", "autopilot", reason, {"result": result})
                status = "applied"
            else:
                patch_evidence(s, cid, "auto_live_blocked", reason)
        summary["created"].append({"type": change_type, "title": title, "status": status})

    # 3. new_rule: uncovered backlog techniques
    p = pol.get("new_rule") or {}
    if p.get("MODE") != "off":
        gaps = rows(s, f"""
            SELECT b.* FROM {DB}.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG b
            WHERE NOT EXISTS (SELECT 1 FROM {DB}.DETECTIONS.DETECTION_RULES r
                              WHERE r.enabled AND r.mitre_technique_id = b.technique_id)
              AND NOT EXISTS (SELECT 1 FROM {CR} c
                              WHERE (c.enabled OR c.test_mode) AND c.mitre_technique_id = b.technique_id)
            ORDER BY b.priority, b.technique_id""")
        made = 0
        for g in gaps:
            if made >= cap(p):
                break
            if g["TECHNIQUE_ID"] in busy_techniques:
                continue
            task = (f"Write a new detection rule for MITRE {g['TECHNIQUE_ID']} {g['TECHNIQUE_NAME']} "
                    f"(tactic {g['TACTIC_ID']}). Use table(s) {g['SOURCE_TABLES']}. What to look for: {g['HINT']} "
                    f"Use mitre_technique_id {g['TECHNIQUE_ID']} and mitre_tactic_id {g['TACTIC_ID']}."
                    + sigma_reference(s, g))
            rid, j, metrics, hist = author(s, cfg, task)
            if not rid:
                record(s, "new_rule", p.get("MODE"), "failed", f"Could not write a rule for {g['TECHNIQUE_ID']}",
                       "All authoring attempts failed validation.", g["TECHNIQUE_ID"], evidence={"attempts": hist})
                summary["failed"].append(g["TECHNIQUE_ID"])
                continue
            ok, reason = passes(metrics, p)
            handle("new_rule", f"New rule: {j.get('name')} ({g['TECHNIQUE_ID']})", j.get("rationale"),
                   rid=rid, technique=g["TECHNIQUE_ID"], severity=to_int(j.get("severity"), 3, 1, 5),
                   evidence={"metrics": metrics, "gate": {"ok": ok, "reason": reason}, "attempts": hist,
                             "sql": rule(s, rid)["CODE"]}, ok=ok, reason=reason)
            made += 1

    # 4. fix_broken: custom rules erroring in the last 24h
    p = pol.get("fix_broken") or {}
    if p.get("MODE") != "off":
        broken = rows(s, f"""
            SELECT c.*, e.err FROM {CR} c
            JOIN (SELECT rule_id, MAX(LEFT(error_message, 400)) AS err FROM {DB}.DETECTIONS.CUSTOM_RULE_ERRORS
                  WHERE error_time > DATEADD('day', -1, CURRENT_TIMESTAMP()) GROUP BY rule_id) e
              ON e.rule_id = c.rule_id
            WHERE c.language = 'sql' AND (c.enabled OR c.test_mode) AND NOT COALESCE(c.pinned, FALSE)
              AND c.managed_by <> 'autopilot_candidate'
            LIMIT {cap(p)}""")
        for b in broken:
            if b["RULE_ID"] in busy_targets:
                continue
            task = (f"Repair this detection rule '{b['NAME']}' ({b.get('MITRE_TECHNIQUE_ID')}). It fails at runtime "
                    f"with: {b['ERR']}. Keep its intent; change only what is needed.")
            rid, j, metrics, hist = author(s, cfg, task, base_rule=b)
            if not rid:
                record(s, "fix_broken", p.get("MODE"), "failed", f"Could not repair {b['NAME']}", "",
                       b.get("MITRE_TECHNIQUE_ID"), target=b["RULE_ID"], evidence={"attempts": hist, "error": b["ERR"]})
                continue
            ok, reason = passes(metrics, p)
            handle("fix_broken", f"Fix rule: {b['NAME']}", j.get("rationale"), rid=rid, target=b["RULE_ID"],
                   technique=b.get("MITRE_TECHNIQUE_ID"), severity=b["SEVERITY"],
                   evidence={"error": b["ERR"], "metrics": metrics, "gate": {"ok": ok, "reason": reason},
                             "before": {"code": b["CODE"], "threshold_count": b["THRESHOLD_COUNT"]},
                             "sql": rule(s, rid)["CODE"], "attempts": hist}, ok=ok, reason=reason)

    # 5. Noise from analyst verdicts: tune_filter (custom) / disable_noisy (any rule)
    fp_min = int(cfg.get("fp_filter_min", 3))
    noisy = rows(s, f"""
        SELECT f.rule_id, COUNT(*) AS n, COUNT_IF(f.disposition = 'false_positive') AS fp,
               COUNT_IF(f.disposition IS NOT NULL) AS judged,
               ARRAY_AGG(DISTINCT IFF(f.disposition = 'false_positive', COALESCE(f.user_name, f.src, f.dest), NULL)) AS fp_entities,
               COALESCE(MAX(c.name), MAX(r.rule_name)) AS name, COALESCE(MAX(c.severity), MAX(r.severity)) AS severity,
               MAX(c.language) AS language, MAX(c.pinned::INT) AS pinned, MAX(c.managed_by) AS managed_by,
               COALESCE(MAX(c.mitre_technique_id), MAX(r.mitre_technique_id)) AS technique
        FROM {DB}.DETECTIONS.DETECTION_FINDINGS f
        LEFT JOIN {CR} c ON c.rule_id = f.rule_id
        LEFT JOIN {DB}.DETECTIONS.DETECTION_RULES r ON r.rule_id = f.rule_id
        WHERE f.detection_time > DATEADD('day', -14, CURRENT_TIMESTAMP())
        GROUP BY f.rule_id
        HAVING COUNT_IF(f.disposition = 'false_positive') >= {fp_min}
        ORDER BY fp DESC""")
    pf, pdn = pol.get("tune_filter") or {}, pol.get("disable_noisy") or {}
    made_f = made_d = 0
    for nr in noisy:
        if nr["RULE_ID"] in busy_targets or nr["PINNED"]:
            continue
        fp_rate = nr["FP"] / max(nr["JUDGED"], 1)
        fp_entities = [e for e in (json.loads(nr["FP_ENTITIES"]) if isinstance(nr["FP_ENTITIES"], str)
                                   else nr["FP_ENTITIES"] or []) if e]
        evid = {"findings_14d": nr["N"], "false_positives": nr["FP"], "judged": nr["JUDGED"],
                "fp_rate": round(fp_rate, 2), "fp_entities": fp_entities[:20]}
        is_custom = nr["LANGUAGE"] == "sql"
        if is_custom and pf.get("MODE") != "off" and made_f < cap(pf):
            base = rule(s, nr["RULE_ID"])
            baseline = evaluate(s, nr["RULE_ID"], fp_entities)
            task = (f"Analysts marked {nr['FP']} of {nr['JUDGED']} reviewed findings of rule '{nr['NAME']}' as false "
                    f"positives. False-positive entities: {', '.join(fp_entities[:20])}. Add precise exclusions so "
                    f"these benign cases stop matching while real attacks still match. Keep the technique mapping.")
            rid, j, metrics, hist = author(s, cfg, task, base_rule=base)
            if rid:
                metrics = evaluate(s, rid, fp_entities)
                ok, reason = passes(metrics, pf, baseline)
                handle("tune_filter", f"Tune rule: {nr['NAME']} (exclude analyst FPs)", j.get("rationale"),
                       rid=rid, target=nr["RULE_ID"], technique=nr["TECHNIQUE"], severity=nr["SEVERITY"],
                       evidence={**evid, "metrics": metrics, "baseline_metrics": baseline,
                                 "gate": {"ok": ok, "reason": reason},
                                 "before": {"code": base["CODE"], "threshold_count": base["THRESHOLD_COUNT"]},
                                 "sql": rule(s, rid)["CODE"], "attempts": hist}, ok=ok, reason=reason)
                made_f += 1
                continue
        corroborated = one(s, f"""SELECT COUNT(*) AS n FROM {DB}.DETECTIONS.DETECTION_FINDINGS WHERE rule_id = ?
                                    AND ARRAY_TO_STRING(conf_factors, ' ') ILIKE '%corroborated%'
                                    AND detection_time > DATEADD('day', -14, CURRENT_TIMESTAMP())""", [nr["RULE_ID"]])["N"]
        if (fp_rate >= float(cfg.get("fp_rate_disable", 0.8)) and nr["JUDGED"] >= int(cfg.get("fp_min_verdicts", 10))
                and not corroborated  # other detections back some of its findings: tune, do not disable
                and pdn.get("MODE") != "off" and made_d < cap(pdn)):
            sev = int(nr["SEVERITY"] or 3)
            extra = (" Built-in rules and severity >= 4 always need a human decision."
                     if sev >= 4 or str(nr["RULE_ID"]).startswith("DET-") else "")
            handle("disable_noisy", f"Disable noisy rule: {nr['NAME']} ({nr['RULE_ID']})",
                   f"{nr['FP']} of {nr['JUDGED']} reviewed findings in 14 days were false positives "
                   f"({round(fp_rate * 100)}%). Consider an exclusion list or disabling it.{extra}",
                   target=nr["RULE_ID"], technique=nr["TECHNIQUE"], severity=sev, evidence=evid)
            made_d += 1

    # 6. tune_threshold: very loud custom rules without analyst complaints yet
    pt = pol.get("tune_threshold") or {}
    if pt.get("MODE") != "off":
        loud = rows(s, f"""
            SELECT c.rule_id, c.name, c.severity, c.threshold_count, c.code, COUNT(*) AS n
            FROM {DB}.DETECTIONS.DETECTION_FINDINGS f JOIN {CR} c ON c.rule_id = f.rule_id
            WHERE f.detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP()) AND c.enabled
              AND NOT COALESCE(c.pinned, FALSE)
            GROUP BY 1, 2, 3, 4, 5 HAVING COUNT(*) > {int(cfg.get('noisy_findings_7d', 50))}
            LIMIT {cap(pt)}""")
        for lr in loud:
            if lr["RULE_ID"] in busy_targets:
                continue
            new_t = max(2, int(lr["THRESHOLD_COUNT"] or 1) * 2)
            handle("tune_threshold", f"Raise threshold: {lr['NAME']} {lr['THRESHOLD_COUNT']} -> {new_t}",
                   f"{lr['N']} findings in 7 days exceeds the noise budget of {cfg.get('noisy_findings_7d', 50)}.",
                   target=lr["RULE_ID"], severity=lr["SEVERITY"],
                   evidence={"findings_7d": lr["N"], "before": {"code": lr["CODE"], "threshold_count": lr["THRESHOLD_COUNT"]},
                             "after": {"threshold_count": new_t}}, ok=True, reason="deterministic threshold tune")

    # 7. retire_silent: enabled custom rules with nothing for N days
    pr = pol.get("retire_silent") or {}
    if pr.get("MODE") != "off":
        days = int(cfg.get("silent_days", 30))
        for sr in rows(s, f"""
                SELECT c.rule_id, c.name, c.severity FROM {CR} c
                WHERE c.enabled AND c.created_at < DATEADD('day', -{days}, CURRENT_TIMESTAMP())
                  AND NOT COALESCE(c.pinned, FALSE)
                  AND NOT EXISTS (SELECT 1 FROM {DB}.DETECTIONS.DETECTION_FINDINGS f WHERE f.rule_id = c.rule_id
                                  AND f.detection_time > DATEADD('day', -{days}, CURRENT_TIMESTAMP()))
                LIMIT {cap(pr)}"""):
            if sr["RULE_ID"] in busy_targets:
                continue
            handle("retire_silent", f"Retire silent rule: {sr['NAME']}",
                   f"No findings in {days} days. Retire it, or keep it if it guards a rare high-impact case.",
                   target=sr["RULE_ID"], severity=sr["SEVERITY"], evidence={"silent_days": days})

    # 8. Human-in-the-loop FP control from analyst verdicts
    fp_control(s, pol, cfg, busy_targets, handle)

    notify(s, summary)
    return summary


def sigma_reference(s, g):
    """Community Sigma logic for the technique, translated by the model instead of invented."""
    refs = g.get("SIGMA_REFS")
    refs = json.loads(refs) if isinstance(refs, str) else (refs or [])
    if not refs:
        return ""
    sig = rows(s, f"""SELECT title, level, falsepositives, detection_yaml FROM {DB}.REFERENCE.SIGMA_RULES
                     WHERE ARRAY_CONTAINS(sigma_id::VARIANT, PARSE_JSON(?)) AND cim_table IS NOT NULL
                     ORDER BY IFF(level = 'critical', 0, IFF(level = 'high', 1, 2)) LIMIT 2""", [json.dumps(refs)])
    if not sig:
        return ""
    out = "\n\nReference: community Sigma rules for this technique (translate their logic to our schema; Sigma's " \
          "Image/CommandLine/ParentImage map to process_path/process/parent_process_name; keep their " \
          "false-positive exclusions):\n"
    for x in sig:
        out += f"--- {x['TITLE']} (level {x['LEVEL']}; known false positives: {x['FALSEPOSITIVES']})\n{(x['DETECTION_YAML'] or '')[:1500]}\n"
    return out


def fp_control(s, pol, cfg, busy_targets, handle):
    """Propose suppressions, allowlists and verdict re-checks; never applies them past policy."""
    # recheck_verdicts: humans dismissed findings that other detections now corroborate
    for r in rows(s, f"""
            SELECT rule_id, COALESCE(user_name, src, dest, 'unknown') AS entity, COUNT(*) AS n,
                   MAX(severity) AS severity, ANY_VALUE(conf_factors) AS factors
            FROM {DB}.DETECTIONS.DETECTION_FINDINGS f
            WHERE status IN ('new', 'dismissed') AND ARRAY_TO_STRING(conf_factors, ' ') ILIKE '%corroborated%'
              AND rule_id IN (SELECT rule_id FROM {DB}.DETECTIONS.DETECTION_FINDINGS g
                              WHERE g.disposition = 'false_positive' AND COALESCE(g.disposition_source, 'analyst') = 'analyst'
                                AND COALESCE(g.user_name, g.src, g.dest, 'unknown') = COALESCE(f.user_name, f.src, f.dest, 'unknown'))
            GROUP BY 1, 2 LIMIT 3"""):
        key = f"{r['RULE_ID']}|{r['ENTITY']}"
        if key in busy_targets or one(s, f"""SELECT 1 AS x FROM {CH} WHERE change_type = 'recheck_verdicts' AND target_rule_id = ?
                                            AND evidence:entity::VARCHAR = ? AND (status IN ('proposed', 'shadow')
                                            OR updated_at > DATEADD('day', -7, CURRENT_TIMESTAMP()))""",
                                     [r["RULE_ID"], r["ENTITY"]]):
            continue
        fp = one(s, f"""SELECT COUNT(*) AS n FROM {DB}.DETECTIONS.DETECTION_FINDINGS WHERE rule_id = ?
                         AND COALESCE(user_name, src, dest, 'unknown') = ? AND disposition = 'false_positive'
                         AND COALESCE(disposition_source, 'analyst') = 'analyst'""", [r["RULE_ID"], r["ENTITY"]])["N"]
        corr = [x.get("detail") for x in (json.loads(r["FACTORS"]) if isinstance(r["FACTORS"], str) else r["FACTORS"] or [])
                if x.get("factor") == "corroborated"]
        handle("recheck_verdicts", f"Re-check {fp} analyst false-positive verdicts: {r['RULE_ID']} on {r['ENTITY']}",
               f"Analysts dismissed {fp} {r['RULE_ID']} findings for {r['ENTITY']} as false positives, but "
               f"{corr[0] if corr else 'other detections fire on it'}. The earlier verdicts may be wrong and they are "
               f"teaching the FP model to hide this entity. Approve to re-open them for review.",
               target=r["RULE_ID"], severity=r["SEVERITY"],
               evidence={"entity": r["ENTITY"], "analyst_fp_verdicts": fp, "corroboration": corr}, ok=False,
               reason="verdict re-checks always need a human")

    # suppress_entity: consistent human FPs, no corroboration, no TP ever
    ps = pol.get("suppress_entity") or {}
    if ps.get("MODE") != "off":
        for r in rows(s, f"""
                SELECT p.rule_id, p.entity, p.fp_count, p.total_count, p.fp_rate
                FROM {DB}.DETECTIONS.FP_PATTERNS p
                WHERE p.fp_count >= {int(float(cfg.get('fp_filter_min', 3)))} AND p.tp_count = 0 AND p.fp_rate >= 0.8
                  AND NOT EXISTS (SELECT 1 FROM {DB}.DETECTIONS.SUPPRESSION_RULES x WHERE x.rule_id = p.rule_id
                                  AND x.entity = p.entity AND (x.expires_at IS NULL OR x.expires_at > CURRENT_TIMESTAMP()))
                  AND NOT EXISTS (SELECT 1 FROM {DB}.DETECTIONS.DETECTION_FINDINGS f WHERE f.rule_id = p.rule_id
                                  AND COALESCE(f.user_name, f.src, f.dest, 'unknown') = p.entity
                                  AND ARRAY_TO_STRING(f.conf_factors, ' ') ILIKE '%corroborated%')
                ORDER BY p.fp_count DESC LIMIT {cap(ps)}"""):
            if f"{r['RULE_ID']}|{r['ENTITY']}" in busy_targets or one(s, f"""SELECT 1 AS x FROM {CH}
                    WHERE change_type = 'suppress_entity' AND target_rule_id = ? AND evidence:entity::VARCHAR = ?
                      AND (status IN ('proposed', 'shadow') OR updated_at > DATEADD('day', -30, CURRENT_TIMESTAMP()))""",
                    [r["RULE_ID"], r["ENTITY"]]):
                continue
            handle("suppress_entity", f"Suppress {r['RULE_ID']} for {r['ENTITY']} for 30 days",
                   f"Analysts marked {r['FP_COUNT']} of {r['TOTAL_COUNT']} findings for {r['ENTITY']} false positive, none "
                   f"true, and no other detection corroborates it. An expiring suppression replaces silent model "
                   f"dismissal; suppressed findings are still spot-checked.",
                   target=r["RULE_ID"], evidence={"entity": r["ENTITY"], "fp": r["FP_COUNT"], "total": r["TOTAL_COUNT"],
                                                   "expires_days": 30,
                                                   "reason": f"{r['FP_COUNT']} analyst FP verdicts, 0 TP (autopilot)"},
                   ok=True, reason="consistent analyst verdicts, uncorroborated")

    # intel_allowlist: an indicator analysts keep dismissing
    pa = pol.get("intel_allowlist") or {}
    if pa.get("MODE") != "off":
        for r in rows(s, f"""
                SELECT i.ioc_type, i.ioc_value, i.threat_name, i.confidence, COUNT(*) AS fp
                FROM {DB}.DETECTIONS.DETECTION_FINDINGS f
                JOIN {DB}.REFERENCE.THREAT_INTEL_IOCS i ON LOWER(i.ioc_value) = LOWER(f.evidence:ioc_value::VARCHAR)
                WHERE f.disposition = 'false_positive' AND COALESCE(f.disposition_source, 'analyst') = 'analyst'
                  AND i.status NOT IN ('allowlisted', 'warninglisted')
                  AND NOT EXISTS (SELECT 1 FROM {DB}.DETECTIONS.DETECTION_FINDINGS g
                                  WHERE LOWER(g.evidence:ioc_value::VARCHAR) = LOWER(i.ioc_value)
                                    AND (g.disposition IN ('true_positive', 'mitigated_by_control')
                                         OR ARRAY_TO_STRING(g.conf_factors, ' ') ILIKE '%corroborated%'))
                GROUP BY 1, 2, 3, 4 HAVING COUNT(*) >= 5 ORDER BY fp DESC LIMIT {cap(pa)}"""):
            if one(s, f"""SELECT 1 AS x FROM {CH} WHERE change_type = 'intel_allowlist' AND evidence:ioc_value::VARCHAR = ?
                          AND (status IN ('proposed', 'shadow') OR updated_at > DATEADD('day', -30, CURRENT_TIMESTAMP()))""",
                   [r["IOC_VALUE"]]):
                continue
            handle("intel_allowlist", f"Allowlist indicator {r['IOC_VALUE']} ({r['THREAT_NAME']})",
                   f"{r['FP']} findings matching this indicator were marked false positive by analysts and none was "
                   f"confirmed or corroborated. Its intel confidence is already down to {r['CONFIDENCE']}/100. "
                   f"Allowlisting stops it alerting until removed.",
                   target="DET-021", severity=3,
                   evidence={"ioc_type": r["IOC_TYPE"], "ioc_value": r["IOC_VALUE"], "fp": r["FP"],
                             "reason": f"{r['FP']} analyst FP verdicts (autopilot)"}, ok=True, reason="consistent analyst verdicts")


# ---------------------------------------------------------------- notify / digest
def notify(s, summary):
    """Webhook only for events a human should know about now."""
    pending = one(s, f"SELECT COUNT(*) AS n FROM {CH} WHERE status = 'proposed'")["N"]
    if not (summary["promoted"] or summary["rolled_back"] or any(c["status"] == "proposed" for c in summary["created"])):
        return
    payload = {"source": "XDR Detection Autopilot", "promoted": summary["promoted"],
               "rolled_back": summary["rolled_back"], "new_changes": summary["created"],
               "pending_approvals": pending}
    try:
        s.sql("""CALL SYSTEM$SEND_SNOWFLAKE_NOTIFICATION(
                    SNOWFLAKE.NOTIFICATION.APPLICATION_JSON(?), SNOWFLAKE.NOTIFICATION.INTEGRATION('XDR_WEBHOOK'))""",
              params=[json.dumps(payload, default=str)]).collect()
        summary["webhook"] = "sent"
    except Exception as e:
        summary["webhook"] = "not sent: " + str(e)[:120]


def intel_digest_lines(s):
    """Threat intel and false-positive control sections of the digest (best effort)."""
    out = []
    try:
        st = json.loads(s.sql(f"CALL {DB}.REFERENCE.INTEL_STATUS(1)").collect()[0][0])
        i = st.get("iocs") or {}
        out.append("Threat intel (24h):")
        out.append(f"  - IOCs: {i.get('active', 0)} active ({i.get('high_confidence', 0)} high confidence), "
                   f"{i.get('new', 0)} new, {i.get('warninglisted', 0)} neutralised by warninglists, "
                   f"{i.get('expired', 0)} expired")
        bad = [f["feed"] for f in st.get("feeds") or [] if f.get("status") not in ("ok", None)]
        if bad:
            out.append("  - Feeds needing attention: " + ", ".join(bad))
        for k in (st.get("new_kev") or [])[:5]:
            out.append(f"  - New CISA KEV {k['cve']} ({k['product']}){' - used by ransomware' if k.get('ransomware') == 'Known' else ''}")
        for t in (st.get("new_techniques") or [])[:5]:
            out.append(f"  - New ATT&CK technique {t}")
        out.append("")
    except Exception:
        pass
    try:
        c = json.loads(s.sql(f"CALL {DB}.DETECTIONS.CONFIDENCE_STATUS()").collect()[0][0])
        b = c.get("open_by_band") or {}
        out.append("False-positive control:")
        out.append(f"  - Open findings by confidence: {b.get('high', 0)} high, {b.get('medium', 0)} medium, {b.get('low', 0)} low")
        out.append(f"  - Auto-suppressed (7d): {c.get('auto_suppressed_7d', 0)}; spot checks waiting for you: {c.get('review_open', 0)}")
        for q in c.get("suppression_quality") or []:
            if q.get("MISSES"):
                out.append(f"  - {q['PATH']}: {q['MISSES']} of {q['REVIEWED']} spot checks were real attacks - review this path")
        out.append("")
    except Exception:
        pass
    return out


def digest(s, to=None):
    cfg = settings(s)
    to = to or cfg.get("digest_email") or ""
    if not to:
        me = one(s, "SELECT CURRENT_USER() AS u")["U"]
        for r in s.sql(f'DESC USER "{me}"').collect():
            d = r.as_dict()
            if str(d.get("property", "")).upper() == "EMAIL":
                to = d.get("value") or ""
    recent = rows(s, f"""SELECT status, change_type, title, rationale, decided_by FROM {CH}
                        WHERE updated_at > DATEADD('day', -1, CURRENT_TIMESTAMP()) ORDER BY updated_at DESC""")
    pending = rows(s, f"SELECT change_type, title FROM {CH} WHERE status = 'proposed' ORDER BY created_at")
    shadow = rows(s, f"SELECT title FROM {CH} WHERE status = 'shadow' ORDER BY created_at")
    lines = ["XDR Detection Autopilot - daily digest", ""]
    counts = {}
    for r in recent:
        counts[r["STATUS"]] = counts.get(r["STATUS"], 0) + 1
    lines.append("Last 24h: " + (", ".join(f"{v} {k}" for k, v in counts.items()) or "no changes"))
    lines.append(f"Waiting for your approval: {len(pending)}   In shadow mode: {len(shadow)}")
    lines.append("")
    for title, items in (("Needs your decision", pending), ("Changes in the last 24h", recent), ("In shadow", shadow)):
        if items:
            lines.append(title + ":")
            for r in items[:15]:
                tag = f"[{r.get('STATUS', r.get('CHANGE_TYPE', ''))}] " if "STATUS" in r else ""
                lines.append(f"  - {tag}{r['TITLE']}")
            lines.append("")
    lines += intel_digest_lines(s)
    url = cfg.get("console_url") or ""
    lines.append("Review, approve, reject or roll back: " + (url + "/autopilot" if url else "XDR console > Detection Autopilot"))
    body = "\n".join(lines)
    if not to:
        return {"sent": False, "reason": "no recipient email", "body": body}
    try:
        s.sql("CALL SYSTEM$SEND_EMAIL('XDR_EMAIL', ?, ?, ?)",
              params=[to, f"[XDR Autopilot] {len(pending)} pending, {len(recent)} changes in 24h", body]).collect()
        return {"sent": True, "to": to, "body": body}
    except Exception as e:
        return {"sent": False, "reason": str(e)[:300], "body": body}


# ---------------------------------------------------------------- decisions
def caller(s, actor=None):
    """Audit identity: the signed-in console user when the console passes one, else the session user."""
    user = one(s, "SELECT CURRENT_USER() AS u")["U"]
    if actor and re.match(r"^[A-Za-z0-9_.@$-]{1,255}$", actor):
        return f"{actor} (console)"
    return user


def decide(s, change_id, action, note):
    # The console sends {"note": ..., "actor": ...}; SQL / agent callers send plain text
    actor = None
    try:
        j = json.loads(note) if note and note.strip().startswith("{") else None
        if isinstance(j, dict):
            note, actor = j.get("note") or None, j.get("actor")
    except ValueError:
        pass
    who = caller(s, actor)
    if action in ("pin", "unpin"):
        s.sql(f"UPDATE {CR} SET pinned = ? WHERE rule_id = ?", params=[action == "pin", change_id]).collect()
        return {"ok": True, "message": f"rule {change_id} {action}ned"}
    ch = one(s, f"SELECT * FROM {CH} WHERE change_id = ?", [change_id])
    if not ch:
        return {"ok": False, "message": "change not found"}
    st, ct = ch["STATUS"], ch["CHANGE_TYPE"]
    if action == "approve":
        if st not in OPEN:
            return {"ok": False, "message": f"cannot approve a change in status {st}"}
        result = go_live(s, ch)
        set_status(s, change_id, "approved", who, note, {"result": result})
        return {"ok": True, "message": f"approved: {result}"}
    if action == "reject":
        if st not in OPEN:
            return {"ok": False, "message": f"cannot reject a change in status {st}"}
        if ch["RULE_ID"]:
            if ct == "new_rule":
                s.sql(f"DELETE FROM {DB}.DETECTIONS.SHADOW_FINDINGS WHERE rule_id = ?", params=[ch["RULE_ID"]]).collect()
                s.sql(f"DELETE FROM {CR} WHERE rule_id = ? AND managed_by = 'autopilot' AND NOT enabled",
                      params=[ch["RULE_ID"]]).collect()
            else:
                drop_candidate(s, ch["RULE_ID"])
        set_status(s, change_id, "rejected", who, note)
        return {"ok": True, "message": "rejected; the autopilot will not re-propose this for 30 days"}
    if action == "rollback":
        if st not in LIVE:
            return {"ok": False, "message": f"only applied/promoted/approved changes can be rolled back (status {st})"}
        result = revert(s, ch)
        set_status(s, change_id, "rolled_back", who, note, {"result": result})
        return {"ok": True, "message": f"rolled back: {result}"}
    return {"ok": False, "message": "action must be approve, reject, rollback, pin or unpin"}


def set_policy(s, arg):
    p = json.loads(arg or "{}")
    ct, mode = p.get("change_type"), p.get("mode")
    if ct is None or (mode and mode not in MODES):
        return {"ok": False, "message": "need change_type and mode in " + ", ".join(MODES)}
    cols, vals = ["updated_by = ?", "updated_at = CURRENT_TIMESTAMP()"], [caller(s, p.get("actor"))]
    for k, typ in (("mode", str), ("max_per_cycle", int), ("promote_after_hours", float),
                   ("min_recall", float), ("max_benign_matches", int)):
        if p.get(k) is not None:
            cols.append(f"{k} = ?")
            vals.append(typ(p[k]))
    n = s.sql(f"UPDATE {DB}.DETECTIONS.AUTOPILOT_POLICY SET {', '.join(cols)} WHERE change_type = ?",
              params=vals + [ct]).collect()[0][0]
    return {"ok": bool(n), "message": f"policy for {ct} updated" if n else f"unknown change_type {ct}"}


def null_safe(session):
    """Snowpark binds Python None as the string 'None'; inline those placeholders as SQL NULL."""
    orig = session.sql

    def sql(query, params=None):
        if not params or all(p is not None for p in params):
            return orig(query, params=params)
        parts, keep = query.split("?"), []
        if len(parts) - 1 != len(params):
            return orig(query, params=params)
        out = parts[0]
        for p, rest in zip(params, parts[1:]):
            if p is None:
                out += "NULL" + rest
            else:
                keep.append(p)
                out += "?" + rest
        return orig(out, params=keep or None)

    session.sql = sql
    return session


def main(session, P_COMMAND, P_ARG, P_NOTE):
    session = null_safe(session)
    cmd = (P_COMMAND or "").lower()
    if cmd == "cycle":
        return cycle(session)
    if cmd == "evaluate":
        return evaluate(session, P_ARG)
    if cmd == "digest":
        return digest(session, P_ARG or None)
    if cmd == "set_policy":
        return set_policy(session, P_ARG)
    if cmd.startswith("decide:"):
        return decide(session, P_ARG, cmd.split(":", 1)[1], P_NOTE)
    return {"error": "unknown command " + cmd}
$$;

-- Thin SQL entry points (console, scheduled task, agent tools)
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CYCLE()
RETURNS VARIANT LANGUAGE SQL EXECUTE AS CALLER
AS
$$
DECLARE r VARIANT;
BEGIN
    CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT('cycle', NULL, NULL) INTO :r;
    RETURN r;
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_DECIDE(
    P_CHANGE_ID VARCHAR, P_ACTION VARCHAR, P_NOTE VARCHAR)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS CALLER
AS
$$
DECLARE r VARIANT;
BEGIN
    CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT('decide:' || LOWER(TRIM(:P_ACTION)), :P_CHANGE_ID, :P_NOTE) INTO :r;
    RETURN r;
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_SET_POLICY(
    P_CHANGE_TYPE VARCHAR, P_MODE VARCHAR)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS CALLER
AS
$$
DECLARE r VARIANT;
BEGIN
    CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT('set_policy',
        TO_JSON(OBJECT_CONSTRUCT('change_type', :P_CHANGE_TYPE, 'mode', :P_MODE)), NULL) INTO :r;
    RETURN r;
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_DIGEST()
RETURNS VARIANT LANGUAGE SQL EXECUTE AS CALLER
AS
$$
DECLARE r VARIANT;
BEGIN
    CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT('digest', NULL, NULL) INTO :r;
    RETURN r;
END;
$$;

-- Read-only status for the agent: counts, open decisions, recent changes
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_STATUS(P_DAYS NUMBER)
RETURNS VARIANT LANGUAGE SQL EXECUTE AS CALLER
AS
$$
BEGIN
    LET r VARIANT := (SELECT OBJECT_CONSTRUCT(
        'by_status', (SELECT OBJECT_AGG(status, n::VARIANT) FROM (
            SELECT status, COUNT(*) n FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES
            WHERE updated_at > DATEADD('day', -COALESCE(:P_DAYS, 7), CURRENT_TIMESTAMP()) GROUP BY status)),
        'changes', (SELECT ARRAY_AGG(OBJECT_CONSTRUCT('change_id', change_id, 'status', status,
                        'change_type', change_type, 'title', title, 'rationale', LEFT(rationale, 300),
                        'updated_at', updated_at, 'decided_by', decided_by,
                        'reason', COALESCE(decision_note, evidence:last_evaluation:reason::VARCHAR,
                                           evidence:gate:reason::VARCHAR),
                        'metrics', COALESCE(evidence:last_evaluation:metrics, evidence:metrics)))
                        WITHIN GROUP (ORDER BY updated_at DESC)
                    FROM (SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES
                          WHERE updated_at > DATEADD('day', -COALESCE(:P_DAYS, 7), CURRENT_TIMESTAMP())
                             OR status IN ('proposed', 'shadow')
                          ORDER BY updated_at DESC LIMIT 25)),
        'policy', (SELECT ARRAY_AGG(OBJECT_CONSTRUCT('change_type', change_type, 'mode', mode))
                   FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_POLICY)));
    RETURN r;
END;
$$;

-- Scheduled loop (suspended by default; resume to let the autopilot run unattended)
CREATE TASK IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.TASK_AUTOPILOT
    WAREHOUSE = XDR_WH
    SCHEDULE = 'USING CRON 0 */6 * * * UTC'
    COMMENT = 'Detection Autopilot: assess, propose, validate, promote, guard every 6 hours'
AS
    CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CYCLE();

CREATE TASK IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.TASK_AUTOPILOT_DIGEST
    WAREHOUSE = XDR_WH
    SCHEDULE = 'USING CRON 0 7 * * * UTC'
    COMMENT = 'Detection Autopilot: daily email digest of changes and pending approvals'
AS
    CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_DIGEST();
