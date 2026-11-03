-- ============================================================================
-- Snowflake XDR - Rule packs (Phase 4)
-- ============================================================================
-- Vetted best-practice detection content per platform (Snowflake, AWS, Entra,
-- Okta, Databricks, Postgres, ClickHouse, Salesforce), kept as YAML in
-- rule-packs/<pack>/pack.yaml and loaded with LOAD_RULE_PACK.
--
-- Coverage-aware install: a pack rule is only installed once its source table
-- actually has data from that vendor. Rules waiting for data are installed
-- automatically by the autopilot cycle when the data shows up (for example
-- after a new OTel source is mapped). Installs go through the autopilot as
-- change type 'pack_rule' (default: shadow for 24h, then promote), so every
-- rule is visible, approvable and rollback-able in the Autopilot feed.
--
-- Pack updates: a changed rule is updated in place (previous version kept in
-- CUSTOM_RULE_HISTORY) unless the rule is pinned or was edited by a human.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. DATABASE_ACTIVITY: CIM table for data-platform audit logs
--    (Snowflake QUERY_HISTORY, Databricks audit, pgaudit, ClickHouse
--     query_log, Salesforce EventLogFile)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY (
    event_id        VARCHAR DEFAULT UUID_STRING(),   -- source-stable id, used for dedupe
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(100),       -- query, grant, revoke, create_user, unload, login ...
    user_name       VARCHAR(255),
    user_role       VARCHAR(255),       -- role / group the statement ran as
    src             VARCHAR(255),       -- client IP when known
    dest            VARCHAR(255),       -- account / workspace / instance
    app             VARCHAR(255),       -- client application or driver
    query_type      VARCHAR(100),       -- vendor statement type (GRANT, UNLOAD, CREATE_USER ...)
    query_text      VARCHAR(16000),
    object          VARCHAR(1000),      -- primary object touched (db.schema.table, user, role)
    object_category VARCHAR(100),       -- table, user, role, stage, integration, parameter ...
    result          VARCHAR(50),        -- success | failure
    reason          VARCHAR(2000),      -- error message
    rows_affected   NUMBER,
    bytes           NUMBER,
    warehouse       VARCHAR(255),       -- compute: warehouse, cluster, endpoint
    session_id      VARCHAR(255),
    vendor_account  VARCHAR(255),
    vendor_product  VARCHAR(100),       -- snowflake, databricks, postgres, clickhouse, salesforce
    lane            VARCHAR(20),        -- fast (near real time) | history (complete, delayed)
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'database',
    _raw            VARIANT
);
-- OTel mappings stamp ingestion_time on every CIM table (setup/30_otel_ingest.sql)
ALTER TABLE SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY ADD COLUMN IF NOT EXISTS ingestion_time TIMESTAMP_LTZ;

-- ---------------------------------------------------------------------------
-- 2. Pack catalog
-- ---------------------------------------------------------------------------
ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES ADD COLUMN IF NOT EXISTS pack_id VARCHAR(50);
ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES ADD COLUMN IF NOT EXISTS pack_rule_version NUMBER;

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.RULE_PACKS (
    pack_id        VARCHAR(50) PRIMARY KEY,
    name           VARCHAR(200),
    vendor         VARCHAR(100),
    version        NUMBER,
    description    VARCHAR(4000),
    requires       VARIANT,          -- [{table, vendor_product}]
    onboarding     VARCHAR(4000),    -- how to get the data in
    auto_install   BOOLEAN DEFAULT TRUE,
    coverage       VARIANT,          -- {TABLE|vendor: rows_7d}
    coverage_at    TIMESTAMP_LTZ,
    loaded_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    loaded_by      VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES (
    rule_id            VARCHAR(50) PRIMARY KEY,   -- e.g. SF-001; also the CUSTOM_RULES rule_id
    pack_id            VARCHAR(50),
    name               VARCHAR(200),
    description        VARCHAR(2000),
    severity           NUMBER,
    mitre_tactic_id    VARCHAR(20),
    mitre_technique_id VARCHAR(30),
    source_table       VARCHAR(100),
    vendor_product     VARCHAR(100),
    code               VARCHAR(10000),
    threshold_count    NUMBER,
    window_minutes     NUMBER,
    lookback_minutes   NUMBER,
    version            NUMBER,
    false_positives    VARCHAR(2000),
    references_        VARIANT,
    install_state      VARCHAR(30) DEFAULT 'available',
                       -- available | waiting_for_data | shadow | proposed | live | rejected | rolled_back | invalid
    state_reason       VARCHAR(1000),
    updated_at         TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);
-- Detection canaries (setup/38_canaries.sql): positive / negative fixtures per rule
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES ADD COLUMN IF NOT EXISTS fixtures VARIANT;
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES ADD COLUMN IF NOT EXISTS expected_latency_seconds NUMBER;

-- ---------------------------------------------------------------------------
-- 3. LOAD_RULE_PACK(yaml): validate and upsert a pack definition
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.LOAD_RULE_PACK(P_YAML VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python', 'pyyaml')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import json
import re
import yaml

DB = "SNOWFLAKE_XDR"
ID_RE = re.compile(r"^[A-Z]{2,5}-[0-9]{3}$")
PACK_RE = re.compile(r"^[a-z][a-z0-9_]{1,40}$")
TECH_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
TACTIC_RE = re.compile(r"^TA[0-9]{4}$")
TABLE_RE = re.compile(r"^[A-Z_]{3,60}$")


def null_safe(session):
    """Snowpark binds Python None as the string 'None'; inline those placeholders as SQL NULL."""
    orig = session.sql

    def sql(query, params=None):
        if not params or all(x is not None for x in params):
            return orig(query, params=params)
        parts, keep = query.split("?"), []
        if len(parts) - 1 != len(params):
            return orig(query, params=params)
        out = parts[0]
        for x, rest in zip(params, parts[1:]):
            if x is None:
                out += "NULL" + rest
            else:
                keep.append(x)
                out += "?" + rest
        return orig(out, params=keep or None)

    session.sql = sql
    return session


def main(s, P_YAML):
    s = null_safe(s)
    p = yaml.safe_load(P_YAML or "")
    if not isinstance(p, dict) or not PACK_RE.match(str(p.get("pack_id", ""))):
        return {"ok": False, "error": "pack_id must be lower_snake_case"}
    pid = p["pack_id"]
    errors, loaded = [], 0
    s.sql(f"""MERGE INTO {DB}.REFERENCE.RULE_PACKS t
              USING (SELECT ? AS pack_id) v ON t.pack_id = v.pack_id
              WHEN MATCHED THEN UPDATE SET name = ?, vendor = ?, version = ?, description = ?,
                   requires = PARSE_JSON(?), onboarding = ?, loaded_at = CURRENT_TIMESTAMP(), loaded_by = CURRENT_USER()
              WHEN NOT MATCHED THEN INSERT (pack_id, name, vendor, version, description, requires, onboarding, loaded_by)
                   VALUES (v.pack_id, ?, ?, ?, ?, PARSE_JSON(?), ?, CURRENT_USER())""",
          params=[pid] + [p.get("name"), p.get("vendor"), int(p.get("version", 1)), p.get("description"),
                          json.dumps(p.get("requires") or []), p.get("onboarding")] * 2).collect()
    default_vp = ((p.get("requires") or [{}])[0] or {}).get("vendor_product")
    for r in p.get("rules") or []:
        rid = str(r.get("id", ""))
        sql = (r.get("sql") or "").strip().rstrip(";")
        table = str(r.get("table", "")).upper()
        problems = []
        if not ID_RE.match(rid):
            problems.append("id must look like SF-001")
        if not TABLE_RE.match(table):
            problems.append("table missing")
        if r.get("technique") and not TECH_RE.match(r["technique"]):
            problems.append("bad technique")
        if r.get("tactic") and not TACTIC_RE.match(r["tactic"]):
            problems.append("bad tactic")
        if not 1 <= int(r.get("severity", 3)) <= 5:
            problems.append("severity 1-5")
        v = s.sql(f"SELECT {DB}.DASHBOARDS.RULE_SQL_VIOLATION(?) AS v", params=[sql]).collect()[0]["V"]
        if v:
            problems.append("sql " + v)
        if problems:
            errors.append({"rule": rid, "problems": problems})
            continue
        vals = [pid, r.get("name"), r.get("description"), int(r.get("severity", 3)), r.get("tactic"),
                r.get("technique"), table, r.get("vendor_product") or default_vp, sql,
                int(r.get("threshold", 1)), int(r.get("window_minutes", 60)), int(r.get("lookback_minutes", 180)),
                int(r.get("version", p.get("version", 1))), r.get("false_positives"),
                json.dumps(r.get("references") or [])]
        s.sql(f"""MERGE INTO {DB}.REFERENCE.RULE_PACK_RULES t
                  USING (SELECT ? AS rule_id) v ON t.rule_id = v.rule_id
                  WHEN MATCHED THEN UPDATE SET pack_id = ?, name = ?, description = ?, severity = ?,
                       mitre_tactic_id = ?, mitre_technique_id = ?, source_table = ?, vendor_product = ?, code = ?,
                       threshold_count = ?, window_minutes = ?, lookback_minutes = ?, version = ?,
                       false_positives = ?, references_ = PARSE_JSON(?), updated_at = CURRENT_TIMESTAMP()
                  WHEN NOT MATCHED THEN INSERT (rule_id, pack_id, name, description, severity, mitre_tactic_id,
                       mitre_technique_id, source_table, vendor_product, code, threshold_count, window_minutes,
                       lookback_minutes, version, false_positives, references_)
                       VALUES (v.rule_id, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, PARSE_JSON(?))""",
              params=[rid] + vals + vals).collect()
        s.sql(f"""UPDATE {DB}.REFERENCE.RULE_PACK_RULES SET fixtures = TRY_PARSE_JSON(NULLIF(?, '')),
                    expected_latency_seconds = ? WHERE rule_id = ?""",
              params=[json.dumps(r.get("fixtures")) if r.get("fixtures") else "",
                      int(r.get("expected_latency_seconds", 300)), rid]).collect()
        loaded += 1
    return {"ok": not errors, "pack_id": pid, "rules_loaded": loaded, "errors": errors}
$$;

-- ---------------------------------------------------------------------------
-- 4. INSTALL_RULE_PACK(pack_id | 'all', force)
--    Measures data coverage, installs rules whose source has data, records
--    each install as an autopilot 'pack_rule' change, and updates rules whose
--    pack version changed. force = install even without data yet.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.INSTALL_RULE_PACK(P_PACK_ID VARCHAR, P_FORCE BOOLEAN)
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
TABLE_RE = re.compile(r"^[A-Z_]{3,60}$")


def rows(s, sql, params=None):
    return [r.as_dict() for r in s.sql(sql, params=params).collect()]


def one(s, sql, params=None):
    r = rows(s, sql, params)
    return r[0] if r else None


def coverage(s, cache, table, vp):
    key = f"{table}|{vp or '*'}"
    if key not in cache:
        exists = one(s, "SELECT COUNT(*) AS n FROM SNOWFLAKE_XDR.INFORMATION_SCHEMA.TABLES "
                        "WHERE table_schema = 'RAW_LOGS' AND table_name = ?", [table])["N"]
        if not exists or not TABLE_RE.match(table):
            cache[key] = 0
        else:
            cache[key] = int(one(s, f"""SELECT COUNT(*) AS n FROM {DB}.RAW_LOGS.{table}
                                        WHERE _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
                                          AND vendor_product ILIKE ?""", [vp or "%"])["N"])
    return cache[key]


def record(s, mode, status, title, rationale, r, evidence):
    cid = one(s, "SELECT UUID_STRING() AS id")["ID"]
    s.sql(f"""INSERT INTO {CH} (change_id, change_type, mode, status, title, rationale, technique_id,
                rule_id, target_rule_id, severity, evidence, decided_by)
              SELECT ?, 'pack_rule', ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, PARSE_JSON(?), NULLIF(?, '')""",
          params=[cid, mode, status, title[:500], rationale[:4000], r["MITRE_TECHNIQUE_ID"] or "",
                  r["RULE_ID"], r["RULE_ID"], int(r["SEVERITY"] or 3), json.dumps(evidence, default=str),
                  "autopilot" if status not in ("proposed", "shadow") else ""]).collect()
    return cid


def null_safe(session):
    """Snowpark binds Python None as the string 'None'; inline those placeholders as SQL NULL."""
    orig = session.sql

    def sql(query, params=None):
        if not params or all(x is not None for x in params):
            return orig(query, params=params)
        parts, keep = query.split("?"), []
        if len(parts) - 1 != len(params):
            return orig(query, params=params)
        out = parts[0]
        for x, rest in zip(params, parts[1:]):
            if x is None:
                out += "NULL" + rest
            else:
                keep.append(x)
                out += "?" + rest
        return orig(out, params=keep or None)

    session.sql = sql
    return session


def main(s, P_PACK_ID, P_FORCE):
    s = null_safe(s)
    force = bool(P_FORCE)
    pol = one(s, f"SELECT * FROM {DB}.DETECTIONS.AUTOPILOT_POLICY WHERE change_type = 'pack_rule'") or {}
    mode = pol.get("MODE") or "shadow_then_promote"
    if mode == "off" and not force:
        return {"ok": True, "message": "pack_rule policy is off", "installed": []}
    if mode == "off":
        mode = "propose_only"
    pid = (P_PACK_ID or "all").lower()
    # Guardrails: the kill switch and the daily change budget apply to unattended installs
    if not force and one(s, f"SELECT {DB}.DETECTIONS.AUTONOMY_PAUSED() AS p")["P"]:
        return {"ok": True, "message": "autonomy is paused (kill switch)", "installed": []}
    left = None
    if not force:
        b = one(s, f"""SELECT (SELECT MAX(value::NUMBER) FROM {DB}.DETECTIONS.AUTONOMY_SETTINGS
                               WHERE setting = 'daily_change_budget') AS total,
                              COALESCE(MAX(daily_budget), NULL) AS per_type,
                              (SELECT COUNT(*) FROM {CH} WHERE created_at >= DATEADD('hour', -24, CURRENT_TIMESTAMP())) AS used_all,
                              (SELECT COUNT(*) FROM {CH} WHERE change_type = 'pack_rule'
                                 AND created_at >= DATEADD('hour', -24, CURRENT_TIMESTAMP())) AS used_type
                       FROM {DB}.DETECTIONS.AUTOPILOT_POLICY WHERE change_type = 'pack_rule'""")
        caps = [int(b["TOTAL"]) - int(b["USED_ALL"]) if b and b["TOTAL"] is not None else None,
                int(b["PER_TYPE"]) - int(b["USED_TYPE"]) if b and b["PER_TYPE"] is not None else None]
        caps = [c for c in caps if c is not None]
        left = max(0, min(caps)) if caps else None
    packs = rows(s, f"""SELECT * FROM {DB}.REFERENCE.RULE_PACKS
                        WHERE (? = 'all' AND auto_install) OR pack_id = ?""", [pid, pid])
    if not packs:
        return {"ok": False, "message": f"unknown pack {pid}", "installed": []}
    cache, out, waiting, updated, budget_held = {}, [], [], [], []
    for pk in packs:
        for r in rows(s, f"SELECT * FROM {DB}.REFERENCE.RULE_PACK_RULES WHERE pack_id = ? ORDER BY rule_id",
                      [pk["PACK_ID"]]):
            n = coverage(s, cache, r["SOURCE_TABLE"], r["VENDOR_PRODUCT"])
            cur = one(s, f"SELECT * FROM {CR} WHERE rule_id = ?", [r["RULE_ID"]])
            if cur:
                # Pack update: refresh code unless pinned or taken over by a human
                if (int(cur.get("PACK_RULE_VERSION") or 0) < int(r["VERSION"] or 1)
                        and cur.get("MANAGED_BY") == "pack" and not cur.get("PINNED")):
                    s.sql(f"""INSERT INTO {DB}.DETECTIONS.CUSTOM_RULE_HISTORY
                                (rule_id, version, name, code, language, severity, threshold_count, enabled, changed_by)
                              SELECT rule_id, version, name, code, language, severity, threshold_count, enabled, 'rule_pack'
                              FROM {CR} WHERE rule_id = ?""", params=[r["RULE_ID"]]).collect()
                    s.sql(f"""UPDATE {CR} SET code = ?, threshold_count = ?, severity = ?, description = ?,
                                version = version + 1, pack_rule_version = ?, updated_at = CURRENT_TIMESTAMP()
                              WHERE rule_id = ?""",
                          params=[r["CODE"], r["THRESHOLD_COUNT"], r["SEVERITY"], r["DESCRIPTION"],
                                  r["VERSION"], r["RULE_ID"]]).collect()
                    record(s, "auto_live", "applied", f"Updated pack rule {r['RULE_ID']}: {r['NAME']}",
                           f"{pk['NAME']} v{r['VERSION']} changed this rule; previous version kept in history.", r,
                           {"pack_id": pk["PACK_ID"], "update": True,
                            "before": {"code": cur["CODE"], "threshold_count": cur["THRESHOLD_COUNT"]}})
                    updated.append(r["RULE_ID"])
                continue
            if r["INSTALL_STATE"] in ("rejected", "rolled_back") and not force:
                continue
            if n == 0 and not force:
                if r["INSTALL_STATE"] != "waiting_for_data":
                    s.sql(f"""UPDATE {DB}.REFERENCE.RULE_PACK_RULES SET install_state = 'waiting_for_data',
                                state_reason = ? WHERE rule_id = ?""",
                          params=[f"no {r['VENDOR_PRODUCT'] or ''} rows in {r['SOURCE_TABLE']} in the last 7 days",
                                  r["RULE_ID"]]).collect()
                waiting.append(r["RULE_ID"])
                continue
            if left is not None and left <= 0:
                budget_held.append(r["RULE_ID"])
                continue
            if left is not None:
                left -= 1
            status = {"shadow_then_promote": "shadow", "auto_live": "applied"}.get(mode, "proposed")
            s.sql(f"""INSERT INTO {CR} (rule_id, name, description, category, severity, mitre_tactic_id,
                        mitre_technique_id, language, source_table, code, threshold_count, threshold_window_minutes,
                        lookback_minutes, enabled, test_mode, created_by, managed_by, pack_id, pack_rule_version)
                      SELECT ?, ?, ?, ?, ?, ?, ?, 'sql', ?, ?, ?, ?, ?, ?, ?, 'rule_pack', 'pack', ?, ?""",
                  params=[r["RULE_ID"], r["NAME"], r["DESCRIPTION"],
                          "cloud" if r["SOURCE_TABLE"] in ("CLOUD_API", "DATABASE_ACTIVITY") else
                          "identity" if r["SOURCE_TABLE"] == "AUTHENTICATION" else "custom",
                          r["SEVERITY"], r["MITRE_TACTIC_ID"], r["MITRE_TECHNIQUE_ID"], r["SOURCE_TABLE"],
                          r["CODE"], r["THRESHOLD_COUNT"], r["WINDOW_MINUTES"], r["LOOKBACK_MINUTES"],
                          status == "applied", status == "shadow", pk["PACK_ID"], r["VERSION"]]).collect()
            s.sql(f"""UPDATE {DB}.REFERENCE.RULE_PACK_RULES SET install_state = ?, state_reason = ?
                      WHERE rule_id = ?""",
                  params=["live" if status == "applied" else status,
                          f"{n} matching source rows in 7 days" if n else "installed without data (forced)",
                          r["RULE_ID"]]).collect()
            title = f"Install {pk['NAME']} rule {r['RULE_ID']}: {r['NAME']}"
            record(s, mode, status, title,
                   f"{r['DESCRIPTION'] or ''} Source {r['SOURCE_TABLE']} has {n} {r['VENDOR_PRODUCT'] or ''} "
                   f"rows in the last 7 days. Known false positives: {r['FALSE_POSITIVES'] or 'none listed'}.",
                   r, {"pack_id": pk["PACK_ID"], "pack_version": pk["VERSION"], "source_rows_7d": n,
                       "references": r["REFERENCES_"], "sql": r["CODE"]})
            out.append({"rule_id": r["RULE_ID"], "title": title, "status": status})
        s.sql(f"UPDATE {DB}.REFERENCE.RULE_PACKS SET coverage = PARSE_JSON(?), coverage_at = CURRENT_TIMESTAMP() "
              "WHERE pack_id = ?", params=[json.dumps(cache), pk["PACK_ID"]]).collect()
    return {"ok": True, "installed": out, "updated": updated, "waiting_for_data": waiting, "mode": mode,
            "held_by_budget": budget_held}
$$;

-- ---------------------------------------------------------------------------
-- 5. Pack status for the console and the agent
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.REFERENCE.V_RULE_PACK_RULES AS
SELECT p.pack_id, p.name AS pack_name, p.vendor, r.rule_id, r.name, r.severity, r.mitre_technique_id,
       r.source_table, r.vendor_product, r.version, r.install_state, r.state_reason,
       c.enabled, c.test_mode, COALESCE(c.pinned, FALSE) AS pinned,
       (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
         WHERE f.rule_id = r.rule_id AND f.detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS findings_7d,
       (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.SHADOW_FINDINGS f WHERE f.rule_id = r.rule_id) AS shadow_findings
FROM SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES r
JOIN SNOWFLAKE_XDR.REFERENCE.RULE_PACKS p ON p.pack_id = r.pack_id
LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES c ON c.rule_id = r.rule_id;

CREATE OR REPLACE VIEW SNOWFLAKE_XDR.REFERENCE.V_RULE_PACKS AS
SELECT p.pack_id, p.name, p.vendor, p.version, p.description, p.onboarding, p.auto_install,
       p.requires, p.coverage, p.coverage_at,
       COUNT(r.rule_id) AS rules,
       COUNT_IF(r.install_state = 'live') AS live,
       COUNT_IF(r.install_state IN ('shadow', 'proposed')) AS pending,
       COUNT_IF(r.install_state = 'waiting_for_data') AS waiting_for_data,
       IFF(COUNT_IF(r.install_state = 'waiting_for_data') = COUNT(r.rule_id), 'no_data',
           IFF(COUNT_IF(r.install_state = 'live') > 0, 'active', 'installing')) AS status
FROM SNOWFLAKE_XDR.REFERENCE.RULE_PACKS p
LEFT JOIN SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES r ON r.pack_id = p.pack_id
GROUP BY ALL;
