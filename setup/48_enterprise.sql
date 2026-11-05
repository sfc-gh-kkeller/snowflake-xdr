-- ============================================================================
-- Snowflake XDR - Phase 5.8: enterprise basics and threat-intel depth
-- ============================================================================
--   1. Console RBAC      viewer < analyst < engineer < admin, resolved per signed-in
--                        user (explicit assignment, else mapped from their Snowflake
--                        roles); enforced at the console's single dispatch point
--   2. Tenancy (demo)    tenant_id on findings, cases and CIM tables, one row access
--                        policy: roles mapped to tenants see only their tenants,
--                        unmapped roles (admins, the console service) see everything
--   3. Compliance        SOC 2, ISO/IEC 27001:2022 and NIST CSF 2.0 controls, each
--                        evidenced by live platform data (V_COMPLIANCE_EVIDENCE)
--   4. Retention tiers   hot days per table; older rows move to the ARCHIVE schema
--                        (or an Iceberg table when an external volume is configured)
--   5. STIX / TAXII 2.1  generic client: discovery, collections, paged objects,
--                        STIX indicator patterns -> THREAT_INTEL_IOCS
--   6. Retro-hunt        newly learned IOCs searched across 30 days of telemetry
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Console RBAC
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DASHBOARDS.CONSOLE_USERS (
    user_name   VARCHAR(255) PRIMARY KEY,   -- Snowflake user name (the ingress identity)
    xdr_role    VARCHAR(20),                -- viewer | analyst | engineer | admin
    tenants     ARRAY,                      -- NULL = all tenants
    granted_by  VARCHAR(255),
    granted_at  TIMESTAMP_LTZ
);
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DASHBOARDS.CONSOLE_ROLE_MAP (
    snowflake_role VARCHAR(255) PRIMARY KEY,
    xdr_role       VARCHAR(20)
);
MERGE INTO SNOWFLAKE_XDR.DASHBOARDS.CONSOLE_ROLE_MAP t
USING (SELECT * FROM VALUES ('ACCOUNTADMIN', 'admin'), ('SECURITYADMIN', 'admin'), ('SYSADMIN', 'engineer'),
                            ('XDR_CONSOLE_USER', 'analyst') AS v(r, x)) s ON t.snowflake_role = s.r
WHEN NOT MATCHED THEN INSERT VALUES (s.r, s.x);
-- The invited testers were promised full access
MERGE INTO SNOWFLAKE_XDR.DASHBOARDS.CONSOLE_USERS t
USING (SELECT * FROM VALUES ('VLUONGO'), ('MBARREIRO') AS v(u)) s ON t.user_name = s.u
WHEN NOT MATCHED THEN INSERT (user_name, xdr_role, granted_by, granted_at) VALUES (s.u, 'admin', 'setup/48', CURRENT_TIMESTAMP());

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DASHBOARDS.CONSOLE_ACCESS_DENIALS (
    at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(), user_name VARCHAR(255), xdr_role VARCHAR(20),
    operation VARCHAR(100), required VARCHAR(20));

-- Owner's rights: reading another user's role grants needs privileges the console service does not hold
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.RESOLVE_CONSOLE_ROLE(P_USER VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS OWNER
AS
$$
import json
import re

DB = "SNOWFLAKE_XDR"
RANK = {"viewer": 0, "analyst": 1, "engineer": 2, "admin": 3}
NAME_RE = re.compile(r"^[A-Za-z0-9_.@$-]{1,255}$")


def main(s, P_USER):
    user = (P_USER or "").strip()
    if not NAME_RE.match(user):
        return {"user": user, "role": "viewer", "via": "no identity", "tenants": None}
    r = s.sql(f"SELECT xdr_role, tenants FROM {DB}.DASHBOARDS.CONSOLE_USERS WHERE UPPER(user_name) = UPPER(?)",
              params=[user]).collect()
    if r and r[0]["XDR_ROLE"] in RANK:
        t = r[0]["TENANTS"]
        return {"user": user, "role": r[0]["XDR_ROLE"], "via": "assigned", "tenants": json.loads(t) if t else None}
    try:
        grants = [g.as_dict() for g in s.sql(f'SHOW GRANTS TO USER "{user.upper()}"').collect()]
    except Exception:
        grants = []
    held = {str(g.get("role", "")).upper() for g in grants}
    mapping = {m["SNOWFLAKE_ROLE"].upper(): m["XDR_ROLE"] for m in
               s.sql(f"SELECT snowflake_role, xdr_role FROM {DB}.DASHBOARDS.CONSOLE_ROLE_MAP").collect()}
    best, via = "viewer", "default"
    for role in held:
        x = mapping.get(role)
        if x in RANK and RANK[x] > RANK[best]:
            best, via = x, f"Snowflake role {role}"
    return {"user": user, "role": best, "via": via, "tenants": None}
$$;

-- ---------------------------------------------------------------------------
-- 2. Tenancy (MSSP demo)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.TENANTS (
    tenant_id VARCHAR(40) PRIMARY KEY, name VARCHAR(200), created_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP());
MERGE INTO SNOWFLAKE_XDR.REFERENCE.TENANTS t
USING (SELECT * FROM VALUES ('default', 'Default tenant'), ('acme', 'Acme Corp (demo)'), ('globex', 'Globex (demo)') AS v(i, n)) s
ON t.tenant_id = s.i WHEN NOT MATCHED THEN INSERT (tenant_id, name) VALUES (s.i, s.n);

-- Roles listed here are restricted to their tenants; any other role is unrestricted
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.TENANT_ROLE_MAP (
    snowflake_role VARCHAR(255), tenant_id VARCHAR(40));
MERGE INTO SNOWFLAKE_XDR.REFERENCE.TENANT_ROLE_MAP t
USING (SELECT 'XDR_TENANT_ACME' AS r, 'acme' AS i) s ON t.snowflake_role = s.r AND t.tenant_id = s.i
WHEN NOT MATCHED THEN INSERT VALUES (s.r, s.i);

CREATE ROLE IF NOT EXISTS XDR_TENANT_ACME COMMENT = 'Demo MSSP role: sees only tenant acme (row access policy)';
GRANT USAGE ON DATABASE SNOWFLAKE_XDR TO ROLE XDR_TENANT_ACME;
GRANT USAGE ON SCHEMA SNOWFLAKE_XDR.DETECTIONS TO ROLE XDR_TENANT_ACME;
GRANT USAGE ON SCHEMA SNOWFLAKE_XDR.INCIDENTS TO ROLE XDR_TENANT_ACME;
GRANT USAGE ON SCHEMA SNOWFLAKE_XDR.RAW_LOGS TO ROLE XDR_TENANT_ACME;
GRANT SELECT ON TABLE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS TO ROLE XDR_TENANT_ACME;
GRANT SELECT ON TABLE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS TO ROLE XDR_TENANT_ACME;
GRANT SELECT ON TABLE SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION TO ROLE XDR_TENANT_ACME;
GRANT USAGE ON WAREHOUSE XDR_WH TO ROLE XDR_TENANT_ACME;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.APPLY_TENANCY()
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
TABLES = ["DETECTIONS.DETECTION_FINDINGS", "INCIDENTS.INCIDENTS"] + [
    "RAW_LOGS." + t for t in ("AUTHENTICATION", "DATABASE_ACTIVITY", "CLOUD_API", "ENDPOINT_PROCESSES", "ENDPOINT_FILESYSTEM",
                              "ENDPOINT_REGISTRY", "NETWORK_TRAFFIC", "DNS_ACTIVITY", "WEB_ACTIVITY", "INTRUSION_DETECTION",
                              "EMAIL_ACTIVITY")]
POLICY = "SNOWFLAKE_XDR.REFERENCE.XDR_TENANT_POLICY"


def main(s):
    s.sql(f"""CREATE ROW ACCESS POLICY IF NOT EXISTS {POLICY} AS (p_tenant VARCHAR) RETURNS BOOLEAN ->
                NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.REFERENCE.TENANT_ROLE_MAP m WHERE m.snowflake_role = CURRENT_ROLE())
                OR EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.REFERENCE.TENANT_ROLE_MAP m
                           WHERE m.snowflake_role = CURRENT_ROLE() AND m.tenant_id = COALESCE(p_tenant, 'default'))""").collect()
    out = {}
    for t in TABLES:
        fq = "SNOWFLAKE_XDR." + t
        try:
            s.sql(f"ALTER TABLE {fq} ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(40)").collect()
            attached = s.sql(f"""SELECT COUNT(*) AS n FROM TABLE(SNOWFLAKE_XDR.INFORMATION_SCHEMA.POLICY_REFERENCES(
                                   REF_ENTITY_NAME => '{fq}', REF_ENTITY_DOMAIN => 'table'))
                                 WHERE policy_kind = 'ROW_ACCESS_POLICY'""").collect()[0]["N"]
            if not attached:
                s.sql(f"ALTER TABLE {fq} ADD ROW ACCESS POLICY {POLICY} ON (tenant_id)").collect()
            out[t] = "ok"
        except Exception as e:
            out[t] = "skipped: " + str(e)[:120]
    return {"ok": True, "tables": out}
$$;
CALL SNOWFLAKE_XDR.REFERENCE.APPLY_TENANCY();

-- ---------------------------------------------------------------------------
-- 3. Compliance: controls evidenced by live platform data
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.COMPLIANCE_CONTROLS (
    framework   VARCHAR(30),
    control_id  VARCHAR(30),
    title       VARCHAR(300),
    evidence    VARCHAR(40),     -- key into V_COMPLIANCE_EVIDENCE
    PRIMARY KEY (framework, control_id)
);
MERGE INTO SNOWFLAKE_XDR.REFERENCE.COMPLIANCE_CONTROLS t
USING (SELECT * FROM VALUES
    ('SOC 2',          'CC6.1', 'Logical access security over protected information assets', 'identity_detection'),
    ('SOC 2',          'CC7.1', 'Detection of configuration changes and new vulnerabilities', 'posture'),
    ('SOC 2',          'CC7.2', 'Monitoring of system components for anomalies indicative of attacks', 'verified_detection'),
    ('SOC 2',          'CC7.3', 'Evaluation of security events to determine incidents', 'case_triage'),
    ('SOC 2',          'CC7.4', 'Response to identified security incidents', 'response'),
    ('SOC 2',          'CC8.1', 'Change management: authorised, tested, approved changes', 'change_control'),
    ('ISO 27001:2022', 'A.5.25', 'Assessment and decision on information security events', 'case_triage'),
    ('ISO 27001:2022', 'A.5.26', 'Response to information security incidents', 'response'),
    ('ISO 27001:2022', 'A.5.28', 'Collection of evidence', 'evidence'),
    ('ISO 27001:2022', 'A.8.15', 'Logging', 'logging'),
    ('ISO 27001:2022', 'A.8.16', 'Monitoring activities', 'verified_detection'),
    ('ISO 27001:2022', 'A.8.32', 'Change management', 'change_control'),
    ('NIST CSF 2.0',   'DE.CM-01', 'Networks and network services are monitored', 'network_detection'),
    ('NIST CSF 2.0',   'DE.CM-03', 'Personnel activity and technology usage are monitored', 'identity_detection'),
    ('NIST CSF 2.0',   'DE.CM-09', 'Computing hardware, software and their data are monitored', 'endpoint_detection'),
    ('NIST CSF 2.0',   'DE.AE-02', 'Potentially adverse events are analysed', 'case_triage'),
    ('NIST CSF 2.0',   'DE.AE-07', 'Threat intelligence is integrated into analysis', 'intel'),
    ('NIST CSF 2.0',   'RS.MI-01', 'Incidents are contained', 'response'),
    ('NIST CSF 2.0',   'GV.OC-04', 'Critical objectives and dependencies are understood', 'threat_profile')
    AS v(framework, control_id, title, evidence)) s
ON t.framework = s.framework AND t.control_id = s.control_id
WHEN MATCHED THEN UPDATE SET title = s.title, evidence = s.evidence
WHEN NOT MATCHED THEN INSERT VALUES (s.framework, s.control_id, s.title, s.evidence);

CREATE OR REPLACE VIEW SNOWFLAKE_XDR.REFERENCE.V_COMPLIANCE_EVIDENCE AS
WITH latest_canary AS (
    SELECT rule_id, status FROM SNOWFLAKE_XDR.DETECTIONS.CANARY_RUNS
    WHERE run_at > DATEADD('day', -30, CURRENT_TIMESTAMP())
    QUALIFY ROW_NUMBER() OVER (PARTITION BY rule_id ORDER BY run_at DESC) = 1
),
live_rules AS (   -- alerting detections: enabled built-ins plus live (non-shadow) custom and pack rules
    SELECT r.rule_id, UPPER(SPLIT_PART(r.source_table, '.', -1)) AS tbl, k.status AS canary
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES r LEFT JOIN latest_canary k ON k.rule_id = r.rule_id
    WHERE r.enabled AND NOT COALESCE(r.test_mode, FALSE)
    UNION ALL
    SELECT d.rule_id, UPPER(d.data_sources[0]::VARCHAR), k.status
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES d LEFT JOIN latest_canary k ON k.rule_id = d.rule_id
    WHERE d.enabled
),
by_area AS (
    SELECT IFF(tbl IN ('AUTHENTICATION', 'DATABASE_ACTIVITY', 'CLOUD_API', 'EMAIL_ACTIVITY'), 'identity_detection',
           IFF(tbl IN ('NETWORK_TRAFFIC', 'DNS_ACTIVITY', 'WEB_ACTIVITY', 'INTRUSION_DETECTION'), 'network_detection',
           IFF(tbl LIKE 'ENDPOINT%' OR tbl = 'HOT_EDR_ALERTS', 'endpoint_detection', 'other'))) AS evidence,
           COUNT(*) AS live, COUNT_IF(canary = 'pass') AS verified
    FROM live_rules GROUP BY 1
)
SELECT evidence, live AS measure, verified AS verified,
       verified || ' of ' || live || ' live rules canary-verified in the last 30 days' AS detail
FROM by_area WHERE evidence <> 'other'
UNION ALL
SELECT 'verified_detection', COUNT(*), COUNT_IF(canary = 'pass'),
       COUNT_IF(canary = 'pass') || ' of ' || COUNT(*) || ' live rules canary-verified in the last 30 days' FROM live_rules
UNION ALL
SELECT 'case_triage', COUNT(*), COUNT_IF(SNOWFLAKE_XDR.DETECTIONS.IS_HUMAN_VERDICT(disposition_source)),
       COUNT_IF(SNOWFLAKE_XDR.DETECTIONS.IS_HUMAN_VERDICT(disposition_source)) || ' human verdicts and '
           || COUNT_IF(conf_band IS NOT NULL) || ' calibrated scores on ' || COUNT(*) || ' findings (30 days)'
FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE detection_time > DATEADD('day', -30, CURRENT_TIMESTAMP())
UNION ALL
SELECT 'response', COUNT(*), COUNT_IF(status IN ('executed', 'undone', 'rejected')),
       COUNT_IF(status IN ('executed', 'undone')) || ' executed, ' || COUNT_IF(status = 'rejected') || ' rejected, '
           || COUNT_IF(status = 'failed') || ' refused or failed, ' || COUNT_IF(status = 'pending_approval')
           || ' pending of ' || COUNT(*) || ' response requests (90 days); each decided by a named person'
FROM SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS WHERE created_at > DATEADD('day', -90, CURRENT_TIMESTAMP())
UNION ALL
SELECT 'change_control', COUNT(*), COUNT_IF(rationale IS NOT NULL AND status <> 'failed'),
       COUNT(*) || ' detection changes ledgered (' || COUNT_IF(rationale IS NOT NULL) || ' with a written rationale); '
           || COUNT_IF(status = 'approved') || ' human-approved, ' || COUNT_IF(status IN ('promoted', 'applied'))
           || ' canary-gated unattended, ' || COUNT_IF(status = 'rolled_back') || ' rolled back (90 days)'
FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES WHERE created_at > DATEADD('day', -90, CURRENT_TIMESTAMP())
UNION ALL
SELECT 'evidence', COUNT(*), COUNT_IF(latest_report_id IS NOT NULL),
       COUNT_IF(latest_report_id IS NOT NULL) || ' of ' || COUNT(*) || ' cases have a generated incident report; every case keeps an event timeline'
FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE created_at > DATEADD('day', -90, CURRENT_TIMESTAMP())
UNION ALL
SELECT 'logging', COUNT(*), COUNT_IF(last_seen > DATEADD('day', -7, CURRENT_TIMESTAMP())),
       COUNT_IF(last_seen > DATEADD('day', -7, CURRENT_TIMESTAMP())) || ' of ' || COUNT(*)
           || ' registered sources sent data in the last 7 days; CIM mappings: '
           || (SELECT COUNT_IF(status = 'live') FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS) || ' live'
FROM SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES
UNION ALL
SELECT 'intel', COUNT(*), COUNT_IF(last_status = 'ok'),
       COUNT_IF(last_status = 'ok') || ' of ' || COUNT(*) || ' intel feeds healthy; '
           || (SELECT COUNT(*) FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS WHERE active) || ' active IOCs'
FROM SNOWFLAKE_XDR.REFERENCE.INTEL_FEEDS WHERE enabled
UNION ALL
SELECT 'posture', COUNT(*), COUNT(*),
       COUNT(*) || ' Trust Center findings ingested (30 days)'
FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
WHERE detection_source = 'trust_center' AND detection_time > DATEADD('day', -30, CURRENT_TIMESTAMP())
UNION ALL
SELECT 'threat_profile', COUNT(*), COUNT(*), IFF(COUNT(*) > 0, 'threat profile defined and mapped to coverage', 'no threat profile')
FROM SNOWFLAKE_XDR.REFERENCE.THREAT_PROFILE;

-- evidenced: at least half of what the control covers is backed by data; partial: some is
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.REFERENCE.V_COMPLIANCE_REPORT AS
SELECT c.framework, c.control_id, c.title, c.evidence,
       CASE WHEN e.measure > 0 AND e.verified / e.measure >= 0.5 THEN 'evidenced'
            WHEN e.verified > 0 THEN 'partial' ELSE 'no evidence' END AS status,
       COALESCE(e.detail, 'no data') AS detail
FROM SNOWFLAKE_XDR.REFERENCE.COMPLIANCE_CONTROLS c
LEFT JOIN SNOWFLAKE_XDR.REFERENCE.V_COMPLIANCE_EVIDENCE e ON e.evidence = c.evidence;

-- ---------------------------------------------------------------------------
-- 4. Retention tiers
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS SNOWFLAKE_XDR.ARCHIVE COMMENT = 'Cold tier: telemetry older than its hot retention';
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.RETENTION_POLICY (
    table_name   VARCHAR(100) PRIMARY KEY,   -- RAW_LOGS table
    hot_days     NUMBER,                     -- kept in RAW_LOGS for detection
    cold_days    NUMBER,                     -- kept in ARCHIVE (0 = delete after hot)
    cold_format  VARCHAR(20),                -- table | iceberg (needs an external volume)
    external_volume VARCHAR(255)
);
MERGE INTO SNOWFLAKE_XDR.REFERENCE.RETENTION_POLICY t
USING (SELECT * FROM VALUES ('OTEL_LOGS', 30, 365), ('AUTHENTICATION', 90, 365), ('DATABASE_ACTIVITY', 90, 365),
                            ('NETWORK_TRAFFIC', 30, 180), ('DNS_ACTIVITY', 30, 180), ('ENDPOINT_PROCESSES', 90, 365)
       AS v(t, h, c)) s ON t.table_name = s.t
WHEN NOT MATCHED THEN INSERT (table_name, hot_days, cold_days, cold_format) VALUES (s.t, s.h, s.c, 'table');

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.APPLY_RETENTION(P_DRY_RUN BOOLEAN)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import re

NAME_RE = re.compile(r"^[A-Z0-9_]{1,100}$")


def main(s, P_DRY_RUN):
    dry = P_DRY_RUN is not False
    out = []
    for p in [r.as_dict() for r in s.sql("SELECT * FROM SNOWFLAKE_XDR.REFERENCE.RETENTION_POLICY").collect()]:
        t = str(p["TABLE_NAME"]).upper()
        if not NAME_RE.match(t):
            continue
        hot, cold = int(p["HOT_DAYS"] or 90), int(p["COLD_DAYS"] or 0)
        src, arc = f"SNOWFLAKE_XDR.RAW_LOGS.{t}", f"SNOWFLAKE_XDR.ARCHIVE.{t}"
        tcol = "RECEIVED_AT" if t == "OTEL_LOGS" else "_TIME"
        moving = s.sql(f"SELECT COUNT(*) AS n FROM {src} WHERE {tcol} < DATEADD('day', ?, CURRENT_TIMESTAMP())",
                       params=[-hot]).collect()[0]["N"]
        row = {"table": t, "hot_days": hot, "cold_days": cold, "rows_past_hot": moving, "format": p["COLD_FORMAT"]}
        if p["COLD_FORMAT"] == "iceberg" and not p["EXTERNAL_VOLUME"]:
            row["note"] = "iceberg needs an external volume; using a standard archive table"
        if not dry and moving:
            if cold > 0:
                s.sql(f"CREATE TABLE IF NOT EXISTS {arc} LIKE {src}").collect()
                s.sql(f"INSERT INTO {arc} SELECT * FROM {src} WHERE {tcol} < DATEADD('day', ?, CURRENT_TIMESTAMP())",
                      params=[-hot]).collect()
            s.sql(f"DELETE FROM {src} WHERE {tcol} < DATEADD('day', ?, CURRENT_TIMESTAMP())", params=[-hot]).collect()
            if cold > 0:
                s.sql(f"DELETE FROM {arc} WHERE {tcol} < DATEADD('day', ?, CURRENT_TIMESTAMP())", params=[-(hot + cold)]).collect()
            row["moved"] = moving
        out.append(row)
    return {"ok": True, "dry_run": dry, "tables": out}
$$;

-- ---------------------------------------------------------------------------
-- 5. STIX / TAXII 2.1
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.TAXII_SERVERS (
    server_id     VARCHAR(40) PRIMARY KEY,
    name          VARCHAR(200),
    api_root      VARCHAR(500),     -- e.g. https://host/api/v21/
    collection_id VARCHAR(200),     -- NULL = every readable collection
    reliability   FLOAT,
    enabled       BOOLEAN,
    added_after   VARCHAR(40),      -- paging cursor (last X-TAXII-Date-Added-Last)
    last_run_at   TIMESTAMP_LTZ,
    last_status   VARCHAR(40),
    last_count    NUMBER,
    last_error    VARCHAR(1000)
);
MERGE INTO SNOWFLAKE_XDR.REFERENCE.TAXII_SERVERS t
USING (SELECT 'mitre_attack' AS i) s ON t.server_id = s.i
WHEN NOT MATCHED THEN INSERT (server_id, name, api_root, reliability, enabled)
VALUES ('mitre_attack', 'MITRE ATT&CK TAXII 2.1 (connectivity check: serves techniques, not indicators)',
        'https://attack-taxii.mitre.org/api/v21/', 1.0, TRUE);

-- Hosts are added here when a server is registered (ALTER NETWORK RULE ... SET VALUE_LIST)
CREATE NETWORK RULE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.XDR_TAXII_RULE
    MODE = EGRESS TYPE = HOST_PORT VALUE_LIST = ('attack-taxii.mitre.org:443');
CREATE SECRET IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.XDR_TAXII_SECRET TYPE = GENERIC_STRING SECRET_STRING = '__unset__'
    COMMENT = 'Optional TAXII credential: "user:password" (basic) or a bearer token';
CREATE EXTERNAL ACCESS INTEGRATION IF NOT EXISTS XDR_TAXII_EAI
    ALLOWED_NETWORK_RULES = (SNOWFLAKE_XDR.REFERENCE.XDR_TAXII_RULE)
    ALLOWED_AUTHENTICATION_SECRETS = (SNOWFLAKE_XDR.REFERENCE.XDR_TAXII_SECRET)
    ENABLED = TRUE;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.SYNC_TAXII(P_SERVER VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python', 'requests')
HANDLER = 'main'
EXTERNAL_ACCESS_INTEGRATIONS = (XDR_TAXII_EAI)
SECRETS = ('taxii' = SNOWFLAKE_XDR.REFERENCE.XDR_TAXII_SECRET)
EXECUTE AS CALLER
AS
$$
import base64
import json
import re

import requests

R = "SNOWFLAKE_XDR.REFERENCE"
ACCEPT = "application/taxii+json;version=2.1"
# STIX 2.1 comparison expressions we can turn into IOCs (ANDed/ORed patterns yield each value)
PATTERNS = [
    (re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'"), "ip"),
    (re.compile(r"ipv6-addr:value\s*=\s*'([^']+)'"), "ip"),
    (re.compile(r"domain-name:value\s*=\s*'([^']+)'"), "domain"),
    (re.compile(r"url:value\s*=\s*'([^']+)'"), "url"),
    (re.compile(r"file:hashes\.'?SHA-256'?\s*=\s*'([0-9a-fA-F]{64})'"), "hash_sha256"),
    (re.compile(r"file:hashes\.'?MD5'?\s*=\s*'([0-9a-fA-F]{32})'"), "hash_md5"),
]
SELFTEST = {"type": "bundle", "objects": [
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--1", "pattern_type": "stix",
     "pattern": "[ipv4-addr:value = '198.51.100.250']", "valid_from": "2026-11-01T00:00:00Z",
     "confidence": 80, "labels": ["malicious-activity"], "name": "selftest C2"},
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--2", "pattern_type": "stix",
     "pattern": "[domain-name:value = 'selftest-c2.example'] OR [url:value = 'http://selftest-c2.example/a']"},
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--3", "pattern_type": "stix",
     "pattern": "[file:hashes.'SHA-256' = '" + "a" * 64 + "']", "revoked": True},
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--4", "pattern_type": "sigma", "pattern": "title: x"},
    {"type": "attack-pattern", "id": "attack-pattern--1", "name": "not an indicator"},
]}


def auth_headers():
    try:
        import _snowflake
        v = _snowflake.get_generic_secret_string("taxii")
    except Exception:
        v = None
    if not v or v.startswith("__"):
        return {}
    if ":" in v and " " not in v:
        return {"Authorization": "Basic " + base64.b64encode(v.encode()).decode()}
    return {"Authorization": "Bearer " + v}


def indicators(objects):
    """STIX objects -> IOC rows; skips revoked, non-STIX patterns and non-indicators."""
    out = []
    for o in objects:
        if o.get("type") != "indicator" or o.get("revoked") or (o.get("pattern_type") or "stix") != "stix":
            continue
        conf = int(o.get("confidence") or 60)
        for rx, kind in PATTERNS:
            for v in rx.findall(o.get("pattern") or ""):
                out.append([kind, v.lower(), "malware", (o.get("name") or o.get("id"))[:200], 4, conf,
                            o.get("valid_from") or o.get("created"), o.get("modified") or o.get("valid_from"),
                            json.dumps((o.get("labels") or []) + ["taxii"])])
    return out


def get(url, params=None):
    r = requests.get(url, headers={"Accept": ACCEPT, **auth_headers()}, params=params, timeout=60)
    r.raise_for_status()
    return r


def pull(server):
    root = server["API_ROOT"].rstrip("/") + "/"
    cols = [server["COLLECTION_ID"]] if server["COLLECTION_ID"] else \
        [c["id"] for c in get(root + "collections/").json().get("collections", []) if c.get("can_read")]
    objs, last_added, errors = [], server["ADDED_AFTER"], []
    for cid in cols[:20]:
        params, pages = {"limit": 500}, 0
        if server["ADDED_AFTER"]:
            params["added_after"] = server["ADDED_AFTER"]
        while pages < 50:
            try:
                r = get(f"{root}collections/{cid}/objects/", params)
            except requests.HTTPError as e:
                if pages == 0:
                    raise
                # keep what was already paged in; the cursor only advances past what we stored
                errors.append(f"{cid}: stopped after {pages} page(s): {str(e)[:120]}")
                break
            body = r.json()
            objs += body.get("objects") or []
            last_added = r.headers.get("X-TAXII-Date-Added-Last") or last_added
            pages += 1
            if not body.get("more") or not body.get("next"):
                break
            params = {"limit": 500, "next": body["next"]}
    return objs, last_added, len(cols), errors


def merge(s, rows_):
    if not rows_:
        return 0
    cols = ["IOC_TYPE", "IOC_VALUE", "THREAT_TYPE", "THREAT_NAME", "SEVERITY", "CONFIDENCE", "FIRST_SEEN", "LAST_SEEN", "TAGS"]
    s.create_dataframe(rows_, schema=cols).write.save_as_table("XDR_TAXII_STAGE", mode="overwrite", table_type="temporary")
    before = s.sql(f"SELECT COUNT(*) n FROM {R}.THREAT_INTEL_IOCS").collect()[0][0]
    s.sql(f"""MERGE INTO {R}.THREAT_INTEL_IOCS t
              USING (SELECT ioc_type, ioc_value, ANY_VALUE(threat_name) AS threat_name, MAX(confidence) AS confidence,
                            MIN(TRY_TO_TIMESTAMP_LTZ(first_seen)) AS first_seen, ANY_VALUE(tags) AS tags
                     FROM XDR_TAXII_STAGE GROUP BY 1, 2) s
              ON t.ioc_type = s.ioc_type AND LOWER(t.ioc_value) = s.ioc_value
              WHEN MATCHED THEN UPDATE SET t.last_seen = CURRENT_TIMESTAMP(),
                   t.sources = ARRAY_DISTINCT(ARRAY_APPEND(COALESCE(t.sources, ARRAY_CONSTRUCT()), 'taxii')),
                   t.sightings = COALESCE(t.sightings, 1) + 1, t.updated_at = CURRENT_TIMESTAMP()
              WHEN NOT MATCHED THEN INSERT (ioc_type, ioc_value, threat_type, threat_name, severity, confidence, base_confidence,
                   source, sources, first_seen, last_seen, tags, active, status, sightings, updated_at)
              VALUES (s.ioc_type, s.ioc_value, 'malware', s.threat_name, 4, s.confidence, s.confidence, 'taxii',
                      ARRAY_CONSTRUCT('taxii'), COALESCE(s.first_seen, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP(),
                      TRY_PARSE_JSON(s.tags), TRUE, 'active', 1, CURRENT_TIMESTAMP())""").collect()
    return s.sql(f"SELECT COUNT(*) n FROM {R}.THREAT_INTEL_IOCS").collect()[0][0] - before


def main(s, P_SERVER):
    which = (P_SERVER or "all").strip()
    if which == "selftest":
        rows_ = indicators(SELFTEST["objects"])
        kinds = sorted({r[0] for r in rows_})
        ok = kinds == ["domain", "ip", "url"] and len(rows_) == 3
        return {"ok": ok, "selftest": True, "parsed": [r[:2] for r in rows_],
                "message": "STIX parser: 3 IOCs from 5 objects (revoked, Sigma-pattern and non-indicator objects skipped)"
                           if ok else "unexpected parse result"}
    servers = [r.as_dict() for r in s.sql(f"SELECT * FROM {R}.TAXII_SERVERS WHERE enabled"
                                           + ("" if which == "all" else " AND server_id = ?"),
                                           params=None if which == "all" else [which]).collect()]
    out = {}
    for srv in servers:
        try:
            objs, last_added, ncols, partial = pull(srv)
            rows_ = indicators(objs)
            new = merge(s, rows_)
            status, err = ("partial", "; ".join(partial)[:900]) if partial else ("ok", None)
            out[srv["SERVER_ID"]] = {"collections": ncols, "objects": len(objs), "indicators": len(rows_), "new_iocs": new,
                                     **({"partial": partial} if partial else {})}
        except Exception as e:
            status, err, last_added, rows_ = "error", str(e)[:900], srv["ADDED_AFTER"], []
            out[srv["SERVER_ID"]] = {"error": err[:200]}
        s.sql(f"""UPDATE {R}.TAXII_SERVERS SET last_run_at = CURRENT_TIMESTAMP(), last_status = ?, last_count = ?,
                    last_error = ?, added_after = ? WHERE server_id = ?""",
              params=[status, len(rows_), err, last_added, srv["SERVER_ID"]]).collect()
    return {"ok": all("error" not in v for v in out.values()), "servers": out}
$$;

-- ---------------------------------------------------------------------------
-- 6. Retro-hunt: IOCs learned recently, searched across 30 days of telemetry
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RETRO_HUNT_IOCS(P_LEARNED_HOURS NUMBER)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_hours NUMBER := LEAST(GREATEST(COALESCE(:P_LEARNED_HOURS, 24), 1), 24 * 30);
    v_n NUMBER;
    v_checked NUMBER;
    v_hits NUMBER;
BEGIN
    CREATE OR REPLACE TEMPORARY TABLE XDR_RETRO_IOCS AS
    SELECT LOWER(ioc_value) AS v, ioc_type, threat_name, COALESCE(severity, 3) AS severity, COALESCE(confidence, 50) AS confidence
    FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
    WHERE active AND COALESCE(status, 'active') = 'active'
      AND GREATEST_IGNORE_NULLS(updated_at, first_seen) > DATEADD('hour', -:v_hours, CURRENT_TIMESTAMP());

    CREATE OR REPLACE TEMPORARY TABLE XDR_RETRO_HITS AS
    SELECT i.v, i.ioc_type, i.threat_name, i.severity, i.confidence, 'NETWORK_TRAFFIC' AS tbl,
           MIN(n._time) AS first_time, MAX(n._time) AS last_time, COUNT(*) AS hits, ANY_VALUE(n.src_ip) AS src, ANY_VALUE(n.dest) AS dest,
           ANY_VALUE(n.src) AS user_name
    FROM XDR_RETRO_IOCS i JOIN SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC n
      ON i.ioc_type = 'ip' AND (n.dest_ip = i.v OR n.src_ip = i.v)
    WHERE n._time > DATEADD('day', -30, CURRENT_TIMESTAMP()) GROUP BY 1, 2, 3, 4, 5
    UNION ALL
    SELECT i.v, i.ioc_type, i.threat_name, i.severity, i.confidence, 'AUTHENTICATION',
           MIN(a._time), MAX(a._time), COUNT(*), ANY_VALUE(a.src), ANY_VALUE(a.dest), ANY_VALUE(a.user_name)
    FROM XDR_RETRO_IOCS i JOIN SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION a ON i.ioc_type = 'ip' AND a.src = i.v
    WHERE a._time > DATEADD('day', -30, CURRENT_TIMESTAMP()) GROUP BY 1, 2, 3, 4, 5
    UNION ALL
    SELECT i.v, i.ioc_type, i.threat_name, i.severity, i.confidence, 'DNS_ACTIVITY',
           MIN(d._time), MAX(d._time), COUNT(*), ANY_VALUE(d.src), ANY_VALUE(d.query), ANY_VALUE(d.src)
    FROM XDR_RETRO_IOCS i JOIN SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY d
      ON i.ioc_type = 'domain' AND (LOWER(d.query) = i.v OR ENDSWITH(LOWER(d.query), '.' || i.v))
    WHERE d._time > DATEADD('day', -30, CURRENT_TIMESTAMP()) GROUP BY 1, 2, 3, 4, 5
    UNION ALL
    SELECT i.v, i.ioc_type, i.threat_name, i.severity, i.confidence, 'WEB_ACTIVITY',
           MIN(w._time), MAX(w._time), COUNT(*), ANY_VALUE(w.src), ANY_VALUE(w.url), ANY_VALUE(w.src)
    FROM XDR_RETRO_IOCS i JOIN SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY w
      ON (i.ioc_type = 'url' AND LOWER(w.url) = i.v) OR (i.ioc_type = 'domain' AND LOWER(w.dest) = i.v)
    WHERE w._time > DATEADD('day', -30, CURRENT_TIMESTAMP()) GROUP BY 1, 2, 3, 4, 5;

    -- one finding per IOC and source table; canary rows never count
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        (finding_id, rule_id, description, category, severity, mitre_tactic_id, mitre_technique_id, user_name, src, dest,
         event_time, detection_time, detection_source, confidence, evidence_count, evidence, risk_score, status)
    SELECT UUID_STRING(), 'INTEL-RETRO-001',
           'Retro-hunt: ' || h.ioc_type || ' ' || h.v || ' (' || COALESCE(h.threat_name, 'threat intel') || ') seen '
               || h.hits || 'x in ' || h.tbl || ' before it was known bad',
           'threat_intel', h.severity, 'TA0011', 'T1071', h.user_name, h.src, h.dest,
           h.first_time, CURRENT_TIMESTAMP(), 'retro_hunt', h.confidence, h.hits,
           OBJECT_CONSTRUCT('ioc_value', h.v, 'ioc_type', h.ioc_type, 'table', h.tbl, 'first_seen', h.first_time,
                            'last_seen', h.last_time, 'hits', h.hits),
           h.severity * 20, 'new'
    FROM XDR_RETRO_HITS h
    WHERE NOT CONTAINS(LOWER(COALESCE(h.user_name, '') || '|' || COALESCE(h.src, '') || '|' || COALESCE(h.dest, '')), 'xdrcanary')
      AND NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
                      WHERE f.rule_id = 'INTEL-RETRO-001' AND f.evidence:ioc_value::VARCHAR = h.v AND f.evidence:table::VARCHAR = h.tbl);
    v_n := SQLROWCOUNT;
    SELECT COUNT(*) INTO :v_checked FROM XDR_RETRO_IOCS;
    SELECT COUNT(*) INTO :v_hits FROM XDR_RETRO_HITS;
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'iocs_checked', :v_checked, 'sightings', :v_hits, 'new_findings', :v_n);
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.RUN_TAXII_RETRO()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    t VARIANT;
    h VARIANT;
BEGIN
    CALL SNOWFLAKE_XDR.REFERENCE.SYNC_TAXII('all') INTO :t;
    CALL SNOWFLAKE_XDR.DETECTIONS.RETRO_HUNT_IOCS(24) INTO :h;
    RETURN OBJECT_CONSTRUCT('taxii', :t, 'retro_hunt', :h);
END;
$$;

CREATE OR REPLACE TASK SNOWFLAKE_XDR.REFERENCE.TASK_TAXII_RETRO
    WAREHOUSE = XDR_WH
    SCHEDULE = 'USING CRON 15 */4 * * * UTC'
    COMMENT = 'Every 4 hours: pull TAXII collections, then retro-hunt IOCs learned in the last day'
AS
    CALL SNOWFLAKE_XDR.REFERENCE.RUN_TAXII_RETRO();
ALTER TASK SNOWFLAKE_XDR.REFERENCE.TASK_TAXII_RETRO RESUME;
