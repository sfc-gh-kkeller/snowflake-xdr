-- ============================================================================
-- Snowflake XDR - 28: Threat intelligence that keeps itself current
-- ============================================================================
-- Pulls public threat intelligence on a schedule through an External Access
-- Integration and turns it into trustworthy signal:
--
--   IOC feeds        abuse.ch Feodo Tracker (C2 IPs); ThreatFox + URLhaus when an
--                    abuse.ch Auth-Key secret is set
--   Warninglists     MISP warninglists (public DNS, cloud/CDN ranges, top sites,
--                    known TI false positives) neutralise benign indicators
--                    before they ever match telemetry
--   IOC confidence   source reliability x age decay + corroboration, expiry by
--                    type, analyst feedback; DET-021 uses the effective value
--   MITRE ATT&CK     full Enterprise catalog synced from MITRE's STIX bundle,
--                    new / changed techniques flagged
--   CISA KEV         Known Exploited Vulnerabilities catalog
--   Sigma            SigmaHQ core rules indexed by technique and log source;
--                    the Detection Autopilot uses them as reference logic and
--                    adds uncovered Sigma techniques to its backlog
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Egress for the feeds
-- ---------------------------------------------------------------------------
CREATE OR REPLACE NETWORK RULE SNOWFLAKE_XDR.REFERENCE.XDR_INTEL_RULE
    MODE = EGRESS
    TYPE = HOST_PORT
    VALUE_LIST = ('feodotracker.abuse.ch:443', 'threatfox-api.abuse.ch:443', 'urlhaus-api.abuse.ch:443',
                  'www.cisa.gov:443', 'raw.githubusercontent.com:443', 'github.com:443',
                  'objects.githubusercontent.com:443', 'release-assets.githubusercontent.com:443',
                  'codeload.github.com:443');

-- abuse.ch now requires a free Auth-Key for ThreatFox and URLhaus
-- (https://auth.abuse.ch). Until it is set those two feeds report 'needs_key'.
--   ALTER SECRET SNOWFLAKE_XDR.REFERENCE.ABUSE_CH_AUTH_KEY SET SECRET_STRING = '<key>';
CREATE SECRET IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.ABUSE_CH_AUTH_KEY
    TYPE = GENERIC_STRING
    SECRET_STRING = '__ABUSE_CH_AUTH_KEY__'
    COMMENT = 'abuse.ch Auth-Key for ThreatFox / URLhaus';

CREATE EXTERNAL ACCESS INTEGRATION IF NOT EXISTS XDR_INTEL_EAI
    ALLOWED_NETWORK_RULES = (SNOWFLAKE_XDR.REFERENCE.XDR_INTEL_RULE)
    ALLOWED_AUTHENTICATION_SECRETS = (SNOWFLAKE_XDR.REFERENCE.ABUSE_CH_AUTH_KEY)
    ENABLED = TRUE
    COMMENT = 'XDR threat intelligence feeds';
ALTER EXTERNAL ACCESS INTEGRATION XDR_INTEL_EAI
    SET ALLOWED_AUTHENTICATION_SECRETS = (SNOWFLAKE_XDR.REFERENCE.ABUSE_CH_AUTH_KEY);

-- ---------------------------------------------------------------------------
-- 2. Feed registry and run log
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.INTEL_FEEDS (
    feed_id         VARCHAR(50) PRIMARY KEY,
    name            VARCHAR(200),
    kind            VARCHAR(20),      -- ioc | warninglist | attack | kev | sigma
    url             VARCHAR(1000),
    reliability     FLOAT,            -- 0-1 source reliability used in IOC confidence
    enabled         BOOLEAN DEFAULT TRUE,
    last_run_at     TIMESTAMP_LTZ,
    last_status     VARCHAR(30),      -- ok | error | needs_key | disabled
    last_count      NUMBER,
    last_new        NUMBER,
    last_error      VARCHAR(1000)
);

MERGE INTO SNOWFLAKE_XDR.REFERENCE.INTEL_FEEDS t
USING (
    SELECT * FROM VALUES
    ('feodo',        'abuse.ch Feodo Tracker C2 IP blocklist', 'ioc',
     'https://feodotracker.abuse.ch/downloads/ipblocklist.json', 0.9),
    ('threatfox',    'abuse.ch ThreatFox IOCs (last 3 days)', 'ioc',
     'https://threatfox-api.abuse.ch/api/v1/', 0.8),
    ('urlhaus',      'abuse.ch URLhaus malware URLs', 'ioc',
     'https://urlhaus-api.abuse.ch/v1/urls/recent/', 0.8),
    ('misp_warninglists', 'MISP warninglists (benign infrastructure)', 'warninglist',
     'https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/', 1.0),
    ('mitre_attack', 'MITRE ATT&CK Enterprise (STIX 2)', 'attack',
     'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json', 1.0),
    ('cisa_kev',     'CISA Known Exploited Vulnerabilities', 'kev',
     'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 1.0),
    ('sigma',        'SigmaHQ core detection rules', 'sigma',
     'https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_core.zip', 0.8)
    AS v(feed_id, name, kind, url, reliability)
) s ON t.feed_id = s.feed_id
WHEN NOT MATCHED THEN INSERT (feed_id, name, kind, url, reliability)
    VALUES (s.feed_id, s.name, s.kind, s.url, s.reliability);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.INTEL_FEED_RUNS (
    run_id      VARCHAR DEFAULT UUID_STRING(),
    feed_id     VARCHAR(50),
    started_at  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    seconds     FLOAT,
    status      VARCHAR(30),
    fetched     NUMBER,
    new_items   NUMBER,
    detail      VARCHAR(2000)
);

-- Reliability of the sources already in THREAT_INTEL_IOCS (seed data, analysts)
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.INTEL_SOURCE_RELIABILITY (
    source       VARCHAR(100) PRIMARY KEY,
    reliability  FLOAT,
    note         VARCHAR(300)
);
MERGE INTO SNOWFLAKE_XDR.REFERENCE.INTEL_SOURCE_RELIABILITY t
USING (SELECT * FROM VALUES
    ('feodo', 0.9, 'abuse.ch Feodo Tracker'), ('abuse.ch', 0.9, 'abuse.ch (seed)'),
    ('threatfox', 0.8, 'abuse.ch ThreatFox'), ('urlhaus', 0.8, 'abuse.ch URLhaus'),
    ('crowdstrike', 0.95, 'commercial'), ('virustotal', 0.85, 'commercial'),
    ('greynoise', 0.7, 'scanner intel - often benign mass scanning'),
    ('internal_research', 0.9, 'own investigations'), ('analyst', 1.0, 'added by an analyst'),
    ('osint_paste', 0.4, 'unvetted OSINT paste lists'), ('ui', 1.0, 'added in the console'),
    ('agent', 0.9, 'added through Ask XDR'), ('manual', 1.0, 'added in Rules & IOCs')
    AS v(source, reliability, note)) s ON t.source = s.source
WHEN NOT MATCHED THEN INSERT (source, reliability, note) VALUES (s.source, s.reliability, s.note);

-- ---------------------------------------------------------------------------
-- 3. IOC lifecycle columns
-- ---------------------------------------------------------------------------
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS ADD COLUMN IF NOT EXISTS base_confidence NUMBER(3);
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS ADD COLUMN IF NOT EXISTS sources ARRAY;
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS ADD COLUMN IF NOT EXISTS sightings NUMBER;
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS ADD COLUMN IF NOT EXISTS status VARCHAR(20);
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS ADD COLUMN IF NOT EXISTS status_reason VARCHAR(500);
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS ADD COLUMN IF NOT EXISTS confidence_factors VARIANT;
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS ADD COLUMN IF NOT EXISTS pinned BOOLEAN;
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP_LTZ;

-- One-time initialisation of rows that predate the lifecycle columns. Seed
-- IOCs count as seen recently so the demo campaigns still match.
UPDATE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
SET base_confidence = COALESCE(base_confidence, confidence),
    sources = COALESCE(sources, ARRAY_CONSTRUCT(source)),
    last_seen = COALESCE(last_seen, DATEADD('day', -2, CURRENT_TIMESTAMP())),
    status = COALESCE(status, 'active'),
    sightings = COALESCE(sightings, 1),
    pinned = COALESCE(pinned, FALSE),
    updated_at = COALESCE(updated_at, CURRENT_TIMESTAMP())
WHERE base_confidence IS NULL OR sources IS NULL OR last_seen IS NULL OR status IS NULL OR pinned IS NULL;

-- A classic feed false positive: malware resolves through public DNS, so OSINT
-- lists publish 8.8.8.8 as an "indicator". The warninglist must neutralise it.
INSERT INTO SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
    (ioc_type, ioc_value, threat_type, threat_name, severity, confidence, base_confidence,
     source, sources, first_seen, last_seen, active, status)
SELECT 'ip', '8.8.8.8', 'c2', 'DNS resolver used by malware (OSINT paste)', 4, 60, 60,
       'osint_paste', ARRAY_CONSTRUCT('osint_paste'), DATEADD('day', -1, CURRENT_TIMESTAMP()),
       DATEADD('day', -1, CURRENT_TIMESTAMP()), TRUE, 'active'
WHERE NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
                  WHERE ioc_type = 'ip' AND ioc_value = '8.8.8.8');

-- Verdict provenance (who decided): analyst | review | fp_model | suppression | control | confidence_model.
-- Only human verdicts (analyst, review) train the FP model and IOC feedback. See 29_confidence.sql.
ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS ADD COLUMN IF NOT EXISTS disposition_source VARCHAR(30);
ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS ADD COLUMN IF NOT EXISTS verdict_by VARCHAR(255);

-- ---------------------------------------------------------------------------
-- 4. Warninglist (known-benign infrastructure) + local allowlist
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.INTEL_WARNINGLIST (
    list_name   VARCHAR(100),     -- MISP list name, or 'local' for analyst allowlist entries
    entry_type  VARCHAR(20),      -- cidr | hostname | string
    value       VARCHAR(1000),
    ip_start    NUMBER,           -- IPv4 range for cidr entries
    ip_end      NUMBER,
    reason      VARCHAR(500),
    added_by    VARCHAR(255),
    added_at    TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- Private and reserved ranges never count as threat infrastructure
DELETE FROM SNOWFLAKE_XDR.REFERENCE.INTEL_WARNINGLIST WHERE list_name = 'reserved';
INSERT INTO SNOWFLAKE_XDR.REFERENCE.INTEL_WARNINGLIST (list_name, entry_type, value, ip_start, ip_end, reason, added_by)
SELECT 'reserved', 'cidr', c, PARSE_IP(c, 'INET'):ipv4_range_start::NUMBER, PARSE_IP(c, 'INET'):ipv4_range_end::NUMBER,
       'RFC1918 / reserved range', 'setup'
FROM (SELECT column1 AS c FROM VALUES ('10.0.0.0/8'), ('172.16.0.0/12'), ('192.168.0.0/16'),
                                       ('127.0.0.0/8'), ('169.254.0.0/16'), ('0.0.0.0/8'));

-- Hard lists neutralise an indicator; soft lists (shared cloud / CDN space, where
-- attackers also host C2 and addresses get reassigned) only lower confidence.
CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.REFERENCE.WARNINGLIST_IS_SOFT(LIST_NAME VARCHAR)
RETURNS BOOLEAN
AS $$ LIST_NAME IN ('amazon-aws', 'microsoft-azure', 'akamai', 'cloudflare') $$;

-- Is an indicator on a warninglist? Returns the list name or NULL.
CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.REFERENCE.WARNINGLIST_MATCH(T VARCHAR, V VARCHAR)
RETURNS VARCHAR
AS
$$
    SELECT MIN(list_name) FROM SNOWFLAKE_XDR.REFERENCE.INTEL_WARNINGLIST w
    WHERE (T = 'ip' AND w.entry_type = 'cidr'
           AND TRY_CAST(PARSE_IP(V, 'INET', 1):ipv4::VARCHAR AS NUMBER) BETWEEN w.ip_start AND w.ip_end)
       OR (T IN ('domain', 'url') AND w.entry_type = 'hostname'
           AND (LOWER(V) = w.value OR ENDSWITH(LOWER(V), '.' || w.value)))
       OR (w.entry_type = 'string' AND LOWER(V) = w.value)
$$;

-- ---------------------------------------------------------------------------
-- 5. Catalogs: ATT&CK, KEV, Sigma
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.ATTACK_CATALOG (
    technique_id      VARCHAR(20) PRIMARY KEY,
    name              VARCHAR(300),
    tactics           ARRAY,
    platforms         ARRAY,
    data_sources      ARRAY,
    description       VARCHAR(2000),
    url               VARCHAR(300),
    is_subtechnique   BOOLEAN,
    attack_modified   TIMESTAMP_LTZ,
    first_synced_at   TIMESTAMP_LTZ,
    last_synced_at    TIMESTAMP_LTZ,
    change_kind       VARCHAR(20)      -- new | updated | unchanged (vs. previous sync)
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.KEV_CATALOG (
    cve_id            VARCHAR(30) PRIMARY KEY,
    vendor            VARCHAR(200),
    product           VARCHAR(200),
    name              VARCHAR(500),
    date_added        DATE,
    due_date          DATE,
    ransomware        VARCHAR(20),
    short_description VARCHAR(2000),
    required_action   VARCHAR(1000),
    cwes              ARRAY,
    first_synced_at   TIMESTAMP_LTZ,
    last_synced_at    TIMESTAMP_LTZ
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.SIGMA_RULES (
    sigma_id          VARCHAR(64) PRIMARY KEY,
    title             VARCHAR(500),
    status            VARCHAR(30),
    level             VARCHAR(20),
    product           VARCHAR(50),
    category          VARCHAR(80),
    service           VARCHAR(80),
    cim_table         VARCHAR(50),     -- our RAW_LOGS table for this log source, NULL if unmapped
    techniques        ARRAY,
    tactics           ARRAY,
    description       VARCHAR(2000),
    falsepositives    ARRAY,
    detection_yaml    VARCHAR,         -- logsource + detection sections, for prompts
    path              VARCHAR(500),
    modified          VARCHAR(20),
    first_synced_at   TIMESTAMP_LTZ,
    last_synced_at    TIMESTAMP_LTZ
);

-- ---------------------------------------------------------------------------
-- 6. Feed sync (one Python procedure for all feeds)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.SYNC_THREAT_INTEL(P_FEED VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python', 'requests', 'pyyaml')
HANDLER = 'main'
EXTERNAL_ACCESS_INTEGRATIONS = (XDR_INTEL_EAI)
SECRETS = ('abuse_ch' = SNOWFLAKE_XDR.REFERENCE.ABUSE_CH_AUTH_KEY)
EXECUTE AS CALLER
AS
$$
import io
import ipaddress
import json
import time
import zipfile

import requests
import yaml

R = "SNOWFLAKE_XDR.REFERENCE"
UA = {"User-Agent": "snowflake-xdr-threat-intel/1.0"}
WARNINGLISTS = {            # MISP list -> max entries kept
    "public-dns-v4": 100000, "google": 10000, "cloudflare": 1000, "akamai": 2000,
    "amazon-aws": 10000, "microsoft-azure": 10000, "microsoft-office365": 2000,
    "crl-hostname": 1000, "tranco": 20000, "ti-falsepositives": 30000,
}
# Sigma log source -> our CIM table
SIGMA_MAP = {
    ("windows", "process_creation"): "ENDPOINT_PROCESSES", ("linux", "process_creation"): "ENDPOINT_PROCESSES",
    ("macos", "process_creation"): "ENDPOINT_PROCESSES",
    ("windows", "registry_set"): "ENDPOINT_REGISTRY", ("windows", "registry_event"): "ENDPOINT_REGISTRY",
    ("windows", "registry_add"): "ENDPOINT_REGISTRY", ("windows", "registry_delete"): "ENDPOINT_REGISTRY",
    ("windows", "file_event"): "ENDPOINT_FILESYSTEM", ("linux", "file_event"): "ENDPOINT_FILESYSTEM",
    ("windows", "network_connection"): "NETWORK_TRAFFIC", ("linux", "network_connection"): "NETWORK_TRAFFIC",
    ("windows", "dns_query"): "DNS_ACTIVITY", (None, "dns"): "DNS_ACTIVITY",
    (None, "proxy"): "WEB_ACTIVITY", (None, "webserver"): "WEB_ACTIVITY",
    ("aws", "cloudtrail"): "CLOUD_API", ("windows", "security"): "AUTHENTICATION",
}


def get(url, **kw):
    r = requests.get(url, timeout=kw.pop("timeout", 120), headers={**UA, **kw.pop("headers", {})}, **kw)
    r.raise_for_status()
    return r


def stage(s, name, cols, data):
    """Write rows to a temporary table (variant-ish values as JSON strings)."""
    df = s.create_dataframe(data or [[None] * len(cols)], schema=cols)
    df.write.save_as_table(name, mode="overwrite", table_type="temporary")
    if not data:
        s.sql(f"DELETE FROM {name}").collect()


def abuse_key():
    try:
        import _snowflake
        k = _snowflake.get_generic_secret_string("abuse_ch")
    except Exception:
        return None
    return None if not k or k.startswith("__") else k


def merge_iocs(s, feed, rows_):
    """rows_: (type, value, threat_type, threat_name, severity, confidence, first_seen, last_seen, tags_json)."""
    stage(s, "XDR_INTEL_IOC_STAGE",
          ["IOC_TYPE", "IOC_VALUE", "THREAT_TYPE", "THREAT_NAME", "SEVERITY", "CONFIDENCE",
           "FIRST_SEEN", "LAST_SEEN", "TAGS"], rows_)
    before = s.sql(f"SELECT COUNT(*) n FROM {R}.THREAT_INTEL_IOCS").collect()[0][0]
    s.sql(f"""
        MERGE INTO {R}.THREAT_INTEL_IOCS t
        USING (SELECT ioc_type, LOWER(ioc_value) AS ioc_value, ANY_VALUE(threat_type) AS threat_type,
                      ANY_VALUE(threat_name) AS threat_name, MAX(severity) AS severity,
                      MAX(confidence) AS confidence, MIN(TRY_TO_TIMESTAMP_LTZ(first_seen)) AS first_seen,
                      MAX(TRY_TO_TIMESTAMP_LTZ(last_seen)) AS last_seen, ANY_VALUE(tags) AS tags
               FROM XDR_INTEL_IOC_STAGE WHERE ioc_value IS NOT NULL GROUP BY 1, 2) s
        ON t.ioc_type = s.ioc_type AND LOWER(t.ioc_value) = s.ioc_value
        WHEN MATCHED THEN UPDATE SET
            t.last_seen = GREATEST_IGNORE_NULLS(t.last_seen, s.last_seen, CURRENT_TIMESTAMP()),
            t.base_confidence = GREATEST_IGNORE_NULLS(t.base_confidence, s.confidence),
            t.sources = ARRAY_DISTINCT(ARRAY_APPEND(COALESCE(t.sources, ARRAY_CONSTRUCT()), '{feed}')),
            t.sightings = COALESCE(t.sightings, 1) + 1,
            t.threat_name = COALESCE(t.threat_name, s.threat_name),
            t.updated_at = CURRENT_TIMESTAMP()
        WHEN NOT MATCHED THEN INSERT (ioc_type, ioc_value, threat_type, threat_name, severity, confidence,
              base_confidence, source, sources, first_seen, last_seen, tags, active, status, sightings, updated_at)
            VALUES (s.ioc_type, s.ioc_value, s.threat_type, s.threat_name, s.severity, s.confidence,
              s.confidence, '{feed}', ARRAY_CONSTRUCT('{feed}'), COALESCE(s.first_seen, CURRENT_TIMESTAMP()),
              COALESCE(s.last_seen, CURRENT_TIMESTAMP()), TRY_PARSE_JSON(s.tags), TRUE, 'active', 1,
              CURRENT_TIMESTAMP())""").collect()
    after = s.sql(f"SELECT COUNT(*) n FROM {R}.THREAT_INTEL_IOCS").collect()[0][0]
    return len(rows_), after - before


# ---------------------------------------------------------------- feeds
def feed_feodo(s, f):
    data = get(f["URL"]).json()
    rows_ = []
    for d in data:
        online = (d.get("status") or "").lower() == "online"
        rows_.append(["ip", d.get("ip_address"), "c2", f"{d.get('malware') or 'botnet'} C2",
                      5 if online else 4, 90 if online else 70, d.get("first_seen"),
                      d.get("last_online") or d.get("first_seen"),
                      json.dumps([d.get("malware"), f"port:{d.get('port')}", d.get("status")])])
    return merge_iocs(s, "feodo", rows_)


def feed_threatfox(s, f):
    key = abuse_key()
    if not key:
        return None
    r = requests.post(f["URL"], json={"query": "get_iocs", "days": 3},
                      headers={**UA, "Auth-Key": key}, timeout=120)
    r.raise_for_status()
    rows_ = []
    kind = {"ip:port": "ip", "domain": "domain", "url": "url", "sha256_hash": "hash_sha256", "md5_hash": "hash_md5"}
    for d in r.json().get("data") or []:
        t = kind.get(d.get("ioc_type"))
        if not t:
            continue
        v = d.get("ioc", "")
        if t == "ip":
            v = v.split(":")[0]
        rows_.append([t, v, "c2" if "cc" in (d.get("threat_type") or "") else "malware",
                      d.get("malware_printable"), 4, int(d.get("confidence_level") or 50),
                      d.get("first_seen"), d.get("last_seen") or d.get("first_seen"),
                      json.dumps(d.get("tags") or [])])
    return merge_iocs(s, "threatfox", rows_)


def feed_urlhaus(s, f):
    key = abuse_key()
    if not key:
        return None
    r = requests.get(f["URL"], headers={**UA, "Auth-Key": key}, timeout=120)
    r.raise_for_status()
    rows_ = []
    for d in (r.json().get("urls") or [])[:5000]:
        if d.get("url_status") != "online":
            continue
        rows_.append(["url", d.get("url"), "malware", d.get("threat") or "malware_download", 4, 75,
                      d.get("date_added"), d.get("date_added"), json.dumps(d.get("tags") or [])])
    return merge_iocs(s, "urlhaus", rows_)


def feed_warninglists(s, f):
    rows_ = []
    for name, cap in WARNINGLISTS.items():
        try:
            j = get(f["URL"] + name + "/list.json").json()
        except Exception:
            continue
        typ = j.get("type", "string")
        for v in (j.get("list") or [])[:cap]:
            v = str(v).strip().lower()
            if not v:
                continue
            if typ == "cidr":
                try:
                    net = ipaddress.ip_network(v, strict=False)
                except ValueError:
                    continue
                if net.version != 4:
                    continue
                rows_.append([name, "cidr", v, int(net.network_address), int(net.broadcast_address)])
            else:
                rows_.append([name, "hostname" if typ in ("hostname", "substring") else "string",
                              v.lstrip("."), None, None])
    stage(s, "XDR_INTEL_WL_STAGE", ["LIST_NAME", "ENTRY_TYPE", "VALUE", "IP_START", "IP_END"], rows_)
    s.sql(f"DELETE FROM {R}.INTEL_WARNINGLIST WHERE list_name NOT IN ('local', 'reserved')").collect()
    s.sql(f"""INSERT INTO {R}.INTEL_WARNINGLIST (list_name, entry_type, value, ip_start, ip_end, reason, added_by)
              SELECT list_name, entry_type, value, ip_start, ip_end, 'MISP warninglist ' || list_name, 'misp'
              FROM XDR_INTEL_WL_STAGE""").collect()
    return len(rows_), len(rows_)


def feed_attack(s, f):
    bundle = get(f["URL"], timeout=300).json()
    tactics = {o["x_mitre_shortname"]: next((r["external_id"] for r in o.get("external_references", [])
                                             if r.get("source_name") == "mitre-attack"), None)
               for o in bundle["objects"] if o.get("type") == "x-mitre-tactic"}
    rows_ = []
    for o in bundle["objects"]:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ref or "enterprise-attack" not in (o.get("x_mitre_domains") or ["enterprise-attack"]):
            continue
        tac = [tactics.get(k["phase_name"]) for k in o.get("kill_chain_phases", [])
               if k.get("kill_chain_name") == "mitre-attack"]
        rows_.append([ref["external_id"], o.get("name"), json.dumps([t for t in tac if t]),
                      json.dumps(o.get("x_mitre_platforms") or []), json.dumps(o.get("x_mitre_data_sources") or []),
                      (o.get("description") or "")[:2000], ref.get("url"), bool(o.get("x_mitre_is_subtechnique")),
                      o.get("modified")])
    stage(s, "XDR_INTEL_ATTACK_STAGE", ["TECHNIQUE_ID", "NAME", "TACTICS", "PLATFORMS", "DATA_SOURCES",
                                        "DESCRIPTION", "URL", "IS_SUB", "MODIFIED"], rows_)
    first = s.sql(f"SELECT COUNT(*) FROM {R}.ATTACK_CATALOG").collect()[0][0] == 0
    s.sql(f"UPDATE {R}.ATTACK_CATALOG SET change_kind = 'unchanged'").collect()
    s.sql(f"""
        MERGE INTO {R}.ATTACK_CATALOG t
        USING XDR_INTEL_ATTACK_STAGE s ON t.technique_id = s.technique_id
        WHEN MATCHED AND t.attack_modified IS DISTINCT FROM TRY_TO_TIMESTAMP_LTZ(s.modified) THEN UPDATE SET
            t.name = s.name, t.tactics = PARSE_JSON(s.tactics), t.platforms = PARSE_JSON(s.platforms),
            t.data_sources = PARSE_JSON(s.data_sources), t.description = s.description, t.url = s.url,
            t.attack_modified = TRY_TO_TIMESTAMP_LTZ(s.modified), t.last_synced_at = CURRENT_TIMESTAMP(),
            t.change_kind = 'updated'
        WHEN MATCHED THEN UPDATE SET t.last_synced_at = CURRENT_TIMESTAMP()
        WHEN NOT MATCHED THEN INSERT (technique_id, name, tactics, platforms, data_sources, description, url,
              is_subtechnique, attack_modified, first_synced_at, last_synced_at, change_kind)
            VALUES (s.technique_id, s.name, PARSE_JSON(s.tactics), PARSE_JSON(s.platforms),
              PARSE_JSON(s.data_sources), s.description, s.url, s.is_sub, TRY_TO_TIMESTAMP_LTZ(s.modified),
              CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP(), '{"unchanged" if first else "new"}')""").collect()
    new = s.sql(f"SELECT COUNT(*) FROM {R}.ATTACK_CATALOG WHERE change_kind = 'new'").collect()[0][0]
    return len(rows_), new


def feed_kev(s, f):
    j = get(f["URL"]).json()
    rows_ = [[v.get("cveID"), v.get("vendorProject"), v.get("product"), v.get("vulnerabilityName"),
              v.get("dateAdded"), v.get("dueDate"), v.get("knownRansomwareCampaignUse"),
              (v.get("shortDescription") or "")[:2000], (v.get("requiredAction") or "")[:1000],
              json.dumps(v.get("cwes") or [])] for v in j.get("vulnerabilities", [])]
    stage(s, "XDR_INTEL_KEV_STAGE", ["CVE_ID", "VENDOR", "PRODUCT", "NAME", "DATE_ADDED", "DUE_DATE",
                                     "RANSOMWARE", "SHORT_DESCRIPTION", "REQUIRED_ACTION", "CWES"], rows_)
    before = s.sql(f"SELECT COUNT(*) FROM {R}.KEV_CATALOG").collect()[0][0]
    s.sql(f"""
        MERGE INTO {R}.KEV_CATALOG t USING XDR_INTEL_KEV_STAGE s ON t.cve_id = s.cve_id
        WHEN MATCHED THEN UPDATE SET t.last_synced_at = CURRENT_TIMESTAMP(), t.ransomware = s.ransomware,
            t.due_date = TRY_TO_DATE(s.due_date)
        WHEN NOT MATCHED THEN INSERT (cve_id, vendor, product, name, date_added, due_date, ransomware,
              short_description, required_action, cwes, first_synced_at, last_synced_at)
            VALUES (s.cve_id, s.vendor, s.product, s.name, TRY_TO_DATE(s.date_added), TRY_TO_DATE(s.due_date),
              s.ransomware, s.short_description, s.required_action, PARSE_JSON(s.cwes),
              CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP())""").collect()
    after = s.sql(f"SELECT COUNT(*) FROM {R}.KEV_CATALOG").collect()[0][0]
    return len(rows_), after - before


def feed_sigma(s, f):
    z = zipfile.ZipFile(io.BytesIO(get(f["URL"], timeout=300).content))
    rows_ = []
    for n in z.namelist():
        if not n.endswith(".yml"):
            continue
        try:
            d = yaml.safe_load(z.read(n))
        except Exception:
            continue
        if not isinstance(d, dict) or not d.get("id") or d.get("status") in ("deprecated", "unsupported"):
            continue
        ls = d.get("logsource") or {}
        product, category, service = ls.get("product"), ls.get("category"), ls.get("service")
        cim = SIGMA_MAP.get((product, category or service)) or SIGMA_MAP.get((None, category or service))
        tags = [str(t) for t in d.get("tags") or []]
        techniques = sorted({t.split(".", 1)[1].upper() for t in tags if t.lower().startswith("attack.t")})
        tactic_tags = [t.split(".", 1)[1] for t in tags if t.lower().startswith("attack.") and not t[7:8].lower() == "t"]
        det = yaml.safe_dump({"logsource": ls, "detection": d.get("detection")}, sort_keys=False)[:4000]
        rows_.append([str(d["id"]), str(d.get("title", ""))[:500], d.get("status"), d.get("level"), product,
                      category, service, cim, json.dumps(techniques), json.dumps(tactic_tags),
                      str(d.get("description") or "")[:2000], json.dumps([str(x) for x in d.get("falsepositives") or []]),
                      det, n, str(d.get("modified") or d.get("date") or "")])
    stage(s, "XDR_INTEL_SIGMA_STAGE", ["SIGMA_ID", "TITLE", "STATUS", "LEVEL", "PRODUCT", "CATEGORY", "SERVICE",
                                       "CIM_TABLE", "TECHNIQUES", "TACTICS", "DESCRIPTION", "FALSEPOSITIVES",
                                       "DETECTION_YAML", "PATH", "MODIFIED"], rows_)
    before = s.sql(f"SELECT COUNT(*) FROM {R}.SIGMA_RULES").collect()[0][0]
    s.sql(f"""
        MERGE INTO {R}.SIGMA_RULES t USING XDR_INTEL_SIGMA_STAGE s ON t.sigma_id = s.sigma_id
        WHEN MATCHED THEN UPDATE SET t.title = s.title, t.status = s.status, t.level = s.level,
            t.cim_table = s.cim_table, t.techniques = PARSE_JSON(s.techniques), t.tactics = PARSE_JSON(s.tactics),
            t.description = s.description, t.falsepositives = PARSE_JSON(s.falsepositives),
            t.detection_yaml = s.detection_yaml, t.modified = s.modified, t.last_synced_at = CURRENT_TIMESTAMP()
        WHEN NOT MATCHED THEN INSERT (sigma_id, title, status, level, product, category, service, cim_table,
              techniques, tactics, description, falsepositives, detection_yaml, path, modified,
              first_synced_at, last_synced_at)
            VALUES (s.sigma_id, s.title, s.status, s.level, s.product, s.category, s.service, s.cim_table,
              PARSE_JSON(s.techniques), PARSE_JSON(s.tactics), s.description, PARSE_JSON(s.falsepositives),
              s.detection_yaml, s.path, s.modified, CURRENT_TIMESTAMP(), CURRENT_TIMESTAMP())""").collect()
    after = s.sql(f"SELECT COUNT(*) FROM {R}.SIGMA_RULES").collect()[0][0]
    return len(rows_), after - before


HANDLERS = {"feodo": feed_feodo, "threatfox": feed_threatfox, "urlhaus": feed_urlhaus,
            "misp_warninglists": feed_warninglists, "mitre_attack": feed_attack, "cisa_kev": feed_kev,
            "sigma": feed_sigma}


def main(session, P_FEED):
    want = (P_FEED or "all").lower()
    feeds = [r.as_dict() for r in session.sql(f"SELECT * FROM {R}.INTEL_FEEDS ORDER BY feed_id").collect()]
    out = {}
    for f in feeds:
        fid = f["FEED_ID"]
        if want != "all" and want != fid:
            continue
        if not f["ENABLED"] or fid not in HANDLERS:
            out[fid] = "disabled"
            continue
        t0 = time.time()
        status, fetched, new, detail = "ok", 0, 0, ""
        try:
            res = HANDLERS[fid](session, f)
            if res is None:
                status, detail = "needs_key", "set SNOWFLAKE_XDR.REFERENCE.ABUSE_CH_AUTH_KEY (free at auth.abuse.ch)"
            else:
                fetched, new = res
        except Exception as e:
            status, detail = "error", str(e)[:1000]
        secs = round(time.time() - t0, 1)
        session.sql(f"""UPDATE {R}.INTEL_FEEDS SET last_run_at = CURRENT_TIMESTAMP(), last_status = ?,
                          last_count = ?, last_new = ?, last_error = ? WHERE feed_id = ?""",
                    params=[status, fetched, new, detail or "", fid]).collect()
        session.sql(f"""INSERT INTO {R}.INTEL_FEED_RUNS (feed_id, seconds, status, fetched, new_items, detail)
                        SELECT ?, ?, ?, ?, ?, ?""", params=[fid, secs, status, fetched, new, detail or ""]).collect()
        out[fid] = {"status": status, "fetched": fetched, "new": new, "seconds": secs, **({"detail": detail} if detail else {})}
    out["scoring"] = session.sql(f"CALL {R}.SCORE_IOCS()").collect()[0][0]
    out["backlog"] = session.sql(f"CALL {R}.REFRESH_AUTOPILOT_BACKLOG()").collect()[0][0]
    return out
$$;

-- ---------------------------------------------------------------------------
-- 7. IOC confidence: reliability x decay + corroboration, analyst feedback,
--    warninglist, expiry. Writes the effective value to `confidence`, which
--    DET-021 uses, and an explanation to `confidence_factors`.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.SCORE_IOCS()
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_active NUMBER;
    v_wl NUMBER;
    v_exp NUMBER;
BEGIN
    UPDATE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS t SET
        confidence = c.score,
        active = c.next_status = 'active',
        status = c.next_status,
        status_reason = c.reason,
        confidence_factors = c.factors,
        expires_at = c.expires_at,
        updated_at = CURRENT_TIMESTAMP()
    FROM (
        WITH keys AS (    -- each indicator as an IPv4 number or its domain + parent domains
            SELECT ioc_type, ioc_value,
                   TRY_CAST(PARSE_IP(ioc_value, 'INET', 1):ipv4::VARCHAR AS NUMBER) AS ip,
                   LOWER(IFF(ioc_type = 'url', PARSE_URL(ioc_value, 1):host::VARCHAR, ioc_value)) AS host
            FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
        ),
        hosts AS (
            SELECT k.ioc_type, k.ioc_value, ARRAY_TO_STRING(ARRAY_SLICE(SPLIT(k.host, '.'), n.index, ARRAY_SIZE(SPLIT(k.host, '.'))), '.') AS h
            FROM keys k, LATERAL FLATTEN(SPLIT(k.host, '.')) n
            WHERE k.ioc_type IN ('domain', 'url') AND k.host IS NOT NULL
              AND n.index < ARRAY_SIZE(SPLIT(k.host, '.')) - 1
        ),
        wl AS (
            SELECT ioc_type, ioc_value,
                   MIN(IFF(SNOWFLAKE_XDR.REFERENCE.WARNINGLIST_IS_SOFT(list_name), NULL, list_name)) AS wl,
                   MIN(IFF(SNOWFLAKE_XDR.REFERENCE.WARNINGLIST_IS_SOFT(list_name), list_name, NULL)) AS soft_wl
            FROM (
                SELECT k.ioc_type, k.ioc_value, w.list_name FROM keys k
                JOIN SNOWFLAKE_XDR.REFERENCE.INTEL_WARNINGLIST w
                  ON k.ioc_type = 'ip' AND w.entry_type = 'cidr' AND k.ip BETWEEN w.ip_start AND w.ip_end
                UNION ALL
                SELECT h.ioc_type, h.ioc_value, w.list_name FROM hosts h
                JOIN SNOWFLAKE_XDR.REFERENCE.INTEL_WARNINGLIST w ON w.entry_type = 'hostname' AND w.value = h.h
                UNION ALL
                SELECT k.ioc_type, k.ioc_value, w.list_name FROM keys k
                JOIN SNOWFLAKE_XDR.REFERENCE.INTEL_WARNINGLIST w ON w.entry_type = 'string' AND w.value = LOWER(k.ioc_value)
            ) GROUP BY 1, 2
        ),
        base AS (
            SELECT i.ioc_type, i.ioc_value, i.status, i.pinned,
                   COALESCE(i.base_confidence, i.confidence, 50) AS base_conf,
                   COALESCE((SELECT MAX(r.reliability) FROM SNOWFLAKE_XDR.REFERENCE.INTEL_SOURCE_RELIABILITY r
                             WHERE ARRAY_CONTAINS(r.source::VARIANT, COALESCE(i.sources, ARRAY_CONSTRUCT(i.source)))), 0.6) AS reliability,
                   ARRAY_SIZE(COALESCE(i.sources, ARRAY_CONSTRUCT(i.source))) AS n_sources,
                   DATEDIFF('hour', COALESCE(i.last_seen, i.first_seen, CURRENT_TIMESTAMP()), CURRENT_TIMESTAMP()) / 24.0 AS age_days,
                   -- half-life by indicator type; analyst / own research decays 3x slower
                   CASE i.ioc_type WHEN 'ip' THEN 14 WHEN 'url' THEN 7 WHEN 'domain' THEN 45 ELSE 365 END
                     * IFF(ARRAYS_OVERLAP(COALESCE(i.sources, ARRAY_CONSTRUCT(i.source)),
                                          ARRAY_CONSTRUCT('analyst', 'internal_research', 'ui', 'agent', 'manual')), 3, 1) AS half_life,
                   CASE i.ioc_type WHEN 'ip' THEN 45 WHEN 'url' THEN 30 WHEN 'domain' THEN 120 ELSE NULL END AS ttl_days,
                   COALESCE(i.last_seen, i.first_seen) AS seen,
                   wl.wl, wl.soft_wl
            FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS i
            LEFT JOIN wl ON wl.ioc_type = i.ioc_type AND wl.ioc_value = i.ioc_value
        ),
        feedback AS (   -- human verdicts on findings that matched the indicator
            SELECT LOWER(evidence:ioc_value::VARCHAR) AS ioc_value,
                   COUNT_IF(disposition = 'false_positive' AND COALESCE(disposition_source, 'analyst') IN ('analyst', 'review')) AS fp,
                   COUNT_IF(disposition IN ('true_positive', 'mitigated_by_control') AND COALESCE(disposition_source, 'analyst') IN ('analyst', 'review', 'control')) AS tp
            FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
            WHERE rule_id = 'DET-021' AND evidence:ioc_value IS NOT NULL
            GROUP BY 1
        ),
        calc AS (
            SELECT b.*, COALESCE(f.fp, 0) AS fp, COALESCE(f.tp, 0) AS tp,
                   POWER(0.5, b.age_days / b.half_life) * IFF(b.soft_wl IS NOT NULL, 0.6, 1) AS decay,
                   LEAST(20, 10 * GREATEST(b.n_sources - 1, 0)) AS corroboration,
                   LEAST(15, 7.5 * COALESCE(f.tp, 0)) - LEAST(25, 5 * COALESCE(f.fp, 0)) * IFF(COALESCE(f.tp, 0) > 0, 0, 1) AS feedback
            FROM base b LEFT JOIN feedback f ON f.ioc_value = LOWER(b.ioc_value)
        )
        SELECT ioc_type, ioc_value,
               GREATEST(0, LEAST(100, ROUND(IFF(wl IS NOT NULL AND NOT COALESCE(pinned, FALSE), LEAST(10, base_conf * reliability * decay),
                   base_conf * reliability * decay + corroboration + feedback)))) AS score,
               IFF(ttl_days IS NULL, NULL, DATEADD('day', ttl_days, seen)) AS expires_at,
               CASE WHEN status IN ('revoked', 'allowlisted') THEN status
                    WHEN wl IS NOT NULL AND NOT COALESCE(pinned, FALSE) THEN 'warninglisted'
                    WHEN ttl_days IS NOT NULL AND DATEADD('day', ttl_days, seen) < CURRENT_TIMESTAMP()
                         AND NOT COALESCE(pinned, FALSE) THEN 'expired'
                    WHEN base_conf * reliability * decay + corroboration + feedback < 25
                         AND NOT COALESCE(pinned, FALSE) THEN 'low_confidence'
                    ELSE 'active' END AS next_status,
               CASE WHEN status IN ('revoked', 'allowlisted') THEN NULL
                    WHEN wl IS NOT NULL AND NOT COALESCE(pinned, FALSE) THEN 'on warninglist ' || wl || ' (known-benign infrastructure)'
                    WHEN ttl_days IS NOT NULL AND DATEADD('day', ttl_days, seen) < CURRENT_TIMESTAMP()
                         AND NOT COALESCE(pinned, FALSE) THEN 'not seen by any feed for ' || ttl_days || ' days'
                    WHEN base_conf * reliability * decay + corroboration + feedback < 25
                         AND NOT COALESCE(pinned, FALSE) THEN 'confidence below 25: does not alert (pin to override)'
                    ELSE NULL END AS reason,
               ARRAY_CONSTRUCT_COMPACT(
                   OBJECT_CONSTRUCT('factor', 'feed confidence', 'value', base_conf),
                   OBJECT_CONSTRUCT('factor', 'source reliability', 'value', ROUND(reliability, 2)),
                   OBJECT_CONSTRUCT('factor', 'age decay', 'value', ROUND(decay, 2),
                                    'detail', ROUND(age_days, 1) || ' days since last seen, half-life ' || half_life || 'd'),
                   IFF(corroboration > 0, OBJECT_CONSTRUCT('factor', 'corroborated', 'value', corroboration,
                                                           'detail', n_sources || ' independent sources'), NULL),
                   IFF(feedback <> 0, OBJECT_CONSTRUCT('factor', 'analyst feedback', 'value', ROUND(feedback),
                                                       'detail', tp || ' true / ' || fp || ' false positive verdicts'), NULL),
                   IFF(wl IS NOT NULL, OBJECT_CONSTRUCT('factor', 'warninglist', 'value', wl), NULL),
                   IFF(soft_wl IS NOT NULL, OBJECT_CONSTRUCT('factor', 'shared infrastructure', 'value', 0.6,
                       'detail', 'address is in ' || soft_wl || ' space: may be reassigned to a benign tenant'), NULL)) AS factors
        FROM calc
    ) c
    WHERE t.ioc_type = c.ioc_type AND t.ioc_value = c.ioc_value;

    SELECT COUNT_IF(active), COUNT_IF(status = 'warninglisted'), COUNT_IF(status = 'expired')
    INTO :v_active, :v_wl, :v_exp
    FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS;
    RETURN 'IOCs scored: ' || v_active || ' active, ' || v_wl || ' neutralised by warninglist, ' || v_exp || ' expired';
END;
$$;

-- ---------------------------------------------------------------------------
-- 8. Feed-driven autopilot backlog: techniques with Sigma rules for log
--    sources we collect, not yet covered, join the backlog with references
-- ---------------------------------------------------------------------------
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG ADD COLUMN IF NOT EXISTS origin VARCHAR(20);
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG ADD COLUMN IF NOT EXISTS sigma_refs ARRAY;
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG ADD COLUMN IF NOT EXISTS added_at TIMESTAMP_LTZ;
UPDATE SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG SET origin = 'curated' WHERE origin IS NULL;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.REFRESH_AUTOPILOT_BACKLOG()
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_new NUMBER;
BEGIN
    -- Sigma references for every technique (curated rows too)
    MERGE INTO SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG b
    USING (
        SELECT s.value::VARCHAR AS technique_id,
               ANY_VALUE(a.name) AS technique_name,
               ANY_VALUE(a.tactics[0]::VARCHAR) AS tactic_id,
               LISTAGG(DISTINCT s.cim_table, ',') AS source_tables,
               LEFT(LISTAGG(DISTINCT s.title, '; '), 900) AS hint,
               ARRAY_SLICE(ARRAY_AGG(DISTINCT s.sigma_id), 0, 5) AS refs,
               MIN(CASE s.level WHEN 'critical' THEN 2 WHEN 'high' THEN 3 ELSE 4 END) AS priority,
               MAX(IFF(a.change_kind = 'new', 1, 0)) AS is_new
        FROM (SELECT s.*, t.value FROM SNOWFLAKE_XDR.REFERENCE.SIGMA_RULES s, LATERAL FLATTEN(s.techniques) t
              WHERE s.cim_table IS NOT NULL AND s.status IN ('stable', 'test')
                AND s.level IN ('high', 'critical', 'medium')) AS s (sigma_id, title, status, level, product, category,
              service, cim_table, techniques, tactics, description, falsepositives, detection_yaml, path, modified,
              first_synced_at, last_synced_at, value)
        LEFT JOIN SNOWFLAKE_XDR.REFERENCE.ATTACK_CATALOG a ON a.technique_id = s.value::VARCHAR
        GROUP BY 1
    ) s ON b.technique_id = s.technique_id
    WHEN MATCHED THEN UPDATE SET b.sigma_refs = s.refs
    WHEN NOT MATCHED AND s.priority <= 3 AND s.technique_name IS NOT NULL THEN
        INSERT (technique_id, technique_name, tactic_id, source_tables, hint, priority, origin, sigma_refs, added_at)
        VALUES (s.technique_id, s.technique_name, s.tactic_id, s.source_tables,
                'Community detections for this technique: ' || s.hint,
                s.priority + 2 - s.is_new, IFF(s.is_new = 1, 'attack_new', 'sigma'), s.refs, CURRENT_TIMESTAMP());
    v_new := SQLROWCOUNT;
    RETURN 'Autopilot backlog refreshed (' || v_new || ' rows merged)';
END;
$$;

-- ---------------------------------------------------------------------------
-- 9. What changed in threat intel (digest, console, agent)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.INTEL_STATUS(P_DAYS NUMBER)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    LET r VARIANT := (SELECT OBJECT_CONSTRUCT(
        'feeds', (SELECT ARRAY_AGG(OBJECT_CONSTRUCT('feed', feed_id, 'name', name, 'status', last_status,
                     'last_run', last_run_at, 'items', last_count, 'new', last_new)) WITHIN GROUP (ORDER BY feed_id)
                  FROM SNOWFLAKE_XDR.REFERENCE.INTEL_FEEDS),
        'iocs', (SELECT OBJECT_CONSTRUCT('active', COUNT_IF(active), 'warninglisted', COUNT_IF(status = 'warninglisted'),
                     'low_confidence', COUNT_IF(status = 'low_confidence'),
                     'expired', COUNT_IF(status = 'expired'), 'allowlisted', COUNT_IF(status = 'allowlisted'),
                     'new', COUNT_IF(first_seen > DATEADD('day', -COALESCE(:P_DAYS, 7), CURRENT_TIMESTAMP())),
                     'high_confidence', COUNT_IF(active AND confidence >= 70))
                 FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS),
        'neutralised', (SELECT ARRAY_AGG(OBJECT_CONSTRUCT('ioc', ioc_value, 'reason', status_reason))
                        FROM (SELECT * FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
                              WHERE status IN ('warninglisted', 'allowlisted') LIMIT 10)),
        'new_techniques', (SELECT ARRAY_AGG(technique_id || ' ' || name)
                           FROM (SELECT * FROM SNOWFLAKE_XDR.REFERENCE.ATTACK_CATALOG
                                 WHERE change_kind = 'new' LIMIT 20)),
        'attack_techniques', (SELECT COUNT(*) FROM SNOWFLAKE_XDR.REFERENCE.ATTACK_CATALOG),
        'new_kev', (SELECT ARRAY_AGG(OBJECT_CONSTRUCT('cve', cve_id, 'product', vendor || ' ' || product,
                        'ransomware', ransomware, 'added', date_added)) WITHIN GROUP (ORDER BY date_added DESC)
                    FROM (SELECT * FROM SNOWFLAKE_XDR.REFERENCE.KEV_CATALOG
                          WHERE date_added > DATEADD('day', -COALESCE(:P_DAYS, 7), CURRENT_DATE())
                          ORDER BY date_added DESC LIMIT 15)),
        'kev_total', (SELECT COUNT(*) FROM SNOWFLAKE_XDR.REFERENCE.KEV_CATALOG),
        'sigma_rules', (SELECT COUNT(*) FROM SNOWFLAKE_XDR.REFERENCE.SIGMA_RULES),
        'sigma_mappable', (SELECT COUNT(*) FROM SNOWFLAKE_XDR.REFERENCE.SIGMA_RULES WHERE cim_table IS NOT NULL),
        'backlog', (SELECT OBJECT_AGG(origin, n::VARIANT) FROM (
                       SELECT COALESCE(origin, 'curated') origin, COUNT(*) n
                       FROM SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG GROUP BY 1))));
    RETURN r;
END;
$$;

-- Daily sync (suspended by default)
CREATE TASK IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.TASK_SYNC_THREAT_INTEL
    WAREHOUSE = XDR_WH
    SCHEDULE = 'USING CRON 0 5 * * * UTC'
    COMMENT = 'Pull IOC feeds, warninglists, ATT&CK, KEV and Sigma; rescore IOCs'
AS
    CALL SNOWFLAKE_XDR.REFERENCE.SYNC_THREAT_INTEL('all');

-- Remove the feed reachability probe used during development
DROP PROCEDURE IF EXISTS SNOWFLAKE_XDR.REFERENCE.INTEL_PROBE();
