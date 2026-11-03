-- ============================================================================
-- Snowflake XDR - Environment profile, threat profile, threat-ranked backlog
-- and the emerging-threat loop (Phase 4)
-- ============================================================================
-- The autopilot should build the detections THIS customer needs first:
--
--   ENVIRONMENT_PROFILE   rebuilt daily from data: systems sending logs, privileged
--                         identities (grants), crown jewels (sensitive tags, most-read
--                         objects), per-user login baselines, data gaps.
--   THREAT_PROFILE        the customer's own words ("EU fintech, ransomware and insider
--                         theft") mapped by Cortex to ATT&CK groups and techniques;
--                         editable in Mission Control.
--   THREAT_TECHNIQUE_SCORES  likelihood x impact per technique, from the profile, the
--                         customer's own incidents and KEV entries for products they run;
--                         impact rises for techniques against admins or crown jewels.
--   Backlog ranking       AUTOPILOT_TECHNIQUE_BACKLOG.threat_score = score x data available
--                         x coverage gap, with a plain-language rank_reason the autopilot
--                         copies into every proposal.
--   Emerging threats      a new KEV or ATT&CK technique that matches the environment
--                         triggers (1) a 30-day retro-hunt, hits become findings and so a
--                         case, (2) a rule proposal via the backlog, (3) an exposure entry
--                         in THREAT_EXPOSURES for the morning briefing.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.ENVIRONMENT_PROFILE (
    built_at   TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    profile    VARIANT
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.THREAT_PROFILE (
    profile_id   VARCHAR(20) PRIMARY KEY,      -- 'current'
    statement    VARCHAR(4000),                -- the customer's own words
    industry     VARCHAR(200),
    regions      ARRAY,
    concerns     ARRAY,
    groups_      VARIANT,                      -- [{name, why}]
    techniques   VARIANT,                      -- [{technique_id, likelihood 1-5, why}]
    model        VARCHAR(100),
    updated_by   VARCHAR(255),
    updated_at   TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.THREAT_TECHNIQUE_SCORES (
    technique_id  VARCHAR(20) PRIMARY KEY,
    name          VARCHAR(300),
    tactic_id     VARCHAR(10),
    likelihood    FLOAT,          -- 1-5
    impact        FLOAT,          -- 1-5
    score         FLOAT,          -- likelihood x impact, 1-25
    sources       ARRAY,          -- profile | incidents | kev | baseline
    reasons       ARRAY,
    computed_at   TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.THREAT_EXPOSURES (
    exposure_id   VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    created_at    TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    kind          VARCHAR(20),    -- kev | attack_new
    ref           VARCHAR(50),    -- CVE id or technique id
    title         VARCHAR(500),
    detail        VARCHAR(2000),
    products      ARRAY,          -- matched environment products
    techniques    ARRAY,
    score         FLOAT,
    retro_hunt    VARIANT,        -- {tables, hits, finding_ids}
    status        VARCHAR(20) DEFAULT 'open'   -- open | acknowledged
);

ALTER TABLE SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG ADD COLUMN IF NOT EXISTS threat_score FLOAT;
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG ADD COLUMN IF NOT EXISTS data_available BOOLEAN;
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG ADD COLUMN IF NOT EXISTS rank_reason VARCHAR(1000);
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG ADD COLUMN IF NOT EXISTS ranked_at TIMESTAMP_LTZ;

-- ---------------------------------------------------------------------------
-- The whole loop as one Python procedure with commands:
--   environment | set_profile:<json> | score | rank | emerging[:days] | cycle
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.THREAT_PROFILE_ENGINE(P_COMMAND VARCHAR, P_ARG VARCHAR)
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
TECH_RE = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")
CIM = ["AUTHENTICATION", "CLOUD_API", "DATABASE_ACTIVITY", "NETWORK_TRAFFIC", "DNS_ACTIVITY", "WEB_ACTIVITY",
       "ENDPOINT_PROCESSES", "ENDPOINT_FILESYSTEM", "ENDPOINT_REGISTRY", "ENDPOINT_SERVICES", "INTRUSION_DETECTION"]
ADMIN_ROLES = ("ACCOUNTADMIN", "SECURITYADMIN", "ORGADMIN", "USERADMIN", "SYSADMIN")
# Techniques whose impact rises when there are privileged identities / crown jewels to abuse
ADMIN_TECH = ("T1078", "T1098", "T1136", "T1548", "T1556", "T1110", "T1621", "T1528", "T1550", "T1484")
DATA_TACTICS = ("TA0009", "TA0010", "TA0040")
# Environment product -> (KEV vendor, KEV product keywords; None = any product of that vendor)
PRODUCT_ALIAS = [("sysmon", "Microsoft", ["Windows"]), ("windows", "Microsoft", ["Windows"]),
                 ("entra", "Microsoft", ["Entra", "Azure"]), ("azure", "Microsoft", ["Azure"]),
                 ("exchange", "Microsoft", ["Exchange"]), ("sharepoint", "Microsoft", ["SharePoint"]),
                 ("palo alto", "Palo Alto", ["PAN-OS", "GlobalProtect"]), ("f5", "F5", ["BIG-IP"]),
                 ("okta", "Okta", None), ("aws", "Amazon", None), ("openssh", "OpenBSD", ["OpenSSH"]),
                 ("bind", "ISC", ["BIND"]), ("infoblox", "Infoblox", None), ("snowflake", "Snowflake", None),
                 ("fortinet", "Fortinet", None), ("fortigate", "Fortinet", ["FortiOS"]), ("cisco", "Cisco", None),
                 ("ivanti", "Ivanti", None), ("citrix", "Citrix", None), ("vmware", "VMware", None),
                 ("databricks", "Databricks", None), ("postgres", "PostgreSQL", None), ("clickhouse", "ClickHouse", None),
                 ("salesforce", "Salesforce", None), ("github", "GitHub", None)]
# ATT&CK data source -> CIM table, for techniques that enter the backlog from the profile
DS_TABLE = [("logon session", "AUTHENTICATION"), ("user account", "AUTHENTICATION"), ("command", "ENDPOINT_PROCESSES"),
            ("process", "ENDPOINT_PROCESSES"), ("file", "ENDPOINT_FILESYSTEM"), ("windows registry", "ENDPOINT_REGISTRY"),
            ("service", "ENDPOINT_SERVICES"), ("network traffic", "NETWORK_TRAFFIC"), ("cloud service", "CLOUD_API"),
            ("cloud storage", "CLOUD_API"), ("instance", "CLOUD_API"), ("snapshot", "CLOUD_API"),
            ("application log", "WEB_ACTIVITY"), ("web credential", "AUTHENTICATION"), ("drive", "ENDPOINT_FILESYSTEM")]


def rows(s, sql, params=None):
    return [r.as_dict() for r in s.sql(sql, params=params).collect()]


def one(s, sql, params=None):
    r = rows(s, sql, params)
    return r[0] if r else None


def safe(fn, default):
    try:
        return fn()
    except Exception as e:  # ACCOUNT_USAGE not granted etc.: profile what we can
        return default if not isinstance(default, dict) else {**default, "error": str(e)[:200]}


# ---------------------------------------------------------------- environment
def environment(s):
    systems = []
    for t in CIM:
        for r in safe(lambda: rows(s, f"""SELECT COALESCE(vendor_product, 'unknown') AS vp, COUNT(*) AS n, MAX(_time) AS last
                                          FROM {DB}.RAW_LOGS.{t} WHERE _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
                                          GROUP BY 1 ORDER BY n DESC LIMIT 20"""), []):
            systems.append({"table": t, "product": r["VP"], "rows_7d": int(r["N"]), "last": str(r["LAST"])})
    gaps = [t for t in CIM if not any(x["table"] == t for x in systems)]
    admins = safe(lambda: rows(s, f"""SELECT grantee_name AS u, ARRAY_AGG(DISTINCT role) AS roles
                                      FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS
                                      WHERE deleted_on IS NULL AND role IN {ADMIN_ROLES} GROUP BY 1 ORDER BY 1 LIMIT 200"""), [])
    tagged = safe(lambda: rows(s, """SELECT object_database || '.' || object_schema || '.' || object_name AS obj,
                                            ARRAY_AGG(DISTINCT tag_name || '=' || COALESCE(tag_value, '')) AS tags
                                     FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES
                                     WHERE object_deleted IS NULL AND domain IN ('TABLE', 'COLUMN')
                                       AND (tag_name ILIKE ANY ('%PII%', '%SENSITIV%', '%CONFIDENTIAL%', '%PCI%', '%PHI%')
                                            OR tag_name IN ('SEMANTIC_CATEGORY', 'PRIVACY_CATEGORY'))
                                     GROUP BY 1 ORDER BY 1 LIMIT 50"""), [])
    most_read = safe(lambda: rows(s, """SELECT f.value:objectName::VARCHAR AS obj, COUNT(*) AS reads,
                                               COUNT(DISTINCT a.user_name) AS users
                                        FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY a,
                                             LATERAL FLATTEN(a.base_objects_accessed) f
                                        WHERE a.query_start_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
                                          AND f.value:objectDomain::VARCHAR = 'Table'
                                          AND f.value:objectName::VARCHAR NOT ILIKE 'SNOWFLAKE_XDR.%'
                                        GROUP BY 1 ORDER BY reads DESC LIMIT 10"""), [])
    baselines = safe(lambda: one(s, f"""SELECT COUNT(DISTINCT user_name) AS users,
                                               COUNT(DISTINCT geo_country) AS countries,
                                               COUNT(DISTINCT src) AS source_ips
                                        FROM {DB}.RAW_LOGS.AUTHENTICATION
                                        WHERE action = 'success' AND _time > DATEADD('day', -30, CURRENT_TIMESTAMP())"""), {})
    waiting = safe(lambda: rows(s, f"""SELECT pack_id, name, waiting_for_data FROM {DB}.REFERENCE.V_RULE_PACKS
                                       WHERE waiting_for_data > 0"""), [])
    products = {}
    for name in ["Snowflake"] + [x["product"] for x in systems if x["product"] != "unknown"]:
        products.setdefault(name.lower(), name)
    products = sorted(products.values())
    prof = {"systems": systems, "products": products, "data_gaps": gaps,
            "privileged_identities": [{"user": a["U"], "roles": json.loads(a["ROLES"]) if isinstance(a["ROLES"], str) else a["ROLES"]}
                                      for a in admins],
            "crown_jewels": {"sensitive_tagged": [{"object": t["OBJ"], "tags": json.loads(t["TAGS"]) if isinstance(t["TAGS"], str) else t["TAGS"]}
                                                  for t in tagged],
                             "most_read": [{"object": m["OBJ"], "reads_7d": int(m["READS"]), "users": int(m["USERS"])} for m in most_read]},
            "login_baseline_30d": {k.lower(): v for k, v in (baselines or {}).items()},
            "packs_waiting_for_data": waiting}
    s.sql(f"INSERT INTO {DB}.REFERENCE.ENVIRONMENT_PROFILE (profile) SELECT PARSE_JSON(?)",
          params=[json.dumps(prof, default=str)]).collect()
    s.sql(f"""DELETE FROM {DB}.REFERENCE.ENVIRONMENT_PROFILE
              WHERE built_at < DATEADD('day', -30, CURRENT_TIMESTAMP())""").collect()
    return {"products": products, "systems": len(systems), "data_gaps": gaps,
            "privileged_identities": len(prof["privileged_identities"]),
            "crown_jewels": len(tagged) + len(most_read)}


def latest_env(s):
    r = one(s, f"SELECT profile FROM {DB}.REFERENCE.ENVIRONMENT_PROFILE ORDER BY built_at DESC LIMIT 1")
    if not r:
        environment(s)
        r = one(s, f"SELECT profile FROM {DB}.REFERENCE.ENVIRONMENT_PROFILE ORDER BY built_at DESC LIMIT 1")
    p = r["PROFILE"]
    return json.loads(p) if isinstance(p, str) else p


# ---------------------------------------------------------------- threat profile (Cortex)
def set_profile(s, arg):
    a = json.loads(arg or "{}")
    statement = str(a.get("statement") or "").strip()[:4000]
    if len(statement) < 5:
        return {"ok": False, "message": "describe your organisation and concerns in a sentence or two"}
    env = latest_env(s)
    model = (one(s, f"SELECT value::VARCHAR AS m FROM {DB}.DETECTIONS.AUTOPILOT_SETTINGS WHERE setting = 'model'")
             or {"M": "claude-sonnet-4-5"})["M"]
    prompt = (
        "You are a threat-intelligence analyst. Map the organisation below to the MITRE ATT&CK (Enterprise) "
        "threat groups and techniques most likely to target it. Prefer techniques detectable in logs.\n"
        f"Organisation (customer statement): {statement}\n"
        f"Systems in use: {', '.join(env.get('products', []))}\n"
        "Return ONLY JSON: {\"industry\": str, \"regions\": [str], \"concerns\": [str], "
        "\"groups\": [{\"name\": str, \"why\": str}] (max 6), "
        "\"techniques\": [{\"technique_id\": \"T1234 or T1234.001\", \"likelihood\": 1-5, \"why\": str}] (15-30 items)}")
    txt = one(s, "SELECT SNOWFLAKE.CORTEX.COMPLETE(?, ?) AS r", [model, prompt])["R"] or ""
    i, j = txt.find("{"), txt.rfind("}")
    if i < 0 or j <= i:
        return {"ok": False, "message": "the model did not return a profile; try rephrasing"}
    p = json.loads(txt[i:j + 1])
    known = {r["TECHNIQUE_ID"] for r in rows(s, f"SELECT technique_id FROM {DB}.REFERENCE.ATTACK_CATALOG")}
    techs, dropped = [], []
    for t in p.get("techniques") or []:
        tid = str(t.get("technique_id", "")).strip().upper()
        if TECH_RE.match(tid) and (not known or tid in known or tid.split(".")[0] in known):
            techs.append({"technique_id": tid, "likelihood": max(1, min(5, int(t.get("likelihood", 3)))),
                          "why": str(t.get("why", ""))[:300]})
        else:
            dropped.append(tid)
    who = a.get("actor") if isinstance(a.get("actor"), str) and re.match(r"^[A-Za-z0-9_.@$-]{1,255}$", a["actor"]) else None
    s.sql(f"""MERGE INTO {DB}.REFERENCE.THREAT_PROFILE t USING (SELECT 'current' AS id) v ON t.profile_id = v.id
              WHEN MATCHED THEN UPDATE SET statement = ?, industry = ?, regions = PARSE_JSON(?), concerns = PARSE_JSON(?),
                   groups_ = PARSE_JSON(?), techniques = PARSE_JSON(?), model = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP()
              WHEN NOT MATCHED THEN INSERT (profile_id, statement, industry, regions, concerns, groups_, techniques, model, updated_by)
                   VALUES ('current', ?, ?, PARSE_JSON(?), PARSE_JSON(?), PARSE_JSON(?), PARSE_JSON(?), ?, ?)""",
          params=[statement, str(p.get("industry", ""))[:200], json.dumps(p.get("regions") or []),
                  json.dumps(p.get("concerns") or []), json.dumps((p.get("groups") or [])[:6]), json.dumps(techs),
                  model, (f"{who} (console)" if who else one(s, "SELECT CURRENT_USER() AS u")["U"])] * 2).collect()
    res = score(s)
    rk = rank(s)
    return {"ok": True, "message": f"Threat profile saved: {len(techs)} techniques, {len(p.get('groups') or [])} groups; "
                                   f"{res['scored']} techniques scored, backlog re-ranked ({rk['ranked']} items)",
            "industry": p.get("industry"), "concerns": p.get("concerns"), "groups": p.get("groups"),
            "techniques": techs, "dropped_invalid": dropped}


# ---------------------------------------------------------------- scoring
def score(s):
    env = latest_env(s)
    prof = one(s, f"SELECT * FROM {DB}.REFERENCE.THREAT_PROFILE WHERE profile_id = 'current'")
    cat = {r["TECHNIQUE_ID"]: r for r in rows(s, f"""SELECT technique_id, name, tactics[0]::VARCHAR AS tactic
                                                    FROM {DB}.REFERENCE.ATTACK_CATALOG""")}
    acc = {}

    def add(tid, likelihood, source, reason):
        e = acc.setdefault(tid, {"likelihood": 0.0, "sources": set(), "reasons": []})
        e["likelihood"] = max(e["likelihood"], likelihood)
        e["sources"].add(source)
        if reason and reason not in e["reasons"]:
            e["reasons"].append(reason)

    if prof:
        for t in json.loads(prof["TECHNIQUES"]) if isinstance(prof["TECHNIQUES"], str) else (prof["TECHNIQUES"] or []):
            add(t["technique_id"], float(t["likelihood"]), "profile", "threat profile: " + t.get("why", ""))
    # The customer's own history: techniques seen in real (not false-positive) incidents / findings, 90 days
    for r in rows(s, f"""SELECT mitre_technique_id AS t, COUNT(*) AS n FROM {DB}.DETECTIONS.DETECTION_FINDINGS
                         WHERE detection_time > DATEADD('day', -90, CURRENT_TIMESTAMP())
                           AND COALESCE(disposition, 'open') NOT IN ('false_positive', 'benign')
                           AND mitre_technique_id LIKE 'T____%'
                         GROUP BY 1 ORDER BY n DESC LIMIT 40"""):
        n = int(r["N"])
        add(r["T"], min(5.0, 3.0 + (1 if n >= 5 else 0) + (1 if n >= 25 else 0)), "incidents",
            f"seen {n} time(s) in your own findings in the last 90 days")
    # KEV entries for products in the environment -> exploitation techniques
    kev = kev_matches(s, env, days=365)
    for k in kev[:50]:
        add("T1190", 4.0 + (1 if k["ransomware"] == "Known" else 0), "kev",
            f"KEV {k['cve']} affects {k['product']} ({k['matched']} in your environment)")
        if k["ransomware"] == "Known":
            add("T1486", 4.0, "kev", f"{k['cve']} is used in ransomware campaigns")
    concerns = " ".join(json.loads(prof["CONCERNS"]) if prof and isinstance(prof["CONCERNS"], str) else []).lower()
    admins = len(env.get("privileged_identities") or [])
    jewels = len((env.get("crown_jewels") or {}).get("sensitive_tagged") or []) + len((env.get("crown_jewels") or {}).get("most_read") or [])

    s.sql(f"DELETE FROM {DB}.REFERENCE.THREAT_TECHNIQUE_SCORES").collect()
    out = []
    for tid, e in acc.items():
        c = cat.get(tid) or cat.get(tid.split(".")[0]) or {}
        tactic = c.get("TACTIC") or ""
        impact, why = 3.0, []
        if tid.split(".")[0] in ADMIN_TECH and admins:
            impact += 1
            why.append(f"{admins} privileged identities could be abused")
        if tactic in DATA_TACTICS and jewels:
            impact += 1
            why.append(f"{jewels} crown-jewel objects in scope")
        if "ransom" in concerns and tactic == "TA0040":
            impact += 1
            why.append("ransomware is a stated concern")
        if "insider" in concerns and tactic in ("TA0009", "TA0010"):
            impact += 1
            why.append("insider theft is a stated concern")
        impact = min(5.0, impact)
        out.append([tid, c.get("NAME") or tid, tactic, e["likelihood"], impact, round(e["likelihood"] * impact, 1),
                    json.dumps(sorted(e["sources"])), json.dumps((e["reasons"] + why)[:6])])
    for o in out:
        s.sql(f"""INSERT INTO {DB}.REFERENCE.THREAT_TECHNIQUE_SCORES
                    (technique_id, name, tactic_id, likelihood, impact, score, sources, reasons)
                  SELECT ?, ?, NULLIF(?, ''), ?, ?, ?, PARSE_JSON(?), PARSE_JSON(?)""", params=o).collect()
    return {"scored": len(out), "kev_matches": len(kev)}


def kev_matches(s, env, days=7):
    out = []
    for p in env.get("products") or []:
        pl = p.lower()
        alias = next((x for x in PRODUCT_ALIAS if x[0] in pl), None)
        if not alias:
            continue          # unknown product: no KEV match rather than a noisy vendor-wide one
        _, vendor, keywords = alias
        for k in rows(s, f"""SELECT cve_id, vendor || ' ' || product AS product, name, ransomware, date_added, short_description
                             FROM {DB}.REFERENCE.KEV_CATALOG
                             WHERE vendor ILIKE ? AND date_added >= DATEADD('day', -?, CURRENT_DATE())
                             ORDER BY date_added DESC LIMIT 100""", [vendor + "%", int(days)]):
            if keywords and not any(w.lower() in (k["PRODUCT"] or "").lower() for w in keywords):
                continue
            out.append({"cve": k["CVE_ID"], "product": k["PRODUCT"], "matched": p, "name": k["NAME"],
                        "ransomware": k["RANSOMWARE"], "added": str(k["DATE_ADDED"]),
                        "description": (k["SHORT_DESCRIPTION"] or "")[:500]})
    seen, uniq = set(), []
    for k in out:
        if k["cve"] not in seen:
            seen.add(k["cve"])
            uniq.append(k)
    return uniq


# ---------------------------------------------------------------- backlog ranking
def tables_with_data(s):
    have = set()
    for t in CIM:
        try:
            if one(s, f"SELECT COUNT(*) AS n FROM (SELECT 1 FROM {DB}.RAW_LOGS.{t} "
                      "WHERE _time > DATEADD('day', -7, CURRENT_TIMESTAMP()) LIMIT 1)")["N"]:
                have.add(t)
        except Exception:
            pass
    return have


def rank(s):
    have = tables_with_data(s)
    scores = {r["TECHNIQUE_ID"]: r for r in rows(s, f"SELECT * FROM {DB}.REFERENCE.THREAT_TECHNIQUE_SCORES")}
    # Profile techniques missing from the backlog join it (source tables from ATT&CK data sources)
    existing = {r["TECHNIQUE_ID"] for r in rows(s, f"SELECT technique_id FROM {DB}.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG")}
    added = 0
    for tid, sc in scores.items():
        if tid in existing or float(sc["SCORE"]) < 12:
            continue
        a = one(s, f"""SELECT name, tactics[0]::VARCHAR AS tactic, LOWER(ARRAY_TO_STRING(data_sources, '|')) AS ds,
                              LEFT(description, 600) AS d FROM {DB}.REFERENCE.ATTACK_CATALOG WHERE technique_id = ?""", [tid])
        if not a:
            continue
        tabs = sorted({t for k, t in DS_TABLE if k in (a["DS"] or "")})
        if not tabs:
            continue
        s.sql(f"""INSERT INTO {DB}.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG
                    (technique_id, technique_name, tactic_id, source_tables, hint, priority, origin, added_at)
                  SELECT ?, ?, ?, ?, ?, 2, 'threat_profile', CURRENT_TIMESTAMP()""",
              params=[tid, a["NAME"][:200], a["TACTIC"], ",".join(tabs), ("ATT&CK: " + (a["D"] or ""))[:1000]]).collect()
        added += 1
    covered = {r["T"] for r in rows(s, f"""
        SELECT mitre_technique_id AS t FROM {DB}.DETECTIONS.DETECTION_RULES WHERE enabled
        UNION SELECT mitre_technique_id FROM {DB}.DETECTIONS.CUSTOM_RULES WHERE enabled OR test_mode""") if r["T"]}
    n = 0
    for b in rows(s, f"SELECT technique_id, source_tables, priority FROM {DB}.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG"):
        tid = b["TECHNIQUE_ID"]
        sc = scores.get(tid) or scores.get(tid.split(".")[0])
        tabs = [t.strip().upper() for t in (b["SOURCE_TABLES"] or "").split(",") if t.strip()]
        avail = any(t in have for t in tabs)
        gap = tid not in covered
        threat = float(sc["SCORE"]) if sc else max(1.0, 6.0 - float(b["PRIORITY"] or 3))   # unscored: curated priority
        value = round(threat * (1.0 if avail else 0.3) * (1.0 if gap else 0.0), 2)
        reasons = (json.loads(sc["REASONS"]) if sc and isinstance(sc["REASONS"], str) else (sc or {}).get("REASONS") or [])
        why = (f"threat {threat:g}/25" + (f" ({'; '.join(reasons[:3])})" if reasons else " (curated, not in your threat profile)")
               + ("" if avail else f"; no data yet in {', '.join(tabs) or '?'}")
               + ("" if gap else "; already covered"))
        s.sql(f"""UPDATE {DB}.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG
                  SET threat_score = ?, data_available = ?, rank_reason = ?, ranked_at = CURRENT_TIMESTAMP()
                  WHERE technique_id = ?""", params=[value, avail, why[:1000], tid]).collect()
        n += 1
    return {"ranked": n, "added_from_profile": added, "tables_with_data": sorted(have)}


# ---------------------------------------------------------------- emerging threats
def retro_hunt(s, cve, product, days=30):
    """30-day hunt for evidence of a CVE in IDS / web / findings; hits become findings (and so a case)."""
    hits, checked = [], []
    probes = [("INTRUSION_DETECTION", "signature", "src", "dest", "NULL"),
              ("WEB_ACTIVITY", "url", "src", "dest", "NULL")]
    for table, col, src, dest, user in probes:
        try:
            for h in rows(s, f"""SELECT _time, {src} AS src, {dest} AS dest, {user} AS user_name, LEFT({col}, 300) AS what
                                 FROM {DB}.RAW_LOGS.{table}
                                 WHERE _time > DATEADD('day', -?, CURRENT_TIMESTAMP()) AND {col} ILIKE ?
                                 ORDER BY _time DESC LIMIT 50""", [days, f"%{cve}%"]):
                hits.append({"table": table, **{k.lower(): str(v) for k, v in h.items()}})
            checked.append(table)
        except Exception:
            pass
    fids = []
    for h in hits[:20]:
        fid = one(s, "SELECT UUID_STRING() AS id")["ID"]
        s.sql(f"""INSERT INTO {DB}.DETECTIONS.DETECTION_FINDINGS
                    (finding_id, rule_id, event_time, severity, confidence, risk_score, mitre_tactic_id, mitre_technique_id,
                     category, src, dest, evidence, evidence_count, description, status, detection_source)
                  SELECT ?, ?, ?::TIMESTAMP_LTZ, 4, 70, 80, 'TA0001', 'T1190', 'network', NULLIF(?, 'None'), NULLIF(?, 'None'),
                         PARSE_JSON(?), 1, ?, 'new', 'retro_hunt'""",
              params=[fid, "HUNT-" + cve, h["_time"], h["src"], h["dest"], json.dumps(h),
                      f"Retro-hunt: {cve} ({product}) indicator in {h['table']}: {h['what'][:200]}"]).collect()
        fids.append(fid)
    return {"days": days, "tables": checked, "hits": len(hits), "finding_ids": fids}


def emerging(s, days):
    env = latest_env(s)
    new = []
    for k in kev_matches(s, env, days=days):
        if one(s, f"SELECT 1 AS x FROM {DB}.REFERENCE.THREAT_EXPOSURES WHERE kind = 'kev' AND ref = ?", [k["cve"]]):
            continue
        hunt = retro_hunt(s, k["cve"], k["product"])
        # rule proposal: make sure exploitation of public-facing apps is ranked first in the backlog
        s.sql(f"""UPDATE {DB}.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG
                  SET threat_score = GREATEST(COALESCE(threat_score, 0), 25),
                      rank_reason = LEFT(? || COALESCE('; ' || rank_reason, ''), 1000), ranked_at = CURRENT_TIMESTAMP()
                  WHERE technique_id = 'T1190'
                    AND NOT EXISTS (SELECT 1 FROM {DB}.DETECTIONS.CUSTOM_RULES c
                                    WHERE c.mitre_technique_id = 'T1190' AND (c.enabled OR c.test_mode))""",
              params=[f"new KEV {k['cve']} for {k['product']} ({k['matched']} in your environment)"]).collect()
        sc = 20 + (5 if k["ransomware"] == "Known" else 0)
        s.sql(f"""INSERT INTO {DB}.REFERENCE.THREAT_EXPOSURES (kind, ref, title, detail, products, techniques, score, retro_hunt)
                  SELECT 'kev', ?, ?, ?, PARSE_JSON(?), PARSE_JSON(?), ?, PARSE_JSON(?)""",
              params=[k["cve"], f"{k['cve']}: {k['name']}"[:500],
                      (f"{k['description']} You run {k['matched']}. Retro-hunt over 30 days: {hunt['hits']} hit(s)"
                       + (f" ({len(hunt['finding_ids'])} finding(s) opened)." if hunt["finding_ids"] else ".")
                       + (" Used in ransomware." if k["ransomware"] == "Known" else ""))[:2000],
                      json.dumps([k["matched"]]), json.dumps(["T1190"] + (["T1486"] if k["ransomware"] == "Known" else [])),
                      sc, json.dumps(hunt)]).collect()
        new.append({"kind": "kev", "ref": k["cve"], "product": k["matched"], "hits": hunt["hits"]})
    # New ATT&CK techniques for platforms we have data for
    platforms = {"AUTHENTICATION": ["Identity Provider", "Office Suite", "SaaS", "Windows", "Linux"],
                 "CLOUD_API": ["IaaS", "SaaS"], "DATABASE_ACTIVITY": ["SaaS", "IaaS"],
                 "ENDPOINT_PROCESSES": ["Windows", "Linux", "macOS"]}
    have = tables_with_data(s)
    plats = sorted({p for t in have for p in platforms.get(t, [])})
    for a in rows(s, f"""SELECT technique_id, name, tactics[0]::VARCHAR AS tactic, LEFT(description, 400) AS d
                         FROM {DB}.REFERENCE.ATTACK_CATALOG
                         WHERE change_kind = 'new' AND ARRAYS_OVERLAP(platforms, PARSE_JSON(?))
                           AND first_synced_at > DATEADD('day', -?, CURRENT_TIMESTAMP())
                         LIMIT 10""", [json.dumps(plats), int(days)]):
        if one(s, f"SELECT 1 AS x FROM {DB}.REFERENCE.THREAT_EXPOSURES WHERE kind = 'attack_new' AND ref = ?",
               [a["TECHNIQUE_ID"]]):
            continue
        s.sql(f"""INSERT INTO {DB}.REFERENCE.THREAT_EXPOSURES (kind, ref, title, detail, techniques, score)
                  SELECT 'attack_new', ?, ?, ?, PARSE_JSON(?), 12""",
              params=[a["TECHNIQUE_ID"], f"New ATT&CK technique {a['TECHNIQUE_ID']}: {a['NAME']}"[:500],
                      (a["D"] or "")[:2000], json.dumps([a["TECHNIQUE_ID"]])]).collect()
        new.append({"kind": "attack_new", "ref": a["TECHNIQUE_ID"]})
    return {"new_exposures": new}


def main(s, P_COMMAND, P_ARG):
    cmd = (P_COMMAND or "").lower()
    if cmd == "environment":
        return environment(s)
    if cmd == "set_profile":
        return set_profile(s, P_ARG)
    if cmd == "score":
        return score(s)
    if cmd == "rank":
        return rank(s)
    if cmd == "emerging":
        return emerging(s, int(P_ARG or 3))
    if cmd == "cycle":
        if one(s, f"SELECT {DB}.DETECTIONS.AUTONOMY_PAUSED() AS p")["P"]:
            return {"paused": True, "message": "autonomy is paused (kill switch)"}
        out = {"environment": environment(s)}
        out["emerging"] = emerging(s, int(P_ARG or 3))
        out["score"] = score(s)
        out["rank"] = rank(s)
        return out
    return {"error": "command must be environment | set_profile | score | rank | emerging | cycle"}
$$;

-- ---------------------------------------------------------------------------
-- Posture versus threat: per technique, how likely/impactful and how covered
-- (verified = has a passing canary, from setup/38_canaries.sql)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.REFERENCE.V_THREAT_HEATMAP AS
WITH cov AS (
    SELECT mitre_technique_id AS technique_id, rule_id, TRUE AS live
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES WHERE enabled
    UNION ALL
    SELECT mitre_technique_id, rule_id, enabled FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    WHERE enabled OR test_mode
),
canary AS (
    SELECT rule_id, status FROM SNOWFLAKE_XDR.DETECTIONS.CANARY_RUNS
    QUALIFY ROW_NUMBER() OVER (PARTITION BY rule_id ORDER BY run_at DESC) = 1
)
SELECT t.technique_id, t.name, t.tactic_id, m.tactic_name, t.likelihood, t.impact, t.score, t.sources, t.reasons,
       COUNT_IF(c.live) AS live_rules,
       COUNT(c.rule_id) - COUNT_IF(c.live) AS shadow_rules,
       COUNT_IF(k.status = 'pass') AS verified_rules,
       CASE WHEN COUNT_IF(k.status = 'pass') > 0 THEN 'verified'
            WHEN COUNT_IF(c.live) > 0 THEN 'claimed'
            WHEN COUNT(c.rule_id) > 0 THEN 'shadow'
            ELSE 'gap' END AS coverage,
       b.rank_reason, b.threat_score AS backlog_value
FROM SNOWFLAKE_XDR.REFERENCE.THREAT_TECHNIQUE_SCORES t
LEFT JOIN cov c ON c.technique_id = t.technique_id OR SPLIT_PART(c.technique_id, '.', 1) = t.technique_id
LEFT JOIN canary k ON k.rule_id = c.rule_id
LEFT JOIN SNOWFLAKE_XDR.REFERENCE.MITRE_TACTICS m ON m.tactic_id = t.tactic_id
LEFT JOIN SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG b ON b.technique_id = t.technique_id
GROUP BY ALL;

CREATE OR REPLACE TASK SNOWFLAKE_XDR.REFERENCE.TASK_THREAT_PROFILE
    WAREHOUSE = XDR_WH
    SCHEDULE = 'USING CRON 30 5 * * * UTC'
    COMMENT = 'Rebuild the environment profile, run the emerging-threat loop, re-score and re-rank the backlog'
AS
    CALL SNOWFLAKE_XDR.REFERENCE.THREAT_PROFILE_ENGINE('cycle', '3');
