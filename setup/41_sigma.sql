-- =============================================================================
-- Snowflake XDR - Phase 5.1: Sigma rule import with canary-verified coverage
-- =============================================================================
-- SigmaHQ rules are compiled deterministically (sigma/sigma_compiler.py, no LLM)
-- to XDR SQL against the CIM tables, each with synthesised canary fixtures: one
-- positive per branch of the condition and a negative that breaks one clause.
-- Compiled rules become rule packs sigma_windows / sigma_network / sigma_cloud and
-- flow through the normal pack_rule path: coverage-aware install -> shadow ->
-- canary -> promote, under the kill switch and the daily change budget.
--
-- Sources (both go through SIGMA_IMPORT):
--   'stage'  - vendored baseline: scripts/sync_sigma.sh zips rule-packs/sigma/ and PUTs it
--   'github' - live: latest SigmaHQ release (sigma_core++.zip) via an external access
--              integration; TASK_SIGMA_SYNC runs weekly and skips unchanged releases.
-- Rules are under the Detection Rule License (DRL) 1.1: authors are kept in each rule.
-- =============================================================================

CREATE STAGE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.SIGMA_STAGE
    COMMENT = 'Sigma compiler module and rule bundles';

-- Pre-install verification (RUN_CANARIES('verify:<pack>')): a pack rule must pass its own fixtures
-- before INSTALL_RULE_PACK installs it. No DEFAULTs: re-running ADD COLUMN ... DEFAULT fails.
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES ADD COLUMN IF NOT EXISTS verify_status VARCHAR(20);
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES ADD COLUMN IF NOT EXISTS verify_detail VARIANT;
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES ADD COLUMN IF NOT EXISTS verified_at TIMESTAMP_LTZ;

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.SIGMA_CATALOG (
    sigma_id          VARCHAR PRIMARY KEY,
    rule_id           VARCHAR,          -- SIG-00001; stable across re-imports
    title             VARCHAR,
    status            VARCHAR,          -- stable | test | experimental | deprecated
    level             VARCHAR,
    logsource         VARIANT,
    source_id         VARCHAR,          -- compiler logsource mapping (process_creation, aws, ...)
    pack_id           VARCHAR,
    path              VARCHAR,
    origin            VARCHAR,          -- vendored | github:<release tag>
    content_sha       VARCHAR,
    revision          NUMBER DEFAULT 1,
    compile_ok        BOOLEAN,
    compile_reason    VARCHAR,
    selected          BOOLEAN,          -- passes the import filter (status / level)
    branches          NUMBER,           -- DNF branches in the condition
    fixture_branches  NUMBER,           -- branches with a synthesised positive fixture
    technique_id      VARCHAR,
    imported_at       TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at        TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.SIGMA_SETTINGS (
    setting     VARCHAR PRIMARY KEY,
    value       VARIANT,
    updated_at  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);
MERGE INTO SNOWFLAKE_XDR.REFERENCE.SIGMA_SETTINGS t USING (
    SELECT 'statuses' AS setting, PARSE_JSON('["stable", "test"]') AS value UNION ALL
    SELECT 'levels', PARSE_JSON('["high", "critical"]') UNION ALL
    SELECT 'release_asset', TO_VARIANT('sigma_core++.zip') UNION ALL
    SELECT 'last_release', TO_VARIANT('')
) s ON t.setting = s.setting
WHEN NOT MATCHED THEN INSERT (setting, value) VALUES (s.setting, s.value);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.SIGMA_SYNC_RUNS (
    run_id       VARCHAR DEFAULT UUID_STRING(),
    origin       VARCHAR,
    started_at   TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    result       VARIANT
);

-- Live sync egress: GitHub release API and asset download hosts only
CREATE NETWORK RULE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.SIGMA_GITHUB_EGRESS
    MODE = EGRESS TYPE = HOST_PORT
    VALUE_LIST = ('api.github.com', 'github.com', 'objects.githubusercontent.com',
                  'release-assets.githubusercontent.com');
CREATE EXTERNAL ACCESS INTEGRATION IF NOT EXISTS XDR_SIGMA_GITHUB_ACCESS
    ALLOWED_NETWORK_RULES = (SNOWFLAKE_XDR.REFERENCE.SIGMA_GITHUB_EGRESS)
    ENABLED = TRUE
    COMMENT = 'Snowflake XDR: download SigmaHQ rule releases';

-- ---------------------------------------------------------------------------
-- SIGMA_IMPORT('stage' | 'github' | 'github:force')
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.SIGMA_IMPORT(P_SOURCE VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python', 'pyyaml')
IMPORTS = ('@SNOWFLAKE_XDR.REFERENCE.SIGMA_STAGE/sigma_compiler.py')
EXTERNAL_ACCESS_INTEGRATIONS = (XDR_SIGMA_GITHUB_ACCESS)
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import hashlib
import io
import json
import re
import urllib.request
import zipfile

import yaml
from sigma_compiler import COMPILER_VERSION, compile_rule

DB = "SNOWFLAKE_XDR"
PACKS = {
    "sigma_windows": ("Sigma - Endpoint", ("process_creation", "registry", "file"),
                      ["ENDPOINT_PROCESSES", "ENDPOINT_REGISTRY", "ENDPOINT_FILESYSTEM"]),
    "sigma_network": ("Sigma - Network, DNS and Proxy", ("network", "dns", "proxy"),
                      ["NETWORK_TRAFFIC", "DNS_ACTIVITY", "WEB_ACTIVITY"]),
    "sigma_cloud": ("Sigma - Cloud and Identity", ("aws", "okta", "azure_activity", "azure_audit", "azure_signin"),
                    ["CLOUD_API", "AUTHENTICATION"]),
}


def rows(s, sql, params=None):
    return [r.as_dict() for r in s.sql(sql, params=params).collect()]


def one(s, sql, params=None):
    r = rows(s, sql, params)
    return r[0] if r else None


def setting(s, name, default=None):
    r = one(s, f"SELECT value FROM {DB}.REFERENCE.SIGMA_SETTINGS WHERE setting = ?", [name])
    if not r or r["VALUE"] is None:
        return default
    return json.loads(r["VALUE"])


def pack_for(source_id):
    return next(p for p, (_, ids, _t) in PACKS.items() if source_id in ids)


def github_bundle(s, force):
    req = urllib.request.Request("https://api.github.com/repos/SigmaHQ/sigma/releases/latest",
                                 headers={"Accept": "application/vnd.github+json", "User-Agent": "snowflake-xdr"})
    rel = json.loads(urllib.request.urlopen(req, timeout=30).read())
    tag, want = rel["tag_name"], setting(s, "release_asset", "sigma_core++.zip")
    if tag == setting(s, "last_release", "") and not force:
        return None, tag
    asset = next(a for a in rel["assets"] if a["name"] == want)
    data = urllib.request.urlopen(urllib.request.Request(asset["browser_download_url"],
                                                         headers={"User-Agent": "snowflake-xdr"}), timeout=120).read()
    return data, tag


def stage_bundle(s):
    with s.file.get_stream(f"@{DB}.REFERENCE.SIGMA_STAGE/sigma_bundle.zip") as f:
        return f.read()


def main(s, P_SOURCE):
    src = (P_SOURCE or "stage").lower()
    if src.startswith("github"):
        if one(s, f"SELECT {DB}.DETECTIONS.AUTONOMY_PAUSED() AS p")["P"] and src != "github:force":
            return {"ok": True, "message": "autonomy is paused (kill switch): Sigma sync skipped"}
        data, tag = github_bundle(s, src == "github:force")
        if data is None:
            return {"ok": True, "message": f"SigmaHQ release {tag} already imported", "release": tag}
        origin = "github:" + tag
    else:
        data, tag, origin = stage_bundle(s), None, "vendored"

    statuses = set(setting(s, "statuses", ["stable", "test"]))
    levels = set(setting(s, "levels", ["high", "critical"]))
    # A rule is only 'unchanged' if its content matches AND it actually reached its pack
    # (a failed earlier load must be retried, not skipped)
    known = {r["SIGMA_ID"]: r for r in rows(s, f"""SELECT c.sigma_id, c.rule_id, c.revision,
                                                  IFF(p.rule_id IS NULL, NULL, c.content_sha) AS content_sha
                                           FROM {DB}.REFERENCE.SIGMA_CATALOG c
                                           LEFT JOIN {DB}.REFERENCE.RULE_PACK_RULES p ON p.rule_id = c.rule_id""")}
    next_n = 1 + max([int(r["RULE_ID"].split("-")[1]) for r in known.values() if r["RULE_ID"]] or [0])

    records, changed = [], {p: [] for p in PACKS}
    stats = {"files": 0, "compiled": 0, "selected": 0, "new": 0, "updated": 0, "unchanged": 0, "failed": {}}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for name in z.namelist():
            if not name.endswith((".yml", ".yaml")) or "/deprecated/" in name:
                continue
            text = z.read(name).decode("utf-8", "replace")
            stats["files"] += 1
            sha = hashlib.sha256((COMPILER_VERSION + "\n" + text).encode()).hexdigest()
            try:
                sid = str((yaml.safe_load(text) or {}).get("id") or "")
            except yaml.YAMLError:
                sid = ""
            if not sid:
                continue
            prev = known.get(sid)
            rule_id = prev["RULE_ID"] if prev and prev["RULE_ID"] else f"SIG-{next_n:05d}"
            r = compile_rule(text, rule_id)
            ok = bool(r["ok"])
            sel = ok and str(r.get("status")) in statuses and str(r.get("level")) in levels
            if ok:
                stats["compiled"] += 1
            else:
                k = r["reason"].split(":")[0][:60]
                stats["failed"][k] = stats["failed"].get(k, 0) + 1
            if sel and not (prev and prev["RULE_ID"]):
                next_n += 1
            revision = int(prev["REVISION"] or 1) if prev else 1
            if prev and prev["CONTENT_SHA"] and prev["CONTENT_SHA"] != sha:
                revision += 1
            pack = pack_for(r["source_id"]) if ok else None
            records.append({"sigma_id": sid, "rule_id": rule_id if sel or (prev and prev["RULE_ID"]) else None,
                            "title": r.get("title"), "status": r.get("status"), "level": r.get("level"),
                            "logsource": json.dumps(r.get("logsource") or {}), "source_id": r.get("source_id"),
                            "pack_id": pack, "path": name, "origin": origin, "content_sha": sha,
                            "revision": revision, "compile_ok": ok, "compile_reason": r["reason"][:500],
                            "selected": sel, "branches": r.get("branches"), "fixture_branches": r.get("fixture_branches"),
                            "technique_id": (r.get("rule") or {}).get("technique")})
            if not sel:
                continue
            stats["selected"] += 1
            if prev and prev["CONTENT_SHA"] == sha and prev["RULE_ID"]:
                stats["unchanged"] += 1
                continue
            stats["updated" if prev and prev["RULE_ID"] else "new"] += 1
            rule = dict(r["rule"], version=revision)
            changed[pack].append(rule)

    # Upsert the catalogue in one MERGE
    if records:
        tmp = "SIGMA_IMPORT_ROWS"
        s.create_dataframe([[json.dumps(x)] for x in records], schema=["J"]).write.save_as_table(
            tmp, mode="overwrite", table_type="temporary")
        s.sql(f"""MERGE INTO {DB}.REFERENCE.SIGMA_CATALOG t USING (
                    SELECT PARSE_JSON(j) AS v FROM {tmp}) x ON t.sigma_id = x.v:sigma_id::VARCHAR
                  WHEN MATCHED THEN UPDATE SET rule_id = COALESCE(t.rule_id, x.v:rule_id::VARCHAR),
                      title = x.v:title::VARCHAR, status = x.v:status::VARCHAR, level = x.v:level::VARCHAR,
                      logsource = PARSE_JSON(x.v:logsource::VARCHAR), source_id = x.v:source_id::VARCHAR,
                      pack_id = x.v:pack_id::VARCHAR, path = x.v:path::VARCHAR, origin = x.v:origin::VARCHAR,
                      content_sha = x.v:content_sha::VARCHAR, revision = x.v:revision::NUMBER,
                      compile_ok = x.v:compile_ok::BOOLEAN, compile_reason = x.v:compile_reason::VARCHAR,
                      selected = x.v:selected::BOOLEAN, branches = x.v:branches::NUMBER,
                      fixture_branches = x.v:fixture_branches::NUMBER, technique_id = x.v:technique_id::VARCHAR,
                      updated_at = CURRENT_TIMESTAMP()
                  WHEN NOT MATCHED THEN INSERT (sigma_id, rule_id, title, status, level, logsource, source_id, pack_id,
                      path, origin, content_sha, revision, compile_ok, compile_reason, selected, branches,
                      fixture_branches, technique_id)
                  VALUES (x.v:sigma_id::VARCHAR, x.v:rule_id::VARCHAR, x.v:title::VARCHAR, x.v:status::VARCHAR,
                      x.v:level::VARCHAR, PARSE_JSON(x.v:logsource::VARCHAR), x.v:source_id::VARCHAR,
                      x.v:pack_id::VARCHAR, x.v:path::VARCHAR, x.v:origin::VARCHAR, x.v:content_sha::VARCHAR,
                      x.v:revision::NUMBER, x.v:compile_ok::BOOLEAN, x.v:compile_reason::VARCHAR,
                      x.v:selected::BOOLEAN, x.v:branches::NUMBER, x.v:fixture_branches::NUMBER,
                      x.v:technique_id::VARCHAR)""").collect()

    # Changed rules -> rule packs (the loader validates every rule's SQL and stores the fixtures)
    loaded = {}
    for pid, rules in changed.items():
        if not rules:
            continue
        name, ids, tables = PACKS[pid]
        pack = {"pack_id": pid, "name": name, "vendor": "SigmaHQ", "version": 1,
                "description": f"SigmaHQ community detections ({', '.join(ids)}), compiled to CIM SQL with "
                               "synthesised canaries. Detection Rule License 1.1; authors credited per rule.",
                "requires": [{"table": t} for t in tables],
                "onboarding": "Ingest the matching telemetry (Sysmon/EDR for endpoint, CloudTrail/Okta/Azure for cloud).",
                "rules": rules}
        res = one(s, f"CALL {DB}.REFERENCE.LOAD_RULE_PACK(?)", [yaml.safe_dump(pack, sort_keys=False)])
        res = json.loads(list(res.values())[0])
        for e in res.get("errors") or []:
            s.sql(f"""UPDATE {DB}.REFERENCE.SIGMA_CATALOG SET compile_ok = FALSE, selected = FALSE,
                        compile_reason = ? WHERE rule_id = ?""",
                  params=["loader: " + "; ".join(e["problems"])[:480], e["rule"]]).collect()
        loaded[pid] = {"loaded": res.get("rules_loaded"), "errors": len(res.get("errors") or [])}
        # Pre-install verification: each rule runs against its own synthesised fixtures in Snowflake
        v = one(s, f"CALL {DB}.DETECTIONS.RUN_CANARIES(?)", ["verify:" + pid])
        v = json.loads(list(v.values())[0])
        loaded[pid]["verified"] = {k: v.get(k) for k in ("rules", "pass", "fail", "error")}
    s.sql(f"""UPDATE {DB}.REFERENCE.RULE_PACKS SET vendor = 'SigmaHQ'
              WHERE pack_id IN ('sigma_windows', 'sigma_network', 'sigma_cloud')""").collect()
    if tag:
        s.sql(f"UPDATE {DB}.REFERENCE.SIGMA_SETTINGS SET value = TO_VARIANT(?), updated_at = CURRENT_TIMESTAMP() "
              "WHERE setting = 'last_release'", params=[tag]).collect()
    out = {"ok": True, "origin": origin, **stats, "packs": loaded}
    s.sql(f"INSERT INTO {DB}.REFERENCE.SIGMA_SYNC_RUNS (origin, result) SELECT ?, PARSE_JSON(?)",
          params=[origin, json.dumps(out)]).collect()
    return out
$$;

-- Catalogue / coverage view for the console
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.REFERENCE.V_SIGMA_STATUS AS
SELECT s.sigma_id, s.rule_id, s.title, s.status, s.level, s.source_id, s.pack_id, s.origin, s.revision,
       s.compile_ok, s.compile_reason, s.selected, s.branches, s.fixture_branches, s.technique_id,
       p.install_state, p.verify_status, p.verify_detail:message::VARCHAR AS verify_message, c.enabled, c.test_mode,
       cr.status AS canary_status, cr.run_at AS canary_at,
       CASE WHEN NOT s.compile_ok THEN 'not_compiled'
            WHEN NOT s.selected THEN 'filtered'
            WHEN p.verify_status IN ('fail', 'error') THEN 'verification_failed'
            WHEN cr.status = 'pass' THEN 'verified'
            WHEN cr.status IS NOT NULL THEN 'canary_failing'
            WHEN c.rule_id IS NOT NULL THEN 'installed'
            ELSE COALESCE(p.install_state, 'catalogued') END AS state
FROM SNOWFLAKE_XDR.REFERENCE.SIGMA_CATALOG s
LEFT JOIN SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES p ON p.rule_id = s.rule_id
LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES c ON c.rule_id = s.rule_id
LEFT JOIN (SELECT rule_id, status, run_at FROM SNOWFLAKE_XDR.DETECTIONS.CANARY_RUNS
           QUALIFY ROW_NUMBER() OVER (PARTITION BY rule_id ORDER BY run_at DESC) = 1) cr ON cr.rule_id = s.rule_id;

-- Weekly live sync (new/changed rules then install through the autopilot's pack_rule step)
CREATE OR REPLACE TASK SNOWFLAKE_XDR.REFERENCE.TASK_SIGMA_SYNC
    WAREHOUSE = XDR_WH
    SCHEDULE = 'USING CRON 0 5 * * 1 UTC'
    COMMENT = 'Weekly SigmaHQ release sync'
AS
    CALL SNOWFLAKE_XDR.REFERENCE.SIGMA_IMPORT('github');
ALTER TASK SNOWFLAKE_XDR.REFERENCE.TASK_SIGMA_SYNC RESUME;
