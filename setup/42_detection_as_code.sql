-- =============================================================================
-- Snowflake XDR - Phase 5.2: Detection-as-code
-- =============================================================================
-- Git holds every detection as YAML (rule-packs/*/pack.yaml for packs,
-- detections/<managed_by>/<rule_id>.yml for human and AI-authored rules).
--   scripts/export_rules.py        Snowflake -> git (so every AI change is a reviewable diff)
--   CI_VERIFY_RULES(yaml_bundle)   pull request: lint + compile + canary-verify changed rules in a
--                                  scratch pack, then remove it (.github/workflows/detections.yml)
--   APPLY_RULES_FROM_GIT(bundle, ref)  merge to main: apply changed rules (history snapshot first,
--                                  pinned rules and pack rules are never overwritten from here)
-- =============================================================================

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.CI_VERIFY_RULES(P_BUNDLE VARCHAR)
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


def one(s, sql, params=None):
    r = s.sql(sql, params=params).collect()
    return r[0].as_dict() if r else None


def main(s, P_BUNDLE):
    """P_BUNDLE: JSON list of {path, text}. Each text is a pack.yaml or a single-rule YAML."""
    files = json.loads(P_BUNDLE or "[]")
    rules, results, mapping = [], [], {}
    for f in files:
        try:
            doc = yaml.safe_load(f["text"]) or {}
        except yaml.YAMLError as e:
            results.append({"path": f["path"], "status": "error", "message": "yaml: " + str(e)[:200]})
            continue
        for r in (doc.get("rules") if isinstance(doc.get("rules"), list) else [doc]):
            if not isinstance(r, dict) or not r.get("sql"):
                results.append({"path": f["path"], "rule": r.get("id") if isinstance(r, dict) else None,
                                "status": "skipped", "message": "not a SQL rule"})
                continue
            ci_id = f"CI-{len(rules) + 1:05d}"
            mapping[ci_id] = {"path": f["path"], "rule": str(r.get("id"))}
            rules.append(dict(r, id=ci_id, version=1))
    if not rules:
        return {"ok": True, "rules": 0, "results": results}
    pack = {"pack_id": "ci_check", "name": "CI check (scratch)", "vendor": "ci", "version": 1, "rules": rules}
    try:
        load = json.loads(list(one(s, f"CALL {DB}.REFERENCE.LOAD_RULE_PACK(?)",
                                   [yaml.safe_dump(pack, sort_keys=False)]).values())[0])
        failed_load = {e["rule"]: "; ".join(e["problems"]) for e in load.get("errors") or []}
        # Compile check: EXPLAIN every loaded rule
        compiled = {}
        for x in s.sql(f"SELECT rule_id, code FROM {DB}.REFERENCE.RULE_PACK_RULES WHERE pack_id = 'ci_check'").collect():
            try:
                s.sql("EXPLAIN " + x["CODE"]).collect()
                compiled[x["RULE_ID"]] = None
            except Exception as e:
                compiled[x["RULE_ID"]] = str(e)[:300]
        verify = json.loads(list(one(s, f"CALL {DB}.DETECTIONS.RUN_CANARIES('verify:ci_check')").values())[0])
        vstate = {x["RULE_ID"]: (x["VERIFY_STATUS"], x["MSG"]) for x in s.sql(
            f"""SELECT rule_id, verify_status, verify_detail:message::VARCHAR AS msg
                FROM {DB}.REFERENCE.RULE_PACK_RULES WHERE pack_id = 'ci_check'""").collect()}
        for ci_id, m in mapping.items():
            if ci_id in failed_load:
                results.append({**m, "status": "fail", "message": "lint: " + failed_load[ci_id]})
            elif compiled.get(ci_id):
                results.append({**m, "status": "fail", "message": "compile: " + compiled[ci_id]})
            elif ci_id in vstate and vstate[ci_id][0]:
                st, msg = vstate[ci_id]
                results.append({**m, "status": "pass" if st == "pass" else "fail", "message": "canary: " + str(msg)})
            else:
                results.append({**m, "status": "warn", "message": "compiles and lints; no fixtures, so not canary-verified"})
    finally:
        s.sql(f"DELETE FROM {DB}.DETECTIONS.CANARY_RUNS WHERE rule_id LIKE 'CI-%'").collect()
        s.sql(f"DELETE FROM {DB}.REFERENCE.RULE_PACK_RULES WHERE pack_id = 'ci_check'").collect()
        s.sql(f"DELETE FROM {DB}.REFERENCE.RULE_PACKS WHERE pack_id = 'ci_check'").collect()
    bad = [r for r in results if r["status"] == "fail" or r["status"] == "error"]
    return {"ok": not bad, "rules": len(rules), "failed": len(bad), "results": results}
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.APPLY_RULES_FROM_GIT(P_BUNDLE VARCHAR, P_REF VARCHAR)
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
CR = DB + ".DETECTIONS.CUSTOM_RULES"
REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,80}$")


def one(s, sql, params=None):
    r = s.sql(sql, params=params).collect()
    return r[0].as_dict() if r else None


def main(s, P_BUNDLE, P_REF):
    """Apply single-rule YAMLs from detections/ (merged to main). Pack rules change through their pack."""
    ref = P_REF if P_REF and REF_RE.match(P_REF) else "unknown"
    out = {"applied": [], "unchanged": [], "skipped": [], "errors": []}
    for f in json.loads(P_BUNDLE or "[]"):
        try:
            r = yaml.safe_load(f["text"]) or {}
        except yaml.YAMLError as e:
            out["errors"].append({"path": f["path"], "error": str(e)[:200]})
            continue
        rid = str(r.get("id") or "")
        cur = one(s, f"SELECT * FROM {CR} WHERE rule_id = ?", [rid])
        if not cur:
            out["skipped"].append({"rule": rid, "why": "no such rule (new rules are created in the console or a pack)"})
            continue
        if cur["MANAGED_BY"] == "pack" or cur["PINNED"]:
            out["skipped"].append({"rule": rid, "why": "pack rule (edit its pack) or pinned"})
            continue
        sql = (r.get("sql") or "").strip().rstrip(";")
        v = one(s, f"SELECT {DB}.DASHBOARDS.RULE_SQL_VIOLATION(?) AS v", [sql])["V"]
        if v:
            out["errors"].append({"rule": rid, "error": "sql " + v})
            continue
        new = (sql, int(r.get("threshold", 1)), int(r.get("severity", 3)), bool(r.get("enabled", cur["ENABLED"])))
        if new == ((cur["CODE"] or "").strip(), int(cur["THRESHOLD_COUNT"] or 1), int(cur["SEVERITY"] or 3), bool(cur["ENABLED"])):
            out["unchanged"].append(rid)
            continue
        s.sql(f"""INSERT INTO {DB}.DETECTIONS.CUSTOM_RULE_HISTORY
                    (rule_id, version, name, code, language, severity, threshold_count, enabled, changed_by)
                  SELECT rule_id, version, name, code, language, severity, threshold_count, enabled, ?
                  FROM {CR} WHERE rule_id = ?""", params=["git:" + ref, rid]).collect()
        s.sql(f"""UPDATE {CR} SET code = ?, threshold_count = ?, severity = ?, enabled = ?, version = version + 1,
                    updated_at = CURRENT_TIMESTAMP() WHERE rule_id = ?""", params=[*new, rid]).collect()
        out["applied"].append(rid)
    return {"ok": not out["errors"], "ref": ref, **out}
$$;
