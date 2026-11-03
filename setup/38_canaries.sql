-- ============================================================================
-- Snowflake XDR - Detection canaries, verified coverage, trust ladder (Phase 4)
-- ============================================================================
-- Canaries prove detections work end to end instead of claiming coverage:
--   * Each rule's positive and negative fixtures (rule-packs/*/pack.yaml, or
--     CANARY_FIXTURES for any custom rule) are injected with a unique marker
--     ('xdrcanary...') and index_name = 'canary'. Fixtures with an "otel" block go
--     through INGEST_OTLP_LOGS and the live CIM mapping, so parsers are tested too.
--   * The rule then has to match every positive within its expected latency and
--     none of the negatives. Canary rows and any findings they cause are removed
--     right after, and the rule engine ignores marker rows, so canaries never
--     reach the queue, metrics or model training.
--   * A failure is logged as a CUSTOM_RULE_ERRORS row (stage 'canary'), which the
--     autopilot turns into a fix_broken change, and shows in Mission Control.
--   * "Verified" coverage (latest canary passed) replaces claimed coverage in
--     V_THREAT_HEATMAP and V_VERIFIED_COVERAGE.
--
-- Trust ladder: per change type, AUTONOMY_TRACK_RECORD tracks approvals,
-- rejections, rollbacks, canary pass rate and post-promotion precision. When
-- thresholds are met the system PROPOSES a one-step promotion
-- (propose_only -> shadow_then_promote -> auto_live) that a human approves;
-- a rollback or canary failure demotes automatically.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

ALTER TABLE SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES ADD COLUMN IF NOT EXISTS fixtures VARIANT;
ALTER TABLE SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES ADD COLUMN IF NOT EXISTS expected_latency_seconds NUMBER;

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.CANARY_FIXTURES (
    rule_id      VARCHAR(100) PRIMARY KEY,
    fixtures     VARIANT,          -- {positive: [...], negative: [...]} (same shape as pack YAML)
    expected_latency_seconds NUMBER DEFAULT 300,
    created_by   VARCHAR(255) DEFAULT CURRENT_USER(),
    updated_at   TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_CANARY_FIXTURES AS
SELECT rule_id, fixtures, COALESCE(expected_latency_seconds, 300) AS expected_latency_seconds, 'pack' AS origin
FROM SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES WHERE fixtures IS NOT NULL
UNION ALL
SELECT rule_id, fixtures, expected_latency_seconds, 'manual'
FROM SNOWFLAKE_XDR.DETECTIONS.CANARY_FIXTURES
WHERE rule_id NOT IN (SELECT rule_id FROM SNOWFLAKE_XDR.REFERENCE.RULE_PACK_RULES WHERE fixtures IS NOT NULL);

-- ---------------------------------------------------------------------------
-- RUN_CANARIES('all' | rule_id)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RUN_CANARIES(P_RULE_ID VARCHAR)
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
import time

DB = "SNOWFLAKE_XDR"
COL_RE = re.compile(r"^[a-z_][a-z0-9_]{0,60}$")
TABLE_RE = re.compile(r"^[A-Z_]{3,60}$")
MARK = "xdrcanary"


def rows(s, sql, params=None):
    return [r.as_dict() for r in s.sql(sql, params=params).collect()]


def one(s, sql, params=None):
    r = rows(s, sql, params)
    return r[0] if r else None


def fill(v, marker, n):
    if isinstance(v, str):
        return v.replace("{{entity}}", marker).replace("{{n}}", str(n))
    if isinstance(v, dict):
        return {k: fill(x, marker, n) for k, x in v.items()}
    if isinstance(v, list):
        return [fill(x, marker, n) for x in v]
    return v


def table_columns(s, cache, table):
    if table not in cache:
        cache[table] = {r["C"].lower(): r["T"] for r in rows(s, """SELECT column_name AS c, data_type AS t
                        FROM SNOWFLAKE_XDR.INFORMATION_SCHEMA.COLUMNS WHERE table_schema = 'RAW_LOGS' AND table_name = ?""",
                                                         [table])}
    return cache[table]


def inject_table(s, cache, fx, marker, touched):
    table = str(fx.get("table", "")).upper()
    cols = table_columns(s, cache, table)
    if not TABLE_RE.match(table) or not cols:
        raise ValueError(f"unknown CIM table {table}")
    count, offset = int(fx.get("count", 1)), float(fx.get("offset_minutes", 1))
    for n in range(count):
        row = fill(fx.get("row") or {}, marker, n)
        names, exprs, binds = ["_time", "index_name"], ["DATEADD('second', ?, CURRENT_TIMESTAMP())", "'canary'"], \
                              [int(-offset * 60 + n)]
        for k, v in row.items():
            k = k.lower()
            if not COL_RE.match(k) or k not in cols or k in ("_time", "index_name"):
                raise ValueError(f"{table} has no column {k}")
            names.append(k)
            if cols[k] in ("VARIANT", "OBJECT", "ARRAY"):
                exprs.append("PARSE_JSON(?)")
                binds.append(json.dumps(v))
            else:
                exprs.append("?")
                binds.append(v if isinstance(v, (int, float)) else str(v))
        s.sql(f"INSERT INTO {DB}.RAW_LOGS.{table} ({', '.join(names)}) SELECT {', '.join(exprs)}",
              params=binds).collect()
    touched.add(table)


def inject_otel(s, fx, marker, touched):
    o = fx["otel"]
    count = int(fx.get("count", 1))
    now_ns = int(time.time() * 1e9)
    records = []
    for n in range(count):
        body = fill(o.get("body"), marker, n)
        records.append({"timeUnixNano": str(now_ns - int(float(fx.get("offset_minutes", 1)) * 60e9) + n),
                        "severityText": "INFO",
                        "body": {"stringValue": json.dumps(body) if not isinstance(body, str) else body},
                        "attributes": [{"key": "xdr.canary", "value": {"boolValue": True}}]})
    payload = {"resourceLogs": [{"resource": {"attributes": [
        {"key": "service.name", "value": {"stringValue": o["service_name"]}}]},
        "scopeLogs": [{"scope": {"name": "xdr-canary"}, "logRecords": records}]}]}
    r = one(s, f"CALL {DB}.RAW_LOGS.INGEST_OTLP_LOGS(?, NULL)", [json.dumps(payload)])
    res = json.loads(list(r.values())[0])
    if not res.get("ok", True) and res.get("error"):
        raise ValueError("ingest: " + str(res.get("error"))[:200])
    touched.add("OTEL")
    for m in rows(s, f"SELECT target_table FROM {DB}.REFERENCE.CIM_MAPPINGS WHERE source_id = ? AND status = 'live'",
                  [o["service_name"]]):
        touched.add(m["TARGET_TABLE"])


def matches(s, rule, marker):
    sql = f"""SELECT COUNT(*) AS n FROM ({rule['CODE']})
              WHERE _time > DATEADD('minute', -{int(rule['LOOKBACK_MINUTES'] or 60)}, CURRENT_TIMESTAMP())
                AND CONTAINS(LOWER(COALESCE(user_name::VARCHAR, '') || '|' || COALESCE(src::VARCHAR, '') || '|' ||
                             COALESCE(dest::VARCHAR, '') || '|' || COALESCE(description::VARCHAR, '')), ?)"""
    return int(one(s, sql, [marker.lower()])["N"])


def cleanup(s, touched, started):
    for t in sorted(touched):
        if t == "OTEL":
            s.sql(f"""DELETE FROM {DB}.RAW_LOGS.OTEL_LOGS WHERE received_at >= ?::TIMESTAMP_LTZ
                      AND (attributes:"xdr.canary"::BOOLEAN OR CONTAINS(body::VARCHAR, '{MARK}'))""",
                  params=[started]).collect()
            continue
        cols = table_columns(s, {}, t)
        cond = " OR ".join(f"CONTAINS(LOWER(COALESCE({c}::VARCHAR, '')), '{MARK}')"
                           for c in ("user_name", "src", "dest", "query_text", "signature", "url", "process")
                           if c in cols) or "FALSE"
        s.sql(f"DELETE FROM {DB}.RAW_LOGS.{t} WHERE index_name = 'canary' OR ({cond})").collect()
    # Findings any detection raised on canary data never reach the queue or metrics
    for t in ("DETECTION_FINDINGS", "SHADOW_FINDINGS"):
        s.sql(f"""DELETE FROM {DB}.DETECTIONS.{t} WHERE detection_time >= DATEADD('minute', -5, ?::TIMESTAMP_LTZ)
                  AND CONTAINS(LOWER(COALESCE(user_name, '') || '|' || COALESCE(src, '') || '|' || COALESCE(dest, '')
                               || '|' || COALESCE(description, '')), '{MARK}')""", params=[started]).collect()


def run_one(s, cache, f, batch):
    rid = f["RULE_ID"]
    rule = one(s, f"SELECT * FROM {DB}.DETECTIONS.CUSTOM_RULES WHERE rule_id = ? AND language = 'sql'", [rid])
    if not rule:
        return None
    fx = json.loads(f["FIXTURES"]) if isinstance(f["FIXTURES"], str) else f["FIXTURES"]
    tag = re.sub(r"[^a-z0-9]", "", rid.lower())
    pos_m, neg_m = f"{MARK}p{tag}{batch[:6]}", f"{MARK}n{tag}{batch[:6]}"
    touched, started = set(), one(s, "SELECT CURRENT_TIMESTAMP()::VARCHAR AS t")["T"]
    detail, status, pos, neg, latency = {}, "error", False, False, None
    try:
        t0 = time.time()
        for x in fx.get("positive") or []:
            (inject_otel if x.get("otel") else lambda s_, x_, m_, t_: inject_table(s_, cache, x_, m_, t_))(s, x, pos_m, touched)
        for x in fx.get("negative") or []:
            (inject_otel if x.get("otel") else lambda s_, x_, m_, t_: inject_table(s_, cache, x_, m_, t_))(s, x, neg_m, touched)
        if "OTEL" in touched:
            detail["mapping"] = str(list(one(s, f"CALL {DB}.REFERENCE.APPLY_CIM_MAPPINGS()").values())[0])[:300]
        need = max(1, int(rule["THRESHOLD_COUNT"] or 1))
        n_pos, n_neg = matches(s, rule, pos_m), matches(s, rule, neg_m)
        latency = round(time.time() - t0, 1)
        pos, neg = n_pos >= need, n_neg >= need
        within = latency <= float(f["EXPECTED_LATENCY_SECONDS"] or 300)
        status = "pass" if pos and not neg and within else "fail"
        detail.update({"positive_matches": n_pos, "needed": need, "negative_matches": n_neg,
                       "message": ("ok" if status == "pass" else
                                   "positive fixture did not fire" if not pos else
                                   "negative fixture fired (false positive)" if neg else
                                   f"fired too slowly ({latency}s)")})
    except Exception as e:
        detail["message"] = "canary error: " + str(e)[:400]
    finally:
        try:
            cleanup(s, touched, started)
        except Exception as e:
            detail["cleanup_error"] = str(e)[:200]
    s.sql(f"""INSERT INTO {DB}.DETECTIONS.CANARY_RUNS (batch_id, rule_id, status, positive_fired, negative_fired,
                latency_seconds, detail) SELECT ?, ?, ?, ?, ?, ?, PARSE_JSON(?)""",
          params=[batch, rid, status, pos, neg, latency if latency is not None else -1, json.dumps(detail)]).collect()
    if status != "pass":
        # The autopilot's fix_broken step repairs rules with recent errors; Mission Control lists the failure
        s.sql(f"""INSERT INTO {DB}.DETECTIONS.CUSTOM_RULE_ERRORS (rule_id, error_message, stage)
                  SELECT ?, ?, 'canary'""", params=[rid, "canary: " + detail.get("message", "failed")]).collect()
    return {"rule_id": rid, "status": status, **{k: detail.get(k) for k in ("message", "positive_matches", "negative_matches")},
            "latency_seconds": latency}


DEMO_USERS = ["amorgan", "bchen", "cdiaz", "dpatel", "ekovacs", "fnakamura", "gsilva", "hokafor"]


def seed(s, pack):
    """Demo data: inject each pack rule's positive fixtures under a realistic user name (no canary marker,
    no cleanup), so the shadow rules produce findings to triage. RUN_CANARIES('seed:<pack>|seed:all')."""
    cache, touched, n = {}, set(), 0
    for i, f in enumerate(rows(s, f"""SELECT v.rule_id, v.fixtures FROM {DB}.DETECTIONS.V_CANARY_FIXTURES v
                                      JOIN {DB}.REFERENCE.RULE_PACK_RULES r ON r.rule_id = v.rule_id
                                      WHERE ? = 'all' OR r.pack_id = ? ORDER BY v.rule_id""", [pack, pack])):
        fx = json.loads(f["FIXTURES"]) if isinstance(f["FIXTURES"], str) else f["FIXTURES"]
        who = DEMO_USERS[i % len(DEMO_USERS)]
        for x in fx.get("positive") or []:
            x = dict(x, offset_minutes=max(float(x.get("offset_minutes", 1)), 5))
            if x.get("otel"):
                inject_otel(s, x, who, touched)
            else:
                x["row"] = {k: v for k, v in (x.get("row") or {}).items()}
                inject_table(s, cache, x, who, touched)
                s.sql(f"UPDATE {DB}.RAW_LOGS.{x['table'].upper()} SET index_name = 'demo' WHERE index_name = 'canary'").collect()
            n += 1
    if "OTEL" in touched:
        s.sql(f"CALL {DB}.REFERENCE.APPLY_CIM_MAPPINGS()").collect()
    s.sql(f"CALL {DB}.DETECTIONS.RUN_CUSTOM_RULES()").collect()
    return {"seeded_fixtures": n, "tables": sorted(touched)}


def main(s, P_RULE_ID):
    batch = one(s, "SELECT REPLACE(UUID_STRING(), '-', '') AS b")["B"]
    want = (P_RULE_ID or "all")
    if want.lower().startswith("seed:"):
        return seed(s, want.split(":", 1)[1].lower() or "all")
    fixtures = rows(s, f"""SELECT v.* FROM {DB}.DETECTIONS.V_CANARY_FIXTURES v
                           JOIN {DB}.DETECTIONS.CUSTOM_RULES c ON c.rule_id = v.rule_id
                           WHERE (? = 'all' AND (c.enabled OR c.test_mode)) OR v.rule_id = ?
                           ORDER BY v.rule_id""", [want, want])
    cache, out = {}, []
    for f in fixtures:
        r = run_one(s, cache, f, batch)
        if r:
            out.append(r)
    passed = sum(1 for r in out if r["status"] == "pass")
    demoted = demote_on_failure(s, [r["rule_id"] for r in out if r["status"] != "pass"])
    return {"batch_id": batch, "rules": len(out), "passed": passed, "failed": len(out) - passed,
            "results": out, "demoted": demoted}


def demote_on_failure(s, failed_rules):
    """Trust ladder: a canary failure on a rule created by an auto_live change type demotes that type one step."""
    out = []
    for ct in {r["CT"] for r in rows(s, f"""SELECT DISTINCT change_type AS ct FROM {DB}.DETECTIONS.AUTOPILOT_CHANGES
                                           WHERE rule_id IN (SELECT value::VARCHAR FROM TABLE(FLATTEN(PARSE_JSON(?))))
                                             AND status IN ('applied', 'promoted', 'approved')""",
                                        [json.dumps(failed_rules)])} if failed_rules else set():
        r = one(s, f"CALL {DB}.DETECTIONS.TRUST_LADDER(?)", [json.dumps({"demote": ct, "reason": "canary failure"})])
        out.append({"change_type": ct, "result": json.loads(list(r.values())[0])})
    return out
$$;

-- ---------------------------------------------------------------------------
-- Verified coverage
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_VERIFIED_COVERAGE AS
WITH latest AS (
    SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.CANARY_RUNS
    QUALIFY ROW_NUMBER() OVER (PARTITION BY rule_id ORDER BY run_at DESC) = 1
),
history AS (
    SELECT rule_id, COUNT(*) AS runs_30d, COUNT_IF(status = 'pass') AS passes_30d
    FROM SNOWFLAKE_XDR.DETECTIONS.CANARY_RUNS WHERE run_at > DATEADD('day', -30, CURRENT_TIMESTAMP()) GROUP BY 1
)
SELECT c.rule_id, c.name, c.mitre_technique_id, c.enabled, c.test_mode, c.pack_id,
       l.status AS canary_status, l.run_at AS last_canary, l.latency_seconds, l.detail:message::VARCHAR AS canary_message,
       h.runs_30d, h.passes_30d,
       CASE WHEN l.status = 'pass' THEN 'verified'
            WHEN l.status IN ('fail', 'error') THEN 'failing'
            WHEN f.rule_id IS NOT NULL THEN 'untested'
            ELSE 'no_fixture' END AS verification
FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES c
LEFT JOIN latest l ON l.rule_id = c.rule_id
LEFT JOIN history h ON h.rule_id = c.rule_id
LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.V_CANARY_FIXTURES f ON f.rule_id = c.rule_id
WHERE c.enabled OR c.test_mode;

-- ---------------------------------------------------------------------------
-- Trust ladder
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_TRACK_RECORD AS
WITH ch AS (
    SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES
    WHERE created_at > DATEADD('day', -90, CURRENT_TIMESTAMP())
      AND change_type NOT IN ('autonomy_promotion', 'autonomy_demotion')
),
human AS (
    SELECT change_type,
           COUNT_IF(status = 'approved' AND decided_by NOT ILIKE 'autopilot%') AS approvals,
           COUNT_IF(status = 'rejected') AS rejections,
           COUNT_IF(status = 'rolled_back') AS rollbacks,
           COUNT_IF(status = 'rolled_back' AND updated_at > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS rollbacks_7d,
           COUNT_IF(status IN ('promoted', 'applied')) AS automatic_live,
           COUNT(*) AS total
    FROM ch GROUP BY 1
),
canary AS (
    SELECT ch.change_type, COUNT(k.run_id) AS canary_runs, COUNT_IF(k.status = 'pass') AS canary_passes,
           COUNT_IF(k.status <> 'pass' AND k.run_at > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS canary_failures_7d
    FROM ch JOIN SNOWFLAKE_XDR.DETECTIONS.CANARY_RUNS k ON k.rule_id = COALESCE(ch.rule_id, ch.target_rule_id)
    WHERE k.run_at > ch.created_at GROUP BY 1
),
prec AS (
    SELECT ch.change_type, COUNT_IF(f.disposition = 'true_positive') AS tp,
           COUNT_IF(f.disposition IN ('false_positive', 'benign')) AS fp
    FROM ch JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f ON f.rule_id = COALESCE(ch.rule_id, ch.target_rule_id)
    WHERE ch.status IN ('promoted', 'applied', 'approved') AND f.detection_time > ch.updated_at
      AND SNOWFLAKE_XDR.DETECTIONS.IS_HUMAN_VERDICT(f.disposition_source)
    GROUP BY 1
)
SELECT p.change_type, p.mode,
       COALESCE(h.approvals, 0) AS approvals, COALESCE(h.rejections, 0) AS rejections,
       COALESCE(h.rollbacks, 0) AS rollbacks, COALESCE(h.rollbacks_7d, 0) AS rollbacks_7d,
       COALESCE(h.automatic_live, 0) AS automatic_live, COALESCE(h.total, 0) AS total,
       COALESCE(c.canary_runs, 0) AS canary_runs,
       IFF(COALESCE(c.canary_runs, 0) = 0, NULL, ROUND(c.canary_passes / c.canary_runs, 3)) AS canary_pass_rate,
       COALESCE(c.canary_failures_7d, 0) AS canary_failures_7d,
       IFF(COALESCE(r.tp, 0) + COALESCE(r.fp, 0) = 0, NULL, ROUND(r.tp / (r.tp + r.fp), 3)) AS precision,
       COALESCE(r.tp, 0) + COALESCE(r.fp, 0) AS verdicts
FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_POLICY p
LEFT JOIN human h ON h.change_type = p.change_type
LEFT JOIN canary c ON c.change_type = p.change_type
LEFT JOIN prec r ON r.change_type = p.change_type;

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.TRUST_LADDER_RULES (
    from_mode            VARCHAR(30) PRIMARY KEY,
    to_mode              VARCHAR(30),
    min_approvals        NUMBER,    -- human approvals of this type in 90 days
    max_rejection_rate   FLOAT,
    min_automatic_live   NUMBER,    -- changes that went live without a human (shadow -> promoted)
    min_canary_pass_rate FLOAT,     -- NULL = not required
    min_precision        FLOAT      -- NULL = not required (needs analyst verdicts)
);

MERGE INTO SNOWFLAKE_XDR.DETECTIONS.TRUST_LADDER_RULES t
USING (SELECT * FROM VALUES
    ('propose_only',        'shadow_then_promote', 5,  0.1, 0,  NULL, NULL),
    ('shadow_then_promote', 'auto_live',           10, 0.05, 10, 0.95, 0.8)
    AS v(from_mode, to_mode, min_approvals, max_rejection_rate, min_automatic_live, min_canary_pass_rate, min_precision)) s
ON t.from_mode = s.from_mode
WHEN NOT MATCHED THEN INSERT VALUES (s.from_mode, s.to_mode, s.min_approvals, s.max_rejection_rate,
    s.min_automatic_live, s.min_canary_pass_rate, s.min_precision);

-- TRUST_LADDER(NULL): evaluate every type, propose promotions, apply demotions.
-- TRUST_LADDER('{"demote": "<change_type>", "reason": "..."}'): demote one type now.
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.TRUST_LADDER(P_ARG VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import json

DB = "SNOWFLAKE_XDR"
CH = DB + ".DETECTIONS.AUTOPILOT_CHANGES"
LADDER = ["propose_only", "shadow_then_promote", "auto_live"]
# Fixed by design: these never climb the ladder (human decisions / hard limits)
NEVER = {"recheck_verdicts", "disable_noisy", "retire_silent", "suppress_entity", "intel_allowlist", "new_parser"}
# Rule-authoring types stop at shadow_then_promote: a written rule is always tested in shadow first
MAX_MODE = {"new_rule": "shadow_then_promote", "fix_broken": "shadow_then_promote", "tune_filter": "shadow_then_promote"}


def rows(s, sql, params=None):
    return [r.as_dict() for r in s.sql(sql, params=params).collect()]


def one(s, sql, params=None):
    r = rows(s, sql, params)
    return r[0] if r else None


def record(s, ct, status, title, rationale, evidence):
    cid = one(s, "SELECT UUID_STRING() AS id")["ID"]
    s.sql(f"""INSERT INTO {CH} (change_id, change_type, mode, status, title, rationale, severity, evidence, decided_by)
              SELECT ?, ?, 'propose_only', ?, ?, ?, 3, PARSE_JSON(?), {"'autopilot:trust_ladder'" if status != 'proposed' else 'NULL'}""",
          params=[cid, ct, status, title[:500], rationale[:4000], json.dumps(evidence, default=str)]).collect()
    return cid


def demote(s, change_type, reason):
    p = one(s, f"SELECT mode FROM {DB}.DETECTIONS.AUTOPILOT_POLICY WHERE change_type = ?", [change_type])
    if not p or p["MODE"] not in LADDER or LADDER.index(p["MODE"]) == 0:
        return {"demoted": False, "reason": "already at the bottom of the ladder or off"}
    to = LADDER[LADDER.index(p["MODE"]) - 1]
    s.sql(f"""UPDATE {DB}.DETECTIONS.AUTOPILOT_POLICY SET mode = ?, updated_by = 'autopilot:trust_ladder',
              updated_at = CURRENT_TIMESTAMP() WHERE change_type = ?""", params=[to, change_type]).collect()
    record(s, "autonomy_demotion", "applied", f"Demoted {change_type}: {p['MODE']} -> {to}",
           f"Automatic demotion after {reason}. A human can promote it again from Mission Control.",
           {"target_type": change_type, "from": p["MODE"], "to": to, "reason": reason})
    return {"demoted": True, "from": p["MODE"], "to": to}


def main(s, P_ARG):
    arg = json.loads(P_ARG) if P_ARG else {}
    if arg.get("demote"):
        return demote(s, arg["demote"], arg.get("reason", "a failure"))
    rules = {r["FROM_MODE"]: r for r in rows(s, f"SELECT * FROM {DB}.DETECTIONS.TRUST_LADDER_RULES")}
    proposed, demoted, held = [], [], []
    for t in rows(s, f"SELECT * FROM {DB}.DETECTIONS.AUTONOMY_TRACK_RECORD"):
        ct, mode = t["CHANGE_TYPE"], t["MODE"]
        if ct in NEVER or mode not in LADDER:
            continue
        # Demotion: a rollback or canary failure in the last 7 days (at most one demotion per type per week)
        if LADDER.index(mode) > 0 and (int(t["ROLLBACKS_7D"]) > 0 or int(t["CANARY_FAILURES_7D"]) > 0):
            if not one(s, f"""SELECT 1 AS x FROM {CH} WHERE change_type = 'autonomy_demotion'
                              AND evidence:target_type::VARCHAR = ?
                              AND created_at > DATEADD('day', -7, CURRENT_TIMESTAMP())""", [ct]):
                demoted.append({ct: demote(s, ct, f"{t['ROLLBACKS_7D']} rollback(s) / {t['CANARY_FAILURES_7D']} canary failure(s) in 7 days")})
            continue
        rule = rules.get(mode)
        if not rule:
            continue
        to = rule["TO_MODE"]
        if ct in MAX_MODE and LADDER.index(to) > LADDER.index(MAX_MODE[ct]):
            continue
        decided = int(t["APPROVALS"]) + int(t["REJECTIONS"])
        rej_rate = int(t["REJECTIONS"]) / decided if decided else 1.0
        checks = {
            "approvals": (int(t["APPROVALS"]) >= int(rule["MIN_APPROVALS"]), f"{t['APPROVALS']} >= {rule['MIN_APPROVALS']}"),
            "rejection_rate": (rej_rate <= float(rule["MAX_REJECTION_RATE"]), f"{rej_rate:.2f} <= {rule['MAX_REJECTION_RATE']}"),
            "automatic_live": (int(t["AUTOMATIC_LIVE"]) >= int(rule["MIN_AUTOMATIC_LIVE"]),
                               f"{t['AUTOMATIC_LIVE']} >= {rule['MIN_AUTOMATIC_LIVE']}"),
            "no_rollbacks": (int(t["ROLLBACKS"]) == 0, f"{t['ROLLBACKS']} rollbacks"),
        }
        if rule["MIN_CANARY_PASS_RATE"] is not None:
            pr = t["CANARY_PASS_RATE"]
            checks["canary_pass_rate"] = (pr is not None and float(pr) >= float(rule["MIN_CANARY_PASS_RATE"]),
                                          f"{pr} >= {rule['MIN_CANARY_PASS_RATE']}")
        if rule["MIN_PRECISION"] is not None:
            pc = t["PRECISION"]
            checks["precision"] = (pc is not None and float(pc) >= float(rule["MIN_PRECISION"]),
                                   f"{pc} >= {rule['MIN_PRECISION']} ({t['VERDICTS']} verdicts)")
        if not all(ok for ok, _ in checks.values()):
            held.append({"change_type": ct, "mode": mode, "missing": [k for k, (ok, _) in checks.items() if not ok]})
            continue
        if one(s, f"""SELECT 1 AS x FROM {CH} WHERE change_type = 'autonomy_promotion' AND evidence:target_type::VARCHAR = ?
                      AND (status = 'proposed' OR (status = 'rejected' AND updated_at > DATEADD('day', -30, CURRENT_TIMESTAMP())))""",
               [ct]):
            continue
        cid = record(s, "autonomy_promotion", "proposed", f"Promote {ct}: {mode} -> {to}",
                     f"{ct} has earned more autonomy: " + "; ".join(f"{k} {v}" for k, (_, v) in checks.items())
                     + ". Approving changes its policy mode; rolling back restores it. Any rollback or canary failure "
                       "later demotes it automatically.",
                     {"target_type": ct, "from": mode, "to": to, "track_record": t,
                      "checks": {k: v for k, (_, v) in checks.items()}})
        proposed.append({"change_type": ct, "from": mode, "to": to, "change_id": cid})
    return {"proposed": proposed, "demoted": demoted, "held": held}
$$;

CREATE OR REPLACE TASK SNOWFLAKE_XDR.DETECTIONS.TASK_RUN_CANARIES
    WAREHOUSE = XDR_WH
    SCHEDULE = 'USING CRON 15 4 * * * UTC'
    COMMENT = 'Daily detection canaries, then the trust ladder'
AS
EXECUTE IMMEDIATE $$
BEGIN
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CANARIES('all');
    CALL SNOWFLAKE_XDR.DETECTIONS.TRUST_LADDER(NULL);
END;
$$;
