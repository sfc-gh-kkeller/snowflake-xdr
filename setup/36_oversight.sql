-- ============================================================================
-- Snowflake XDR - Mission Control: oversight of an autonomous SOC (Phase 4)
-- ============================================================================
-- One place for a human to see what the AI did, what needs them, and to stop
-- or undo anything:
--
--   V_AI_ACTION_LEDGER   every machine-made change: autopilot and pack changes,
--                        agent tool calls, auto-suppressions, non-human case
--                        events, ticket sync, CIM mappings, response actions,
--                        guardrail changes. Each row says why and how to undo.
--   V_NEEDS_HUMAN        one ranked queue: approvals, spot checks, response
--                        approvals, SLA breaches, failed ticket syncs, failing
--                        canaries, autonomy promotions.
--   SET_AUTONOMY         kill switch and daily change budget (AUTONOMY_SETTINGS,
--                        defined in 26_autopilot.sql so every engine can read it).
--   UNDO_AI_ACTION       one undo entry point for ledger rows.
--   MORNING_BRIEFING     email / webhook: overnight changes, what needs you, exposure.
--
-- Fixed rules (not policy): severity >= 4 changes, built-in rules and response
-- actions always need a human; every automatic change is reversible.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Shared oversight tables (filled by 38_canaries.sql and 39_response.sql)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_AUDIT (
    audit_id    VARCHAR DEFAULT UUID_STRING(),
    at          TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    actor       VARCHAR(255),
    setting     VARCHAR(50),
    old_value   VARIANT,
    new_value   VARIANT,
    reason      VARCHAR(1000)
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.CANARY_RUNS (
    run_id          VARCHAR DEFAULT UUID_STRING(),
    batch_id        VARCHAR,
    rule_id         VARCHAR(100),
    run_at          TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    status          VARCHAR(20),       -- pass | fail | error | no_fixture
    positive_fired  BOOLEAN,
    negative_fired  BOOLEAN,
    latency_seconds NUMBER,
    detail          VARIANT
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS (
    run_id            VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    action_id         VARCHAR(64),
    incident_id       VARCHAR,
    target            VARCHAR(255),
    status            VARCHAR(30),   -- pending_approval | executed | rejected | undone | failed
    reason            VARCHAR(2000),
    requested_by      VARCHAR(255),
    requested_by_type VARCHAR(20),   -- human | agent | autopilot
    decided_by        VARCHAR(255),
    decided_at        TIMESTAMP_LTZ,
    executed_at       TIMESTAMP_LTZ,
    undo_state        VARIANT,       -- exactly what to restore
    result            VARIANT,
    created_at        TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at        TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- 2. The AI action ledger
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DASHBOARDS.V_AI_ACTION_LEDGER AS
-- Autopilot and rule-pack changes
SELECT 'autopilot:' || c.change_id AS ledger_id, c.updated_at AS at, 'autopilot' AS source,
       COALESCE(NULLIF(c.decided_by, ''), 'autopilot') AS actor,
       IFF(c.decided_by IS NULL OR c.decided_by ILIKE 'autopilot%', 'autopilot', 'human') AS actor_type,
       c.change_type AS action, c.title, COALESCE(c.decision_note, c.rationale) AS reason, c.status,
       c.evidence, c.severity,
       CASE WHEN c.status IN ('applied', 'promoted', 'approved') THEN 'rollback'
            WHEN c.status IN ('proposed', 'shadow') THEN 'reject' END AS undo,
       c.change_id AS ref_id, '/autopilot' AS link
FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES c
UNION ALL
-- XDR Analyst agent tool calls
SELECT 'agent:' || a.action_id, a.action_time, 'agent', a.executed_by, 'agent', a.tool,
       a.tool || COALESCE(' on ' || a.target, ''), LEFT(a.result, 1000),
       IFF(a.result ILIKE '%error%', 'failed', 'done'), a.params, NULL, NULL, a.action_id, '/ask'
FROM SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG a
UNION ALL
-- Auto-suppressions by the confidence model, one row per rule per day
SELECT 'suppress:' || f.rule_id || '|' || TO_VARCHAR(DATE(f.triaged_at)), MAX(f.triaged_at), 'confidence',
       'confidence_model', 'autopilot', 'auto_suppress',
       'Auto-suppressed ' || COUNT(*) || ' finding(s) of ' || f.rule_id,
       ANY_VALUE(SPLIT_PART(f.triage_notes, 'Auto-suppressed: ', 2)), 'applied',
       OBJECT_CONSTRUCT('findings', COUNT(*), 'entities', ARRAY_AGG(DISTINCT COALESCE(f.user_name, f.src, f.dest))),
       MAX(f.severity), 'reopen', f.rule_id || '|' || TO_VARCHAR(DATE(f.triaged_at)), '/intel'
FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
WHERE f.disposition_source = 'confidence_model' AND f.triaged_at IS NOT NULL
GROUP BY f.rule_id, DATE(f.triaged_at)
UNION ALL
-- Case changes made by the agent, autopilot, ticket systems or the platform
SELECT 'case:' || e.event_id, e.event_time, 'case', e.actor, e.actor_type, e.event_type,
       e.event_type || ': ' || COALESCE(i.title, e.incident_id) ||
           COALESCE(' (' || e.from_value || ' -> ' || e.to_value || ')', ''),
       e.detail:reason::VARCHAR, 'done', e.detail, i.severity, NULL, e.incident_id,
       '/cases?id=' || e.incident_id
FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS e
LEFT JOIN SNOWFLAKE_XDR.INCIDENTS.INCIDENTS i ON i.incident_id = e.incident_id
WHERE COALESCE(e.actor_type, 'system') <> 'human'
UNION ALL
-- Ticket sync operations
SELECT 'ticket:' || o.op_id, COALESCE(o.done_at, o.created_at), 'ticketing', 'ticket sync', 'system',
       'ticket_' || o.op, o.op || ' on ' || o.connection_id, o.last_error, o.status, o.payload, NULL,
       IFF(o.status = 'failed', 'retry', NULL), o.op_id, '/cases?id=' || o.incident_id
FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_OUTBOX o
UNION ALL
-- CIM mappings (parsers) written by the autopilot or a person
SELECT 'mapping:' || m.mapping_id, m.updated_at, 'parser', m.created_by,
       IFF(m.created_by ILIKE '%autopilot%', 'autopilot', IFF(m.created_by = 'setup', 'system', 'human')),
       'cim_mapping', m.source_id || ' -> ' || m.target_table || ' v' || m.version,
       m.last_error, m.status, m.validation, NULL,
       IFF(m.status = 'live', 'retire', NULL), m.mapping_id, '/sources'
FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS m
UNION ALL
-- Response actions
SELECT 'response:' || r.run_id, r.updated_at, 'response', COALESCE(r.decided_by, r.requested_by),
       IFF(r.decided_by IS NOT NULL, 'human', r.requested_by_type), r.action_id,
       r.action_id || ' on ' || r.target, r.reason, r.status, r.result, 5,
       IFF(r.status = 'executed', 'undo_response', NULL), r.run_id,
       COALESCE('/cases?id=' || r.incident_id, '/mission')
FROM SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS r
UNION ALL
-- Guardrail changes (kill switch, budget)
SELECT 'guardrail:' || g.audit_id, g.at, 'guardrail', g.actor, 'human', 'set_' || g.setting,
       g.setting || ' -> ' || COALESCE(g.new_value::VARCHAR, 'null'), g.reason, 'done',
       OBJECT_CONSTRUCT('old', g.old_value, 'new', g.new_value), NULL, NULL, g.audit_id, '/mission'
FROM SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_AUDIT g;

-- ---------------------------------------------------------------------------
-- 3. Needs a human: one ranked queue
--    score = urgency (kind) + severity x 10 + age bonus (max 20)
-- ---------------------------------------------------------------------------
-- Owned by setup/45_track_record.sql; created here too because the queue reads it
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_REVIEWS (
    review_id VARCHAR DEFAULT UUID_STRING() PRIMARY KEY, change_id VARCHAR, change_type VARCHAR(40),
    title VARCHAR(500), sampled_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(), status VARCHAR(20),
    reviewer VARCHAR(255), note VARCHAR(2000), decided_at TIMESTAMP_LTZ);

CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DASHBOARDS.V_NEEDS_HUMAN AS
WITH items AS (
    SELECT 'change:' || c.change_id AS item_id, IFF(c.change_type = 'autonomy_promotion', 'autonomy_promotion',
               IFF(c.change_type = 'new_parser', 'parser_approval', 'change_approval')) AS kind,
           c.title, c.rationale AS detail, COALESCE(c.severity, 3) AS severity, c.created_at,
           40 AS urgency, c.change_id AS ref_id, ARRAY_CONSTRUCT('approve', 'reject') AS actions,
           IFF(c.change_type = 'new_parser', '/sources', '/autopilot') AS link, c.change_type AS sub_kind
    FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES c
    WHERE c.status = 'proposed'
    UNION ALL
    SELECT 'review:' || q.review_id, 'spot_check',
           'Spot-check a ' || REPLACE(q.reason, '_', ' ') || ' finding: ' || COALESCE(q.rule_id, '?') ||
               ' on ' || COALESCE(q.entity, '?'),
           'Confidence ' || ROUND(COALESCE(q.conf_score, 0) * 100) || '% (' || COALESCE(q.conf_band, '?') ||
               '), suppressed by ' || COALESCE(q.suppressed_by, '?'),
           COALESCE(f.severity, 2), q.sampled_at, 30, q.review_id,
           ARRAY_CONSTRUCT('true_positive', 'false_positive', 'benign'), '/intel', q.reason
    FROM SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE q
    LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f ON f.finding_id = q.finding_id
    WHERE q.status = 'open'
    UNION ALL
    SELECT 'response:' || r.run_id, 'response_approval', r.action_id || ' on ' || r.target, r.reason, 5,
           r.created_at, 80, r.run_id, ARRAY_CONSTRUCT('approve', 'reject'),
           COALESCE('/cases?id=' || r.incident_id, '/mission'), r.action_id
    FROM SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS r
    WHERE r.status = 'pending_approval'
    UNION ALL
    SELECT 'sla:' || s.incident_id, 'sla_breach',
           s.priority || ' case past its ' || s.next_milestone || ' deadline: ' || COALESCE(s.title, ''),
           'Due ' || TO_VARCHAR(s.next_due_at, 'YYYY-MM-DD HH24:MI') || COALESCE(', assigned to ' || s.assignee, ', unassigned'),
           GREATEST(1, 6 - COALESCE(TRY_TO_NUMBER(SUBSTR(s.priority, 2)), 3)), s.next_due_at, 60, s.incident_id,
           ARRAY_CONSTRUCT('open_case'), '/cases?id=' || s.incident_id, s.next_milestone
    FROM SNOWFLAKE_XDR.INCIDENTS.V_INCIDENT_SLA s
    WHERE s.status <> 'closed' AND (s.ack_breached OR s.contain_breached OR s.resolve_breached)
    UNION ALL
    SELECT 'ticket:' || o.op_id, 'ticket_sync_failed', 'Ticket ' || o.op || ' to ' || o.connection_id || ' failed',
           o.last_error, 2, o.created_at, 25, o.op_id, ARRAY_CONSTRUCT('retry'), '/cases?id=' || o.incident_id,
           o.connection_id
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_OUTBOX o
    WHERE o.status = 'failed'
    UNION ALL
    SELECT 'canary:' || k.rule_id, 'canary_failing', 'Detection ' || k.rule_id || ' failed its canary',
           COALESCE(k.detail:message::VARCHAR, 'positive fixture did not fire'),
           COALESCE(r.severity, 3), k.run_at, 55, k.rule_id, ARRAY_CONSTRUCT('open_rule'), '/mission', k.status
    FROM (SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.CANARY_RUNS
          QUALIFY ROW_NUMBER() OVER (PARTITION BY rule_id ORDER BY run_at DESC) = 1) k
    LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES r ON r.rule_id = k.rule_id
    WHERE k.status IN ('fail', 'error')
    UNION ALL
    -- Weekly random sample of unattended autopilot changes (setup/45_track_record.sql)
    SELECT 'areview:' || v.review_id, 'autonomy_review', 'Would you have made this change? ' || COALESCE(v.title, ''),
           'The autopilot made this ' || REPLACE(v.change_type, '_', ' ') || ' change without a human. '
               || 'Disagreeing costs that change type a rung of autonomy.',
           2, v.sampled_at, 20, v.review_id, ARRAY_CONSTRUCT('agree', 'disagree'), '/autopilot', v.change_type
    FROM SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_REVIEWS v
    WHERE v.status = 'open'
)
SELECT i.*, i.urgency + i.severity * 10
            + LEAST(20, GREATEST(0, DATEDIFF('hour', i.created_at, CURRENT_TIMESTAMP()))) AS score
FROM items i;

-- ---------------------------------------------------------------------------
-- 4. Kill switch and budget
--    P_ARG: {"paused": true, "reason": "...", "daily_change_budget": 40,
--            "type_budget": {"change_type": "new_rule", "budget": 2}, "actor": "..."}
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.SET_AUTONOMY(P_ARG VARCHAR)
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
ACTOR_RE = re.compile(r"^[A-Za-z0-9_.@$-]{1,255}$")


def main(s, P_ARG):
    p = json.loads(P_ARG or "{}")
    user = s.sql("SELECT CURRENT_USER() AS u").collect()[0]["U"]
    actor = f"{p['actor']} (console)" if isinstance(p.get("actor"), str) and ACTOR_RE.match(p["actor"]) else user
    reason = str(p.get("reason") or "")[:1000]
    changed = []

    def put(setting, value):
        old = s.sql(f"SELECT value FROM {DB}.DETECTIONS.AUTONOMY_SETTINGS WHERE setting = ?", params=[setting]).collect()
        s.sql(f"""MERGE INTO {DB}.DETECTIONS.AUTONOMY_SETTINGS t USING (SELECT ? AS k) v ON t.setting = v.k
                  WHEN MATCHED THEN UPDATE SET value = PARSE_JSON(?), updated_by = ?, updated_at = CURRENT_TIMESTAMP()
                  WHEN NOT MATCHED THEN INSERT (setting, value, updated_by) VALUES (v.k, PARSE_JSON(?), ?)""",
              params=[setting, json.dumps(value), actor, json.dumps(value), actor]).collect()
        s.sql(f"""INSERT INTO {DB}.DETECTIONS.AUTONOMY_AUDIT (actor, setting, old_value, new_value, reason)
                  SELECT ?, ?, PARSE_JSON(?), PARSE_JSON(?), ?""",
              params=[actor, setting, json.dumps(old[0]["VALUE"] if old else None, default=str),
                      json.dumps(value), reason]).collect()
        changed.append(setting)

    if "paused" in p:
        put("paused", bool(p["paused"]))
        put("paused_reason", reason if p["paused"] else "")
    if p.get("daily_change_budget") is not None:
        b = int(p["daily_change_budget"])
        if not 0 <= b <= 1000:
            return {"ok": False, "message": "daily_change_budget must be 0-1000"}
        put("daily_change_budget", b)
    tb = p.get("type_budget")
    if isinstance(tb, dict) and tb.get("change_type"):
        b = tb.get("budget")
        if b is None:   # no per-type cap
            n = s.sql(f"UPDATE {DB}.DETECTIONS.AUTOPILOT_POLICY SET daily_budget = NULL, updated_by = ?, "
                      "updated_at = CURRENT_TIMESTAMP() WHERE change_type = ?",
                      params=[actor, tb["change_type"]]).collect()[0][0]
        else:
            n = s.sql(f"UPDATE {DB}.DETECTIONS.AUTOPILOT_POLICY SET daily_budget = ?, updated_by = ?, "
                      "updated_at = CURRENT_TIMESTAMP() WHERE change_type = ?",
                      params=[max(0, int(b)), actor, tb["change_type"]]).collect()[0][0]
        if not n:
            return {"ok": False, "message": f"unknown change type {tb['change_type']}"}
        s.sql(f"""INSERT INTO {DB}.DETECTIONS.AUTONOMY_AUDIT (actor, setting, new_value, reason)
                  SELECT ?, ?, PARSE_JSON(?), ?""",
              params=[actor, "budget:" + tb["change_type"], json.dumps(b), reason]).collect()
        changed.append("budget:" + tb["change_type"])
    if not changed:
        return {"ok": False, "message": "nothing to change"}
    msg = ("Autonomy PAUSED: autopilot, auto-suppression, pack installs, ticket routing and automatic response are stopped"
           if p.get("paused") is True else
           "Autonomy resumed" if p.get("paused") is False else "Guardrails updated: " + ", ".join(changed))
    return {"ok": True, "message": msg}
$$;

CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DASHBOARDS.V_AUTONOMY_STATUS AS
SELECT
    SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_PAUSED() AS paused,
    (SELECT MAX(value::VARCHAR) FROM SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_SETTINGS WHERE setting = 'paused_reason') AS paused_reason,
    (SELECT MAX(updated_by) FROM SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_SETTINGS WHERE setting = 'paused') AS paused_by,
    (SELECT MAX(updated_at) FROM SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_SETTINGS WHERE setting = 'paused') AS paused_changed_at,
    (SELECT MAX(value::NUMBER) FROM SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_SETTINGS WHERE setting = 'daily_change_budget') AS daily_change_budget,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES
      WHERE created_at >= DATEADD('hour', -24, CURRENT_TIMESTAMP())) AS changes_24h,
    (SELECT ARRAY_AGG(OBJECT_CONSTRUCT('change_type', p.change_type, 'mode', p.mode, 'budget', p.daily_budget,
                                       'used_24h', (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES c
                                                    WHERE c.change_type = p.change_type
                                                      AND c.created_at >= DATEADD('hour', -24, CURRENT_TIMESTAMP()))))
       FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_POLICY p) AS per_type;

-- ---------------------------------------------------------------------------
-- 5. One undo entry point for the ledger
--    P_LEDGER_ID: the ledger_id column (source:ref)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.UNDO_AI_ACTION(P_LEDGER_ID VARCHAR, P_REASON VARCHAR, P_ACTOR VARCHAR)
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
ACTOR_RE = re.compile(r"^[A-Za-z0-9_.@$ ()-]{1,255}$")


def val(r):
    v = list(r[0].as_dict().values())[0] if r else None
    return json.loads(v) if isinstance(v, str) and v[:1] in "{[" else v


def main(s, P_LEDGER_ID, P_REASON, P_ACTOR):
    lid = P_LEDGER_ID or ""
    source, _, ref = lid.partition(":")
    actor = P_ACTOR if P_ACTOR and ACTOR_RE.match(P_ACTOR) else s.sql("SELECT CURRENT_USER() AS u").collect()[0]["U"]
    note = json.dumps({"note": (P_REASON or "undone from Mission Control")[:900],
                       "actor": actor if re.match(r"^[A-Za-z0-9_.@$-]{1,255}$", actor) else None})
    row = s.sql(f"SELECT undo, status FROM {DB}.DASHBOARDS.V_AI_ACTION_LEDGER WHERE ledger_id = ?", params=[lid]).collect()
    if not row:
        return {"ok": False, "message": "ledger entry not found"}
    undo = row[0]["UNDO"]
    if not undo:
        return {"ok": False, "message": f"this {source} entry has nothing to undo (status {row[0]['STATUS']})"}
    if source == "autopilot":
        r = val(s.sql(f"CALL {DB}.DETECTIONS.AUTOPILOT(?, ?, ?)", params=[f"decide:{undo}", ref, note]).collect())
        return {"ok": bool(r.get("ok")), "message": r.get("message")}
    if source == "suppress":
        rule_id, _, day = ref.partition("|")
        n = s.sql(f"""UPDATE {DB}.DETECTIONS.DETECTION_FINDINGS
                      SET status = 'new', disposition = NULL, disposition_source = NULL, verdict_by = NULL,
                          triage_notes = COALESCE(triage_notes || ' | ', '') || 'Re-opened by ' || ? || ': ' || ?
                      WHERE disposition_source = 'confidence_model' AND rule_id = ? AND DATE(triaged_at) = ?::DATE""",
                  params=[actor, (P_REASON or "auto-suppression undone")[:300], rule_id, day]).collect()[0][0]
        return {"ok": True, "message": f"re-opened {n} auto-suppressed finding(s) of {rule_id}"}
    if source == "mapping":
        r = val(s.sql(f"CALL {DB}.REFERENCE.RETIRE_CIM_MAPPING(?, TRUE)", params=[ref]).collect())
        return {"ok": bool(r.get("ok", True)), "message": r.get("message", "mapping retired")}
    if source == "ticket":
        s.sql(f"""UPDATE {DB}.INCIDENTS.INCIDENT_OUTBOX SET status = 'pending', next_attempt_at = CURRENT_TIMESTAMP()
                  WHERE op_id = ? AND status = 'failed'""", params=[ref]).collect()
        return {"ok": True, "message": "ticket operation re-queued; it will be retried on the next sync"}
    if source == "response":
        r = val(s.sql(f"CALL {DB}.INCIDENTS.UNDO_ANY_RESPONSE(?, ?)", params=[ref, actor]).collect())
        return {"ok": bool(r.get("ok")), "message": r.get("message")}
    return {"ok": False, "message": f"no undo for {source} entries"}
$$;

-- ---------------------------------------------------------------------------
-- 6. Morning briefing: overnight changes, what needs you, exposure
--    P_TO: email address (NULL = autopilot digest_email or the caller's email)
--    P_SEND: FALSE = preview only
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.MORNING_BRIEFING(P_TO VARCHAR, P_SEND BOOLEAN)
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


def rows(s, sql, params=None):
    return [r.as_dict() for r in s.sql(sql, params=params).collect()]


def main(s, P_TO, P_SEND):
    url = (rows(s, f"SELECT value::VARCHAR AS v FROM {DB}.DETECTIONS.AUTOPILOT_SETTINGS WHERE setting = 'console_url'")
           or [{"V": ""}])[0]["V"] or ""
    link = lambda path: (url.rstrip("/") + path) if url else path
    status = rows(s, f"SELECT * FROM {DB}.DASHBOARDS.V_AUTONOMY_STATUS")[0]
    did = rows(s, f"""SELECT source, action, status, COUNT(*) AS n, ANY_VALUE(title) AS example
                      FROM {DB}.DASHBOARDS.V_AI_ACTION_LEDGER
                      WHERE at >= DATEADD('hour', -24, CURRENT_TIMESTAMP()) AND actor_type <> 'human'
                      GROUP BY 1, 2, 3 ORDER BY n DESC LIMIT 15""")
    needs = rows(s, f"""SELECT kind, title, score, link FROM {DB}.DASHBOARDS.V_NEEDS_HUMAN
                        ORDER BY score DESC LIMIT 10""")
    n_needs = rows(s, f"SELECT COUNT(*) AS n FROM {DB}.DASHBOARDS.V_NEEDS_HUMAN")[0]["N"]
    cases = rows(s, f"""SELECT incident_id, priority, title FROM {DB}.INCIDENTS.INCIDENTS
                        WHERE created_at >= DATEADD('hour', -24, CURRENT_TIMESTAMP()) AND priority IN ('P1', 'P2')
                        ORDER BY priority, created_at DESC LIMIT 5""")
    tc = rows(s, f"""SELECT COUNT(*) AS n, MAX(description) AS example FROM {DB}.DETECTIONS.DETECTION_FINDINGS
                     WHERE detection_source = 'trust_center' AND detection_time >= DATEADD('hour', -24, CURRENT_TIMESTAMP())""")[0]
    try:  # threat exposure, from setup/37_threat_profile.sql when deployed
        exposure = rows(s, f"""SELECT title, detail FROM {DB}.REFERENCE.THREAT_EXPOSURES
                               WHERE created_at >= DATEADD('hour', -24, CURRENT_TIMESTAMP())
                               ORDER BY score DESC LIMIT 5""")
    except Exception:
        exposure = []

    lines = ["XDR morning briefing", ""]
    if status["PAUSED"]:
        lines += [f"AUTONOMY IS PAUSED: {status['PAUSED_REASON'] or 'no reason given'} (by {status['PAUSED_BY']})", ""]
    lines.append(f"Needs you ({n_needs}): {link('/mission')}")
    lines += [f"  - [{x['KIND'].replace('_', ' ')}] {x['TITLE']}" for x in needs] or ["  nothing waiting"]
    lines += ["", "What the AI did in the last 24h:"]
    lines += [f"  - {x['N']} x {x['ACTION']} ({x['STATUS']}), e.g. {x['EXAMPLE']}" for x in did] or ["  no automatic changes"]
    lines += ["", f"Changes used today: {status['CHANGES_24H']} of {status['DAILY_CHANGE_BUDGET']} budget"]
    if cases:
        lines += ["", "New P1/P2 cases:"] + [f"  - {c['PRIORITY']} {c['TITLE']}: {link('/cases?id=' + c['INCIDENT_ID'])}"
                                             for c in cases]
    if tc["N"]:
        lines += ["", f"Trust Center: {tc['N']} new finding(s), e.g. {tc['EXAMPLE']}"]
    if exposure:
        lines += ["", "Exposure news:"] + [f"  - {e['TITLE']}: {e['DETAIL']}" for e in exposure]
    try:  # weekly track record, from setup/45_track_record.sql when deployed
        w = rows(s, f"""SELECT * FROM {DB}.DETECTIONS.V_AUTONOMY_SCORECARD WHERE grain = 'week'
                        ORDER BY period_start DESC LIMIT 1""")[0]
        pct = lambda v: "-" if v is None else f"{float(v) * 100:.0f}%"  # noqa: E731
        lines += ["", f"Track record this week: {w['CHANGES']} changes, {w['WENT_LIVE_UNATTENDED']} live unattended, "
                      f"reversed {pct(w['REVERSAL_RATE'])}, canaries passing {pct(w['CANARY_PASS_RATE'])}, "
                      f"reviewer agreement {pct(w['REVIEWER_AGREEMENT'])}"]
    except Exception:
        pass
    body = "\n".join(lines)
    subject = f"XDR briefing: {n_needs} item(s) need you" + (" - AUTONOMY PAUSED" if status["PAUSED"] else "")

    sent = {}
    if P_SEND:
        to = P_TO or (rows(s, f"""SELECT value::VARCHAR AS v FROM {DB}.DETECTIONS.AUTOPILOT_SETTINGS
                                  WHERE setting = 'digest_email'""") or [{"V": ""}])[0]["V"]
        if not to:
            try:
                d = rows(s, "DESCRIBE USER IDENTIFIER(CURRENT_USER())")
                to = next((str(x.get("value")) for x in d if str(x.get("property", "")).upper() == "EMAIL"), "")
            except Exception:
                to = ""
        try:
            if not to or to == "null":
                raise ValueError("no recipient email")
            s.sql("CALL SYSTEM$SEND_EMAIL('XDR_EMAIL', ?, ?, ?)", params=[to, subject, body]).collect()
            sent["email"] = to
        except Exception as e:
            sent["email"] = "not sent: " + str(e)[:150]
        try:
            s.sql("""CALL SYSTEM$SEND_SNOWFLAKE_NOTIFICATION(
                        SNOWFLAKE.NOTIFICATION.APPLICATION_JSON(?), SNOWFLAKE.NOTIFICATION.INTEGRATION('XDR_WEBHOOK'))""",
                  params=[json.dumps({"source": "XDR morning briefing", "text": body})]).collect()
            sent["webhook"] = "sent"
        except Exception as e:
            sent["webhook"] = "not sent: " + str(e)[:150]
    return {"subject": subject, "body": body, "needs_you": n_needs, "sent": sent}
$$;

CREATE OR REPLACE TASK SNOWFLAKE_XDR.DASHBOARDS.TASK_MORNING_BRIEFING
    WAREHOUSE = XDR_WH
    SCHEDULE = 'USING CRON 0 7 * * * UTC'
    COMMENT = 'Mission Control morning briefing (email + webhook)'
AS
    CALL SNOWFLAKE_XDR.DASHBOARDS.MORNING_BRIEFING(NULL, TRUE);

-- ---------------------------------------------------------------------------
-- 7. Agent tools: what_did_you_do, undo_action, needs_human
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_WHAT_DID_YOU_DO(P_HOURS NUMBER)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    h NUMBER := LEAST(GREATEST(COALESCE(:P_HOURS, 24), 1), 720);
    v_items VARIANT;
    v_counts VARIANT;
    v_status VARIANT;
BEGIN
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('ledger_id', ledger_id, 'at', at, 'source', source, 'actor', actor,
                                      'action', action, 'title', title, 'reason', LEFT(reason, 300), 'status', status,
                                      'undo', undo)) WITHIN GROUP (ORDER BY at DESC)
      INTO :v_items
      FROM (SELECT * FROM SNOWFLAKE_XDR.DASHBOARDS.V_AI_ACTION_LEDGER
            WHERE actor_type <> 'human' AND at >= DATEADD('hour', -:h, CURRENT_TIMESTAMP())
            ORDER BY at DESC LIMIT 40);
    SELECT OBJECT_AGG(source || ':' || action, n::VARIANT) INTO :v_counts
      FROM (SELECT source, action, COUNT(*) AS n FROM SNOWFLAKE_XDR.DASHBOARDS.V_AI_ACTION_LEDGER
            WHERE actor_type <> 'human' AND at >= DATEADD('hour', -:h, CURRENT_TIMESTAMP()) GROUP BY 1, 2);
    SELECT OBJECT_CONSTRUCT(*) INTO :v_status FROM SNOWFLAKE_XDR.DASHBOARDS.V_AUTONOMY_STATUS;
    RETURN OBJECT_CONSTRUCT('hours', :h, 'autonomy', :v_status, 'counts', COALESCE(:v_counts, {}),
                            'recent', COALESCE(:v_items, []),
                            'how_to_undo', 'call undo_action with a ledger_id whose undo is not null');
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_UNDO_ACTION(P_LEDGER_ID VARCHAR, P_REASON VARCHAR)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE r VARIANT;
BEGIN
    CALL SNOWFLAKE_XDR.DASHBOARDS.UNDO_AI_ACTION(:P_LEDGER_ID, COALESCE(:P_REASON, 'undone by the XDR Analyst agent'),
                                                 'xdr_agent') INTO :r;
    INSERT INTO SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (tool, target, params, result)
        SELECT 'undo_action', :P_LEDGER_ID, OBJECT_CONSTRUCT('reason', :P_REASON), LEFT(:r::VARCHAR, 4000);
    RETURN r;
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_NEEDS_HUMAN()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE v VARIANT;
BEGIN
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('kind', kind, 'title', title, 'detail', LEFT(detail, 300), 'score', score,
                                      'link', link)) WITHIN GROUP (ORDER BY score DESC)
      INTO :v FROM (SELECT * FROM SNOWFLAKE_XDR.DASHBOARDS.V_NEEDS_HUMAN ORDER BY score DESC LIMIT 25);
    RETURN OBJECT_CONSTRUCT('items', COALESCE(:v, []),
                            'note', 'Approvals and verdicts are human decisions: point the user to Mission Control.');
END;
$$;
