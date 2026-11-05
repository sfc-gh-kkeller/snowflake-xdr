-- ============================================================================
-- Snowflake XDR - Phase 5.4: multi-connector response (demo mode)
-- ============================================================================
-- Generalises contain_snowflake_user (39_response.sql) to identity and endpoint
-- actions on Okta, Entra ID, CrowdStrike, Defender and SentinelOne, plus an IOC
-- blocklist. Same safety model as Phase 4, enforced here in SQL:
--   * user / host targets must be on RESPONSE_TARGET_ALLOWLIST with the right kind,
--     and never the calling user; IOC targets may not be private, our own, or on a
--     known-good warning list
--   * approval actions run only after a human approves (DECIDE_RESPONSE_ACTION);
--     only low-risk reversible actions (block_ioc) run automatically, and never
--     while the kill switch is on
--   * every executed action stores its exact inverse; UNDO restores it
--
-- Demo mode (the default for every connector): the vendor API request is built for
-- real (method, URL, body, lookup step) and recorded on the run, then its effect is
-- applied to RESPONSE_DEMO_STATE instead of being sent. Live mode needs an external
-- access integration and a secret per connector and is not exercised by this build:
-- EXECUTE_CONNECTOR_ACTION refuses live connectors until that is configured.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Connectors, actions, allowlist kinds, demo state
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.RESPONSE_CONNECTORS (
    connector_id  VARCHAR(40) PRIMARY KEY,
    system        VARCHAR(100),
    mode          VARCHAR(10),       -- demo | live
    api_base      VARCHAR(500),
    integration   VARCHAR(255),      -- external access integration (live mode)
    secret_name   VARCHAR(500),      -- API credential secret (live mode)
    notes         VARCHAR(1000)
);
MERGE INTO SNOWFLAKE_XDR.INCIDENTS.RESPONSE_CONNECTORS t
USING (SELECT * FROM VALUES
    ('okta',        'Okta',                            'demo', 'https://example.okta.com'),
    ('entra',       'Microsoft Entra ID (Graph)',       'demo', 'https://graph.microsoft.com/v1.0'),
    ('crowdstrike', 'CrowdStrike Falcon',               'demo', 'https://api.crowdstrike.com'),
    ('defender',    'Microsoft Defender for Endpoint',  'demo', 'https://api.securitycenter.microsoft.com/api'),
    ('sentinelone', 'SentinelOne',                      'demo', 'https://example.sentinelone.net/web/api/v2.1'),
    ('blocklist',   'XDR IOC blocklist',                'demo', 'snowflake://SNOWFLAKE_XDR.INCIDENTS.RESPONSE_BLOCKLIST')
    AS v(connector_id, system, mode, api_base)) s ON t.connector_id = s.connector_id
WHEN NOT MATCHED THEN INSERT (connector_id, system, mode, api_base, notes)
    VALUES (s.connector_id, s.system, s.mode, s.api_base, 'demo mode: requests are built and logged, not sent');

-- No DEFAULTs: re-running ADD COLUMN ... DEFAULT fails
ALTER TABLE SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTIONS ADD COLUMN IF NOT EXISTS connector_id VARCHAR(40);
ALTER TABLE SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTIONS ADD COLUMN IF NOT EXISTS target_kind VARCHAR(20);
ALTER TABLE SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTIONS ADD COLUMN IF NOT EXISTS risk_level VARCHAR(10);
ALTER TABLE SNOWFLAKE_XDR.INCIDENTS.RESPONSE_TARGET_ALLOWLIST ADD COLUMN IF NOT EXISTS target_kind VARCHAR(20);
UPDATE SNOWFLAKE_XDR.INCIDENTS.RESPONSE_TARGET_ALLOWLIST SET target_kind = 'snowflake_user' WHERE target_kind IS NULL;

MERGE INTO SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTIONS t
USING (SELECT * FROM VALUES
    ('okta_suspend_user',        'Suspend Okta user',                 'approval',  TRUE,  'okta',        'user', 'high',
     'Suspends the Okta user (all apps). Undo unsuspends.'),
    ('okta_clear_sessions',      'Clear Okta sessions',               'approval',  FALSE, 'okta',        'user', 'low',
     'Ends every Okta session and refresh token, forcing a new sign-in. Cannot be undone (the user simply signs in again).'),
    ('entra_disable_user',       'Disable Entra ID user',             'approval',  TRUE,  'entra',       'user', 'high',
     'Sets accountEnabled = false. Undo re-enables.'),
    ('entra_revoke_sessions',    'Revoke Entra ID sessions',          'approval',  FALSE, 'entra',       'user', 'low',
     'revokeSignInSessions: invalidates refresh tokens. Cannot be undone.'),
    ('crowdstrike_contain_host', 'Network-contain host (CrowdStrike)', 'approval', TRUE,  'crowdstrike', 'host', 'high',
     'Falcon network containment: the host only talks to the Falcon cloud. Undo lifts containment.'),
    ('defender_isolate_host',    'Isolate host (Defender)',           'approval',  TRUE,  'defender',    'host', 'high',
     'Defender full isolation. Undo releases it.'),
    ('sentinelone_isolate_host', 'Disconnect host from network (SentinelOne)', 'approval', TRUE, 'sentinelone', 'host', 'high',
     'SentinelOne network quarantine. Undo reconnects.'),
    ('block_ioc',                'Block indicator',                   'automatic', TRUE,  'blocklist',   'ioc',  'low',
     'Adds an attacker IP, domain or hash to the XDR blocklist (and, in live mode, to each EDR''s custom IOCs). Undo removes it.')
    AS v(action_id, name, autonomy, reversible, connector_id, target_kind, risk_level, description)) s
ON t.action_id = s.action_id
WHEN MATCHED THEN UPDATE SET name = s.name, autonomy = s.autonomy, reversible = s.reversible, description = s.description,
     connector_id = s.connector_id, target_kind = s.target_kind, risk_level = s.risk_level
WHEN NOT MATCHED THEN INSERT (action_id, name, autonomy, reversible, description, connector_id, target_kind, risk_level)
     VALUES (s.action_id, s.name, s.autonomy, s.reversible, s.description, s.connector_id, s.target_kind, s.risk_level);
UPDATE SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTIONS SET target_kind = 'snowflake_user', risk_level = 'high'
WHERE action_id = 'contain_snowflake_user' AND target_kind IS NULL;

-- Demo targets: one identity, one host (the only allowed targets until a human adds more)
MERGE INTO SNOWFLAKE_XDR.INCIDENTS.RESPONSE_TARGET_ALLOWLIST t
USING (SELECT * FROM VALUES
    ('DEMO.COMPROMISED@CONTOSO.COM', 'user', 'demo identity for Okta / Entra response'),
    ('WS-DEMO-01',                   'host', 'demo endpoint for EDR isolation')
    AS v(u, k, r)) s ON t.user_name = s.u
WHEN NOT MATCHED THEN INSERT (user_name, target_kind, reason) VALUES (s.u, s.k, s.r);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.RESPONSE_DEMO_STATE (
    system      VARCHAR(40),
    target      VARCHAR(500),
    state       VARIANT,           -- e.g. {"status": "SUSPENDED"} or {"containment": "contained"}
    updated_at  TIMESTAMP_LTZ,
    updated_by  VARCHAR(255)
);
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.RESPONSE_BLOCKLIST (
    ioc         VARCHAR(500),
    ioc_type    VARCHAR(20),       -- ip | domain | hash
    run_id      VARCHAR,
    active      BOOLEAN,
    added_at    TIMESTAMP_LTZ,
    removed_at  TIMESTAMP_LTZ
);

-- ---------------------------------------------------------------------------
-- 2. Executor and undo (owner's rights)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.EXECUTE_CONNECTOR_ACTION(P_RUN_ID VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS OWNER
AS
$$
import ipaddress
import json
import re
from urllib.parse import quote

DB = "SNOWFLAKE_XDR"
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
USER_RE = re.compile(r"^[A-Za-z0-9._%+'-]{1,128}@[A-Za-z0-9.-]{1,253}$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
HASH_RE = re.compile(r"^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")


def one(s, sql, params=None):
    r = s.sql(sql, params=params).collect()
    return r[0].as_dict() if r else None


def fail(s, run_id, msg):
    s.sql(f"""UPDATE {DB}.INCIDENTS.RESPONSE_ACTION_RUNS SET status = 'failed', result = OBJECT_CONSTRUCT('error', ?),
              updated_at = CURRENT_TIMESTAMP() WHERE run_id = ? AND status = 'approved'""", params=[msg, run_id]).collect()
    return {"ok": False, "message": "refused: " + msg}


def ioc_kind(v):
    v = v.strip().lower()
    try:
        ip = ipaddress.ip_address(v)
        return "ip" if ip.is_global else None          # never block private, loopback or reserved ranges
    except ValueError:
        pass
    if HASH_RE.match(v):
        return "hash"
    if DOMAIN_RE.match(v):
        return "domain"
    return None


def requests_for(action, target, base):
    """(do, undo) vendor API requests. Host actions resolve the device id first, as the real APIs require."""
    t = quote(target, safe="@.")
    host_q = quote(target)
    return {
        "okta_suspend_user": ([{"method": "POST", "url": f"{base}/api/v1/users/{t}/lifecycle/suspend"}],
                              [{"method": "POST", "url": f"{base}/api/v1/users/{t}/lifecycle/unsuspend"}]),
        "okta_clear_sessions": ([{"method": "DELETE", "url": f"{base}/api/v1/users/{t}/sessions?oauthTokens=true"}], None),
        "entra_disable_user": ([{"method": "PATCH", "url": f"{base}/users/{t}", "body": {"accountEnabled": False}}],
                               [{"method": "PATCH", "url": f"{base}/users/{t}", "body": {"accountEnabled": True}}]),
        "entra_revoke_sessions": ([{"method": "POST", "url": f"{base}/users/{t}/revokeSignInSessions"}], None),
        "crowdstrike_contain_host": (
            [{"method": "GET", "url": f"{base}/devices/queries/devices/v1?filter=hostname:'{host_q}'", "as": "device_id"},
             {"method": "POST", "url": f"{base}/devices/entities/devices-actions/v2?action_name=contain",
              "body": {"ids": ["${device_id}"]}}],
            [{"method": "POST", "url": f"{base}/devices/entities/devices-actions/v2?action_name=lift_containment",
              "body": {"ids": ["${device_id}"]}}]),
        "defender_isolate_host": (
            [{"method": "GET", "url": f"{base}/machines?$filter=computerDnsName eq '{host_q}'", "as": "machine_id"},
             {"method": "POST", "url": f"{base}/machines/${{machine_id}}/isolate",
              "body": {"Comment": "XDR approved isolation", "IsolationType": "Full"}}],
            [{"method": "POST", "url": f"{base}/machines/${{machine_id}}/unisolate",
              "body": {"Comment": "XDR undo"}}]),
        "sentinelone_isolate_host": (
            [{"method": "POST", "url": f"{base}/agents/actions/disconnect", "body": {"filter": {"computerName": target}}}],
            [{"method": "POST", "url": f"{base}/agents/actions/connect", "body": {"filter": {"computerName": target}}}]),
        "block_ioc": ([{"method": "INSERT", "url": base, "body": {"ioc": target}}],
                      [{"method": "UPDATE", "url": base, "body": {"ioc": target, "active": False}}]),
    }[action]


DEMO_EFFECT = {
    "okta_suspend_user": {"status": "SUSPENDED"}, "okta_clear_sessions": {"sessions": "cleared"},
    "entra_disable_user": {"accountEnabled": False}, "entra_revoke_sessions": {"sessions": "revoked"},
    "crowdstrike_contain_host": {"containment": "contained"}, "defender_isolate_host": {"isolation": "Full"},
    "sentinelone_isolate_host": {"network": "disconnected"},
}


def main(s, P_RUN_ID):
    run = one(s, f"""SELECT r.*, a.connector_id, a.target_kind, a.reversible, c.mode, c.api_base, c.system
                     FROM {DB}.INCIDENTS.RESPONSE_ACTION_RUNS r
                     JOIN {DB}.INCIDENTS.RESPONSE_ACTIONS a ON a.action_id = r.action_id
                     JOIN {DB}.INCIDENTS.RESPONSE_CONNECTORS c ON c.connector_id = a.connector_id
                     WHERE r.run_id = ?""", [P_RUN_ID or ""])
    if not run:
        return {"ok": False, "message": "refused: no connector run with this id"}
    if run["STATUS"] != "approved":
        return {"ok": False, "message": f"refused: run is {run['STATUS']}, it must be approved first"}
    action, kind, target = run["ACTION_ID"], run["TARGET_KIND"], (run["TARGET"] or "").strip()
    caller = one(s, "SELECT CURRENT_USER() AS u")["U"]
    if kind in ("user", "host"):
        ok = HOST_RE.match(target) if kind == "host" else USER_RE.match(target)
        if not ok:
            return fail(s, P_RUN_ID, f"invalid {kind} name")
        if not one(s, f"""SELECT 1 AS x FROM {DB}.INCIDENTS.RESPONSE_TARGET_ALLOWLIST
                          WHERE UPPER(user_name) = UPPER(?) AND target_kind = ?""", [target, kind]):
            return fail(s, P_RUN_ID, f"{target} is not an allowlisted {kind} target")
        if target.split("@")[0].upper() == caller.upper():
            return fail(s, P_RUN_ID, "cannot act on the calling user")
    elif kind == "ioc":
        ioc_type = ioc_kind(target)
        if not ioc_type:
            return fail(s, P_RUN_ID, "not a public IP, domain or hash")
        if one(s, f"""SELECT 1 AS x FROM {DB}.REFERENCE.INTEL_WARNINGLIST
                      WHERE LOWER(value) = LOWER(?) OR (? LIKE ('%.' || LOWER(value)))""", [target, target.lower()]):
            return fail(s, P_RUN_ID, f"{target} is on a known-good warning list")
    else:
        return fail(s, P_RUN_ID, f"unsupported target kind {kind}")
    if run["MODE"] != "demo":
        return fail(s, P_RUN_ID, f"{run['SYSTEM']} is in {run['MODE']} mode, which needs an external access integration "
                                 "and a credential secret configured for this connector")
    do, undo = requests_for(action, target, run["API_BASE"])
    prev = one(s, f"SELECT state FROM {DB}.INCIDENTS.RESPONSE_DEMO_STATE WHERE system = ? AND UPPER(target) = UPPER(?)",
               [run["CONNECTOR_ID"], target])
    if action == "block_ioc":
        s.sql(f"""INSERT INTO {DB}.INCIDENTS.RESPONSE_BLOCKLIST (ioc, ioc_type, run_id, active, added_at)
                  SELECT LOWER(?), ?, ?, TRUE, CURRENT_TIMESTAMP()""", params=[target, ioc_type, P_RUN_ID]).collect()
        effect = {"blocked": True}
    else:
        effect = DEMO_EFFECT[action]
        s.sql(f"DELETE FROM {DB}.INCIDENTS.RESPONSE_DEMO_STATE WHERE system = ? AND UPPER(target) = UPPER(?)",
              params=[run["CONNECTOR_ID"], target]).collect()
        merged = {**(json.loads(prev["STATE"]) if prev and prev["STATE"] else {}), **effect}
        s.sql(f"""INSERT INTO {DB}.INCIDENTS.RESPONSE_DEMO_STATE (system, target, state, updated_at, updated_by)
                  SELECT ?, ?, PARSE_JSON(?), CURRENT_TIMESTAMP(), ?""",
              params=[run["CONNECTOR_ID"], target, json.dumps(merged), caller]).collect()
    undo_state = {"connector": run["CONNECTOR_ID"], "target": target, "requests": undo,
                  "previous_state": json.loads(prev["STATE"]) if prev and prev["STATE"] else None}
    result = {"mode": "demo", "system": run["SYSTEM"], "requests_built": do, "effect": effect,
              "note": "demo mode: the request was built and logged, not sent"}
    s.sql(f"""UPDATE {DB}.INCIDENTS.RESPONSE_ACTION_RUNS SET status = 'executed', executed_at = CURRENT_TIMESTAMP(),
                undo_state = PARSE_JSON(?), result = PARSE_JSON(?), updated_at = CURRENT_TIMESTAMP() WHERE run_id = ?""",
          params=[json.dumps(undo_state if run["REVERSIBLE"] else None), json.dumps(result), P_RUN_ID]).collect()
    return {"ok": True, "message": f"{action} on {target}: done ({run['SYSTEM']}, demo mode)", **result}
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.UNDO_CONNECTOR_ACTION(P_RUN_ID VARCHAR, P_ACTOR VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS OWNER
AS
$$
import json

DB = "SNOWFLAKE_XDR"


def one(s, sql, params=None):
    r = s.sql(sql, params=params).collect()
    return r[0].as_dict() if r else None


def main(s, P_RUN_ID, P_ACTOR):
    run = one(s, f"""SELECT r.*, a.reversible FROM {DB}.INCIDENTS.RESPONSE_ACTION_RUNS r
                     JOIN {DB}.INCIDENTS.RESPONSE_ACTIONS a ON a.action_id = r.action_id WHERE r.run_id = ?""",
              [P_RUN_ID or ""])
    if not run:
        return {"ok": False, "message": "response run not found"}
    if run["STATUS"] != "executed":
        return {"ok": False, "message": f"nothing to undo (status {run['STATUS']})"}
    if not run["REVERSIBLE"] or not run["UNDO_STATE"]:
        return {"ok": False, "message": f"{run['ACTION_ID']} cannot be undone: the user signs in again to get new sessions"}
    st = json.loads(run["UNDO_STATE"])
    who = P_ACTOR or one(s, "SELECT CURRENT_USER() AS u")["U"]
    if run["ACTION_ID"] == "block_ioc":
        s.sql(f"""UPDATE {DB}.INCIDENTS.RESPONSE_BLOCKLIST SET active = FALSE, removed_at = CURRENT_TIMESTAMP()
                  WHERE run_id = ?""", params=[P_RUN_ID]).collect()
    else:
        s.sql(f"DELETE FROM {DB}.INCIDENTS.RESPONSE_DEMO_STATE WHERE system = ? AND UPPER(target) = UPPER(?)",
              params=[st["connector"], st["target"]]).collect()
        if st.get("previous_state"):
            s.sql(f"""INSERT INTO {DB}.INCIDENTS.RESPONSE_DEMO_STATE (system, target, state, updated_at, updated_by)
                      SELECT ?, ?, PARSE_JSON(?), CURRENT_TIMESTAMP(), ?""",
                  params=[st["connector"], st["target"], json.dumps(st["previous_state"]), who]).collect()
    s.sql(f"""UPDATE {DB}.INCIDENTS.RESPONSE_ACTION_RUNS SET status = 'undone',
                result = OBJECT_INSERT(COALESCE(result, OBJECT_CONSTRUCT()), 'undone',
                         OBJECT_CONSTRUCT('by', ?, 'requests_built', PARSE_JSON(?), 'at', CURRENT_TIMESTAMP()::VARCHAR), TRUE),
                updated_at = CURRENT_TIMESTAMP() WHERE run_id = ?""",
          params=[who, json.dumps(st.get("requests")), P_RUN_ID]).collect()
    if run["INCIDENT_ID"]:
        s.sql(f"""INSERT INTO {DB}.INCIDENTS.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, detail, source_system)
                  SELECT ?, 'response_undone', ?, 'human', ?, OBJECT_CONSTRUCT('target', ?), 'xdr'""",
              params=[run["INCIDENT_ID"], who, run["ACTION_ID"], st["target"]]).collect()
    return {"ok": True, "message": f"undid {run['ACTION_ID']} on {st['target']} (demo mode)"}
$$;

-- ---------------------------------------------------------------------------
-- 3. Routing: request / decide / undo dispatch to the right executor
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
    v_connector VARCHAR;
    v_run VARCHAR := UUID_STRING();
    v_type VARCHAR := IFF(LOWER(:P_TYPE) IN ('human', 'agent', 'autopilot'), LOWER(:P_TYPE), 'agent');
    v_open NUMBER;
    r VARIANT;
BEGIN
    SELECT MAX(autonomy), MAX(connector_id) INTO :v_autonomy, :v_connector
    FROM SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTIONS WHERE action_id = :P_ACTION;
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
            CASE :v_autonomy WHEN 'approval' THEN 'pending_approval' WHEN 'recommendation' THEN 'recommended'
                             ELSE IFF(:v_connector IS NOT NULL, 'approved', 'executed') END,
            LEFT(:P_REASON, 2000), COALESCE(:P_REQUESTED_BY, CURRENT_USER()), :v_type);
    IF (NULLIF(:P_INCIDENT_ID, '') IS NOT NULL) THEN
        INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, detail, source_system)
        SELECT :P_INCIDENT_ID, 'response_requested', COALESCE(:P_REQUESTED_BY, CURRENT_USER()), :v_type, :P_ACTION,
               OBJECT_CONSTRUCT('target', :P_TARGET, 'run_id', :v_run, 'autonomy', :v_autonomy, 'reason', LEFT(:P_REASON, 500)), 'xdr';
    END IF;
    -- Automatic connector actions (low risk, reversible) execute now, through the same guarded executor
    IF (v_autonomy = 'automatic' AND v_connector IS NOT NULL) THEN
        UPDATE SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS SET decided_by = 'policy:automatic', decided_at = CURRENT_TIMESTAMP()
        WHERE run_id = :v_run;
        CALL SNOWFLAKE_XDR.INCIDENTS.EXECUTE_CONNECTOR_ACTION(:v_run) INTO :r;
        RETURN OBJECT_INSERT(r, 'run_id', :v_run, TRUE);
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
    v_connector VARCHAR;
    v_who VARCHAR := COALESCE(:P_ACTOR || ' (console)', CURRENT_USER());
    r VARIANT;
    v_set VARIANT;
BEGIN
    SELECT MAX(r.status), MAX(r.action_id), MAX(r.target), MAX(r.incident_id), MAX(a.connector_id)
      INTO :v_status, :v_action, :v_target, :v_incident, :v_connector
    FROM SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS r
    LEFT JOIN SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTIONS a ON a.action_id = r.action_id
    WHERE r.run_id = :P_RUN_ID;
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
        ELSEIF (v_connector IS NOT NULL) THEN
            CALL SNOWFLAKE_XDR.INCIDENTS.EXECUTE_CONNECTOR_ACTION(:P_RUN_ID) INTO :r;
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
            CALL SNOWFLAKE_XDR.INCIDENTS.SET_INCIDENT_STATE(:v_incident, 'contained', :v_action || ' executed: ' || :v_target,
                                                           :v_who, 'human', NULL, NULL) INTO :v_set;
        END IF;
    END IF;
    RETURN r;
END;
$$;

-- Undo entry point used by Mission Control and the agent: Snowflake roles or connector actions
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.UNDO_ANY_RESPONSE(P_RUN_ID VARCHAR, P_ACTOR VARCHAR)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_action VARCHAR;
    r VARIANT;
BEGIN
    SELECT MAX(action_id) INTO :v_action FROM SNOWFLAKE_XDR.INCIDENTS.RESPONSE_ACTION_RUNS WHERE run_id = :P_RUN_ID;
    IF (v_action = 'contain_snowflake_user') THEN
        CALL SNOWFLAKE_XDR.INCIDENTS.UNDO_RESPONSE_ACTION(:P_RUN_ID, :P_ACTOR) INTO :r;
    ELSE
        CALL SNOWFLAKE_XDR.INCIDENTS.UNDO_CONNECTOR_ACTION(:P_RUN_ID, :P_ACTOR) INTO :r;
    END IF;
    RETURN r;
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. Playbook: which action fits an entity (used by auto-investigation)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.INCIDENTS.V_RESPONSE_OPTIONS AS
WITH host_edr AS (
    SELECT UPPER(dest) AS target, vendor_product FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE _time > DATEADD('day', -7, CURRENT_TIMESTAMP()) AND dest IS NOT NULL GROUP BY 1, 2
),
user_idp AS (
    SELECT UPPER(user_name) AS target, vendor_product FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE _time > DATEADD('day', -7, CURRENT_TIMESTAMP()) AND vendor_product IN ('Okta', 'Entra ID') GROUP BY 1, 2
)
SELECT a.user_name AS target, a.target_kind,
       CASE a.target_kind WHEN 'snowflake_user' THEN 'contain_snowflake_user'
            WHEN 'host' THEN DECODE(h.vendor_product, 'CrowdStrike Falcon', 'crowdstrike_contain_host',
                                    'Microsoft Defender for Endpoint', 'defender_isolate_host',
                                    'SentinelOne', 'sentinelone_isolate_host', NULL)
            WHEN 'user' THEN DECODE(u.vendor_product, 'Okta', 'okta_suspend_user', 'Entra ID', 'entra_disable_user',
                                    'okta_suspend_user') END AS action_id,
       COALESCE(h.vendor_product, u.vendor_product) AS seen_in
FROM SNOWFLAKE_XDR.INCIDENTS.RESPONSE_TARGET_ALLOWLIST a
LEFT JOIN host_edr h ON a.target_kind = 'host' AND h.target = UPPER(a.user_name)
LEFT JOIN user_idp u ON a.target_kind = 'user' AND u.target IN (UPPER(a.user_name), UPPER(SPLIT_PART(a.user_name, '@', 1)));

-- ---------------------------------------------------------------------------
-- 5. EDR demo story: a credential-theft chain on WS-DEMO-01 through the real
--    CrowdStrike ingest path, detected by the CrowdStrike pack, correlated into a case
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.SEED_EDR_DEMO()
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS CALLER
AS
$$
import json
import time

DB = "SNOWFLAKE_XDR"
HOST, USER = "WS-DEMO-01", "demo.compromised"


def one(s, sql, params=None):
    r = s.sql(sql, params=params).collect()
    return r[0].as_dict() if r else None


def main(s):
    now = int(time.time() * 1000)
    base = {"ComputerName": HOST, "UserName": USER, "event_platform": "Win", "aid": "demo-aid"}
    events = [
        {**base, "event_simpleName": "ProcessRollup2", "timestamp": str(now - 900000),
         "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami /all",
         "ParentBaseFileName": "WINWORD.EXE", "TargetProcessId": "5100"},
        {**base, "event_simpleName": "ProcessRollup2", "timestamp": str(now - 600000),
         "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\rundll32.exe",
         "CommandLine": "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Users\\Public\\l.dmp full",
         "ParentBaseFileName": "cmd.exe", "TargetProcessId": "5200"},
        {**base, "event_simpleName": "NetworkConnectIP4", "timestamp": str(now - 300000), "LocalAddressIP4": "10.0.0.31",
         "LocalPort": "50777", "RemoteAddressIP4": "203.0.113.66", "RemotePort": "4444", "Protocol": "6",
         "ContextBaseFileName": "rundll32.exe"},
        {"metadata": {"eventType": "DetectionSummaryEvent", "eventCreationTime": now - 590000},
         "event": {"ComputerName": HOST, "UserName": USER, "Severity": 5, "DetectName": "CredentialDumping",
                   "Description": "LSASS memory dumped with comsvcs.dll", "Tactic": "Credential Access",
                   "Technique": "OS Credential Dumping", "LocalIP": "10.0.0.31"}},
    ]
    recs = [{"timeUnixNano": str(now * 1000000 + i), "severityText": "INFO", "body": {"stringValue": json.dumps(e)}}
            for i, e in enumerate(events)]
    payload = {"resourceLogs": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "crowdstrike"}}]},
                                 "scopeLogs": [{"scope": {"name": "xdr-demo"}, "logRecords": recs}]}]}
    ingest = one(s, f"CALL {DB}.RAW_LOGS.INGEST_OTLP_LOGS(?, NULL)", [json.dumps(payload)])
    s.sql(f"CALL {DB}.REFERENCE.APPLY_CIM_MAPPINGS()").collect()
    # Shadow rules would only write shadow findings; evaluate this story's rules straight into findings
    rules = ["CS-001", "CS-002", "CS-004", "CS-007"]
    keep = {r["RULE_ID"]: r["TEST_MODE"] for r in
            [x.as_dict() for x in s.sql(f"SELECT rule_id, test_mode FROM {DB}.DETECTIONS.CUSTOM_RULES "
                                        f"WHERE rule_id IN ({','.join(['?'] * len(rules))})", params=rules).collect()]}
    try:
        for r in keep:
            s.sql(f"UPDATE {DB}.DETECTIONS.CUSTOM_RULES SET test_mode = FALSE WHERE rule_id = ?", params=[r]).collect()
            s.sql(f"CALL {DB}.DETECTIONS.RUN_CUSTOM_RULE_SQL(?, FALSE)", params=[r]).collect()
    finally:
        for r, tm in keep.items():
            s.sql(f"UPDATE {DB}.DETECTIONS.CUSTOM_RULES SET test_mode = ? WHERE rule_id = ?", params=[tm, r]).collect()
    s.sql(f"CALL {DB}.INCIDENTS.CORRELATE_INCIDENTS()").collect()
    case = one(s, f"""SELECT incident_id, priority, title FROM {DB}.INCIDENTS.INCIDENTS
                      WHERE status <> 'closed' AND (UPPER(primary_entity) IN (?, ?) OR title ILIKE ? OR title ILIKE ?)
                      ORDER BY created_at DESC LIMIT 1""", [HOST, USER.upper(), f"%{HOST}%", f"%{USER}%"])
    return {"ok": True, "ingest": list(ingest.values())[0] if ingest else None, "rules": list(keep), "case": case,
            "next": "CALL SNOWFLAKE_XDR.INCIDENTS.AUTO_INVESTIGATE('<incident_id>')"}
$$;
