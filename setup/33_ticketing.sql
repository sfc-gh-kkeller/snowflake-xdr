-- ============================================================================
-- Snowflake XDR - 33: Ticketing integration (phase 3, part 2)
-- ============================================================================
-- Incidents become Jira / ServiceNow tickets and stay in sync both ways.
--
--   ROUTE   incidents matching a connection's rule get a ticket (idempotent: an
--           existing ticket with the XDR reference is adopted, never duplicated)
--   PUSH    INCIDENT_OUTBOX ops (create, comment, transition, attach_report) are
--           sent with retries and backoff; failures are visible, never dropped
--   POLL    remote changes (state, assignee, comments) land in TICKET_INBOX
--   APPLY   inbox rows go through SET_INCIDENT_STATE / ASSIGN_INCIDENT /
--           ADD_INCIDENT_COMMENT with actor_type 'ticket', so they are recorded
--           in INCIDENT_EVENTS and not echoed back to the ticket
--
-- Connectors: jira (Cloud REST v3), servicenow_sir (sn_si_incident),
-- servicenow_itsm (incident), and mock (a ticket system inside Snowflake, so the
-- whole round trip demos without credentials).
--
-- Who owns workflow: once a ticket exists, its state is authoritative and the XDR
-- mirrors it; XDR detection data (findings, entities, evidence) is authoritative
-- and is pushed to the ticket. By default only summaries and console links leave
-- Snowflake (config include_raw_evidence = false).
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Connections and inbox
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS (
    connection_id   VARCHAR(64) PRIMARY KEY,
    system          VARCHAR(30),      -- mock | jira | servicenow_sir | servicenow_itsm
    name            VARCHAR(200),
    base_url        VARCHAR(500),     -- https://acme.atlassian.net, https://acme.service-now.com
    enabled         BOOLEAN DEFAULT TRUE,
    auto_create     BOOLEAN DEFAULT TRUE,
    min_priority    VARCHAR(5) DEFAULT 'P2',   -- auto-create for this priority and more urgent
    config          VARIANT,          -- project_key, issue_type, assignment_group, priority_map, state maps, ...
    last_poll_at    TIMESTAMP_LTZ,
    last_poll_status VARCHAR(2000),
    created_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.TICKET_INBOX (
    inbox_id        VARCHAR DEFAULT UUID_STRING(),
    connection_id   VARCHAR(64),
    external_key    VARCHAR(100),
    kind            VARCHAR(20),      -- state | assignee | comment
    value           VARCHAR(8000),
    remote_actor    VARCHAR(255),
    remote_time     TIMESTAMP_LTZ,
    dedupe_key      VARCHAR(300),
    via             VARCHAR(20),      -- poll | webhook
    received_at     TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    status          VARCHAR(20) DEFAULT 'pending',   -- pending | applied | ignored | error
    result          VARCHAR(2000)
);

-- Mock ticket system: behaves like a remote tracker (own keys, own states, own comments)
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.MOCK_TICKETS (
    ticket_key      VARCHAR(30) PRIMARY KEY,
    xdr_reference   VARCHAR(100),
    summary         VARCHAR(500),
    description     VARCHAR,
    priority        VARCHAR(30),
    state           VARCHAR(50),
    assignee        VARCHAR(255),
    labels          ARRAY,
    comments        ARRAY,            -- [{author, body, created}]
    attachments     ARRAY,
    created_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_by      VARCHAR(255)
);
CREATE SEQUENCE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.MOCK_TICKET_SEQ START = 101;

-- Default connections: the mock is enabled; Jira / ServiceNow are templates, disabled until configured
MERGE INTO SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS t
USING (
    SELECT 'mock' AS connection_id, 'mock' AS system, 'Demo tracker (Jira-style, inside Snowflake)' AS name,
           NULL AS base_url, TRUE AS enabled, PARSE_JSON('{
             "project_key": "SEC",
             "priority_map": {"P1": "Highest", "P2": "High", "P3": "Medium", "P4": "Low", "P5": "Lowest"},
             "state_out": {"acknowledged": "In Progress", "investigating": "In Progress", "contained": "Contained",
                           "eradicated": "Contained", "recovered": "Contained", "closed": "Done", "open": "To Do"},
             "state_in": {"to do": "open", "in progress": "investigating", "contained": "contained", "done": "closed"},
             "include_raw_evidence": false}') AS config
    UNION ALL
    SELECT 'jira', 'jira', 'Jira Cloud', 'https://your-site.atlassian.net', FALSE, PARSE_JSON('{
             "project_key": "SEC", "issue_type": "Task",
             "priority_map": {"P1": "Highest", "P2": "High", "P3": "Medium", "P4": "Low", "P5": "Lowest"},
             "state_out": {"acknowledged": ["In Progress"], "investigating": ["In Progress"],
                           "contained": ["Contained", "In Progress"], "eradicated": ["Contained", "In Progress"],
                           "recovered": ["Contained", "In Progress"], "closed": ["Done", "Closed", "Resolved"],
                           "open": ["To Do", "Open", "Reopened"]},
             "state_in": {"to do": "open", "open": "open", "reopened": "open", "in progress": "investigating",
                          "contained": "contained", "done": "closed", "closed": "closed", "resolved": "closed"},
             "include_raw_evidence": false}')
    UNION ALL
    SELECT 'servicenow', 'servicenow_sir', 'ServiceNow Security Incident Response', 'https://your-instance.service-now.com',
           FALSE, PARSE_JSON('{
             "table": "sn_si_incident", "assignment_group": null, "category": null,
             "urgency_impact": {"P1": [1, 1], "P2": [1, 2], "P3": [2, 2], "P4": [3, 2], "P5": [3, 3]},
             "state_out": {"acknowledged": ["Analysis"], "investigating": ["Analysis"], "contained": ["Contain"],
                           "eradicated": ["Eradicate"], "recovered": ["Recover"], "closed": ["Closed", "Review"],
                           "open": ["Draft", "New"]},
             "state_in": {"draft": "open", "new": "open", "analysis": "investigating", "contain": "contained",
                          "eradicate": "eradicated", "recover": "recovered", "review": "recovered",
                          "closed": "closed", "cancelled": "closed", "in progress": "investigating",
                          "on hold": "investigating", "resolved": "closed"},
             "close_code": {"true_positive": "Confirmed", "false_positive": "False positive", "benign": "False positive",
                            "duplicate": "Duplicate", "test": "Testing"},
             "include_raw_evidence": false}')
) s ON t.connection_id = s.connection_id
WHEN NOT MATCHED THEN INSERT (connection_id, system, name, base_url, enabled, auto_create, min_priority, config)
    VALUES (s.connection_id, s.system, s.name, s.base_url, s.enabled, TRUE, 'P2', s.config);

-- ---------------------------------------------------------------------------
-- 2. Credentials and egress (placeholders until a customer configures them)
-- ---------------------------------------------------------------------------
--   Jira:       ALTER SECRET SNOWFLAKE_XDR.INCIDENTS.JIRA_CREDENTIALS SET USERNAME = 'me@acme.com' PASSWORD = '<api token>';
--   ServiceNow: ALTER SECRET SNOWFLAKE_XDR.INCIDENTS.SERVICENOW_CREDENTIALS SET USERNAME = 'xdr.integration' PASSWORD = '...';
--   Hosts:      CALL SNOWFLAKE_XDR.INCIDENTS.CONFIGURE_TICKET_CONNECTION('jira', 'https://acme.atlassian.net', TRUE, NULL);
CREATE SECRET IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.JIRA_CREDENTIALS
    TYPE = PASSWORD USERNAME = 'not-configured' PASSWORD = 'not-configured'
    COMMENT = 'Jira Cloud: Atlassian account email + API token';
CREATE SECRET IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.SERVICENOW_CREDENTIALS
    TYPE = PASSWORD USERNAME = 'not-configured' PASSWORD = 'not-configured'
    COMMENT = 'ServiceNow integration user (sn_si.integration_user for SIR)';

CREATE NETWORK RULE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.XDR_TICKETING_RULE
    MODE = EGRESS TYPE = HOST_PORT
    -- Hosts must resolve: start with a harmless placeholder; CONFIGURE_TICKET_CONNECTION sets the real sites
    VALUE_LIST = ('developer.atlassian.com');

CREATE EXTERNAL ACCESS INTEGRATION IF NOT EXISTS XDR_TICKETING_EAI
    ALLOWED_NETWORK_RULES = (SNOWFLAKE_XDR.INCIDENTS.XDR_TICKETING_RULE)
    ALLOWED_AUTHENTICATION_SECRETS = (SNOWFLAKE_XDR.INCIDENTS.JIRA_CREDENTIALS, SNOWFLAKE_XDR.INCIDENTS.SERVICENOW_CREDENTIALS)
    ENABLED = TRUE
    COMMENT = 'XDR ticket sync: Jira / ServiceNow hosts of configured connections only';

-- Point a connection at a site and allow egress to exactly that host
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.CONFIGURE_TICKET_CONNECTION(
    P_CONNECTION_ID VARCHAR, P_BASE_URL VARCHAR, P_ENABLED BOOLEAN, P_CONFIG VARIANT
)
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


def main(s, cid, base_url, enabled, config):
    row = s.sql("SELECT system, config FROM SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS WHERE connection_id = ?",
                params=[cid]).collect()
    if not row:
        return {"ok": False, "message": "connection not found"}
    system = row[0]["SYSTEM"]
    if base_url:
        m = re.fullmatch(r"https://([a-z0-9-]+(\.[a-z0-9-]+)+)/?", base_url.strip().lower())
        if not m:
            return {"ok": False, "message": "base_url must be https://<host>"}
        host = m.group(1)
        allowed = {"jira": r"[a-z0-9-]+\.atlassian\.net", "servicenow_sir": r"[a-z0-9-]+\.service-now\.com",
                   "servicenow_itsm": r"[a-z0-9-]+\.service-now\.com"}.get(system)
        if allowed is None or not re.fullmatch(allowed, host):
            return {"ok": False, "message": f"{system} connections must point at a {allowed or 'n/a'} host"}
        hosts = set()
        for r in s.sql("SELECT base_url FROM SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS WHERE connection_id <> ? "
                       "AND base_url IS NOT NULL", params=[cid]).collect():
            hm = re.fullmatch(r"https://([^/]+)/?", r["BASE_URL"] or "")
            if hm:
                hosts.add(hm.group(1))
        hosts.add(host)
        value_list = ", ".join("'" + h.replace("'", "") + "'" for h in sorted(hosts))
        s.sql(f"ALTER NETWORK RULE SNOWFLAKE_XDR.INCIDENTS.XDR_TICKETING_RULE SET VALUE_LIST = ({value_list})").collect()
        base_url = "https://" + host
    merged = json.loads(row[0]["CONFIG"] or "{}")
    if config:
        merged.update(config if isinstance(config, dict) else json.loads(config))
    s.sql("""UPDATE SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS
             SET base_url = COALESCE(?, base_url), enabled = COALESCE(?, enabled), config = PARSE_JSON(?),
                 updated_at = CURRENT_TIMESTAMP() WHERE connection_id = ?""",
          params=[base_url, enabled, json.dumps(merged), cid]).collect()
    return {"ok": True, "message": f"{cid} configured" + (f"; egress allowed to {base_url}" if base_url else "")}
$$;

-- ---------------------------------------------------------------------------
-- 3. Routing and manual ticket creation
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.CREATE_TICKET(
    P_INCIDENT_ID VARCHAR, P_CONNECTION_ID VARCHAR, P_ACTOR VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_conn VARCHAR;
    v_want VARCHAR := NULLIF(TRIM(:P_CONNECTION_ID), '');
    v_inc NUMBER;
BEGIN
    -- Default target: the first enabled real ticket system, else the demo tracker
    IF (v_want IS NULL) THEN
        SELECT COALESCE(MIN(IFF(system <> 'mock', connection_id, NULL)), MIN(connection_id)) INTO :v_want
        FROM SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS WHERE enabled;
    END IF;
    SELECT MAX(connection_id) INTO :v_conn FROM SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS
    WHERE connection_id = :v_want AND enabled;
    IF (v_conn IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'no enabled ticket connection ' || COALESCE(:P_CONNECTION_ID, ''));
    END IF;
    SELECT COUNT(*) INTO :v_inc FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE incident_id = :P_INCIDENT_ID;
    IF (v_inc = 0) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'incident not found');
    END IF;
    MERGE INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS t
    USING (SELECT :P_INCIDENT_ID AS incident_id, :v_conn AS connection_id) s
    ON t.incident_id = s.incident_id AND t.connection_id = s.connection_id
    WHEN NOT MATCHED THEN INSERT (incident_id, connection_id, sync_status) VALUES (s.incident_id, s.connection_id, 'pending');
    IF (SQLROWCOUNT = 0) THEN
        RETURN OBJECT_CONSTRUCT('ok', TRUE, 'message', 'incident already linked to ' || :v_conn, 'connection_id', :v_conn);
    END IF;
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_OUTBOX (incident_id, connection_id, op, payload)
    SELECT :P_INCIDENT_ID, :v_conn, 'create', OBJECT_CONSTRUCT('actor', COALESCE(NULLIF(:P_ACTOR, ''), CURRENT_USER()));
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, source_system)
    SELECT :P_INCIDENT_ID, 'ticket_requested', COALESCE(NULLIF(:P_ACTOR, ''), CURRENT_USER()), 'human', :v_conn, 'xdr';
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'connection_id', :v_conn,
                            'message', 'ticket queued on ' || :v_conn || '; it is created on the next sync');
END;
$$;

-- Which incidents get a ticket automatically: open, at or above the connection's priority,
-- not already linked, and not made only of dismissed / low-confidence findings.
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.ROUTE_INCIDENTS()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_new NUMBER;
    v_reopen NUMBER;
BEGIN
    CREATE OR REPLACE TEMPORARY TABLE XDR_ROUTE AS
    SELECT i.incident_id, c.connection_id
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS i
    JOIN SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS c
      ON c.enabled AND c.auto_create
     AND TRY_TO_NUMBER(SUBSTR(COALESCE(i.priority, 'P3'), 2)) <= TRY_TO_NUMBER(SUBSTR(c.min_priority, 2))
    WHERE i.status <> 'closed'
      AND NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS t WHERE t.incident_id = i.incident_id)
      -- a real ticket system wins over the demo tracker when both are enabled
      AND (c.system <> 'mock' OR NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS r
                                             WHERE r.enabled AND r.auto_create AND r.system <> 'mock'))
      -- phase 1.5 FP control: no tickets for incidents with nothing left that looks real
      AND EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_FINDINGS x
                  JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f ON f.finding_id = x.finding_id
                  WHERE x.incident_id = i.incident_id
                    AND COALESCE(f.disposition, 'open') NOT IN ('false_positive', 'benign', 'auto_suppressed', 'suppressed')
                    AND COALESCE(f.conf_band, 'medium') <> 'low');
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS (incident_id, connection_id, sync_status)
    SELECT incident_id, connection_id, 'pending' FROM XDR_ROUTE;
    v_new := SQLROWCOUNT;
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_OUTBOX (incident_id, connection_id, op, payload)
    SELECT incident_id, connection_id, 'create', OBJECT_CONSTRUCT('actor', 'routing') FROM XDR_ROUTE;
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, source_system)
    SELECT incident_id, 'ticket_requested', 'routing', 'system', connection_id, 'xdr' FROM XDR_ROUTE;

    -- New findings on a closed incident with a ticket: reopen instead of attaching data to a closed ticket
    CREATE OR REPLACE TEMPORARY TABLE XDR_REOPEN AS
    SELECT DISTINCT i.incident_id, COUNT(x.finding_id) OVER (PARTITION BY i.incident_id) AS n
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS i
    JOIN SNOWFLAKE_XDR.INCIDENTS.INCIDENT_FINDINGS x ON x.incident_id = i.incident_id AND x.added_at > i.closed_at
    WHERE i.status = 'closed'
      AND EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS t WHERE t.incident_id = i.incident_id);
    v_reopen := 0;
    LET c CURSOR FOR SELECT incident_id, n FROM XDR_REOPEN;
    FOR r IN c DO
        LET iid VARCHAR := r.incident_id;
        LET nn NUMBER := r.n;
        CALL SNOWFLAKE_XDR.INCIDENTS.SET_INCIDENT_STATE(:iid, 'investigating',
            :nn || ' new finding(s) after close', 'routing', 'system', NULL, NULL);
        v_reopen := v_reopen + 1;
    END FOR;
    RETURN OBJECT_CONSTRUCT('tickets_requested', :v_new, 'reopened', :v_reopen);
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. Mock tracker actions (the "analyst working in Jira" side of the demo)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.MOCK_TICKET_ACTION(
    P_TICKET_KEY VARCHAR, P_STATE VARCHAR, P_ASSIGNEE VARCHAR, P_COMMENT VARCHAR, P_ACTOR VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_state VARCHAR := NULLIF(TRIM(:P_STATE), '');
BEGIN
    IF (v_state IS NOT NULL AND v_state NOT IN ('To Do', 'In Progress', 'Contained', 'Done')) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'mock states: To Do, In Progress, Contained, Done');
    END IF;
    UPDATE SNOWFLAKE_XDR.INCIDENTS.MOCK_TICKETS
    SET state = COALESCE(:v_state, state),
        assignee = COALESCE(NULLIF(TRIM(:P_ASSIGNEE), ''), assignee),
        comments = IFF(NULLIF(TRIM(:P_COMMENT), '') IS NULL, comments,
                       ARRAY_APPEND(COALESCE(comments, ARRAY_CONSTRUCT()),
                                    OBJECT_CONSTRUCT('author', COALESCE(NULLIF(:P_ACTOR, ''), 'jira.analyst'),
                                                     'body', LEFT(TRIM(:P_COMMENT), 4000),
                                                     'created', CURRENT_TIMESTAMP()))),
        updated_at = CURRENT_TIMESTAMP(), updated_by = COALESCE(NULLIF(:P_ACTOR, ''), 'jira.analyst')
    WHERE ticket_key = :P_TICKET_KEY;
    RETURN OBJECT_CONSTRUCT('ok', SQLROWCOUNT > 0,
                            'message', IFF(SQLROWCOUNT > 0, :P_TICKET_KEY || ' updated in the tracker', 'ticket not found'));
END;
$$;

-- ---------------------------------------------------------------------------
-- 5. The sync engine (push outbox, poll, apply)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.SYNC_TICKETS(P_MODE VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python', 'requests')
HANDLER = 'main'
EXTERNAL_ACCESS_INTEGRATIONS = (XDR_TICKETING_EAI)
SECRETS = ('jira' = SNOWFLAKE_XDR.INCIDENTS.JIRA_CREDENTIALS, 'servicenow' = SNOWFLAKE_XDR.INCIDENTS.SERVICENOW_CREDENTIALS)
EXECUTE AS OWNER
AS
$$
import hashlib
import json
import time
from datetime import datetime, timedelta, timezone

import requests

DB = "SNOWFLAKE_XDR.INCIDENTS"
XDR_TAG = "[Snowflake XDR]"            # marks comments written by the XDR, so polling never re-imports them
MAX_ATTEMPTS = 6
HTTP = requests.Session()


def rows(s, sql, params=None):
    return [r.as_dict() for r in s.sql(sql, params=params or []).collect()]


def jload(v, default=None):
    if v is None:
        return default
    if isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(v)
    except (TypeError, ValueError):
        return default


class Remote(Exception):
    """A remote call failed; retryable unless permanent=True."""

    def __init__(self, msg, permanent=False):
        super().__init__(msg)
        self.permanent = permanent


def call(method, url, auth, **kw):
    for attempt in range(3):
        r = HTTP.request(method, url, auth=auth, timeout=30, **kw)
        if r.status_code == 429 or r.status_code >= 500:
            time.sleep(min(int(r.headers.get("Retry-After", 2 ** attempt)), 10))
            continue
        if r.status_code >= 400:
            raise Remote(f"{method} {url.split('?')[0]} -> HTTP {r.status_code}: {r.text[:300]}",
                         permanent=r.status_code in (400, 401, 403, 404))
        return r.json() if r.content and "json" in r.headers.get("content-type", "") else {}
    raise Remote(f"{method} {url.split('?')[0]} -> rate limited / unavailable")


# ---------------------------------------------------------------- payload
def console_url(s):
    r = rows(s, "SELECT MAX(setting_value) AS v FROM SNOWFLAKE_XDR.REFERENCE.PLATFORM_SETTINGS WHERE setting_key = 'xdr_console_url'")
    return (r[0]["V"] or "").rstrip("/")


def incident_payload(s, iid, cfg):
    inc = rows(s, f"SELECT * FROM {DB}.INCIDENTS WHERE incident_id = ?", [iid])[0]
    f = rows(s, """SELECT f.rule_id, COALESCE(r.rule_name, c.name, f.rule_id) AS rule_name, f.severity, f.event_time,
                          f.src, f.dest, f.user_name, f.mitre_technique_id, f.conf_band, f.description, f.evidence
                   FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_FINDINGS x
                   JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f ON f.finding_id = x.finding_id
                   LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES r ON r.rule_id = f.rule_id
                   LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES c ON c.rule_id = f.rule_id
                   WHERE x.incident_id = ? ORDER BY f.severity DESC, f.event_time LIMIT 10""", [iid])
    link = f"{console_url(s)}/investigations?id={iid}"
    entities = sorted({e for x in f for e in (x["SRC"], x["DEST"], x["USER_NAME"]) if e})[:15]
    techniques = sorted({x["MITRE_TECHNIQUE_ID"] for x in f if x["MITRE_TECHNIQUE_ID"]})
    lines = [
        f"{inc['DESCRIPTION'] or inc['TITLE']}",
        "",
        f"Priority {inc['PRIORITY']} | severity {inc['SEVERITY']} | kill chain: {inc['KILL_CHAIN_STAGE'] or '-'}",
        f"First seen {str(inc['FIRST_SEEN'])[:16]}, last seen {str(inc['LAST_SEEN'])[:16]}",
        f"Entities: {', '.join(entities) or '-'}",
        f"MITRE ATT&CK: {', '.join(techniques) or '-'}",
        "",
        "Top detections:",
    ]
    for x in f:
        lines.append(f"- {str(x['EVENT_TIME'])[:16]} {x['RULE_NAME']} (sev {x['SEVERITY']}, {x['CONF_BAND'] or '?'} confidence): "
                     f"{(x['DESCRIPTION'] or '')[:200]}")
        if cfg.get("include_raw_evidence") and x["EVIDENCE"]:
            lines.append(f"  evidence: {str(x['EVIDENCE'])[:500]}")
    lines += ["", f"Investigate in Snowflake XDR: {link}", f"XDR incident id: {iid}"]
    return {"title": f"[XDR {inc['PRIORITY']}] {inc['TITLE']}"[:250], "text": "\n".join(lines), "link": link,
            "priority": inc["PRIORITY"] or "P3", "state": inc["STATUS"], "techniques": techniques}


def report_markdown(s, report_id):
    r = rows(s, f"SELECT title, markdown FROM {DB}.INCIDENT_REPORTS WHERE report_id = ?", [report_id])
    return (r[0]["TITLE"], r[0]["MARKDOWN"]) if r else (None, None)


# ---------------------------------------------------------------- connectors
class Mock:
    """Jira-style tracker stored in MOCK_TICKETS."""

    def __init__(self, s, conn):
        self.s, self.cfg = s, conn["cfg"]

    def find(self, iid):
        r = rows(self.s, f"SELECT ticket_key FROM {DB}.MOCK_TICKETS WHERE xdr_reference = ?", [iid])
        return (r[0]["TICKET_KEY"], r[0]["TICKET_KEY"]) if r else None

    def create(self, iid, p):
        n = rows(self.s, f"SELECT {DB}.MOCK_TICKET_SEQ.NEXTVAL AS n")[0]["N"]
        key = f"{self.cfg.get('project_key', 'SEC')}-{n}"
        self.s.sql(f"""INSERT INTO {DB}.MOCK_TICKETS (ticket_key, xdr_reference, summary, description, priority, state,
                         labels, comments, attachments, updated_by)
                       SELECT ?, ?, ?, ?, ?, 'To Do', ARRAY_CONSTRUCT('snowflake-xdr'), ARRAY_CONSTRUCT(), ARRAY_CONSTRUCT(), 'xdr'""",
                   params=[key, iid, p["title"], p["text"], self.cfg["priority_map"].get(p["priority"], "Medium")]).collect()
        return key, key

    def comment(self, key, text):
        self.s.sql(f"""UPDATE {DB}.MOCK_TICKETS SET comments = ARRAY_APPEND(COALESCE(comments, ARRAY_CONSTRUCT()),
                         OBJECT_CONSTRUCT('author', 'snowflake-xdr', 'body', ?, 'created', CURRENT_TIMESTAMP())),
                         updated_at = CURRENT_TIMESTAMP(), updated_by = 'xdr' WHERE ticket_key = ?""",
                   params=[f"{XDR_TAG} {text}", key]).collect()

    def transition(self, key, state, resolution, reason):
        target = self.cfg["state_out"].get(state)
        if not target:
            return f"no mapped state for {state}"
        self.s.sql(f"UPDATE {DB}.MOCK_TICKETS SET state = ?, updated_at = CURRENT_TIMESTAMP(), updated_by = 'xdr' "
                   f"WHERE ticket_key = ?", params=[target, key]).collect()
        if reason or resolution:
            self.comment(key, f"Status set to {state}" + (f" ({resolution})" if resolution else "") + (f": {reason}" if reason else ""))
        return target

    def attach(self, key, name, content):
        self.s.sql(f"""UPDATE {DB}.MOCK_TICKETS SET attachments = ARRAY_APPEND(COALESCE(attachments, ARRAY_CONSTRUCT()),
                         OBJECT_CONSTRUCT('name', ?, 'size', ?, 'created', CURRENT_TIMESTAMP())),
                         updated_at = CURRENT_TIMESTAMP(), updated_by = 'xdr' WHERE ticket_key = ?""",
                   params=[name, len(content), key]).collect()

    def url(self, key):
        return f"{console_url(self.s)}/cases?ticket={key}"

    def changes(self, since):
        out = []
        for t in rows(self.s, f"""SELECT ticket_key, state, assignee, comments, updated_at, updated_by FROM {DB}.MOCK_TICKETS
                                 WHERE updated_at > ? AND COALESCE(updated_by, '') <> 'xdr'""", [str(since)]):
            out.append({"key": t["TICKET_KEY"], "state": t["STATE"], "assignee": t["ASSIGNEE"],
                        "updated": t["UPDATED_AT"], "actor": t["UPDATED_BY"],
                        "comments": [c for c in jload(t["COMMENTS"], []) if not str(c.get("body", "")).startswith(XDR_TAG)]})
        return out


class Jira:
    """Jira Cloud REST v3. Auth: Atlassian email + API token (PASSWORD secret 'jira')."""

    def __init__(self, s, conn):
        import _snowflake
        cred = _snowflake.get_username_password("jira")
        self.s, self.cfg, self.base = s, conn["cfg"], conn["BASE_URL"].rstrip("/")
        self.auth = (cred.username, cred.password)
        self.label = "snowflake-xdr"

    def adf(self, text):
        return {"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": line}] if line else []}
            for line in text.split("\n")[:200]]}

    def find(self, iid):
        r = call("POST", f"{self.base}/rest/api/3/search/jql", self.auth,
                 json={"jql": f'labels = "xdr-{iid}"', "fields": ["key"], "maxResults": 1})
        issues = r.get("issues", [])
        return (issues[0]["key"], issues[0]["id"]) if issues else None

    def create(self, iid, p):
        fields = {"project": {"key": self.cfg["project_key"]}, "issuetype": {"name": self.cfg.get("issue_type", "Task")},
                  "summary": p["title"], "description": self.adf(p["text"]),
                  "labels": [self.label, f"xdr-{iid}"] + [t.replace(".", "_") for t in p["techniques"][:5]]}
        prio = self.cfg.get("priority_map", {}).get(p["priority"])
        if prio:
            fields["priority"] = {"name": prio}
        try:
            r = call("POST", f"{self.base}/rest/api/3/issue", self.auth, json={"fields": fields})
        except Remote as e:
            if "priority" in str(e).lower() and "priority" in fields:   # priority field not on the screen
                fields.pop("priority")
                r = call("POST", f"{self.base}/rest/api/3/issue", self.auth, json={"fields": fields})
            else:
                raise
        return r["key"], r["id"]

    def comment(self, key, text):
        call("POST", f"{self.base}/rest/api/3/issue/{key}/comment", self.auth, json={"body": self.adf(f"{XDR_TAG} {text}")})

    def transition(self, key, state, resolution, reason):
        wanted = [w.lower() for w in (self.cfg["state_out"].get(state) or [])]
        if not wanted:
            return f"no mapped state for {state}"
        cur = call("GET", f"{self.base}/rest/api/3/issue/{key}?fields=status", self.auth)["fields"]["status"]["name"]
        if cur.lower() in wanted:
            return cur
        ts = call("GET", f"{self.base}/rest/api/3/issue/{key}/transitions", self.auth).get("transitions", [])
        # transitions differ per workflow: pick the first whose target status is acceptable, in preference order
        for w in wanted:
            for t in ts:
                if t.get("to", {}).get("name", "").lower() == w:
                    call("POST", f"{self.base}/rest/api/3/issue/{key}/transitions", self.auth, json={"transition": {"id": t["id"]}})
                    if reason or resolution:
                        self.comment(key, f"Status set to {state}" + (f" ({resolution})" if resolution else "") +
                                     (f": {reason}" if reason else ""))
                    return t["to"]["name"]
        raise Remote(f"no transition from '{cur}' to any of {wanted}", permanent=True)

    def attach(self, key, name, content):
        call("POST", f"{self.base}/rest/api/3/issue/{key}/attachments", self.auth,
             headers={"X-Atlassian-Token": "no-check"}, files={"file": (name, content.encode(), "text/markdown")})

    def url(self, key):
        return f"{self.base}/browse/{key}"

    def changes(self, since):
        mins = max(2, int((datetime.now(timezone.utc) - since).total_seconds() // 60) + 1)
        r = call("POST", f"{self.base}/rest/api/3/search/jql", self.auth,
                 json={"jql": f'labels = "{self.label}" AND updated >= "-{mins}m" ORDER BY updated ASC',
                       "fields": ["status", "assignee", "updated"], "maxResults": 100})
        out = []
        for i in r.get("issues", []):
            fl = i["fields"]
            cm = call("GET", f"{self.base}/rest/api/3/issue/{i['key']}/comment?orderBy=-created&maxResults=20", self.auth)
            comments = []
            for c in cm.get("comments", []):
                body = " ".join(t.get("text", "") for blk in (c.get("body") or {}).get("content", [])
                                for t in blk.get("content", []) if t.get("type") == "text")
                if not body.startswith(XDR_TAG):
                    comments.append({"author": (c.get("author") or {}).get("displayName"), "body": body,
                                     "created": c.get("created"), "id": c.get("id")})
            out.append({"key": i["key"], "state": fl["status"]["name"],
                        "assignee": (fl.get("assignee") or {}).get("displayName"), "updated": fl.get("updated"),
                        "actor": None, "comments": comments})
        return out


class ServiceNow:
    """Table API on sn_si_incident (SIR) or incident (ITSM). Auth: integration user (PASSWORD secret 'servicenow')."""

    def __init__(self, s, conn):
        import _snowflake
        cred = _snowflake.get_username_password("servicenow")
        self.s, self.cfg, self.base = s, conn["cfg"], conn["BASE_URL"].rstrip("/")
        self.auth = (cred.username, cred.password)
        self.table = self.cfg.get("table") or ("sn_si_incident" if conn["SYSTEM"] == "servicenow_sir" else "incident")
        self._states = None

    def states(self):
        """State label -> value from the instance's own choice list (values differ between SIR, ITSM and customisations)."""
        if self._states is None:
            r = call("GET", f"{self.base}/api/now/table/sys_choice?sysparm_query=name={self.table}^element=state^inactive=false"
                            f"&sysparm_fields=label,value", self.auth)
            self._states = {c["label"].lower(): c["value"] for c in r.get("result", [])}
        return self._states

    def find(self, iid):
        r = call("GET", f"{self.base}/api/now/table/{self.table}?sysparm_query=correlation_id={iid}&sysparm_fields=number,sys_id"
                        f"&sysparm_limit=1", self.auth)
        res = r.get("result", [])
        return (res[0]["number"], res[0]["sys_id"]) if res else None

    def create(self, iid, p):
        u, i = (self.cfg.get("urgency_impact") or {}).get(p["priority"], [2, 2])
        body = {"short_description": p["title"], "description": p["text"], "urgency": str(u), "impact": str(i),
                "correlation_id": iid, "correlation_display": "Snowflake XDR"}
        for k in ("assignment_group", "category", "subcategory"):
            if self.cfg.get(k):
                body[k] = self.cfg[k]
        r = call("POST", f"{self.base}/api/now/table/{self.table}", self.auth, json=body,
                 headers={"Accept": "application/json"})["result"]
        return r["number"], r["sys_id"]

    def _patch(self, sys_id, body):
        call("PATCH", f"{self.base}/api/now/table/{self.table}/{sys_id}", self.auth, json=body,
             headers={"Accept": "application/json"})

    def comment(self, sys_id, text):
        self._patch(sys_id, {"work_notes": f"{XDR_TAG} {text}"})

    def transition(self, sys_id, state, resolution, reason):
        wanted = [w.lower() for w in (self.cfg["state_out"].get(state) or [])]
        st = self.states()
        for w in wanted:
            if w in st:
                body = {"state": st[w]}
                if state == "closed":
                    body["close_code"] = (self.cfg.get("close_code") or {}).get(resolution or "true_positive", "Confirmed")
                    body["close_notes"] = f"{XDR_TAG} {reason or 'Closed in Snowflake XDR'}"
                self._patch(sys_id, body)
                return w
        raise Remote(f"none of {wanted} is a state of {self.table} (states: {sorted(st)})", permanent=True)

    def attach(self, sys_id, name, content):
        call("POST", f"{self.base}/api/now/attachment/file?table_name={self.table}&table_sys_id={sys_id}&file_name={name}",
             self.auth, data=content.encode(), headers={"Content-Type": "text/markdown", "Accept": "application/json"})

    def url(self, number):
        return f"{self.base}/nav_to.do?uri={self.table}.do?sysparm_query=number={number}"

    def changes(self, since):
        mins = max(2, int((datetime.now(timezone.utc) - since).total_seconds() // 60) + 1)
        r = call("GET", f"{self.base}/api/now/table/{self.table}?sysparm_query=correlation_display=Snowflake XDR"
                        f"^sys_updated_on>=javascript:gs.minutesAgoStart({mins})&sysparm_display_value=true"
                        f"&sysparm_fields=number,sys_id,state,assigned_to,sys_updated_on,sys_updated_by&sysparm_limit=100",
                 self.auth)
        out = []
        for t in r.get("result", []):
            j = call("GET", f"{self.base}/api/now/table/sys_journal_field?sysparm_query=element_id={t['sys_id']}"
                            f"^elementINwork_notes,comments^sys_created_on>=javascript:gs.minutesAgoStart({mins})"
                            f"&sysparm_fields=value,sys_created_by,sys_created_on,sys_id&sysparm_limit=50", self.auth)
            comments = [{"author": c["sys_created_by"], "body": c["value"], "created": c["sys_created_on"], "id": c["sys_id"]}
                        for c in j.get("result", []) if not c["value"].startswith(XDR_TAG)]
            assignee = t.get("assigned_to")
            out.append({"key": t["number"], "sys_id": t["sys_id"], "state": t.get("state"),
                        "assignee": assignee.get("display_value") if isinstance(assignee, dict) else assignee,
                        "updated": t.get("sys_updated_on"), "actor": t.get("sys_updated_by"), "comments": comments})
        return out


CONNECTORS = {"mock": Mock, "jira": Jira, "servicenow_sir": ServiceNow, "servicenow_itsm": ServiceNow}


def connections(s):
    out = {}
    for c in rows(s, f"SELECT * FROM {DB}.TICKET_CONNECTIONS WHERE enabled"):
        c["cfg"] = jload(c["CONFIG"], {})
        out[c["CONNECTION_ID"]] = c
    return out


def client(s, conn, cache):
    cid = conn["CONNECTION_ID"]
    if cid not in cache:
        if conn["SYSTEM"] != "mock" and not conn["BASE_URL"]:
            raise Remote("connection has no base_url", permanent=True)
        cache[cid] = CONNECTORS[conn["SYSTEM"]](s, conn)
    return cache[cid]


# ---------------------------------------------------------------- push
def push(s, conns, cache):
    done = failed = 0
    ops = rows(s, f"""SELECT o.*, t.external_key, t.external_id FROM {DB}.INCIDENT_OUTBOX o
                     LEFT JOIN {DB}.INCIDENT_TICKETS t ON t.incident_id = o.incident_id AND t.connection_id = o.connection_id
                     WHERE o.status = 'pending' AND o.next_attempt_at <= CURRENT_TIMESTAMP()
                     ORDER BY IFF(o.op = 'create', 0, 1), o.created_at LIMIT 200""")
    for op in ops:
        conn = conns.get(op["CONNECTION_ID"])
        if conn is None:
            s.sql(f"UPDATE {DB}.INCIDENT_OUTBOX SET status = 'skipped', last_error = 'connection disabled' WHERE op_id = ?",
                  params=[op["OP_ID"]]).collect()
            continue
        payload = jload(op["PAYLOAD"], {})
        iid, kind = op["INCIDENT_ID"], op["OP"]
        try:
            c = client(s, conn, cache)
            key, ext = op["EXTERNAL_KEY"], op["EXTERNAL_ID"]
            ref = ext if conn["SYSTEM"].startswith("servicenow") else key
            if kind == "create" or not key:
                if kind != "create":
                    continue      # the create for this ticket has not gone through yet; retry later
                p = incident_payload(s, iid, conn["cfg"])
                found = c.find(iid)      # idempotency: adopt a ticket a previous attempt already created
                key, ext = found if found else c.create(iid, p)
                s.sql(f"""UPDATE {DB}.INCIDENT_TICKETS SET external_key = ?, external_id = ?, url = ?, sync_status = 'ok',
                            remote_state = ?, last_error = NULL, last_synced_at = CURRENT_TIMESTAMP()
                          WHERE incident_id = ? AND connection_id = ?""",
                      params=[key, ext, c.url(key), "To Do" if conn["SYSTEM"] == "mock" else None, iid, op["CONNECTION_ID"]]).collect()
                s.sql(f"""INSERT INTO {DB}.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, detail, source_system)
                          SELECT ?, 'ticket_linked', ?, 'system', ?, OBJECT_CONSTRUCT('url', ?, 'adopted', ?), ?""",
                      params=[iid, payload.get("actor", "sync"), key, c.url(key), bool(found), op["CONNECTION_ID"]]).collect()
                ref = ext if conn["SYSTEM"].startswith("servicenow") else key
                # the ticket starts where the incident already is
                if p["state"] not in ("open",):
                    st = c.transition(ref, p["state"], None, None)
                    s.sql(f"UPDATE {DB}.INCIDENT_TICKETS SET remote_state = ? WHERE incident_id = ? AND connection_id = ?",
                          params=[st, iid, op["CONNECTION_ID"]]).collect()
            elif kind == "comment":
                c.comment(ref, payload.get("text", ""))
            elif kind == "transition":
                st = c.transition(ref, payload["state"], payload.get("resolution"), payload.get("reason"))
                s.sql(f"UPDATE {DB}.INCIDENT_TICKETS SET remote_state = ? WHERE incident_id = ? AND connection_id = ?",
                      params=[st, iid, op["CONNECTION_ID"]]).collect()
            elif kind == "attach_report":
                title, md = report_markdown(s, payload.get("report_id"))
                if md:
                    c.attach(ref, f"xdr-incident-report-{iid[:8]}.md", md)
                    c.comment(ref, f"Incident report attached: {title}")
            s.sql(f"UPDATE {DB}.INCIDENT_OUTBOX SET status = 'done', done_at = CURRENT_TIMESTAMP(), attempts = attempts + 1, "
                  f"last_error = NULL WHERE op_id = ?", params=[op["OP_ID"]]).collect()
            s.sql(f"UPDATE {DB}.INCIDENT_TICKETS SET sync_status = 'ok', last_error = NULL, last_synced_at = CURRENT_TIMESTAMP() "
                  f"WHERE incident_id = ? AND connection_id = ?", params=[iid, op["CONNECTION_ID"]]).collect()
            done += 1
        except Exception as e:  # recorded on the op, the link and the incident timeline
            failed += 1
            perm = isinstance(e, Remote) and e.permanent
            attempts = (op["ATTEMPTS"] or 0) + 1
            final = perm or attempts >= MAX_ATTEMPTS
            msg = str(e)[:1900]
            s.sql(f"""UPDATE {DB}.INCIDENT_OUTBOX SET attempts = ?, last_error = ?, status = IFF(?, 'failed', 'pending'),
                        next_attempt_at = DATEADD('second', ?, CURRENT_TIMESTAMP()) WHERE op_id = ?""",
                  params=[attempts, msg, final, min(3600, 30 * 2 ** attempts), op["OP_ID"]]).collect()
            s.sql(f"UPDATE {DB}.INCIDENT_TICKETS SET sync_status = 'error', last_error = ? WHERE incident_id = ? AND connection_id = ?",
                  params=[msg, iid, op["CONNECTION_ID"]]).collect()
            if final:
                s.sql(f"""INSERT INTO {DB}.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, detail, source_system)
                          SELECT ?, 'ticket_sync_error', 'sync', 'system', ?, OBJECT_CONSTRUCT('error', ?), ?""",
                      params=[iid, kind, msg, op["CONNECTION_ID"]]).collect()
    return {"pushed": done, "failed": failed}


# ---------------------------------------------------------------- poll
def to_dt(v):
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if not v:
        return datetime.now(timezone.utc)
    txt = str(v).replace("Z", "+00:00")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
        try:
            d = datetime.strptime(txt if "%z" in fmt else txt[:19], fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def poll(s, conns, cache):
    queued = 0
    for cid, conn in conns.items():
        since = conn["LAST_POLL_AT"] or (datetime.now(timezone.utc) - timedelta(hours=1))
        since = since if since.tzinfo else since.replace(tzinfo=timezone.utc)
        started = datetime.now(timezone.utc)
        try:
            changes = client(s, conn, cache).changes(since - timedelta(seconds=30))
        except Exception as e:
            s.sql(f"UPDATE {DB}.TICKET_CONNECTIONS SET last_poll_status = ? WHERE connection_id = ?",
                  params=[("error: " + str(e))[:1900], cid]).collect()
            continue
        links = {r["EXTERNAL_KEY"]: r for r in rows(s, f"""SELECT external_key, remote_state, remote_assignee
                     FROM {DB}.INCIDENT_TICKETS WHERE connection_id = ? AND external_key IS NOT NULL""", [cid])}
        for ch in changes:
            link = links.get(ch["key"])
            if not link:
                continue
            items = []
            if ch.get("state") and ch["state"] != link["REMOTE_STATE"]:
                items.append(("state", ch["state"], ch.get("actor"), ch.get("updated"), f"{ch['key']}:state:{ch['state']}:{ch.get('updated')}"))
            if ch.get("assignee") and ch["assignee"] != link["REMOTE_ASSIGNEE"]:
                items.append(("assignee", ch["assignee"], ch.get("actor"), ch.get("updated"), f"{ch['key']}:assignee:{ch['assignee']}"))
            for cm in ch.get("comments", []):
                items.append(("comment", cm.get("body", "")[:7900], cm.get("author"), cm.get("created"),
                              f"{ch['key']}:comment:{cm.get('id') or cm.get('created')}:{hashlib.md5(cm.get('body', '').encode()).hexdigest()[:12]}"))
            for kind, value, actor, when, dk in items:
                n = s.sql(f"""INSERT INTO {DB}.TICKET_INBOX (connection_id, external_key, kind, value, remote_actor, remote_time, dedupe_key, via)
                              SELECT ?, ?, ?, ?, ?, TRY_TO_TIMESTAMP_LTZ(?), ?, 'poll'
                              WHERE NOT EXISTS (SELECT 1 FROM {DB}.TICKET_INBOX WHERE connection_id = ? AND dedupe_key = ?)""",
                          params=[cid, ch["key"], kind, value, actor, str(to_dt(when).isoformat()), dk[:300], cid, dk[:300]]).collect()[0][0]
                queued += n
        s.sql(f"UPDATE {DB}.TICKET_CONNECTIONS SET last_poll_at = ?, last_poll_status = ? WHERE connection_id = ?",
              params=[started.isoformat(), f"ok: {len(changes)} changed tickets", cid]).collect()
    return {"inbox_new": queued}


# ---------------------------------------------------------------- apply
def apply(s, conns):
    applied = ignored = 0
    for r in rows(s, f"""SELECT b.*, t.incident_id FROM {DB}.TICKET_INBOX b
                        LEFT JOIN {DB}.INCIDENT_TICKETS t ON t.connection_id = b.connection_id AND t.external_key = b.external_key
                        WHERE b.status = 'pending' ORDER BY b.remote_time, b.received_at LIMIT 500"""):
        cid, iid, kind = r["CONNECTION_ID"], r["INCIDENT_ID"], r["KIND"]
        actor = f"{r['REMOTE_ACTOR'] or cid} ({cid})"
        status, result = "applied", ""
        try:
            if iid is None:
                status, result = "ignored", "ticket not linked to an incident"
            elif kind == "state":
                state_in = (conns.get(cid, {}).get("cfg") or {}).get("state_in", {})
                target = state_in.get((r["VALUE"] or "").lower())
                if not target:
                    status, result = "ignored", f"remote state '{r['VALUE']}' has no XDR mapping"
                else:
                    res = s.call(f"{DB}.SET_INCIDENT_STATE", iid, target, f"changed in {cid} ticket {r['EXTERNAL_KEY']}",
                                 actor, "ticket", None, cid)
                    res = jload(res, {})
                    result = res.get("message", "")
                    status = "applied" if res.get("ok") else "error"
                s.sql(f"UPDATE {DB}.INCIDENT_TICKETS SET remote_state = ? WHERE connection_id = ? AND external_key = ?",
                      params=[r["VALUE"], cid, r["EXTERNAL_KEY"]]).collect()
            elif kind == "assignee":
                res = jload(s.call(f"{DB}.ASSIGN_INCIDENT", iid, r["VALUE"], actor, "ticket", cid), {})
                result = res.get("message", "")
                s.sql(f"UPDATE {DB}.INCIDENT_TICKETS SET remote_assignee = ? WHERE connection_id = ? AND external_key = ?",
                      params=[r["VALUE"], cid, r["EXTERNAL_KEY"]]).collect()
            elif kind == "comment":
                res = jload(s.call(f"{DB}.ADD_INCIDENT_COMMENT", iid, r["VALUE"], actor, "ticket", cid), {})
                result = res.get("message", "")
        except Exception as e:
            status, result = "error", str(e)[:1900]
        applied += status == "applied"
        ignored += status != "applied"
        s.sql(f"UPDATE {DB}.TICKET_INBOX SET status = ?, result = ? WHERE inbox_id = ?",
              params=[status, result[:1990], r["INBOX_ID"]]).collect()
    return {"applied": applied, "ignored_or_error": ignored}


def main(s, mode):
    mode = (mode or "all").lower()
    out = {}
    conns = connections(s)
    cache = {}
    if mode in ("all", "route"):
        out["route"] = jload(s.call(f"{DB}.ROUTE_INCIDENTS"), {})
    if mode in ("all", "push", "route"):
        out["push"] = push(s, conns, cache)
    if mode in ("all", "poll"):
        out["poll"] = poll(s, conns, cache)
    if mode in ("all", "poll", "apply"):
        out["apply"] = apply(s, conns)
    if mode == "all":
        out["sla"] = s.call(f"{DB}.CHECK_INCIDENT_SLAS")
    return out
$$;

-- ---------------------------------------------------------------------------
-- 6. Inbound push: webhooks from the receiver (/v1/webhooks/{connection})
-- ---------------------------------------------------------------------------
-- Accepts Jira issue webhooks / Jira Automation "Send web request" bodies and
-- ServiceNow outbound REST messages; writes TICKET_INBOX rows (applied by the next sync).
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.INGEST_TICKET_WEBHOOK(P_CONNECTION_ID VARCHAR, P_PAYLOAD VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS OWNER
AS
$$
import hashlib
import json

DB = "SNOWFLAKE_XDR.INCIDENTS"


def adf_text(body):
    if isinstance(body, str):
        return body
    return " ".join(t.get("text", "") for blk in (body or {}).get("content", []) for t in blk.get("content", [])
                    if t.get("type") == "text")


def main(s, cid, payload):
    conn = s.sql(f"SELECT system FROM {DB}.TICKET_CONNECTIONS WHERE connection_id = ? AND enabled", params=[cid]).collect()
    if not conn:
        return {"ok": False, "message": "unknown or disabled connection"}
    try:
        p = json.loads(payload)
    except ValueError:
        return {"ok": False, "message": "payload is not JSON"}
    system = conn[0]["SYSTEM"]
    items = []
    if system == "jira":
        issue = p.get("issue") or {}
        key = issue.get("key") or p.get("key")
        f = issue.get("fields") or {}
        when = str(p.get("timestamp") or f.get("updated") or "")
        actor = (p.get("user") or {}).get("displayName")
        if (f.get("status") or {}).get("name"):
            items.append(("state", f["status"]["name"], actor, f"{key}:state:{f['status']['name']}:{when}"))
        if (f.get("assignee") or {}).get("displayName"):
            items.append(("assignee", f["assignee"]["displayName"], actor, f"{key}:assignee:{f['assignee']['displayName']}"))
        c = p.get("comment")
        if c:
            text = adf_text(c.get("body"))
            if not text.startswith("[Snowflake XDR]"):
                items.append(("comment", text, (c.get("author") or {}).get("displayName"), f"{key}:comment:{c.get('id')}"))
    else:
        # ServiceNow outbound REST message: {"number", "state", "assigned_to", "work_note", "updated_by", "updated_on"}
        key = p.get("number")
        when = str(p.get("updated_on") or "")
        if p.get("state"):
            items.append(("state", p["state"], p.get("updated_by"), f"{key}:state:{p['state']}:{when}"))
        if p.get("assigned_to"):
            items.append(("assignee", p["assigned_to"], p.get("updated_by"), f"{key}:assignee:{p['assigned_to']}"))
        note = p.get("work_note") or p.get("comment")
        if note and not str(note).startswith("[Snowflake XDR]"):
            items.append(("comment", str(note), p.get("updated_by"), f"{key}:comment:{when}:{hashlib.md5(str(note).encode()).hexdigest()[:12]}"))
    if not key:
        return {"ok": False, "message": "no ticket key in payload"}
    n = 0
    for kind, value, actor, dk in items:
        n += s.sql(f"""INSERT INTO {DB}.TICKET_INBOX (connection_id, external_key, kind, value, remote_actor, remote_time, dedupe_key, via)
                       SELECT ?, ?, ?, ?, ?, CURRENT_TIMESTAMP(), ?, 'webhook'
                       WHERE NOT EXISTS (SELECT 1 FROM {DB}.TICKET_INBOX WHERE connection_id = ? AND dedupe_key = ?)""",
                   params=[cid, key, kind, str(value)[:7900], actor, dk[:300], cid, dk[:300]]).collect()[0][0]
    return {"ok": True, "queued": n, "ticket": key}
$$;

-- ---------------------------------------------------------------------------
-- 7. Status and schedule
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.TICKETING_STATUS()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_conns VARIANT;
    v_links VARIANT;
    v_queue VARIANT;
    v_inbox NUMBER;
BEGIN
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('connection_id', connection_id, 'system', system, 'name', name, 'enabled', enabled,
                                      'auto_create', auto_create, 'min_priority', min_priority, 'base_url', base_url,
                                      'last_poll_at', last_poll_at, 'last_poll_status', last_poll_status))
    INTO :v_conns FROM SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS;
    SELECT OBJECT_CONSTRUCT('linked', COUNT(*), 'ok', COUNT_IF(sync_status = 'ok'), 'pending', COUNT_IF(sync_status = 'pending'),
                            'error', COUNT_IF(sync_status = 'error'))
    INTO :v_links FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS;
    SELECT COUNT(*) INTO :v_inbox FROM SNOWFLAKE_XDR.INCIDENTS.TICKET_INBOX WHERE status = 'pending';
    SELECT OBJECT_CONSTRUCT('outbox_pending', COUNT_IF(status = 'pending'), 'outbox_failed', COUNT_IF(status = 'failed'),
                            'inbox_pending', :v_inbox)
    INTO :v_queue FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_OUTBOX;
    RETURN OBJECT_CONSTRUCT('connections', :v_conns, 'tickets', :v_links, 'queues', :v_queue);
END;
$$;

CREATE TASK IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.TASK_TICKET_SYNC
    WAREHOUSE = XDR_WH
    SCHEDULE = '2 MINUTE'
    COMMENT = 'Route incidents to tickets, push outbox, poll ticket changes, apply them, check SLAs'
AS
    CALL SNOWFLAKE_XDR.INCIDENTS.SYNC_TICKETS('all');

-- ---------------------------------------------------------------------------
-- 8. XDR Analyst agent tools (simple signatures; actor_type 'agent')
-- ---------------------------------------------------------------------------
-- Replaces the direct-update version from 24_agent_actions.sql: agent status changes are audited and synced.
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_SET_INCIDENT_STATUS(P_INCIDENT_ID VARCHAR, P_STATUS VARCHAR)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    s VARCHAR := LOWER(TRIM(:P_STATUS));
    res VARIANT;
BEGIN
    -- the agent closes as true_positive unless an analyst records another resolution in the console
    CALL SNOWFLAKE_XDR.INCIDENTS.SET_INCIDENT_STATE(:P_INCIDENT_ID, :s, 'set by XDR Analyst agent', 'xdr-analyst-agent',
                                                    'agent', IFF(:s = 'closed', 'true_positive', NULL), NULL) INTO :res;
    INSERT INTO SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (tool, target, params, result)
        SELECT 'set_incident_status', :P_INCIDENT_ID, OBJECT_CONSTRUCT('status', :s), :res:message::VARCHAR;
    RETURN :res:message::VARCHAR;
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_CASE_ACTION(
    P_INCIDENT_ID VARCHAR, P_ACTION VARCHAR, P_TEXT VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    a VARCHAR := LOWER(TRIM(:P_ACTION));
    res VARIANT;
BEGIN
    IF (a = 'timeline') THEN
        CALL SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TIMELINE(:P_INCIDENT_ID) INTO :res;
        RETURN :res;
    ELSEIF (a = 'comment') THEN
        CALL SNOWFLAKE_XDR.INCIDENTS.ADD_INCIDENT_COMMENT(:P_INCIDENT_ID, :P_TEXT, 'xdr-analyst-agent', 'agent', NULL) INTO :res;
    ELSEIF (a = 'assign') THEN
        CALL SNOWFLAKE_XDR.INCIDENTS.ASSIGN_INCIDENT(:P_INCIDENT_ID, :P_TEXT, 'xdr-analyst-agent', 'agent', NULL) INTO :res;
    ELSEIF (a = 'add_task') THEN
        CALL SNOWFLAKE_XDR.INCIDENTS.UPSERT_INCIDENT_TASK(:P_INCIDENT_ID, NULL, :P_TEXT, NULL, 24, 'open', 'xdr-analyst-agent') INTO :res;
    ELSEIF (a = 'create_ticket') THEN
        CALL SNOWFLAKE_XDR.INCIDENTS.CREATE_TICKET(:P_INCIDENT_ID, NULLIF(TRIM(:P_TEXT), ''), 'xdr-analyst-agent') INTO :res;
        IF (res:ok::BOOLEAN) THEN
            CALL SNOWFLAKE_XDR.INCIDENTS.SYNC_TICKETS('push');
            LET conn VARCHAR := res:connection_id::VARCHAR;
            LET tk VARIANT;
            SELECT ARRAY_AGG(OBJECT_CONSTRUCT('key', external_key, 'url', url, 'status', sync_status, 'error', last_error))[0]
            INTO :tk FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS
            WHERE incident_id = :P_INCIDENT_ID AND connection_id = :conn;
            res := OBJECT_INSERT(:res, 'ticket', :tk, TRUE);
        END IF;
    ELSEIF (a = 'report') THEN
        CALL SNOWFLAKE_XDR.INCIDENTS.GENERATE_INCIDENT_REPORT(:P_INCIDENT_ID, 'xdr-analyst-agent') INTO :res;
    ELSE
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message',
                                'action must be one of: timeline, comment, assign, add_task, create_ticket, report');
    END IF;
    INSERT INTO SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (tool, target, params, result)
        SELECT 'case_action', :P_INCIDENT_ID, OBJECT_CONSTRUCT('action', :a, 'text', LEFT(:P_TEXT, 500)), LEFT(:res::VARCHAR, 4000);
    RETURN :res;
END;
$$;
