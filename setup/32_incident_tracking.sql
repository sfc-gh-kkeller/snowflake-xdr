-- ============================================================================
-- Snowflake XDR - 32: Native incident tracking (phase 3, part 1)
-- ============================================================================
-- Turns INCIDENTS into a case-management system of record:
--   lifecycle   open -> acknowledged -> investigating -> contained -> eradicated
--               -> recovered -> closed (NIST 800-61), every change through
--               SET_INCIDENT_STATE with actor + reason
--   audit trail INCIDENT_EVENTS (status, assignment, comments, tasks, tickets, SLA, reports)
--   tasks       INCIDENT_TASKS (response work items per incident)
--   SLAs        INCIDENT_SLA_POLICY per priority, breaches become events
--   reports     GENERATE_INCIDENT_REPORT: SQL facts + Cortex narrative
--   metrics     V_INCIDENT_METRICS (MTTA / MTTC / MTTR, SLA compliance, reopen rate)
--
-- Ticket sync (33_ticketing.sql) hangs off the same procedures: any change made
-- here by a person, agent or the autopilot is queued in INCIDENT_OUTBOX for the
-- linked Jira / ServiceNow ticket; changes coming back from a ticket are applied
-- with actor_type = 'ticket' and are never echoed back.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Incident columns for lifecycle and SLA
-- ---------------------------------------------------------------------------
ALTER TABLE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP_LTZ;
ALTER TABLE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS ADD COLUMN IF NOT EXISTS contained_at TIMESTAMP_LTZ;
ALTER TABLE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS ADD COLUMN IF NOT EXISTS reopened_count NUMBER;
ALTER TABLE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS ADD COLUMN IF NOT EXISTS latest_report_id VARCHAR;

-- ---------------------------------------------------------------------------
-- 2. Tables
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS (
    event_id      VARCHAR DEFAULT UUID_STRING(),
    incident_id   VARCHAR NOT NULL,
    event_time    TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    event_type    VARCHAR(40),     -- created, status, assignment, comment, task, finding_added, ticket_linked,
                                   -- ticket_sync_error, sla_breach, report, reopened
    actor         VARCHAR(255),
    actor_type    VARCHAR(20),     -- human | agent | autopilot | ticket | system
    from_value    VARCHAR(255),
    to_value      VARCHAR(255),
    detail        VARIANT,
    source_system VARCHAR(50)      -- xdr, or the ticket connection the change came from
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TASKS (
    task_id       VARCHAR DEFAULT UUID_STRING(),
    incident_id   VARCHAR NOT NULL,
    title         VARCHAR(500),
    owner         VARCHAR(255),
    due_at        TIMESTAMP_LTZ,
    status        VARCHAR(20) DEFAULT 'open',   -- open | done | cancelled
    created_by    VARCHAR(255),
    created_at    TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    completed_at  TIMESTAMP_LTZ
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.INCIDENT_SLA_POLICY (
    priority          VARCHAR(5) PRIMARY KEY,
    ack_minutes       NUMBER,
    contain_minutes   NUMBER,
    resolve_minutes   NUMBER,
    updated_at        TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);
MERGE INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_SLA_POLICY t
USING (SELECT * FROM VALUES ('P1', 15, 240, 1440), ('P2', 60, 480, 4320), ('P3', 240, 1440, 10080),
                            ('P4', 1440, 4320, 20160), ('P5', 2880, 10080, 43200)
       AS v(priority, ack_minutes, contain_minutes, resolve_minutes)) s
ON t.priority = s.priority
WHEN NOT MATCHED THEN INSERT (priority, ack_minutes, contain_minutes, resolve_minutes)
    VALUES (s.priority, s.ack_minutes, s.contain_minutes, s.resolve_minutes);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.INCIDENT_REPORTS (
    report_id     VARCHAR DEFAULT UUID_STRING(),
    incident_id   VARCHAR NOT NULL,
    created_at    TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    created_by    VARCHAR(255),
    title         VARCHAR(500),
    markdown      VARCHAR,
    facts         VARIANT,          -- every number in the report comes from here
    narrative     VARIANT,          -- Cortex-written sections
    model         VARCHAR(100)
);

-- Ticket links and the outbound queue live here so every lifecycle procedure can enqueue;
-- connections, connectors and the sync engine are in 33_ticketing.sql.
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS (
    incident_id        VARCHAR NOT NULL,
    connection_id      VARCHAR(64) NOT NULL,
    external_key       VARCHAR(100),     -- Jira key / ServiceNow number
    external_id        VARCHAR(100),     -- Jira id / ServiceNow sys_id
    url                VARCHAR(1000),
    remote_state       VARCHAR(100),
    remote_assignee    VARCHAR(255),
    remote_updated_at  TIMESTAMP_LTZ,
    sync_status        VARCHAR(20),      -- pending | ok | error
    last_error         VARCHAR(2000),
    last_synced_at     TIMESTAMP_LTZ,
    created_at         TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    PRIMARY KEY (incident_id, connection_id)
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS.INCIDENT_OUTBOX (
    op_id            VARCHAR DEFAULT UUID_STRING(),
    incident_id      VARCHAR NOT NULL,
    connection_id    VARCHAR(64) NOT NULL,
    op               VARCHAR(20),        -- create | update | comment | transition | attach_report
    payload          VARIANT,
    status           VARCHAR(20) DEFAULT 'pending',   -- pending | done | failed | skipped
    attempts         NUMBER DEFAULT 0,
    next_attempt_at  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    last_error       VARCHAR(2000),
    created_at       TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    done_at          TIMESTAMP_LTZ
);

-- ---------------------------------------------------------------------------
-- 3. Lifecycle
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.INCIDENTS.INCIDENT_STATES()
RETURNS ARRAY
AS
$$
    ARRAY_CONSTRUCT('open', 'acknowledged', 'investigating', 'contained', 'eradicated', 'recovered', 'closed')
$$;

CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.INCIDENTS.INCIDENT_RESOLUTIONS()
RETURNS ARRAY
AS
$$
    ARRAY_CONSTRUCT('true_positive', 'benign', 'false_positive', 'duplicate', 'test')
$$;

-- Queue an outbound change for every ticket linked to an incident (not for changes that came from a ticket)
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.ENQUEUE_TICKET_OP(
    P_INCIDENT_ID VARCHAR, P_OP VARCHAR, P_PAYLOAD VARIANT, P_ACTOR_TYPE VARCHAR, P_SOURCE VARCHAR
)
RETURNS NUMBER
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_OUTBOX (incident_id, connection_id, op, payload)
    SELECT t.incident_id, t.connection_id, :P_OP, :P_PAYLOAD
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS t
    WHERE t.incident_id = :P_INCIDENT_ID
      -- a change that arrived from a ticket system is not sent back to that system
      AND NOT (COALESCE(:P_ACTOR_TYPE, '') = 'ticket' AND t.connection_id = COALESCE(:P_SOURCE, ''));
    RETURN SQLROWCOUNT;
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.SET_INCIDENT_STATE(
    P_INCIDENT_ID VARCHAR, P_STATE VARCHAR, P_REASON VARCHAR, P_ACTOR VARCHAR, P_ACTOR_TYPE VARCHAR,
    P_RESOLUTION VARCHAR, P_SOURCE VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_state VARCHAR := LOWER(TRIM(:P_STATE));
    v_res VARCHAR := NULLIF(LOWER(TRIM(:P_RESOLUTION)), '');
    v_actor_type VARCHAR := COALESCE(NULLIF(LOWER(TRIM(:P_ACTOR_TYPE)), ''), 'human');
    v_actor VARCHAR := COALESCE(NULLIF(TRIM(:P_ACTOR), ''), CURRENT_USER());
    v_old VARCHAR;
    v_old_res VARCHAR;
    v_queued NUMBER := 0;
BEGIN
    IF (NOT ARRAY_CONTAINS(:v_state::VARIANT, SNOWFLAKE_XDR.INCIDENTS.INCIDENT_STATES())) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'state must be one of: ' ||
                                ARRAY_TO_STRING(SNOWFLAKE_XDR.INCIDENTS.INCIDENT_STATES(), ', '));
    END IF;
    IF (v_actor_type NOT IN ('human', 'agent', 'autopilot', 'ticket', 'system')) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'invalid actor_type');
    END IF;
    IF (v_res IS NOT NULL AND NOT ARRAY_CONTAINS(:v_res::VARIANT, SNOWFLAKE_XDR.INCIDENTS.INCIDENT_RESOLUTIONS())) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'resolution must be one of: ' ||
                                ARRAY_TO_STRING(SNOWFLAKE_XDR.INCIDENTS.INCIDENT_RESOLUTIONS(), ', '));
    END IF;
    SELECT MAX(status), MAX(resolution) INTO :v_old, :v_old_res
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE incident_id = :P_INCIDENT_ID;
    IF (v_old IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'incident not found');
    END IF;
    -- Closing needs a resolution (ticket systems may close without one: keep the old or mark true_positive)
    IF (v_state = 'closed' AND v_res IS NULL AND v_old_res IS NULL AND v_actor_type <> 'ticket') THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'closing an incident needs a resolution: ' ||
                                ARRAY_TO_STRING(SNOWFLAKE_XDR.INCIDENTS.INCIDENT_RESOLUTIONS(), ', '));
    END IF;
    IF (v_old = v_state AND (v_res IS NULL OR v_res = v_old_res)) THEN
        RETURN OBJECT_CONSTRUCT('ok', TRUE, 'message', 'incident already ' || v_state, 'changed', FALSE);
    END IF;

    UPDATE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
    SET status = :v_state,
        resolution = IFF(:v_state = 'closed', COALESCE(:v_res, resolution, 'true_positive'), resolution),
        resolution_notes = IFF(:v_state = 'closed' AND NULLIF(:P_REASON, '') IS NOT NULL, :P_REASON, resolution_notes),
        acknowledged_at = IFF(:v_state <> 'open', COALESCE(acknowledged_at, CURRENT_TIMESTAMP()), acknowledged_at),
        contained_at = IFF(:v_state IN ('contained', 'eradicated', 'recovered', 'closed'),
                           COALESCE(contained_at, CURRENT_TIMESTAMP()), contained_at),
        closed_at = IFF(:v_state = 'closed', CURRENT_TIMESTAMP(), NULL),
        reopened_count = COALESCE(reopened_count, 0) + IFF(:v_old = 'closed' AND :v_state <> 'closed', 1, 0),
        updated_at = CURRENT_TIMESTAMP()
    WHERE incident_id = :P_INCIDENT_ID;

    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS
        (incident_id, event_type, actor, actor_type, from_value, to_value, detail, source_system)
    SELECT :P_INCIDENT_ID, IFF(:v_old = 'closed' AND :v_state <> 'closed', 'reopened', 'status'), :v_actor, :v_actor_type,
           :v_old, :v_state, OBJECT_CONSTRUCT('reason', NULLIF(:P_REASON, ''), 'resolution', :v_res),
           COALESCE(NULLIF(:P_SOURCE, ''), 'xdr');

    CALL SNOWFLAKE_XDR.INCIDENTS.ENQUEUE_TICKET_OP(:P_INCIDENT_ID, 'transition',
        OBJECT_CONSTRUCT('state', :v_state, 'resolution', :v_res, 'reason', NULLIF(:P_REASON, ''), 'actor', :v_actor),
        :v_actor_type, :P_SOURCE) INTO :v_queued;

    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'changed', TRUE, 'from', :v_old, 'to', :v_state, 'tickets_queued', :v_queued,
                            'message', 'incident ' || :v_old || ' -> ' || :v_state ||
                                       IFF(:v_queued > 0, ' (' || :v_queued || ' ticket update queued)', ''));
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.ASSIGN_INCIDENT(
    P_INCIDENT_ID VARCHAR, P_ASSIGNEE VARCHAR, P_ACTOR VARCHAR, P_ACTOR_TYPE VARCHAR, P_SOURCE VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_old VARCHAR;
    v_new VARCHAR := NULLIF(TRIM(:P_ASSIGNEE), '');
    v_found NUMBER;
BEGIN
    SELECT COUNT(*), MAX(assignee) INTO :v_found, :v_old FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
    WHERE incident_id = :P_INCIDENT_ID;
    IF (v_found = 0) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'incident not found');
    END IF;
    IF (EQUAL_NULL(v_old, v_new)) THEN
        RETURN OBJECT_CONSTRUCT('ok', TRUE, 'message', 'assignee unchanged');
    END IF;
    UPDATE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS SET assignee = :v_new, updated_at = CURRENT_TIMESTAMP()
    WHERE incident_id = :P_INCIDENT_ID;
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS
        (incident_id, event_type, actor, actor_type, from_value, to_value, source_system)
    SELECT :P_INCIDENT_ID, 'assignment', COALESCE(NULLIF(:P_ACTOR, ''), CURRENT_USER()),
           COALESCE(NULLIF(:P_ACTOR_TYPE, ''), 'human'), :v_old, :v_new, COALESCE(NULLIF(:P_SOURCE, ''), 'xdr');
    CALL SNOWFLAKE_XDR.INCIDENTS.ENQUEUE_TICKET_OP(:P_INCIDENT_ID, 'comment',
        OBJECT_CONSTRUCT('text', 'Assigned to ' || COALESCE(:v_new, 'nobody') || ' in Snowflake XDR'),
        :P_ACTOR_TYPE, :P_SOURCE);
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'message', 'assigned to ' || COALESCE(:v_new, 'nobody'));
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.ADD_INCIDENT_COMMENT(
    P_INCIDENT_ID VARCHAR, P_TEXT VARCHAR, P_ACTOR VARCHAR, P_ACTOR_TYPE VARCHAR, P_SOURCE VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_text VARCHAR := LEFT(TRIM(:P_TEXT), 8000);
    v_found NUMBER;
    v_queued NUMBER := 0;
BEGIN
    IF (v_text IS NULL OR v_text = '') THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'comment is empty');
    END IF;
    SELECT COUNT(*) INTO :v_found FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE incident_id = :P_INCIDENT_ID;
    IF (v_found = 0) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'incident not found');
    END IF;
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS
        (incident_id, event_type, actor, actor_type, detail, source_system)
    SELECT :P_INCIDENT_ID, 'comment', COALESCE(NULLIF(:P_ACTOR, ''), CURRENT_USER()),
           COALESCE(NULLIF(:P_ACTOR_TYPE, ''), 'human'), OBJECT_CONSTRUCT('text', :v_text),
           COALESCE(NULLIF(:P_SOURCE, ''), 'xdr');
    CALL SNOWFLAKE_XDR.INCIDENTS.ENQUEUE_TICKET_OP(:P_INCIDENT_ID, 'comment',
        OBJECT_CONSTRUCT('text', :v_text, 'actor', COALESCE(NULLIF(:P_ACTOR, ''), CURRENT_USER())),
        :P_ACTOR_TYPE, :P_SOURCE) INTO :v_queued;
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'message', 'comment added' ||
                            IFF(:v_queued > 0, ' and queued for ' || :v_queued || ' ticket(s)', ''));
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.UPSERT_INCIDENT_TASK(
    P_INCIDENT_ID VARCHAR, P_TASK_ID VARCHAR, P_TITLE VARCHAR, P_OWNER VARCHAR, P_DUE_HOURS NUMBER,
    P_STATUS VARCHAR, P_ACTOR VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_status VARCHAR := COALESCE(NULLIF(LOWER(TRIM(:P_STATUS)), ''), 'open');
    v_id VARCHAR := NULLIF(TRIM(:P_TASK_ID), '');
    v_title VARCHAR;
BEGIN
    IF (v_status NOT IN ('open', 'done', 'cancelled')) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'status must be open, done or cancelled');
    END IF;
    IF (v_id IS NULL) THEN
        IF (NULLIF(TRIM(:P_TITLE), '') IS NULL) THEN
            RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'task title required');
        END IF;
        v_id := UUID_STRING();
        INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TASKS
            (task_id, incident_id, title, owner, due_at, status, created_by, completed_at)
        SELECT :v_id, :P_INCIDENT_ID, LEFT(TRIM(:P_TITLE), 500), NULLIF(TRIM(:P_OWNER), ''),
               IFF(:P_DUE_HOURS IS NULL, NULL, DATEADD('minute', :P_DUE_HOURS * 60, CURRENT_TIMESTAMP())),
               :v_status, COALESCE(NULLIF(:P_ACTOR, ''), CURRENT_USER()),
               IFF(:v_status = 'done', CURRENT_TIMESTAMP(), NULL)
        WHERE EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE incident_id = :P_INCIDENT_ID);
        IF (SQLROWCOUNT = 0) THEN
            RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'incident not found');
        END IF;
        v_title := LEFT(TRIM(:P_TITLE), 500);
    ELSE
        UPDATE SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TASKS
        SET status = :v_status, owner = COALESCE(NULLIF(TRIM(:P_OWNER), ''), owner),
            completed_at = IFF(:v_status = 'done', CURRENT_TIMESTAMP(), NULL)
        WHERE task_id = :v_id AND incident_id = :P_INCIDENT_ID;
        IF (SQLROWCOUNT = 0) THEN
            RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'task not found');
        END IF;
        SELECT MAX(title) INTO :v_title FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TASKS WHERE task_id = :v_id;
    END IF;
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, detail)
    SELECT :P_INCIDENT_ID, 'task', COALESCE(NULLIF(:P_ACTOR, ''), CURRENT_USER()), 'human', :v_status,
           OBJECT_CONSTRUCT('task_id', :v_id, 'title', :v_title);
    CALL SNOWFLAKE_XDR.INCIDENTS.ENQUEUE_TICKET_OP(:P_INCIDENT_ID, 'comment',
        OBJECT_CONSTRUCT('text', 'Response task ' || :v_status || ': ' || :v_title), 'human', NULL);
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'task_id', :v_id, 'message', 'task ' || :v_status || ': ' || :v_title);
END;
$$;

-- Timeline for one incident: lifecycle events merged with attacker activity
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TIMELINE(P_INCIDENT_ID VARCHAR)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_inc VARIANT;
    v_events VARIANT;
    v_attack VARIANT;
    v_tasks VARIANT;
    v_tickets VARIANT;
BEGIN
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('incident_id', incident_id, 'title', title, 'status', status, 'priority', priority,
                                'severity', severity, 'assignee', assignee, 'resolution', resolution,
                                'created_at', created_at, 'acknowledged_at', acknowledged_at,
                                'contained_at', contained_at, 'closed_at', closed_at))[0]
    INTO :v_inc FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE incident_id = :P_INCIDENT_ID;
    IF (v_inc IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('error', 'incident not found');
    END IF;
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('time', event_time, 'type', event_type, 'actor', actor, 'actor_type', actor_type,
                                      'from', from_value, 'to', to_value, 'detail', detail, 'source', source_system))
               WITHIN GROUP (ORDER BY event_time)
    INTO :v_events FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS WHERE incident_id = :P_INCIDENT_ID;
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('time', event_time, 'technique', technique_id, 'description', action_summary,
                                      'actor', actor_entity, 'target', target_entity))
               WITHIN GROUP (ORDER BY event_time)
    INTO :v_attack FROM (SELECT * FROM SNOWFLAKE_XDR.INCIDENTS.ATTACKER_TIMELINE WHERE incident_id = :P_INCIDENT_ID
                         ORDER BY event_time LIMIT 100);
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('task_id', task_id, 'title', title, 'owner', owner, 'status', status, 'due_at', due_at))
    INTO :v_tasks FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TASKS WHERE incident_id = :P_INCIDENT_ID;
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT('connection_id', connection_id, 'key', external_key, 'url', url,
                                      'state', remote_state, 'sync_status', sync_status, 'error', last_error))
    INTO :v_tickets FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS WHERE incident_id = :P_INCIDENT_ID;
    RETURN OBJECT_CONSTRUCT('incident', :v_inc, 'events', COALESCE(:v_events, []), 'attacker_activity', COALESCE(:v_attack, []),
                            'tasks', COALESCE(:v_tasks, []), 'tickets', COALESCE(:v_tickets, []));
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. SLAs
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.INCIDENTS.V_INCIDENT_SLA AS
SELECT i.incident_id, i.title, i.priority, i.status, i.assignee, i.created_at,
       DATEADD('minute', p.ack_minutes, i.created_at) AS ack_due_at,
       DATEADD('minute', p.contain_minutes, i.created_at) AS contain_due_at,
       DATEADD('minute', p.resolve_minutes, i.created_at) AS resolve_due_at,
       CASE
           WHEN i.status = 'closed' THEN NULL
           WHEN i.acknowledged_at IS NULL THEN DATEADD('minute', p.ack_minutes, i.created_at)
           WHEN i.contained_at IS NULL THEN DATEADD('minute', p.contain_minutes, i.created_at)
           ELSE DATEADD('minute', p.resolve_minutes, i.created_at)
       END AS next_due_at,
       CASE
           WHEN i.status = 'closed' THEN NULL
           WHEN i.acknowledged_at IS NULL THEN 'acknowledge'
           WHEN i.contained_at IS NULL THEN 'contain'
           ELSE 'resolve'
       END AS next_milestone,
       COALESCE(i.acknowledged_at, CURRENT_TIMESTAMP()) > DATEADD('minute', p.ack_minutes, i.created_at) AS ack_breached,
       COALESCE(i.contained_at, CURRENT_TIMESTAMP()) > DATEADD('minute', p.contain_minutes, i.created_at) AS contain_breached,
       COALESCE(i.closed_at, CURRENT_TIMESTAMP()) > DATEADD('minute', p.resolve_minutes, i.created_at) AS resolve_breached
FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS i
LEFT JOIN SNOWFLAKE_XDR.INCIDENTS.INCIDENT_SLA_POLICY p ON p.priority = COALESCE(i.priority, 'P3');

-- Record each breach once as an event (and on linked tickets as a comment)
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.CHECK_INCIDENT_SLAS()
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    n NUMBER;
BEGIN
    CREATE OR REPLACE TEMPORARY TABLE XDR_SLA_NEW AS
    WITH b AS (
        SELECT incident_id, 'acknowledge' AS milestone FROM SNOWFLAKE_XDR.INCIDENTS.V_INCIDENT_SLA
        WHERE status <> 'closed' AND ack_breached
        UNION ALL
        SELECT incident_id, 'contain' FROM SNOWFLAKE_XDR.INCIDENTS.V_INCIDENT_SLA WHERE status <> 'closed' AND contain_breached
        UNION ALL
        SELECT incident_id, 'resolve' FROM SNOWFLAKE_XDR.INCIDENTS.V_INCIDENT_SLA WHERE status <> 'closed' AND resolve_breached
    )
    SELECT b.incident_id, b.milestone
    FROM b
    LEFT JOIN SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS e
      ON e.incident_id = b.incident_id AND e.event_type = 'sla_breach' AND e.to_value = b.milestone
    WHERE e.event_id IS NULL;
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, detail)
    SELECT incident_id, 'sla_breach', 'sla-monitor', 'system', milestone,
           OBJECT_CONSTRUCT('text', 'SLA breached: ' || milestone || ' deadline passed')
    FROM XDR_SLA_NEW;
    n := SQLROWCOUNT;
    INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_OUTBOX (incident_id, connection_id, op, payload)
    SELECT b.incident_id, t.connection_id, 'comment',
           OBJECT_CONSTRUCT('text', 'SLA breached: the ' || b.milestone || ' deadline for this priority has passed.')
    FROM XDR_SLA_NEW b JOIN SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS t ON t.incident_id = b.incident_id;
    RETURN n || ' new SLA breaches';
END;
$$;

-- ---------------------------------------------------------------------------
-- 5. Metrics
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.INCIDENTS.V_INCIDENT_METRICS AS
SELECT COALESCE(i.priority, 'P3') AS priority,
       COUNT(*) AS incidents,
       COUNT_IF(i.status <> 'closed') AS open_incidents,
       ROUND(AVG(DATEDIFF('minute', i.created_at, i.acknowledged_at)), 1) AS mtta_minutes,
       ROUND(AVG(DATEDIFF('minute', i.created_at, i.contained_at)), 1) AS mttc_minutes,
       ROUND(AVG(DATEDIFF('minute', i.created_at, i.closed_at)), 1) AS mttr_minutes,
       ROUND(1 - COUNT_IF(s.ack_breached OR s.contain_breached OR s.resolve_breached) / NULLIF(COUNT(*), 0), 3)
           AS sla_compliance,
       ROUND(COUNT_IF(COALESCE(i.reopened_count, 0) > 0) / NULLIF(COUNT_IF(i.closed_at IS NOT NULL OR i.reopened_count > 0), 0), 3)
           AS reopen_rate,
       COUNT_IF(i.resolution = 'true_positive') AS true_positive,
       COUNT_IF(i.resolution IN ('false_positive', 'benign')) AS not_real,
       (SELECT COUNT(*) FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS t
         JOIN SNOWFLAKE_XDR.INCIDENTS.INCIDENTS x ON x.incident_id = t.incident_id
         WHERE COALESCE(x.priority, 'P3') = COALESCE(i.priority, 'P3')) AS tickets
FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS i
JOIN SNOWFLAKE_XDR.INCIDENTS.V_INCIDENT_SLA s ON s.incident_id = i.incident_id
GROUP BY 1;

-- ---------------------------------------------------------------------------
-- 6. Incident report: facts from SQL, narrative from Cortex
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.GENERATE_INCIDENT_REPORT(P_INCIDENT_ID VARCHAR, P_ACTOR VARCHAR)
RETURNS VARIANT
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'main'
EXECUTE AS OWNER
AS
$$
import json
from datetime import datetime

DB = "SNOWFLAKE_XDR"


def q(s, sql, params=None):
    return [r.as_dict() for r in s.sql(sql, params=params or []).collect()]


def fmt_t(v):
    if v is None:
        return "-"
    return v.strftime("%Y-%m-%d %H:%M") if isinstance(v, datetime) else str(v)[:16]


def dur(a, b):
    if a is None or b is None:
        return "-"
    m = int((b - a).total_seconds() // 60)
    return f"{m // 60}h {m % 60}m" if m >= 60 else f"{m}m"


def md_escape(v):
    return str(v if v is not None else "-").replace("|", "\\|").replace("\n", " ")


def table(rows, cols):
    if not rows:
        return "_none_\n"
    out = "| " + " | ".join(c[1] for c in cols) + " |\n|" + "---|" * len(cols) + "\n"
    for r in rows:
        out += "| " + " | ".join(md_escape(c[2](r) if len(c) > 2 else r.get(c[0])) for c in cols) + " |\n"
    return out


def main(s, incident_id, actor):
    inc = q(s, f"SELECT * FROM {DB}.INCIDENTS.INCIDENTS WHERE incident_id = ?", [incident_id])
    if not inc:
        return {"ok": False, "message": "incident not found"}
    inc = inc[0]
    findings = q(s, f"""
        SELECT f.finding_id, f.rule_id, COALESCE(r.rule_name, c.name, f.rule_id) AS rule_name, f.severity,
               f.event_time, f.src, f.dest, f.user_name, f.mitre_technique_id, f.description, f.disposition,
               f.conf_band, f.conf_score, f.evidence_count
        FROM {DB}.INCIDENTS.INCIDENT_FINDINGS x
        JOIN {DB}.DETECTIONS.DETECTION_FINDINGS f ON f.finding_id = x.finding_id
        LEFT JOIN {DB}.DETECTIONS.DETECTION_RULES r ON r.rule_id = f.rule_id
        LEFT JOIN {DB}.DETECTIONS.CUSTOM_RULES c ON c.rule_id = f.rule_id
        WHERE x.incident_id = ? ORDER BY f.event_time LIMIT 50""", [incident_id])
    chain = q(s, f"""SELECT * FROM {DB}.INCIDENTS.KILL_CHAIN_PROGRESSION WHERE incident_id = ? ORDER BY stage_order""",
              [incident_id])
    events = q(s, f"""SELECT event_time, event_type, actor, actor_type, from_value, to_value, detail, source_system
                     FROM {DB}.INCIDENTS.INCIDENT_EVENTS WHERE incident_id = ? ORDER BY event_time""", [incident_id])
    tasks = q(s, f"""SELECT title, owner, status, due_at, completed_at FROM {DB}.INCIDENTS.INCIDENT_TASKS
                    WHERE incident_id = ? ORDER BY created_at""", [incident_id])
    tickets = q(s, f"""SELECT connection_id, external_key, url, remote_state FROM {DB}.INCIDENTS.INCIDENT_TICKETS
                      WHERE incident_id = ?""", [incident_id])
    sla = q(s, f"SELECT * FROM {DB}.INCIDENTS.V_INCIDENT_SLA WHERE incident_id = ?", [incident_id])
    sla = sla[0] if sla else {}
    entities = sorted({e for f in findings for e in (f["SRC"], f["DEST"], f["USER_NAME"]) if e})
    techniques = sorted({f["MITRE_TECHNIQUE_ID"] for f in findings if f["MITRE_TECHNIQUE_ID"]})
    comments = [e for e in events if e["EVENT_TYPE"] == "comment"]

    facts = {
        "incident_id": incident_id, "title": inc["TITLE"], "priority": inc["PRIORITY"], "severity": inc["SEVERITY"],
        "status": inc["STATUS"], "resolution": inc["RESOLUTION"], "assignee": inc["ASSIGNEE"],
        "first_seen": fmt_t(inc["FIRST_SEEN"]), "last_seen": fmt_t(inc["LAST_SEEN"]),
        "created_at": fmt_t(inc["CREATED_AT"]), "acknowledged_at": fmt_t(inc.get("ACKNOWLEDGED_AT")),
        "contained_at": fmt_t(inc.get("CONTAINED_AT")), "closed_at": fmt_t(inc.get("CLOSED_AT")),
        "time_to_acknowledge": dur(inc["CREATED_AT"], inc.get("ACKNOWLEDGED_AT")),
        "time_to_contain": dur(inc["CREATED_AT"], inc.get("CONTAINED_AT")),
        "time_to_close": dur(inc["CREATED_AT"], inc.get("CLOSED_AT")),
        "sla_breaches": [m for m, k in (("acknowledge", "ACK_BREACHED"), ("contain", "CONTAIN_BREACHED"),
                                        ("resolve", "RESOLVE_BREACHED")) if sla.get(k)],
        "kill_chain_stage": inc["KILL_CHAIN_STAGE"], "finding_count": len(findings),
        "entities": entities[:30], "mitre_techniques": techniques,
        "rules": sorted({f["RULE_NAME"] for f in findings}),
        "high_confidence_findings": sum(1 for f in findings if f["CONF_BAND"] == "high"),
        "tasks_done": sum(1 for t in tasks if t["STATUS"] == "done"), "tasks_open": sum(1 for t in tasks if t["STATUS"] == "open"),
        "tickets": [f"{t['CONNECTION_ID']}:{t['EXTERNAL_KEY']}" for t in tickets],
    }

    model = (q(s, f"""SELECT MAX(setting_value) AS m FROM {DB}.REFERENCE.PLATFORM_SETTINGS
                     WHERE setting_key = 'report_model'""")[0]["M"] or "claude-sonnet-4-5")
    prompt = (
        "You write the narrative sections of a security incident report. Use ONLY the facts below; do not invent "
        "hosts, users, times, counts or actions. If something is unknown, say it is not recorded. Be concise and "
        "factual, written for a CISO and an incident responder.\n\nFACTS:\n" + json.dumps(facts, default=str) +
        "\n\nFINDINGS (chronological):\n" + json.dumps([{k: f[k] for k in ("EVENT_TIME", "RULE_NAME", "SEVERITY", "SRC",
                                                         "DEST", "USER_NAME", "MITRE_TECHNIQUE_ID", "DESCRIPTION")}
                                                         for f in findings[:30]], default=str)[:8000] +
        "\n\nANALYST COMMENTS:\n" + json.dumps([(c["ACTOR"], (c["DETAIL"] or {}) if isinstance(c["DETAIL"], dict)
                                               else json.loads(c["DETAIL"] or "{}")) for c in comments[-20:]],
                                               default=str)[:3000] +
        '\n\nReturn ONLY JSON: {"executive_summary": "3-5 sentences", "attack_narrative": "what happened, in order",'
        ' "impact": "1-3 sentences", "root_cause": "1-3 sentences or not yet determined",'
        ' "lessons_learned": ["..."], "detection_gaps": ["techniques or data sources that were missing or late"]}')
    narrative, err = {}, None
    try:
        txt = s.sql("SELECT SNOWFLAKE.CORTEX.COMPLETE(?, ?) AS r", params=[model, prompt]).collect()[0]["R"] or ""
        a, b = txt.find("{"), txt.rfind("}")
        narrative = json.loads(txt[a:b + 1]) if a >= 0 and b > a else {}
    except Exception as e:  # the report still renders from facts
        err = str(e)[:300]

    def section(key, title):
        v = narrative.get(key)
        if not v:
            return f"## {title}\n\n_not available_\n\n"
        if isinstance(v, list):
            return f"## {title}\n\n" + "".join(f"- {x}\n" for x in v) + "\n"
        return f"## {title}\n\n{v}\n\n"

    md = f"# Incident report: {inc['TITLE']}\n\n"
    md += (f"| Incident | Priority | Severity | Status | Resolution | Assignee |\n|---|---|---|---|---|---|\n"
           f"| `{incident_id[:8]}` | {md_escape(inc['PRIORITY'])} | {md_escape(inc['SEVERITY'])} | {md_escape(inc['STATUS'])} "
           f"| {md_escape(inc['RESOLUTION'])} | {md_escape(inc['ASSIGNEE'])} |\n\n")
    md += section("executive_summary", "Executive summary")
    md += ("## Response times\n\n| Milestone | When | Time from creation | SLA |\n|---|---|---|---|\n"
           f"| Attack first seen | {facts['first_seen']} | | |\n"
           f"| Incident created | {facts['created_at']} | | |\n"
           f"| Acknowledged | {facts['acknowledged_at']} | {facts['time_to_acknowledge']} | "
           f"{'breached' if 'acknowledge' in facts['sla_breaches'] else 'met'} |\n"
           f"| Contained | {facts['contained_at']} | {facts['time_to_contain']} | "
           f"{'breached' if 'contain' in facts['sla_breaches'] else 'met'} |\n"
           f"| Closed | {facts['closed_at']} | {facts['time_to_close']} | "
           f"{'breached' if 'resolve' in facts['sla_breaches'] else 'met'} |\n\n")
    md += section("attack_narrative", "What happened")
    md += "## Kill chain\n\n" + table(chain, [("TACTIC_NAME", "Stage"), ("FIRST_OBSERVED", "First seen", lambda r: fmt_t(r.get("FIRST_OBSERVED"))),
                                              ("FINDING_COUNT", "Findings")]) + "\n"
    md += (f"## Scope\n\n- **Entities ({len(entities)}):** {', '.join(f'`{e}`' for e in entities[:30]) or '-'}\n"
           f"- **MITRE ATT&CK:** {', '.join(techniques) or '-'}\n"
           f"- **Detections:** {len(findings)} findings from {len(facts['rules'])} rules, "
           f"{facts['high_confidence_findings']} high confidence\n\n")
    md += section("impact", "Impact")
    md += "## Evidence\n\n" + table(findings[:25], [
        ("EVENT_TIME", "Time", lambda r: fmt_t(r["EVENT_TIME"])), ("RULE_NAME", "Detection"), ("SEVERITY", "Sev"),
        ("CONF_BAND", "Confidence"), ("MITRE_TECHNIQUE_ID", "Technique"),
        ("ENTITY", "Entity", lambda r: r["USER_NAME"] or r["DEST"] or r["SRC"]),
        ("DESCRIPTION", "Description", lambda r: (r["DESCRIPTION"] or "")[:140])]) + "\n"
    md += "## Response actions\n\n" + table(tasks, [("TITLE", "Task"), ("OWNER", "Owner"), ("STATUS", "Status"),
                                                    ("COMPLETED_AT", "Completed", lambda r: fmt_t(r["COMPLETED_AT"]))]) + "\n"
    md += "## Case timeline\n\n" + table(
        [e for e in events if e["EVENT_TYPE"] != "comment"][-40:],
        [("EVENT_TIME", "Time", lambda r: fmt_t(r["EVENT_TIME"])), ("EVENT_TYPE", "Event"),
         ("CHANGE", "Change", lambda r: f"{r['FROM_VALUE'] or ''} -> {r['TO_VALUE']}" if r["TO_VALUE"] else ""),
         ("ACTOR", "By", lambda r: f"{r['ACTOR']} ({r['ACTOR_TYPE']})"), ("SOURCE_SYSTEM", "Via")]) + "\n"
    md += section("root_cause", "Root cause")
    md += section("lessons_learned", "Lessons learned")
    md += section("detection_gaps", "Detection gaps")
    if tickets:
        md += "## Tickets\n\n" + "".join(f"- {t['CONNECTION_ID']}: [{t['EXTERNAL_KEY']}]({t['URL']}) ({t['REMOTE_STATE']})\n"
                                         for t in tickets) + "\n"
    md += (f"---\n_Generated by Snowflake XDR at {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC. Figures come "
           f"from XDR tables; narrative sections were drafted by {model}{' (narrative unavailable: ' + err + ')' if err else ''}._\n")

    rid = s.sql("SELECT UUID_STRING() AS id").collect()[0]["ID"]
    s.sql(f"""INSERT INTO {DB}.INCIDENTS.INCIDENT_REPORTS (report_id, incident_id, created_by, title, markdown, facts, narrative, model)
              SELECT ?, ?, ?, ?, ?, PARSE_JSON(?), PARSE_JSON(?), ?""",
          params=[rid, incident_id, actor or "system", f"Incident report: {inc['TITLE']}", md,
                  json.dumps(facts, default=str), json.dumps(narrative, default=str), model]).collect()
    s.sql(f"UPDATE {DB}.INCIDENTS.INCIDENTS SET latest_report_id = ? WHERE incident_id = ?", params=[rid, incident_id]).collect()
    s.sql(f"""INSERT INTO {DB}.INCIDENTS.INCIDENT_EVENTS (incident_id, event_type, actor, actor_type, to_value, detail)
              SELECT ?, 'report', ?, 'human', ?, OBJECT_CONSTRUCT('report_id', ?)""",
          params=[incident_id, actor or "system", rid, rid]).collect()
    s.sql(f"""INSERT INTO {DB}.INCIDENTS.INCIDENT_OUTBOX (incident_id, connection_id, op, payload)
              SELECT incident_id, connection_id, 'attach_report', OBJECT_CONSTRUCT('report_id', ?)
              FROM {DB}.INCIDENTS.INCIDENT_TICKETS WHERE incident_id = ?""", params=[rid, incident_id]).collect()
    return {"ok": True, "report_id": rid, "message": f"report generated ({len(md)} chars)" + (f"; narrative failed: {err}" if err else ""),
            "tickets": len(tickets)}
$$;

-- ---------------------------------------------------------------------------
-- 7. Backfill: every existing incident gets a 'created' event
-- ---------------------------------------------------------------------------
INSERT INTO SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS (incident_id, event_time, event_type, actor, actor_type, to_value, detail)
SELECT i.incident_id, i.created_at, 'created', 'correlation_engine', 'system', i.status,
       OBJECT_CONSTRUCT('priority', i.priority, 'severity', i.severity)
FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS i
WHERE NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_EVENTS e
                  WHERE e.incident_id = i.incident_id AND e.event_type = 'created');
