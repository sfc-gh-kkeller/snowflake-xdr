-- ============================================================================
-- Snowflake XDR - 16: Attack Graph & Lateral Movement
-- ============================================================================
-- Unified event-edge model over all telemetry, recursive attack-path tracing,
-- door-rattling (fan-out) detection, and the AI campaign narrator.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Unified edge model: every telemetry event becomes a graph edge
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.ATTACK_PATH_EDGES (
    edge_id         VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    src_entity      VARCHAR(255) NOT NULL,
    dst_entity      VARCHAR(255) NOT NULL,
    edge_type       VARCHAR(30),      -- auth, network, process, dns
    edge_detail     VARCHAR(500),     -- protocol/port/app/process context
    _time           TIMESTAMP_LTZ NOT NULL,
    event_id        VARCHAR(100),
    user_name       VARCHAR(255),
    action          VARCHAR(50),      -- success/allowed vs failure/blocked
    built_at         TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.BUILD_ATTACK_GRAPH()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_edges NUMBER;
BEGIN
    DELETE FROM SNOWFLAKE_XDR.DETECTIONS.ATTACK_PATH_EDGES;

    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.ATTACK_PATH_EDGES
        (src_entity, dst_entity, edge_type, edge_detail, _time, event_id, user_name, action)
    -- Auth: attacker host -> account (login attempt), then account -> target host.
    -- Normalize: strip any stale 'host:' prefixes, re-add only when not an IP.
    SELECT CASE WHEN src REGEXP '^[0-9]+\\.' THEN REPLACE(src, 'host:', '')
                ELSE 'host:' || REPLACE(src, 'host:', '') END,
           'user:' || user_name, 'auth',
           app || ' login ' || action, _time, event_id, user_name, action
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE user_name IS NOT NULL AND src IS NOT NULL
      AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    UNION ALL
    SELECT 'user:' || user_name,
           CASE WHEN COALESCE(dest, 'unknown') REGEXP '^[0-9]+\\.'
                THEN REPLACE(dest, 'host:', '')
                ELSE 'host:' || REPLACE(COALESCE(dest, 'unknown'), 'host:', '') END,
           'auth',
           app || ' access to ' || COALESCE(dest, 'unknown'), _time, event_id, user_name, action
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE user_name IS NOT NULL
      AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    -- Network: host/IP -> host/IP (the "doors"). Prefer the hostname when
    -- present so network edges connect to auth edges of the same host.
    UNION ALL
    SELECT CASE WHEN COALESCE(src, '') REGEXP '^[0-9]+\\.' THEN COALESCE(src, src_ip)
                ELSE 'host:' || COALESCE(src, src_ip) END,
           CASE WHEN COALESCE(dest, '') REGEXP '^[0-9]+\\.' THEN COALESCE(dest, dest_ip)
                ELSE 'host:' || COALESCE(dest, dest_ip) END,
           'network',
           protocol || '/' || COALESCE(dest_port::VARCHAR, '') || ' ' || COALESCE(action, ''),
           _time, event_id, NULL, action
    FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    WHERE COALESCE(src_ip, src) IS NOT NULL AND COALESCE(dest_ip, dest) IS NOT NULL
      AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    -- Endpoint: host -> process
    UNION ALL
    SELECT 'host:' || host, 'proc:' || process_name, 'process',
           'process ' || COALESCE(action, 'run'), _time, event_id, NULL, action
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE host IS NOT NULL AND process_name IS NOT NULL
      AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    -- DNS: host -> queried domain (C2 / tunneling edges)
    UNION ALL
    SELECT 'host:' || COALESCE(host, src), 'domain:' || query, 'dns',
           'dns query', _time, event_id, NULL, action
    FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
    WHERE COALESCE(host, src) IS NOT NULL AND query IS NOT NULL
      AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP());

    SELECT COUNT(*) INTO :v_edges FROM SNOWFLAKE_XDR.DETECTIONS.ATTACK_PATH_EDGES;
    RETURN 'Attack graph built: ' || :v_edges || ' edges (7-day window).';
END;
$$;

-- ---------------------------------------------------------------------------
-- 2. Door-rattling scan: one source trying many doors (set-based, no loops)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DOOR_RATTLING_SCAN()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_windows NUMBER;
BEGIN
    -- Sources touching many distinct doors in a 1-hour window where most fail
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        (finding_id, rule_id, description, category, severity,
         mitre_tactic_id, mitre_technique_id, user_name, src,
         event_time, detection_time, detection_source, confidence,
         evidence, risk_score, status)
    SELECT
        UUID_STRING(),
        'GRAPH-RATTLE-001',
        'Door rattling: ' || w.src_entity || ' touched ' || w.doors_tried
            || ' distinct targets in one hour, ' || w.failed || ' failed',
        CASE WHEN w.edge_type = 'auth' THEN 'identity' ELSE 'network' END,
        IFF(w.doors_tried >= 20, 4, 3),
        'TA0007',
        'T1110',
        w.src_entity,
        w.src_entity,
        w.window_start,
        CURRENT_TIMESTAMP(),
        'attack_graph',
        80,
        OBJECT_CONSTRUCT(
            'src', w.src_entity,
            'edge_type', w.edge_type,
            'doors_tried', w.doors_tried,
            'doors_opened', w.doors_opened,
            'failed', w.failed,
            'window_start', w.window_start
        ),
        IFF(w.doors_tried >= 20, 70, 55),
        'new'
    FROM (
        SELECT
            src_entity,
            edge_type,
            TIME_SLICE(_time::TIMESTAMP_NTZ, 1, 'HOUR', 'START') AS window_start,
            COUNT(DISTINCT dst_entity) AS doors_tried,
            COUNT(DISTINCT IFF(action IN ('success', 'allowed'), dst_entity, NULL)) AS doors_opened,
            COUNT(*) AS attempts,
            COUNT(IFF(action IN ('failure', 'blocked', 'dropped'), 1, NULL)) AS failed
        FROM SNOWFLAKE_XDR.DETECTIONS.ATTACK_PATH_EDGES
        WHERE edge_type IN ('auth', 'network')
          AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
        GROUP BY src_entity, edge_type, TIME_SLICE(_time::TIMESTAMP_NTZ, 1, 'HOUR', 'START')
        HAVING COUNT(DISTINCT dst_entity) >= 5
           AND COUNT(IFF(action IN ('failure', 'blocked', 'dropped'), 1, NULL))
               / COUNT(*) >= 0.5
    ) w
    -- Don't re-alert on the same source+window
    WHERE NOT EXISTS (
        SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
        WHERE f.rule_id = 'GRAPH-RATTLE-001'
          AND f.src = w.src_entity
          AND f.event_time = w.window_start
    );

    v_windows := SQLROWCOUNT;
    RETURN 'Door-rattling scan complete. New findings: ' || :v_windows;
END;
$$;

-- ---------------------------------------------------------------------------
-- 3. Recursive attack-path tracing: how did the attacker get from A to B?
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.TRACE_ATTACK_PATHS(
    P_START_ENTITY VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
AS
$$
BEGIN
    -- Recursive CTE: time-ordered walks up to 5 hops from the start entity.
    -- Returns per-hop path rows; the UI renders them as a graph.
    LET paths VARIANT;
    WITH RECURSIVE walk AS (
        SELECT
            src_entity,
            dst_entity,
            edge_type,
            edge_detail,
            _time,
            1 AS hop,
            ARRAY_CONSTRUCT(src_entity, dst_entity) AS path_entities,
            ARRAY_CONSTRUCT(OBJECT_CONSTRUCT(
                'type', edge_type, 'detail', edge_detail,
                'time', _time, 'action', action)) AS path_edges,
            action
        FROM SNOWFLAKE_XDR.DETECTIONS.ATTACK_PATH_EDGES
        WHERE src_entity = :P_START_ENTITY
          AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
        UNION ALL
        SELECT
            w.dst_entity,
            e.dst_entity,
            e.edge_type,
            e.edge_detail,
            e._time,
            w.hop + 1,
            ARRAY_APPEND(w.path_entities, e.dst_entity),
            ARRAY_APPEND(w.path_edges, OBJECT_CONSTRUCT(
                'type', e.edge_type, 'detail', e.edge_detail,
                'time', e._time, 'action', e.action)),
            e.action
        FROM walk w
        JOIN SNOWFLAKE_XDR.DETECTIONS.ATTACK_PATH_EDGES e
          ON e.src_entity = w.dst_entity
         AND e._time > w._time              -- strictly forward in time
         AND ARRAY_POSITION(TO_VARIANT(e.dst_entity), w.path_entities) IS NULL  -- no cycles
        WHERE w.hop < 5
    )
    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
               'hops', hop,
               'end_entity', dst_entity,
               'entities', path_entities,
               'edges', path_edges,
               'first_seen', path_edges[0]:time,
               'last_seen', _time,
               'suspicious', IFF(
                   ARRAY_POSITION(TO_VARIANT('domain:'), path_entities) IS NOT NULL, TRUE,
                   IFF(hop >= 3, TRUE, FALSE))
           ))
    INTO :paths
    FROM (
        SELECT * FROM walk
        ORDER BY hop DESC, _time ASC
        LIMIT 25
    ) top_paths;

    RETURN OBJECT_CONSTRUCT(
        'start_entity', :P_START_ENTITY,
        'paths', COALESCE(paths, ARRAY_CONSTRUCT())
    );
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. AI campaign narrator: turn correlated findings into an attacker story
-- ---------------------------------------------------------------------------
-- The latest AI campaign story lives in its own column. Earlier versions
-- appended stories to DESCRIPTION, which overflowed VARCHAR(4000) after a few
-- regenerations; the UPDATE below strips any such appended stories (idempotent).
ALTER TABLE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS ADD COLUMN IF NOT EXISTS ai_campaign_story VARCHAR;
ALTER TABLE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS ADD COLUMN IF NOT EXISTS ai_campaign_story_at TIMESTAMP_LTZ;
UPDATE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
SET description = RTRIM(LEFT(description, POSITION('## Campaign Narrative' IN description) - 1))
WHERE POSITION('## Campaign Narrative' IN description) > 1;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.INCIDENTS.AI_CAMPAIGN_STORY(
    P_INCIDENT_ID VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
AS
$$
DECLARE
    v_incident VARCHAR;
    v_findings VARCHAR;
    v_paths VARCHAR;
    v_story VARCHAR;
BEGIN
    SELECT 'Incident: ' || COALESCE(title, '') || ' | Severity ' || severity
           || ' | Primary entity: ' || COALESCE(primary_entity, 'unknown')
           || ' | Kill chain stage: ' || COALESCE(kill_chain_stage, 'unknown')
           || ' | First seen: ' || first_seen || ' | Last seen: ' || last_seen
    INTO :v_incident
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
    WHERE incident_id = :P_INCIDENT_ID;

    IF (v_incident IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('error', 'incident not found');
    END IF;

    SELECT 'Findings (chronological): ' || ARRAY_TO_STRING(ARRAY_AGG(
        CONCAT(' - [', COALESCE(mitre_tactic_id, '?'), '] ',
               TO_CHAR(event_time, 'HH24:MI'), ' ',
               COALESCE(user_name, src, dest), ': ',
               LEFT(description, 80))), ' | ')
    INTO :v_findings
    FROM (
        SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE incident_id = :P_INCIDENT_ID
        ORDER BY event_time
    );

    LET v_primary VARCHAR;
    SELECT COALESCE(primary_entity, '') INTO :v_primary
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
    WHERE incident_id = :P_INCIDENT_ID;

    -- Trace attack paths from the incident's primary entity for graph context
    LET path_call RESULTSET := (
        CALL SNOWFLAKE_XDR.DETECTIONS.TRACE_ATTACK_PATHS(:v_primary)
    );
    FOR rec IN path_call DO
        v_paths := TO_JSON(rec);
    END FOR;

    SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3.1-70b',
        'You are a senior SOC incident narrator. Write the attacker story for this security incident.
Explain how the events connect as a campaign: initial access, what the attacker tried, how they moved, and what the kill-chain stage means.

INCIDENT: ' || :v_incident || '

' || COALESCE(:v_findings, 'No findings linked.') || '

ATTACK GRAPH PATHS from the primary entity (JSON): ' || COALESCE(:v_paths, 'none') || '

Write a chronological narrative in markdown with:
## Campaign Narrative
2-3 short paragraphs telling the story of the attack.
## How It Connects
Bullets linking each finding to the next stage of the attack.
## Analyst Next Steps
2-3 concrete next steps for the responding analyst.
Under 300 words. Be specific - use the actual entities, times, and techniques.')
    INTO :v_story;

    -- Persist the latest story in its own column (overwritten, never appended)
    UPDATE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
    SET ai_campaign_story = :v_story,
        ai_campaign_story_at = CURRENT_TIMESTAMP()
    WHERE incident_id = :P_INCIDENT_ID;

    RETURN OBJECT_CONSTRUCT('story', :v_story);
END;
$$;
