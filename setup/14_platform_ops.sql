-- ============================================================================
-- Snowflake XDR - Entity Investigation, IOC Management, Health Monitoring
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- Entity search: normalized search across all telemetry for a user/host/IP
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.SEARCH_ENTITY(
    P_ENTITY VARCHAR,
    P_DAYS NUMBER DEFAULT 7
)
RETURNS VARIANT
LANGUAGE SQL
AS
$$
DECLARE
    results ARRAY;
BEGIN
    LET events ARRAY;
    events := (
        SELECT ARRAY_AGG(event) WITHIN GROUP (ORDER BY event:time::VARCHAR)
        FROM (
            SELECT OBJECT_CONSTRUCT(
                       'time', _time, 'source', 'authentication', 'action', action,
                       'user', user_name, 'src', src, 'dest', dest, 'app', app,
                       'country', geo_country, 'detail', COALESCE(signature, reason)) AS event
            FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
            WHERE (:P_ENTITY IN (user_name, src, dest))
              AND _time > DATEADD('day', -:P_DAYS, CURRENT_TIMESTAMP())
            UNION ALL
            SELECT OBJECT_CONSTRUCT(
                       'time', _time, 'source', 'endpoint_process', 'action', action,
                       'user', user_name, 'src', dest, 'dest', dest,
                       'process', process_name, 'detail', COALESCE(process, '')) AS event
            FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
            WHERE (:P_ENTITY IN (user_name, dest))
              AND _time > DATEADD('day', -:P_DAYS, CURRENT_TIMESTAMP())
            UNION ALL
            SELECT OBJECT_CONSTRUCT(
                       'time', _time, 'source', 'network', 'action', direction,
                       'src', src_ip, 'dest', dest_ip, 'protocol', protocol,
                       'detail', 'bytes_out=' || COALESCE(bytes_out::VARCHAR, '0')) AS event
            FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
            WHERE (:P_ENTITY IN (src_ip, dest_ip))
              AND _time > DATEADD('day', -:P_DAYS, CURRENT_TIMESTAMP())
            UNION ALL
            SELECT OBJECT_CONSTRUCT(
                       'time', _time, 'source', 'dns', 'src', src, 'query', query,
                       'detail', query_type) AS event
            FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
            WHERE (:P_ENTITY = src)
              AND _time > DATEADD('day', -:P_DAYS, CURRENT_TIMESTAMP())
            UNION ALL
            SELECT OBJECT_CONSTRUCT(
                       'time', _time, 'source', 'web', 'src', src, 'url', url,
                       'status', status, 'detail', http_method) AS event
            FROM SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY
            WHERE (:P_ENTITY IN (src, dest))
              AND _time > DATEADD('day', -:P_DAYS, CURRENT_TIMESTAMP())
            UNION ALL
            SELECT OBJECT_CONSTRUCT(
                       'time', _time, 'source', 'cloud_api', 'user', user_name,
                       'action', action, 'object', object, 'detail', result) AS event
            FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API
            WHERE (:P_ENTITY IN (user_name, src, dest))
              AND _time > DATEADD('day', -:P_DAYS, CURRENT_TIMESTAMP())
            UNION ALL
            SELECT OBJECT_CONSTRUCT(
                       'time', detection_time, 'source', 'xdr_finding',
                       'action', status, 'detail', description, 'severity', severity,
                       'rule', rule_id) AS event
            FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
            WHERE (:P_ENTITY IN (user_name, src, dest))
              AND detection_time > DATEADD('day', -:P_DAYS, CURRENT_TIMESTAMP())
        )
    );

    RETURN OBJECT_CONSTRUCT('entity', :P_ENTITY, 'days', :P_DAYS, 'events', COALESCE(:events, ARRAY_CONSTRUCT()));
END;
$$;

-- ---------------------------------------------------------------------------
-- AI investigation: LLM summary of an entity's activity
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AI_INVESTIGATE_ENTITY(
    P_ENTITY VARCHAR,
    P_DAYS NUMBER DEFAULT 7
)
RETURNS VARIANT
LANGUAGE SQL
AS
$$
DECLARE
    entity_json VARIANT;
    ai_response VARCHAR;
    v_sample VARCHAR;
    v_ev_count NUMBER;
BEGIN
    CALL SNOWFLAKE_XDR.DETECTIONS.SEARCH_ENTITY(:P_ENTITY, :P_DAYS)
        INTO :entity_json;

    v_ev_count := ARRAY_SIZE(:entity_json:events);
    IF (:v_ev_count = 0) THEN
        RETURN OBJECT_CONSTRUCT('summary', 'No activity found for entity ' || :P_ENTITY,
                                 'events', 0);
    END IF;

    v_sample := SUBSTR(:entity_json:events::VARCHAR, 1, 8000);

    SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3.1-70b',
        'You are a SOC investigator. Analyze this entity activity timeline and provide a security assessment.
ENTITY: ' || :P_ENTITY || '
EVENTS (' || :v_ev_count || ' total, sample below):
' || :v_sample || '

Provide:
1. SUMMARY: 2-3 sentences on what this entity has been doing
2. RISK: low|medium|high|critical with one-line justification
3. RECOMMENDED_ACTIONS: 2-3 bullet points for the SOC analyst
Plain text, concise.')
        INTO :ai_response;

    RETURN OBJECT_CONSTRUCT('entity', :P_ENTITY, 'events', :v_ev_count, 'summary', :ai_response);
END;
$$;

-- ---------------------------------------------------------------------------
-- IOC management: add/remove via UI
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.ADD_IOC(
    P_TYPE VARCHAR,
    P_VALUE VARCHAR,
    P_THREAT_TYPE VARCHAR,
    P_THREAT_NAME VARCHAR,
    P_SEVERITY NUMBER,
    P_SOURCE VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_count NUMBER;
BEGIN
    SELECT COUNT(*) INTO :v_count
    FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
    WHERE ioc_type = :P_TYPE AND ioc_value = :P_VALUE;

    IF (:v_count > 0) THEN
        RETURN 'EXISTS';
    END IF;

    INSERT INTO SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
        (ioc_type, ioc_value, threat_type, threat_name, severity, confidence, source, first_seen, active)
    SELECT :P_TYPE, :P_VALUE, :P_THREAT_TYPE, :P_THREAT_NAME, :P_SEVERITY,
           100, :P_SOURCE, CURRENT_TIMESTAMP(), TRUE;
    RETURN 'ADDED';
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.REMOVE_IOC(
    P_TYPE VARCHAR,
    P_VALUE VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    DELETE FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
    WHERE ioc_type = :P_TYPE AND ioc_value = :P_VALUE;
    RETURN 'REMOVED';
END;
$$;

-- ---------------------------------------------------------------------------
-- Detection health: per-rule performance for the health monitor page
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_DETECTION_HEALTH AS
SELECT
    r.rule_id,
    r.rule_name,
    r.category,
    r.severity,
    r.enabled,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
     WHERE f.rule_id = r.rule_id) AS findings_total,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
     WHERE f.rule_id = r.rule_id
       AND f.detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS findings_7d,
    (SELECT MAX(f.detection_time) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
     WHERE f.rule_id = r.rule_id) AS last_fired,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_ERRORS e
     WHERE e.rule_id = r.rule_id) AS recent_errors
FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES r
UNION ALL
SELECT
    c.rule_id,
    c.name,
    COALESCE(c.category, 'custom'),
    c.severity,
    c.enabled,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
     WHERE f.rule_id = c.rule_id) AS findings_total,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
     WHERE f.rule_id = c.rule_id
       AND f.detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS findings_7d,
    (SELECT MAX(f.detection_time) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
     WHERE f.rule_id = c.rule_id) AS last_fired,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_ERRORS e
     WHERE e.rule_id = c.rule_id) AS recent_errors
FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES c;

-- ---------------------------------------------------------------------------
-- Platform health: data freshness per source + pipeline stats
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_DATA_FRESHNESS AS
SELECT 'authentication' AS source_table,
       (SELECT MAX(_time) FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION) AS latest_event,
       (SELECT COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION) AS event_count
UNION ALL
SELECT 'endpoint_processes',
       (SELECT MAX(_time) FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES),
       (SELECT COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES)
UNION ALL
SELECT 'network_traffic',
       (SELECT MAX(_time) FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC),
       (SELECT COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC)
UNION ALL
SELECT 'dns_activity',
       (SELECT MAX(_time) FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY),
       (SELECT COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY)
UNION ALL
SELECT 'web_activity',
       (SELECT MAX(_time) FROM SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY),
       (SELECT COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY)
UNION ALL
SELECT 'cloud_api',
       (SELECT MAX(_time) FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API),
       (SELECT COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API);
