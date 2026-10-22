-- ============================================================================
-- Snowflake XDR - 24: Agent action tools
-- ============================================================================
-- Write-capable custom tools for the XDR_ANALYST agent, so "Ask XDR" can act:
-- create/test/enable detection rules, toggle rules, add IOCs, triage findings,
-- move incidents, create response playbooks, and re-run detections.
--
-- Each procedure takes only scalar arguments (agents cannot pass OBJECT),
-- validates its inputs against the same enums the console uses, wraps the
-- platform's existing procedures, and records every call in AGENT_ACTION_LOG.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE SCHEMA DASHBOARDS;

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (
    action_id    VARCHAR DEFAULT UUID_STRING(),
    action_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    tool         VARCHAR(64),
    target       VARCHAR(500),
    params       VARIANT,
    result       VARCHAR(4000),
    executed_by  VARCHAR(255) DEFAULT CURRENT_USER()
);

-- ---------------------------------------------------------------------------
-- Create a custom SQL detection rule written by the agent, test it against
-- current data, and optionally enable it. The SQL must be one read-only
-- SELECT over SNOWFLAKE_XDR.RAW_LOGS returning _time, user_name, src, dest,
-- description. A rule whose test errors is discarded (no disabled duplicates)
-- and the error is returned so the agent can fix the SQL and retry.
-- ---------------------------------------------------------------------------
DROP PROCEDURE IF EXISTS SNOWFLAKE_XDR.DASHBOARDS.AGENT_CREATE_RULE(VARCHAR, BOOLEAN);

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_CREATE_RULE(
    P_NAME VARCHAR,
    P_DESCRIPTION VARCHAR,
    P_CATEGORY VARCHAR,
    P_SEVERITY NUMBER,
    P_MITRE_TACTIC_ID VARCHAR,
    P_MITRE_TECHNIQUE_ID VARCHAR,
    P_RULE_SQL VARCHAR,
    P_LOOKBACK_MINUTES NUMBER,
    P_ENABLE BOOLEAN
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    v_sql VARCHAR := TRIM(REGEXP_REPLACE(COALESCE(P_RULE_SQL, ''), ';\\s*$', ''));
    v_cat VARCHAR := LOWER(TRIM(COALESCE(P_CATEGORY, 'custom')));
    v_tac VARCHAR := NULLIF(UPPER(TRIM(COALESCE(P_MITRE_TACTIC_ID, ''))), '');
    v_tec VARCHAR := NULLIF(UPPER(TRIM(COALESCE(P_MITRE_TECHNIQUE_ID, ''))), '');
    v_id VARCHAR := UUID_STRING();
    test_res VARIANT;
    v_err VARCHAR;
    v_matches NUMBER;
    out VARIANT;
BEGIN
    -- Input validation: name, enums, MITRE id shape
    IF (P_NAME IS NULL OR LENGTH(TRIM(P_NAME)) = 0) THEN
        RETURN OBJECT_CONSTRUCT('error', 'p_name is required');
    END IF;
    IF (v_cat NOT IN ('identity', 'endpoint', 'network', 'cloud', 'application', 'custom')) THEN
        v_cat := 'custom';
    END IF;
    IF ((v_tac IS NOT NULL AND NOT REGEXP_LIKE(v_tac, 'TA[0-9]{4}'))
        OR (v_tec IS NOT NULL AND NOT REGEXP_LIKE(v_tec, 'T[0-9]{4}(\\.[0-9]{3})?'))) THEN
        RETURN OBJECT_CONSTRUCT('error', 'MITRE ids must look like TA0043 and T1595 / T1595.002');
    END IF;

    -- Safety: a single read-only SELECT whose only fully qualified objects are RAW_LOGS tables
    IF (NOT REGEXP_LIKE(v_sql, '^(SELECT|WITH)\\s.*', 'is')) THEN
        RETURN OBJECT_CONSTRUCT('error', 'p_rule_sql must be a single SELECT (or WITH ... SELECT) statement');
    END IF;
    IF (CONTAINS(v_sql, ';') OR CONTAINS(v_sql, CHR(36) || CHR(36))
        OR REGEXP_LIKE(v_sql, '.*\\b(INSERT|UPDATE|DELETE|MERGE|DROP|CREATE|ALTER|GRANT|REVOKE|CALL|EXECUTE|COPY|PUT|GET|REMOVE|TRUNCATE|UNDROP|USE|SYSTEM\\$[A-Z_]+)\\b.*', 'is')) THEN
        RETURN OBJECT_CONSTRUCT('error', 'p_rule_sql must be read-only: no DML/DDL, CALL, multiple statements, or system functions');
    END IF;
    IF (NOT REGEXP_LIKE(v_sql, '.*SNOWFLAKE_XDR\\.RAW_LOGS\\.[A-Z_]+.*', 'is')
        OR REGEXP_COUNT(v_sql, '\\b[A-Za-z_][A-Za-z0-9_$]*\\.[A-Za-z_][A-Za-z0-9_$]*\\.[A-Za-z_][A-Za-z0-9_$]*\\b')
           != REGEXP_COUNT(v_sql, 'SNOWFLAKE_XDR\\.RAW_LOGS\\.[A-Za-z_][A-Za-z0-9_$]*', 1, 'i')) THEN
        RETURN OBJECT_CONSTRUCT('error', 'p_rule_sql may only read fully qualified SNOWFLAKE_XDR.RAW_LOGS.<table> objects');
    END IF;

    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
        (rule_id, name, description, category, severity, mitre_tactic_id, mitre_technique_id,
         language, source_table, code, threshold_count, threshold_window_minutes,
         lookback_minutes, enabled, created_by)
    SELECT :v_id, LEFT(:P_NAME, 200), LEFT(:P_DESCRIPTION, 2000), :v_cat,
           LEAST(GREATEST(COALESCE(:P_SEVERITY, 3), 1), 5), :v_tac, :v_tec,
           'sql', NULL, :v_sql, 1, 60,
           LEAST(GREATEST(COALESCE(:P_LOOKBACK_MINUTES, 1440), 5), 20160), FALSE, 'ask_xdr_agent';

    BEGIN
        CALL SNOWFLAKE_XDR.DETECTIONS.TEST_CUSTOM_RULE(:v_id) INTO :test_res;
        v_err := test_res:error::VARCHAR;
    EXCEPTION
        WHEN OTHER THEN
            v_err := SQLERRM;
    END;

    IF (v_err IS NOT NULL) THEN
        DELETE FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE rule_id = :v_id;
        out := OBJECT_CONSTRUCT(
            'error', 'Rule SQL failed its test against current data, so it was not saved. Fix the SQL and retry.',
            'test_error', LEFT(:v_err, 600));
    ELSE
        v_matches := COALESCE(ARRAY_SIZE(test_res), ARRAY_SIZE(test_res:matches), 0);
        IF (COALESCE(P_ENABLE, FALSE)) THEN
            UPDATE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
               SET enabled = TRUE, updated_at = CURRENT_TIMESTAMP()
             WHERE rule_id = :v_id;
        END IF;
        out := OBJECT_CONSTRUCT(
            'rule_id', :v_id,
            'name', :P_NAME,
            'mitre_tactic_id', :v_tac,
            'mitre_technique_id', :v_tec,
            'test_passed', TRUE,
            'test_matches_in_lookback', :v_matches,
            'enabled', COALESCE(:P_ENABLE, FALSE),
            'note', IFF(COALESCE(:P_ENABLE, FALSE),
                        'Rule is live and runs with the next detection cycle (or run_detections now).',
                        'Rule saved disabled; enable with set_rule_enabled or in Rules & IOCs.'));
    END IF;

    INSERT INTO SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (tool, target, params, result)
        SELECT 'create_detection_rule', IFF(:v_err IS NULL, :v_id, NULL),
               OBJECT_CONSTRUCT('name', :P_NAME, 'enable', :P_ENABLE, 'sql', LEFT(:v_sql, 2000)),
               LEFT(:out::VARCHAR, 4000);
    RETURN out;
END;
$$;

-- ---------------------------------------------------------------------------
-- Enable / disable a built-in (DET-xxx) or custom rule.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_SET_RULE_ENABLED(
    P_RULE_ID VARCHAR,
    P_ENABLED BOOLEAN
)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    n NUMBER := 0;
    res VARCHAR;
BEGIN
    UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES SET enabled = :P_ENABLED WHERE rule_id = :P_RULE_ID;
    n := SQLROWCOUNT;
    IF (n = 0) THEN
        UPDATE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
           SET enabled = :P_ENABLED, updated_at = CURRENT_TIMESTAMP()
         WHERE rule_id = :P_RULE_ID;
        n := SQLROWCOUNT;
    END IF;
    res := IFF(n = 0, 'No rule found with id ' || :P_RULE_ID,
               'Rule ' || :P_RULE_ID || IFF(:P_ENABLED, ' enabled', ' disabled'));
    INSERT INTO SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (tool, target, params, result)
        SELECT 'set_rule_enabled', :P_RULE_ID, OBJECT_CONSTRUCT('enabled', :P_ENABLED), :res;
    RETURN res;
END;
$$;

-- ---------------------------------------------------------------------------
-- Add a threat-intel IOC (picked up by DETECT_KNOWN_BAD_IOC).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_ADD_IOC(
    P_IOC_TYPE VARCHAR,
    P_IOC_VALUE VARCHAR,
    P_THREAT_TYPE VARCHAR,
    P_SEVERITY NUMBER
)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    res VARCHAR;
    t VARCHAR := LOWER(TRIM(P_IOC_TYPE));
    th VARCHAR := LOWER(TRIM(COALESCE(P_THREAT_TYPE, 'malware')));
BEGIN
    IF (t NOT IN ('ip', 'domain', 'url', 'hash_md5', 'hash_sha256', 'email', 'user_agent')) THEN
        RETURN 'Invalid ioc_type. Use one of: ip, domain, url, hash_md5, hash_sha256, email, user_agent';
    END IF;
    IF (th NOT IN ('malware', 'phishing', 'c2', 'botnet', 'ransomware', 'apt', 'credential_abuse', 'exfiltration', 'scanner')) THEN
        RETURN 'Invalid threat_type. Use one of: malware, phishing, c2, botnet, ransomware, apt, credential_abuse, exfiltration, scanner';
    END IF;
    IF (P_IOC_VALUE IS NULL OR LENGTH(TRIM(P_IOC_VALUE)) = 0 OR LENGTH(P_IOC_VALUE) > 500) THEN
        RETURN 'ioc_value is required (max 500 chars)';
    END IF;
    CALL SNOWFLAKE_XDR.REFERENCE.ADD_IOC(:t, TRIM(:P_IOC_VALUE), :th, :th,
                                         LEAST(GREATEST(COALESCE(:P_SEVERITY, 3), 1), 5), 'ask_xdr_agent') INTO :res;
    INSERT INTO SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (tool, target, params, result)
        SELECT 'add_ioc', :P_IOC_VALUE, OBJECT_CONSTRUCT('type', :t, 'threat', :th, 'severity', :P_SEVERITY), :res;
    RETURN 'IOC ' || :res;
END;
$$;

-- ---------------------------------------------------------------------------
-- Triage a finding: status, disposition, assignee, notes.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_UPDATE_FINDING(
    P_FINDING_ID VARCHAR,
    P_STATUS VARCHAR,
    P_DISPOSITION VARCHAR,
    P_ASSIGNED_TO VARCHAR,
    P_NOTES VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    s VARCHAR := LOWER(TRIM(P_STATUS));
    d VARCHAR := NULLIF(LOWER(TRIM(COALESCE(P_DISPOSITION, ''))), '');
    res VARCHAR;
BEGIN
    IF (s NOT IN ('new', 'investigating', 'contained', 'resolved', 'dismissed')) THEN
        RETURN 'Invalid status. Use one of: new, investigating, contained, resolved, dismissed';
    END IF;
    IF (d IS NOT NULL AND d NOT IN ('true_positive', 'false_positive', 'benign', 'mitigated_by_control')) THEN
        RETURN 'Invalid disposition. Use one of: true_positive, false_positive, benign, mitigated_by_control';
    END IF;
    UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
       SET status = :s,
           disposition = COALESCE(:d, disposition),
           assigned_to = COALESCE(NULLIF(LEFT(:P_ASSIGNED_TO, 100), ''), assigned_to),
           triage_notes = COALESCE(NULLIF(LEFT(:P_NOTES, 2000), ''), triage_notes),
           triaged_at = CURRENT_TIMESTAMP()
     WHERE finding_id = :P_FINDING_ID;
    res := IFF(SQLROWCOUNT = 0, 'No finding found with id ' || :P_FINDING_ID,
               'Finding ' || :P_FINDING_ID || ' set to ' || :s || COALESCE(' / ' || :d, ''));
    INSERT INTO SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (tool, target, params, result)
        SELECT 'update_finding', :P_FINDING_ID,
               OBJECT_CONSTRUCT('status', :s, 'disposition', :d, 'assigned_to', :P_ASSIGNED_TO), :res;
    RETURN res;
END;
$$;

-- ---------------------------------------------------------------------------
-- Move an incident through its lifecycle.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_SET_INCIDENT_STATUS(
    P_INCIDENT_ID VARCHAR,
    P_STATUS VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    s VARCHAR := LOWER(TRIM(P_STATUS));
    res VARCHAR;
BEGIN
    IF (s NOT IN ('open', 'investigating', 'contained', 'closed')) THEN
        RETURN 'Invalid status. Use one of: open, investigating, contained, closed';
    END IF;
    UPDATE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
       SET status = :s, closed_at = IFF(:s = 'closed', CURRENT_TIMESTAMP(), NULL)
     WHERE incident_id = :P_INCIDENT_ID;
    res := IFF(SQLROWCOUNT = 0, 'No incident found with id ' || :P_INCIDENT_ID,
               'Incident ' || :P_INCIDENT_ID || ' set to ' || :s);
    INSERT INTO SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (tool, target, params, result)
        SELECT 'set_incident_status', :P_INCIDENT_ID, OBJECT_CONSTRUCT('status', :s), :res;
    RETURN res;
END;
$$;

-- ---------------------------------------------------------------------------
-- Create a response playbook. Webhook/Slack actions reuse the deployment's
-- notification integration, so only email / incident / AI-triage actions
-- need configuration here.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_CREATE_PLAYBOOK(
    P_NAME VARCHAR,
    P_DESCRIPTION VARCHAR,
    P_MIN_SEVERITY NUMBER,
    P_ACTION_TYPE VARCHAR,
    P_EMAIL_TO VARCHAR,
    P_ENTITY VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    a VARCHAR := LOWER(TRIM(P_ACTION_TYPE));
    cfg VARIANT;
    res VARCHAR;
BEGIN
    IF (a NOT IN ('email', 'webhook', 'create_incident', 'ai_triage')) THEN
        RETURN 'Invalid action_type. Use one of: email, webhook, create_incident, ai_triage';
    END IF;
    IF (P_NAME IS NULL OR LENGTH(TRIM(P_NAME)) = 0) THEN
        RETURN 'name is required';
    END IF;
    IF (a = 'email' AND NOT REGEXP_LIKE(COALESCE(P_EMAIL_TO, ''),
            '^[^\\s@,]+@[^\\s@,]+\\.[^\\s@,]+(\\s*,\\s*[^\\s@,]+@[^\\s@,]+\\.[^\\s@,]+)*$')) THEN
        RETURN 'email actions need email_to as a comma-separated list of addresses';
    END IF;
    cfg := IFF(a = 'email', OBJECT_CONSTRUCT('to', :P_EMAIL_TO), OBJECT_CONSTRUCT());
    CALL SNOWFLAKE_XDR.RESPONSE.SAVE_PLAYBOOK(
        '', LEFT(:P_NAME, 200), LEFT(COALESCE(:P_DESCRIPTION, ''), 1000),
        LEAST(GREATEST(COALESCE(:P_MIN_SEVERITY, 4), 1), 5), NULL, NULL,
        NULLIF(LEFT(TRIM(COALESCE(:P_ENTITY, '')), 128), ''), 1, 60, 60, :a, :cfg, TRUE) INTO :res;
    INSERT INTO SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (tool, target, params, result)
        SELECT 'create_playbook', :P_NAME,
               OBJECT_CONSTRUCT('action', :a, 'min_severity', :P_MIN_SEVERITY, 'entity', :P_ENTITY), :res;
    RETURN 'Playbook ' || :res;
END;
$$;

-- ---------------------------------------------------------------------------
-- Re-run all detections (built-in + enabled custom rules) now.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DASHBOARDS.AGENT_RUN_DETECTIONS()
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS OWNER
AS
$$
DECLARE
    r1 VARCHAR;
    r2 VARCHAR;
BEGIN
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_ALL_DETECTIONS() INTO :r1;
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULES() INTO :r2;
    INSERT INTO SNOWFLAKE_XDR.DASHBOARDS.AGENT_ACTION_LOG (tool, target, params, result)
        SELECT 'run_detections', NULL, NULL, LEFT(:r1 || ' | ' || :r2, 4000);
    RETURN LEFT(:r1 || ' | ' || :r2, 4000);
END;
$$;
