-- ============================================================================
-- Snowflake XDR - Custom Detection Rule Engine
-- ============================================================================
-- Manually authored rules in SQL, Python, or JavaScript with thresholds,
-- dry-run testing, and Cortex AI-assisted generation.
--
-- SQL rule contract: the stored query must return columns
--   _time, user_name, src, dest, description
-- Python/JS rule contract: handler code defines  detect(row) -> 0/1
-- operating on a VARIANT of one log row from the rule's source table.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE SCHEMA DETECTIONS;

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES (
    rule_id VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description VARCHAR(2000),
    category VARCHAR(50) DEFAULT 'custom',
    severity NUMBER DEFAULT 3,
    mitre_tactic_id VARCHAR(20),
    mitre_technique_id VARCHAR(30),
    language VARCHAR(20) NOT NULL,
    source_table VARCHAR(100),
    code VARCHAR(10000) NOT NULL,
    threshold_count NUMBER DEFAULT 1,
    threshold_window_minutes NUMBER DEFAULT 60,
    lookback_minutes NUMBER DEFAULT 60,
    schedule_cron VARCHAR(50) DEFAULT '0 * * * *',
    enabled BOOLEAN DEFAULT FALSE,
    test_mode BOOLEAN DEFAULT FALSE,
    version NUMBER DEFAULT 1,
    created_by VARCHAR(100) DEFAULT CURRENT_USER(),
    created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_ERRORS (
    rule_id VARCHAR,
    error_time TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    error_message VARCHAR(4000),
    stage VARCHAR(50)
);

-- ---------------------------------------------------------------------------
-- Stage matched rows for a SQL rule into a temp table, then aggregate/insert.
-- P_DRY_RUN=TRUE returns JSON samples without inserting.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULE_SQL(
    P_RULE_ID VARCHAR,
    P_DRY_RUN BOOLEAN
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_name VARCHAR;
    v_desc VARCHAR;
    v_cat VARCHAR;
    v_sev NUMBER;
    v_tactic VARCHAR;
    v_tech VARCHAR;
    v_code VARCHAR;
    v_thresh NUMBER;
    v_window NUMBER;
    v_lookback NUMBER;
    v_sample VARCHAR;
BEGIN
    SELECT name, description, category, severity, mitre_tactic_id, mitre_technique_id,
           code, threshold_count, threshold_window_minutes, lookback_minutes
    INTO :v_name, :v_desc, :v_cat, :v_sev, :v_tactic, :v_tech,
         :v_code, :v_thresh, :v_window, :v_lookback
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    WHERE rule_id = :P_RULE_ID;

    IF (v_code IS NULL) THEN
        RETURN 'ERROR: rule not found';
    END IF;

    -- Materialize matched rows (dynamic DDL needs no INTO)
    LET stage_sql VARCHAR := 'CREATE OR REPLACE TEMPORARY TABLE XDR_CUSTOM_RULE_MATCHES AS SELECT user_name, src, dest, _time, description FROM (' || :v_code || ') WHERE _time > DATEADD(''minute'', ' || (-1 * :v_lookback) || ', CURRENT_TIMESTAMP())';
    EXECUTE IMMEDIATE (:stage_sql);

    IF (:P_DRY_RUN) THEN
        SELECT COALESCE(TO_JSON(ARRAY_AGG(OBJECT_CONSTRUCT(
                       'time', _time, 'user', user_name, 'src', src,
                       'dest', dest, 'desc', description)
                   ) WITHIN GROUP (ORDER BY _time)), '[]')
        INTO :v_sample
        FROM (SELECT * FROM XDR_CUSTOM_RULE_MATCHES LIMIT 20);
        RETURN :v_sample;
    END IF;

    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        (finding_id, rule_id, description, category, severity,
         mitre_tactic_id, mitre_technique_id, user_name, src, dest,
         event_time, detection_time, detection_source, confidence,
         evidence_count, evidence, risk_score, status)
    SELECT
        UUID_STRING(),
        :P_RULE_ID,
        :v_name || ' - ' || COALESCE(user_name, src, 'unknown'),
        :v_cat, :v_sev, :v_tactic, :v_tech,
        user_name, src, dest,
        MIN(_time), CURRENT_TIMESTAMP(), 'custom_rule', 80,
        COUNT(*),
        OBJECT_CONSTRUCT('matched_events', COUNT(*), 'window_minutes', :v_window),
        :v_sev * 20, 'new'
    FROM XDR_CUSTOM_RULE_MATCHES
    GROUP BY user_name, src, dest,
             FLOOR(DATEDIFF('minute', '2000-01-01'::TIMESTAMP, _time) / :v_window)
    HAVING COUNT(*) >= :v_thresh;

    LET inserted NUMBER := SQLROWCOUNT;
    UPDATE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    SET updated_at = CURRENT_TIMESTAMP()
    WHERE rule_id = :P_RULE_ID;
    RETURN 'OK: ' || :inserted || ' findings inserted';
END;
$$;

-- ---------------------------------------------------------------------------
-- Compile a python/js rule handler into a UDF
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.COMPILE_CUSTOM_RULE_UDF(
    P_RULE_ID VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_language VARCHAR;
    v_code VARCHAR;
    v_short VARCHAR;
    v_ddl VARCHAR;
    DOLLAR2 VARCHAR := CHR(36) || CHR(36);
BEGIN
    SELECT language, code INTO :v_language, :v_code
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    WHERE rule_id = :P_RULE_ID;

    v_short := 'R' || SUBSTR(SHA1(:P_RULE_ID), 0, 12);

    IF (:v_language = 'python') THEN
        v_ddl := 'CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.DETECTIONS.CUSTOM_' || :v_short || '(row VARIANT) RETURNS NUMBER LANGUAGE PYTHON RUNTIME_VERSION = ''3.10'' HANDLER = ''detect'' AS ' || DOLLAR2 || :v_code || DOLLAR2;
    ELSE
        IF (:v_language = 'javascript') THEN
            v_ddl := 'CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.DETECTIONS.CUSTOM_' || :v_short || '(row VARIANT) RETURNS NUMBER LANGUAGE JAVASCRIPT HANDLER = ''detect'' AS ' || DOLLAR2 || :v_code || DOLLAR2;
        ELSE
            RETURN 'OK: sql rule needs no compilation';
        END IF;
    END IF;

    EXECUTE IMMEDIATE (:v_ddl);
    RETURN 'OK: compiled CUSTOM_' || :v_short;
END;
$$;

-- ---------------------------------------------------------------------------
-- Execute a python/js rule: apply UDF over source table
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULE_CODE(
    P_RULE_ID VARCHAR,
    P_DRY_RUN BOOLEAN
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_language VARCHAR;
    v_source VARCHAR;
    v_lookback NUMBER;
    v_short VARCHAR;
    v_stage VARCHAR;
    v_sample VARCHAR;
BEGIN
    SELECT language, source_table, lookback_minutes
    INTO :v_language, :v_source, :v_lookback
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    WHERE rule_id = :P_RULE_ID;

    v_short := 'CUSTOM_R' || SUBSTR(SHA1(:P_RULE_ID), 0, 12);

    LET stage_sql VARCHAR := 'CREATE OR REPLACE TEMPORARY TABLE XDR_CUSTOM_RULE_MATCHES AS SELECT l.* FROM SNOWFLAKE_XDR.RAW_LOGS.' || :v_source || ' l WHERE l._time > DATEADD(''minute'', ' || (-1 * :v_lookback) || ', CURRENT_TIMESTAMP()) AND SNOWFLAKE_XDR.DETECTIONS.' || :v_short || '(TO_VARIANT(l)) = 1';
    EXECUTE IMMEDIATE (:stage_sql);

    IF (:P_DRY_RUN) THEN
        SELECT COALESCE(TO_JSON(ARRAY_AGG(OBJECT_CONSTRUCT(
                       'time', _time, 'user', user_name, 'src', src, 'dest', dest)
                   ) WITHIN GROUP (ORDER BY _time)), '[]')
        INTO :v_sample
        FROM (SELECT * FROM XDR_CUSTOM_RULE_MATCHES LIMIT 20);
        RETURN :v_sample;
    END IF;

    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        (finding_id, rule_id, description, category, severity,
         mitre_tactic_id, mitre_technique_id, user_name, src, dest,
         event_time, detection_time, detection_source, confidence,
         evidence, risk_score, status)
    SELECT
        UUID_STRING(),
        :P_RULE_ID,
        cr.name || ' - custom detection',
        cr.category, cr.severity, cr.mitre_tactic_id, cr.mitre_technique_id,
        l.user_name, l.src, l.dest,
        l._time, CURRENT_TIMESTAMP(), 'custom_rule', 70,
        TO_VARIANT(l), cr.severity * 20, 'new'
    FROM XDR_CUSTOM_RULE_MATCHES l,
         SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES cr
    WHERE cr.rule_id = :P_RULE_ID;

    LET inserted NUMBER := SQLROWCOUNT;
    RETURN 'OK: ' || :inserted || ' findings inserted';
END;
$$;

-- ---------------------------------------------------------------------------
-- Master runner for all enabled custom rules
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULES()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    total_findings NUMBER DEFAULT 0;
    run_status VARCHAR;
    cur_rule_id VARCHAR;
    cur_language VARCHAR;
    err_msg VARCHAR;
    rules CURSOR FOR
        SELECT rule_id, language FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
        WHERE enabled = TRUE;
BEGIN
    FOR rec IN rules DO
        cur_rule_id := rec.rule_id;
        cur_language := rec.language;
        BEGIN
            IF (cur_language = 'sql') THEN
                CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULE_SQL(:cur_rule_id, FALSE)
                    INTO :run_status;
            ELSE
                CALL SNOWFLAKE_XDR.DETECTIONS.COMPILE_CUSTOM_RULE_UDF(:cur_rule_id)
                    INTO :run_status;
                IF (NOT STARTSWITH(:run_status, 'OK')) THEN
                    CONTINUE;
                END IF;
                CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULE_CODE(:cur_rule_id, FALSE)
                    INTO :run_status;
            END IF;
            IF (STARTSWITH(:run_status, 'OK')) THEN
                total_findings := :total_findings
                    + CAST(SPLIT_PART(:run_status, ': ', 2) AS NUMBER);
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                err_msg := SQLERRM;
                INSERT INTO SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_ERRORS
                    (rule_id, error_message, stage)
                VALUES (:cur_rule_id, :err_msg, 'execute');
        END;
    END FOR;

    RETURN 'Custom rules run complete. Findings: ' || :total_findings;
END;
$$;

-- ---------------------------------------------------------------------------
-- Dry-run any rule regardless of language (for the UI test button)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.TEST_CUSTOM_RULE(
    P_RULE_ID VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
AS
$$
DECLARE
    v_language VARCHAR;
    v_result VARCHAR;
BEGIN
    SELECT language INTO :v_language
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    WHERE rule_id = :P_RULE_ID;

    IF (:v_language = 'sql') THEN
        CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULE_SQL(:P_RULE_ID, TRUE)
            INTO :v_result;
    ELSE
        CALL SNOWFLAKE_XDR.DETECTIONS.COMPILE_CUSTOM_RULE_UDF(:P_RULE_ID) INTO :v_result;
        IF (NOT STARTSWITH(:v_result, 'OK')) THEN
            RETURN OBJECT_CONSTRUCT('error', :v_result);
        END IF;
        CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULE_CODE(:P_RULE_ID, TRUE)
            INTO :v_result;
    END IF;

    BEGIN
        RETURN TRY_PARSE_JSON(:v_result);
    EXCEPTION
        WHEN OTHER THEN
            RETURN OBJECT_CONSTRUCT('status', :v_result);
    END;
END;
$$;

-- ---------------------------------------------------------------------------
-- AI rule builder: natural language -> draft detection rule
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AI_GENERATE_RULE(
    P_DESCRIPTION VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
AS
$$
DECLARE
    ai_response VARCHAR;
    rule_json VARIANT;
    v_id VARCHAR;
BEGIN
    SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3.1-70b', '
You are a detection engineer for a Snowflake-native XDR platform. Convert the user''s
requirement into a detection rule.

AVAILABLE DATA TABLES (all in SNOWFLAKE_XDR.RAW_LOGS):
- AUTHENTICATION(_time, action, app, authentication_method, authentication_service, dest, src, user_name, user_type, signature, signature_id, geo_country, reason)
- ENDPOINT_PROCESSES(_time, action, dest, user_name, process, process_name, process_id, process_path, parent_process_name, os)
- ENDPOINT_FILESYSTEM(_time, action, dest, user_name, file_path, file_name, file_size)
- ENDPOINT_REGISTRY(_time, action, dest, user_name, registry_key, registry_value)
- NETWORK_TRAFFIC(_time, src_ip, src_port, dest_ip, dest_port, protocol, bytes_in, bytes_out, direction, app)
- DNS_ACTIVITY(_time, src, query, query_type, query_length, response_ips)
- WEB_ACTIVITY(_time, src, url, http_method, status, http_user_agent, bytes_out, dest)
- CLOUD_API(_time, action, user_name, user_type, src, dest, object, object_category, result, app)

REQUIREMENT:
' || :P_DESCRIPTION || '

Return ONLY a JSON object with these fields:
{"name": "short rule name", "description": "one sentence", "category": "identity|endpoint|network|cloud|application|custom", "severity": 1-5, "mitre_tactic_id": "TA00XX or null", "mitre_technique_id": "TXXXX or null", "source_table": "table name", "rule_sql": "SELECT _time, user_name, src, dest, description FROM ... WHERE ...", "threshold_count": 1, "threshold_window_minutes": 60, "lookback_minutes": 60}
The rule_sql MUST return columns named exactly: _time, user_name, src, dest, description.
Use NULL for columns not applicable. No markdown, no explanation, JSON only.')
    INTO :ai_response;

    LET s_pos NUMBER := POSITION('{', :ai_response);
    LET e_pos NUMBER := POSITION('}', REVERSE(:ai_response));
    LET cleaned VARCHAR := '';
    IF (:s_pos > 0 AND :e_pos > 0) THEN
        cleaned := SUBSTR(:ai_response, :s_pos, LENGTH(:ai_response) - :s_pos - :e_pos + 2);
    END IF;
    rule_json := TRY_PARSE_JSON(:cleaned);

    IF (rule_json IS NULL OR rule_json:rule_sql IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('error', 'AI did not return valid JSON', 'raw', :ai_response);
    END IF;

    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
        (name, description, category, severity, mitre_tactic_id, mitre_technique_id,
         language, source_table, code, threshold_count, threshold_window_minutes,
         lookback_minutes, enabled, created_by)
    SELECT
        :rule_json:name::VARCHAR,
        :rule_json:description::VARCHAR,
        COALESCE(:rule_json:category::VARCHAR, 'custom'),
        COALESCE(:rule_json:severity::NUMBER, 3),
        :rule_json:mitre_tactic_id::VARCHAR,
        :rule_json:mitre_technique_id::VARCHAR,
        'sql',
        :rule_json:source_table::VARCHAR,
        :rule_json:rule_sql::VARCHAR,
        COALESCE(:rule_json:threshold_count::NUMBER, 1),
        COALESCE(:rule_json:threshold_window_minutes::NUMBER, 60),
        COALESCE(:rule_json:lookback_minutes::NUMBER, 60),
        FALSE,
        'ai_assisted';

    SELECT rule_id INTO :v_id
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    WHERE created_by = 'ai_assisted'
    ORDER BY created_at DESC LIMIT 1;

    RETURN OBJECT_CONSTRUCT(
        'rule_id', :v_id,
        'name', :rule_json:name::VARCHAR,
        'description', :rule_json:description::VARCHAR,
        'rule_sql', :rule_json:rule_sql::VARCHAR,
        'status', 'draft_created - review and enable'
    );
END;
$$;

-- ---------------------------------------------------------------------------
-- CRUD helper used by the UI
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.SAVE_CUSTOM_RULE(
    P_RULE_ID VARCHAR,
    P_NAME VARCHAR,
    P_DESCRIPTION VARCHAR,
    P_CATEGORY VARCHAR,
    P_SEVERITY NUMBER,
    P_TACTIC VARCHAR,
    P_TECHNIQUE VARCHAR,
    P_LANGUAGE VARCHAR,
    P_SOURCE_TABLE VARCHAR,
    P_CODE VARCHAR,
    P_THRESHOLD NUMBER,
    P_WINDOW NUMBER,
    P_LOOKBACK NUMBER,
    P_ENABLED BOOLEAN
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_count NUMBER;
    v_id VARCHAR;
BEGIN
    SELECT COUNT(*) INTO :v_count
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    WHERE rule_id = :P_RULE_ID;

    IF (:P_RULE_ID IS NULL OR :P_RULE_ID = '') THEN
        INSERT INTO SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
            (name, description, category, severity, mitre_tactic_id, mitre_technique_id,
             language, source_table, code, threshold_count, threshold_window_minutes,
             lookback_minutes, enabled, created_by)
        VALUES (:P_NAME, :P_DESCRIPTION, :P_CATEGORY, :P_SEVERITY, :P_TACTIC, :P_TECHNIQUE,
                :P_LANGUAGE, :P_SOURCE_TABLE, :P_CODE, :P_THRESHOLD, :P_WINDOW,
                :P_LOOKBACK, :P_ENABLED, 'ui');
        RETURN 'CREATED';
    ELSE
        -- Version history: snapshot the current rule before updating it
        INSERT INTO SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_HISTORY
            (rule_id, version, name, code, language, severity, threshold_count, enabled, changed_by)
        SELECT rule_id, version, name, code, language, severity,
               threshold_count, enabled, 'ui'
        FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
        WHERE rule_id = :P_RULE_ID;

        UPDATE SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
        SET name = :P_NAME, description = :P_DESCRIPTION, category = :P_CATEGORY,
            severity = :P_SEVERITY, mitre_tactic_id = :P_TACTIC, mitre_technique_id = :P_TECHNIQUE,
            language = :P_LANGUAGE, source_table = :P_SOURCE_TABLE, code = :P_CODE,
            threshold_count = :P_THRESHOLD, threshold_window_minutes = :P_WINDOW,
            lookback_minutes = :P_LOOKBACK, enabled = :P_ENABLED,
            version = version + 1, updated_at = CURRENT_TIMESTAMP()
        WHERE rule_id = :P_RULE_ID;
        RETURN 'UPDATED';
    END IF;
END;
$$;
