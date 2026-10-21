-- ============================================================================
-- Snowflake XDR - Response Automation (SOAR-lite Playbooks)
-- ============================================================================
-- Configurable playbooks: when a finding matches trigger conditions
-- (severity, rule, category, entity, threshold within window, cooldown),
-- execute actions: email, webhook, external API call, create incident,
-- or AI triage. All executions are logged to RESPONSE.PLAYBOOK_ACTIONS.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.RESPONSE.PLAYBOOKS (
    playbook_id VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description VARCHAR(1000),
    -- Trigger conditions
    trigger_severity_min NUMBER DEFAULT 1,        -- fire when finding severity >= this
    trigger_rule_ids ARRAY,                      -- NULL/empty = any rule
    trigger_categories ARRAY,                     -- NULL/empty = any category
    trigger_entity VARCHAR,                       -- NULL = any user/src/dest
    threshold_count NUMBER DEFAULT 1,            -- findings needed in window
    threshold_window_minutes NUMBER DEFAULT 60,
    cooldown_minutes NUMBER DEFAULT 60,          -- suppress repeats per entity
    -- Action
    action_type VARCHAR NOT NULL,                -- email|webhook|api_call|create_incident|ai_triage
    action_config VARIANT,                        -- action-specific config JSON
    enabled BOOLEAN DEFAULT TRUE,
    created_by VARCHAR(100) DEFAULT CURRENT_USER(),
    created_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS (
    action_id VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    playbook_id VARCHAR,
    playbook_name VARCHAR,
    finding_id VARCHAR,
    action_type VARCHAR,
    status VARCHAR,                               -- success|error|suppressed_cooldown|skipped
    detail VARCHAR(4000),
    executed_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Core evaluator: check a finding against all enabled playbooks and fire
-- matching actions. Called after detection runs and from the UI test button.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.RESPONSE.EVALUATE_RESPONSE(
    P_FINDING_ID VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    f_severity NUMBER;
    f_rule VARCHAR;
    f_cat VARCHAR;
    f_user VARCHAR;
    f_src VARCHAR;
    f_dest VARCHAR;
    f_desc VARCHAR;
    f_entity VARCHAR;
    pb_id VARCHAR;
    pb_name VARCHAR;
    pb_action VARCHAR;
    pb_config VARIANT;
    pb_sev_min NUMBER;
    pb_thresh NUMBER;
    pb_window NUMBER;
    pb_cooldown NUMBER;
    pb_rules ARRAY;
    pb_cats ARRAY;
    pb_entity VARCHAR;
    window_count NUMBER;
    last_action TIMESTAMP;
    action_status VARCHAR;
    actions_fired NUMBER DEFAULT 0;
    result_detail VARCHAR;
    email_subject VARCHAR;
    email_body VARCHAR;
    email_to VARCHAR;
    api_url VARCHAR;
    api_payload VARCHAR;
    api_auth VARCHAR;
    playbook_cursor CURSOR FOR
        SELECT playbook_id, name, action_type, action_config, trigger_severity_min,
               threshold_count, threshold_window_minutes, cooldown_minutes,
               trigger_rule_ids, trigger_categories, trigger_entity
        FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOKS
        WHERE enabled = TRUE;
BEGIN
    -- Load the finding
    SELECT severity, rule_id, category, user_name, src, dest, description
    INTO :f_severity, :f_rule, :f_cat, :f_user, :f_src, :f_dest, :f_desc
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE finding_id = :P_FINDING_ID;

    IF (f_severity IS NULL) THEN
        RETURN 'ERROR: finding not found';
    END IF;

    f_entity := COALESCE(:f_user, :f_src, :f_dest, 'unknown');

    FOR pb IN playbook_cursor DO
        pb_id := pb.playbook_id;
        pb_name := pb.name;
        pb_action := pb.action_type;
        pb_config := pb.action_config;
        pb_sev_min := pb.trigger_severity_min;
        pb_thresh := pb.threshold_count;
        pb_window := pb.threshold_window_minutes;
        pb_cooldown := pb.cooldown_minutes;
        pb_rules := pb.trigger_rule_ids;
        pb_cats := pb.trigger_categories;
        pb_entity := pb.trigger_entity;

        -- Condition: severity
        IF (:f_severity < :pb_sev_min) THEN
            CONTINUE;
        END IF;

        -- Condition: rule filter
        IF (ARRAY_SIZE(:pb_rules) > 0 AND NOT ARRAY_CONTAINS(:f_rule::VARIANT, :pb_rules)) THEN
            CONTINUE;
        END IF;

        -- Condition: category filter
        IF (ARRAY_SIZE(:pb_cats) > 0 AND NOT ARRAY_CONTAINS(:f_cat::VARIANT, :pb_cats)) THEN
            CONTINUE;
        END IF;

        -- Condition: entity filter
        IF (:pb_entity IS NOT NULL AND :pb_entity != ''
            AND :pb_entity != :f_user AND :pb_entity != :f_src AND :pb_entity != :f_dest) THEN
            CONTINUE;
        END IF;

        -- Condition: threshold within window for this entity
        SELECT COUNT(*) INTO :window_count
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE severity >= :pb_sev_min
          AND COALESCE(user_name, src, dest, 'unknown') = :f_entity
          AND detection_time > DATEADD('minute', -:pb_window, CURRENT_TIMESTAMP());

        IF (:window_count < :pb_thresh) THEN
            CONTINUE;
        END IF;

        -- Condition: cooldown per entity+playbook
        SELECT MAX(executed_at) INTO :last_action
        FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS
        WHERE playbook_id = :pb_id
          AND finding_id IN (
              SELECT finding_id FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
              WHERE COALESCE(user_name, src, dest, 'unknown') = :f_entity);

        IF (:last_action IS NOT NULL
            AND :last_action > DATEADD('minute', -:pb_cooldown, CURRENT_TIMESTAMP())) THEN
            INSERT INTO SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS
                (playbook_id, playbook_name, finding_id, action_type, status, detail)
            VALUES (:pb_id, :pb_name, :P_FINDING_ID, :pb_action,
                    'suppressed_cooldown',
                    'Entity ' || :f_entity || ' already actioned within ' || :pb_cooldown || ' min');
            CONTINUE;
        END IF;

        -- Execute the action
        action_status := 'success';
        result_detail := '';

        IF (:pb_action = 'email') THEN
            email_to := COALESCE(:pb_config:to::VARCHAR, 'kevin.keller@snowflake.com');
            email_subject := '[XDR] ' || :pb_name || ': ' || COALESCE(:f_desc, 'security finding');
            email_body := 'XDR finding triggered playbook ' || :pb_name
                || '\nFinding: ' || :f_desc
                || '\nSeverity: ' || :f_severity
                || '\nRule: ' || :f_rule
                || '\nEntity: ' || :f_entity
                || '\nTime: ' || CURRENT_TIMESTAMP();
            BEGIN
                CALL SYSTEM$SEND_EMAIL('XDR_EMAIL', :email_to, :email_subject, :email_body);
                result_detail := 'Email sent to ' || :email_to;
            EXCEPTION
                WHEN OTHER THEN
                    action_status := 'error';
                    result_detail := 'Email failed: ' || SQLERRM;
            END;

        ELSE
            IF (:pb_action = 'webhook') THEN
                BEGIN
                    CALL SYSTEM$SEND_SNOWFLAKE_NOTIFICATION(
                        SNOWFLAKE.NOTIFICATION.APPLICATION_JSON(
                            OBJECT_CONSTRUCT(
                                'playbook', :pb_name,
                                'finding', :f_desc,
                                'severity', :f_severity,
                                'rule', :f_rule,
                                'entity', :f_entity,
                                'time', CURRENT_TIMESTAMP()
                            )::VARCHAR),
                        SNOWFLAKE.NOTIFICATION.INTEGRATION('XDR_WEBHOOK'));
                    result_detail := 'Webhook notification enqueued';
                EXCEPTION
                    WHEN OTHER THEN
                        action_status := 'error';
                        result_detail := 'Webhook failed: ' || SQLERRM;
                END;

            ELSE
                IF (:pb_action = 'api_call') THEN
                    api_url := :pb_config:url::VARCHAR;
                    api_auth := :pb_config:auth_header::VARCHAR;
                    api_payload := OBJECT_CONSTRUCT(
                        'playbook', :pb_name,
                        'finding_id', :P_FINDING_ID,
                        'description', :f_desc,
                        'severity', :f_severity,
                        'rule', :f_rule,
                        'entity', :f_entity,
                        'time', CURRENT_TIMESTAMP()
                    )::VARCHAR;
                    BEGIN
                        SELECT SNOWFLAKE_XDR.RESPONSE.CALL_API(:api_url, :api_payload, COALESCE(:api_auth, ''))
                        INTO :result_detail;
                        IF (STARTSWITH(:result_detail, 'error=')) THEN
                            action_status := 'error';
                        END IF;
                    EXCEPTION
                        WHEN OTHER THEN
                            action_status := 'error';
                            result_detail := 'API call failed: ' || SQLERRM;
                    END;

                ELSE
                    IF (:pb_action = 'create_incident') THEN
                        BEGIN
                            CALL SNOWFLAKE_XDR.INCIDENTS.CORRELATE_INCIDENTS();
                            result_detail := 'Incident correlation executed';
                        EXCEPTION
                            WHEN OTHER THEN
                                action_status := 'error';
                                result_detail := 'Incident creation failed: ' || SQLERRM;
                        END;

                    ELSE
                        IF (:pb_action = 'ai_triage') THEN
                            BEGIN
                                CALL SNOWFLAKE_XDR.DETECTIONS.AI_TRIAGE_AGENT(1);
                                result_detail := 'AI triage executed for finding';
                            EXCEPTION
                                WHEN OTHER THEN
                                    action_status := 'error';
                                    result_detail := 'AI triage failed: ' || SQLERRM;
                            END;
                        END IF;
                    END IF;
                END IF;
            END IF;
        END IF;

        INSERT INTO SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS
            (playbook_id, playbook_name, finding_id, action_type, status, detail)
        VALUES (:pb_id, :pb_name, :P_FINDING_ID, :pb_action, :action_status, :result_detail);

        actions_fired := :actions_fired + 1;
    END FOR;

    RETURN 'Response evaluation complete. Actions fired: ' || :actions_fired;
END;
$$;

-- ---------------------------------------------------------------------------
-- Evaluate all unactioned findings (used after detection runs)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.RESPONSE.EVALUATE_ALL_NEW_FINDINGS()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    total_actions NUMBER DEFAULT 0;
    eval_result VARCHAR;
    findings_cursor CURSOR FOR
        SELECT finding_id
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE status = 'new'
          AND detection_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())
          AND finding_id NOT IN (SELECT finding_id FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS)
        ORDER BY severity DESC, detection_time DESC
        LIMIT 100;
    cur_finding VARCHAR;
BEGIN
    FOR rec IN findings_cursor DO
        cur_finding := rec.finding_id;
        BEGIN
            CALL SNOWFLAKE_XDR.RESPONSE.EVALUATE_RESPONSE(:cur_finding)
            INTO :eval_result;
            IF (STARTSWITH(:eval_result, 'Response evaluation complete')) THEN
                total_actions := :total_actions
                    + CAST(SPLIT_PART(:eval_result, ': ', 2) AS NUMBER);
            END IF;
        EXCEPTION
            WHEN OTHER THEN
                CONTINUE;
        END;
    END FOR;

    RETURN 'Batch response evaluation complete. Total actions fired: ' || :total_actions;
END;
$$;

-- ---------------------------------------------------------------------------
-- CRUD helper for the UI
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.RESPONSE.SAVE_PLAYBOOK(
    P_PLAYBOOK_ID VARCHAR,
    P_NAME VARCHAR,
    P_DESCRIPTION VARCHAR,
    P_SEV_MIN NUMBER,
    P_RULE_IDS ARRAY,
    P_CATEGORIES ARRAY,
    P_ENTITY VARCHAR,
    P_THRESHOLD NUMBER,
    P_WINDOW NUMBER,
    P_COOLDOWN NUMBER,
    P_ACTION_TYPE VARCHAR,
    P_ACTION_CONFIG VARIANT,
    P_ENABLED BOOLEAN
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_count NUMBER;
BEGIN
    SELECT COUNT(*) INTO :v_count
    FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOKS
    WHERE playbook_id = :P_PLAYBOOK_ID;

    IF (:v_count = 0) THEN
        INSERT INTO SNOWFLAKE_XDR.RESPONSE.PLAYBOOKS
            (name, description, trigger_severity_min, trigger_rule_ids,
             trigger_categories, trigger_entity, threshold_count,
             threshold_window_minutes, cooldown_minutes, action_type,
             action_config, enabled, created_by)
        SELECT :P_NAME, :P_DESCRIPTION, :P_SEV_MIN, :P_RULE_IDS,
                :P_CATEGORIES, :P_ENTITY, :P_THRESHOLD, :P_WINDOW,
                :P_COOLDOWN, :P_ACTION_TYPE, :P_ACTION_CONFIG, :P_ENABLED, 'ui';
        RETURN 'CREATED';
    ELSE
        UPDATE SNOWFLAKE_XDR.RESPONSE.PLAYBOOKS
        SET name = :P_NAME, description = :P_DESCRIPTION,
            trigger_severity_min = :P_SEV_MIN, trigger_rule_ids = :P_RULE_IDS,
            trigger_categories = :P_CATEGORIES, trigger_entity = :P_ENTITY,
            threshold_count = :P_THRESHOLD, threshold_window_minutes = :P_WINDOW,
            cooldown_minutes = :P_COOLDOWN, action_type = :P_ACTION_TYPE,
            action_config = :P_ACTION_CONFIG, enabled = :P_ENABLED,
            updated_at = CURRENT_TIMESTAMP()
        WHERE playbook_id = :P_PLAYBOOK_ID;
        RETURN 'UPDATED';
    END IF;
END;
$$;
