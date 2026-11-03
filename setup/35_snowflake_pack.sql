-- ============================================================================
-- Snowflake XDR - Snowflake rule pack data lanes (Phase 4)
-- ============================================================================
-- Three lanes feed the Snowflake pack (rule-packs/snowflake/pack.yaml):
--
--   fast          INFORMATION_SCHEMA.LOGIN_HISTORY() / QUERY_HISTORY() table
--                 functions: near real time, 7 days, 10k rows per call. Runs
--                 every 5 minutes so time-sensitive rules (brute force,
--                 privilege grants, exfil) fire within minutes.
--   history       SNOWFLAKE.ACCOUNT_USAGE LOGIN_HISTORY / QUERY_HISTORY /
--                 SESSIONS: complete and authoritative but 45 min - 3 h late.
--                 Hourly; fills anything the fast lane missed (event ids are
--                 shared, so rows are deduplicated) and back-fills the client
--                 IP of queries via SESSIONS -> LOGIN_HISTORY.
--   trust_center  SNOWFLAKE.TRUST_CENTER.FINDINGS: open scanner findings
--                 (CIS benchmarks, Security Essentials, threat scanners) become
--                 TC-<scanner> detection findings, so posture problems join the
--                 same triage, correlation and case flow as detections.
--
-- Logins land in AUTHENTICATION (so DET-001 brute force etc. also cover
-- Snowflake); statements land in DATABASE_ACTIVITY.
--
-- Requires: ACCOUNT_USAGE access (IMPORTED PRIVILEGES on SNOWFLAKE) and the
-- SNOWFLAKE.TRUST_CENTER_VIEWER application role for the Trust Center lane.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.TELEMETRY_LANES (
    lane         VARCHAR(30) PRIMARY KEY,
    watermark    TIMESTAMP_LTZ,
    last_run     TIMESTAMP_LTZ,
    last_rows    NUMBER,
    total_rows   NUMBER DEFAULT 0,
    last_error   VARCHAR(2000)
);

MERGE INTO SNOWFLAKE_XDR.REFERENCE.TELEMETRY_LANES t
USING (SELECT column1 AS lane FROM VALUES ('snowflake_fast'), ('snowflake_history'), ('trust_center')) s
ON t.lane = s.lane
WHEN NOT MATCHED THEN INSERT (lane, watermark) VALUES (s.lane, DATEADD('day', -2, CURRENT_TIMESTAMP()));

-- Statement types worth keeping. Plain reads and writes are only kept when
-- they are large or fail, which keeps volume low without losing exfil signals.
CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.REFERENCE.SF_KEEP_QUERY(
    QT VARCHAR, STATUS VARCHAR, ROWS_OUT NUMBER, OUT_BYTES NUMBER)
RETURNS BOOLEAN
AS
$$
    COALESCE(QT, '') NOT IN ('SHOW', 'DESCRIBE', 'USE', 'ALTER_SESSION', 'COMMIT', 'ROLLBACK',
                             'BEGIN_TRANSACTION', 'REFRESH GLOBAL DATABASE', 'ALTER_PIPE',
                             'REFRESH DYNAMIC TABLE AT REFRESH VERSION', 'UNKNOWN',
                             'REFRESH_GLOBAL_DATABASE', 'REFRESH_DYNAMIC_TABLE_AT_REFRESH_VERSION',
                             'BEGIN_TRANSACTION', 'LIST_FILES')
    AND (COALESCE(QT, '') NOT IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'CALL')
         OR COALESCE(STATUS, 'SUCCESS') <> 'SUCCESS'
         OR COALESCE(ROWS_OUT, 0) >= 100000
         OR COALESCE(OUT_BYTES, 0) > 0)
$$;

-- Coarse statement class used by rules (action column)
CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.REFERENCE.SF_ACTION(QT VARCHAR)
RETURNS VARCHAR
AS
$$
    CASE
        WHEN QT IN ('GRANT', 'REVOKE') THEN LOWER(QT)
        WHEN QT = 'UNLOAD' THEN 'unload'
        WHEN QT IN ('GET_FILES', 'PUT_FILES', 'LIST_FILES', 'REMOVE_FILES') THEN 'stage_file'
        WHEN QT LIKE 'CREATE%' THEN 'create'
        WHEN QT LIKE 'ALTER%' THEN 'alter'
        WHEN QT LIKE 'DROP%' THEN 'drop'
        WHEN QT IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'COPY', 'CALL') THEN LOWER(QT)
        ELSE 'other'
    END
$$;

-- ---------------------------------------------------------------------------
-- SYNC_SNOWFLAKE_TELEMETRY('fast' | 'history' | 'trust_center' | 'all')
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.SYNC_SNOWFLAKE_TELEMETRY(P_LANE VARCHAR)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    lane VARCHAR := LOWER(COALESCE(:P_LANE, 'all'));
    wm TIMESTAMP_LTZ;
    started TIMESTAMP_LTZ := CURRENT_TIMESTAMP();
    n_login NUMBER DEFAULT 0;
    n_query NUMBER DEFAULT 0;
    n_tc NUMBER DEFAULT 0;
    acct VARCHAR := CURRENT_ACCOUNT_NAME();
    errs ARRAY := ARRAY_CONSTRUCT();
    err VARCHAR;
BEGIN
    -- ---------------------------------------------------------------- fast lane
    IF (lane IN ('fast', 'all')) THEN
        BEGIN
            SELECT GREATEST(DATEADD('minute', -10, watermark), DATEADD('hour', -167, CURRENT_TIMESTAMP()))
              INTO :wm FROM SNOWFLAKE_XDR.REFERENCE.TELEMETRY_LANES WHERE lane = 'snowflake_fast';

            MERGE INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION t
            USING (
                SELECT 'sflogin:' || event_id AS event_id, event_timestamp AS _time,
                       IFF(is_success = 'YES', 'success', 'failure') AS action, 'snowflake' AS app,
                       first_authentication_factor || COALESCE('+' || second_authentication_factor, '') AS authentication_method,
                       'Snowflake' AS authentication_service, :acct AS dest, error_message AS reason,
                       event_type AS signature, error_code::VARCHAR AS signature_id, client_ip AS src,
                       user_name, reported_client_type || ' ' || COALESCE(reported_client_version, '') AS user_agent,
                       OBJECT_CONSTRUCT('event_id', event_id, 'event_type', event_type, 'client_ip', client_ip,
                                        'client', reported_client_type, 'first_factor', first_authentication_factor,
                                        'second_factor', second_authentication_factor, 'is_success', is_success,
                                        'error_code', error_code, 'error_message', error_message, 'lane', 'fast') AS _raw
                FROM TABLE(SNOWFLAKE_XDR.INFORMATION_SCHEMA.LOGIN_HISTORY(
                         TIME_RANGE_START => :wm, RESULT_LIMIT => 10000))
            ) s
            ON t.event_id = s.event_id AND t.vendor_product = 'snowflake' AND t._time >= DATEADD('hour', -1, :wm)
            WHEN NOT MATCHED THEN INSERT (event_id, _time, action, app, authentication_method, authentication_service,
                    dest, reason, signature, signature_id, src, user_name, user_agent, vendor_account, vendor_product,
                    source, sourcetype, _raw)
                VALUES (s.event_id, s._time, s.action, s.app, s.authentication_method, s.authentication_service,
                    s.dest, s.reason, s.signature, s.signature_id, s.src, s.user_name, s.user_agent, :acct, 'snowflake',
                    'INFORMATION_SCHEMA.LOGIN_HISTORY', 'snowflake:login', s._raw);
            n_login := n_login + SQLROWCOUNT;

            MERGE INTO SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY t
            USING (SELECT q.*, a.src FROM (
                SELECT 'sfquery:' || query_id AS event_id, start_time AS _time,
                       SNOWFLAKE_XDR.REFERENCE.SF_ACTION(query_type) AS action, user_name, role_name AS user_role,
                       query_type, LEFT(query_text, 16000) AS query_text,
                       NULLIF(CONCAT_WS('.', database_name, schema_name), '') AS object,
                       IFF(execution_status = 'SUCCESS', 'success', 'failure') AS result, error_message AS reason,
                       COALESCE(rows_produced, rows_inserted) AS rows_affected,
                       COALESCE(NULLIF(outbound_data_transfer_bytes, 0), bytes_scanned) AS bytes,
                       warehouse_name AS warehouse, session_id::VARCHAR AS session_id, authn_event_id,
                       OBJECT_CONSTRUCT('query_id', query_id, 'query_tag', query_tag, 'user_type', user_type,
                                        'outbound_bytes', outbound_data_transfer_bytes,
                                        'outbound_cloud', outbound_data_transfer_cloud,
                                        'outbound_region', outbound_data_transfer_region,
                                        'authn_event_id', authn_event_id, 'lane', 'fast') AS _raw
                FROM TABLE(SNOWFLAKE_XDR.INFORMATION_SCHEMA.QUERY_HISTORY(
                         END_TIME_RANGE_START => :wm, RESULT_LIMIT => 10000))
                WHERE SNOWFLAKE_XDR.REFERENCE.SF_KEEP_QUERY(query_type, execution_status, rows_produced,
                                                           outbound_data_transfer_bytes)
                  AND session_id <> CURRENT_SESSION()::NUMBER
            ) q
            -- the session's login event gives the client IP when the fast lane already saw it
            LEFT JOIN (SELECT event_id AS login_id, src FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
                       WHERE vendor_product = 'snowflake' AND _time >= DATEADD('day', -8, :wm)) a
              ON a.login_id = 'sflogin:' || q.authn_event_id) s
            ON t.event_id = s.event_id AND t.vendor_product = 'snowflake' AND t._time >= DATEADD('day', -1, :wm)
            WHEN NOT MATCHED THEN INSERT (event_id, _time, action, user_name, user_role, src, dest, query_type,
                    query_text, object, result, reason, rows_affected, bytes, warehouse, session_id, vendor_account,
                    vendor_product, lane, source, sourcetype, _raw)
                VALUES (s.event_id, s._time, s.action, s.user_name, s.user_role, s.src, :acct, s.query_type, s.query_text, s.object, s.result, s.reason, s.rows_affected, s.bytes,
                    s.warehouse, s.session_id, :acct, 'snowflake', 'fast', 'INFORMATION_SCHEMA.QUERY_HISTORY',
                    'snowflake:query', s._raw);
            n_query := n_query + SQLROWCOUNT;

            UPDATE SNOWFLAKE_XDR.REFERENCE.TELEMETRY_LANES
               SET watermark = :started, last_run = CURRENT_TIMESTAMP(), last_rows = :n_login + :n_query,
                   total_rows = total_rows + :n_login + :n_query, last_error = NULL
             WHERE lane = 'snowflake_fast';
        EXCEPTION WHEN OTHER THEN
            err := SQLERRM;
            errs := ARRAY_APPEND(:errs, 'fast: ' || :err);
            UPDATE SNOWFLAKE_XDR.REFERENCE.TELEMETRY_LANES SET last_run = CURRENT_TIMESTAMP(), last_error = :err
             WHERE lane = 'snowflake_fast';
        END;
    END IF;

    -- ---------------------------------------------------------------- history lane
    IF (lane IN ('history', 'history_tc', 'all')) THEN
        BEGIN
            LET h_login NUMBER := 0;
            LET h_query NUMBER := 0;
            -- ACCOUNT_USAGE is up to ~3h late: always re-read the last 4 hours
            SELECT LEAST(DATEADD('hour', -4, watermark), DATEADD('hour', -4, CURRENT_TIMESTAMP()))
              INTO :wm FROM SNOWFLAKE_XDR.REFERENCE.TELEMETRY_LANES WHERE lane = 'snowflake_history';

            MERGE INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION t
            USING (
                SELECT 'sflogin:' || event_id AS event_id, event_timestamp AS _time,
                       IFF(is_success = 'YES', 'success', 'failure') AS action,
                       first_authentication_factor || COALESCE('+' || second_authentication_factor, '') AS authentication_method,
                       error_message AS reason, event_type AS signature, error_code::VARCHAR AS signature_id,
                       client_ip AS src, user_name,
                       reported_client_type || ' ' || COALESCE(reported_client_version, '') AS user_agent,
                       OBJECT_CONSTRUCT('event_id', event_id, 'event_type', event_type, 'client_ip', client_ip,
                                        'client', reported_client_type, 'first_factor', first_authentication_factor,
                                        'second_factor', second_authentication_factor, 'is_success', is_success,
                                        'error_code', error_code, 'error_message', error_message, 'lane', 'history') AS _raw
                FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
                WHERE event_timestamp >= :wm
            ) s
            ON t.event_id = s.event_id AND t.vendor_product = 'snowflake' AND t._time >= DATEADD('hour', -1, :wm)
            WHEN NOT MATCHED THEN INSERT (event_id, _time, action, app, authentication_method, authentication_service,
                    dest, reason, signature, signature_id, src, user_name, user_agent, vendor_account, vendor_product,
                    source, sourcetype, _raw)
                VALUES (s.event_id, s._time, s.action, 'snowflake', s.authentication_method, 'Snowflake', :acct,
                    s.reason, s.signature, s.signature_id, s.src, s.user_name, s.user_agent, :acct, 'snowflake',
                    'ACCOUNT_USAGE.LOGIN_HISTORY', 'snowflake:login', s._raw);
            h_login := SQLROWCOUNT;

            MERGE INTO SNOWFLAKE_XDR.RAW_LOGS.DATABASE_ACTIVITY t
            USING (
                SELECT 'sfquery:' || q.query_id AS event_id, q.start_time AS _time,
                       SNOWFLAKE_XDR.REFERENCE.SF_ACTION(q.query_type) AS action, q.user_name, q.role_name AS user_role,
                       l.client_ip AS src, q.query_type, LEFT(q.query_text, 16000) AS query_text,
                       NULLIF(CONCAT_WS('.', q.database_name, q.schema_name), '') AS object,
                       IFF(q.execution_status = 'SUCCESS', 'success', 'failure') AS result, q.error_message AS reason,
                       COALESCE(q.rows_produced, q.rows_inserted) AS rows_affected,
                       COALESCE(NULLIF(q.outbound_data_transfer_bytes, 0), q.bytes_scanned) AS bytes,
                       q.warehouse_name AS warehouse, q.session_id::VARCHAR AS session_id,
                       PARSE_JSON(se.client_environment):APPLICATION::VARCHAR AS app,
                       OBJECT_CONSTRUCT('query_id', q.query_id, 'query_tag', q.query_tag,
                                        'outbound_bytes', q.outbound_data_transfer_bytes,
                                        'outbound_cloud', q.outbound_data_transfer_cloud,
                                        'outbound_region', q.outbound_data_transfer_region,
                                        'client_ip', l.client_ip, 'lane', 'history') AS _raw
                FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY q
                LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.SESSIONS se ON se.session_id = q.session_id
                LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY l ON l.event_id = se.login_event_id
                WHERE q.start_time >= :wm
                  AND SNOWFLAKE_XDR.REFERENCE.SF_KEEP_QUERY(q.query_type, q.execution_status, q.rows_produced,
                                                           q.outbound_data_transfer_bytes)
            ) s
            ON t.event_id = s.event_id AND t.vendor_product = 'snowflake' AND t._time >= DATEADD('hour', -1, :wm)
            -- fast-lane rows have no client IP or application: complete them from the history lane
            WHEN MATCHED AND (t.src IS NULL OR t.app IS NULL) AND (s.src IS NOT NULL OR s.app IS NOT NULL)
                THEN UPDATE SET src = COALESCE(t.src, s.src), app = COALESCE(t.app, s.app)
            WHEN NOT MATCHED THEN INSERT (event_id, _time, action, user_name, user_role, src, dest, app, query_type,
                    query_text, object, result, reason, rows_affected, bytes, warehouse, session_id, vendor_account,
                    vendor_product, lane, source, sourcetype, _raw)
                VALUES (s.event_id, s._time, s.action, s.user_name, s.user_role, s.src, :acct, s.app, s.query_type,
                    s.query_text, s.object, s.result, s.reason, s.rows_affected, s.bytes, s.warehouse, s.session_id,
                    :acct, 'snowflake', 'history', 'ACCOUNT_USAGE.QUERY_HISTORY', 'snowflake:query', s._raw);
            h_query := SQLROWCOUNT;
            n_login := n_login + h_login;
            n_query := n_query + h_query;

            UPDATE SNOWFLAKE_XDR.REFERENCE.TELEMETRY_LANES
               SET watermark = :started, last_run = CURRENT_TIMESTAMP(), last_rows = :h_login + :h_query,
                   total_rows = total_rows + :h_login + :h_query, last_error = NULL
             WHERE lane = 'snowflake_history';
        EXCEPTION WHEN OTHER THEN
            err := SQLERRM;
            errs := ARRAY_APPEND(:errs, 'history: ' || :err);
            UPDATE SNOWFLAKE_XDR.REFERENCE.TELEMETRY_LANES SET last_run = CURRENT_TIMESTAMP(), last_error = :err
             WHERE lane = 'snowflake_history';
        END;
    END IF;

    -- ---------------------------------------------------------------- Trust Center
    IF (lane IN ('trust_center', 'history_tc', 'all')) THEN
        BEGIN
            -- Latest scan per finding identifier; one XDR finding per open identifier. A new
            -- finding is raised when the at-risk count grows (posture regressed) or after 30 days.
            INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
                (finding_id, rule_id, detection_time, event_time, severity, confidence, risk_score,
                 mitre_tactic_id, mitre_technique_id, category, user_name, dest, affected_entities,
                 evidence, evidence_count, description, status, detection_source)
            SELECT UUID_STRING(), 'TC-' || f.scanner_id, CURRENT_TIMESTAMP(), f.start_timestamp,
                   f.sev, 90, f.sev * 20,
                   IFF(f.is_threat, 'TA0001', NULL), IFF(f.is_threat, 'T1078', NULL),
                   IFF(f.is_threat, 'identity', 'posture'),
                   IFF(f.total_at_risk_count = 1, f.at_risk_entities[0]:entity_name::VARCHAR, NULL),
                   :acct,
                   f.at_risk_entities,
                   OBJECT_CONSTRUCT('finding_identifier', f.finding_identifier, 'scanner', f.scanner_name,
                                    'package', f.scanner_package_name, 'at_risk', f.total_at_risk_count,
                                    'suggested_action', LEFT(f.suggested_action, 2000),
                                    'impact', LEFT(f.impact, 1000), 'trust_center_event_id', f.event_id),
                   f.total_at_risk_count,
                   LEFT('Trust Center: ' || COALESCE(NULLIF(f.scanner_short_description, ''), f.scanner_name) ||
                        ' (' || f.total_at_risk_count || ' at risk)', 4000),
                   'new', 'trust_center'
            FROM (
                SELECT x.*,
                       DECODE(UPPER(x.severity), 'CRITICAL', 5, 'HIGH', 4, 'MEDIUM', 3, 'LOW', 2, 1) AS sev,
                       x.scanner_package_id NOT IN ('CIS_BENCHMARKS', 'SECURITY_ESSENTIALS') AS is_threat
                FROM SNOWFLAKE.TRUST_CENTER.FINDINGS x
                WHERE x.start_timestamp > DATEADD('day', -3, CURRENT_TIMESTAMP())
                  AND COALESCE(x.state, 'Open') = 'Open' AND x.total_at_risk_count > 0
                QUALIFY ROW_NUMBER() OVER (PARTITION BY x.finding_identifier ORDER BY x.start_timestamp DESC) = 1
            ) f
            LEFT JOIN (
                SELECT evidence:finding_identifier::VARCHAR AS fid, MAX(evidence:at_risk::NUMBER) AS at_risk
                FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
                WHERE detection_source = 'trust_center' AND detection_time > DATEADD('day', -30, CURRENT_TIMESTAMP())
                GROUP BY 1
            ) prev ON prev.fid = f.finding_identifier
            WHERE f.sev >= 3
              AND (prev.fid IS NULL OR f.total_at_risk_count > prev.at_risk);
            n_tc := SQLROWCOUNT;
            UPDATE SNOWFLAKE_XDR.REFERENCE.TELEMETRY_LANES
               SET watermark = CURRENT_TIMESTAMP(), last_run = CURRENT_TIMESTAMP(), last_rows = :n_tc,
                   total_rows = total_rows + :n_tc, last_error = NULL
             WHERE lane = 'trust_center';
        EXCEPTION WHEN OTHER THEN
            err := SQLERRM;
            errs := ARRAY_APPEND(:errs, 'trust_center: ' || :err);
            UPDATE SNOWFLAKE_XDR.REFERENCE.TELEMETRY_LANES SET last_run = CURRENT_TIMESTAMP(), last_error = :err
             WHERE lane = 'trust_center';
        END;
    END IF;

    RETURN OBJECT_CONSTRUCT('ok', ARRAY_SIZE(:errs) = 0, 'logins', :n_login, 'statements', :n_query,
                            'trust_center_findings', :n_tc, 'errors', :errs);
END;
$$;

-- Fast lane + rules every 5 minutes; history + Trust Center hourly.
-- Suspended by default like every other XDR task: ALTER TASK ... RESUME.
CREATE OR REPLACE TASK SNOWFLAKE_XDR.REFERENCE.TASK_SNOWFLAKE_FAST_LANE
    WAREHOUSE = XDR_WH
    SCHEDULE = '5 MINUTE'
    COMMENT = 'Snowflake pack: INFORMATION_SCHEMA fast lane, then custom/pack rules'
AS
EXECUTE IMMEDIATE $$
BEGIN
    CALL SNOWFLAKE_XDR.REFERENCE.SYNC_SNOWFLAKE_TELEMETRY('fast');
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULES();
END;
$$;

CREATE OR REPLACE TASK SNOWFLAKE_XDR.REFERENCE.TASK_SNOWFLAKE_HISTORY_LANE
    WAREHOUSE = XDR_WH
    SCHEDULE = '60 MINUTE'
    COMMENT = 'Snowflake pack: ACCOUNT_USAGE history lane and Trust Center findings'
AS
    CALL SNOWFLAKE_XDR.REFERENCE.SYNC_SNOWFLAKE_TELEMETRY('history_tc');
