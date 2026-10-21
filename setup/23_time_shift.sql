-- ============================================================================
-- Snowflake XDR - 23: Demo Clock (time shift)
-- ============================================================================
-- SHIFT_DEMO_TIME() moves the whole demo forward in time so the newest
-- telemetry lands at "now". Every view filters on the last 7 days, so a demo
-- dataset generated weeks ago would otherwise look empty.
--
-- It discovers every TIMESTAMP column in the RAW_LOGS, DETECTIONS, INCIDENTS,
-- REFERENCE and RESPONSE schemas and shifts them all by the same delta, which
-- keeps every relative ordering (kill chains, baselines, lag) intact.
-- Shifts by whole days (keeps time buckets aligned); no-op when the
-- newest event is less than a day old.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.SHIFT_DEMO_TIME()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_latest TIMESTAMP_LTZ;
    v_delta NUMBER;
    v_tables NUMBER DEFAULT 0;
    v_sql VARCHAR;
    ts_cols CURSOR FOR
        SELECT c.table_schema, c.table_name,
               LISTAGG('"' || c.column_name || '" = DATEADD(second, DELTA_SECONDS, "'
                       || c.column_name || '")', ', ') AS set_clause
        FROM SNOWFLAKE_XDR.INFORMATION_SCHEMA.COLUMNS c
        JOIN SNOWFLAKE_XDR.INFORMATION_SCHEMA.TABLES t
          ON t.table_schema = c.table_schema
         AND t.table_name = c.table_name
         AND t.table_type = 'BASE TABLE'
        WHERE c.table_schema IN ('RAW_LOGS', 'DETECTIONS', 'INCIDENTS', 'REFERENCE', 'RESPONSE')
          AND c.data_type LIKE 'TIMESTAMP%'
          -- Static MITRE reference data has no event times worth moving
          AND c.table_name NOT IN ('MITRE_TACTICS', 'MITRE_TECHNIQUES')
        GROUP BY c.table_schema, c.table_name;
BEGIN
    -- Anchor: the newest event across the high-volume telemetry tables
    v_latest := (SELECT GREATEST(
               COALESCE((SELECT MAX(_time) FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION), '1970-01-01'::TIMESTAMP_LTZ),
               COALESCE((SELECT MAX(_time) FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC), '1970-01-01'::TIMESTAMP_LTZ),
               COALESCE((SELECT MAX(_time) FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY), '1970-01-01'::TIMESTAMP_LTZ),
               COALESCE((SELECT MAX(_time) FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES), '1970-01-01'::TIMESTAMP_LTZ)));

    IF (v_latest = '1970-01-01'::TIMESTAMP_LTZ) THEN
        RETURN 'No telemetry yet - nothing to shift.';
    END IF;

    -- Whole days only: keeps every minute/hour/day bucket aligned, so
    -- detection dedup keys (TIME_SLICE windows, per-day anomalies) still match
    v_delta := FLOOR(DATEDIFF('second', v_latest, CURRENT_TIMESTAMP()) / 86400) * 86400;
    IF (v_delta < 86400) THEN
        RETURN 'Demo clock already current (newest event '
            || DATEDIFF('minute', v_latest, CURRENT_TIMESTAMP()) || ' min ago) - no shift.';
    END IF;

    -- v_delta is an internally computed integer, so inlining it as a literal
    -- is safe; table/column names come from INFORMATION_SCHEMA and are quoted.
    FOR rec IN ts_cols DO
        v_sql := 'UPDATE SNOWFLAKE_XDR."' || rec.table_schema || '"."' || rec.table_name
              || '" SET ' || REPLACE(rec.set_clause, 'DELTA_SECONDS', v_delta::VARCHAR);
        EXECUTE IMMEDIATE v_sql;
        v_tables := v_tables + 1;
    END FOR;

    RETURN 'Shifted demo clock forward ' || ROUND(v_delta / 86400, 1) || ' days across '
        || v_tables || ' tables.';
END;
$$;

-- ---------------------------------------------------------------------------
-- DEDUPE_FINDINGS(): remove duplicate findings created by re-running
-- detections over the same events (the built-in rules are written for a
-- scheduler and re-flag their lookback window on every manual run).
-- A duplicate is the same rule + entities + event time (hour bucket for the
-- hourly door-rattling windows). The copy that has been worked on (incident,
-- disposition, notes) is kept.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DEDUPE_FINDINGS()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_removed NUMBER;
BEGIN
    DELETE FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    USING (
        SELECT finding_id
        FROM (
            SELECT finding_id,
                   ROW_NUMBER() OVER (
                       PARTITION BY rule_id,
                                    COALESCE(user_name, ''), COALESCE(src, ''), COALESCE(dest, ''),
                                    IFF(rule_id = 'GRAPH-RATTLE-001',
                                        DATE_TRUNC('hour', event_time), event_time)
                       ORDER BY IFF(incident_id IS NOT NULL, 0, 1),
                                IFF(disposition IS NOT NULL, 0, 1),
                                IFF(triage_notes IS NOT NULL, 0, 1),
                                detection_time, finding_id) AS rn
            FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        )
        WHERE rn > 1
    ) dupes
    WHERE DETECTION_FINDINGS.finding_id = dupes.finding_id;

    v_removed := SQLROWCOUNT;
    RETURN 'Removed ' || :v_removed || ' duplicate findings.';
END;
$$;

-- ---------------------------------------------------------------------------
-- REPLAY_DETECTIONS(P_DAYS): backfill detections over historical telemetry.
-- The built-in rules look back 15-60 minutes from DETECTION_NOW(). On a fresh
-- build that only covers the newest hour of the 7-day dataset, so this steps
-- the detection clock through every "hot" hour (activity well above the
-- table's hourly average, or traffic touching a known-bad IOC IP) and runs all
-- detections as of the end of that hour. Findings keep their true event times.
-- The clock is always reset to real time, including on error.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.REPLAY_DETECTIONS(P_DAYS NUMBER DEFAULT 7)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_hours NUMBER DEFAULT 0;
    v_before NUMBER;
    v_after NUMBER;
    v_as_of VARCHAR;
    v_sql VARCHAR;
    rs RESULTSET;
BEGIN
    SELECT COUNT(*) INTO :v_before FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS;

    -- Hot-hour query: declared cursors can't bind procedure args, so build a
    -- RESULTSET with USING and iterate a cursor over it
    v_sql := '        WITH h AS (
            SELECT ''auth'' t, DATE_TRUNC(''hour'', _time) hr, COUNT(*) c FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION GROUP BY 1, 2
            UNION ALL SELECT ''proc'', DATE_TRUNC(''hour'', _time), COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES GROUP BY 1, 2
            UNION ALL SELECT ''net'', DATE_TRUNC(''hour'', _time), COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC GROUP BY 1, 2
            UNION ALL SELECT ''fs'', DATE_TRUNC(''hour'', _time), COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_FILESYSTEM GROUP BY 1, 2
            UNION ALL SELECT ''reg'', DATE_TRUNC(''hour'', _time), COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_REGISTRY GROUP BY 1, 2
            UNION ALL SELECT ''svc'', DATE_TRUNC(''hour'', _time), COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_SERVICES GROUP BY 1, 2
            UNION ALL SELECT ''dns'', DATE_TRUNC(''hour'', _time), COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY GROUP BY 1, 2
            UNION ALL SELECT ''web'', DATE_TRUNC(''hour'', _time), COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY GROUP BY 1, 2
            UNION ALL SELECT ''cloud'', DATE_TRUNC(''hour'', _time), COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API GROUP BY 1, 2
            UNION ALL SELECT ''ids'', DATE_TRUNC(''hour'', _time), COUNT(*) FROM SNOWFLAKE_XDR.RAW_LOGS.INTRUSION_DETECTION GROUP BY 1, 2
        ),
        scored AS (
            -- hourly count vs. the table''s average hour over the window
            SELECT hr, c / GREATEST(SUM(c) OVER (PARTITION BY t) / (24.0 * ?), 1) AS score, c
            FROM h
        ),
        ioc AS (
            SELECT DISTINCT DATE_TRUNC(''hour'', n._time) AS hr
            FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC n
            JOIN SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS i
              ON i.active AND i.ioc_type = ''ip'' AND i.ioc_value IN (n.dest_ip, n.src_ip, n.dest)
        )
        SELECT DISTINCT hr FROM (
            SELECT hr FROM scored WHERE score >= 3 AND c >= 3
            UNION SELECT hr FROM ioc
        )
        WHERE hr > DATEADD(''day'', -?, CURRENT_TIMESTAMP())
          -- the newest hours are covered by the normal real-time run
          AND hr < DATEADD(''hour'', -1, CURRENT_TIMESTAMP())
        ORDER BY hr';
    rs := (EXECUTE IMMEDIATE :v_sql USING (P_DAYS, P_DAYS));
    LET hot_hours CURSOR FOR rs;
    FOR rec IN hot_hours DO
        -- End of the hot hour, so 15-60 minute rule windows cover it
        v_as_of := TO_VARCHAR(DATEADD('minute', 59, rec.hr), 'YYYY-MM-DD HH24:MI:SS.FF3 TZHTZM');
        MERGE INTO SNOWFLAKE_XDR.REFERENCE.PLATFORM_SETTINGS t
        USING (SELECT 'detection_as_of' AS k, :v_as_of AS v) s ON t.setting_key = s.k
        WHEN MATCHED THEN UPDATE SET setting_value = s.v, updated_at = CURRENT_TIMESTAMP()
        WHEN NOT MATCHED THEN INSERT (setting_key, setting_value) VALUES (s.k, s.v);
        CALL SNOWFLAKE_XDR.DETECTIONS.RUN_ALL_DETECTIONS();
        v_hours := v_hours + 1;
    END FOR;

    DELETE FROM SNOWFLAKE_XDR.REFERENCE.PLATFORM_SETTINGS WHERE setting_key = 'detection_as_of';
    SELECT COUNT(*) INTO :v_after FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS;
    RETURN 'Replayed detections over ' || :v_hours || ' hot hour(s); new findings: ' || (:v_after - :v_before) || '.';
EXCEPTION
    WHEN OTHER THEN
        -- Never leave the detection clock frozen in the past
        DELETE FROM SNOWFLAKE_XDR.REFERENCE.PLATFORM_SETTINGS WHERE setting_key = 'detection_as_of';
        RAISE;
END;
$$;
