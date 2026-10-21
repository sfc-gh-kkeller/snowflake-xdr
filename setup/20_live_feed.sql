-- ============================================================================
-- Snowflake XDR - 20: Live Tail with Lagged Sources
-- ============================================================================
-- EMIT_LIVE_EVENTS generates "fresh" telemetry (mostly benign, configurable
-- attack rate) with per-source ingestion delays: endpoint 20-45 min behind,
-- auth 2-5 min, DNS near-real-time, network 0-2 min. V_LIVE_FEED surfaces the
-- lag so analysts know which sources are behind.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Live event emitter with per-source delays
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.RAW_LOGS.EMIT_LIVE_EVENTS(
    P_BATCHES NUMBER
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_batches NUMBER;
    v_events NUMBER;
BEGIN
    v_batches := 0;
    v_events := 0;

    -- Auth events: benign logins from known users, _time = now - 2..5 min
    WHILE (v_batches < :P_BATCHES) DO
        INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
            (_time, action, app, authentication_method, authentication_service,
             dest, src, user_name, host, source, sourcetype, index_name, ingestion_time)
        SELECT
            DATEADD('minute', -2 - ABS(HASH(UUID_STRING())) % 3, CURRENT_TIMESTAMP()),
            CASE WHEN ABS(HASH(UUID_STRING())) % 20 = 0 THEN 'failure' ELSE 'success' END,
            'vpn', 'password', 'OpenVPN',
            'host:VPN-GW-01',
            '10.1.' || TO_VARCHAR(ABS(HASH(UUID_STRING())) % 40 + 10) || '.'
                || TO_VARCHAR(ABS(HASH(UUID_STRING())) % 200 + 20),
            (SELECT COLUMN_VALUE FROM (
                SELECT VALUE AS COLUMN_VALUE FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(
                    'jsmith','kwu','abernathy','lgreco','mtanaka','rpatel','cvasquez','dhoffman'
                )))
            ) ORDER BY ABS(HASH(UUID_STRING())) LIMIT 1),
            'VPN-GW-01',
            '/var/log/vpn/auth.log', 'openvpn', 'auth',
            CURRENT_TIMESTAMP();
        v_events := :v_events + SQLROWCOUNT;

        -- DNS: near-real-time (0-30 s lag)
        INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
            (_time, action, src, dest, query, query_type, answer, reply_code,
             query_length, vendor_product, host, source, sourcetype, index_name, ingestion_time)
        SELECT
            DATEADD('second', -ABS(HASH(UUID_STRING())) % 30, CURRENT_TIMESTAMP()),
            'success', '10.1.2.42', 'host:DNS-01',
            (SELECT COLUMN_VALUE FROM (
                SELECT VALUE AS COLUMN_VALUE FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(
                    'updates.microsoft.com','cdn.example-corp.com','mail.example-corp.com','status.aws.amazon.com'
                )))
            ) ORDER BY ABS(HASH(UUID_STRING())) LIMIT 1),
            'A', '93.184.216.34', 'NOERROR',
            30, 'Bind', 'DNS-01',
            '/var/log/named/queries.log', 'bind:dns', 'dns',
            CURRENT_TIMESTAMP();
        v_events := :v_events + SQLROWCOUNT;

        -- Network: 0-2 min lag, occasional blocked port scan
        INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
            (_time, action, src, src_ip, dest, dest_ip, dest_port, transport,
             protocol, app, bytes, duration, rule, dvc, direction, host, source,
             sourcetype, index_name, ingestion_time)
        SELECT
            DATEADD('minute', -ABS(HASH(UUID_STRING())) % 2, CURRENT_TIMESTAMP()),
            CASE WHEN ABS(HASH(UUID_STRING())) % 25 = 0 THEN 'blocked' ELSE 'allowed' END,
            'WKS-00' || TO_VARCHAR(ABS(HASH(UUID_STRING())) % 3 + 1),
            '10.1.2.' || TO_VARCHAR(ABS(HASH(UUID_STRING())) % 200 + 20),
            'FS-FILE01', '10.1.3.10',
            CASE WHEN ABS(HASH(UUID_STRING())) % 10 = 0 THEN 445
                 ELSE IFF(ABS(HASH(UUID_STRING())) % 2 = 0, 443, 80) END,
            'tcp', 'HTTPS', 'app', 4096, 1.0,
            'Allow-Internal', 'FW-CORE', 'outbound', 'FW-CORE',
            '/var/log/firewall/core.log', 'firewall', 'network',
            CURRENT_TIMESTAMP();
        v_events := :v_events + SQLROWCOUNT;

        -- Endpoint: SLOW SOURCE - events land 20-45 min after they happened
        INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
            (_time, action, dest, user_name, process_name, process_path,
             parent_process_name, host, source, sourcetype, index_name, ingestion_time)
        SELECT
            DATEADD('minute', -20 - ABS(HASH(UUID_STRING())) % 25, CURRENT_TIMESTAMP()),
            'start', 'WKS-00' || TO_VARCHAR(ABS(HASH(UUID_STRING())) % 3 + 1),
            'system',
            (SELECT COLUMN_VALUE FROM (
                SELECT VALUE AS COLUMN_VALUE FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(
                    'svchost.exe','chrome.exe','teams.exe','explorer.exe'
                )))
            ) ORDER BY ABS(HASH(UUID_STRING())) LIMIT 1),
            'C:\\\\Windows\\\\System32\\\\svchost.exe', 'services.exe',
            'WKS-00' || TO_VARCHAR(ABS(HASH(UUID_STRING())) % 3 + 1),
            'edr/agent/logs/process.json', 'edr:process', 'endpoint',
            CURRENT_TIMESTAMP();
        v_events := :v_events + SQLROWCOUNT;

        v_batches := :v_batches + 1;
    END WHILE;

    RETURN 'Emitted ' || :v_events || ' live events in ' || :v_batches || ' batches.';
END;
$$;

-- ---------------------------------------------------------------------------
-- 2. Live feed view: latest events with lag and per-source state
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_LIVE_FEED AS
WITH latest AS (
    SELECT 'authentication' AS source_table, _time, ingestion_time, user_name AS entity,
           action, app AS detail
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE _time > DATEADD('hour', -1, CURRENT_TIMESTAMP())
    UNION ALL
    SELECT 'dns_activity', _time, ingestion_time, host, action, 'query ' || query
    FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
    WHERE _time > DATEADD('hour', -1, CURRENT_TIMESTAMP())
    UNION ALL
    SELECT 'network_traffic', _time, ingestion_time, src, action,
           protocol || '/' || COALESCE(dest_port::VARCHAR, '')
    FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    WHERE _time > DATEADD('hour', -1, CURRENT_TIMESTAMP())
    UNION ALL
    SELECT 'endpoint_processes', _time, ingestion_time, host, action, process_name
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE _time > DATEADD('hour', -2, CURRENT_TIMESTAMP())
)
SELECT
    source_table,
    _time AS event_time,
    ingestion_time,
    DATEDIFF('second', _time, ingestion_time) AS lag_seconds,
    CASE
        WHEN DATEDIFF('second', _time, ingestion_time) < 60 THEN 'real-time'
        WHEN DATEDIFF('second', _time, ingestion_time) < 900 THEN 'delayed'
        ELSE 'lagging'
    END AS source_state,
    entity,
    action,
    detail
FROM latest
ORDER BY _time DESC
LIMIT 200;

-- ---------------------------------------------------------------------------
-- 3. Per-source freshness with lag-based staleness (upgrades V_DATA_FRESHNESS)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_SOURCE_LAG AS
SELECT 'authentication' AS source_table,
       MAX(_time) AS latest_event,
       MIN(DATEDIFF('minute', _time, ingestion_time)) AS min_lag_min,
       MAX(DATEDIFF('minute', _time, ingestion_time)) AS max_lag_min,
       CASE WHEN MAX(_time) < DATEADD('minute', -10, CURRENT_TIMESTAMP())
            THEN 'STALE - source behind, detections may miss recent events'
            ELSE 'fresh' END AS health
FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
UNION ALL
SELECT 'dns_activity', MAX(_time),
       MIN(DATEDIFF('minute', _time, ingestion_time)),
       MAX(DATEDIFF('minute', _time, ingestion_time)),
       CASE WHEN MAX(_time) < DATEADD('minute', -10, CURRENT_TIMESTAMP())
            THEN 'STALE - source behind' ELSE 'fresh' END
FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
UNION ALL
SELECT 'network_traffic', MAX(_time),
       MIN(DATEDIFF('minute', _time, ingestion_time)),
       MAX(DATEDIFF('minute', _time, ingestion_time)),
       CASE WHEN MAX(_time) < DATEADD('minute', -10, CURRENT_TIMESTAMP())
            THEN 'STALE - source behind' ELSE 'fresh' END
FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
UNION ALL
SELECT 'endpoint_processes', MAX(_time),
       MIN(DATEDIFF('minute', _time, ingestion_time)),
       MAX(DATEDIFF('minute', _time, ingestion_time)),
       -- Endpoint is expected to lag ~45 min; only flag if worse
       CASE WHEN MAX(_time) < DATEADD('minute', -60, CURRENT_TIMESTAMP())
            THEN 'STALE - EDR feed slower than its normal 45 min delay' ELSE 'fresh (known 45 min delay)' END
FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES;
