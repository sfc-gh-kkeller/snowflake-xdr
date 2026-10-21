-- ============================================================================
-- Snowflake XDR/SIEM - Splunk DB Connect Compatible Views
-- ============================================================================
-- These views present data in the exact format Splunk expects when querying
-- via DB Connect. They:
--   1. Order by _time DESC (Splunk's default sort)
--   2. Include all CIM fields at top level
--   3. Add computed fields Splunk expects (tag, eventtype)
--   4. Support direct use with | dbxquery or scheduled DB Connect inputs
--
-- Usage from Splunk:
--   | dbxquery query="SELECT * FROM SNOWFLAKE_XDR.SPLUNK_VIEWS.V_AUTHENTICATION
--     WHERE _time > DATEADD('hour', -1, CURRENT_TIMESTAMP())" connection="snowflake_xdr"
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
CREATE SCHEMA IF NOT EXISTS SPLUNK_VIEWS
    COMMENT = 'Splunk DB Connect compatible views - CIM data model aligned';

USE SCHEMA SPLUNK_VIEWS;

-- ---------------------------------------------------------------------------
-- Authentication Data Model View
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW V_AUTHENTICATION AS
SELECT
    _time,
    action,
    app,
    authentication_method,
    authentication_service,
    dest,
    duration,
    reason AS reason_id,
    signature,
    signature_id,
    src,
    src_user,
    user_name AS "user",
    user_id,
    user_type,
    user_role,
    user_agent,
    vendor_account,
    vendor_product,
    host,
    source,
    sourcetype,
    index_name AS "index",
    -- Splunk computed fields
    'authentication' AS tag,
    CASE
        WHEN action = 'success' AND src_user IS NOT NULL THEN 'privileged'
        WHEN authentication_method IN ('password', 'cleartext') THEN 'insecure'
        ELSE 'default'
    END AS authentication_category,
    _raw,
    event_id
FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
ORDER BY _time DESC;

-- ---------------------------------------------------------------------------
-- Endpoint Processes View
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW V_ENDPOINT_PROCESSES AS
SELECT
    _time,
    action,
    dest,
    user_name AS "user",
    user_id,
    process,
    process_name,
    process_id,
    process_guid,
    process_path,
    process_exec,
    process_hash,
    process_integrity_level,
    original_file_name,
    parent_process,
    parent_process_name,
    parent_process_id,
    parent_process_path,
    parent_process_guid,
    parent_process_exec,
    process_current_directory,
    loaded_file,
    os,
    vendor_product,
    host,
    source,
    sourcetype,
    index_name AS "index",
    -- Splunk tags
    'process' AS tag,
    'report' AS tag2,
    _raw,
    event_id
FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
ORDER BY _time DESC;

-- ---------------------------------------------------------------------------
-- Endpoint Filesystem View
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW V_ENDPOINT_FILESYSTEM AS
SELECT
    _time,
    action,
    dest,
    user_name AS "user",
    file_name,
    file_path,
    file_hash,
    file_size,
    file_create_time,
    file_modify_time,
    file_access_time,
    file_acl,
    process_id,
    process_guid,
    process_name,
    image,
    vendor_product,
    host,
    source,
    sourcetype,
    index_name AS "index",
    'endpoint' AS tag,
    'filesystem' AS tag2,
    _raw,
    event_id
FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_FILESYSTEM
ORDER BY _time DESC;

-- ---------------------------------------------------------------------------
-- Endpoint Registry View
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW V_ENDPOINT_REGISTRY AS
SELECT
    _time,
    action,
    dest,
    user_name AS "user",
    registry_hive,
    registry_path,
    registry_key_name,
    registry_value_name,
    registry_value_data,
    registry_value_type,
    status,
    process_id,
    process_guid,
    process_name,
    image,
    vendor_product,
    host,
    source,
    sourcetype,
    index_name AS "index",
    'endpoint' AS tag,
    'registry' AS tag2,
    _raw,
    event_id
FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_REGISTRY
ORDER BY _time DESC;

-- ---------------------------------------------------------------------------
-- Network Traffic View
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW V_NETWORK_TRAFFIC AS
SELECT
    _time,
    action,
    src,
    src_ip,
    src_port,
    src_mac,
    dest,
    dest_ip,
    dest_port,
    dest_mac,
    transport,
    protocol,
    app,
    bytes,
    bytes_in,
    bytes_out,
    packets,
    packets_in,
    packets_out,
    duration,
    rule,
    dvc,
    direction,
    vendor_product,
    host,
    source,
    sourcetype,
    index_name AS "index",
    'network' AS tag,
    'communicate' AS tag2,
    _raw,
    event_id
FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
ORDER BY _time DESC;

-- ---------------------------------------------------------------------------
-- DNS Activity View
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW V_DNS AS
SELECT
    _time,
    action,
    src,
    dest,
    query,
    query_type,
    answer,
    reply_code,
    transaction_id,
    transport,
    query_length,
    answer_count,
    ttl,
    vendor_product,
    host,
    source,
    sourcetype,
    index_name AS "index",
    'network' AS tag,
    'resolution' AS tag2,
    'dns' AS tag3,
    _raw,
    event_id
FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
ORDER BY _time DESC;

-- ---------------------------------------------------------------------------
-- Web Activity View
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW V_WEB AS
SELECT
    _time,
    action,
    src,
    dest,
    url,
    uri_path,
    uri_query,
    http_method,
    status,
    http_user_agent,
    http_referrer,
    http_content_type,
    cookie,
    bytes_in,
    bytes_out,
    duration,
    category,
    vendor_product,
    host,
    source,
    sourcetype,
    index_name AS "index",
    'web' AS tag,
    threat_category,
    _raw,
    event_id
FROM SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY
ORDER BY _time DESC;

-- ---------------------------------------------------------------------------
-- Cloud API / Change View
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW V_CLOUD_CHANGE AS
SELECT
    _time,
    action,
    command,
    user_name AS "user",
    user_type,
    src,
    dest,
    object,
    object_category,
    result,
    reason,
    app,
    vendor_account,
    vendor_region,
    vendor_product,
    host,
    source,
    sourcetype,
    index_name AS "index",
    'change' AS tag,
    _raw,
    event_id
FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API
ORDER BY _time DESC;

-- ---------------------------------------------------------------------------
-- Intrusion Detection View
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW V_INTRUSION_DETECTION AS
SELECT
    _time,
    action,
    src,
    src_ip,
    src_port,
    dest,
    dest_ip,
    dest_port,
    transport,
    signature,
    signature_id,
    severity,
    category,
    ids_type,
    dvc,
    vendor_product,
    host,
    source,
    sourcetype,
    index_name AS "index",
    'ids' AS tag,
    'attack' AS tag2,
    _raw,
    event_id
FROM SNOWFLAKE_XDR.RAW_LOGS.INTRUSION_DETECTION
ORDER BY _time DESC;

-- ---------------------------------------------------------------------------
-- Unified Search View (simulates Splunk "index=*" across all data)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW V_ALL_EVENTS AS
SELECT _time, 'authentication' AS datamodel, action, src, dest, user_name AS "user", host, source, sourcetype, index_name AS "index", event_id FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
UNION ALL
SELECT _time, 'endpoint_process', action, NULL, dest, user_name, host, source, sourcetype, index_name, event_id FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
UNION ALL
SELECT _time, 'endpoint_filesystem', action, NULL, dest, user_name, host, source, sourcetype, index_name, event_id FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_FILESYSTEM
UNION ALL
SELECT _time, 'endpoint_registry', action, NULL, dest, user_name, host, source, sourcetype, index_name, event_id FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_REGISTRY
UNION ALL
SELECT _time, 'network_traffic', action, src, dest, NULL, host, source, sourcetype, index_name, event_id FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
UNION ALL
SELECT _time, 'dns', action, src, dest, NULL, host, source, sourcetype, index_name, event_id FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
UNION ALL
SELECT _time, 'web', action, src, dest, NULL, host, source, sourcetype, index_name, event_id FROM SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY
UNION ALL
SELECT _time, 'cloud_api', action, src, dest, user_name, host, source, sourcetype, index_name, event_id FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API;
