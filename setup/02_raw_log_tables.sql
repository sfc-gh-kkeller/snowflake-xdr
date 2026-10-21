-- ============================================================================
-- Snowflake XDR/SIEM - Raw Log Tables (Splunk CIM Compatible)
-- ============================================================================
-- Tables use Splunk Common Information Model (CIM) field names so that
-- customers can query via Splunk DB Connect with zero field aliasing.
-- Each table includes:
--   _time       : Primary timestamp (CIM standard)
--   _raw        : Full event JSON for ad-hoc field extraction
--   host        : Originating host
--   source      : Log source path/identifier
--   sourcetype  : Splunk-style sourcetype for filtering
--   index_name  : Logical index partition (main, security, network, etc.)
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE SCHEMA RAW_LOGS;

-- ---------------------------------------------------------------------------
-- Authentication Data Model (CIM: Authentication)
-- Covers: login/logout, MFA, SSO, privilege escalation, account lockout
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS AUTHENTICATION (
    event_id        VARCHAR DEFAULT UUID_STRING(),
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(50),        -- success, failure, pending, error
    app             VARCHAR(255),       -- ssh, splunk, win:local, okta
    authentication_method VARCHAR(100), -- password, mfa, saml, certificate
    authentication_service VARCHAR(100),-- ActiveDirectory, Okta, AzureAD
    dest            VARCHAR(255),       -- target host/service
    duration        NUMBER,             -- seconds
    reason          VARCHAR(500),       -- failure reason
    signature       VARCHAR(255),       -- human-readable event name
    signature_id    VARCHAR(50),        -- event code (4624, 4625, etc.)
    src             VARCHAR(255),       -- source IP/host
    src_user        VARCHAR(255),       -- initiator in privilege escalation
    user_name       VARCHAR(255),       -- target user
    user_id         VARCHAR(255),
    user_type       VARCHAR(50),        -- IAMUser, Admin, System, Service
    user_role       VARCHAR(100),
    user_agent      VARCHAR(1000),
    vendor_account  VARCHAR(255),       -- cloud account/org
    vendor_product  VARCHAR(255),       -- CrowdStrike, Okta, etc.
    -- Splunk metadata
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'security',
    _raw            VARIANT,
    -- XDR enrichment (not in CIM but useful)
    geo_city        VARCHAR(100),
    geo_country     VARCHAR(10),
    geo_lat         FLOAT,
    geo_lon         FLOAT,
    threat_score    NUMBER(3),
    ingestion_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Endpoint Processes (CIM: Endpoint.Processes)
-- Covers: process creation, injection, termination
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ENDPOINT_PROCESSES (
    event_id        VARCHAR DEFAULT UUID_STRING(),
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(50),        -- allowed, blocked, deferred
    dest            VARCHAR(255),       -- endpoint hostname
    user_name       VARCHAR(255),
    user_id         VARCHAR(255),
    -- Process fields
    process         VARCHAR(4000),      -- full command line
    process_name    VARCHAR(255),       -- friendly name (cmd.exe)
    process_id      NUMBER,
    process_guid    VARCHAR(100),
    process_path    VARCHAR(1000),      -- full file path
    process_exec    VARCHAR(255),       -- executable name
    process_hash    VARCHAR(500),       -- md5/sha1/sha256
    process_integrity_level VARCHAR(20),-- system, high, medium, low
    original_file_name VARCHAR(255),
    -- Parent process fields
    parent_process  VARCHAR(4000),      -- full parent command line
    parent_process_name VARCHAR(255),
    parent_process_id NUMBER,
    parent_process_path VARCHAR(1000),
    parent_process_guid VARCHAR(100),
    parent_process_exec VARCHAR(255),
    -- Context
    process_current_directory VARCHAR(1000),
    loaded_file     VARCHAR(1000),
    os              VARCHAR(100),
    vendor_product  VARCHAR(255),
    -- Splunk metadata
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'endpoint',
    _raw            VARIANT,
    ingestion_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Endpoint Filesystem (CIM: Endpoint.Filesystem)
-- Covers: file create, modify, delete, permission changes
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ENDPOINT_FILESYSTEM (
    event_id        VARCHAR DEFAULT UUID_STRING(),
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(50),        -- created, deleted, modified, read, acl_modified
    dest            VARCHAR(255),
    user_name       VARCHAR(255),
    -- File fields
    file_name       VARCHAR(500),
    file_path       VARCHAR(2000),
    file_hash       VARCHAR(500),
    file_size       NUMBER,             -- kilobytes
    file_create_time TIMESTAMP_LTZ,
    file_modify_time TIMESTAMP_LTZ,
    file_access_time TIMESTAMP_LTZ,
    file_acl        VARCHAR(1000),
    -- Process context
    process_id      NUMBER,
    process_guid    VARCHAR(100),
    process_name    VARCHAR(255),
    image           VARCHAR(1000),      -- binary tied to PID
    vendor_product  VARCHAR(255),
    -- Splunk metadata
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'endpoint',
    _raw            VARIANT,
    ingestion_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Endpoint Registry (CIM: Endpoint.Registry)
-- Covers: registry key/value create, modify, delete
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ENDPOINT_REGISTRY (
    event_id        VARCHAR DEFAULT UUID_STRING(),
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(50),        -- created, deleted, modified, read
    dest            VARCHAR(255),
    user_name       VARCHAR(255),
    -- Registry fields
    registry_hive   VARCHAR(100),       -- HKEY_LOCAL_MACHINE, etc.
    registry_path   VARCHAR(2000),
    registry_key_name VARCHAR(500),
    registry_value_name VARCHAR(500),
    registry_value_data VARCHAR(4000),
    registry_value_type VARCHAR(50),    -- REG_SZ, REG_DWORD, etc.
    status          VARCHAR(20),        -- success, failure
    -- Process context
    process_id      NUMBER,
    process_guid    VARCHAR(100),
    process_name    VARCHAR(255),
    image           VARCHAR(1000),
    vendor_product  VARCHAR(255),
    -- Splunk metadata
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'endpoint',
    _raw            VARIANT,
    ingestion_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Endpoint Services (CIM: Endpoint.Services)
-- Covers: service install, start, stop, modification
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ENDPOINT_SERVICES (
    event_id        VARCHAR DEFAULT UUID_STRING(),
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(50),
    dest            VARCHAR(255),
    user_name       VARCHAR(255),
    -- Service fields
    service         VARCHAR(500),       -- full service name
    service_name    VARCHAR(255),       -- friendly name
    service_id      VARCHAR(100),
    service_path    VARCHAR(1000),
    service_exec    VARCHAR(255),
    service_hash    VARCHAR(500),
    service_dll     VARCHAR(500),
    service_dll_path VARCHAR(1000),
    start_mode      VARCHAR(20),        -- disabled, manual, auto
    status          VARCHAR(20),        -- started, stopped, critical
    vendor_product  VARCHAR(255),
    -- Splunk metadata
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'endpoint',
    _raw            VARIANT,
    ingestion_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Network Traffic (CIM: Network Traffic)
-- Covers: firewall logs, flow data, connection events
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS NETWORK_TRAFFIC (
    event_id        VARCHAR DEFAULT UUID_STRING(),
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(50),        -- allowed, blocked, dropped, teardown
    -- Source
    src             VARCHAR(255),
    src_ip          VARCHAR(45),
    src_port        NUMBER,
    src_mac         VARCHAR(20),
    -- Destination
    dest            VARCHAR(255),
    dest_ip         VARCHAR(45),
    dest_port       NUMBER,
    dest_mac        VARCHAR(20),
    -- Transport
    transport       VARCHAR(10),        -- tcp, udp, icmp
    protocol        VARCHAR(50),        -- HTTP, DNS, SMB, RDP, SSH
    app             VARCHAR(255),       -- application name
    -- Metrics
    bytes           NUMBER,
    bytes_in        NUMBER,
    bytes_out       NUMBER,
    packets         NUMBER,
    packets_in      NUMBER,
    packets_out     NUMBER,
    duration        FLOAT,              -- seconds
    -- Context
    rule            VARCHAR(500),       -- firewall rule matched
    dvc             VARCHAR(255),       -- reporting device
    direction       VARCHAR(10),        -- inbound, outbound
    vendor_product  VARCHAR(255),
    -- Splunk metadata
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'network',
    _raw            VARIANT,
    -- XDR enrichment
    geo_src_country VARCHAR(10),
    geo_dest_country VARCHAR(10),
    threat_score    NUMBER(3),
    ingestion_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- DNS Activity (CIM: Network Resolution / DNS)
-- Covers: DNS queries, responses, tunneling indicators
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS DNS_ACTIVITY (
    event_id        VARCHAR DEFAULT UUID_STRING(),
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(50),        -- query, response, blocked
    src             VARCHAR(255),       -- requesting client
    dest            VARCHAR(255),       -- DNS server
    -- DNS fields
    query           VARCHAR(500),       -- queried domain
    query_type      VARCHAR(20),        -- A, AAAA, MX, TXT, CNAME, NS
    answer          VARCHAR(2000),      -- resolved answer(s)
    reply_code      VARCHAR(20),        -- NOERROR, NXDOMAIN, SERVFAIL
    transaction_id  VARCHAR(20),
    transport       VARCHAR(10),        -- udp, tcp, doh
    -- Enrichment
    query_length    NUMBER,             -- for tunneling detection
    answer_count    NUMBER,
    ttl             NUMBER,
    vendor_product  VARCHAR(255),
    -- Splunk metadata
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'network',
    _raw            VARIANT,
    ingestion_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Web Activity (CIM: Web)
-- Covers: HTTP requests, WAF events, proxy logs
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS WEB_ACTIVITY (
    event_id        VARCHAR DEFAULT UUID_STRING(),
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(50),        -- allowed, blocked
    src             VARCHAR(255),       -- client IP
    dest            VARCHAR(255),       -- web server
    -- HTTP fields
    url             VARCHAR(4000),
    uri_path        VARCHAR(2000),
    uri_query       VARCHAR(2000),
    http_method     VARCHAR(10),        -- GET, POST, PUT, DELETE
    status          NUMBER,             -- HTTP status code
    http_user_agent VARCHAR(1000),
    http_referrer   VARCHAR(2000),
    http_content_type VARCHAR(100),
    cookie          VARCHAR(4000),
    -- Metrics
    bytes_in        NUMBER,
    bytes_out       NUMBER,
    duration        FLOAT,
    -- Context
    category        VARCHAR(100),       -- WAF category
    vendor_product  VARCHAR(255),
    -- Splunk metadata
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'web',
    _raw            VARIANT,
    -- XDR enrichment
    threat_category VARCHAR(100),       -- sqli, xss, rfi, etc.
    threat_score    NUMBER(3),
    ingestion_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Cloud API Activity (CIM: Change + custom cloud fields)
-- Covers: AWS CloudTrail, Azure Activity Log, GCP Audit Log
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS CLOUD_API (
    event_id        VARCHAR DEFAULT UUID_STRING(),
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(255),       -- API action (RunInstances, etc.)
    command         VARCHAR(500),       -- CLI command if applicable
    user_name       VARCHAR(255),       -- IAM user/role
    user_type       VARCHAR(50),        -- IAMUser, Root, AssumedRole
    src             VARCHAR(255),       -- source IP
    dest            VARCHAR(255),       -- target service/resource
    -- Change fields
    object          VARCHAR(500),       -- affected resource ARN/ID
    object_category VARCHAR(100),       -- instance, bucket, role, policy
    result          VARCHAR(50),        -- success, failure, denied
    reason          VARCHAR(1000),      -- error message
    -- Cloud context
    app             VARCHAR(100),       -- service name (ec2, s3, iam)
    vendor_account  VARCHAR(100),       -- AWS account ID / Azure sub
    vendor_region   VARCHAR(50),        -- us-east-1, etc.
    vendor_product  VARCHAR(100),       -- aws, azure, gcp
    -- Request details
    request_parameters VARIANT,         -- full request params JSON
    response_elements VARIANT,          -- response JSON
    -- Splunk metadata
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'cloud',
    _raw            VARIANT,
    ingestion_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Intrusion Detection (CIM: Intrusion Detection)
-- Covers: IDS/IPS alerts, WAF detections, EDR alerts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS INTRUSION_DETECTION (
    event_id        VARCHAR DEFAULT UUID_STRING(),
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(50),        -- allowed, blocked, dropped
    -- Source/Dest
    src             VARCHAR(255),
    src_ip          VARCHAR(45),
    src_port        NUMBER,
    dest            VARCHAR(255),
    dest_ip         VARCHAR(45),
    dest_port       NUMBER,
    transport       VARCHAR(10),
    -- Signature
    signature       VARCHAR(500),       -- rule name
    signature_id    VARCHAR(50),        -- rule ID (SID)
    severity        VARCHAR(20),        -- critical, high, medium, low, info
    category        VARCHAR(200),       -- attack category
    -- Context
    ids_type        VARCHAR(50),        -- network, host, application
    dvc             VARCHAR(255),       -- reporting device
    vendor_product  VARCHAR(255),
    -- Splunk metadata
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'ids',
    _raw            VARIANT,
    ingestion_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);
