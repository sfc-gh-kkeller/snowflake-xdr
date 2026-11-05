-- ============================================================================
-- Snowflake XDR - Phase 5.3: EDR and email telemetry
-- ============================================================================
-- Vendor-native records arrive over OTLP (service.name = source_id) and map into
-- the shared CIM tables, so the EDR packs, the Sigma endpoint pack and the
-- built-in detections all run on every EDR without per-vendor rules.
--
--   crowdstrike        Falcon Data Replicator / Event Streams
--                      ProcessRollup2 -> ENDPOINT_PROCESSES, NetworkConnectIP4 -> NETWORK_TRAFFIC,
--                      DnsRequest -> DNS_ACTIVITY, *FileWritten -> ENDPOINT_FILESYSTEM,
--                      DetectionSummaryEvent / EppDetectionSummaryEvent -> INTRUSION_DETECTION
--   defender           Microsoft Defender for Endpoint, Advanced Hunting streaming (Event Hubs)
--                      DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceEvents (DNS),
--                      AlertInfo + AlertEvidence -> INTRUSION_DETECTION
--   sentinelone        Singularity Cloud Funnel (Deep Visibility) + threats API
--   m365_messagetrace  Exchange Online message trace                 -> EMAIL_ACTIVITY
--   m365_audit         Exchange Online audit (inbox rules, forwarding) -> EMAIL_ACTIVITY
--   proofpoint         Proofpoint TAP SIEM API (messages, clicks)     -> EMAIL_ACTIVITY
-- Collector recipes: otel-receiver/collector-examples/{crowdstrike_fdr,defender_eventhub,
-- sentinelone_funnel,m365_mail,proofpoint_tap}.*
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.RAW_LOGS.EMAIL_ACTIVITY (
    event_id        VARCHAR DEFAULT UUID_STRING(),
    _time           TIMESTAMP_LTZ NOT NULL,
    action          VARCHAR(100),      -- delivered | blocked | quarantined | click | inbox_rule | forwarding_set
    user_name       VARCHAR(255),      -- mailbox owner (recipient, or the user who made the rule)
    recipient       VARCHAR(500),
    sender          VARCHAR(500),
    sender_domain   VARCHAR(255),
    subject         VARCHAR(2000),
    src             VARCHAR(255),      -- sending / clicking / client IP
    dest            VARCHAR(255),      -- recipient domain / tenant
    direction       VARCHAR(20),       -- inbound | outbound | internal
    message_id      VARCHAR(1000),
    url             VARCHAR(4000),
    forward_to      VARCHAR(1000),     -- inbox-rule / mailbox forwarding target
    verdict         VARCHAR(100),      -- clean | spam | phish | malware | impostor
    threat_name     VARCHAR(500),
    attachment_name VARCHAR(1000),
    attachment_hash VARCHAR(128),
    size_bytes      NUMBER,
    vendor_product  VARCHAR(100),      -- m365 | proofpoint
    host            VARCHAR(255),
    source          VARCHAR(500),
    sourcetype      VARCHAR(100),
    index_name      VARCHAR(50) DEFAULT 'email',
    _raw            VARIANT,
    ingestion_time  TIMESTAMP_LTZ
);

MERGE INTO SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES t
USING (SELECT * FROM VALUES
    ('crowdstrike',       'CrowdStrike Falcon FDR / Event Streams (forwarder)',            'edr'),
    ('defender',          'Microsoft Defender for Endpoint Advanced Hunting (azureeventhub)', 'edr'),
    ('sentinelone',       'SentinelOne Cloud Funnel / threats API (forwarder)',            'edr'),
    ('m365_messagetrace', 'Exchange Online message trace (forwarder)',                     'email'),
    ('m365_audit',        'Exchange Online audit log (Management Activity API)',           'email'),
    ('proofpoint',        'Proofpoint TAP SIEM API (forwarder)',                            'email')
    AS v(source_id, name, kind)) s ON t.source_id = s.source_id
WHEN NOT MATCHED THEN INSERT (source_id, name, kind, status, owner, notes)
    VALUES (s.source_id, s.name, s.kind, 'mapped', 'setup', 'shipped mapping (EDR / email packs)');

INSERT INTO SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS (source_id, target_table, mapping_sql, status, created_by)
SELECT v.source_id, v.target_table, v.mapping_sql, 'live', 'setup'
FROM (SELECT * FROM VALUES
-- --------------------------------------------------------------- CrowdStrike
('crowdstrike', 'ENDPOINT_PROCESSES', $$SELECT COALESCE(TO_TIMESTAMP_LTZ(TRY_TO_NUMBER(body:timestamp::VARCHAR), 3), event_time) AS _time,
       'created' AS action,
       body:ComputerName::VARCHAR AS dest,
       LOWER(body:UserName::VARCHAR) AS user_name,
       body:UserSid::VARCHAR AS user_id,
       body:CommandLine::VARCHAR AS process,
       LOWER(REGEXP_SUBSTR(body:ImageFileName::VARCHAR, '[^\\\\/]+$')) AS process_name,
       REGEXP_REPLACE(body:ImageFileName::VARCHAR, '^\\\\Device\\\\HarddiskVolume[0-9]+', 'C:') AS process_path,
       body:TargetProcessId::VARCHAR AS process_id,
       body:SHA256HashData::VARCHAR AS process_hash,
       body:IntegrityLevel::VARCHAR AS process_integrity_level,
       body:ParentBaseFileName::VARCHAR AS parent_process,
       LOWER(body:ParentBaseFileName::VARCHAR) AS parent_process_name,
       body:ParentProcessId::VARCHAR AS parent_process_id,
       body:event_platform::VARCHAR AS os,
       'CrowdStrike Falcon' AS vendor_product, body:ComputerName::VARCHAR AS host,
       'crowdstrike:fdr' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'crowdstrike' AND body:event_simpleName::VARCHAR IN ('ProcessRollup2', 'SyntheticProcessRollup2')$$),

('crowdstrike', 'NETWORK_TRAFFIC', $$SELECT COALESCE(TO_TIMESTAMP_LTZ(TRY_TO_NUMBER(body:timestamp::VARCHAR), 3), event_time) AS _time,
       IFF(body:event_simpleName::VARCHAR = 'NetworkConnectIP4', 'allowed', 'listen') AS action,
       body:ComputerName::VARCHAR AS src,
       body:LocalAddressIP4::VARCHAR AS src_ip, TRY_TO_NUMBER(body:LocalPort::VARCHAR) AS src_port,
       body:RemoteAddressIP4::VARCHAR AS dest,
       body:RemoteAddressIP4::VARCHAR AS dest_ip, TRY_TO_NUMBER(body:RemotePort::VARCHAR) AS dest_port,
       DECODE(body:Protocol::VARCHAR, '6', 'tcp', '17', 'udp', LOWER(body:Protocol::VARCHAR)) AS transport,
       LOWER(body:ContextBaseFileName::VARCHAR) AS app,
       IFF(body:ConnectionDirection::VARCHAR = '1', 'inbound', 'outbound') AS direction,
       'CrowdStrike Falcon' AS vendor_product, body:ComputerName::VARCHAR AS host,
       'crowdstrike:fdr' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'crowdstrike' AND body:event_simpleName::VARCHAR IN ('NetworkConnectIP4', 'NetworkListenIP4')$$),

('crowdstrike', 'DNS_ACTIVITY', $$SELECT COALESCE(TO_TIMESTAMP_LTZ(TRY_TO_NUMBER(body:timestamp::VARCHAR), 3), event_time) AS _time,
       'query' AS action,
       body:ComputerName::VARCHAR AS src,
       LOWER(body:DomainName::VARCHAR) AS query,
       body:RequestType::VARCHAR AS query_type,
       body:IP4Records::VARCHAR AS answer,
       LOWER(body:ContextBaseFileName::VARCHAR) AS dest,
       'CrowdStrike Falcon' AS vendor_product, body:ComputerName::VARCHAR AS host,
       'crowdstrike:fdr' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'crowdstrike' AND body:event_simpleName::VARCHAR = 'DnsRequest'$$),

('crowdstrike', 'ENDPOINT_FILESYSTEM', $$SELECT COALESCE(TO_TIMESTAMP_LTZ(TRY_TO_NUMBER(body:timestamp::VARCHAR), 3), event_time) AS _time,
       'created' AS action,
       body:ComputerName::VARCHAR AS dest,
       LOWER(body:UserName::VARCHAR) AS user_name,
       REGEXP_SUBSTR(body:TargetFileName::VARCHAR, '[^\\\\/]+$') AS file_name,
       REGEXP_REPLACE(body:TargetFileName::VARCHAR, '^\\\\Device\\\\HarddiskVolume[0-9]+', 'C:') AS file_path,
       body:SHA256HashData::VARCHAR AS file_hash,
       LOWER(body:ContextBaseFileName::VARCHAR) AS process_name,
       body:ContextBaseFileName::VARCHAR AS image,
       'CrowdStrike Falcon' AS vendor_product, body:ComputerName::VARCHAR AS host,
       'crowdstrike:fdr' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'crowdstrike' AND body:event_simpleName::VARCHAR LIKE '%Written'$$),

('crowdstrike', 'INTRUSION_DETECTION', $$SELECT COALESCE(TO_TIMESTAMP_LTZ(TRY_TO_NUMBER(body:metadata:eventCreationTime::VARCHAR), 3), event_time) AS _time,
       'alert' AS action,
       body:event:ComputerName::VARCHAR AS src,
       body:event:LocalIP::VARCHAR AS src_ip,
       LOWER(body:event:UserName::VARCHAR) AS dest,
       COALESCE(body:event:DetectName, body:event:Name)::VARCHAR || ': ' || COALESCE(body:event:Description::VARCHAR, '') AS signature,
       COALESCE(body:event:Technique, body:event:DetectId)::VARCHAR AS signature_id,
       TRY_TO_NUMBER(body:event:Severity::VARCHAR) AS severity,
       body:event:Tactic::VARCHAR AS category,
       'edr' AS ids_type, body:event:ComputerName::VARCHAR AS dvc,
       'CrowdStrike Falcon' AS vendor_product, body:event:ComputerName::VARCHAR AS host,
       'crowdstrike:event_stream' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'crowdstrike' AND body:metadata:eventType::VARCHAR IN ('DetectionSummaryEvent', 'EppDetectionSummaryEvent')$$),

-- --------------------------------------------------------------- Microsoft Defender for Endpoint
('defender', 'ENDPOINT_PROCESSES', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(COALESCE(body:properties:Timestamp, body:time)::VARCHAR), event_time) AS _time,
       LOWER(body:properties:ActionType::VARCHAR) AS action,
       body:properties:DeviceName::VARCHAR AS dest,
       LOWER(body:properties:AccountName::VARCHAR) AS user_name,
       body:properties:AccountSid::VARCHAR AS user_id,
       body:properties:ProcessCommandLine::VARCHAR AS process,
       LOWER(body:properties:FileName::VARCHAR) AS process_name,
       body:properties:FolderPath::VARCHAR AS process_path,
       body:properties:ProcessId::VARCHAR AS process_id,
       body:properties:SHA256::VARCHAR AS process_hash,
       body:properties:ProcessIntegrityLevel::VARCHAR AS process_integrity_level,
       body:properties:InitiatingProcessCommandLine::VARCHAR AS parent_process,
       LOWER(body:properties:InitiatingProcessFileName::VARCHAR) AS parent_process_name,
       body:properties:InitiatingProcessFolderPath::VARCHAR AS parent_process_path,
       body:properties:InitiatingProcessId::VARCHAR AS parent_process_id,
       'windows' AS os, 'Microsoft Defender for Endpoint' AS vendor_product,
       body:properties:DeviceName::VARCHAR AS host, 'mde:deviceprocessevents' AS sourcetype, body:properties AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'defender' AND body:category::VARCHAR = 'AdvancedHunting-DeviceProcessEvents'$$),

('defender', 'NETWORK_TRAFFIC', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(COALESCE(body:properties:Timestamp, body:time)::VARCHAR), event_time) AS _time,
       IFF(body:properties:ActionType::VARCHAR ILIKE '%fail%', 'blocked', 'allowed') AS action,
       body:properties:DeviceName::VARCHAR AS src,
       body:properties:LocalIP::VARCHAR AS src_ip, TRY_TO_NUMBER(body:properties:LocalPort::VARCHAR) AS src_port,
       COALESCE(body:properties:RemoteUrl::VARCHAR, body:properties:RemoteIP::VARCHAR) AS dest,
       body:properties:RemoteIP::VARCHAR AS dest_ip, TRY_TO_NUMBER(body:properties:RemotePort::VARCHAR) AS dest_port,
       LOWER(body:properties:Protocol::VARCHAR) AS transport,
       LOWER(body:properties:InitiatingProcessFileName::VARCHAR) AS app,
       IFF(body:properties:ActionType::VARCHAR = 'InboundConnectionAccepted', 'inbound', 'outbound') AS direction,
       'Microsoft Defender for Endpoint' AS vendor_product, body:properties:DeviceName::VARCHAR AS host,
       'mde:devicenetworkevents' AS sourcetype, body:properties AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'defender' AND body:category::VARCHAR = 'AdvancedHunting-DeviceNetworkEvents'$$),

('defender', 'DNS_ACTIVITY', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(COALESCE(body:properties:Timestamp, body:time)::VARCHAR), event_time) AS _time,
       'query' AS action,
       body:properties:DeviceName::VARCHAR AS src,
       LOWER(COALESCE(TRY_PARSE_JSON(body:properties:AdditionalFields::VARCHAR):DnsQueryString,
                      body:properties:AdditionalFields:DnsQueryString)::VARCHAR) AS query,
       LOWER(body:properties:InitiatingProcessFileName::VARCHAR) AS dest,
       'Microsoft Defender for Endpoint' AS vendor_product, body:properties:DeviceName::VARCHAR AS host,
       'mde:deviceevents' AS sourcetype, body:properties AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'defender' AND body:category::VARCHAR = 'AdvancedHunting-DeviceEvents'
  AND body:properties:ActionType::VARCHAR = 'DnsQueryResponse'$$),

('defender', 'ENDPOINT_FILESYSTEM', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(COALESCE(body:properties:Timestamp, body:time)::VARCHAR), event_time) AS _time,
       LOWER(REPLACE(body:properties:ActionType::VARCHAR, 'File', '')) AS action,
       body:properties:DeviceName::VARCHAR AS dest,
       LOWER(body:properties:InitiatingProcessAccountName::VARCHAR) AS user_name,
       body:properties:FileName::VARCHAR AS file_name,
       body:properties:FolderPath::VARCHAR AS file_path,
       body:properties:SHA256::VARCHAR AS file_hash,
       TRY_TO_NUMBER(body:properties:FileSize::VARCHAR) AS file_size,
       LOWER(body:properties:InitiatingProcessFileName::VARCHAR) AS process_name,
       body:properties:InitiatingProcessFolderPath::VARCHAR AS image,
       'Microsoft Defender for Endpoint' AS vendor_product, body:properties:DeviceName::VARCHAR AS host,
       'mde:devicefileevents' AS sourcetype, body:properties AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'defender' AND body:category::VARCHAR = 'AdvancedHunting-DeviceFileEvents'$$),

('defender', 'INTRUSION_DETECTION', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(COALESCE(body:properties:Timestamp, body:time)::VARCHAR), event_time) AS _time,
       'alert' AS action,
       COALESCE(body:properties:DeviceName::VARCHAR, 'defender') AS src,
       body:properties:RemoteIP::VARCHAR AS src_ip,
       LOWER(body:properties:AccountName::VARCHAR) AS dest,
       body:properties:Title::VARCHAR AS signature,
       COALESCE(body:properties:AttackTechniques::VARCHAR, body:properties:AlertId::VARCHAR) AS signature_id,
       DECODE(LOWER(body:properties:Severity::VARCHAR), 'high', 4, 'medium', 3, 'low', 2, 'informational', 1, 3) AS severity,
       body:properties:Category::VARCHAR AS category,
       'edr' AS ids_type, body:properties:DeviceName::VARCHAR AS dvc,
       'Microsoft Defender for Endpoint' AS vendor_product, COALESCE(body:properties:DeviceName::VARCHAR, 'defender') AS host,
       'mde:alertinfo' AS sourcetype, body:properties AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'defender' AND body:category::VARCHAR IN ('AdvancedHunting-AlertInfo', 'AdvancedHunting-AlertEvidence')
  AND body:properties:Title IS NOT NULL$$),

-- --------------------------------------------------------------- SentinelOne (Cloud Funnel keys are dotted)
('sentinelone', 'ENDPOINT_PROCESSES', $$SELECT COALESCE(TO_TIMESTAMP_LTZ(TRY_TO_NUMBER(GET_PATH(body, '"event.time"')::VARCHAR), 3), event_time) AS _time,
       'created' AS action,
       GET_PATH(body, '"endpoint.name"')::VARCHAR AS dest,
       LOWER(REGEXP_SUBSTR(COALESCE(GET_PATH(body, '"tgt.process.user"'), GET_PATH(body, '"src.process.user"'))::VARCHAR, '[^\\\\]+$')) AS user_name,
       GET_PATH(body, '"tgt.process.cmdline"')::VARCHAR AS process,
       LOWER(REGEXP_SUBSTR(GET_PATH(body, '"tgt.process.image.path"')::VARCHAR, '[^\\\\/]+$')) AS process_name,
       GET_PATH(body, '"tgt.process.image.path"')::VARCHAR AS process_path,
       GET_PATH(body, '"tgt.process.pid"')::VARCHAR AS process_id,
       GET_PATH(body, '"tgt.process.image.sha256"')::VARCHAR AS process_hash,
       GET_PATH(body, '"tgt.process.integrityLevel"')::VARCHAR AS process_integrity_level,
       GET_PATH(body, '"src.process.cmdline"')::VARCHAR AS parent_process,
       LOWER(REGEXP_SUBSTR(GET_PATH(body, '"src.process.image.path"')::VARCHAR, '[^\\\\/]+$')) AS parent_process_name,
       GET_PATH(body, '"src.process.image.path"')::VARCHAR AS parent_process_path,
       GET_PATH(body, '"src.process.pid"')::VARCHAR AS parent_process_id,
       LOWER(GET_PATH(body, '"endpoint.os"')::VARCHAR) AS os,
       'SentinelOne' AS vendor_product, GET_PATH(body, '"endpoint.name"')::VARCHAR AS host,
       'sentinelone:cloud_funnel' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'sentinelone' AND GET_PATH(body, '"event.type"')::VARCHAR = 'Process Creation'$$),

('sentinelone', 'NETWORK_TRAFFIC', $$SELECT COALESCE(TO_TIMESTAMP_LTZ(TRY_TO_NUMBER(GET_PATH(body, '"event.time"')::VARCHAR), 3), event_time) AS _time,
       IFF(GET_PATH(body, '"event.network.connectionStatus"')::VARCHAR ILIKE '%fail%', 'blocked', 'allowed') AS action,
       GET_PATH(body, '"endpoint.name"')::VARCHAR AS src,
       GET_PATH(body, '"src.ip.address"')::VARCHAR AS src_ip, TRY_TO_NUMBER(GET_PATH(body, '"src.port.number"')::VARCHAR) AS src_port,
       GET_PATH(body, '"dst.ip.address"')::VARCHAR AS dest,
       GET_PATH(body, '"dst.ip.address"')::VARCHAR AS dest_ip, TRY_TO_NUMBER(GET_PATH(body, '"dst.port.number"')::VARCHAR) AS dest_port,
       LOWER(GET_PATH(body, '"event.network.protocolName"')::VARCHAR) AS transport,
       LOWER(REGEXP_SUBSTR(GET_PATH(body, '"src.process.image.path"')::VARCHAR, '[^\\\\/]+$')) AS app,
       LOWER(GET_PATH(body, '"event.network.direction"')::VARCHAR) AS direction,
       'SentinelOne' AS vendor_product, GET_PATH(body, '"endpoint.name"')::VARCHAR AS host,
       'sentinelone:cloud_funnel' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'sentinelone' AND GET_PATH(body, '"event.type"')::VARCHAR IN ('IP Connect', 'IP Listen')$$),

('sentinelone', 'DNS_ACTIVITY', $$SELECT COALESCE(TO_TIMESTAMP_LTZ(TRY_TO_NUMBER(GET_PATH(body, '"event.time"')::VARCHAR), 3), event_time) AS _time,
       'query' AS action,
       GET_PATH(body, '"endpoint.name"')::VARCHAR AS src,
       LOWER(GET_PATH(body, '"event.dns.request"')::VARCHAR) AS query,
       GET_PATH(body, '"event.dns.response"')::VARCHAR AS answer,
       LOWER(REGEXP_SUBSTR(GET_PATH(body, '"src.process.image.path"')::VARCHAR, '[^\\\\/]+$')) AS dest,
       'SentinelOne' AS vendor_product, GET_PATH(body, '"endpoint.name"')::VARCHAR AS host,
       'sentinelone:cloud_funnel' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'sentinelone' AND GET_PATH(body, '"event.type"')::VARCHAR IN ('DNS Resolved', 'DNS Unresolved')$$),

('sentinelone', 'ENDPOINT_FILESYSTEM', $$SELECT COALESCE(TO_TIMESTAMP_LTZ(TRY_TO_NUMBER(GET_PATH(body, '"event.time"')::VARCHAR), 3), event_time) AS _time,
       LOWER(REPLACE(GET_PATH(body, '"event.type"')::VARCHAR, 'File ', '')) AS action,
       GET_PATH(body, '"endpoint.name"')::VARCHAR AS dest,
       LOWER(REGEXP_SUBSTR(GET_PATH(body, '"src.process.user"')::VARCHAR, '[^\\\\]+$')) AS user_name,
       REGEXP_SUBSTR(GET_PATH(body, '"tgt.file.path"')::VARCHAR, '[^\\\\/]+$') AS file_name,
       GET_PATH(body, '"tgt.file.path"')::VARCHAR AS file_path,
       GET_PATH(body, '"tgt.file.sha256"')::VARCHAR AS file_hash,
       LOWER(REGEXP_SUBSTR(GET_PATH(body, '"src.process.image.path"')::VARCHAR, '[^\\\\/]+$')) AS process_name,
       GET_PATH(body, '"src.process.image.path"')::VARCHAR AS image,
       'SentinelOne' AS vendor_product, GET_PATH(body, '"endpoint.name"')::VARCHAR AS host,
       'sentinelone:cloud_funnel' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'sentinelone' AND GET_PATH(body, '"event.type"')::VARCHAR IN ('File Creation', 'File Modification', 'File Rename')$$),

('sentinelone', 'INTRUSION_DETECTION', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:threatInfo:createdAt::VARCHAR), event_time) AS _time,
       'alert' AS action,
       body:agentRealtimeInfo:agentComputerName::VARCHAR AS src,
       LOWER(REGEXP_SUBSTR(body:threatInfo:processUser::VARCHAR, '[^\\\\]+$')) AS dest,
       body:threatInfo:threatName::VARCHAR || ': ' || COALESCE(body:threatInfo:classification::VARCHAR, '') AS signature,
       body:threatInfo:threatId::VARCHAR AS signature_id,
       DECODE(LOWER(body:threatInfo:confidenceLevel::VARCHAR), 'malicious', 5, 'suspicious', 3, 3) AS severity,
       body:threatInfo:classification::VARCHAR AS category,
       'edr' AS ids_type, body:agentRealtimeInfo:agentComputerName::VARCHAR AS dvc,
       'SentinelOne' AS vendor_product, body:agentRealtimeInfo:agentComputerName::VARCHAR AS host,
       'sentinelone:threat' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'sentinelone' AND body:threatInfo:threatName IS NOT NULL$$),

-- --------------------------------------------------------------- Email
('m365_messagetrace', 'EMAIL_ACTIVITY', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:Received::VARCHAR), event_time) AS _time,
       CASE LOWER(body:Status::VARCHAR) WHEN 'delivered' THEN 'delivered' WHEN 'quarantined' THEN 'quarantined'
            WHEN 'filteredasspam' THEN 'quarantined' WHEN 'failed' THEN 'blocked' ELSE LOWER(body:Status::VARCHAR) END AS action,
       LOWER(SPLIT_PART(body:RecipientAddress::VARCHAR, '@', 1)) AS user_name,
       LOWER(body:RecipientAddress::VARCHAR) AS recipient,
       LOWER(body:SenderAddress::VARCHAR) AS sender,
       LOWER(SPLIT_PART(body:SenderAddress::VARCHAR, '@', 2)) AS sender_domain,
       body:Subject::VARCHAR AS subject,
       body:FromIP::VARCHAR AS src,
       LOWER(SPLIT_PART(body:RecipientAddress::VARCHAR, '@', 2)) AS dest,
       IFF(SPLIT_PART(body:SenderAddress::VARCHAR, '@', 2) ILIKE COALESCE(body:Organization::VARCHAR, '~'),
           IFF(SPLIT_PART(body:RecipientAddress::VARCHAR, '@', 2) ILIKE COALESCE(body:Organization::VARCHAR, '~'), 'internal', 'outbound'),
           'inbound') AS direction,
       body:MessageId::VARCHAR AS message_id,
       IFF(LOWER(body:Status::VARCHAR) = 'filteredasspam', 'spam', NULL) AS verdict,
       TRY_TO_NUMBER(body:Size::VARCHAR) AS size_bytes,
       'm365' AS vendor_product, 'outlook.office365.com' AS host, 'm365:messagetrace' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'm365_messagetrace' AND body:RecipientAddress IS NOT NULL$$),

('m365_audit', 'EMAIL_ACTIVITY', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:CreationTime::VARCHAR), event_time) AS _time,
       IFF(body:Operation::VARCHAR ILIKE '%InboxRule%', 'inbox_rule', 'forwarding_set') AS action,
       LOWER(SPLIT_PART(body:UserId::VARCHAR, '@', 1)) AS user_name,
       LOWER(body:UserId::VARCHAR) AS recipient,
       LOWER(body:UserId::VARCHAR) AS sender,
       LOWER(SPLIT_PART(body:UserId::VARCHAR, '@', 2)) AS sender_domain,
       body:Operation::VARCHAR AS subject,
       SPLIT_PART(body:ClientIP::VARCHAR, ':', 1) AS src,
       LOWER(SPLIT_PART(body:UserId::VARCHAR, '@', 2)) AS dest,
       'internal' AS direction,
       LOWER(REGEXP_SUBSTR(body:Parameters::VARCHAR,
             '"Name":"(ForwardTo|ForwardAsAttachmentTo|RedirectTo|ForwardingSmtpAddress|ForwardingAddress)","Value":"([^"]+)"',
             1, 1, 'e', 2)) AS forward_to,
       'm365' AS vendor_product, 'outlook.office365.com' AS host, 'm365:audit' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'm365_audit' AND body:Operation::VARCHAR IN ('New-InboxRule', 'Set-InboxRule', 'Set-Mailbox', 'UpdateInboxRules')$$),

('proofpoint', 'EMAIL_ACTIVITY', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(COALESCE(body:clickTime, body:messageTime)::VARCHAR), event_time) AS _time,
       CASE GET_PATH(body, '"_type"')::VARCHAR WHEN 'clicksPermitted' THEN 'click' WHEN 'clicksBlocked' THEN 'click_blocked'
            WHEN 'messagesDelivered' THEN 'delivered' WHEN 'messagesBlocked' THEN 'blocked' ELSE GET_PATH(body, '"_type"')::VARCHAR END AS action,
       LOWER(SPLIT_PART(COALESCE(body:recipient[0], body:recipient)::VARCHAR, '@', 1)) AS user_name,
       LOWER(COALESCE(body:recipient[0], body:recipient)::VARCHAR) AS recipient,
       LOWER(COALESCE(body:fromAddress[0], body:sender)::VARCHAR) AS sender,
       LOWER(SPLIT_PART(COALESCE(body:fromAddress[0], body:sender)::VARCHAR, '@', 2)) AS sender_domain,
       body:subject::VARCHAR AS subject,
       COALESCE(body:clickIP, body:senderIP)::VARCHAR AS src,
       LOWER(SPLIT_PART(COALESCE(body:recipient[0], body:recipient)::VARCHAR, '@', 2)) AS dest,
       'inbound' AS direction,
       body:messageID::VARCHAR AS message_id,
       COALESCE(body:url, body:threatsInfoMap[0]:threat)::VARCHAR AS url,
       LOWER(COALESCE(body:classification, body:threatsInfoMap[0]:classification)::VARCHAR) AS verdict,
       COALESCE(body:threatID, body:threatsInfoMap[0]:threatID)::VARCHAR AS threat_name,
       body:messageParts[0]:filename::VARCHAR AS attachment_name,
       body:messageParts[0]:sha256::VARCHAR AS attachment_hash,
       'proofpoint' AS vendor_product, 'tap-api-v2.proofpoint.com' AS host, 'proofpoint:tap' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'proofpoint' AND GET_PATH(body, '"_type"') IS NOT NULL$$)
AS x(source_id, target_table, mapping_sql)) v
WHERE NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS m
                  WHERE m.source_id = v.source_id AND m.target_table = v.target_table AND m.status = 'live');

CALL SNOWFLAKE_XDR.REFERENCE.APPLY_CIM_MAPPINGS();
