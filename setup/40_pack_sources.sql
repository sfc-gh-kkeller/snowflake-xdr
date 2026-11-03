-- ============================================================================
-- Snowflake XDR - OpenTelemetry sources and CIM mappings for the rule packs
-- ============================================================================
-- One OTel source (service.name) per log type, each mapped into the CIM table
-- its pack reads. Collector / forwarder recipes: otel-receiver/collector-examples/.
--
--   okta            Okta System Log, admin & lifecycle events  -> CLOUD_API
--                   (sign-ins: AUTHENTICATION, setup/30_otel_ingest.sql)
--   aws_cloudtrail  CloudTrail                                  -> CLOUD_API (setup/30)
--   entra_signin    Entra ID SignInLogs (Azure Monitor export)  -> AUTHENTICATION
--   entra_audit     Entra ID AuditLogs                          -> CLOUD_API
--   azure_activity  Azure Activity log (Administrative)         -> CLOUD_API
--   databricks      Databricks audit logs                       -> DATABASE_ACTIVITY
--   postgres        PostgreSQL jsonlog with pgaudit + auth      -> DATABASE_ACTIVITY
--   clickhouse      ClickHouse system.query_log                 -> DATABASE_ACTIVITY
--   salesforce      Salesforce event monitoring (Login, Report,
--                   Api, BulkApiResult) and SetupAuditTrail     -> DATABASE_ACTIVITY
--
-- Mappings keep the parsed record in _raw so rules can use vendor fields.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- Okta, Entra and Salesforce report full country names ("United States"), not ISO codes
ALTER TABLE SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION ALTER COLUMN geo_country SET DATA TYPE VARCHAR(100);

MERGE INTO SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES t
USING (SELECT * FROM VALUES
    ('entra_signin',   'Entra ID sign-in logs (azureeventhub receiver)',    'entra'),
    ('entra_audit',    'Entra ID audit logs (azureeventhub receiver)',      'entra'),
    ('azure_activity', 'Azure Activity log (azureeventhub receiver)',       'azure'),
    ('databricks',     'Databricks audit logs (system.access.audit / delivery)', 'databricks'),
    ('postgres',       'PostgreSQL jsonlog + pgaudit (filelog receiver)',   'postgres'),
    ('clickhouse',     'ClickHouse system.query_log (forwarder)',           'clickhouse'),
    ('salesforce',     'Salesforce event monitoring (forwarder)',           'salesforce')
    AS v(source_id, name, kind)) s ON t.source_id = s.source_id
WHEN NOT MATCHED THEN INSERT (source_id, name, kind, status, owner, notes)
    VALUES (s.source_id, s.name, s.kind, 'mapped', 'setup', 'shipped mapping (rule packs)');

INSERT INTO SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS (source_id, target_table, mapping_sql, status, created_by)
SELECT v.source_id, v.target_table, v.mapping_sql, 'live', 'setup'
FROM (SELECT * FROM VALUES
('okta', 'CLOUD_API', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:published::VARCHAR), event_time) AS _time,
       body:eventType::VARCHAR AS action,
       body:displayMessage::VARCHAR AS command,
       SPLIT_PART(body:actor:alternateId::VARCHAR, '@', 1) AS user_name,
       body:actor:type::VARCHAR AS user_type,
       body:client:ipAddress::VARCHAR AS src,
       'okta' AS dest,
       COALESCE(body:target[0]:alternateId::VARCHAR, body:target[0]:displayName::VARCHAR) AS object,
       body:target[0]:type::VARCHAR AS object_category,
       IFF(UPPER(COALESCE(body:outcome:result::VARCHAR, 'SUCCESS')) IN ('SUCCESS', 'ALLOW'), 'success', 'failure') AS result,
       body:outcome:reason::VARCHAR AS reason,
       'okta' AS app, 'Okta' AS vendor_product, body:target AS request_parameters,
       'okta' AS host, 'okta:system_log' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'okta' AND body:eventType IS NOT NULL AND body:eventType::VARCHAR NOT LIKE 'user.session.%'$$),

('entra_signin', 'AUTHENTICATION', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:time::VARCHAR), event_time) AS _time,
       IFF(COALESCE(TRY_TO_NUMBER(body:properties:status:errorCode::VARCHAR), 0) = 0, 'success', 'failure') AS action,
       body:properties:appDisplayName::VARCHAR AS app,
       body:properties:authenticationRequirement::VARCHAR AS authentication_method,
       'Entra ID' AS authentication_service,
       body:properties:resourceDisplayName::VARCHAR AS dest,
       body:properties:status:failureReason::VARCHAR AS reason,
       'SignIn risk=' || COALESCE(body:properties:riskLevelDuringSignIn::VARCHAR, 'none') AS signature,
       body:properties:status:errorCode::VARCHAR AS signature_id,
       body:properties:ipAddress::VARCHAR AS src,
       LOWER(SPLIT_PART(body:properties:userPrincipalName::VARCHAR, '@', 1)) AS user_name,
       body:properties:userId::VARCHAR AS user_id,
       body:properties:clientAppUsed::VARCHAR AS user_agent,
       body:properties:location:city::VARCHAR AS geo_city,
       body:properties:location:countryOrRegion::VARCHAR AS geo_country,
       body:tenantId::VARCHAR AS vendor_account, 'Entra ID' AS vendor_product,
       'login.microsoftonline.com' AS host, 'azure:aad:signin' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'entra_signin' AND body:properties:userPrincipalName IS NOT NULL$$),

('entra_audit', 'CLOUD_API', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:time::VARCHAR), event_time) AS _time,
       COALESCE(body:properties:activityDisplayName::VARCHAR, body:operationName::VARCHAR) AS action,
       COALESCE(body:properties:category::VARCHAR, 'Audit') || ':' ||
           COALESCE(body:properties:activityDisplayName::VARCHAR, body:operationName::VARCHAR) AS command,
       LOWER(SPLIT_PART(COALESCE(body:properties:initiatedBy:user:userPrincipalName::VARCHAR,
                                 body:properties:initiatedBy:app:displayName::VARCHAR), '@', 1)) AS user_name,
       IFF(body:properties:initiatedBy:user IS NOT NULL, 'User', 'Application') AS user_type,
       body:properties:initiatedBy:user:ipAddress::VARCHAR AS src,
       'entra' AS dest,
       COALESCE(body:properties:targetResources[0]:userPrincipalName::VARCHAR,
                body:properties:targetResources[0]:displayName::VARCHAR) AS object,
       body:properties:targetResources[0]:type::VARCHAR AS object_category,
       IFF(LOWER(COALESCE(body:properties:result::VARCHAR, body:resultType::VARCHAR, 'success')) IN ('success', '0'),
           'success', 'failure') AS result,
       body:properties:resultReason::VARCHAR AS reason,
       'entra' AS app, body:tenantId::VARCHAR AS vendor_account, 'Entra ID' AS vendor_product,
       body:properties:targetResources AS request_parameters,
       'graph.microsoft.com' AS host, 'azure:aad:audit' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'entra_audit' AND COALESCE(body:properties:activityDisplayName, body:operationName) IS NOT NULL$$),

('azure_activity', 'CLOUD_API', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:time::VARCHAR), event_time) AS _time,
       UPPER(body:operationName::VARCHAR) AS action,
       COALESCE(body:category::VARCHAR, 'Administrative') || ':' || UPPER(body:operationName::VARCHAR) AS command,
       LOWER(SPLIT_PART(body:caller::VARCHAR, '@', 1)) AS user_name,
       IFF(CONTAINS(body:caller::VARCHAR, '@'), 'User', 'ServicePrincipal') AS user_type,
       body:callerIpAddress::VARCHAR AS src,
       SPLIT_PART(body:resourceId::VARCHAR, '/', 7) AS dest,
       body:resourceId::VARCHAR AS object,
       SPLIT_PART(body:resourceId::VARCHAR, '/', 8) AS object_category,
       CASE WHEN LOWER(body:resultType::VARCHAR) IN ('success', 'succeeded') THEN 'success'
            WHEN LOWER(body:resultType::VARCHAR) IN ('failure', 'failed') THEN 'failure'
            ELSE LOWER(COALESCE(body:resultType::VARCHAR, 'success')) END AS result,
       body:resultSignature::VARCHAR AS reason,
       'azure' AS app, SPLIT_PART(body:resourceId::VARCHAR, '/', 3) AS vendor_account,
       body:location::VARCHAR AS vendor_region, 'azure' AS vendor_product, body:properties AS request_parameters,
       'management.azure.com' AS host, 'azure:activity' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'azure_activity' AND body:operationName IS NOT NULL$$),

('databricks', 'DATABASE_ACTIVITY', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:timestamp::VARCHAR), event_time) AS _time,
       body:actionName::VARCHAR AS action,
       LOWER(SPLIT_PART(body:userIdentity:email::VARCHAR, '@', 1)) AS user_name,
       body:sourceIPAddress::VARCHAR AS src,
       COALESCE(body:workspaceId::VARCHAR, 'account') AS dest,
       body:userAgent::VARCHAR AS app,
       body:serviceName::VARCHAR || '.' || body:actionName::VARCHAR AS query_type,
       LEFT(body:requestParams::VARCHAR, 16000) AS query_text,
       COALESCE(body:requestParams:full_name_arg::VARCHAR, body:requestParams:name::VARCHAR,
                body:requestParams:path::VARCHAR, body:requestParams:targetGroupName::VARCHAR) AS object,
       body:serviceName::VARCHAR AS object_category,
       IFF(COALESCE(body:response:statusCode::NUMBER, 200) BETWEEN 200 AND 299, 'success', 'failure') AS result,
       body:response:errorMessage::VARCHAR AS reason,
       body:accountId::VARCHAR AS vendor_account, 'databricks' AS vendor_product,
       'databricks' AS host, 'databricks:audit' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'databricks' AND body:actionName IS NOT NULL$$),

('postgres', 'DATABASE_ACTIVITY', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:timestamp::VARCHAR), event_time) AS _time,
       CASE WHEN body:message::VARCHAR LIKE 'AUDIT:%' THEN LOWER(SPLIT_PART(body:message::VARCHAR, ',', 4))
            ELSE 'login' END AS action,
       body:user::VARCHAR AS user_name,
       SPLIT_PART(body:remote_host::VARCHAR, ':', 1) AS src,
       body:dbname::VARCHAR AS dest,
       body:application_name::VARCHAR AS app,
       IFF(body:message::VARCHAR LIKE 'AUDIT:%', UPPER(SPLIT_PART(body:message::VARCHAR, ',', 5)), 'LOGIN') AS query_type,
       IFF(body:message::VARCHAR LIKE 'AUDIT:%',
           REGEXP_REPLACE(REGEXP_SUBSTR(body:message::VARCHAR, '^AUDIT: ([^,]*,){7}(.*)$', 1, 1, 'e', 2), ',<[a-z ]+>$', ''),
           body:message::VARCHAR) AS query_text,
       NULLIF(SPLIT_PART(body:message::VARCHAR, ',', 7), '') AS object,
       NULLIF(SPLIT_PART(body:message::VARCHAR, ',', 6), '') AS object_category,
       IFF(body:state_code::VARCHAR = '28P01' OR body:error_severity::VARCHAR IN ('ERROR', 'FATAL'), 'failure', 'success') AS result,
       IFF(body:state_code::VARCHAR = '28P01' OR body:error_severity::VARCHAR IN ('ERROR', 'FATAL'),
           body:message::VARCHAR, NULL) AS reason,
       body:session_id::VARCHAR AS session_id,
       'postgres' AS vendor_product, COALESCE(resource:"host.name"::VARCHAR, 'postgres') AS host,
       'postgres:jsonlog' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'postgres'
  AND (body:message::VARCHAR LIKE 'AUDIT:%' OR body:state_code::VARCHAR = '28P01'
       OR body:message::VARCHAR ILIKE 'connection authorized%' OR body:message::VARCHAR ILIKE 'password authentication failed%')$$),

('clickhouse', 'DATABASE_ACTIVITY', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(body:event_time::VARCHAR), event_time) AS _time,
       LOWER(COALESCE(body:query_kind::VARCHAR, 'other')) AS action,
       body:user::VARCHAR AS user_name,
       REPLACE(body:address::VARCHAR, '::ffff:', '') AS src,
       COALESCE(resource:"host.name"::VARCHAR, 'clickhouse') AS dest,
       body:client_name::VARCHAR AS app,
       UPPER(COALESCE(body:query_kind::VARCHAR, 'OTHER')) AS query_type,
       LEFT(body:query::VARCHAR, 16000) AS query_text,
       ARRAY_TO_STRING(body:tables, ',') AS object,
       'table' AS object_category,
       IFF(body:type::VARCHAR LIKE 'Exception%', 'failure', 'success') AS result,
       LEFT(body:exception::VARCHAR, 2000) AS reason,
       COALESCE(body:result_rows::NUMBER, body:written_rows::NUMBER) AS rows_affected,
       body:read_bytes::NUMBER AS bytes,
       body:query_id::VARCHAR AS session_id,
       'clickhouse' AS vendor_product, COALESCE(resource:"host.name"::VARCHAR, 'clickhouse') AS host,
       'clickhouse:query_log' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'clickhouse' AND COALESCE(body:type::VARCHAR, '') <> 'QueryStart' AND body:query IS NOT NULL$$),

('salesforce', 'DATABASE_ACTIVITY', $$SELECT COALESCE(TRY_TO_TIMESTAMP_LTZ(COALESCE(body:EventDate, body:CreatedDate)::VARCHAR), event_time) AS _time,
       CASE body:EventType::VARCHAR WHEN 'LoginEvent' THEN 'login' WHEN 'ReportEvent' THEN 'report'
            WHEN 'ApiEvent' THEN 'api' WHEN 'BulkApiResultEvent' THEN 'bulk_api' WHEN 'SetupAuditTrail' THEN 'setup'
            ELSE LOWER(body:EventType::VARCHAR) END AS action,
       LOWER(SPLIT_PART(COALESCE(body:Username, body:CreatedByUsername)::VARCHAR, '@', 1)) AS user_name,
       body:SourceIp::VARCHAR AS src,
       COALESCE(body:OrganizationId::VARCHAR, 'salesforce') AS dest,
       COALESCE(body:Application, body:Client)::VARCHAR AS app,
       COALESCE(body:Operation, body:LoginType, body:Action, body:EventType)::VARCHAR AS query_type,
       LEFT(COALESCE(body:Query, body:Display, body:QueriedEntities)::VARCHAR, 16000) AS query_text,
       COALESCE(body:ReportId, body:QueriedEntities, body:Section)::VARCHAR AS object,
       body:EventType::VARCHAR AS object_category,
       IFF(body:EventType::VARCHAR = 'LoginEvent' AND COALESCE(body:Status::VARCHAR, 'Success') <> 'Success',
           'failure', 'success') AS result,
       IFF(body:EventType::VARCHAR = 'LoginEvent' AND COALESCE(body:Status::VARCHAR, 'Success') <> 'Success',
           body:Status::VARCHAR, NULL) AS reason,
       body:RowsProcessed::NUMBER AS rows_affected,
       body:SessionKey::VARCHAR AS session_id,
       body:OrganizationId::VARCHAR AS vendor_account, 'salesforce' AS vendor_product,
       'salesforce' AS host, 'salesforce:event_monitoring' AS sourcetype, body AS _raw
FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS
WHERE source_id = 'salesforce' AND body:EventType IS NOT NULL$$)
AS x(source_id, target_table, mapping_sql)) v
WHERE NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS m
                  WHERE m.source_id = v.source_id AND m.target_table = v.target_table AND m.status = 'live');

-- Validate every shipped mapping now (compiles and casts against the CIM table)
CALL SNOWFLAKE_XDR.REFERENCE.APPLY_CIM_MAPPINGS();
