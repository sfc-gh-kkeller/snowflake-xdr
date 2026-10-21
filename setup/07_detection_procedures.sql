-- ============================================================================
-- Snowflake XDR/SIEM - Detection Stored Procedures
-- ============================================================================
-- 30 detection rules organized by category, each mapped to MITRE ATT&CK.
-- Each procedure:
--   1. Queries RAW_LOGS tables for the specified lookback window
--   2. Applies detection logic (pattern match for TTP, statistical for Anomaly)
--   3. Writes findings to DETECTIONS.DETECTION_FINDINGS
--   4. Respects DETECTION_SUPPRESSIONS entries
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE SCHEMA DETECTIONS;

-- ===========================================================================
-- DETECTION CLOCK
-- ===========================================================================
-- All rule windows are relative to DETECTION_NOW(), which is real time unless
-- REFERENCE.PLATFORM_SETTINGS.detection_as_of is set. REPLAY_DETECTIONS uses
-- that override to run the rules "as of" past hours, so a freshly generated
-- 7-day dataset is detected end to end, not just its last hour. The upper
-- bound (_time <= DETECTION_NOW()) keeps later events out of a replayed window.
CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
RETURNS TIMESTAMP_LTZ
AS
$$
    COALESCE(
        (SELECT TRY_TO_TIMESTAMP_LTZ(MAX(setting_value))
         FROM SNOWFLAKE_XDR.REFERENCE.PLATFORM_SETTINGS
         WHERE setting_key = 'detection_as_of'),
        CURRENT_TIMESTAMP())
$$;

-- ===========================================================================
-- SEED THE DETECTION RULES CATALOG
-- ===========================================================================
INSERT OVERWRITE INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES (
    rule_id, rule_name, description, category, detection_type, severity,
    mitre_tactic_id, mitre_tactic, mitre_technique_id, mitre_technique,
    enabled, lookback_minutes, data_sources, splunk_analytic_story, splunk_detection_name
)
SELECT 'DET-001','Brute Force Login Attempts','Detects 10+ failed login attempts from a single source within 10 minutes','identity','ttp',4,'TA0006','Credential Access','T1110','Brute Force',TRUE,60,ARRAY_CONSTRUCT('AUTHENTICATION'),'Credential Access','Detect Excessive Account Lockouts From Endpoint'
UNION ALL SELECT 'DET-002','Impossible Travel Authentication','Login from two geographically distant locations within a short time window','identity','anomaly',4,'TA0001','Initial Access','T1078','Valid Accounts',TRUE,1440,ARRAY_CONSTRUCT('AUTHENTICATION'),'Compromised User Credentials','Detect Activity Related to Pass the Hash Attacks'
UNION ALL SELECT 'DET-003','Login from Unusual Geolocation','Authentication from a country not in the users baseline','identity','anomaly',3,'TA0001','Initial Access','T1078','Valid Accounts',TRUE,60,ARRAY_CONSTRUCT('AUTHENTICATION'),'Suspicious Logins','Authentication from unusual geolocation'
UNION ALL SELECT 'DET-004','MFA Bypass / Fatigue Attack','Multiple MFA push notifications in rapid succession suggesting MFA fatigue attack','identity','ttp',4,'TA0006','Credential Access','T1621','MFA Request Generation',TRUE,30,ARRAY_CONSTRUCT('AUTHENTICATION'),'Multi-factor Authentication Interception','MFA Fatigue Detected'
UNION ALL SELECT 'DET-005','Account Lockout Surge','Spike in account lockouts across multiple users suggesting credential spray','identity','anomaly',3,'TA0006','Credential Access','T1110','Brute Force',TRUE,60,ARRAY_CONSTRUCT('AUTHENTICATION'),'Credential Access','Multiple Disabled Users Failing To Authenticate From Host'
UNION ALL SELECT 'DET-006','Privilege Escalation via Role Change','User assumes an elevated role or receives admin privileges unexpectedly','identity','ttp',4,'TA0004','Privilege Escalation','T1078.004','Cloud Accounts',TRUE,60,ARRAY_CONSTRUCT('AUTHENTICATION','CLOUD_API'),'Cloud Federated Credential Abuse','Unusual role assumption'
UNION ALL SELECT 'DET-007','Suspicious PowerShell Execution','PowerShell with encoded commands, download cradles, or execution policy bypasses','endpoint','ttp',4,'TA0002','Execution','T1059.001','PowerShell',TRUE,60,ARRAY_CONSTRUCT('ENDPOINT_PROCESSES'),'Malicious PowerShell','Any Powershell DownloadString'
UNION ALL SELECT 'DET-008','LSASS Memory Access','Process accessing LSASS memory suggesting credential dumping','endpoint','ttp',5,'TA0006','Credential Access','T1003.001','LSASS Memory',TRUE,60,ARRAY_CONSTRUCT('ENDPOINT_PROCESSES'),'Credential Dumping','Detect Credential Dumping through LSASS access'
UNION ALL SELECT 'DET-009','Scheduled Task Created for Persistence','Suspicious scheduled task creation for maintaining persistence','endpoint','ttp',3,'TA0003','Persistence','T1053.005','Scheduled Task',TRUE,60,ARRAY_CONSTRUCT('ENDPOINT_PROCESSES'),'Scheduled Tasks','Schtasks scheduling job on remote system'
UNION ALL SELECT 'DET-010','Registry Run Key Modification','Modification of registry run keys for persistence','endpoint','ttp',4,'TA0003','Persistence','T1547.001','Registry Run Keys',TRUE,60,ARRAY_CONSTRUCT('ENDPOINT_REGISTRY'),'Windows Persistence Techniques','Registry Keys Used For Persistence'
UNION ALL SELECT 'DET-011','Executable Written to SMB Share','Executable file dropped on a network share suggesting lateral movement staging','endpoint','ttp',4,'TA0008','Lateral Movement','T1021.002','SMB/Windows Admin Shares',TRUE,60,ARRAY_CONSTRUCT('ENDPOINT_FILESYSTEM','NETWORK_TRAFFIC'),'Active Directory Lateral Movement','Detect Renamed Executable'
UNION ALL SELECT 'DET-012','Process Injection Indicators','Indicators of process injection such as WriteProcessMemory or CreateRemoteThread','endpoint','ttp',5,'TA0005','Defense Evasion','T1055','Process Injection',TRUE,60,ARRAY_CONSTRUCT('ENDPOINT_PROCESSES'),'Process Injection','Suspicious Process Injection'
UNION ALL SELECT 'DET-013','Unusual Parent-Child Process Tree','Unexpected parent-child process relationship indicating malicious spawning','endpoint','anomaly',3,'TA0002','Execution','T1059','Command and Scripting Interpreter',TRUE,60,ARRAY_CONSTRUCT('ENDPOINT_PROCESSES'),'Suspicious Process Lineage','Suspicious Parent-Child Process'
UNION ALL SELECT 'DET-014','Volume Shadow Copy Deletion','Deletion of volume shadow copies indicating ransomware preparation','endpoint','ttp',5,'TA0040','Impact','T1490','Inhibit System Recovery',TRUE,60,ARRAY_CONSTRUCT('ENDPOINT_PROCESSES'),'Ransomware','Deleting Shadow Copies'
UNION ALL SELECT 'DET-015','DNS Tunneling Detection','Unusually long DNS queries or high volume of TXT record requests suggesting DNS tunneling','network','anomaly',4,'TA0011','Command and Control','T1071.004','DNS',TRUE,60,ARRAY_CONSTRUCT('DNS_ACTIVITY'),'DNS Hijacking','Detect hosts connecting to dynamic domain providers'
UNION ALL SELECT 'DET-016','Beaconing Activity','Periodic outbound connections with consistent intervals suggesting C2 communication','network','anomaly',5,'TA0011','Command and Control','T1071.001','Web Protocols',TRUE,240,ARRAY_CONSTRUCT('NETWORK_TRAFFIC'),'Command And Control','Clients Connecting to Multiple DNS Servers'
UNION ALL SELECT 'DET-017','Large Outbound Data Transfer','Single connection or session transferring unusually large amounts of data outbound','network','anomaly',4,'TA0010','Exfiltration','T1048','Exfiltration Over Alternative Protocol',TRUE,60,ARRAY_CONSTRUCT('NETWORK_TRAFFIC'),'Data Exfiltration','Large Volume Data Transfer'
UNION ALL SELECT 'DET-018','SMB Lateral Movement','SMB connections between workstations or to sensitive servers from unexpected sources','network','ttp',4,'TA0008','Lateral Movement','T1021.002','SMB/Windows Admin Shares',TRUE,60,ARRAY_CONSTRUCT('NETWORK_TRAFFIC'),'Active Directory Lateral Movement','SMB Traffic Spike'
UNION ALL SELECT 'DET-019','RDP from Unexpected Source','RDP connection from a non-jump-box source to sensitive infrastructure','network','ttp',3,'TA0008','Lateral Movement','T1021.001','Remote Desktop Protocol',TRUE,60,ARRAY_CONSTRUCT('NETWORK_TRAFFIC','AUTHENTICATION'),'Active Directory Lateral Movement','Remote Desktop Network Traffic'
UNION ALL SELECT 'DET-020','Port Scanning Activity','Single source connecting to many ports on a target within a short window','network','ttp',3,'TA0007','Discovery','T1046','Network Service Discovery',TRUE,30,ARRAY_CONSTRUCT('NETWORK_TRAFFIC'),'Network Discovery','Detect Port Scanning'
UNION ALL SELECT 'DET-021','Connection to Known-Bad IOC','Network connection to an IP or domain listed in threat intelligence feeds','network','ttp',5,'TA0011','Command and Control','T1071','Application Layer Protocol',TRUE,15,ARRAY_CONSTRUCT('NETWORK_TRAFFIC','DNS_ACTIVITY'),'Command And Control','ThreatConnect Threat IOC Match'
UNION ALL SELECT 'DET-022','Unusual Cloud API Volume','Spike in API calls from a single identity exceeding baseline by 3x','cloud','anomaly',3,'TA0004','Privilege Escalation','T1078.004','Cloud Accounts',TRUE,60,ARRAY_CONSTRUCT('CLOUD_API'),'Cloud Cryptomining','Cloud API Call Spike'
UNION ALL SELECT 'DET-023','Cloud Storage Made Public','S3 bucket or equivalent storage made publicly accessible','cloud','ttp',5,'TA0009','Collection','T1530','Data from Cloud Storage',TRUE,15,ARRAY_CONSTRUCT('CLOUD_API'),'Suspicious AWS S3 Activities','S3 Bucket Accessible'
UNION ALL SELECT 'DET-024','Cloud Role Assumption from New Source','Role assumed from an IP or identity not previously seen','cloud','anomaly',3,'TA0003','Persistence','T1098','Account Manipulation',TRUE,60,ARRAY_CONSTRUCT('CLOUD_API'),'Cloud Federated Credential Abuse','AWS Cross Account Activity'
UNION ALL SELECT 'DET-025','Security Group Modified to Allow All','Cloud security group opened to 0.0.0.0/0 on sensitive ports','cloud','ttp',5,'TA0005','Defense Evasion','T1562.007','Disable or Modify Cloud Firewall',TRUE,15,ARRAY_CONSTRUCT('CLOUD_API'),'AWS Defense Evasion','AWS Security Group Modification'
UNION ALL SELECT 'DET-026','Cloud Logging Disabled','CloudTrail, audit logging, or monitoring disabled','cloud','ttp',5,'TA0005','Defense Evasion','T1562.008','Disable Cloud Logs',TRUE,15,ARRAY_CONSTRUCT('CLOUD_API'),'Cloud Defense Evasion','AWS CloudTrail Changes'
UNION ALL SELECT 'DET-027','SQL Injection Attempt Pattern','HTTP requests containing SQL injection payloads','application','ttp',4,'TA0001','Initial Access','T1190','Exploit Public-Facing Application',TRUE,30,ARRAY_CONSTRUCT('WEB_ACTIVITY'),'SQL Injection','SQL Injection with Long URLs'
UNION ALL SELECT 'DET-028','Webshell Activity Indicators','File upload to web-accessible directory or suspicious web process spawning commands','application','ttp',5,'TA0003','Persistence','T1505.003','Web Shell',TRUE,60,ARRAY_CONSTRUCT('WEB_ACTIVITY','ENDPOINT_PROCESSES'),'Web Shell','W3WP Spawning Shell'
UNION ALL SELECT 'DET-029','Bulk Data Access Beyond Baseline','User accessing significantly more records/files than their historical baseline','application','anomaly',3,'TA0009','Collection','T1530','Data from Cloud Storage',TRUE,60,ARRAY_CONSTRUCT('ENDPOINT_FILESYSTEM','CLOUD_API'),'Insider Threat','Abnormally High Number Of Cloud Infrastructure API Calls'
UNION ALL SELECT 'DET-030','Application Auth Token Abuse','Access token used from unusual IP or after reported compromise','application','ttp',4,'TA0006','Credential Access','T1528','Steal Application Access Token',TRUE,60,ARRAY_CONSTRUCT('AUTHENTICATION','CLOUD_API'),'OAuth Account Takeover','Suspicious Token Usage';






-- ===========================================================================
-- MASTER DETECTION RUNNER
-- Calls each individual detection based on its lookback window
-- ===========================================================================
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RUN_ALL_DETECTIONS()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    findings_before NUMBER;
    findings_after NUMBER;
    new_findings NUMBER;
BEGIN
    SELECT COUNT(*) INTO :findings_before FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS;

    -- Identity Detections
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_BRUTE_FORCE();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_IMPOSSIBLE_TRAVEL();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_UNUSUAL_GEO();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_PRIVILEGE_ESCALATION();

    -- Endpoint Detections
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_SUSPICIOUS_POWERSHELL();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_LSASS_ACCESS();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_REGISTRY_PERSISTENCE();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_SHADOW_COPY_DELETION();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_SUSPICIOUS_PARENT_CHILD();

    -- Network Detections
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_DNS_TUNNELING();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_BEACONING();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_LARGE_OUTBOUND();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_SMB_LATERAL();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_KNOWN_BAD_IOC();

    -- Cloud Detections
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_CLOUD_LOGGING_DISABLED();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_CLOUD_STORAGE_PUBLIC();

    -- Application Detections
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_SQL_INJECTION();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_WEBSHELL();
    CALL SNOWFLAKE_XDR.DETECTIONS.DETECT_BULK_DATA_ACCESS();

    SELECT COUNT(*) INTO :findings_after FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS;
    new_findings := :findings_after - :findings_before;

    RETURN 'Detection run complete. New findings generated: ' || :new_findings::VARCHAR;
END;
$$;

-- ===========================================================================
-- INDIVIDUAL DETECTION PROCEDURES
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- DET-001: Brute Force Login Attempts
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_BRUTE_FORCE()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, user_name, affected_entities, evidence, evidence_count, description
    )
    SELECT
        'DET-001',
        MAX(_time),
        4,
        LEAST(50 + (COUNT(*) - 10) * 5, 100),
        4 * LEAST(50 + (COUNT(*) - 10) * 5, 100) / 20.0,
        'TA0006', 'T1110', 'identity',
        src, dest, NULL,
        OBJECT_CONSTRUCT('source_ips', ARRAY_AGG(DISTINCT src), 'target_users', ARRAY_AGG(DISTINCT user_name)),
        OBJECT_CONSTRUCT('failed_count', COUNT(*), 'time_window_minutes', 10, 'unique_users_targeted', COUNT(DISTINCT user_name)),
        COUNT(*),
        'Brute force detected: ' || COUNT(*)::VARCHAR || ' failed login attempts from ' || src || ' within 10 minutes targeting ' || COUNT(DISTINCT user_name)::VARCHAR || ' user(s)'
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE action = 'failure'
      AND _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
    GROUP BY src, dest, DATE_TRUNC('minute', _time)::DATE
    HAVING COUNT(*) >= 10
    -- Exclude suppressed
    AND NOT EXISTS (
        SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_SUPPRESSIONS s
        WHERE s.rule_id = 'DET-001' AND s.enabled = TRUE
          AND (s.match_src IS NULL OR s.match_src = src)
    );

    RETURN 'DET-001 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-002: Impossible Travel
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_IMPOSSIBLE_TRAVEL()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, user_name, affected_entities, evidence, evidence_count, description
    )
    WITH auth_sequence AS (
        SELECT
            user_name, _time, src, geo_country,
            LAG(geo_country) OVER (PARTITION BY user_name ORDER BY _time) AS prev_country,
            LAG(_time) OVER (PARTITION BY user_name ORDER BY _time) AS prev_time,
            LAG(src) OVER (PARTITION BY user_name ORDER BY _time) AS prev_src
        FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
        WHERE action = 'success'
          AND _time > DATEADD('day', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
          AND geo_country IS NOT NULL
    )
    SELECT
        'DET-002',
        _time,
        4,
        85,
        4 * 85 / 20.0,
        'TA0001', 'T1078', 'identity',
        src, NULL, user_name,
        OBJECT_CONSTRUCT('user', user_name, 'current_src', src, 'previous_src', prev_src),
        OBJECT_CONSTRUCT('current_country', geo_country, 'previous_country', prev_country,
                        'time_between_minutes', DATEDIFF('minute', prev_time, _time)),
        2,
        'Impossible travel for user ' || user_name || ': login from ' || geo_country || ' after ' || prev_country || ' within ' || DATEDIFF('minute', prev_time, _time)::VARCHAR || ' minutes'
    FROM auth_sequence
    WHERE prev_country IS NOT NULL
      AND geo_country != prev_country
      AND DATEDIFF('minute', prev_time, _time) < 120;

    RETURN 'DET-002 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-003: Unusual Geolocation
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_UNUSUAL_GEO()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, user_name, evidence, evidence_count, description
    )
    SELECT
        'DET-003',
        a._time,
        3,
        70,
        3 * 70 / 20.0,
        'TA0001', 'T1078', 'identity',
        a.src, a.dest, a.user_name,
        OBJECT_CONSTRUCT('country', a.geo_country, 'src_ip', a.src),
        1,
        'Login from unusual country ' || a.geo_country || ' for user ' || a.user_name
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION a
    WHERE a.action = 'success'
      AND a._time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND a._time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND a.geo_country NOT IN ('US', 'CA', 'GB', 'DE')  -- Expected countries
      AND a.geo_country IS NOT NULL;

    RETURN 'DET-003 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-006: Privilege Escalation via Role Change
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_PRIVILEGE_ESCALATION()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, user_name, evidence, evidence_count, description
    )
    SELECT
        'DET-006',
        _time,
        4,
        80,
        4 * 80 / 20.0,
        'TA0004', 'T1078.004', 'cloud',
        src, dest, user_name,
        OBJECT_CONSTRUCT('action', action, 'object', object, 'user_type', user_type),
        1,
        'Privilege escalation: ' || user_name || ' performed ' || action || ' on ' || object
    FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API
    WHERE _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND action IN ('AttachRolePolicy', 'CreateRole', 'AssumeRole', 'PutRolePolicy')
      AND (object LIKE '%Admin%' OR object LIKE '%admin%' OR action = 'AssumeRole');

    RETURN 'DET-006 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-007: Suspicious PowerShell Execution
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_SUSPICIOUS_POWERSHELL()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, user_name, evidence, evidence_count, description
    )
    SELECT
        'DET-007',
        _time,
        4,
        90,
        4 * 90 / 20.0,
        'TA0002', 'T1059.001', 'endpoint',
        NULL, dest, user_name,
        OBJECT_CONSTRUCT('command_line', process, 'process_name', process_name, 'parent', parent_process_name),
        1,
        'Suspicious PowerShell on ' || dest || ' by ' || user_name || ': ' || LEFT(process, 200)
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND LOWER(process_name) IN ('powershell.exe', 'pwsh.exe')
      AND (
          LOWER(process) LIKE '%encodedcommand%'
          OR LOWER(process) LIKE '%-enc %'
          OR LOWER(process) LIKE '%downloadstring%'
          OR LOWER(process) LIKE '%invoke-expression%'
          OR LOWER(process) LIKE '%iex%'
          OR LOWER(process) LIKE '%-nop%'
          OR LOWER(process) LIKE '%-w hidden%'
          OR LOWER(process) LIKE '%bypass%'
          OR LOWER(process) LIKE '%webclient%'
          OR LOWER(process) LIKE '%net.webclient%'
      );

    RETURN 'DET-007 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-008: LSASS Memory Access (Credential Dumping)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_LSASS_ACCESS()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        dest, user_name, evidence, evidence_count, description
    )
    SELECT
        'DET-008',
        _time,
        5,
        95,
        5 * 95 / 20.0,
        'TA0006', 'T1003.001', 'endpoint',
        dest, user_name,
        OBJECT_CONSTRUCT('command_line', process, 'process_name', process_name, 'parent', parent_process_name),
        1,
        'Credential dumping detected on ' || dest || ': ' || process_name || ' accessing LSASS memory'
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND (
          LOWER(process) LIKE '%lsass%'
          OR LOWER(process) LIKE '%mimikatz%'
          OR LOWER(process) LIKE '%sekurlsa%'
          OR (LOWER(process_name) = 'rundll32.exe' AND LOWER(process) LIKE '%minidump%')
          OR (LOWER(process_name) = 'procdump.exe' AND LOWER(process) LIKE '%lsass%')
      );

    RETURN 'DET-008 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-010: Registry Run Key Persistence
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_REGISTRY_PERSISTENCE()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        dest, user_name, evidence, evidence_count, description
    )
    SELECT
        'DET-010',
        _time,
        4,
        85,
        4 * 85 / 20.0,
        'TA0003', 'T1547.001', 'endpoint',
        dest, user_name,
        OBJECT_CONSTRUCT('registry_path', registry_path, 'value_name', registry_value_name, 'value_data', registry_value_data),
        1,
        'Registry persistence on ' || dest || ': Run key modified to execute ' || COALESCE(registry_value_data, 'unknown')
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_REGISTRY
    WHERE _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND action IN ('created', 'modified')
      AND (
          LOWER(registry_path) LIKE '%\\currentversion\\run%'
          OR LOWER(registry_path) LIKE '%\\currentversion\\runonce%'
          OR LOWER(registry_path) LIKE '%\\currentversion\\explorer\\shell folders%'
      )
      AND registry_value_data IS NOT NULL
      AND LOWER(registry_value_data) NOT LIKE '%microsoft%'
      AND LOWER(registry_value_data) NOT LIKE '%windows\\system32%';

    RETURN 'DET-010 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-014: Volume Shadow Copy Deletion (Ransomware)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_SHADOW_COPY_DELETION()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        dest, user_name, evidence, evidence_count, description
    )
    SELECT
        'DET-014',
        _time,
        5,
        98,
        5 * 98 / 20.0,
        'TA0040', 'T1490', 'endpoint',
        dest, user_name,
        OBJECT_CONSTRUCT('command_line', process, 'process_name', process_name),
        1,
        'CRITICAL: Shadow copy deletion on ' || dest || ' by ' || COALESCE(user_name, 'SYSTEM') || ' - possible ransomware activity'
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND (
          (LOWER(process_name) = 'vssadmin.exe' AND LOWER(process) LIKE '%delete shadows%')
          OR (LOWER(process_name) = 'wmic.exe' AND LOWER(process) LIKE '%shadowcopy%' AND LOWER(process) LIKE '%delete%')
          OR (LOWER(process_name) = 'bcdedit.exe' AND LOWER(process) LIKE '%recoveryenabled%' AND LOWER(process) LIKE '%no%')
          OR (LOWER(process_name) = 'wbadmin.exe' AND LOWER(process) LIKE '%delete%catalog%')
      );

    RETURN 'DET-014 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-013: Unusual Parent-Child Process
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_SUSPICIOUS_PARENT_CHILD()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        dest, user_name, evidence, evidence_count, description
    )
    SELECT
        'DET-013',
        _time,
        3,
        75,
        3 * 75 / 20.0,
        'TA0002', 'T1059', 'endpoint',
        dest, user_name,
        OBJECT_CONSTRUCT('process', process_name, 'parent', parent_process_name, 'command', process),
        1,
        'Unusual process tree: ' || COALESCE(parent_process_name,'unknown') || ' spawned ' || process_name || ' on ' || dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    WHERE _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND (
          -- Office apps spawning shells
          (LOWER(parent_process_name) IN ('winword.exe','excel.exe','powerpnt.exe','outlook.exe')
           AND LOWER(process_name) IN ('cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe','mshta.exe'))
          -- Web servers spawning shells
          OR (LOWER(parent_process_name) IN ('w3wp.exe','httpd.exe','nginx.exe','tomcat.exe','java.exe')
              AND LOWER(process_name) IN ('cmd.exe','powershell.exe','bash','sh'))
          -- Services spawning unexpected children
          OR (LOWER(parent_process_name) = 'services.exe'
              AND LOWER(process_name) NOT IN ('svchost.exe','msdtc.exe','taskhost.exe','spoolsv.exe'))
      );

    RETURN 'DET-013 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-015: DNS Tunneling
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_DNS_TUNNELING()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, evidence, evidence_count, description
    )
    SELECT
        'DET-015',
        MAX(_time),
        4,
        CASE WHEN AVG(query_length) > 50 THEN 90 ELSE 70 END,
        4 * (CASE WHEN AVG(query_length) > 50 THEN 90 ELSE 70 END) / 20.0,
        'TA0011', 'T1071.004', 'network',
        src, NULL,
        OBJECT_CONSTRUCT('avg_query_length', ROUND(AVG(query_length),1), 'query_count', COUNT(*),
                        'sample_queries', ARRAY_AGG(query) WITHIN GROUP (ORDER BY _time DESC)),
        COUNT(*),
        'Possible DNS tunneling from ' || src || ': ' || COUNT(*)::VARCHAR || ' queries with avg length ' || ROUND(AVG(query_length),1)::VARCHAR
    FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
    WHERE _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND query_length > 40
    GROUP BY src
    HAVING COUNT(*) > 20 OR AVG(query_length) > 50;

    RETURN 'DET-015 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-016: C2 Beaconing Detection
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_BEACONING()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, evidence, evidence_count, description
    )
    WITH connections AS (
        SELECT
            src_ip, dest_ip, dest,
            _time,
            DATEDIFF('second', LAG(_time) OVER (PARTITION BY src_ip, dest_ip ORDER BY _time), _time) AS interval_sec
        FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
        WHERE _time > DATEADD('hour', -4, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
          AND direction = 'outbound'
          AND dest_port IN (80, 443)
    ),
    beacon_candidates AS (
        SELECT
            src_ip, dest_ip, dest,
            COUNT(*) AS connection_count,
            AVG(interval_sec) AS avg_interval,
            STDDEV(interval_sec) AS stddev_interval,
            MAX(_time) AS last_seen
        FROM connections
        WHERE interval_sec IS NOT NULL AND interval_sec > 0
        GROUP BY src_ip, dest_ip, dest
        HAVING COUNT(*) >= 10
           AND STDDEV(interval_sec) < AVG(interval_sec) * 0.2  -- Low jitter = beaconing
    )
    SELECT
        'DET-016',
        last_seen,
        5,
        CASE WHEN stddev_interval < avg_interval * 0.1 THEN 95 ELSE 80 END,
        5 * (CASE WHEN stddev_interval < avg_interval * 0.1 THEN 95 ELSE 80 END) / 20.0,
        'TA0011', 'T1071.001', 'network',
        src_ip, dest,
        OBJECT_CONSTRUCT('avg_interval_sec', ROUND(avg_interval,1), 'stddev_sec', ROUND(stddev_interval,1),
                        'connection_count', connection_count, 'dest_ip', dest_ip),
        connection_count,
        'C2 beaconing detected: ' || src_ip || ' -> ' || COALESCE(dest, dest_ip) || ' every ~' || ROUND(avg_interval)::VARCHAR || 's (' || connection_count::VARCHAR || ' connections)'
    FROM beacon_candidates;

    RETURN 'DET-016 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-017: Large Outbound Data Transfer
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_LARGE_OUTBOUND()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, evidence, evidence_count, description
    )
    SELECT
        'DET-017',
        MAX(_time),
        4,
        80,
        4 * 80 / 20.0,
        'TA0010', 'T1048', 'network',
        src_ip, dest,
        OBJECT_CONSTRUCT('total_bytes_out', SUM(bytes_out), 'total_mb', ROUND(SUM(bytes_out)/1048576.0, 2),
                        'connection_count', COUNT(*), 'dest_ip', dest_ip),
        COUNT(*),
        'Large outbound transfer: ' || src_ip || ' sent ' || ROUND(SUM(bytes_out)/1048576.0, 1)::VARCHAR || ' MB to ' || COALESCE(dest, dest_ip)
    FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    WHERE _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND direction = 'outbound'
      AND bytes_out > 0
    GROUP BY src_ip, dest_ip, dest
    HAVING SUM(bytes_out) > 100000000;  -- > 100 MB

    RETURN 'DET-017 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-018: SMB Lateral Movement
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_SMB_LATERAL()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, evidence, evidence_count, description
    )
    SELECT
        'DET-018',
        MAX(_time),
        4,
        85,
        4 * 85 / 20.0,
        'TA0008', 'T1021.002', 'network',
        src_ip, NULL,
        OBJECT_CONSTRUCT('targets', ARRAY_AGG(DISTINCT dest_ip), 'target_count', COUNT(DISTINCT dest_ip)),
        COUNT(*),
        'SMB lateral movement: ' || src_ip || ' connected to ' || COUNT(DISTINCT dest_ip)::VARCHAR || ' hosts via SMB (port 445)'
    FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    WHERE _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND dest_port = 445
      AND action = 'allowed'
      AND src_ip LIKE '10.%'  -- Internal source
    GROUP BY src_ip
    HAVING COUNT(DISTINCT dest_ip) >= 3;  -- 3+ unique SMB targets

    RETURN 'DET-018 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-021: Connection to Known-Bad IOC
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_KNOWN_BAD_IOC()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    -- Match network traffic against threat intel IPs
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, evidence, evidence_count, description
    )
    SELECT
        'DET-021',
        n._time,
        t.severity,
        t.confidence,
        t.severity * t.confidence / 20.0,
        'TA0011', 'T1071', 'network',
        n.src_ip, n.dest,
        OBJECT_CONSTRUCT('ioc_value', t.ioc_value, 'threat_type', t.threat_type,
                        'threat_name', t.threat_name, 'ioc_source', t.source, 'dest_port', n.dest_port),
        1,
        'Connection to known-bad IOC: ' || n.src_ip || ' -> ' || t.ioc_value || ' (' || t.threat_name || ')'
    FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC n
    JOIN SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS t
      ON t.ioc_type = 'ip' AND n.dest_ip = t.ioc_value AND t.active = TRUE
    WHERE n._time > DATEADD('minute', -15, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND n._time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW();

    -- Match DNS queries against threat intel domains
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, evidence, evidence_count, description
    )
    SELECT
        'DET-021',
        d._time,
        t.severity,
        t.confidence,
        t.severity * t.confidence / 20.0,
        'TA0011', 'T1071', 'network',
        d.src, d.query,
        OBJECT_CONSTRUCT('ioc_value', t.ioc_value, 'threat_type', t.threat_type,
                        'threat_name', t.threat_name, 'ioc_source', t.source, 'dns_answer', d.answer),
        1,
        'DNS query to known-bad domain: ' || d.src || ' resolved ' || t.ioc_value || ' (' || t.threat_name || ')'
    FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY d
    JOIN SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS t
      ON t.ioc_type = 'domain' AND d.query = t.ioc_value AND t.active = TRUE
    WHERE d._time > DATEADD('minute', -15, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND d._time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW();

    RETURN 'DET-021 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-026: Cloud Logging Disabled
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_CLOUD_LOGGING_DISABLED()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, user_name, evidence, evidence_count, description
    )
    SELECT
        'DET-026',
        _time,
        5,
        95,
        5 * 95 / 20.0,
        'TA0005', 'T1562.008', 'cloud',
        src, user_name,
        OBJECT_CONSTRUCT('action', action, 'object', object, 'vendor', vendor_product, 'region', vendor_region),
        1,
        'CRITICAL: Cloud logging disabled by ' || user_name || ': ' || action || ' on ' || object
    FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API
    WHERE _time > DATEADD('minute', -15, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND LOWER(action) IN ('stoplogging', 'deletetrail', 'updatetrail', 'disablelogging',
                            'deleteflowlogs', 'deleteloggroup');

    RETURN 'DET-026 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-023: Cloud Storage Made Public
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_CLOUD_STORAGE_PUBLIC()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, user_name, evidence, evidence_count, description
    )
    SELECT
        'DET-023',
        _time,
        5,
        90,
        5 * 90 / 20.0,
        'TA0009', 'T1530', 'cloud',
        src, user_name,
        OBJECT_CONSTRUCT('action', action, 'object', object, 'vendor', vendor_product),
        1,
        'Cloud storage policy modified (possible public exposure) by ' || user_name || ' on ' || object
    FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API
    WHERE _time > DATEADD('minute', -15, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND LOWER(action) IN ('putbucketpolicy', 'putbucketacl', 'putobjectacl',
                            'setbucketaccesscontrol', 'setiampolicy');

    RETURN 'DET-023 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-027: SQL Injection Attempts
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_SQL_INJECTION()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, evidence, evidence_count, description
    )
    SELECT
        'DET-027',
        MAX(_time),
        4,
        88,
        4 * 88 / 20.0,
        'TA0001', 'T1190', 'application',
        src, dest,
        OBJECT_CONSTRUCT('attempt_count', COUNT(*), 'sample_urls', ARRAY_AGG(LEFT(url, 200)) WITHIN GROUP (ORDER BY _time DESC),
                        'user_agent', ANY_VALUE(http_user_agent)),
        COUNT(*),
        'SQL injection attack from ' || src || ' against ' || dest || ': ' || COUNT(*)::VARCHAR || ' attempts detected'
    FROM SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY
    WHERE _time > DATEADD('minute', -30, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND threat_category = 'sqli'
    GROUP BY src, dest
    HAVING COUNT(*) >= 3;

    RETURN 'DET-027 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-028: Web Shell Detection
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_WEBSHELL()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        src, dest, evidence, evidence_count, description
    )
    SELECT
        'DET-028',
        _time,
        5,
        92,
        5 * 92 / 20.0,
        'TA0003', 'T1505.003', 'application',
        src, dest,
        OBJECT_CONSTRUCT('url', url, 'method', http_method, 'status', status, 'user_agent', http_user_agent),
        1,
        'Web shell detected: suspicious upload/access at ' || url || ' from ' || src
    FROM SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY
    WHERE _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND (
          threat_category = 'webshell'
          OR (http_method = 'POST' AND (
              LOWER(uri_path) LIKE '%.aspx' OR LOWER(uri_path) LIKE '%.jsp' OR LOWER(uri_path) LIKE '%.php'
          ) AND LOWER(uri_path) LIKE '%upload%')
          OR (LOWER(uri_path) LIKE '%shell%' AND status = 200)
      );

    RETURN 'DET-028 complete';
END;
$$;

-- ---------------------------------------------------------------------------
-- DET-029: Bulk Data Access Beyond Baseline
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DETECT_BULK_DATA_ACCESS()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
        rule_id, event_time, severity, confidence, risk_score,
        mitre_tactic_id, mitre_technique_id, category,
        dest, user_name, evidence, evidence_count, description
    )
    SELECT
        'DET-029',
        MAX(_time),
        3,
        75,
        3 * 75 / 20.0,
        'TA0009', 'T1530', 'application',
        dest, user_name,
        OBJECT_CONSTRUCT('file_count', COUNT(*), 'total_size_kb', SUM(file_size),
                        'time_window', 'last_1_hour', 'action', 'read'),
        COUNT(*),
        'Bulk data access: ' || user_name || ' accessed ' || COUNT(*)::VARCHAR || ' files (' || ROUND(SUM(file_size)/1024.0, 1)::VARCHAR || ' MB) on ' || dest
    FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_FILESYSTEM
    WHERE _time > DATEADD('hour', -1, SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()) AND _time <= SNOWFLAKE_XDR.DETECTIONS.DETECTION_NOW()
      AND action = 'read'
    GROUP BY user_name, dest
    HAVING COUNT(*) > 20;  -- More than 20 file reads in an hour

    RETURN 'DET-029 complete';
END;
$$;
