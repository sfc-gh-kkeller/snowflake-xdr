-- ============================================================================
-- Snowflake XDR/SIEM - Reference Data
-- ============================================================================
-- MITRE ATT&CK reference tables, threat intel IOCs, and entity baselines.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE SCHEMA REFERENCE;

-- ---------------------------------------------------------------------------
-- MITRE ATT&CK Tactics
-- ---------------------------------------------------------------------------
CREATE OR REPLACE TABLE MITRE_TACTICS (
    tactic_id       VARCHAR(10) PRIMARY KEY,
    tactic_name     VARCHAR(50) NOT NULL,
    tactic_order    NUMBER NOT NULL,
    description     VARCHAR(1000),
    url             VARCHAR(200)
);

INSERT INTO MITRE_TACTICS VALUES
    ('TA0043', 'Reconnaissance', 1, 'The adversary is trying to gather information they can use to plan future operations.', 'https://attack.mitre.org/tactics/TA0043/'),
    ('TA0042', 'Resource Development', 2, 'The adversary is trying to establish resources they can use to support operations.', 'https://attack.mitre.org/tactics/TA0042/'),
    ('TA0001', 'Initial Access', 3, 'The adversary is trying to get into your network.', 'https://attack.mitre.org/tactics/TA0001/'),
    ('TA0002', 'Execution', 4, 'The adversary is trying to run malicious code.', 'https://attack.mitre.org/tactics/TA0002/'),
    ('TA0003', 'Persistence', 5, 'The adversary is trying to maintain their foothold.', 'https://attack.mitre.org/tactics/TA0003/'),
    ('TA0004', 'Privilege Escalation', 6, 'The adversary is trying to gain higher-level permissions.', 'https://attack.mitre.org/tactics/TA0004/'),
    ('TA0005', 'Defense Evasion', 7, 'The adversary is trying to avoid being detected.', 'https://attack.mitre.org/tactics/TA0005/'),
    ('TA0006', 'Credential Access', 8, 'The adversary is trying to steal account names and passwords.', 'https://attack.mitre.org/tactics/TA0006/'),
    ('TA0007', 'Discovery', 9, 'The adversary is trying to figure out your environment.', 'https://attack.mitre.org/tactics/TA0007/'),
    ('TA0008', 'Lateral Movement', 10, 'The adversary is trying to move through your environment.', 'https://attack.mitre.org/tactics/TA0008/'),
    ('TA0009', 'Collection', 11, 'The adversary is trying to gather data of interest to their goal.', 'https://attack.mitre.org/tactics/TA0009/'),
    ('TA0011', 'Command and Control', 12, 'The adversary is trying to communicate with compromised systems.', 'https://attack.mitre.org/tactics/TA0011/'),
    ('TA0010', 'Exfiltration', 13, 'The adversary is trying to steal data.', 'https://attack.mitre.org/tactics/TA0010/'),
    ('TA0040', 'Impact', 14, 'The adversary is trying to manipulate, interrupt, or destroy your systems and data.', 'https://attack.mitre.org/tactics/TA0040/');

-- ---------------------------------------------------------------------------
-- MITRE ATT&CK Techniques (subset relevant to our detections)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE TABLE MITRE_TECHNIQUES (
    technique_id    VARCHAR(20) PRIMARY KEY,
    technique_name  VARCHAR(200) NOT NULL,
    tactic_id       VARCHAR(10),
    tactic_name     VARCHAR(50),
    description     VARCHAR(2000),
    platforms       ARRAY,
    data_sources    ARRAY,
    url             VARCHAR(200)
);

INSERT INTO MITRE_TECHNIQUES
    SELECT 'T1110', 'Brute Force', 'TA0006', 'Credential Access', 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or password hashes are obtained.', ['Windows','Linux','macOS','Cloud'], ['Authentication','Network Traffic'], 'https://attack.mitre.org/techniques/T1110/'
    UNION ALL SELECT 'T1078', 'Valid Accounts', 'TA0001', 'Initial Access', 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.', ['Windows','Linux','macOS','Cloud'], ['Authentication','Logon Session'], 'https://attack.mitre.org/techniques/T1078/'
    UNION ALL SELECT 'T1078.004', 'Cloud Accounts', 'TA0004', 'Privilege Escalation', 'Adversaries may obtain and abuse credentials of a cloud account.', ['Cloud'], ['Authentication','Logon Session'], 'https://attack.mitre.org/techniques/T1078/004/'
    UNION ALL SELECT 'T1621', 'Multi-Factor Authentication Request Generation', 'TA0006', 'Credential Access', 'Adversaries may attempt to bypass MFA by generating push notifications repeatedly.', ['Windows','Linux','macOS','Cloud'], ['Authentication','Logon Session'], 'https://attack.mitre.org/techniques/T1621/'
    UNION ALL SELECT 'T1059', 'Command and Scripting Interpreter', 'TA0002', 'Execution', 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.', ['Windows','Linux','macOS'], ['Process','Command'], 'https://attack.mitre.org/techniques/T1059/'
    UNION ALL SELECT 'T1059.001', 'PowerShell', 'TA0002', 'Execution', 'Adversaries may abuse PowerShell commands and scripts for execution.', ['Windows'], ['Process','Command','Script'], 'https://attack.mitre.org/techniques/T1059/001/'
    UNION ALL SELECT 'T1003', 'OS Credential Dumping', 'TA0006', 'Credential Access', 'Adversaries may attempt to dump credentials to obtain account login and credential material.', ['Windows','Linux','macOS'], ['Process','Command'], 'https://attack.mitre.org/techniques/T1003/'
    UNION ALL SELECT 'T1003.001', 'LSASS Memory', 'TA0006', 'Credential Access', 'Adversaries may attempt to access credential material stored in LSASS process memory.', ['Windows'], ['Process'], 'https://attack.mitre.org/techniques/T1003/001/'
    UNION ALL SELECT 'T1053.005', 'Scheduled Task', 'TA0003', 'Persistence', 'Adversaries may abuse the Windows Task Scheduler to perform task scheduling for execution of malicious code.', ['Windows'], ['Process','Scheduled Job'], 'https://attack.mitre.org/techniques/T1053/005/'
    UNION ALL SELECT 'T1547.001', 'Registry Run Keys / Startup Folder', 'TA0003', 'Persistence', 'Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.', ['Windows'], ['Windows Registry','File'], 'https://attack.mitre.org/techniques/T1547/001/'
    UNION ALL SELECT 'T1021.002', 'SMB/Windows Admin Shares', 'TA0008', 'Lateral Movement', 'Adversaries may use Valid Accounts to interact with a remote network share using SMB.', ['Windows'], ['Network Traffic','Logon Session'], 'https://attack.mitre.org/techniques/T1021/002/'
    UNION ALL SELECT 'T1021.001', 'Remote Desktop Protocol', 'TA0008', 'Lateral Movement', 'Adversaries may use Valid Accounts to log into a computer using RDP.', ['Windows'], ['Network Traffic','Logon Session'], 'https://attack.mitre.org/techniques/T1021/001/'
    UNION ALL SELECT 'T1055', 'Process Injection', 'TA0005', 'Defense Evasion', 'Adversaries may inject code into processes in order to evade process-based defenses and elevate privileges.', ['Windows','Linux','macOS'], ['Process'], 'https://attack.mitre.org/techniques/T1055/'
    UNION ALL SELECT 'T1490', 'Inhibit System Recovery', 'TA0040', 'Impact', 'Adversaries may delete or remove built-in OS data and turn off services designed to aid in recovery.', ['Windows','Linux','macOS'], ['Process','Command'], 'https://attack.mitre.org/techniques/T1490/'
    UNION ALL SELECT 'T1071', 'Application Layer Protocol', 'TA0011', 'Command and Control', 'Adversaries may communicate using application layer protocols to avoid detection.', ['Windows','Linux','macOS'], ['Network Traffic'], 'https://attack.mitre.org/techniques/T1071/'
    UNION ALL SELECT 'T1071.001', 'Web Protocols', 'TA0011', 'Command and Control', 'Adversaries may communicate using application layer protocols associated with web traffic.', ['Windows','Linux','macOS'], ['Network Traffic'], 'https://attack.mitre.org/techniques/T1071/001/'
    UNION ALL SELECT 'T1071.004', 'DNS', 'TA0011', 'Command and Control', 'Adversaries may communicate using the DNS application layer protocol to avoid detection.', ['Windows','Linux','macOS'], ['Network Traffic'], 'https://attack.mitre.org/techniques/T1071/004/'
    UNION ALL SELECT 'T1048', 'Exfiltration Over Alternative Protocol', 'TA0010', 'Exfiltration', 'Adversaries may steal data by exfiltrating it over a different protocol than the existing C2 channel.', ['Windows','Linux','macOS'], ['Network Traffic'], 'https://attack.mitre.org/techniques/T1048/'
    UNION ALL SELECT 'T1046', 'Network Service Discovery', 'TA0007', 'Discovery', 'Adversaries may attempt to get a listing of services running on remote hosts.', ['Windows','Linux','macOS'], ['Network Traffic'], 'https://attack.mitre.org/techniques/T1046/'
    UNION ALL SELECT 'T1530', 'Data from Cloud Storage', 'TA0009', 'Collection', 'Adversaries may access data from improperly secured cloud storage.', ['Cloud'], ['Cloud Storage'], 'https://attack.mitre.org/techniques/T1530/'
    UNION ALL SELECT 'T1098', 'Account Manipulation', 'TA0003', 'Persistence', 'Adversaries may manipulate accounts to maintain access to victim systems.', ['Windows','Linux','macOS','Cloud'], ['User Account'], 'https://attack.mitre.org/techniques/T1098/'
    UNION ALL SELECT 'T1562.007', 'Disable or Modify Cloud Firewall', 'TA0005', 'Defense Evasion', 'Adversaries may disable or modify a cloud firewall to bypass controls.', ['Cloud'], ['Firewall'], 'https://attack.mitre.org/techniques/T1562/007/'
    UNION ALL SELECT 'T1562.008', 'Disable Cloud Logs', 'TA0005', 'Defense Evasion', 'Adversaries may disable cloud logging capabilities to prevent their activity from being captured.', ['Cloud'], ['Cloud Service'], 'https://attack.mitre.org/techniques/T1562/008/'
    UNION ALL SELECT 'T1190', 'Exploit Public-Facing Application', 'TA0001', 'Initial Access', 'Adversaries may attempt to exploit a weakness in an Internet-facing host or program.', ['Windows','Linux','macOS','Cloud'], ['Application Log','Network Traffic'], 'https://attack.mitre.org/techniques/T1190/'
    UNION ALL SELECT 'T1505.003', 'Web Shell', 'TA0003', 'Persistence', 'Adversaries may backdoor web servers with web shells to establish persistent access.', ['Windows','Linux','macOS'], ['File','Network Traffic','Process'], 'https://attack.mitre.org/techniques/T1505/003/'
    UNION ALL SELECT 'T1528', 'Steal Application Access Token', 'TA0006', 'Credential Access', 'Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.', ['Cloud','SaaS'], ['User Account'], 'https://attack.mitre.org/techniques/T1528/'
    UNION ALL SELECT 'T1112', 'Modify Registry', 'TA0005', 'Defense Evasion', 'Adversaries may interact with the Windows Registry to hide configuration information.', ['Windows'], ['Windows Registry'], 'https://attack.mitre.org/techniques/T1112/';
-- ---------------------------------------------------------------------------
-- Threat Intelligence IOCs (sample data for enrichment)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS THREAT_INTEL_IOCS (
    ioc_id          VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    ioc_type        VARCHAR(20),        -- ip, domain, hash_md5, hash_sha256, url
    ioc_value       VARCHAR(1000) NOT NULL,
    threat_type     VARCHAR(50),        -- malware, c2, phishing, exploit
    threat_name     VARCHAR(200),
    severity        NUMBER(1),          -- 1-5
    confidence      NUMBER(3),          -- 0-100
    source          VARCHAR(100),       -- feed name
    first_seen      TIMESTAMP_LTZ,
    last_seen       TIMESTAMP_LTZ,
    expires_at      TIMESTAMP_LTZ,
    tags            ARRAY,
    active          BOOLEAN DEFAULT TRUE
);

-- Sample IOCs for demo
-- Seed only when empty, so analyst IOC changes survive re-runs
INSERT INTO THREAT_INTEL_IOCS (ioc_type, ioc_value, threat_type, threat_name, severity, confidence, source, first_seen, active)
SELECT * FROM (VALUES
    ('ip', '185.220.101.42', 'c2', 'Cobalt Strike Beacon', 5, 95, 'abuse.ch', '2024-01-15'::TIMESTAMP_LTZ, TRUE),
    ('ip', '91.219.236.222', 'c2', 'Metasploit Handler', 5, 90, 'abuse.ch', '2024-02-01'::TIMESTAMP_LTZ, TRUE),
    ('ip', '23.106.215.100', 'malware', 'DarkGate Loader', 4, 85, 'threatfox', '2024-03-10'::TIMESTAMP_LTZ, TRUE),
    ('domain', 'evil-update.com', 'c2', 'Custom C2 Framework', 5, 92, 'internal_research', '2024-01-20'::TIMESTAMP_LTZ, TRUE),
    ('domain', 'data-sync-service.net', 'exfiltration', 'Data Exfil Endpoint', 4, 88, 'internal_research', '2024-02-15'::TIMESTAMP_LTZ, TRUE),
    ('domain', 'cdn-analytics-update.com', 'c2', 'Beaconing Infrastructure', 5, 90, 'crowdstrike', '2024-04-01'::TIMESTAMP_LTZ, TRUE),
    ('hash_sha256', 'e99a18c428cb38d5f260853678922e03abd8340b', 'malware', 'Mimikatz', 5, 99, 'virustotal', '2023-06-01'::TIMESTAMP_LTZ, TRUE),
    ('hash_sha256', 'aabbccdd11223344556677889900aabbccdd1122', 'malware', 'Custom Ransomware', 5, 95, 'internal_research', '2024-05-01'::TIMESTAMP_LTZ, TRUE),
    ('ip', '103.137.144.25', 'scanner', 'Mass Scanner', 2, 70, 'greynoise', '2024-01-01'::TIMESTAMP_LTZ, TRUE),
    ('ip', '45.33.32.156', 'scanner', 'Known Scanner (Shodan)', 1, 60, 'greynoise', '2024-01-01'::TIMESTAMP_LTZ, TRUE)
) v
WHERE NOT EXISTS (SELECT 1 FROM THREAT_INTEL_IOCS);

-- ---------------------------------------------------------------------------
-- Entity Baselines (learned normal behavior per entity)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ENTITY_BASELINES (
    baseline_id     VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    entity_type     VARCHAR(50),        -- user, host, ip
    entity_value    VARCHAR(500),
    -- Behavioral metrics
    metric_name     VARCHAR(100),       -- avg_logins_per_day, normal_login_hours, typical_src_ips, etc.
    metric_value    VARIANT,            -- can be number, array, object
    -- Statistical bounds
    mean_value      FLOAT,
    stddev_value    FLOAT,
    p95_value       FLOAT,
    p99_value       FLOAT,
    -- Validity
    sample_period_start TIMESTAMP_LTZ,
    sample_period_end TIMESTAMP_LTZ,
    sample_count    NUMBER,
    last_updated    TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Platform settings (key/value)
--   xdr_console_url   recorded by scripts/deploy_demo.sh; read by the deprecated
--                     XDR_SOC app's banner
--   detection_as_of   detection clock override used by REPLAY_DETECTIONS
--                     (NULL/absent = real time)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE.PLATFORM_SETTINGS (
    setting_key   VARCHAR PRIMARY KEY,
    setting_value VARCHAR,
    updated_at    TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);
