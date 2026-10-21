-- ============================================================================
-- Snowflake XDR - 17: Multi-Stage Attack Campaign Data
-- ============================================================================
-- A scripted 4-stage campaign that gives the attack graph a real story:
--   Stage 1 Recon: 10.1.5.107 rattles 8 user doors on VPN-GW-01 (failures)
--   Stage 2 Access: jsmith compromise succeeds
--   Stage 3 Lateral: jsmith -> WS-042 (SSH) -> FS-FILE01 (SMB) -> DC-01 (RDP)
--   Stage 4 C2: DNS beacons from WS-042 to a DGA-style domain
-- A few actions are 'blocked' to exercise the compensating-controls engine.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE WAREHOUSE XDR_WH;

-- Idempotent: the whole campaign is inserted once. Re-runs detect the
-- stage-1 VPN rows from 10.1.5.107 and skip.
EXECUTE IMMEDIATE $$
DECLARE
    v_existing NUMBER;
BEGIN
    SELECT COUNT(*) INTO :v_existing
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE src = '10.1.5.107' AND app = 'vpn';
    IF (v_existing > 0) THEN
        RETURN 'Campaign already present (' || v_existing || ' stage-1 rows) - skipped.';
    END IF;

-- ---------------------------------------------------------------------------
-- Stage 1: door rattling — 8 users x ~5 failed VPN logins from 10.1.5.107
-- ---------------------------------------------------------------------------
INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    (_time, action, app, authentication_method, authentication_service,
     dest, src, user_name, host, source, sourcetype, index_name, ingestion_time)
SELECT
    DATEADD('minute', -360 + (u.idx * 3 + f.idx), CURRENT_TIMESTAMP()),
    'failure',
    'vpn',
    'password',
    'OpenVPN',
    'host:VPN-GW-01',
    '10.1.5.107',
    u.uname,
    'VPN-GW-01',
    '/var/log/vpn/auth.log',
    'openvpn',
    'auth',
    DATEADD('minute', -358 + (u.idx * 3 + f.idx), CURRENT_TIMESTAMP())
FROM (
    SELECT VALUE AS uname, INDEX AS idx
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(
        'jsmith','kwu','abernathy','lgreco','mtanaka','rpatel','cvasquez','dhoffman'
    )))
) u
CROSS JOIN (
    SELECT VALUE AS f, INDEX AS idx
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(0, 1, 2, 3, 4)))
) f;

-- ---------------------------------------------------------------------------
-- Stage 2: initial access — jsmith VPN login succeeds
-- ---------------------------------------------------------------------------
INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    (_time, action, app, authentication_method, authentication_service,
     dest, src, user_name, host, source, sourcetype, index_name, ingestion_time)
VALUES
    (DATEADD('minute', -300, CURRENT_TIMESTAMP()), 'success', 'vpn', 'password',
     'OpenVPN', 'host:VPN-GW-01', '10.1.5.107', 'jsmith', 'VPN-GW-01',
     '/var/log/vpn/auth.log', 'openvpn', 'auth',
     DATEADD('minute', -299, CURRENT_TIMESTAMP())),
    -- jsmith authenticates to workstation WS-042 (pivot begins)
    (DATEADD('minute', -290, CURRENT_TIMESTAMP()), 'success', 'ssh', 'password',
     'OpenSSH', 'host:WS-042', 'VPN-GW-01', 'jsmith', 'WS-042',
     '/var/log/secure', 'linux_secure', 'auth',
     DATEADD('minute', -289, CURRENT_TIMESTAMP()));

-- ---------------------------------------------------------------------------
-- Stage 3: lateral movement chain across hosts
-- ---------------------------------------------------------------------------
-- WS-042 -> FS-FILE01 over SMB (staging)
INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    (_time, action, src, src_ip, dest, dest_ip, dest_port, transport,
     protocol, app, bytes, duration, rule, dvc, direction, host, source,
     sourcetype, index_name, ingestion_time)
VALUES
    (DATEADD('minute', -270, CURRENT_TIMESTAMP()), 'allowed', 'WS-042', '10.1.2.42',
     'FS-FILE01', '10.1.3.10', 445, 'tcp', 'SMB', 'smbd', 524288, 45.0,
     'Allow-Internal-SMB', 'FW-CORE', 'outbound', 'FW-CORE',
     '/var/log/firewall/core.log', 'firewall', 'network',
     DATEADD('minute', -270, CURRENT_TIMESTAMP()));

-- WS-042 process: attacker tooling (feeds process edges)
INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
    (_time, action, dest, user_name, process_name, process_path,
     parent_process_name, host, source, sourcetype, index_name, ingestion_time)
VALUES
    (DATEADD('minute', -268, CURRENT_TIMESTAMP()), 'start', 'WS-042', 'jsmith',
     'psexec.exe', 'C:\\Temp\\psexec.exe', 'cmd.exe', 'WS-042',
     'edr/agent/logs/process.json', 'edr:process', 'endpoint',
     DATEADD('minute', -240, CURRENT_TIMESTAMP())),
    (DATEADD('minute', -265, CURRENT_TIMESTAMP()), 'start', 'WS-042', 'jsmith',
     'mimikatz.exe', 'C:\\Temp\\mimikatz.exe', 'psexec.exe', 'WS-042',
     'edr/agent/logs/process.json', 'edr:process', 'endpoint',
     DATEADD('minute', -240, CURRENT_TIMESTAMP()));

-- FS-FILE01 -> DC-01 over RDP — BLOCKED by jump-box policy (control-covered)
INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    (_time, action, src, src_ip, dest, dest_ip, dest_port, transport,
     protocol, app, bytes, duration, rule, dvc, direction, host, source,
     sourcetype, index_name, ingestion_time)
VALUES
    (DATEADD('minute', -250, CURRENT_TIMESTAMP()), 'blocked', 'FS-FILE01', '10.1.3.10',
     'DC-01', '10.1.1.5', 3389, 'tcp', 'RDP', 'msrdp', 0, 0.0,
     'Block-RDP-NonJumpbox', 'FW-CORE', 'outbound', 'FW-CORE',
     '/var/log/firewall/core.log', 'firewall', 'network',
     DATEADD('minute', -250, CURRENT_TIMESTAMP())),
    -- Retry from WS-042 also blocked
    (DATEADD('minute', -245, CURRENT_TIMESTAMP()), 'blocked', 'WS-042', '10.1.2.42',
     'DC-01', '10.1.1.5', 3389, 'tcp', 'RDP', 'msrdp', 0, 0.0,
     'Block-RDP-NonJumpbox', 'FW-CORE', 'outbound', 'FW-CORE',
     '/var/log/firewall/core.log', 'firewall', 'network',
     DATEADD('minute', -245, CURRENT_TIMESTAMP()));

-- WS-042 -> DC-01 via SMB admin share — allowed (the real compromise path)
INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    (_time, action, src, src_ip, dest, dest_ip, dest_port, transport,
     protocol, app, bytes, duration, rule, dvc, direction, host, source,
     sourcetype, index_name, ingestion_time)
VALUES
    (DATEADD('minute', -230, CURRENT_TIMESTAMP()), 'allowed', 'WS-042', '10.1.2.42',
     'DC-01', '10.1.1.5', 445, 'tcp', 'SMB', 'smbd', 1048576, 120.0,
     'Allow-Internal-SMB', 'FW-CORE', 'outbound', 'FW-CORE',
     '/var/log/firewall/core.log', 'firewall', 'network',
     DATEADD('minute', -230, CURRENT_TIMESTAMP()));

-- ---------------------------------------------------------------------------
-- Stage 4: C2 — DNS beacons from WS-042 (15 queries, DGA-style domain)
-- ---------------------------------------------------------------------------
INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
    (_time, action, src, dest, query, query_type, answer, reply_code,
     query_length, vendor_product, host, source, sourcetype, index_name, ingestion_time)
SELECT
    DATEADD('minute', -200 + b.idx * 12, CURRENT_TIMESTAMP()),
    'success',
    'WS-042',
    '10.1.2.42',
    'x' || TO_VARCHAR(b.idx) || 'f3kd9z.pay4load-cdn' || TO_VARCHAR(ABS(HASH(b.idx)) % 90 + 10) || '.top',
    'A',
    '91.219.236.' || TO_VARCHAR(ABS(HASH(b.idx)) % 250 + 1),
    'NOERROR',
    34,
    'Bind',
    'DNS-01',
    '/var/log/named/queries.log',
    'bind:dns',
    'dns',
    DATEADD('second', -5, DATEADD('minute', -200 + b.idx * 12, CURRENT_TIMESTAMP()))
FROM (
    SELECT VALUE AS bv, INDEX AS idx
    FROM TABLE(FLATTEN(ARRAY_CONSTRUCT(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14)))
) b;

    RETURN 'Campaign seeded.';
END;
$$;

-- ---------------------------------------------------------------------------
-- Recurring benign noise: the internal attack-surface scanner (10.1.9.50)
-- checks the Shodan scanner IP (an IOC, severity 1) every 12 hours. DET-021
-- fires on every check; analysts have dismissed these as false positives
-- (SEED_ANALYST_DISPOSITIONS), so the FP model learns to auto-suppress the
-- newest ones. Seeding it makes the FP-learning demo deterministic instead of
-- depending on what the random generator happens to produce. Rows sit at
-- minute :50 so replayed 15-minute windows cover them. Run-once like above.
-- ---------------------------------------------------------------------------
EXECUTE IMMEDIATE $$
DECLARE
    v_existing NUMBER;
BEGIN
    SELECT COUNT(*) INTO :v_existing
    FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
    WHERE src_ip = '10.1.9.50' AND dest_ip = '45.33.32.156';
    IF (v_existing > 0) THEN
        RETURN 'Scanner noise already present (' || v_existing || ' rows) - skipped.';
    END IF;

    INSERT INTO SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
        (_time, action, src, src_ip, dest, dest_ip, dest_port, transport,
         protocol, app, bytes, duration, rule, dvc, direction, host, source,
         sourcetype, index_name, ingestion_time)
    SELECT
        t, 'allowed', 'SCAN-01', '10.1.9.50', '45.33.32.156', '45.33.32.156', 443, 'tcp',
        'HTTPS', 'ssl', 2048, 1.2, 'Allow-Scanner-Egress', 'FW-EDGE', 'outbound', 'FW-EDGE',
        '/var/log/firewall/edge.log', 'firewall', 'network', t
    FROM (
        SELECT DATEADD('minute', 50, DATE_TRUNC('hour',
                   DATEADD('hour', -12 * (SEQ4() + 1), CURRENT_TIMESTAMP()))) AS t
        FROM TABLE(GENERATOR(ROWCOUNT => 14))
    );

    RETURN 'Scanner noise seeded (14 rows).';
END;
$$;
