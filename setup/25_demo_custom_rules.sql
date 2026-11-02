-- ============================================================================
-- Snowflake XDR - 25: Demo custom detection rules
-- ============================================================================
-- A ready-made set of custom rules for the Rules & IOCs view, written against
-- the demo's attack activity so each live rule produces findings:
--   * three SQL rules (enabled)
--   * one Python rule (enabled) - shows the multi-language rule engine
--   * one SQL rule saved disabled - shows the review / test / enable flow
-- Idempotent: rules tagged created_by = 'demo_seed' are replaced on rerun.
-- Thresholds are 1 because each query does its own aggregation (the runner
-- applies threshold_count on top). Lookbacks are 7 days so they keep matching as the demo clock is shifted.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE SCHEMA DETECTIONS;

DELETE FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
 WHERE rule_id IN (SELECT rule_id FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE created_by = 'demo_seed');
DELETE FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE created_by = 'demo_seed';

INSERT INTO SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    (name, description, category, severity, mitre_tactic_id, mitre_technique_id,
     language, source_table, code, threshold_count, threshold_window_minutes,
     lookback_minutes, enabled, created_by)
VALUES
-- 1. Credential theft / lateral movement tooling
('Credential theft tool execution',
 'Known credential-dumping or remote-execution tools (Mimikatz, PsExec, ProcDump, Rubeus, LaZagne, secretsdump) launched on an endpoint.',
 'endpoint', 5, 'TA0006', 'T1003', 'sql', NULL,
 $$SELECT _time, user_name, NULL AS src, dest,
       'Credential/lateral tool executed: ' || process_name || ' on ' || dest || ' by ' || COALESCE(user_name, 'unknown') AS description
FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
WHERE LOWER(process_name) IN ('mimikatz.exe', 'psexec.exe', 'procdump.exe', 'rubeus.exe', 'lazagne.exe', 'secretsdump.exe')$$,
 1, 60, 10080, TRUE, 'demo_seed'),

-- 2. Domain discovery burst
('Domain discovery command burst',
 'Three or more distinct account/domain discovery commands (net user/group, nltest, whoami, systeminfo, ...) by one user on one host within an hour - typical of post-compromise recon scripts.',
 'endpoint', 4, 'TA0007', 'T1087.002', 'sql', NULL,
 $$SELECT MAX(_time) AS _time, user_name, NULL AS src, dest,
       'Discovery burst: ' || COUNT(DISTINCT process) || ' recon commands by ' || COALESCE(user_name, 'unknown') || ' on ' || dest AS description
FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
WHERE REGEXP_LIKE(LOWER(process), '.*(net( |\\.exe )(user|group|localgroup)|nltest|whoami|quser|systeminfo|ipconfig /all|arp -a).*')
GROUP BY user_name, dest, DATE_TRUNC('hour', _time)
HAVING COUNT(DISTINCT process) >= 3$$,
 1, 60, 10080, TRUE, 'demo_seed'),

-- 3. Brute force followed by success
('Brute force followed by successful login',
 'Five or more failed logins for a user from one source, followed by a successful login from the same source within 3 hours.',
 'identity', 5, 'TA0006', 'T1110', 'sql', NULL,
 $$SELECT s._time, s.user_name, s.src, s.dest,
       'Brute force succeeded: ' || f.fails || ' failures then success for ' || s.user_name || ' from ' || s.src AS description
FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION s
JOIN (SELECT user_name, src, COUNT(*) AS fails, MAX(_time) AS last_fail
      FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
      WHERE action = 'failure'
      GROUP BY user_name, src
      HAVING COUNT(*) >= 5) f
  ON s.user_name = f.user_name AND s.src = f.src
WHERE s.action = 'success'
  AND s._time BETWEEN f.last_fail AND DATEADD('hour', 3, f.last_fail)$$,
 1, 60, 10080, TRUE, 'demo_seed'),

-- 4. Python rule: service account used interactively
('Service account interactive login (Python)',
 'A service account (svc*) successfully logged in through an interactive channel (RDP, SSH, VPN, web portal). Service accounts should only authenticate non-interactively.',
 'identity', 4, 'TA0001', 'T1078.002', 'python', 'AUTHENTICATION',
 'def detect(row):
    user = (row.get("USER_NAME") or "").lower()
    app = (row.get("APP") or "").lower()
    ok = (row.get("ACTION") or "").lower() == "success"
    interactive = app in ("rdp", "ssh", "vpn", "win:remote", "web portal")
    return 1 if ok and user.startswith("svc") and interactive else 0
',
 1, 60, 10080, TRUE, 'demo_seed'),

-- 5. Draft rule (disabled) for the review / enable flow
('DNS exfiltration - long query volume (draft)',
 'Ten or more unusually long DNS queries (>50 chars) from one source within an hour - possible DNS tunnelling or exfiltration. Draft: tune the length threshold before enabling.',
 'network', 4, 'TA0010', 'T1048.003', 'sql', NULL,
 $$SELECT MAX(_time) AS _time, NULL AS user_name, src, NULL AS dest,
       'Possible DNS exfiltration: ' || COUNT(*) || ' long queries from ' || src AS description
FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
WHERE query_length > 50
GROUP BY src, DATE_TRUNC('hour', _time)
HAVING COUNT(*) >= 10$$,
 1, 60, 10080, FALSE, 'demo_seed');

-- Compile the Python rule's UDF and run the enabled rules once so findings exist
EXECUTE IMMEDIATE $$
DECLARE
    v_id VARCHAR;
    c CURSOR FOR SELECT rule_id FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
                 WHERE created_by = 'demo_seed' AND language <> 'sql';
BEGIN
    FOR r IN c DO
        v_id := r.rule_id;
        CALL SNOWFLAKE_XDR.DETECTIONS.COMPILE_CUSTOM_RULE_UDF(:v_id);
    END FOR;
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULES();
    CALL SNOWFLAKE_XDR.DETECTIONS.DEDUPE_FINDINGS();
    RETURN 'Demo custom rules seeded';
END;
$$;
