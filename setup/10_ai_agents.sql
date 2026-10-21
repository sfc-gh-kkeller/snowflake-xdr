-- ============================================================================
-- Snowflake XDR/SIEM - AI Agents (Cortex-Powered)
-- ============================================================================
-- Three AI agents using Snowflake Cortex COMPLETE:
--   1. Detection Agent  - Re-analyzes logs to find what rules missed
--   2. Triage Agent     - Scores findings for false positive probability
--   3. Hunting Agent    - Proactively hunts using MITRE/OWASP knowledge
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE SCHEMA DETECTIONS;

-- ===========================================================================
-- AI DETECTION AGENT
-- Re-analyzes logs with LLM reasoning to find patterns static rules miss
-- ===========================================================================
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AI_DETECTION_AGENT(
    TARGET_ENTITY VARCHAR DEFAULT NULL,
    LOOKBACK_HOURS NUMBER DEFAULT 4
)
RETURNS VARIANT
LANGUAGE SQL
AS
$$
DECLARE
    log_context VARCHAR;
    existing_findings VARCHAR;
    ai_response VARCHAR;
    result VARIANT;
BEGIN
    -- Gather relevant logs for the entity
    SELECT LISTAGG(event_summary, '\n') WITHIN GROUP (ORDER BY _time)
    INTO :log_context
    FROM (
        SELECT _time, 'AUTH: ' || action || ' user=' || COALESCE(user_name,'?') || ' src=' || COALESCE(src,'?') || ' dest=' || COALESCE(dest,'?') || ' app=' || COALESCE(app,'?') AS event_summary
        FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
        WHERE _time > DATEADD('hour', -:LOOKBACK_HOURS, CURRENT_TIMESTAMP())
          AND (:TARGET_ENTITY IS NULL OR user_name = :TARGET_ENTITY OR src = :TARGET_ENTITY)
        UNION ALL
        SELECT _time, 'PROCESS: ' || COALESCE(process_name,'?') || ' cmd=' || LEFT(COALESCE(process,'?'),150) || ' user=' || COALESCE(user_name,'?') || ' host=' || COALESCE(dest,'?') || ' parent=' || COALESCE(parent_process_name,'?')
        FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
        WHERE _time > DATEADD('hour', -:LOOKBACK_HOURS, CURRENT_TIMESTAMP())
          AND (:TARGET_ENTITY IS NULL OR user_name = :TARGET_ENTITY OR dest = :TARGET_ENTITY)
        UNION ALL
        SELECT _time, 'NETWORK: ' || COALESCE(src_ip,'?') || ':' || COALESCE(src_port::VARCHAR,'?') || ' -> ' || COALESCE(dest_ip,'?') || ':' || COALESCE(dest_port::VARCHAR,'?') || ' ' || COALESCE(protocol,'?') || ' bytes_out=' || COALESCE(bytes_out::VARCHAR,'0')
        FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
        WHERE _time > DATEADD('hour', -:LOOKBACK_HOURS, CURRENT_TIMESTAMP())
          AND (:TARGET_ENTITY IS NULL OR src_ip = :TARGET_ENTITY OR src = :TARGET_ENTITY)
        UNION ALL
        SELECT _time, 'DNS: ' || COALESCE(src,'?') || ' queried ' || COALESCE(query,'?') || ' type=' || COALESCE(query_type,'?')
        FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
        WHERE _time > DATEADD('hour', -:LOOKBACK_HOURS, CURRENT_TIMESTAMP())
          AND (:TARGET_ENTITY IS NULL OR src = :TARGET_ENTITY)
        ORDER BY _time
        LIMIT 200
    );

    -- Gather existing findings for context
    SELECT COALESCE(LISTAGG(description, '; ') WITHIN GROUP (ORDER BY detection_time), 'None')
    INTO :existing_findings
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE detection_time > DATEADD('hour', -:LOOKBACK_HOURS, CURRENT_TIMESTAMP())
      AND (:TARGET_ENTITY IS NULL OR user_name = :TARGET_ENTITY OR src = :TARGET_ENTITY OR dest = :TARGET_ENTITY)
    LIMIT 10;

    -- Call Cortex LLM
    SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3.1-70b',
        'You are a senior SOC analyst performing threat detection. Analyze these security logs and identify suspicious patterns that automated rules may have missed.

CONTEXT:
- Entity of interest: ' || COALESCE(:TARGET_ENTITY, 'all entities') || '
- Time window: last ' || :LOOKBACK_HOURS::VARCHAR || ' hours
- Existing detections already fired: ' || :existing_findings || '

LOGS:
' || COALESCE(:log_context, 'No logs found') || '

INSTRUCTIONS:
1. Look for subtle indicators of compromise not caught by signature-based rules
2. Consider MITRE ATT&CK techniques, especially multi-step attack chains
3. Look for anomalous behavior patterns, timing anomalies, or unusual entity relationships
4. Consider what a skilled attacker might do to evade detection

Return your findings as a JSON array (or empty array if nothing suspicious):
[{"technique": "T1xxx", "tactic": "tactic_name", "confidence": 0-100, "evidence": "what you observed", "explanation": "why this is suspicious"}]

Return ONLY valid JSON, no other text.')
    INTO :ai_response;

    -- Parse and insert AI findings
    BEGIN
        INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
            rule_id, event_time, severity, confidence, risk_score,
            mitre_tactic_id, mitre_technique_id, category,
            user_name, description, evidence,
            detection_source
        )
        SELECT
            'AI-DET-001',
            CURRENT_TIMESTAMP(),
            CASE
                WHEN f.value:confidence::NUMBER >= 90 THEN 5
                WHEN f.value:confidence::NUMBER >= 70 THEN 4
                WHEN f.value:confidence::NUMBER >= 50 THEN 3
                ELSE 2
            END,
            f.value:confidence::NUMBER,
            (CASE WHEN f.value:confidence::NUMBER >= 90 THEN 5
                  WHEN f.value:confidence::NUMBER >= 70 THEN 4
                  WHEN f.value:confidence::NUMBER >= 50 THEN 3
                  ELSE 2 END) * f.value:confidence::NUMBER / 20.0,
            NULL, -- would need mapping from tactic name
            f.value:technique::VARCHAR,
            'ai_detection',
            :TARGET_ENTITY,
            f.value:explanation::VARCHAR,
            OBJECT_CONSTRUCT('evidence', f.value:evidence, 'technique', f.value:technique, 'tactic', f.value:tactic),
            'ai_detection_agent'
        FROM TABLE(FLATTEN(TRY_PARSE_JSON(:ai_response))) f
        WHERE f.value:confidence::NUMBER >= 50;
    EXCEPTION
        WHEN OTHER THEN NULL; -- graceful handling if JSON parsing fails
    END;

    result := TRY_PARSE_JSON(:ai_response);
    RETURN :result;
END;
$$;

-- ===========================================================================
-- AI TRIAGE AGENT
-- Evaluates findings and scores false-positive probability
-- ===========================================================================
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AI_TRIAGE_AGENT(
    BATCH_SIZE NUMBER DEFAULT 10
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    triaged_count NUMBER DEFAULT 0;
    finding_cursor CURSOR FOR
        SELECT finding_id, rule_id, description, evidence, user_name, src, dest, severity, confidence
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE status = 'new'
          AND ai_fp_probability IS NULL
        ORDER BY risk_score DESC;
    v_finding_id VARCHAR;
    v_rule_id VARCHAR;
    v_description VARCHAR;
    v_evidence VARIANT;
    v_user VARCHAR;
    v_src VARCHAR;
    v_dest VARCHAR;
    v_severity NUMBER;
    v_confidence NUMBER;
    v_ai_response VARCHAR;
BEGIN
    FOR rec IN finding_cursor DO
        IF (triaged_count >= :BATCH_SIZE) THEN EXIT; END IF;
        v_finding_id := rec.finding_id;
        v_rule_id := rec.rule_id;
        v_description := rec.description;
        v_evidence := rec.evidence;
        v_user := rec.user_name;
        v_src := rec.src;
        v_dest := rec.dest;
        v_severity := rec.severity;
        v_confidence := rec.confidence;

        -- Get historical context for this entity
        LET entity_context VARCHAR := '';
        SELECT COALESCE(
            'Previous findings for this entity: ' ||
            COUNT(*)::VARCHAR || ' total, ' ||
            SUM(CASE WHEN disposition = 'false_positive' THEN 1 ELSE 0 END)::VARCHAR || ' were FP, ' ||
            SUM(CASE WHEN disposition = 'true_positive' THEN 1 ELSE 0 END)::VARCHAR || ' were TP',
            'No history')
        INTO :entity_context
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE (user_name = :v_user OR src = :v_src OR dest = :v_dest)
          AND finding_id != :v_finding_id
          AND disposition IS NOT NULL;

        -- Call Cortex LLM for triage
        SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3.1-70b',
            'You are a SOC triage analyst. Evaluate this security finding and estimate the probability it is a FALSE POSITIVE.

FINDING:
- Rule: ' || COALESCE(:v_rule_id,'?') || '
- Description: ' || COALESCE(:v_description,'?') || '
- Severity: ' || :v_severity::VARCHAR || '/5
- Confidence: ' || :v_confidence::VARCHAR || '%
- User: ' || COALESCE(:v_user,'N/A') || '
- Source: ' || COALESCE(:v_src,'N/A') || '
- Destination: ' || COALESCE(:v_dest,'N/A') || '
- Evidence: ' || COALESCE(:v_evidence::VARCHAR,'{}') || '

HISTORICAL CONTEXT:
' || :entity_context || '

INSTRUCTIONS:
Respond with ONLY a JSON object (no other text):
{"fp_probability": 0.0-1.0, "recommendation": "confirm|dismiss|investigate", "reasoning": "brief explanation"}')
        INTO :v_ai_response;

        -- Update the finding with triage results
        BEGIN
            UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
            SET ai_fp_probability = TRY_PARSE_JSON(:v_ai_response):fp_probability::FLOAT,
                ai_explanation = TRY_PARSE_JSON(:v_ai_response):reasoning::VARCHAR,
                status = CASE
                    WHEN TRY_PARSE_JSON(:v_ai_response):recommendation::VARCHAR = 'dismiss' THEN 'dismissed'
                    WHEN TRY_PARSE_JSON(:v_ai_response):recommendation::VARCHAR = 'confirm' THEN 'investigating'
                    ELSE 'new'
                END,
                triaged_at = CURRENT_TIMESTAMP()
            WHERE finding_id = :v_finding_id;
        EXCEPTION
            WHEN OTHER THEN NULL;
        END;

        triaged_count := :triaged_count + 1;
    END FOR;
    RETURN 'Triage complete. Findings evaluated: ' || :triaged_count::VARCHAR;
END;
$$;

-- ===========================================================================
-- AI HUNTING AGENT
-- Proactively hunts for threats using MITRE/OWASP/kill-chain knowledge
-- ===========================================================================
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AI_HUNTING_AGENT(
    FOCUS_AREA VARCHAR DEFAULT 'general',  -- general, lateral_movement, exfiltration, persistence, initial_access
    LOOKBACK_HOURS NUMBER DEFAULT 24
)
RETURNS VARIANT
LANGUAGE SQL
AS
$$
DECLARE
    log_sample VARCHAR;
    hunt_focus VARCHAR;
    ai_response VARCHAR;
    result VARIANT;
BEGIN
    -- Build focus-specific guidance
    CASE :FOCUS_AREA
        WHEN 'lateral_movement' THEN
            hunt_focus := 'Focus on: unusual SMB/RDP connections between workstations, pass-the-hash indicators, WMI/PSExec usage, unexpected admin shares access. MITRE: T1021, T1047, T1570.';
        WHEN 'exfiltration' THEN
            hunt_focus := 'Focus on: large data transfers to external IPs, DNS tunneling, unusual outbound protocols, after-hours data access, cloud storage uploads. MITRE: T1048, T1041, T1567.';
        WHEN 'persistence' THEN
            hunt_focus := 'Focus on: new scheduled tasks, registry modifications, new services, startup folder changes, DLL side-loading. MITRE: T1547, T1053, T1543.';
        WHEN 'initial_access' THEN
            hunt_focus := 'Focus on: phishing indicators (Office spawning cmd/powershell), exploit attempts, unusual authentication patterns, VPN from unusual locations. MITRE: T1566, T1190, T1078.';
        ELSE
            hunt_focus := 'Perform general threat hunting across all MITRE ATT&CK tactics. Look for any indicators of compromise, living-off-the-land techniques, or anomalous behavior patterns. Consider OWASP Top 10 for web-facing assets.';
    END CASE;

    -- Gather a diverse sample of recent logs
    SELECT LISTAGG(log_line, '\n') WITHIN GROUP (ORDER BY _time)
    INTO :log_sample
    FROM (
        (SELECT _time, 'AUTH|' || action || '|' || COALESCE(user_name,'?') || '|' || COALESCE(src,'?') || '|' || COALESCE(dest,'?') || '|' || COALESCE(app,'?') || '|' || COALESCE(geo_country,'?') AS log_line
        FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
        WHERE _time > DATEADD('hour', -:LOOKBACK_HOURS, CURRENT_TIMESTAMP())
        ORDER BY RANDOM() LIMIT 30)
        UNION ALL
        (        SELECT _time, 'PROC|' || COALESCE(dest,'?') || '|' || COALESCE(user_name,'?') || '|' || COALESCE(process_name,'?') || '|' || LEFT(COALESCE(process,'?'),120) || '|parent=' || COALESCE(parent_process_name,'?')
        FROM SNOWFLAKE_XDR.RAW_LOGS.ENDPOINT_PROCESSES
        WHERE _time > DATEADD('hour', -:LOOKBACK_HOURS, CURRENT_TIMESTAMP())
        ORDER BY RANDOM() LIMIT 40)
        UNION ALL
        (        SELECT _time, 'NET|' || COALESCE(src_ip,'?') || ':' || COALESCE(src_port::VARCHAR,'?') || '->' || COALESCE(dest_ip,'?') || ':' || COALESCE(dest_port::VARCHAR,'?') || '|' || COALESCE(protocol,'?') || '|bytes_out=' || COALESCE(bytes_out::VARCHAR,'0') || '|' || COALESCE(direction,'?')
        FROM SNOWFLAKE_XDR.RAW_LOGS.NETWORK_TRAFFIC
        WHERE _time > DATEADD('hour', -:LOOKBACK_HOURS, CURRENT_TIMESTAMP())
        ORDER BY RANDOM() LIMIT 40)
        UNION ALL
        (        SELECT _time, 'DNS|' || COALESCE(src,'?') || '|' || COALESCE(query,'?') || '|' || COALESCE(query_type,'?') || '|len=' || COALESCE(query_length::VARCHAR,'?')
        FROM SNOWFLAKE_XDR.RAW_LOGS.DNS_ACTIVITY
        WHERE _time > DATEADD('hour', -:LOOKBACK_HOURS, CURRENT_TIMESTAMP())
        ORDER BY RANDOM() LIMIT 30)
        UNION ALL
        (        SELECT _time, 'WEB|' || COALESCE(src,'?') || '|' || COALESCE(http_method,'?') || ' ' || COALESCE(LEFT(url,150),'?') || '|status=' || COALESCE(status::VARCHAR,'?') || '|ua=' || LEFT(COALESCE(http_user_agent,'?'),80)
        FROM SNOWFLAKE_XDR.RAW_LOGS.WEB_ACTIVITY
        WHERE _time > DATEADD('hour', -:LOOKBACK_HOURS, CURRENT_TIMESTAMP())
        ORDER BY RANDOM() LIMIT 20)
        UNION ALL
        (        SELECT _time, 'CLOUD|' || COALESCE(user_name,'?') || '|' || COALESCE(action,'?') || '|' || COALESCE(object,'?') || '|result=' || COALESCE(result,'?')
        FROM SNOWFLAKE_XDR.RAW_LOGS.CLOUD_API
        WHERE _time > DATEADD('hour', -:LOOKBACK_HOURS, CURRENT_TIMESTAMP())
        ORDER BY RANDOM() LIMIT 20)
        ORDER BY _time
    );

    -- Call the hunting LLM
    SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3.1-70b',
        'You are an elite threat hunter performing proactive security analysis. You have deep knowledge of MITRE ATT&CK, OWASP Top 10, and real-world APT tradecraft.

HUNTING FOCUS:
' || :hunt_focus || '

LOG SAMPLE (format: TYPE|field1|field2|...):
' || COALESCE(:log_sample, 'No logs available') || '

INSTRUCTIONS:
1. Analyze these logs as a threat hunter would - look for subtle IOCs, behavioral anomalies, and attack patterns
2. Consider living-off-the-land binaries (LOLBins), fileless attacks, and evasion techniques
3. Look for patterns across log types that individually seem normal but together suggest compromise
4. Apply the "assume breach" mindset - what would an attacker do that might blend in?

Return findings as a JSON array (empty if nothing found):
[{"technique": "T1xxx", "tactic": "name", "confidence": 0-100, "entities_involved": ["entity1"], "evidence": "what you observed across logs", "hunt_hypothesis": "what attack scenario this suggests", "recommended_next_steps": "what to investigate further"}]

Return ONLY valid JSON.')
    INTO :ai_response;

    -- Insert hunting findings
    BEGIN
        INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS (
            rule_id, event_time, severity, confidence, risk_score,
            mitre_technique_id, category, description, evidence,
            detection_source
        )
        SELECT
            'AI-HUNT-001',
            CURRENT_TIMESTAMP(),
            CASE
                WHEN f.value:confidence::NUMBER >= 80 THEN 4
                WHEN f.value:confidence::NUMBER >= 60 THEN 3
                ELSE 2
            END,
            f.value:confidence::NUMBER,
            (CASE WHEN f.value:confidence::NUMBER >= 80 THEN 4
                  WHEN f.value:confidence::NUMBER >= 60 THEN 3
                  ELSE 2 END) * f.value:confidence::NUMBER / 20.0,
            f.value:technique::VARCHAR,
            'hunting',
            'Hunting lead (' || :FOCUS_AREA || '): ' || f.value:hunt_hypothesis::VARCHAR,
            OBJECT_CONSTRUCT('evidence', f.value:evidence, 'entities', f.value:entities_involved,
                           'next_steps', f.value:recommended_next_steps, 'focus', :FOCUS_AREA),
            'ai_hunting_agent'
        FROM TABLE(FLATTEN(TRY_PARSE_JSON(:ai_response))) f
        WHERE f.value:confidence::NUMBER >= 40;
    EXCEPTION
        WHEN OTHER THEN NULL;
    END;

    result := TRY_PARSE_JSON(:ai_response);
    RETURN :result;
END;
$$;
