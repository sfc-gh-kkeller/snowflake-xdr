-- ============================================================================
-- Snowflake XDR - Pro Features Backend
-- ============================================================================
-- Semantic view (natural-language query), Cortex Search (similar alerts),
-- entity baselines + ML anomaly detection (UEBA), rule history,
-- posture metrics, and the AI daily briefing.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Semantic view: natural-language querying over the XDR data model
-- ---------------------------------------------------------------------------
-- DASHBOARDS schema already exists (created during app deployment)

CREATE OR REPLACE SEMANTIC VIEW SNOWFLAKE_XDR.DASHBOARDS.XDR_SECURITY
    tables (
        SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS primary key (FINDING_ID)
            with synonyms=('detections','alerts','security findings','hits')
            comment='Security findings raised by XDR detection rules',
        SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES primary key (RULE_ID)
            with synonyms=('detection rules','analytics','detections library')
            comment='Detection rule catalog with MITRE ATT&CK mapping',
        SNOWFLAKE_XDR.INCIDENTS.INCIDENTS primary key (INCIDENT_ID)
            with synonyms=('cases','security incidents','breaches')
            comment='Correlated security incidents'
    )
    relationships (
        FINDINGS_TO_RULES as DETECTION_FINDINGS(RULE_ID) references DETECTION_RULES(RULE_ID),
        FINDINGS_TO_INCIDENTS as DETECTION_FINDINGS(INCIDENT_ID) references INCIDENTS(INCIDENT_ID)
    )
    facts (
        DETECTION_FINDINGS.FINDING_COUNT as 1 comment='Count of security findings',
        DETECTION_FINDINGS.HIGH_SEVERITY_COUNT as IFF(severity >= 4, 1, 0) comment='Count of high or critical findings',
        DETECTION_RULES.ENABLED_RULE_COUNT as IFF(enabled, 1, 0) comment='Count of enabled detection rules',
        INCIDENTS.OPEN_INCIDENT_COUNT as IFF(status = 'open', 1, 0) comment='Count of open incidents'
    )
    dimensions (
        DETECTION_FINDINGS.SEVERITY as SEVERITY with synonyms=('sev','criticality','urgency') comment='Finding severity 1 (info) to 5 (critical)',
        DETECTION_FINDINGS.CATEGORY as CATEGORY with synonyms=('domain','telemetry type') comment='identity, endpoint, network, cloud, application, or custom',
        DETECTION_FINDINGS.STATUS as STATUS with synonyms=('finding state','triage status') comment='new, investigating, contained, resolved, dismissed',
        DETECTION_FINDINGS.DETECTION_TIME as DETECTION_TIME with synonyms=('alert time','detected at','when') comment='When the finding was raised',
        DETECTION_FINDINGS.USER_NAME as USER_NAME with synonyms=('user','account','identity','affected user') comment='User associated with the finding',
        DETECTION_FINDINGS.SRC as SRC with synonyms=('source ip','origin','attacker ip') comment='Source IP or host of the triggering event',
        DETECTION_FINDINGS.RULE_ID as RULE_ID with synonyms=('rule','detection id') comment='Rule that raised the finding',
        DETECTION_FINDINGS.RISK_SCORE as RISK_SCORE with synonyms=('risk','priority score') comment='Risk score of the finding',
        DETECTION_FINDINGS.DETECTION_SOURCE as DETECTION_SOURCE with synonyms=('engine','detector') comment='stored_procedure, custom_rule, ai_hunting_agent, ml_anomaly',
        DETECTION_FINDINGS.DISPOSITION as DISPOSITION with synonyms=('verdict','outcome','mitigated','covered by control','false positive','suppressed','true positive') comment='Analyst or engine verdict: true_positive, false_positive, benign, or mitigated_by_control (real finding already covered by an existing security control). NULL means not yet dispositioned.',
        DETECTION_RULES.RULE_NAME as RULE_NAME with synonyms=('detection name') comment='Human-readable rule name',
        DETECTION_RULES.MITRE_TACTIC as MITRE_TACTIC with synonyms=('tactic','attack phase') comment='MITRE ATT&CK tactic',
        DETECTION_RULES.MITRE_TECHNIQUE as MITRE_TECHNIQUE with synonyms=('technique','attack technique') comment='MITRE ATT&CK technique',
        INCIDENTS.INCIDENT_ID as INCIDENT_ID with synonyms=('incident','case id') comment='Incident identifier',
        INCIDENTS.PRIORITY as PRIORITY comment='Incident priority P1-P4',
        INCIDENTS.DESCRIPTION as DESCRIPTION with synonyms=('incident summary') comment='What the incident is about'
    )
    comment='Snowflake XDR security analytics. Query findings, rules, and incidents by severity, category, MITRE tactic, entity, and time.';

-- ---------------------------------------------------------------------------
-- 2. Cortex Search service: similar-finding retrieval
-- ---------------------------------------------------------------------------
CREATE OR REPLACE CORTEX SEARCH SERVICE SNOWFLAKE_XDR.DETECTIONS.FINDING_SEARCH
    ON description
    ATTRIBUTES rule_id, category, user_name, src, dest, severity, finding_id, detection_time
    WAREHOUSE = XDR_WH
    TARGET_LAG = '10 minutes'
    AS SELECT description, rule_id, category, user_name, src, dest, severity, finding_id, detection_time
       FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS;

-- Similar findings procedure: given a finding, return the most similar ones
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.FIND_SIMILAR_FINDINGS(
    P_FINDING_ID VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
AS
$$
DECLARE
    v_description VARCHAR;
    results VARIANT;
BEGIN
    SELECT COALESCE(description, rule_id, '') INTO :v_description
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE finding_id = :P_FINDING_ID;

    IF (v_description IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('error', 'finding not found');
    END IF;

    SELECT ARRAY_AGG(OBJECT_CONSTRUCT(
               'finding_id', finding_id,
               'rule_id', rule_id,
               'severity', severity,
               'description', description,
               'user_name', user_name,
               'detected', detection_time,
               'similarity', similarity
           ))
    INTO :results
    FROM (
        SELECT finding_id, rule_id, severity, description, user_name,
               detection_time,
               AI_SIMILARITY(:v_description, description) AS similarity
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE finding_id != :P_FINDING_ID
          AND description IS NOT NULL
        ORDER BY similarity DESC
        LIMIT 8
    );

    RETURN OBJECT_CONSTRUCT('query_finding', :P_FINDING_ID,
                            'similar', COALESCE(:results, ARRAY_CONSTRUCT()));
END;
$$;

-- ---------------------------------------------------------------------------
-- 3. UEBA: entity baselines + ML anomaly detection
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.REFERENCE.BUILD_BASELINES()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_users NUMBER;
    v_rows NUMBER;
BEGIN
    DELETE FROM SNOWFLAKE_XDR.REFERENCE.ENTITY_BASELINES;

    -- Per-user behavioral baselines from authentication history,
    -- stored as one row per metric (entity_type, entity_value, metric_name)
    INSERT INTO SNOWFLAKE_XDR.REFERENCE.ENTITY_BASELINES
        (entity_type, entity_value, metric_name, metric_value,
         mean_value, stddev_value, sample_count,
         sample_period_start, sample_period_end)
    SELECT
        'user',
        user_name,
        'failure_rate',
        AVG(IFF(action = 'failure', 1.0, 0.0)),
        AVG(IFF(action = 'failure', 1.0, 0.0)),
        STDDEV(IFF(action = 'failure', 1.0, 0.0)),
        COUNT(*),
        DATEADD('day', -7, CURRENT_TIMESTAMP()),
        CURRENT_TIMESTAMP()
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE user_name IS NOT NULL
      AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    GROUP BY user_name
    UNION ALL
    SELECT
        'user',
        user_name,
        'events_per_day',
        COUNT(*) / 7.0,
        COUNT(*) / 7.0,
        0,
        COUNT(*),
        DATEADD('day', -7, CURRENT_TIMESTAMP()),
        CURRENT_TIMESTAMP()
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE user_name IS NOT NULL
      AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    GROUP BY user_name
    UNION ALL
    SELECT
        'user',
        user_name,
        'distinct_sources',
        COUNT(DISTINCT src),
        COUNT(DISTINCT src),
        0,
        COUNT(*),
        DATEADD('day', -7, CURRENT_TIMESTAMP()),
        CURRENT_TIMESTAMP()
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE user_name IS NOT NULL
      AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    GROUP BY user_name;

    SELECT COUNT(*) INTO :v_users FROM SNOWFLAKE_XDR.REFERENCE.ENTITY_BASELINES;
    RETURN 'Baselines built for ' || :v_users || ' entities.';
END;
$$;

-- ML anomaly detection: statistically unusual event volume per user
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RUN_ML_ANOMALY_DETECTION()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_users NUMBER;
    v_findings NUMBER;
BEGIN
    -- Series: events per day per user over the last 7 days
    CREATE OR REPLACE TEMPORARY TABLE XDR_ANOMALY_SERIES AS
    SELECT
        user_name,
        DATE_TRUNC('day', _time::TIMESTAMP_NTZ) AS ts,
        COUNT(*) AS event_count
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE user_name IS NOT NULL
      AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    GROUP BY user_name, DATE_TRUNC('day', _time::TIMESTAMP_NTZ);

    SELECT COUNT(DISTINCT user_name) INTO :v_users FROM XDR_ANOMALY_SERIES;

    -- UEBA pattern: baseline each user on the trailing window (all days
    -- except the most recent), then score the most recent day against it.
    -- A floor on the threshold keeps low-variance users detectable.
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        (finding_id, rule_id, description, category, severity,
         mitre_tactic_id, mitre_technique_id, user_name,
         event_time, detection_time, detection_source, confidence,
         evidence, risk_score, status)
    SELECT
        UUID_STRING(),
        'ML-ANOMALY-001',
        'Behavioral anomaly: unusual daily activity volume for ' || s.user_name,
        'identity', 3, 'TA0006', 'T1078',
        s.user_name,
        s.ts, CURRENT_TIMESTAMP(), 'ml_anomaly', 85,
        OBJECT_CONSTRUCT(
            'events_in_day', s.event_count,
            'user_mean', ROUND(m.mean_count, 1),
            'user_stddev', ROUND(m.std_count, 1),
            'baseline_days', m.day_count,
            'threshold', ROUND(m.mean_count + GREATEST(2 * m.std_count, 0.5 * m.mean_count, 3), 1)
        ),
        60, 'new'
    FROM XDR_ANOMALY_SERIES s
    -- Expanding baseline: each day is scored against all prior days of
    -- that user (retro UEBA scan over the 7-day window)
    JOIN (
        SELECT s2.user_name, s2.ts,
               AVG(b.event_count) AS mean_count,
               COALESCE(STDDEV(b.event_count), 0) AS std_count,
               COUNT(b.event_count) AS day_count
        FROM XDR_ANOMALY_SERIES s2
        JOIN XDR_ANOMALY_SERIES b
          ON b.user_name = s2.user_name AND b.ts < s2.ts
        GROUP BY s2.user_name, s2.ts
    ) m ON m.user_name = s.user_name AND m.ts = s.ts
    WHERE s.event_count > m.mean_count + GREATEST(2 * m.std_count, 0.5 * m.mean_count, 3)
      -- One finding per user-day: re-runs must not duplicate anomalies
      AND NOT EXISTS (
          SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
          WHERE f.rule_id = 'ML-ANOMALY-001'
            AND f.user_name = s.user_name
            AND DATE_TRUNC('day', f.event_time) = DATE_TRUNC('day', s.ts));

    v_findings := SQLROWCOUNT;
    RETURN 'ML anomaly detection complete. Users analyzed: ' || :v_users
        || ', anomalies found: ' || :v_findings;
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. Rule history: version tracking for custom rules
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_HISTORY (
    history_id VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    rule_id VARCHAR,
    version NUMBER,
    name VARCHAR,
    code VARCHAR,
    language VARCHAR,
    severity NUMBER,
    threshold_count NUMBER,
    enabled BOOLEAN,
    changed_by VARCHAR,
    changed_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.SNAPSHOT_CUSTOM_RULE(
    P_RULE_ID VARCHAR
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_version NUMBER;
BEGIN
    SELECT COALESCE(version, 1) - 1 INTO :v_version
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    WHERE rule_id = :P_RULE_ID;

    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_HISTORY
        (rule_id, version, name, code, language, severity, threshold_count, enabled, changed_by)
    SELECT rule_id, GREATEST(:v_version, 1), name, code, language, severity,
           threshold_count, enabled, 'system'
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    WHERE rule_id = :P_RULE_ID;

    RETURN 'SNAPSHOT_SAVED';
END;
$$;

-- ---------------------------------------------------------------------------
-- 5. Executive posture metrics
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_POSTURE_METRICS AS
SELECT
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE status = 'open') AS open_incidents,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE status = 'new') AS untriaged_findings,
    (SELECT COALESCE(AVG(DATEDIFF('minute', created_at, closed_at)), 0)
     FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE closed_at IS NOT NULL) AS mttr_minutes,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES WHERE enabled = TRUE) AS enabled_rules,
    (SELECT COUNT(DISTINCT mitre_tactic_id) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES
     WHERE enabled = TRUE AND mitre_tactic_id IS NOT NULL) AS tactics_covered,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.REFERENCE.MITRE_TACTICS) AS total_tactics,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS) AS playbook_actions,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS WHERE status = 'success') AS successful_actions,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
     WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS findings_7d,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
     WHERE severity >= 4 AND detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS critical_7d,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS WHERE active = TRUE) AS active_iocs;

-- ---------------------------------------------------------------------------
-- 6. AI daily briefing: the "analyst opens the console and reads" feature
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AI_DAILY_BRIEFING()
RETURNS VARIANT
LANGUAGE SQL
AS
$$
DECLARE
    ai_response VARCHAR;
    metrics_json VARCHAR;
BEGIN
    SELECT OBJECT_CONSTRUCT(
        'open_incidents', COUNT_IF(status = 'open'),
        'total_incidents', COUNT(*),
        'open_by_severity', ARRAY_AGG(DISTINCT severity)
    )::VARCHAR
    INTO :metrics_json
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS;

    LET findings_summary VARCHAR;
    SELECT 'Findings by category last 7 days: ' || ARRAY_TO_STRING(
        ARRAY_AGG(CONCAT(category, ': ', cnt)), ', ')
    INTO :findings_summary
    FROM (SELECT COALESCE(category, 'other') AS category, COUNT(*) AS cnt
          FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
          WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
          GROUP BY 1);

    LET top_entities VARCHAR;
    SELECT 'Most affected entities: ' || ARRAY_TO_STRING(
        ARRAY_AGG(CONCAT(entity, ' (', cnt, ')')), ', ')
    INTO :top_entities
    FROM (SELECT COALESCE(user_name, src, dest, 'unknown') AS entity, COUNT(*) AS cnt
          FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
          WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
          GROUP BY 1 ORDER BY cnt DESC LIMIT 5);

    LET posture VARCHAR;
    SELECT 'MTTR ' || ROUND(COALESCE(mttr_minutes, 0), 0) || ' min, '
        || enabled_rules || ' rules enabled, '
        || untriaged_findings || ' findings untriaged'
    INTO :posture
    FROM SNOWFLAKE_XDR.DETECTIONS.V_POSTURE_METRICS;

    SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3.1-70b',
        'You are the lead analyst writing the morning security briefing for the SOC team.
Platform data:
- Incidents: ' || :metrics_json || '
- ' || :findings_summary || '
- ' || :top_entities || '
- Posture: ' || :posture || '

Write a concise daily briefing with:
1. HEADLINE: one sentence on the security state
2. TOP CONCERNS: 2-3 bullets of what needs attention today
3. WINS: 1-2 bullets of positive indicators
Keep it under 150 words. Plain text with markdown headers.')
    INTO :ai_response;

    RETURN OBJECT_CONSTRUCT('briefing', :ai_response);
END;
$$;

-- ---------------------------------------------------------------------------
-- 7. MITRE gap finder backend: uncovered techniques with attack data present
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_MITRE_GAPS AS
SELECT
    t.technique_id,
    t.technique_name,
    t.tactic_id,
    t.tactic_name,
    t.description,
    (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES r
     WHERE r.mitre_technique_id = t.technique_id AND r.enabled = TRUE) AS enabled_rules
FROM SNOWFLAKE_XDR.REFERENCE.MITRE_TECHNIQUES t
WHERE (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES r
       WHERE r.mitre_technique_id = t.technique_id AND r.enabled = TRUE) = 0
ORDER BY t.tactic_name, t.technique_id;

-- ---------------------------------------------------------------------------
-- 8. Executive report generator
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AI_EXEC_REPORT()
RETURNS VARIANT
LANGUAGE SQL
AS
$$
DECLARE
    ai_response VARCHAR;
BEGIN
    LET posture VARCHAR;
    SELECT 'Open incidents: ' || open_incidents || ', MTTR: ' || ROUND(mttr_minutes, 0)
        || ' min, Rules enabled: ' || enabled_rules || ', Tactics covered: ' || tactics_covered
        || '/' || total_tactics || ', Findings last 7d: ' || findings_7d
        || ', Critical last 7d: ' || critical_7d || ', Playbook actions: ' || playbook_actions
    INTO :posture
    FROM SNOWFLAKE_XDR.DETECTIONS.V_POSTURE_METRICS;

    LET incident_summary VARCHAR;
    SELECT COALESCE(ARRAY_TO_STRING(
        ARRAY_AGG(CONCAT(severity, '/5 - ', LEFT(description, 80))), ' | '), 'No incidents')
    INTO :incident_summary
    FROM (SELECT severity, description FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
          ORDER BY severity DESC LIMIT 5);

    SELECT SNOWFLAKE.CORTEX.COMPLETE('llama3.1-70b',
        'Write an executive security report section for the CISO based on:
PLATFORM METRICS: ' || :posture || '
TOP INCIDENTS: ' || :incident_summary || '

Structure:
## Executive Security Summary
One paragraph on overall security posture.

## Key Metrics
Bullet the metrics with brief interpretation.

## Incidents Review
One short paragraph on the incidents above.

## Recommendations
2-3 actionable recommendations for leadership.

Professional tone, under 300 words, markdown.')
    INTO :ai_response;

    RETURN OBJECT_CONSTRUCT('report', :ai_response);
END;
$$;
