-- ============================================================================
-- Snowflake XDR - 19: False-Positive Learning & Auto-Suppression
-- ============================================================================
-- Learns FP rates per (rule, entity) from analyst dispositions, auto-dismisses
-- repeat offenders, scores everything else, and adds an AI_CLASSIFY second
-- opinion for findings with no history.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Learned FP patterns (materialized from analyst dispositions)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.FP_PATTERNS (
    rule_id         VARCHAR(100) NOT NULL,
    entity          VARCHAR(255) NOT NULL,
    fp_count        NUMBER DEFAULT 0,
    tp_count        NUMBER DEFAULT 0,
    benign_count    NUMBER DEFAULT 0,
    total_count     NUMBER DEFAULT 0,
    fp_rate         FLOAT,
    last_disposition TIMESTAMP_LTZ,
    trained_at      TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    PRIMARY KEY (rule_id, entity)
);

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.TRAIN_FP_MODEL()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_patterns NUMBER;
BEGIN
    MERGE INTO SNOWFLAKE_XDR.DETECTIONS.FP_PATTERNS p
    USING (
        SELECT rule_id,
               COALESCE(user_name, src, dest, 'unknown') AS entity,
               COUNT(IFF(disposition = 'false_positive', 1, NULL)) AS fp_count,
               COUNT(IFF(disposition = 'true_positive', 1, NULL)) AS tp_count,
               COUNT(IFF(disposition = 'benign', 1, NULL)) AS benign_count,
               COUNT(*) AS total_count,
               MAX(triaged_at) AS last_disp
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        -- Human verdicts only: machine suppressions must not train the model that made them
        WHERE disposition IS NOT NULL
          AND COALESCE(disposition_source, 'analyst') IN ('analyst', 'review')
        GROUP BY 1, 2
    ) f
    ON p.rule_id = f.rule_id AND p.entity = f.entity
    WHEN MATCHED THEN UPDATE SET
        p.fp_count = f.fp_count,
        p.tp_count = f.tp_count,
        p.benign_count = f.benign_count,
        p.total_count = f.total_count,
        p.fp_rate = (f.fp_count + 0.5 * f.benign_count + 0.5) / (f.total_count + 1),
        p.last_disposition = f.last_disp,
        p.trained_at = CURRENT_TIMESTAMP()
    WHEN NOT MATCHED THEN INSERT
        (rule_id, entity, fp_count, tp_count, benign_count, total_count,
         fp_rate, last_disposition)
    VALUES
        (f.rule_id, f.entity, f.fp_count, f.tp_count, f.benign_count,
         f.total_count,
         (f.fp_count + 0.5 * f.benign_count + 0.5) / (f.total_count + 1),
         f.last_disp);

    -- Patterns whose human verdicts were all withdrawn (re-opened) no longer apply
    DELETE FROM SNOWFLAKE_XDR.DETECTIONS.FP_PATTERNS p
    WHERE NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
                      WHERE f.rule_id = p.rule_id AND COALESCE(f.user_name, f.src, f.dest, 'unknown') = p.entity
                        AND f.disposition IS NOT NULL
                        AND COALESCE(f.disposition_source, 'analyst') IN ('analyst', 'review'));

    SELECT COUNT(*) INTO :v_patterns FROM SNOWFLAKE_XDR.DETECTIONS.FP_PATTERNS;
    RETURN 'FP model trained on ' || :v_patterns || ' (rule, entity) patterns.';
END;
$$;

-- ---------------------------------------------------------------------------
-- 2. Explicit analyst suppressions (with expiry - auditable)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.SUPPRESSION_RULES (
    suppression_id  VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    rule_id         VARCHAR(100),
    entity          VARCHAR(255),
    reason          VARCHAR(500),
    created_by      VARCHAR(100) DEFAULT 'ui',
    created_at      TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP(),
    expires_at      TIMESTAMP_NTZ
);

-- ---------------------------------------------------------------------------
-- 3. Score + suppress open findings
--    Explicit, expiring suppressions first; then the calibrated confidence
--    model (29_confidence.sql) scores every finding and auto-suppresses only
--    low-confidence, uncorroborated findings with a learned human FP pattern.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.SCORE_FINDINGS_FP()
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_dismissed NUMBER;
    v_conf VARCHAR;
BEGIN
    -- 3a. Explicit suppression rules (not yet expired)
    UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
    SET f.status = 'dismissed',
        f.disposition = 'false_positive',
        f.disposition_source = 'suppression',
        f.verdict_by = s.created_by,
        f.triage_notes = COALESCE(f.triage_notes || ' | ', '')
            || 'Suppressed by rule: ' || s.reason,
        f.triaged_at = CURRENT_TIMESTAMP()
    FROM SNOWFLAKE_XDR.DETECTIONS.SUPPRESSION_RULES s
    WHERE f.status = 'new'
      AND (s.rule_id IS NULL OR s.rule_id = f.rule_id)
      AND (s.entity IS NULL OR s.entity IN (f.user_name, f.src, f.dest))
      AND (s.expires_at IS NULL OR s.expires_at > CURRENT_TIMESTAMP());

    v_dismissed := SQLROWCOUNT;

    -- 3b. Calibrated confidence: score, explain, route
    CALL SNOWFLAKE_XDR.DETECTIONS.SCORE_CONFIDENCE() INTO :v_conf;

    RETURN 'Suppression rules dismissed ' || :v_dismissed || '. ' || :v_conf;
END;
$$;

-- ---------------------------------------------------------------------------
-- 4. AI_CLASSIFY second opinion for findings with no disposition history
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.AI_CLASSIFY_FINDINGS(
    P_LIMIT NUMBER
)
RETURNS VARCHAR
LANGUAGE SQL
AS
$$
DECLARE
    v_scored NUMBER;
BEGIN
    -- Materialize AI labels first (AI_CLASSIFY in a correlated UPDATE does
    -- not persist), then apply them with a static UPDATE.
    LET v_max NUMBER := :P_LIMIT;
    CREATE OR REPLACE TEMPORARY TABLE XDR_AI_CLASSIFY_BATCH AS
    SELECT finding_id, label FROM (
        SELECT finding_id,
               AI_CLASSIFY(
                   LEFT(description, 500),
                   ['true_positive', 'false_positive', 'benign_admin'],
                   {'true_positive': 'genuine malicious security event',
                    'false_positive': 'benign activity misflagged by a noisy detection rule',
                    'benign_admin': 'expected administrative or automated activity'}
               ):labels[0]::VARCHAR AS label
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE status = 'new'
          AND triage_notes IS NULL
    ) WHERE label IS NOT NULL
    LIMIT :v_max;

    LET v_batch NUMBER;
    SELECT COUNT(*) INTO :v_batch FROM XDR_AI_CLASSIFY_BATCH;

    UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
    SET f.triage_notes = 'AI second opinion: ' || b.label
    FROM XDR_AI_CLASSIFY_BATCH b
    WHERE f.finding_id = b.finding_id;

    v_scored := SQLROWCOUNT;
    RETURN 'AI classified ' || :v_scored || ' findings (batch size '
        || :v_batch || ').';
END;
$$;
