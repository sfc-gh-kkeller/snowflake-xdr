-- ============================================================================
-- Snowflake XDR - 29: Calibrated confidence and human-in-the-loop FP control
-- ============================================================================
-- The false-positive problem, and what this file does about it:
--
--  1. Verdict provenance. Every disposition records who made it
--     (disposition_source: analyst | review | fp_model | suppression | control |
--     confidence_model). Only human verdicts train anything, so automatic
--     suppression can no longer teach itself to suppress more.
--  2. Calibrated confidence per finding (0-1, band high / medium / low) from
--     the rule's measured precision (Beta posterior over human verdicts, prior
--     from the rule / autopilot backtest), entity history, corroboration by
--     other rules on the same entity, incident membership, IOC confidence and
--     the AI second opinion. Every finding carries its factors.
--  3. Routing by band. Low-confidence findings with a learned human FP pattern
--     and no corroboration are auto-suppressed (policy: auto_suppress).
--     Machine-dismissed findings that become corroborated are re-opened.
--  4. Spot checks. A sample of everything the machine dismissed goes to a
--     review queue. A true positive there revokes the suppression, re-opens the
--     findings it hid and retrains the FP model.
--  5. Calibration. Per band, how often humans confirmed the finding; per
--     suppression path, the measured miss rate and estimated hidden attacks.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- ---------------------------------------------------------------------------
-- 1. Columns and provenance backfill
-- ---------------------------------------------------------------------------
ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS ADD COLUMN IF NOT EXISTS disposition_source VARCHAR(30);
ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS ADD COLUMN IF NOT EXISTS verdict_by VARCHAR(255);
ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS ADD COLUMN IF NOT EXISTS conf_score FLOAT;
ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS ADD COLUMN IF NOT EXISTS conf_band VARCHAR(10);
ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS ADD COLUMN IF NOT EXISTS conf_factors VARIANT;
ALTER TABLE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS ADD COLUMN IF NOT EXISTS conf_scored_at TIMESTAMP_LTZ;

UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
SET disposition_source = CASE
        WHEN triage_notes ILIKE '%Auto-suppressed by FP model%' THEN 'fp_model'
        WHEN triage_notes ILIKE '%Suppressed by rule%' THEN 'suppression'
        WHEN disposition = 'mitigated_by_control' THEN 'control'
        ELSE 'analyst' END
WHERE disposition IS NOT NULL AND disposition_source IS NULL;

CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.DETECTIONS.IS_HUMAN_VERDICT(SRC VARCHAR)
RETURNS BOOLEAN
AS $$ COALESCE(SRC, 'analyst') IN ('analyst', 'review') $$;

-- ---------------------------------------------------------------------------
-- 2. Settings
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.CONFIDENCE_SETTINGS (
    setting VARCHAR(50) PRIMARY KEY,
    value   FLOAT,
    note    VARCHAR(300)
);
MERGE INTO SNOWFLAKE_XDR.DETECTIONS.CONFIDENCE_SETTINGS t
USING (SELECT * FROM VALUES
    ('high_threshold', 0.70, 'score >= this is high confidence'),
    ('low_threshold', 0.35, 'score < this is low confidence'),
    ('prior_weight', 4, 'pseudo-verdicts behind the rule prior'),
    ('fp_pattern_min', 3, 'human FP verdicts on (rule, entity) before auto-suppression'),
    ('fp_pattern_rate', 0.85, 'minimum human FP rate on (rule, entity) for auto-suppression'),
    ('spot_check_rate', 0.10, 'share of machine-dismissed findings sent to review'),
    ('spot_check_min_per_pattern', 1, 'reviews per suppression pattern per week, at least')
    AS v(setting, value, note)) s ON t.setting = s.setting
WHEN NOT MATCHED THEN INSERT (setting, value, note) VALUES (s.setting, s.value, s.note);

CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.DETECTIONS.CONF_SETTING(K VARCHAR)
RETURNS FLOAT
AS $$ SELECT MAX(value) FROM SNOWFLAKE_XDR.DETECTIONS.CONFIDENCE_SETTINGS WHERE setting = K $$;

-- Autopilot policy rows for the FP-control change types
MERGE INTO SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_POLICY t
USING (SELECT * FROM VALUES
    ('auto_suppress',      'auto_live',    0, 0, 0.0, 0, 'Auto-suppress low-confidence findings with a learned human FP pattern (spot-checked)'),
    ('suppress_entity',    'propose_only', 5, 0, 0.0, 0, 'Create an expiring suppression for a (rule, entity) analysts keep dismissing'),
    ('intel_allowlist',    'propose_only', 5, 0, 0.0, 0, 'Allowlist an indicator analysts keep marking false positive'),
    ('revoke_suppression', 'auto_live',    0, 0, 0.0, 0, 'Revoke a suppression after a spot check found a true positive'),
    ('recheck_verdicts',   'propose_only', 3, 0, 0.0, 0, 'Re-open analyst false-positive verdicts that other detections now contradict (always human)')
    AS v(change_type, mode, max_per_cycle, promote_after_hours, min_recall, max_benign_matches, description)
) s ON t.change_type = s.change_type
WHEN NOT MATCHED THEN INSERT (change_type, mode, max_per_cycle, promote_after_hours, min_recall,
                              max_benign_matches, description, updated_by)
    VALUES (s.change_type, s.mode, s.max_per_cycle, s.promote_after_hours, s.min_recall,
            s.max_benign_matches, s.description, 'default');

-- ---------------------------------------------------------------------------
-- 3. Rule precision from human verdicts (Beta posterior)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_RULE_PRECISION AS
WITH verdicts AS (
    SELECT rule_id,
           COUNT_IF(disposition IN ('true_positive', 'mitigated_by_control')) AS tp,
           COUNT_IF(disposition = 'false_positive') AS fp,
           COUNT_IF(disposition = 'benign') AS benign
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE disposition IS NOT NULL
      AND (SNOWFLAKE_XDR.DETECTIONS.IS_HUMAN_VERDICT(disposition_source) OR disposition_source = 'control')
    GROUP BY rule_id
),
rules AS (
    SELECT rule_id, rule_name AS name, severity, 'built_in' AS kind, NULL::FLOAT AS backtest_precision
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES
    UNION ALL
    SELECT c.rule_id, c.name, c.severity, COALESCE(c.managed_by, 'human'),
           (SELECT MAX(COALESCE(a.evidence:last_evaluation:metrics:precision, a.evidence:metrics:precision)::FLOAT)
            FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES a WHERE a.rule_id = c.rule_id)
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES c
),
f AS (SELECT rule_id, AVG(confidence) / 100 AS stated FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS GROUP BY 1)
SELECT r.rule_id, r.name, r.severity, r.kind,
       COALESCE(v.tp, 0) AS tp, COALESCE(v.fp, 0) AS fp, COALESCE(v.benign, 0) AS benign,
       COALESCE(v.tp, 0) + COALESCE(v.fp, 0) + COALESCE(v.benign, 0) AS judged,
       -- prior: autopilot backtest, else the rule's stated confidence, shrunk toward 0.5 -
       -- a rule's own claim is weak evidence until humans confirm it
       0.5 + (COALESCE(r.backtest_precision, f.stated, 0.5) - 0.5) * 0.4 AS prior,
       (COALESCE(v.tp, 0) + SNOWFLAKE_XDR.DETECTIONS.CONF_SETTING('prior_weight')
            * (0.5 + (COALESCE(r.backtest_precision, f.stated, 0.5) - 0.5) * 0.4))
         / (COALESCE(v.tp, 0) + COALESCE(v.fp, 0) + COALESCE(v.benign, 0)
            + SNOWFLAKE_XDR.DETECTIONS.CONF_SETTING('prior_weight')) AS precision
FROM rules r
LEFT JOIN verdicts v ON v.rule_id = r.rule_id
LEFT JOIN f ON f.rule_id = r.rule_id;

-- ---------------------------------------------------------------------------
-- 4. Score, explain and route findings
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.SCORE_CONFIDENCE()
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_scored NUMBER;
    v_suppressed NUMBER := 0;
    v_reopened NUMBER;
    v_mode VARCHAR;
BEGIN
    UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS t SET
        conf_score = s.score,
        conf_band = s.band,
        conf_factors = s.factors,
        conf_scored_at = CURRENT_TIMESTAMP()
    FROM (
        WITH cand AS (
            SELECT f.finding_id, f.rule_id, f.event_time, f.incident_id, f.ai_fp_probability, f.evidence,
                   COALESCE(f.user_name, f.src, f.dest, 'unknown') AS entity,
                   ARRAY_CONSTRUCT_COMPACT(f.user_name, f.src, f.dest) AS keys
            FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
            WHERE f.status IN ('new', 'investigating')
               OR (f.status = 'dismissed' AND f.disposition_source IN ('fp_model', 'confidence_model', 'suppression'))
        ),
        corr AS (   -- other rules firing on the same entity within 24h (human-dismissed ones do not count)
            SELECT c.finding_id, COUNT(DISTINCT o.rule_id) AS n_rules,
                   ARRAY_SLICE(ARRAY_AGG(DISTINCT o.rule_id), 0, 5) AS rules
            FROM cand c
            JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS o
              ON o.rule_id <> c.rule_id
             AND ARRAYS_OVERLAP(ARRAY_CONSTRUCT_COMPACT(o.user_name, o.src, o.dest), c.keys)
             AND ABS(DATEDIFF('hour', o.event_time, c.event_time)) <= 24
             AND NOT (COALESCE(o.disposition, '') = 'false_positive' AND SNOWFLAKE_XDR.DETECTIONS.IS_HUMAN_VERDICT(o.disposition_source))
             AND COALESCE(o.disposition_source, '') NOT IN ('fp_model', 'confidence_model', 'suppression')
            GROUP BY c.finding_id
        ),
        tc_ents AS (   -- entities at risk in Trust Center findings (setup/35_snowflake_pack.sql), 7 days
            SELECT DISTINCT LOWER(e.value:entity_name::VARCHAR) AS ent, f.rule_id
            FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f, LATERAL FLATTEN(INPUT => f.affected_entities) e
            WHERE f.detection_source = 'trust_center' AND f.detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
              AND e.value:entity_name IS NOT NULL
        ),
        tc AS (
            SELECT c.finding_id, ARRAY_SLICE(ARRAY_AGG(DISTINCT t.rule_id), 0, 3) AS tc_rules
            FROM cand c JOIN tc_ents t ON t.ent IN (LOWER(c.keys[0]::VARCHAR), LOWER(c.keys[1]::VARCHAR), LOWER(c.keys[2]::VARCHAR))
            WHERE c.rule_id NOT LIKE 'TC-%'
            GROUP BY c.finding_id
        ),
        x AS (
            SELECT c.*, rp.precision AS rule_p, rp.judged AS rule_n, rp.tp AS rule_tp, rp.fp AS rule_fp,
                   p.fp_count AS ent_fp, p.tp_count AS ent_tp, p.total_count AS ent_n,
                   COALESCE(cr.n_rules, 0) AS n_corr, cr.rules AS corr_rules,
                   i.confidence AS ioc_conf, i.ioc_value AS ioc_value, tc.tc_rules
            FROM cand c
            LEFT JOIN tc ON tc.finding_id = c.finding_id
            LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.V_RULE_PRECISION rp ON rp.rule_id = c.rule_id
            LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.FP_PATTERNS p ON p.rule_id = c.rule_id AND p.entity = c.entity
            LEFT JOIN corr cr ON cr.finding_id = c.finding_id
            LEFT JOIN SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS i
              ON c.evidence:ioc_value IS NOT NULL AND LOWER(i.ioc_value) = LOWER(c.evidence:ioc_value::VARCHAR)
        ),
        e AS (   -- log-odds effects
            SELECT x.*,
                   LN(GREATEST(LEAST(COALESCE(rule_p, 0.5), 0.98), 0.02) / (1 - GREATEST(LEAST(COALESCE(rule_p, 0.5), 0.98), 0.02))) AS base_lo,
                   -- entity history, shrunk toward the rule: (tp + 2p) / (n + 2)
                   IFF(COALESCE(ent_n, 0) = 0, 0,
                       LN(GREATEST(LEAST((ent_tp + 2 * COALESCE(rule_p, 0.5)) / (ent_n + 2), 0.98), 0.02)
                          / (1 - GREATEST(LEAST((ent_tp + 2 * COALESCE(rule_p, 0.5)) / (ent_n + 2), 0.98), 0.02)))
                       - LN(GREATEST(LEAST(COALESCE(rule_p, 0.5), 0.98), 0.02) / (1 - GREATEST(LEAST(COALESCE(rule_p, 0.5), 0.98), 0.02)))) AS ent_lo,
                   CASE WHEN n_corr >= 2 THEN 2.2 WHEN n_corr = 1 THEN 1.4 ELSE 0 END AS corr_lo,
                   IFF(incident_id IS NOT NULL, 0.7, 0) AS inc_lo,
                   IFF(ioc_conf IS NULL, 0, (ioc_conf / 100 - 0.5) * 3) AS ioc_lo,
                   IFF(ai_fp_probability IS NULL, 0, -(ai_fp_probability - 0.5) * 1.5) AS ai_lo,
                   IFF(tc_rules IS NULL, 0, 1.0) AS tc_lo
            FROM x
        )
        SELECT finding_id,
               ROUND(1 / (1 + EXP(-(base_lo + ent_lo + corr_lo + inc_lo + ioc_lo + ai_lo + tc_lo))), 3) AS score,
               CASE WHEN 1 / (1 + EXP(-(base_lo + ent_lo + corr_lo + inc_lo + ioc_lo + ai_lo + tc_lo)))
                         >= SNOWFLAKE_XDR.DETECTIONS.CONF_SETTING('high_threshold') THEN 'high'
                    WHEN 1 / (1 + EXP(-(base_lo + ent_lo + corr_lo + inc_lo + ioc_lo + ai_lo + tc_lo)))
                         < SNOWFLAKE_XDR.DETECTIONS.CONF_SETTING('low_threshold') THEN 'low'
                    ELSE 'medium' END AS band,
               ARRAY_CONSTRUCT_COMPACT(
                   OBJECT_CONSTRUCT('factor', 'rule precision', 'effect', ROUND(base_lo, 2),
                       'detail', ROUND(COALESCE(rule_p, 0.5) * 100) || '% of this rule''s findings confirmed ('
                                 || COALESCE(rule_tp, 0) || ' true / ' || COALESCE(rule_fp, 0) || ' false of '
                                 || COALESCE(rule_n, 0) || ' human verdicts, plus prior)'),
                   IFF(ent_lo <> 0, OBJECT_CONSTRUCT('factor', 'entity history', 'effect', ROUND(ent_lo, 2),
                       'detail', entity || ': ' || ent_tp || ' true / ' || ent_fp || ' false of ' || ent_n || ' verdicts for this rule'), NULL),
                   IFF(corr_lo <> 0, OBJECT_CONSTRUCT('factor', 'corroborated', 'effect', corr_lo,
                       'detail', n_corr || ' other rule(s) on the same entity within 24h: ' || ARRAY_TO_STRING(corr_rules, ', ')), NULL),
                   IFF(inc_lo <> 0, OBJECT_CONSTRUCT('factor', 'part of an incident', 'effect', inc_lo, 'detail', incident_id), NULL),
                   IFF(ioc_conf IS NOT NULL, OBJECT_CONSTRUCT('factor', 'IOC confidence', 'effect', ROUND(ioc_lo, 2),
                       'detail', ioc_value || ' scored ' || ioc_conf || '/100 by threat intel'), NULL),
                   IFF(ai_lo <> 0, OBJECT_CONSTRUCT('factor', 'AI second opinion', 'effect', ROUND(ai_lo, 2),
                       'detail', ROUND(ai_fp_probability * 100) || '% likely false positive'), NULL),
                   IFF(tc_lo <> 0, OBJECT_CONSTRUCT('factor', 'Trust Center', 'effect', tc_lo,
                       'detail', 'entity is at risk in Snowflake Trust Center: ' || ARRAY_TO_STRING(tc_rules, ', ')), NULL)) AS factors
        FROM e
    ) s
    WHERE t.finding_id = s.finding_id;
    v_scored := SQLROWCOUNT;

    -- Safety net: a machine-dismissed finding that another detection now corroborates
    -- (or that scores high) is re-opened. Automation never hides corroborated activity.
    UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    SET status = 'new', disposition = NULL, disposition_source = NULL, verdict_by = NULL,
        triage_notes = COALESCE(triage_notes || ' | ', '') || 'Re-opened by the confidence model: '
            || IFF(ARRAY_TO_STRING(conf_factors, ' ') ILIKE '%corroborated%',
                   'other detections fire on the same entity, so it was not safe to suppress',
                   'now ' || ROUND(conf_score * 100) || '% confidence')
    WHERE status = 'dismissed' AND disposition_source IN ('fp_model', 'confidence_model', 'suppression')
      AND (conf_band = 'high' OR ARRAY_TO_STRING(conf_factors, ' ') ILIKE '%corroborated%');
    v_reopened := SQLROWCOUNT;

    -- Auto-suppress: low confidence + learned human FP pattern + no corroboration
    SELECT MAX(mode) INTO :v_mode FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_POLICY WHERE change_type = 'auto_suppress';
    -- the Mission Control kill switch stops automatic suppression
    IF (SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_PAUSED()) THEN
        v_mode := 'paused';
    END IF;
    IF (COALESCE(v_mode, 'auto_live') = 'auto_live') THEN
        UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
        SET f.status = 'dismissed', f.disposition = 'false_positive', f.disposition_source = 'confidence_model',
            f.verdict_by = 'confidence_model',
            f.triage_notes = COALESCE(f.triage_notes || ' | ', '') || 'Auto-suppressed: confidence '
                || ROUND(f.conf_score * 100) || '% (low); analysts marked ' || p.fp_count || ' of ' || p.total_count
                || ' earlier findings for ' || p.entity || ' false positive. Spot-checked.',
            f.triaged_at = CURRENT_TIMESTAMP()
        FROM SNOWFLAKE_XDR.DETECTIONS.FP_PATTERNS p
        WHERE f.status = 'new' AND f.conf_band = 'low'
          AND p.rule_id = f.rule_id AND p.entity = COALESCE(f.user_name, f.src, f.dest, 'unknown')
          AND p.fp_count >= SNOWFLAKE_XDR.DETECTIONS.CONF_SETTING('fp_pattern_min')
          AND p.fp_rate >= SNOWFLAKE_XDR.DETECTIONS.CONF_SETTING('fp_pattern_rate')
          AND p.tp_count = 0
          AND NOT ARRAY_TO_STRING(f.conf_factors, ' ') ILIKE '%corroborated%';
        v_suppressed := SQLROWCOUNT;
    END IF;

    RETURN 'Confidence scored ' || v_scored || ' findings; auto-suppressed ' || v_suppressed
        || '; re-opened ' || v_reopened || ' (mode ' || COALESCE(v_mode, 'auto_live') || ')';
END;
$$;

-- ---------------------------------------------------------------------------
-- 5. Spot-check review queue
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE (
    review_id    VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    finding_id   VARCHAR,
    rule_id      VARCHAR(100),
    entity       VARCHAR(255),
    reason       VARCHAR(40),       -- spot_check_suppressed | low_confidence_sample
    suppressed_by VARCHAR(30),      -- disposition_source at sampling time
    conf_score   FLOAT,
    conf_band    VARCHAR(10),
    sampled_at   TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    status       VARCHAR(20) DEFAULT 'open',   -- open | done
    verdict      VARCHAR(30),
    reviewed_by  VARCHAR(255),
    reviewed_at  TIMESTAMP_LTZ,
    note         VARCHAR(1000),
    outcome      VARCHAR(1000)
);

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.SAMPLE_REVIEWS()
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_n NUMBER;
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE
        (finding_id, rule_id, entity, reason, suppressed_by, conf_score, conf_band)
    SELECT finding_id, rule_id, entity, 'spot_check_suppressed', disposition_source, conf_score, conf_band
    FROM (
        SELECT f.*, COALESCE(f.user_name, f.src, f.dest, 'unknown') AS entity,
               ROW_NUMBER() OVER (PARTITION BY f.rule_id, COALESCE(f.user_name, f.src, f.dest, 'unknown')
                                  ORDER BY f.severity DESC, f.event_time DESC) AS rn
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
        WHERE f.status = 'dismissed'
          AND f.disposition_source IN ('fp_model', 'confidence_model', 'suppression')
          AND f.triaged_at > DATEADD('day', -7, CURRENT_TIMESTAMP())
          AND NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE q WHERE q.finding_id = f.finding_id)
    ) d
    -- at least N per (rule, entity) pattern per week, then a deterministic % sample of the rest
    WHERE (rn <= SNOWFLAKE_XDR.DETECTIONS.CONF_SETTING('spot_check_min_per_pattern')
           AND NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE q
                           WHERE q.rule_id = d.rule_id AND q.entity = d.entity
                             AND q.sampled_at > DATEADD('day', -7, CURRENT_TIMESTAMP())))
       OR MOD(ABS(HASH(finding_id)), 100) < 100 * SNOWFLAKE_XDR.DETECTIONS.CONF_SETTING('spot_check_rate');
    v_n := SQLROWCOUNT;
    RETURN 'Spot checks queued: ' || v_n;
END;
$$;

-- Record a review verdict. A true positive on something the machine dismissed
-- revokes the suppression path, re-opens what it hid and retrains the model.
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.REVIEW_DECIDE(
    P_REVIEW_ID VARCHAR, P_VERDICT VARCHAR, P_NOTE VARCHAR, P_ACTOR VARCHAR
)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_finding VARCHAR;
    v_rule VARCHAR;
    v_entity VARCHAR;
    v_src VARCHAR;
    v_open VARCHAR;
    v_actor VARCHAR := COALESCE(NULLIF(TRIM(:P_ACTOR), ''), CURRENT_USER());
    v_verdict VARCHAR := LOWER(TRIM(:P_VERDICT));
    v_reopened NUMBER := 0;
    v_revoked NUMBER := 0;
    v_outcome VARCHAR;
BEGIN
    IF (v_verdict NOT IN ('true_positive', 'false_positive', 'benign')) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'verdict must be true_positive, false_positive or benign');
    END IF;
    SELECT MAX(finding_id), MAX(rule_id), MAX(entity), MAX(suppressed_by), MAX(status)
      INTO :v_finding, :v_rule, :v_entity, :v_src, :v_open
    FROM SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE WHERE review_id = :P_REVIEW_ID;
    IF (v_finding IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'review not found');
    END IF;
    IF (v_open <> 'open') THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'review already decided');
    END IF;

    UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    SET disposition = :v_verdict, disposition_source = 'review', verdict_by = :v_actor,
        status = CASE :v_verdict WHEN 'true_positive' THEN 'investigating'
                                 WHEN 'benign' THEN 'resolved' ELSE 'dismissed' END,
        triage_notes = COALESCE(triage_notes || ' | ', '') || 'Spot check by ' || :v_actor || ': '
                       || REPLACE(:v_verdict, '_', ' ') || COALESCE(' - ' || NULLIF(:P_NOTE, ''), ''),
        triaged_at = CURRENT_TIMESTAMP()
    WHERE finding_id = :v_finding;

    v_outcome := 'Suppression confirmed';
    IF (v_verdict = 'true_positive') THEN
        -- The machine hid a real finding: stop that suppression path
        UPDATE SNOWFLAKE_XDR.DETECTIONS.SUPPRESSION_RULES
        SET expires_at = CURRENT_TIMESTAMP(),
            reason = reason || ' [revoked by spot check ' || :P_REVIEW_ID || ']'
        WHERE (rule_id IS NULL OR rule_id = :v_rule) AND (entity IS NULL OR entity = :v_entity)
          AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP());
        v_revoked := SQLROWCOUNT;

        UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        SET status = 'new', disposition = NULL, disposition_source = NULL,
            triage_notes = COALESCE(triage_notes || ' | ', '') || 'Re-opened: spot check ' || :P_REVIEW_ID
                           || ' found a true positive for this rule and entity'
        WHERE rule_id = :v_rule AND COALESCE(user_name, src, dest, 'unknown') = :v_entity
          AND status = 'dismissed' AND disposition_source IN ('fp_model', 'confidence_model', 'suppression');
        v_reopened := SQLROWCOUNT;

        CALL SNOWFLAKE_XDR.DETECTIONS.TRAIN_FP_MODEL();
        v_outcome := 'Suppression was wrong: re-opened ' || v_reopened || ' hidden finding(s), revoked '
                     || v_revoked || ' suppression rule(s), FP model retrained';

        INSERT INTO SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES
            (change_type, mode, status, title, rationale, target_rule_id, evidence, decided_by, decision_note)
        SELECT 'revoke_suppression', 'auto_live', 'applied',
               'Revoked suppression: ' || :v_rule || ' on ' || :v_entity,
               'A spot check of a finding dismissed by ' || COALESCE(:v_src, 'automation')
               || ' found a true positive. Every finding this path hid was re-opened.',
               :v_rule,
               OBJECT_CONSTRUCT('review_id', :P_REVIEW_ID, 'finding_id', :v_finding, 'entity', :v_entity,
                                'reopened', :v_reopened, 'revoked_rules', :v_revoked),
               :v_actor || ' (spot check)', :P_NOTE;
    END IF;

    UPDATE SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE
    SET status = 'done', verdict = :v_verdict, reviewed_by = :v_actor, reviewed_at = CURRENT_TIMESTAMP(),
        note = :P_NOTE, outcome = :v_outcome
    WHERE review_id = :P_REVIEW_ID;

    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'message', v_outcome, 'reopened', v_reopened);
END;
$$;

-- ---------------------------------------------------------------------------
-- 6. Calibration and suppression quality
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_CONFIDENCE_CALIBRATION AS
SELECT conf_band AS band,
       COUNT(*) AS human_verdicts,
       COUNT_IF(disposition IN ('true_positive', 'mitigated_by_control')) AS confirmed,
       ROUND(COUNT_IF(disposition IN ('true_positive', 'mitigated_by_control')) / NULLIF(COUNT(*), 0), 2) AS observed_precision,
       ROUND(AVG(conf_score), 2) AS mean_score
FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
WHERE conf_band IS NOT NULL AND disposition IS NOT NULL
  AND SNOWFLAKE_XDR.DETECTIONS.IS_HUMAN_VERDICT(disposition_source)
GROUP BY conf_band;

CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_SUPPRESSION_QUALITY AS
WITH d AS (
    SELECT disposition_source AS path, COUNT(*) AS dismissed
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE status = 'dismissed' AND disposition_source IN ('fp_model', 'confidence_model', 'suppression')
      AND triaged_at > DATEADD('day', -30, CURRENT_TIMESTAMP())
    GROUP BY 1
),
r AS (
    SELECT suppressed_by AS path, COUNT_IF(status = 'done') AS reviewed,
           COUNT_IF(verdict = 'true_positive') AS misses, COUNT_IF(status = 'open') AS pending
    FROM SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE
    WHERE sampled_at > DATEADD('day', -30, CURRENT_TIMESTAMP())
    GROUP BY 1
)
SELECT COALESCE(d.path, r.path) AS path, COALESCE(d.dismissed, 0) AS dismissed_30d,
       COALESCE(r.reviewed, 0) AS reviewed, COALESCE(r.misses, 0) AS misses, COALESCE(r.pending, 0) AS pending,
       ROUND(COALESCE(r.misses, 0) / NULLIF(r.reviewed, 0), 2) AS miss_rate,
       ROUND(COALESCE(d.dismissed, 0) * COALESCE(r.misses, 0) / NULLIF(r.reviewed, 0)) AS est_hidden_true_positives
FROM d FULL OUTER JOIN r ON r.path = d.path;

-- Status for the console digest and agent
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.CONFIDENCE_STATUS()
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
BEGIN
    LET r VARIANT := (SELECT OBJECT_CONSTRUCT(
        'open_by_band', (SELECT OBJECT_AGG(COALESCE(conf_band, 'unscored'), n::VARIANT) FROM (
            SELECT conf_band, COUNT(*) n FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
            WHERE status IN ('new', 'investigating') GROUP BY 1)),
        'auto_suppressed_7d', (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
            WHERE disposition_source IN ('fp_model', 'confidence_model', 'suppression') AND status = 'dismissed'
              AND triaged_at > DATEADD('day', -7, CURRENT_TIMESTAMP())),
        'review_open', (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE WHERE status = 'open'),
        'reviews', (SELECT ARRAY_AGG(OBJECT_CONSTRUCT('review_id', q.review_id, 'rule_id', q.rule_id,
                        'entity', q.entity, 'suppressed_by', q.suppressed_by, 'description', LEFT(f.description, 200),
                        'severity', f.severity, 'conf', q.conf_score)) WITHIN GROUP (ORDER BY f.severity DESC)
                    FROM SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE q
                    JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f ON f.finding_id = q.finding_id
                    WHERE q.status = 'open'),
        'suppression_quality', (SELECT ARRAY_AGG(OBJECT_CONSTRUCT(*)) FROM SNOWFLAKE_XDR.DETECTIONS.V_SUPPRESSION_QUALITY),
        'calibration', (SELECT ARRAY_AGG(OBJECT_CONSTRUCT(*)) FROM SNOWFLAKE_XDR.DETECTIONS.V_CONFIDENCE_CALIBRATION)));
    RETURN r;
END;
$$;

-- Every 15 minutes: score, route and sample (task suspended by default)
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.RUN_CONFIDENCE_PIPELINE()
RETURNS VARCHAR
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    a VARCHAR;
    b VARCHAR;
BEGIN
    CALL SNOWFLAKE_XDR.DETECTIONS.SCORE_FINDINGS_FP() INTO :a;
    CALL SNOWFLAKE_XDR.DETECTIONS.SAMPLE_REVIEWS() INTO :b;
    RETURN a || ' ' || b;
END;
$$;

CREATE TASK IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.TASK_SCORE_CONFIDENCE
    WAREHOUSE = XDR_WH
    SCHEDULE = '15 MINUTE'
    COMMENT = 'Score finding confidence, apply suppressions, queue spot checks'
AS
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CONFIDENCE_PIPELINE();
