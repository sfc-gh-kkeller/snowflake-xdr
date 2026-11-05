-- ============================================================================
-- Snowflake XDR - Phase 5.5: the autonomy track record
-- ============================================================================
-- Proof, not claims. Per week and per month:
--   what the machine changed, how much went live without a human, how often a
--   guardrail or a human reversed it, canary pass rate and branch coverage,
--   verified coverage, MTTD / MTTR, precision of AI-authored vs pack rules (from
--   analyst verdicts), and how often a human reviewer agreed with a random sample
--   of autonomous changes.
--
--   V_AUTONOMY_SCORECARD          one row per period (week / month)
--   V_AUTONOMY_SCORECARD_BY_TYPE  per change type, last 90 days
--   AUTONOMY_REVIEWS              weekly random sample of autonomous changes for a human
--   SAMPLE_AUTONOMY_REVIEWS(n)    TASK_SAMPLE_AUTONOMY_REVIEWS runs it Mondays (n = 5)
--   DECIDE_AUTONOMY_REVIEW(id, agree|disagree, note, actor)
--       disagree demotes that change type one rung on the trust ladder (TRUST_LADDER)
--       and offers the change's undo in Mission Control
-- ============================================================================

CREATE TABLE IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_REVIEWS (
    review_id    VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    change_id    VARCHAR,
    change_type  VARCHAR(40),
    title        VARCHAR(500),
    sampled_at   TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    status       VARCHAR(20),      -- open | agreed | disagreed
    reviewer     VARCHAR(255),
    note         VARCHAR(2000),
    decided_at   TIMESTAMP_LTZ
);

-- ---------------------------------------------------------------------------
-- Scorecard
-- ---------------------------------------------------------------------------
CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_AUTONOMY_SCORECARD AS
WITH periods AS (
    SELECT 'week' AS grain, DATE_TRUNC('week', DATEADD('week', -seq4(), CURRENT_DATE())) AS period_start
    FROM TABLE(GENERATOR(ROWCOUNT => 12))
    UNION ALL
    SELECT 'month', DATE_TRUNC('month', DATEADD('month', -seq4(), CURRENT_DATE()))
    FROM TABLE(GENERATOR(ROWCOUNT => 6))
),
p AS (
    SELECT grain, period_start::TIMESTAMP_LTZ AS t0,
           IFF(grain = 'week', DATEADD('week', 1, period_start), DATEADD('month', 1, period_start))::TIMESTAMP_LTZ AS t1
    FROM periods
),
ch AS (
    SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES
    WHERE change_type NOT IN ('autonomy_promotion', 'autonomy_demotion')
),
changes AS (
    SELECT p.grain, p.t0,
           COUNT(c.change_id) AS changes,
           COUNT_IF(c.status IN ('promoted', 'applied') AND COALESCE(c.decided_by, 'autopilot') ILIKE 'autopilot%') AS went_live_unattended,
           COUNT_IF(c.status = 'approved') AS approved_by_human,
           COUNT_IF(c.status = 'rejected') AS rejected_by_human,
           COUNT_IF(c.status = 'rolled_back' AND c.decided_by ILIKE 'autopilot%') AS auto_rollbacks,
           COUNT_IF(c.status = 'rolled_back' AND NOT c.decided_by ILIKE 'autopilot%') AS human_undos,
           COUNT_IF(c.status = 'failed') AS failed_attempts
    FROM p LEFT JOIN ch c ON c.created_at >= p.t0 AND c.created_at < p.t1
    GROUP BY 1, 2
),
canary AS (
    SELECT p.grain, p.t0, COUNT(k.run_id) AS canary_runs, COUNT_IF(k.status = 'pass') AS canary_passes,
           SUM(IFF(k.run_id IS NULL, 0, COALESCE(k.detail:branches::NUMBER, 1))) AS branches_tested,
           SUM(IFF(k.run_id IS NULL, 0, COALESCE(k.detail:branches_fired::NUMBER, IFF(k.status = 'pass', 1, 0)))) AS branches_fired
    FROM p LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.CANARY_RUNS k ON k.run_at >= p.t0 AND k.run_at < p.t1
    GROUP BY 1, 2
),
mttd AS (
    SELECT p.grain, p.t0,
           MEDIAN(DATEDIFF('second', f.event_time, f.detection_time)) / 60 AS median_detect_minutes,
           COUNT(f.finding_id) AS findings
    FROM p LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
      ON f.detection_time >= p.t0 AND f.detection_time < p.t1 AND f.event_time <= f.detection_time
    GROUP BY 1, 2
),
mttr AS (
    SELECT p.grain, p.t0,
           MEDIAN(DATEDIFF('minute', i.created_at, i.contained_at)) / 60 AS median_contain_hours,
           MEDIAN(DATEDIFF('minute', i.created_at, i.closed_at)) / 60 AS median_close_hours,
           COUNT(i.incident_id) AS cases
    FROM p LEFT JOIN SNOWFLAKE_XDR.INCIDENTS.INCIDENTS i ON i.created_at >= p.t0 AND i.created_at < p.t1
    GROUP BY 1, 2
),
verdicts AS (
    SELECT p.grain, p.t0,
           COUNT_IF(r.managed_by = 'autopilot' AND f.disposition = 'true_positive') AS ai_tp,
           COUNT_IF(r.managed_by = 'autopilot' AND f.disposition IN ('false_positive', 'benign')) AS ai_fp,
           COUNT_IF(r.managed_by = 'pack' AND f.disposition = 'true_positive') AS pack_tp,
           COUNT_IF(r.managed_by = 'pack' AND f.disposition IN ('false_positive', 'benign')) AS pack_fp
    FROM p LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
      ON f.detection_time >= p.t0 AND f.detection_time < p.t1
     AND SNOWFLAKE_XDR.DETECTIONS.IS_HUMAN_VERDICT(f.disposition_source)
    LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES r ON r.rule_id = f.rule_id
    GROUP BY 1, 2
),
reviews AS (
    SELECT p.grain, p.t0, COUNT_IF(v.status = 'agreed') AS reviews_agreed, COUNT_IF(v.status = 'disagreed') AS reviews_disagreed,
           COUNT_IF(v.status = 'open') AS reviews_open
    FROM p LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_REVIEWS v ON v.sampled_at >= p.t0 AND v.sampled_at < p.t1
    GROUP BY 1, 2
)
SELECT c.grain, c.t0::DATE AS period_start,
       c.changes, c.went_live_unattended, c.approved_by_human, c.rejected_by_human,
       c.auto_rollbacks, c.human_undos, c.failed_attempts,
       IFF(c.changes = 0, NULL, ROUND((c.auto_rollbacks + c.human_undos) / c.changes, 3)) AS reversal_rate,
       k.canary_runs, IFF(k.canary_runs = 0, NULL, ROUND(k.canary_passes / k.canary_runs, 3)) AS canary_pass_rate,
       IFF(COALESCE(k.branches_tested, 0) = 0, NULL, ROUND(k.branches_fired / k.branches_tested, 3)) AS branch_coverage,
       ROUND(d.median_detect_minutes, 1) AS median_detect_minutes, d.findings,
       ROUND(r.median_contain_hours, 1) AS median_contain_hours, ROUND(r.median_close_hours, 1) AS median_close_hours, r.cases,
       IFF(v.ai_tp + v.ai_fp = 0, NULL, ROUND(v.ai_tp / (v.ai_tp + v.ai_fp), 3)) AS ai_rule_precision, v.ai_tp + v.ai_fp AS ai_verdicts,
       IFF(v.pack_tp + v.pack_fp = 0, NULL, ROUND(v.pack_tp / (v.pack_tp + v.pack_fp), 3)) AS pack_rule_precision, v.pack_tp + v.pack_fp AS pack_verdicts,
       w.reviews_agreed, w.reviews_disagreed, w.reviews_open,
       IFF(w.reviews_agreed + w.reviews_disagreed = 0, NULL,
           ROUND(w.reviews_agreed / (w.reviews_agreed + w.reviews_disagreed), 3)) AS reviewer_agreement
FROM changes c
JOIN canary k ON k.grain = c.grain AND k.t0 = c.t0
JOIN mttd d ON d.grain = c.grain AND d.t0 = c.t0
JOIN mttr r ON r.grain = c.grain AND r.t0 = c.t0
JOIN verdicts v ON v.grain = c.grain AND v.t0 = c.t0
JOIN reviews w ON w.grain = c.grain AND w.t0 = c.t0;

CREATE OR REPLACE VIEW SNOWFLAKE_XDR.DETECTIONS.V_AUTONOMY_SCORECARD_BY_TYPE AS
SELECT t.change_type, t.mode, t.total, t.automatic_live, t.approvals, t.rejections, t.rollbacks,
       t.canary_pass_rate, t.precision, t.verdicts,
       COUNT_IF(v.status = 'agreed') AS reviews_agreed, COUNT_IF(v.status = 'disagreed') AS reviews_disagreed
FROM SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_TRACK_RECORD t
LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_REVIEWS v
  ON v.change_type = t.change_type AND v.sampled_at > DATEADD('day', -90, CURRENT_TIMESTAMP())
WHERE t.total > 0
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10;

-- ---------------------------------------------------------------------------
-- "Would a human have agreed?" sampling
-- ---------------------------------------------------------------------------
CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.SAMPLE_AUTONOMY_REVIEWS(P_N NUMBER)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_n NUMBER := LEAST(GREATEST(COALESCE(:P_N, 5), 1), 20);
    v_added NUMBER;
BEGIN
    INSERT INTO SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_REVIEWS (change_id, change_type, title, status)
    SELECT change_id, change_type, title, 'open'
    FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES c
    WHERE c.status IN ('promoted', 'applied')
      AND COALESCE(c.decided_by, 'autopilot') ILIKE 'autopilot%'      -- went live without a human
      AND c.change_type NOT IN ('autonomy_promotion', 'autonomy_demotion')
      AND c.updated_at > DATEADD('day', -7, CURRENT_TIMESTAMP())
      AND NOT EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_REVIEWS v WHERE v.change_id = c.change_id)
    QUALIFY ROW_NUMBER() OVER (ORDER BY RANDOM()) <= :v_n;
    v_added := SQLROWCOUNT;
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'sampled', :v_added,
        'message', :v_added || ' autonomous change(s) sampled for human review in Mission Control');
END;
$$;

CREATE OR REPLACE PROCEDURE SNOWFLAKE_XDR.DETECTIONS.DECIDE_AUTONOMY_REVIEW(
    P_REVIEW_ID VARCHAR, P_VERDICT VARCHAR, P_NOTE VARCHAR, P_ACTOR VARCHAR)
RETURNS VARIANT
LANGUAGE SQL
EXECUTE AS CALLER
AS
$$
DECLARE
    v_status VARCHAR;
    v_type VARCHAR;
    v_change VARCHAR;
    v_who VARCHAR := COALESCE(:P_ACTOR || ' (console)', CURRENT_USER());
    r VARIANT;
BEGIN
    SELECT MAX(status), MAX(change_type), MAX(change_id) INTO :v_status, :v_type, :v_change
    FROM SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_REVIEWS WHERE review_id = :P_REVIEW_ID;
    IF (v_status IS NULL) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'review not found');
    END IF;
    IF (v_status <> 'open') THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'review is already ' || v_status);
    END IF;
    IF (LOWER(:P_VERDICT) NOT IN ('agree', 'disagree')) THEN
        RETURN OBJECT_CONSTRUCT('ok', FALSE, 'message', 'verdict must be agree or disagree');
    END IF;
    UPDATE SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_REVIEWS
       SET status = IFF(LOWER(:P_VERDICT) = 'agree', 'agreed', 'disagreed'), reviewer = :v_who,
           note = LEFT(:P_NOTE, 2000), decided_at = CURRENT_TIMESTAMP()
     WHERE review_id = :P_REVIEW_ID;
    IF (LOWER(:P_VERDICT) = 'disagree') THEN
        -- A human disagreeing with an unattended change costs that change type a rung of autonomy
        CALL SNOWFLAKE_XDR.DETECTIONS.TRUST_LADDER(TO_JSON(OBJECT_CONSTRUCT('demote', :v_type,
             'reason', 'a reviewer disagreed with change ' || :v_change || COALESCE(': ' || :P_NOTE, '')))) INTO :r;
        RETURN OBJECT_CONSTRUCT('ok', TRUE, 'demotion', :r, 'undo', 'autopilot:' || :v_change,
            'message', 'Recorded. ' || :v_type || ' loses a rung of autonomy; undo the change itself from the ledger if it is wrong.');
    END IF;
    RETURN OBJECT_CONSTRUCT('ok', TRUE, 'message', 'Recorded: you agreed with this ' || :v_type || ' change');
END;
$$;

CREATE OR REPLACE TASK SNOWFLAKE_XDR.DETECTIONS.TASK_SAMPLE_AUTONOMY_REVIEWS
    WAREHOUSE = XDR_WH
    SCHEDULE = 'USING CRON 0 6 * * 1 UTC'
    COMMENT = 'Weekly: sample 5 unattended autopilot changes for a human to agree or disagree with'
AS
    CALL SNOWFLAKE_XDR.DETECTIONS.SAMPLE_AUTONOMY_REVIEWS(5);
ALTER TASK SNOWFLAKE_XDR.DETECTIONS.TASK_SAMPLE_AUTONOMY_REVIEWS RESUME;
