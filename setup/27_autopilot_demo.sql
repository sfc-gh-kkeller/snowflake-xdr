-- ============================================================================
-- Snowflake XDR - 27: Detection Autopilot demo state
-- ============================================================================
-- Resets the autopilot to a clean demo state and lets it do real work, so
-- the Detection Autopilot view opens with a genuine change history:
--   cycle 1: drafts rules for uncovered techniques (shadow) and proposes
--            disabling a noisy built-in rule (needs a human)
--   cycle 2: (promotion wait temporarily 0h) promotes shadow rules that
--            pass their backtest, rewrites ones that miss labelled attacks,
--            drafts more rules
-- Afterwards the default 24h shadow period is restored, so new drafts wait.
-- Only autopilot-owned objects are touched; human and demo-seed rules stay.
-- Re-run any time to reset the autopilot demo.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

DELETE FROM SNOWFLAKE_XDR.DETECTIONS.SHADOW_FINDINGS
 WHERE rule_id IN (SELECT rule_id FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
                   WHERE managed_by IN ('autopilot', 'autopilot_candidate'));
DELETE FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
 WHERE rule_id IN (SELECT rule_id FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
                   WHERE managed_by IN ('autopilot', 'autopilot_candidate'));
DELETE FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_HISTORY
 WHERE rule_id IN (SELECT rule_id FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
                   WHERE managed_by IN ('autopilot', 'autopilot_candidate'));
DELETE FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE managed_by IN ('autopilot', 'autopilot_candidate');
-- Undo FP-control changes from earlier runs (suppressions, allowlists, re-checks)
DELETE FROM SNOWFLAKE_XDR.DETECTIONS.SUPPRESSION_RULES
 WHERE suppression_id IN (SELECT evidence:suppression_id::VARCHAR FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES
                          WHERE change_type = 'suppress_entity');
DELETE FROM SNOWFLAKE_XDR.REFERENCE.INTEL_WARNINGLIST
 WHERE list_name = 'local' AND value IN (SELECT LOWER(evidence:ioc_value::VARCHAR) FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES
                                         WHERE change_type = 'intel_allowlist');
UPDATE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS SET status = 'active', status_reason = NULL WHERE status = 'allowlisted';
DELETE FROM SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE;
DELETE FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES;
-- Built-in rules the autopilot may have been approved to disable
UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES SET enabled = TRUE WHERE rule_id = 'DET-021';

UPDATE SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_POLICY p SET
    mode = d.mode, max_per_cycle = d.max_per_cycle, promote_after_hours = d.promote_after_hours,
    min_recall = d.min_recall, max_benign_matches = d.max_benign_matches,
    updated_by = 'demo_reset', updated_at = CURRENT_TIMESTAMP()
FROM (SELECT * FROM VALUES
    ('new_rule',       'shadow_then_promote', 2, 24, 0.5, 10),
    ('fix_broken',     'shadow_then_promote', 3, 6,  0.5, 25),
    ('tune_filter',    'shadow_then_promote', 2, 24, 0.5, 25),
    ('tune_threshold', 'auto_live',           3, 0,  0.0, 0),
    ('disable_noisy',  'propose_only',        3, 0,  0.0, 0),
    ('retire_silent',  'propose_only',        3, 0,  0.0, 0),
    ('new_parser',     'propose_only',        2, 24, 0.0, 0),
    ('auto_suppress',  'auto_live',           0, 0,  0.0, 0),
    ('suppress_entity','propose_only',        5, 0,  0.0, 0),
    ('intel_allowlist','propose_only',        5, 0,  0.0, 0),
    ('recheck_verdicts','propose_only',       3, 0,  0.0, 0)
    AS v(change_type, mode, max_per_cycle, promote_after_hours, min_recall, max_benign_matches)) d
WHERE p.change_type = d.change_type;

-- False-positive story: analysts dismissed DET-021 on the vulnerability scanner AND on the
-- real C2 beacon (10.1.1.10). Re-apply those verdicts, retrain, score: the confidence model
-- re-opens the machine-suppressed C2 findings (DET-016 corroborates them) and keeps the
-- scanner suppressed; the autopilot then proposes a verdict re-check, a suppression and an
-- allowlist for a human to decide.
UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS SET disposition = NULL, disposition_source = NULL, verdict_by = NULL,
       status = 'new', triage_notes = NULL
 WHERE rule_id = 'DET-021';
CALL SNOWFLAKE_XDR.REFERENCE.SEED_ANALYST_DISPOSITIONS();
CALL SNOWFLAKE_XDR.REFERENCE.SCORE_IOCS();
CALL SNOWFLAKE_XDR.DETECTIONS.TRAIN_FP_MODEL();
CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CONFIDENCE_PIPELINE();

CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CYCLE();

UPDATE SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_POLICY SET promote_after_hours = 0 WHERE change_type = 'new_rule';
CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CYCLE();
UPDATE SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_POLICY SET promote_after_hours = 24, updated_by = 'demo_reset'
 WHERE change_type = 'new_rule';

-- Run the promoted rules once so their findings show up in Triage
CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULES();
CALL SNOWFLAKE_XDR.DETECTIONS.DEDUPE_FINDINGS();
CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CONFIDENCE_PIPELINE();

SELECT status, COUNT(*) AS changes FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES GROUP BY status ORDER BY status;
