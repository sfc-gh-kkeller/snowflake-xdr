-- ============================================================================
-- Snowflake XDR/SIEM - Scheduled Tasks
-- ============================================================================
-- Automates detection runs and incident correlation on a schedule.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;

-- Run all detections every 5 minutes
CREATE OR REPLACE TASK SNOWFLAKE_XDR.DETECTIONS.TASK_RUN_DETECTIONS
    WAREHOUSE = XDR_WH
    SCHEDULE = '5 MINUTE'
    COMMENT = 'Runs all detection procedures every 5 minutes'
AS
    CALL SNOWFLAKE_XDR.DETECTIONS.RUN_ALL_DETECTIONS();

-- Run incident correlation every 15 minutes
CREATE OR REPLACE TASK SNOWFLAKE_XDR.INCIDENTS.TASK_CORRELATE_INCIDENTS
    WAREHOUSE = XDR_WH
    SCHEDULE = '15 MINUTE'
    COMMENT = 'Correlates findings into incidents every 15 minutes'
AS
    CALL SNOWFLAKE_XDR.INCIDENTS.CORRELATE_INCIDENTS();

-- Run AI triage agent every 30 minutes on new findings
CREATE OR REPLACE TASK SNOWFLAKE_XDR.DETECTIONS.TASK_AI_TRIAGE
    WAREHOUSE = XDR_WH
    SCHEDULE = '30 MINUTE'
    COMMENT = 'AI triage agent evaluates new findings for false positive probability'
AS
    CALL SNOWFLAKE_XDR.DETECTIONS.AI_TRIAGE_AGENT(10);

-- Run AI hunting agent every 4 hours
CREATE OR REPLACE TASK SNOWFLAKE_XDR.DETECTIONS.TASK_AI_HUNTING
    WAREHOUSE = XDR_WH
    SCHEDULE = '240 MINUTE'
    COMMENT = 'AI hunting agent proactively searches for threats'
AS
    CALL SNOWFLAKE_XDR.DETECTIONS.AI_HUNTING_AGENT('general', 4);

-- NOTE: Tasks are created in SUSPENDED state by default.
-- To activate the pipeline, run:
--   ALTER TASK SNOWFLAKE_XDR.DETECTIONS.TASK_RUN_DETECTIONS RESUME;
--   ALTER TASK SNOWFLAKE_XDR.INCIDENTS.TASK_CORRELATE_INCIDENTS RESUME;
--   ALTER TASK SNOWFLAKE_XDR.DETECTIONS.TASK_AI_TRIAGE RESUME;
--   ALTER TASK SNOWFLAKE_XDR.DETECTIONS.TASK_AI_HUNTING RESUME;
