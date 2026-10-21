-- ============================================================================
-- Snowflake XDR/SIEM - Detection Tables
-- ============================================================================
-- Detection rule catalog, fired findings, and suppression/tuning entries.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE SCHEMA DETECTIONS;

-- ---------------------------------------------------------------------------
-- Detection Rule Catalog
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS DETECTION_RULES (
    rule_id         VARCHAR PRIMARY KEY,
    rule_name       VARCHAR(500) NOT NULL,
    description     VARCHAR(4000),
    -- Classification
    category        VARCHAR(50),        -- endpoint, network, cloud, identity, application
    detection_type  VARCHAR(20),        -- ttp, anomaly, hunting, correlation
    severity        NUMBER(1) NOT NULL, -- 1=info, 2=low, 3=medium, 4=high, 5=critical
    -- MITRE mapping
    mitre_tactic_id VARCHAR(10),        -- TA0001-TA0014
    mitre_tactic    VARCHAR(50),
    mitre_technique_id VARCHAR(20),     -- T1110, T1059.001, etc.
    mitre_technique VARCHAR(200),
    -- Operational
    enabled         BOOLEAN DEFAULT TRUE,
    schedule_cron   VARCHAR(50),        -- cron expression for task scheduling
    lookback_minutes NUMBER DEFAULT 60, -- how far back each run looks
    data_sources    ARRAY,              -- which RAW_LOGS tables to query
    -- Splunk reference
    splunk_analytic_story VARCHAR(500), -- mapped Splunk analytic story
    splunk_detection_name VARCHAR(500), -- equivalent ESCU detection
    -- Metadata
    created_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    author          VARCHAR(100) DEFAULT 'XDR Platform'
);

-- ---------------------------------------------------------------------------
-- Detection Findings (fired alerts)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS DETECTION_FINDINGS (
    finding_id      VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    rule_id         VARCHAR NOT NULL,
    -- Timing
    detection_time  TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    event_time      TIMESTAMP_LTZ,      -- when the suspicious activity occurred
    -- Scoring
    severity        NUMBER(1),          -- inherited from rule, can be elevated
    confidence      NUMBER(3),          -- 0-100
    risk_score      NUMBER(5,2),        -- severity * confidence / 20
    -- Context
    mitre_tactic_id VARCHAR(10),
    mitre_technique_id VARCHAR(20),
    category        VARCHAR(50),
    -- Affected entities
    src             VARCHAR(255),
    dest            VARCHAR(255),
    user_name       VARCHAR(255),
    affected_entities VARIANT,          -- JSON array of all entities
    -- Evidence
    evidence        VARIANT,            -- JSON with matched events/fields
    evidence_count  NUMBER,             -- number of corroborating events
    description     VARCHAR(4000),      -- human-readable finding summary
    -- Triage
    status          VARCHAR(20) DEFAULT 'new',  -- new, investigating, confirmed, dismissed
    disposition     VARCHAR(20),        -- true_positive, false_positive, benign
    assigned_to     VARCHAR(100),
    triage_notes    VARCHAR(4000),
    triaged_at      TIMESTAMP_LTZ,
    -- AI enrichment
    ai_fp_probability FLOAT,            -- triage agent score (0-1)
    ai_explanation  VARCHAR(4000),      -- AI triage reasoning
    -- Source tracking
    detection_source VARCHAR(50) DEFAULT 'stored_procedure', -- stored_procedure, ai_detection_agent, ai_hunting_agent
    -- Incident linkage
    incident_id     VARCHAR,
    -- Metadata
    created_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Detection Suppressions (tuning / whitelisting)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS DETECTION_SUPPRESSIONS (
    suppression_id  VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    rule_id         VARCHAR NOT NULL,
    -- Matching criteria (any non-null field must match to suppress)
    match_src       VARCHAR(255),
    match_dest      VARCHAR(255),
    match_user      VARCHAR(255),
    match_field     VARCHAR(100),       -- arbitrary field name
    match_value     VARCHAR(500),       -- value to suppress on
    match_pattern   VARCHAR(500),       -- regex pattern
    -- Lifecycle
    reason          VARCHAR(1000),
    created_by      VARCHAR(100),
    created_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    expires_at      TIMESTAMP_LTZ,      -- NULL = permanent
    enabled         BOOLEAN DEFAULT TRUE
);
