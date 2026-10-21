-- ============================================================================
-- Snowflake XDR/SIEM - Incident Ontology Tables
-- ============================================================================
-- Tables for correlating findings into incidents, tracking kill chain
-- progression, entity relationships, and attacker timelines.
-- ============================================================================

USE DATABASE SNOWFLAKE_XDR;
USE SCHEMA INCIDENTS;

-- ---------------------------------------------------------------------------
-- Incidents (correlated groups of findings)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS INCIDENTS (
    incident_id     VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    title           VARCHAR(500),
    description     VARCHAR(4000),
    -- Scoring
    severity        NUMBER(1),          -- max(child findings) + chain bonus
    priority        VARCHAR(10),        -- P1-P5
    risk_score      FLOAT,
    -- Kill chain state
    kill_chain_stage VARCHAR(50),       -- highest observed stage
    kill_chain_stages_observed ARRAY,   -- all stages seen
    tactics_observed ARRAY,             -- all MITRE tactics seen
    -- Timing
    first_seen      TIMESTAMP_LTZ,
    last_seen       TIMESTAMP_LTZ,
    duration_hours  FLOAT,
    -- Entities
    primary_entity  VARCHAR(255),       -- main attacker/compromised entity
    entity_type     VARCHAR(50),        -- user, host, ip
    affected_entities VARIANT,          -- JSON array
    affected_host_count NUMBER,
    affected_user_count NUMBER,
    -- Status
    status          VARCHAR(20) DEFAULT 'open', -- open, investigating, contained, closed
    assignee        VARCHAR(100),
    resolution      VARCHAR(50),        -- true_incident, false_alarm, test, duplicate
    resolution_notes VARCHAR(4000),
    -- Metadata
    created_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    updated_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    closed_at       TIMESTAMP_LTZ
);

-- ---------------------------------------------------------------------------
-- Incident-Finding Junction (many-to-many)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS INCIDENT_FINDINGS (
    incident_id     VARCHAR NOT NULL,
    finding_id      VARCHAR NOT NULL,
    added_at        TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP(),
    added_by        VARCHAR(50) DEFAULT 'correlation_engine',
    PRIMARY KEY (incident_id, finding_id)
);

-- ---------------------------------------------------------------------------
-- Entity Graph (relationships between entities in an incident)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ENTITY_GRAPH (
    edge_id         VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    incident_id     VARCHAR NOT NULL,
    -- Source entity
    src_entity_type VARCHAR(50),        -- user, host, ip, domain, process
    src_entity_value VARCHAR(500),
    -- Destination entity
    dst_entity_type VARCHAR(50),
    dst_entity_value VARCHAR(500),
    -- Relationship
    relationship_type VARCHAR(50),      -- authenticated_to, lateral_moved_to, spawned_process,
                                        -- exfiltrated_from, communicated_with, escalated_on
    -- Timing
    first_seen      TIMESTAMP_LTZ,
    last_seen       TIMESTAMP_LTZ,
    event_count     NUMBER DEFAULT 1,
    -- Evidence
    finding_ids     ARRAY,              -- findings that prove this edge
    mitre_technique VARCHAR(20),        -- technique that produced this edge
    -- Metadata
    created_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Kill Chain Progression (per-incident tactic advancement)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS KILL_CHAIN_PROGRESSION (
    progression_id  VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    incident_id     VARCHAR NOT NULL,
    -- Stage info
    stage_order     NUMBER,             -- 1-14 (MITRE tactic order)
    tactic_id       VARCHAR(10),
    tactic_name     VARCHAR(50),
    -- Evidence
    first_finding_id VARCHAR,
    finding_count   NUMBER,
    first_observed  TIMESTAMP_LTZ,
    last_observed   TIMESTAMP_LTZ,
    -- Prediction
    predicted_next_stage VARCHAR(50),
    confidence      FLOAT,
    -- Metadata
    created_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ---------------------------------------------------------------------------
-- Attacker Timeline (chronological actions by a threat actor)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ATTACKER_TIMELINE (
    timeline_id     VARCHAR DEFAULT UUID_STRING() PRIMARY KEY,
    incident_id     VARCHAR NOT NULL,
    -- Event
    event_time      TIMESTAMP_LTZ NOT NULL,
    action_summary  VARCHAR(1000),      -- human-readable description
    -- Classification
    tactic_id       VARCHAR(10),
    technique_id    VARCHAR(20),
    -- Actor/Target
    actor_entity    VARCHAR(500),       -- who performed the action
    actor_type      VARCHAR(50),
    target_entity   VARCHAR(500),       -- what was targeted
    target_type     VARCHAR(50),
    -- Evidence linkage
    finding_id      VARCHAR,
    source_table    VARCHAR(100),       -- which RAW_LOGS table
    source_event_id VARCHAR,
    -- Metadata
    created_at      TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP()
);
