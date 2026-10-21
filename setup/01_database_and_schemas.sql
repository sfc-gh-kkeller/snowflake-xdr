-- ============================================================================
-- Snowflake XDR/SIEM - Database and Schema Setup
-- ============================================================================
-- Creates the core database and schema structure for the security analytics
-- platform. Schema uses Splunk CIM-compatible field naming for seamless
-- integration with Splunk DB Connect during migration/coexistence scenarios.
-- ============================================================================

USE ROLE ACCOUNTADMIN;

CREATE DATABASE IF NOT EXISTS SNOWFLAKE_XDR
    COMMENT = 'Security analytics platform - XDR/SIEM with CIM-compatible schema';

-- Schema for normalized raw log storage (CIM-aligned)
CREATE SCHEMA IF NOT EXISTS SNOWFLAKE_XDR.RAW_LOGS
    COMMENT = 'Normalized security event logs using Splunk CIM field naming';

-- Schema for detection rules and findings
CREATE SCHEMA IF NOT EXISTS SNOWFLAKE_XDR.DETECTIONS
    COMMENT = 'Detection engine: rules catalog, findings, and suppressions';

-- Schema for incident ontology and attack tracking
CREATE SCHEMA IF NOT EXISTS SNOWFLAKE_XDR.INCIDENTS
    COMMENT = 'Incident correlation, entity graph, kill chain tracking';

-- Schema for reference/enrichment data
CREATE SCHEMA IF NOT EXISTS SNOWFLAKE_XDR.REFERENCE
    COMMENT = 'MITRE ATT&CK reference, threat intel IOCs, entity baselines';

-- Schema for response automation (playbooks, notification secrets, API UDF)
CREATE SCHEMA IF NOT EXISTS SNOWFLAKE_XDR.RESPONSE
    COMMENT = 'Response playbooks, action log, notification and API objects';

-- Schema for the UI layer (semantic view, Cortex Agent, apps)
CREATE SCHEMA IF NOT EXISTS SNOWFLAKE_XDR.DASHBOARDS
    COMMENT = 'Semantic view, XDR_ANALYST agent, XDR console and legacy Streamlit app';

-- Warehouse for detection workloads
CREATE WAREHOUSE IF NOT EXISTS XDR_WH
    WAREHOUSE_SIZE = 'XSMALL'
    AUTO_SUSPEND = 60
    AUTO_RESUME = TRUE
    COMMENT = 'Warehouse for XDR detection and agent workloads';
