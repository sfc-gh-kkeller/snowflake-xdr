-- ============================================================================
-- Snowflake XDR - 00: CTF Demo Dataset (Splunk federated-query demo data)
-- ============================================================================
-- Tables, file format, and stage for the CTF dataset (115k rows of web access
-- logs, assets, vulnerabilities, findings). The compressed CSVs live in
-- data/ctf/ and are uploaded by scripts/deploy_demo.sh with
-- `snow stage copy`; this script then loads them with COPY INTO.
--
-- Idempotent: tables are CREATE IF NOT EXISTS, and COPY INTO skips files it
-- has already loaded (load metadata). The runner also skips the whole load
-- when CTF.PUBLIC.ACCESS_LOGS is already populated.
-- ============================================================================

CREATE DATABASE IF NOT EXISTS CTF;
CREATE SCHEMA IF NOT EXISTS CTF.PUBLIC;
USE SCHEMA CTF.PUBLIC;
USE WAREHOUSE XDR_WH;

CREATE TABLE IF NOT EXISTS ACCESS_LOGS (
    TIMESTAMP       TIMESTAMP_NTZ,
    IP_ADDRESS      VARCHAR(45),
    REQUEST_METHOD  VARCHAR(10),
    REQUEST_PATH    VARCHAR(2024),
    STATUS_CODE     NUMBER(38,0),
    BYTES_SENT      NUMBER(38,0),
    BACKEND_IP      VARCHAR(45)
);

CREATE TABLE IF NOT EXISTS ASSET_INVENTORY (
    ID              VARCHAR,
    OS              VARCHAR,
    MEMORY_GB       NUMBER(38,0),
    CPU_CORES       NUMBER(38,0),
    DISK_GB         NUMBER(38,0),
    LOCATION        VARCHAR,
    OWNER           VARCHAR,
    PROVIDER        VARCHAR,
    STATUS          VARCHAR,
    LAST_UPDATED    TIMESTAMP_NTZ,
    TAGS            VARIANT
);

CREATE TABLE IF NOT EXISTS VULNERABILITIES (
    CREATED_AT           TIMESTAMP_NTZ,
    TITLE                VARCHAR,
    SEVERITY             NUMBER(38,0),
    STATUS               VARCHAR(10),
    RESOURCE_TYPE        VARCHAR(20),
    RESOURCE_EXTERNAL_ID VARCHAR(255),
    SUBSCRIPTION_ID      VARCHAR(255),
    PROJECT_IDS          VARCHAR(255),
    RESOLVED_TIME        TIMESTAMP_NTZ,
    CONTROL_ID           VARCHAR(255),
    RESOURCE_HOSTNAME    VARCHAR(255),
    RESOURCE_IP          VARCHAR(255),
    RESOURCE_REGION      VARCHAR(20),
    RESOURCE_STATUS      VARCHAR(20),
    RESOURCE_PLATFORM    VARCHAR(20),
    RESOURCE_OS          VARCHAR(50),
    ISSUE_ID             VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS SECURITY_FINDINGS (
    FINDING_ID      NUMBER(38,0) NOT NULL,
    DETECTED_AT     TIMESTAMP_NTZ,
    FINDING_TYPE    VARCHAR(100),
    SEVERITY        VARCHAR(20),
    STATUS          VARCHAR(30),
    STATUS_COMMENT  VARCHAR(2000),
    TIMESTAMP       TIMESTAMP_NTZ,
    IP_ADDRESS      VARCHAR(45),
    REQUEST_PATH    VARCHAR(2048),
    REQUEST_METHOD  VARCHAR(10),
    STATUS_CODE     NUMBER(38,0),
    BYTES_SENT      NUMBER(38,0),
    BACKEND_IP      VARCHAR(45),
    DESCRIPTION     VARCHAR(2000),
    LAST_UPDATED_AT TIMESTAMP_NTZ,
    LAST_UPDATED_BY VARCHAR(256),
    EMAIL_SENT      BOOLEAN,
    EMAIL_SENT_AT   TIMESTAMP_NTZ
);

CREATE FILE FORMAT IF NOT EXISTS CTF_CSV_FORMAT
    TYPE = 'CSV'
    COMPRESSION = 'GZIP'
    FIELD_DELIMITER = ','
    SKIP_HEADER = 1
    FIELD_OPTIONALLY_ENCLOSED_BY = '"'
    NULL_IF = ('', 'NULL', 'null', 'None', '\\N')
    TRIM_SPACE = TRUE
    ERROR_ON_COLUMN_COUNT_MISMATCH = FALSE;

CREATE STAGE IF NOT EXISTS CTF_UPLOAD_STAGE
    FILE_FORMAT = CTF_CSV_FORMAT;
