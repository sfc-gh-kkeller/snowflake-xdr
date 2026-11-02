-- ============================================================================
-- Snowflake XDR - 31: OTLP receiver on Snowpark Container Services
-- ============================================================================
-- Infrastructure for otel-receiver/ (deployed by scripts/deploy_otel_receiver.sh):
--   role XDR_INGEST_ROLE  least-privilege owner of the service; can only call
--                         INGEST_OTLP_LOGS (owner's rights) and use XDR_WH
--   XDR_OTEL_POOL         compute pool (CPU_X64_XS, 1-2 nodes)
--   XDR_IMAGES            image repository
--   XDR_OTLP_RECEIVER     the service, public endpoint "otlp" on port 4318
--
-- Callers authenticate at the SPCS ingress with a Snowflake Programmatic Access
-- Token. Grant XDR_OTLP_SENDER to the (service) user that a Collector uses.
-- ============================================================================

USE ROLE ACCOUNTADMIN;

CREATE ROLE IF NOT EXISTS XDR_INGEST_ROLE COMMENT = 'Owns the XDR OTLP receiver service';
CREATE ROLE IF NOT EXISTS XDR_OTLP_SENDER COMMENT = 'May send OTLP data to the XDR receiver endpoint';
GRANT ROLE XDR_INGEST_ROLE TO ROLE ACCOUNTADMIN;
GRANT ROLE XDR_OTLP_SENDER TO ROLE ACCOUNTADMIN;

CREATE COMPUTE POOL IF NOT EXISTS XDR_OTEL_POOL
    MIN_NODES = 1 MAX_NODES = 2
    INSTANCE_FAMILY = CPU_X64_XS
    AUTO_RESUME = TRUE
    AUTO_SUSPEND_SECS = 3600
    COMMENT = 'XDR OTLP receiver';

CREATE IMAGE REPOSITORY IF NOT EXISTS SNOWFLAKE_XDR.RAW_LOGS.XDR_IMAGES;

GRANT USAGE, MONITOR ON COMPUTE POOL XDR_OTEL_POOL TO ROLE XDR_INGEST_ROLE;
GRANT USAGE ON DATABASE SNOWFLAKE_XDR TO ROLE XDR_INGEST_ROLE;
GRANT USAGE ON SCHEMA SNOWFLAKE_XDR.RAW_LOGS TO ROLE XDR_INGEST_ROLE;
GRANT CREATE SERVICE ON SCHEMA SNOWFLAKE_XDR.RAW_LOGS TO ROLE XDR_INGEST_ROLE;
GRANT READ ON IMAGE REPOSITORY SNOWFLAKE_XDR.RAW_LOGS.XDR_IMAGES TO ROLE XDR_INGEST_ROLE;
GRANT USAGE ON WAREHOUSE XDR_WH TO ROLE XDR_INGEST_ROLE;
GRANT BIND SERVICE ENDPOINT ON ACCOUNT TO ROLE XDR_INGEST_ROLE;
-- The only data path: an owner's-rights procedure that writes OTEL_LOGS / OTEL_SOURCES
GRANT USAGE ON PROCEDURE SNOWFLAKE_XDR.RAW_LOGS.INGEST_OTLP_LOGS(VARCHAR, VARCHAR) TO ROLE XDR_INGEST_ROLE;

-- Senders reach the endpoint through the service role (granted by the deploy script once the
-- service exists); the ingress also requires USAGE on the service's database and schema.
GRANT USAGE ON DATABASE SNOWFLAKE_XDR TO ROLE XDR_OTLP_SENDER;
GRANT USAGE ON SCHEMA SNOWFLAKE_XDR.RAW_LOGS TO ROLE XDR_OTLP_SENDER;

-- Senders reach the endpoint through the service role (granted by the deploy script once the
-- service exists); the SPCS ingress also needs USAGE on the service's database and schema.
GRANT USAGE ON DATABASE SNOWFLAKE_XDR TO ROLE XDR_OTLP_SENDER;
GRANT USAGE ON SCHEMA SNOWFLAKE_XDR.RAW_LOGS TO ROLE XDR_OTLP_SENDER;

-- Ticket webhooks (/v1/webhooks/{connection}) go through one owner's-rights procedure as well
GRANT USAGE ON SCHEMA SNOWFLAKE_XDR.INCIDENTS TO ROLE XDR_INGEST_ROLE;
GRANT USAGE ON PROCEDURE SNOWFLAKE_XDR.INCIDENTS.INGEST_TICKET_WEBHOOK(VARCHAR, VARCHAR) TO ROLE XDR_INGEST_ROLE;
