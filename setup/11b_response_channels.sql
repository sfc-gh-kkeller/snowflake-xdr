-- ============================================================================
-- Snowflake XDR - 11b: Response channels (integrations, secret, network rule)
-- ============================================================================
-- Account-level and RESPONSE-schema objects used by response automation:
--   XDR_EMAIL                   email notification integration
--   RESPONSE.SLACK_WEBHOOK      secret holding the Slack webhook path token
--   XDR_WEBHOOK                 Slack webhook notification integration
--   RESPONSE.XDR_API_RULE       egress network rule for the API UDF
--   XDR_API_EAI                 external access integration for CALL_API
--
-- Everything is IF NOT EXISTS, so re-runs never touch a configured secret.
-- The Slack token is never stored in this repo. On a fresh build the runner
-- substitutes the SLACK_WEBHOOK_TOKEN environment variable for the
-- __SLACK_WEBHOOK_TOKEN__ placeholder; if unset, a placeholder value is used
-- and webhook actions log an error until you run:
--   ALTER SECRET SNOWFLAKE_XDR.RESPONSE.SLACK_WEBHOOK SET SECRET_STRING = '<token>';
-- ============================================================================

USE ROLE ACCOUNTADMIN;

CREATE NOTIFICATION INTEGRATION IF NOT EXISTS XDR_EMAIL
    TYPE = EMAIL
    ENABLED = TRUE
    COMMENT = 'XDR response automation - email channel';

-- Path token only, e.g. T000/B000/XXXX; the integration supplies the host
CREATE SECRET IF NOT EXISTS SNOWFLAKE_XDR.RESPONSE.SLACK_WEBHOOK
    TYPE = GENERIC_STRING
    SECRET_STRING = '__SLACK_WEBHOOK_TOKEN__'
    COMMENT = 'Slack incoming-webhook path token for XDR_WEBHOOK';

CREATE NOTIFICATION INTEGRATION IF NOT EXISTS XDR_WEBHOOK
    TYPE = WEBHOOK
    ENABLED = TRUE
    WEBHOOK_URL = 'https://hooks.slack.com/services/SNOWFLAKE_WEBHOOK_SECRET'
    WEBHOOK_SECRET = SNOWFLAKE_XDR.RESPONSE.SLACK_WEBHOOK
    WEBHOOK_HEADERS = ('Content-Type' = 'application/json')
    COMMENT = 'XDR response automation - Slack webhook channel';

-- Broad egress for the demo's generic API action; narrow this per customer
CREATE NETWORK RULE IF NOT EXISTS SNOWFLAKE_XDR.RESPONSE.XDR_API_RULE
    MODE = EGRESS
    TYPE = HOST_PORT
    VALUE_LIST = ('0.0.0.0:443', '0.0.0.0:80');

CREATE EXTERNAL ACCESS INTEGRATION IF NOT EXISTS XDR_API_EAI
    ALLOWED_NETWORK_RULES = (SNOWFLAKE_XDR.RESPONSE.XDR_API_RULE)
    ENABLED = TRUE
    COMMENT = 'XDR response automation - outbound API calls (CALL_API UDF)';
