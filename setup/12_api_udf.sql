-- ============================================================================
-- Snowflake XDR - External API call function
-- ============================================================================
-- Generic HTTP POST to an external API endpoint (e.g. a SOAR platform,
-- ticketing system, or messaging webhook). Backed by the XDR_API_EAI
-- external access integration.
-- ============================================================================

CREATE OR REPLACE FUNCTION SNOWFLAKE_XDR.RESPONSE.CALL_API(
    p_url VARCHAR,
    p_payload VARCHAR,
    p_auth_header VARCHAR
)
RETURNS VARCHAR
LANGUAGE PYTHON
RUNTIME_VERSION = '3.10'
HANDLER = 'call_api'
EXTERNAL_ACCESS_INTEGRATIONS = (XDR_API_EAI)
PACKAGES = ('snowflake-snowpark-python')
AS
$$
import _snowflake
import requests

def call_api(p_url, p_payload, p_auth_header):
    headers = {'Content-Type': 'application/json'}
    if p_auth_header:
        headers['Authorization'] = p_auth_header
    try:
        resp = requests.post(p_url, data=p_payload, headers=headers, timeout=10)
        return f'status={resp.status_code} body={resp.text[:500]}'
    except Exception as e:
        return f'error={type(e).__name__}: {str(e)[:400]}'
$$;
