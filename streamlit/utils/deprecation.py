"""Deprecation banner for the legacy XDR_SOC Streamlit app.

The SOC experience moved to the XDR Console (a Snowflake App Runtime app).
Every page calls show_deprecation_banner() right after st.set_page_config().
The console URL is read from REFERENCE.PLATFORM_SETTINGS, which
scripts/deploy_demo.sh updates after each console deploy.
"""

import streamlit as st

# Where the console lives when no deployed URL has been recorded yet
_FALLBACK_HINT = "Snowsight > Projects > Apps > XDR_CONSOLE (SNOWFLAKE_XDR.DASHBOARDS)"

# Console route that replaces each legacy page
CONSOLE_ROUTES = {
    "app": "/",
    "soc_overview": "/",
    "threat_map": "/attack-graph",
    "triage_queue": "/triage",
    "alert_center": "/response",
    "case_management": "/triage",
    "entity_investigation": "/entity",
    "incident_view": "/investigations",
    "hunting_console": "/hunt",
    "agent_comparison": "/hunt",
    "detection_library": "/detections",
    "mitre_coverage": "/detections",
    "rule_editor": "/rules",
    "response_automation": "/response",
    "ioc_management": "/rules",
    "security_posture": "/posture",
    "health_monitoring": "/detections",
    "attack_graph": "/attack-graph",
    "live_tail": "/live",
    "ask_xdr": "/ask",
}


@st.cache_data(ttl=600, show_spinner=False)
def _console_url():
    try:
        conn = st.connection("snowflake")
        df = conn.query(
            "SELECT setting_value FROM SNOWFLAKE_XDR.REFERENCE.PLATFORM_SETTINGS "
            "WHERE setting_key = 'xdr_console_url'",
            ttl=600,
        )
        if not df.empty and df.iloc[0, 0]:
            return str(df.iloc[0, 0]).rstrip("/")
    except Exception:
        pass
    return None


def show_deprecation_banner(page="app"):
    """Render the 'this app is deprecated' notice with a link to the replacement view."""
    url = _console_url()
    route = CONSOLE_ROUTES.get(page, "/")
    if url:
        link = f"[Open this view in the XDR Console]({url}{route})"
    else:
        link = f"Find it in {_FALLBACK_HINT}"
    st.warning(
        "**Deprecated:** this Streamlit app is no longer maintained. "
        "The SOC experience moved to the **XDR Console** (Snowflake App Runtime) — "
        f"same data and procedures, faster UI. {link}",
        icon="⚠️",
    )
