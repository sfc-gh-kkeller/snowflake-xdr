import streamlit as st
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Snowflake XDR", page_icon="🛡️", layout="wide")
show_deprecation_banner("app")

st.sidebar.title("Snowflake XDR")
st.sidebar.markdown("---")
st.sidebar.markdown("**Security Analytics Platform**")
st.sidebar.markdown("Native Snowflake XDR/SIEM with AI-powered detection engineering, response automation, and threat hunting.")
st.sidebar.markdown("---")

st.title("Snowflake XDR - Security Operations Center")
st.markdown("""
Welcome to the Snowflake-native XDR/SIEM platform. This system provides:

- **Detection Engine**: 30 built-in rules mapped to MITRE ATT&CK plus custom rules authored in SQL, Python, or JavaScript
- **AI Detection Engineering**: Cortex AI generates and triages detection rules from natural language
- **Incident Correlation**: Automatic grouping of related findings with kill chain tracking
- **Response Automation**: Playbooks that trigger email, webhook, and API actions on findings
- **Investigation**: Entity search across all telemetry with AI investigation summaries
- **Splunk Interoperability**: CIM-compatible schema for seamless DB Connect integration

Use the sidebar to navigate between views.
""")

# Quick stats
conn = st.connection("snowflake")

col1, col2, col3, col4 = st.columns(4)

with col1:
    result = conn.query("SELECT COUNT(*) as cnt FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE status = 'open'")
    st.metric("Open Incidents", result.iloc[0]['CNT'])

with col2:
    result = conn.query("SELECT COUNT(*) as cnt FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE detection_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())")
    st.metric("Findings (24h)", result.iloc[0]['CNT'])

with col3:
    result = conn.query("SELECT COUNT(*) as cnt FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE status = 'new'")
    st.metric("Untriaged", result.iloc[0]['CNT'])

with col4:
    result = conn.query("SELECT COUNT(*) as cnt FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES WHERE enabled = TRUE")
    st.metric("Active Rules", result.iloc[0]['CNT'])
