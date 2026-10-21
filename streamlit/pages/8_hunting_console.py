import streamlit as st
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Hunting Console", layout="wide")
show_deprecation_banner("hunting_console")
st.title("AI Threat Hunting Console")

conn = st.connection("snowflake")

st.markdown("""
The AI Hunting Agent uses Snowflake Cortex to proactively search for threats
using MITRE ATT&CK and OWASP knowledge. Unlike rule-based detections, it
reasons about log patterns heuristically -- finding what static rules cannot.
""")

col1, col2 = st.columns(2)
with col1:
    focus_area = st.selectbox("Hunting Focus", [
        'general', 'lateral_movement', 'exfiltration', 'persistence', 'initial_access'
    ])
with col2:
    lookback = st.slider("Lookback (hours)", 1, 48, 24)

if st.button("Launch Hunting Agent", type="primary"):
    with st.spinner("AI Hunting Agent analyzing logs..."):
        result = conn.query(f"CALL SNOWFLAKE_XDR.DETECTIONS.AI_HUNTING_AGENT('{focus_area}', {lookback})")
        st.success("Hunting complete!")
        if result is not None and not result.empty:
            st.json(result.iloc[0][0])

st.markdown("---")
st.subheader("Recent Hunting Findings")
hunt_findings = conn.query("""
    SELECT finding_id, detection_time, severity, confidence,
           mitre_technique_id, LEFT(description, 300) as description,
           evidence:focus::VARCHAR as focus_area
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE detection_source = 'ai_hunting_agent'
    ORDER BY detection_time DESC
    LIMIT 20
""")
if not hunt_findings.empty:
    st.dataframe(hunt_findings, use_container_width=True)
else:
    st.info("No hunting findings yet. Run the agent above to generate results.")

# Also offer the detection agent
st.markdown("---")
st.subheader("AI Detection Agent (Targeted Re-analysis)")
st.markdown("Re-analyze logs for a specific entity to find what rule-based detections missed.")

target = st.text_input("Target Entity (user, IP, or hostname)", placeholder="e.g., jsmith or 185.220.101.42")
det_lookback = st.slider("Detection Lookback (hours)", 1, 24, 4, key="det_lb")

if st.button("Run Detection Agent"):
    if target:
        with st.spinner(f"AI Detection Agent analyzing logs for {target}..."):
            result = conn.query(f"CALL SNOWFLAKE_XDR.DETECTIONS.AI_DETECTION_AGENT('{target}', {det_lookback})")
            st.success("Analysis complete!")
            if result is not None and not result.empty:
                st.json(result.iloc[0][0])
    else:
        st.warning("Please enter a target entity.")
