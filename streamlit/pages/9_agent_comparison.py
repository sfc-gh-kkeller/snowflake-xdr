import streamlit as st
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Agent Comparison", layout="wide")
show_deprecation_banner("agent_comparison")
st.title("Agent vs. Rule Comparison")

conn = st.connection("snowflake")

st.markdown("""
This view compares findings from **rule-based detections** (stored procedures) against
**AI-based detections** (Cortex agents) for the same time window. It demonstrates
where AI adds value beyond static pattern matching.
""")

# Time window selection
hours = st.slider("Comparison Window (hours back)", 1, 168, 24)

col1, col2 = st.columns(2)

with col1:
    st.subheader("Rule-Based Findings")
    rule_findings = conn.query(f"""
        SELECT rule_id, severity, confidence, category, mitre_technique_id,
               LEFT(description, 150) as description, detection_time
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE detection_source = 'stored_procedure'
          AND detection_time > DATEADD('hour', -{hours}, CURRENT_TIMESTAMP())
        ORDER BY risk_score DESC
        LIMIT 25
    """)
    if not rule_findings.empty:
        st.metric("Count", len(rule_findings))
        st.dataframe(rule_findings, use_container_width=True)
    else:
        st.info("No rule-based findings in this window.")

with col2:
    st.subheader("AI Agent Findings")
    ai_findings = conn.query(f"""
        SELECT rule_id, severity, confidence, category, mitre_technique_id,
               LEFT(description, 150) as description, detection_time, detection_source
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE detection_source IN ('ai_detection_agent', 'ai_hunting_agent')
          AND detection_time > DATEADD('hour', -{hours}, CURRENT_TIMESTAMP())
        ORDER BY risk_score DESC
        LIMIT 25
    """)
    if not ai_findings.empty:
        st.metric("Count", len(ai_findings))
        st.dataframe(ai_findings, use_container_width=True)
    else:
        st.info("No AI findings in this window. Run the agents from the Hunting Console.")

# Gap analysis
st.markdown("---")
st.subheader("Coverage Gap Analysis")
st.markdown("Techniques detected **only** by AI (not caught by rules):")

ai_only = conn.query(f"""
    SELECT DISTINCT mitre_technique_id, LEFT(description, 200) as finding, detection_source, confidence
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE detection_source IN ('ai_detection_agent', 'ai_hunting_agent')
      AND detection_time > DATEADD('hour', -{hours}, CURRENT_TIMESTAMP())
      AND mitre_technique_id NOT IN (
          SELECT DISTINCT mitre_technique_id
          FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
          WHERE detection_source = 'stored_procedure'
            AND detection_time > DATEADD('hour', -{hours}, CURRENT_TIMESTAMP())
            AND mitre_technique_id IS NOT NULL
      )
      AND mitre_technique_id IS NOT NULL
""")
if not ai_only.empty:
    st.dataframe(ai_only, use_container_width=True)
else:
    st.success("No gaps detected - rules and AI are covering the same techniques.")
