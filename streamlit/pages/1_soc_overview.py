import streamlit as st
import pandas as pd
import json
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="SOC Overview", layout="wide")
show_deprecation_banner("soc_overview")
st.title("SOC Overview")

conn = st.connection("snowflake")

# AI Daily Briefing — the first thing an analyst reads each morning
briefing_holder = st.container()
with briefing_holder:
    bcol1, bcol2 = st.columns([4, 1])
    with bcol2:
        generate = st.button("AI Daily Briefing", type="primary")
    with bcol1:
        st.subheader("Analyst Daily Briefing")
        st.caption("Cortex AI summary of live platform data — the morning read")
    if generate:
        with st.spinner("Cortex AI is writing today's briefing..."):
            try:
                r = conn.query("CALL SNOWFLAKE_XDR.DETECTIONS.AI_DAILY_BRIEFING()", ttl=0)
                briefing = json.loads(r.iloc[0][0])["briefing"]
                st.markdown(briefing)
            except Exception as e:
                st.error(f"Briefing generation failed: {e}")
    else:
        st.info("Click the button to generate the analyst briefing from live data.")

st.markdown("---")

# KPI Row
col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    r = conn.query("SELECT COUNT(*) cnt FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE status = 'open'")
    st.metric("Open Incidents", r.iloc[0]['CNT'])
with col2:
    r = conn.query("SELECT COUNT(*) cnt FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE detection_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())")
    st.metric("Findings (24h)", r.iloc[0]['CNT'])
with col3:
    r = conn.query("SELECT COALESCE(AVG(DATEDIFF('minute', created_at, closed_at)),0) avg_min FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE closed_at IS NOT NULL")
    st.metric("Avg MTTR (min)", round(r.iloc[0]['AVG_MIN'], 1))
with col4:
    r = conn.query("SELECT COUNT(*) cnt FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE severity >= 4 AND status = 'new'")
    st.metric("Critical/High Untriaged", r.iloc[0]['CNT'])
with col5:
    r = conn.query("""SELECT COUNT(*) cnt FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
                      WHERE detection_source IN ('ai_detection_agent','ai_hunting_agent')
                      AND detection_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())""")
    st.metric("AI Findings (24h)", r.iloc[0]['CNT'])

st.markdown("---")

# Findings timeline
st.subheader("Detection Findings Over Time")
timeline = conn.query("""
    SELECT DATE_TRUNC('hour', detection_time) as hour,
           severity,
           COUNT(*) as count
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    GROUP BY 1, 2
    ORDER BY 1
""")
if not timeline.empty:
    pivot = timeline.pivot(index='HOUR', columns='SEVERITY', values='COUNT').fillna(0)
    st.bar_chart(pivot)

# Severity distribution
col1, col2 = st.columns(2)
with col1:
    st.subheader("Findings by Severity")
    sev = conn.query("""
        SELECT CASE severity WHEN 5 THEN 'Critical' WHEN 4 THEN 'High' WHEN 3 THEN 'Medium' WHEN 2 THEN 'Low' ELSE 'Info' END as severity_label,
               COUNT(*) as count
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
        GROUP BY severity ORDER BY severity DESC
    """)
    if not sev.empty:
        st.bar_chart(sev.set_index('SEVERITY_LABEL'))

with col2:
    st.subheader("Findings by Category")
    cat = conn.query("""
        SELECT category, COUNT(*) as count
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
        GROUP BY category ORDER BY count DESC
    """)
    if not cat.empty:
        st.bar_chart(cat.set_index('CATEGORY'))

# Recent incidents
st.subheader("Recent Incidents")
incidents = conn.query("""
    SELECT incident_id, title, severity, priority, status,
           primary_entity, entity_type,
           first_seen, last_seen, duration_hours
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
    ORDER BY created_at DESC LIMIT 10
""")
if not incidents.empty:
    st.dataframe(incidents, use_container_width=True)

# Top affected entities
st.subheader("Top Affected Entities")
entities = conn.query("""
    SELECT COALESCE(user_name, src, dest) as entity, COUNT(*) as finding_count,
           MAX(severity) as max_severity
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
      AND COALESCE(user_name, src, dest) IS NOT NULL
    GROUP BY 1 ORDER BY 2 DESC LIMIT 10
""")
if not entities.empty:
    st.dataframe(entities, use_container_width=True)
