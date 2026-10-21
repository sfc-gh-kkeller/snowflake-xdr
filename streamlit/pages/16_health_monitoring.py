import streamlit as st
import pandas as pd
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Health Monitor", layout="wide")
show_deprecation_banner("health_monitoring")
st.title("Detection Health & Platform Monitoring")

conn = st.connection("snowflake")

st.markdown("""
Monitor detection rule performance, data pipeline freshness, and recent errors.
""")

# ---------------- Detection health ----------------
st.subheader("Detection Health")
health = conn.query("""
    SELECT rule_id, rule_name, category, severity, enabled,
           findings_total, findings_7d, last_fired, recent_errors
    FROM SNOWFLAKE_XDR.DETECTIONS.V_DETECTION_HEALTH
    ORDER BY recent_errors DESC, findings_7d DESC, severity DESC
""")

c1, c2, c3 = st.columns(3)
if not health.empty:
    c1.metric("Total Rules", len(health))
    c2.metric("Rules Fired (7d)", len(health[health['FINDINGS_7D'] > 0]))
    c3.metric("Rules With Errors", len(health[health['RECENT_ERRORS'] > 0]))

    # Flag stale rules
    def health_style(row):
        if row['RECENT_ERRORS'] > 0:
            return ['background-color: #dc3545'] * len(row)
        elif row['LAST_FIRED'] is not None and pd.notna(row['LAST_FIRED']):
            return ['background-color: #28a745'] * len(row)
        else:
            return ['background-color: #ffc107'] * len(row)

    display = health.copy()
    display['LAST_FIRED'] = pd.to_datetime(display['LAST_FIRED'], errors='coerce')
    st.dataframe(display, use_container_width=True, height=400)

# ---------------- Data freshness ----------------
st.markdown("---")
st.subheader("Data Pipeline Freshness")
freshness = conn.query("""
    SELECT source_table, latest_event, event_count,
           DATEDIFF('hour', latest_event, CURRENT_TIMESTAMP()) AS hours_old
    FROM SNOWFLAKE_XDR.DETECTIONS.V_DATA_FRESHNESS
    ORDER BY hours_old ASC
""")
if not freshness.empty:
    c1, c2 = st.columns([3, 2])
    with c1:
        st.dataframe(freshness, use_container_width=True)
    with c2:
        st.bar_chart(freshness.set_index('SOURCE_TABLE')['EVENT_COUNT'])

# ---------------- Custom rule errors ----------------
st.markdown("---")
st.subheader("Recent Custom Rule Errors")
errors = conn.query("""
    SELECT e.error_time, r.name AS rule_name, e.stage, LEFT(e.error_message, 100) AS error_message
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_ERRORS e
    LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES r ON r.rule_id = e.rule_id
    ORDER BY e.error_time DESC LIMIT 20
""")
if not errors.empty:
    st.dataframe(errors, use_container_width=True)
else:
    st.success("No custom rule errors — all rules healthy.")

# ---------------- Pipeline stats ----------------
st.markdown("---")
st.subheader("Platform Stats")
stats = conn.query("""
    SELECT
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS) AS total_findings,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
         WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS findings_7d,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS) AS total_incidents,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS) AS playbook_actions,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE enabled = TRUE) AS active_custom_rules
""")
if not stats.empty:
    s = stats.iloc[0]
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Findings", s['TOTAL_FINDINGS'])
    c2.metric("Findings (7d)", s['FINDINGS_7D'])
    c3.metric("Incidents", s['TOTAL_INCIDENTS'])
    c4.metric("Playbook Actions", s['PLAYBOOK_ACTIONS'])
    c5.metric("Active Custom Rules", s['ACTIVE_CUSTOM_RULES'])
