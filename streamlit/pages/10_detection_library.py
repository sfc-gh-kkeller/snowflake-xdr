import streamlit as st
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Detection Library", layout="wide")
show_deprecation_banner("detection_library")
st.title("Detection Rule Library")

conn = st.connection("snowflake")

st.markdown("All detection rules with MITRE mapping, type, and recent activity.")

# Filters
col1, col2, col3 = st.columns(3)
with col1:
    cat = st.selectbox("Category", ['All', 'identity', 'endpoint', 'network', 'cloud', 'application'])
with col2:
    det_type = st.selectbox("Type", ['All', 'ttp', 'anomaly', 'hunting', 'correlation'])
with col3:
    enabled_only = st.checkbox("Enabled only", value=True)

where = []
if cat != 'All':
    where.append(f"r.category = '{cat}'")
if det_type != 'All':
    where.append(f"r.detection_type = '{det_type}'")
if enabled_only:
    where.append("r.enabled = TRUE")

where_sql = "WHERE " + " AND ".join(where) if where else ""

rules = conn.query(f"""
    SELECT
        r.rule_id, r.rule_name, r.category, r.detection_type, r.severity,
        r.mitre_tactic, r.mitre_technique_id, r.mitre_technique,
        r.enabled, r.lookback_minutes,
        r.splunk_analytic_story,
        COUNT(f.finding_id) as findings_total,
        COUNT(CASE WHEN f.detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP()) THEN 1 END) as findings_7d,
        MAX(f.detection_time) as last_fired
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES r
    LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f ON f.rule_id = r.rule_id
    {where_sql}
    GROUP BY r.rule_id, r.rule_name, r.category, r.detection_type, r.severity,
             r.mitre_tactic, r.mitre_technique_id, r.mitre_technique, r.enabled,
             r.lookback_minutes, r.splunk_analytic_story
    ORDER BY r.category, r.severity DESC
""")

if not rules.empty:
    st.metric("Rules Displayed", len(rules))
    st.dataframe(rules, use_container_width=True, height=600)
else:
    st.info("No rules match filters.")
