import streamlit as st
import pandas as pd
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="MITRE Coverage", layout="wide")
show_deprecation_banner("mitre_coverage")
st.title("MITRE ATT&CK Coverage Matrix")

conn = st.connection("snowflake")

st.markdown("""
This heatmap shows detection coverage across MITRE ATT&CK tactics.
- **Green**: Covered by TTP detection (high confidence)
- **Yellow**: Covered by Anomaly detection only
- **Red**: No coverage (gap)
""")

# Get tactic coverage
coverage = conn.query("""
    SELECT
        t.tactic_id,
        t.tactic_name,
        t.tactic_order,
        COUNT(DISTINCT r.rule_id) as rule_count,
        COUNT(DISTINCT CASE WHEN r.detection_type = 'ttp' THEN r.rule_id END) as ttp_count,
        COUNT(DISTINCT CASE WHEN r.detection_type = 'anomaly' THEN r.rule_id END) as anomaly_count,
        COUNT(DISTINCT f.finding_id) as findings_7d
    FROM SNOWFLAKE_XDR.REFERENCE.MITRE_TACTICS t
    LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES r ON r.mitre_tactic_id = t.tactic_id AND r.enabled = TRUE
    LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f ON f.mitre_tactic_id = t.tactic_id
        AND f.detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    GROUP BY t.tactic_id, t.tactic_name, t.tactic_order
    ORDER BY t.tactic_order
""")

if not coverage.empty:
    # Display as a styled table
    def color_coverage(row):
        if row['TTP_COUNT'] > 0:
            return ['background-color: #28a745'] * len(row)
        elif row['ANOMALY_COUNT'] > 0:
            return ['background-color: #ffc107'] * len(row)
        elif row['RULE_COUNT'] > 0:
            return ['background-color: #17a2b8'] * len(row)
        else:
            return ['background-color: #dc3545'] * len(row)

    display_df = coverage[['TACTIC_NAME', 'RULE_COUNT', 'TTP_COUNT', 'ANOMALY_COUNT', 'FINDINGS_7D']].copy()
    display_df.columns = ['Tactic', 'Total Rules', 'TTP Rules', 'Anomaly Rules', 'Findings (7d)']
    st.dataframe(display_df.style.apply(color_coverage, axis=1), use_container_width=True)

# Technique-level detail
st.markdown("---")
st.subheader("Detection Rules by Technique")
rules = conn.query("""
    SELECT
        r.rule_id, r.rule_name, r.category, r.detection_type, r.severity,
        r.mitre_tactic, r.mitre_technique_id, r.mitre_technique,
        r.enabled,
        COUNT(f.finding_id) as findings_7d
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES r
    LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f ON f.rule_id = r.rule_id
        AND f.detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    GROUP BY r.rule_id, r.rule_name, r.category, r.detection_type, r.severity,
             r.mitre_tactic, r.mitre_technique_id, r.mitre_technique, r.enabled
    ORDER BY r.mitre_tactic, r.severity DESC
""")
if not rules.empty:
    # Filter by category
    categories = ['All'] + list(rules['CATEGORY'].unique())
    selected_cat = st.selectbox("Filter by Category", categories)
    if selected_cat != 'All':
        rules = rules[rules['CATEGORY'] == selected_cat]
    st.dataframe(rules, use_container_width=True)

# Coverage gap finder
st.markdown("---")
st.subheader("Coverage Gap Finder")
st.caption("MITRE techniques with no enabled detection rule — where the platform is blind")
try:
    gaps = conn.query("""
        SELECT technique_id, technique_name, tactic_name,
               LEFT(description, 100) AS description
        FROM SNOWFLAKE_XDR.DETECTIONS.V_MITRE_GAPS
        ORDER BY tactic_name, technique_id
    """)
    if not gaps.empty:
        st.dataframe(
            gaps.rename(columns={
                "TECHNIQUE_ID": "Technique", "TECHNIQUE_NAME": "Name",
                "TACTIC_NAME": "Tactic", "DESCRIPTION": "Description"
            }),
            use_container_width=True, hide_index=True,
        )
        st.warning(
            f"{len(gaps)} techniques lack detection coverage. "
            "Use the Rule Editor (AI-assisted) to close these gaps."
        )
    else:
        st.success("Full technique coverage — no gaps found.")
except Exception as e:
    st.warning(f"Gap finder unavailable: {e}")
