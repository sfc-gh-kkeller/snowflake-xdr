import streamlit as st
import pandas as pd
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Triage Queue", layout="wide")
show_deprecation_banner("triage_queue")
st.title("Triage Queue")

conn = st.connection("snowflake")

st.markdown("Unresolved findings ranked by risk score. AI triage recommendations, FP-model scores, and control coverage shown where available.")

# FP suppression engine controls
c0, c1, c2 = st.columns(3)
with c0:
    if st.button("Train FP Model"):
        r = conn.query("CALL SNOWFLAKE_XDR.DETECTIONS.TRAIN_FP_MODEL()", ttl=0)
        st.success(r.iloc[0][0])
with c1:
    if st.button("Apply FP Scoring"):
        r = conn.query("CALL SNOWFLAKE_XDR.DETECTIONS.SCORE_FINDINGS_FP()", ttl=0)
        st.success(r.iloc[0][0])
with c2:
    if st.button("Assess Control Coverage"):
        r = conn.query("CALL SNOWFLAKE_XDR.DETECTIONS.APPLY_CONTROL_ASSESSMENT()", ttl=0)
        st.success(r.iloc[0][0])

st.markdown("---")

# Filters
col1, col2, col3 = st.columns(3)
with col1:
    severity_filter = st.multiselect("Severity", [5, 4, 3, 2, 1], default=[5, 4, 3])
with col2:
    category_filter = st.selectbox("Category", ['All', 'identity', 'endpoint', 'network', 'cloud', 'application'])
with col3:
    source_filter = st.selectbox("Detection Source", ['All', 'stored_procedure', 'ai_detection_agent', 'ai_hunting_agent'])

# Build query
where_clauses = ["status IN ('new', 'investigating')"]
if severity_filter:
    where_clauses.append(f"severity IN ({','.join(str(s) for s in severity_filter)})")
if category_filter != 'All':
    where_clauses.append(f"category = '{category_filter}'")
if source_filter != 'All':
    where_clauses.append(f"detection_source = '{source_filter}'")

where_sql = " AND ".join(where_clauses)

findings = conn.query(f"""
    SELECT
        f.finding_id, f.rule_id, f.detection_time, f.severity, f.confidence, f.risk_score,
        f.category, f.mitre_technique_id,
        COALESCE(f.user_name, f.src, f.dest) as primary_entity,
        LEFT(f.description, 200) as description,
        f.status, f.detection_source,
        f.ai_fp_probability, LEFT(f.ai_explanation, 150) as ai_recommendation,
        IFF(f.disposition = 'mitigated_by_control', 'COVERED', '') as control_covered,
        LEFT(f.triage_notes, 120) as fp_notes,
        (SELECT ROUND(fp.fp_rate * 100) FROM SNOWFLAKE_XDR.DETECTIONS.FP_PATTERNS fp
         WHERE fp.rule_id = f.rule_id
           AND fp.entity = COALESCE(f.user_name, f.src, f.dest, 'unknown')) as fp_rate_pct
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
    WHERE {where_sql}
    ORDER BY f.risk_score DESC
    LIMIT 50
""")

if not findings.empty:
    st.metric("Findings in Queue", len(findings))

    # AI triage summary
    ai_triaged = findings[findings['AI_FP_PROBABILITY'].notna()]
    if not ai_triaged.empty:
        likely_fp = len(ai_triaged[ai_triaged['AI_FP_PROBABILITY'] > 0.7])
        likely_tp = len(ai_triaged[ai_triaged['AI_FP_PROBABILITY'] < 0.3])
        st.info(f"AI Triage: {likely_tp} likely true positives, {likely_fp} likely false positives out of {len(ai_triaged)} evaluated")

    # Display findings
    st.dataframe(findings, use_container_width=True, height=600)

    # Triage actions
    st.markdown("---")
    st.subheader("Bulk Triage Actions")
    selected = st.text_input("Finding IDs to action (comma-separated)")
    action = st.selectbox("Action", ['confirm_true_positive', 'dismiss_false_positive', 'escalate_to_incident'])
    if st.button("Apply Action"):
        if selected and action:
            ids = [f"'{x.strip()}'" for x in selected.split(',')]
            id_list = ','.join(ids)
            if action == 'dismiss_false_positive':
                conn.query(f"UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS SET status='dismissed', disposition='false_positive', triaged_at=CURRENT_TIMESTAMP() WHERE finding_id IN ({id_list})")
            elif action == 'confirm_true_positive':
                conn.query(f"UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS SET status='investigating', disposition='true_positive', triaged_at=CURRENT_TIMESTAMP() WHERE finding_id IN ({id_list})")
            st.success(f"Applied {action} to {len(ids)} findings")
            st.rerun()
else:
    st.success("No findings in queue matching filters.")
