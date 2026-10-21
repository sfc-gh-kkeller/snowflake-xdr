import streamlit as st
import json
import pandas as pd
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Case Management", layout="wide")
show_deprecation_banner("case_management")
st.title("Case Management")

conn = st.connection("snowflake")

st.markdown("""
Full triage workflow: investigate findings, assign owners, track status
through the resolution lifecycle, and record disposition notes.
""")

STATUS_FLOW = ['new', 'investigating', 'contained', 'resolved', 'dismissed']

# ---------------- Filters ----------------
col1, col2, col3 = st.columns(3)
with col1:
    status_filter = st.multiselect("Status", STATUS_FLOW, default=['new', 'investigating'], key="cm_status")
with col2:
    sev_filter = st.slider("Min severity", 1, 5, 1, key="cm_sev")
with col3:
    search = st.text_input("Search entity/description", key="cm_search")

where = [f"severity >= {sev_filter}"]
if status_filter:
    where.append("status IN ({})".format(','.join(f"'{s}'" for s in status_filter)))
if search:
    where.append(f"(LOWER(COALESCE(user_name,src,dest)) LIKE '%{search.lower()}%' OR LOWER(description) LIKE '%{search.lower()}%')")

findings = conn.query(f"""
    SELECT f.finding_id, f.detection_time, f.rule_id, f.severity, f.status,
           f.description, COALESCE(f.user_name, f.src, f.dest) AS entity,
           f.risk_score, f.ai_fp_probability, f.assigned_to, f.disposition,
           f.triage_notes, f.incident_id
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
    WHERE {' AND '.join(where)}
    ORDER BY f.severity DESC, f.risk_score DESC, f.detection_time DESC
    LIMIT 100
""")

st.metric("Cases Matching Filters", len(findings))

if findings.empty:
    st.success("No open cases. Queue is clear.")
    st.stop()

# ---------------- Case queue table ----------------
st.dataframe(findings[['DETECTION_TIME', 'RULE_ID', 'SEVERITY', 'STATUS',
                       'ENTITY', 'RISK_SCORE', 'AI_FP_PROBABILITY', 'ASSIGNED_TO']],
             use_container_width=True, height=300)

# ---------------- Case detail + workflow ----------------
st.markdown("---")
st.subheader("Case Detail & Workflow")

case_ids = findings['FINDING_ID'].tolist()
selected = st.selectbox(
    "Select case",
    case_ids,
    format_func=lambda i: f"Sev {findings[findings['FINDING_ID']==i]['SEVERITY'].iloc[0]} | "
                          f"{findings[findings['FINDING_ID']==i]['ENTITY'].iloc[0]} | "
                          f"{str(findings[findings['FINDING_ID']==i]['DESCRIPTION'].iloc[0])[:50]}",
    key="case_sel")

if selected:
    case = findings[findings['FINDING_ID'] == selected].iloc[0]

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Severity", f"{case['SEVERITY']}/5")
    col2.metric("Risk Score", case['RISK_SCORE'])
    col3.metric("Status", case['STATUS'])
    ai_fp = case['AI_FP_PROBABILITY']
    col4.metric("AI FP Probability", f"{ai_fp:.2f}" if ai_fp is not None else "not scored")

    st.markdown(f"**Description:** {case['DESCRIPTION']}")
    st.markdown(f"**Entity:** {case['ENTITY']}")
    if case['DISPOSITION']:
        st.markdown(f"**Disposition:** {case['DISPOSITION']}")

    # Evidence
    evidence = conn.query(
        "SELECT evidence FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE finding_id = %s",
        params=(selected,))
    ev = evidence.iloc[0]['EVIDENCE']
    if ev:
        with st.expander("Evidence"):
            ev_data = json.loads(ev) if isinstance(ev, str) else ev
            st.json(ev_data)

    # AI explanation
    ai_exp = conn.query(
        "SELECT ai_explanation FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS WHERE finding_id = %s",
        params=(selected,))
    exp = ai_exp.iloc[0]['AI_EXPLANATION']
    if exp:
        with st.expander("AI Triage Explanation"):
            st.markdown(str(exp))

    # Similar findings (Cortex AI semantic similarity)
    st.markdown("---")
    st.subheader("Similar Findings")
    st.caption("Semantically similar alerts found by Cortex AI — is this part of a bigger campaign?")
    try:
        sim_call = conn.query(
            "CALL SNOWFLAKE_XDR.DETECTIONS.FIND_SIMILAR_FINDINGS(%s)",
            params=(selected,), ttl=0)
        sim_data = json.loads(sim_call.iloc[0][0]).get("similar", [])
        if sim_data:
            sim_df = pd.DataFrame(sim_data)
            st.dataframe(
                sim_df[["rule_id", "severity", "user_name", "description", "similarity", "detected"]]
                .rename(columns={
                    "rule_id": "Rule", "severity": "Sev", "user_name": "User",
                    "description": "Description", "similarity": "Similarity", "detected": "Detected"
                }),
                use_container_width=True, hide_index=True,
            )
        else:
            st.info("No similar findings found.")
    except Exception as e:
        st.warning(f"Similar-findings lookup unavailable: {e}")

    # Pivot buttons
    st.subheader("Pivot To")
    pcol1, pcol2 = st.columns(2)
    with pcol1:
        if case.get('ENTITY') and st.button("Investigate User", key="pivot_user"):
            st.markdown(
                f"Open: Entity Investigation for `{case['ENTITY']}` "
                "(see Entity Investigation page)")
    with pcol2:
        if case.get('RULE_ID') and st.button("View Rule", key="pivot_rule"):
            st.markdown(
                f"Open: Detection Library, filter rule `{case['RULE_ID']}`")
        else:
            st.caption("")

    # Workflow controls
    st.markdown("---")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        new_status = st.selectbox("Set Status", STATUS_FLOW,
                                  index=STATUS_FLOW.index(case['STATUS']) if case['STATUS'] in STATUS_FLOW else 0,
                                  key="wf_status")
    with c2:
        assignee = st.text_input("Assign To", value=case['ASSIGNED_TO'] or '', key="wf_assignee")
    with c3:
        disposition = st.selectbox("Disposition", ['', 'true_positive', 'false_positive', 'benign'],
                                   key="wf_disposition")
    with c4:
        notes = st.text_input("Triage Notes", value=case['TRIAGE_NOTES'] or '', key="wf_notes")

    b1, b2 = st.columns(2)
    with b1:
        if st.button("Update Case", type="primary", key="wf_update"):
            conn.query(f"""
                UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
                SET status = '{new_status}',
                    assigned_to = %s,
                    disposition = COALESCE(NULLIF('{disposition}', ''), disposition),
                    triage_notes = %s,
                    triaged_at = CURRENT_TIMESTAMP()
                WHERE finding_id = %s
            """, params=(assignee, notes, selected))
            st.success(f"Case updated: {new_status}")
            st.rerun()
    with b2:
        if st.button("Run AI Triage on This Finding", key="wf_ai"):
            with st.spinner("Cortex AI triaging..."):
                conn.query("CALL SNOWFLAKE_XDR.DETECTIONS.AI_TRIAGE_AGENT(1)")
            st.rerun()
