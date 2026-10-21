import streamlit as st
import json
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Response Automation", layout="wide")
show_deprecation_banner("response_automation")
st.title("Response Automation")

conn = st.connection("snowflake")

st.markdown("""
Configure **playbooks** that fire when findings match trigger conditions.
Actions: email, webhook (Slack/Teams), external API call, create incident, AI triage.
""")

# ---------------- Playbook list ----------------
playbooks = conn.query("""
    SELECT playbook_id, name, description, trigger_severity_min,
           threshold_count, threshold_window_minutes, cooldown_minutes,
           action_type, action_config, enabled
    FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOKS
    ORDER BY created_at DESC
""")

st.subheader("Playbooks")

pb_options = ["+ New Playbook"] + [
    f"{r['NAME']} (sev>={r['TRIGGER_SEVERITY_MIN']} -> {r['ACTION_TYPE']}, {'enabled' if r['ENABLED'] else 'disabled'})"
    for _, r in playbooks.iterrows()
] if not playbooks.empty else ["+ New Playbook"]

sel = st.selectbox("Select playbook", range(len(pb_options)),
                   format_func=lambda i: pb_options[i], key="pb_sel")

if sel == 0:
    st.markdown("---")
    st.subheader("New Playbook")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Trigger Conditions**")
        p_name = st.text_input("Playbook Name", key="p_name")
        p_desc = st.text_input("Description", key="p_desc")
        p_sev = st.slider("Minimum Severity", 1, 5, 4, key="p_sev")
        p_thresh = st.number_input("Threshold (findings in window)", 1, 100, 1, key="p_thresh")
        p_window = st.number_input("Threshold window (minutes)", 1, 1440, 60, key="p_window")
        p_cooldown = st.number_input("Cooldown (minutes per entity)", 1, 1440, 60, key="p_cooldown")
        p_entity = st.text_input("Entity filter (user/IP/host, blank = any)", key="p_entity")
    with col2:
        st.markdown("**Action**")
        p_action = st.selectbox("Action Type",
            ["email", "webhook", "api_call", "create_incident", "ai_triage"], key="p_action")
        p_config_str = "{}"
        if p_action == "email":
            to = st.text_input("Recipient email(s), comma-separated", key="p_to")
            p_config_str = json.dumps({"to": to})
        elif p_action == "api_call":
            api_url = st.text_input("API endpoint URL", key="p_url")
            api_auth = st.text_input("Authorization header (optional)", key="p_auth")
            p_config_str = json.dumps({"url": api_url, "auth_header": api_auth})
        elif p_action == "webhook":
            st.info("Webhook posts the finding as JSON to the configured XDR_WEBHOOK integration (Slack/Teams).")
        p_enabled = st.checkbox("Enabled", value=True, key="p_enabled")

    if st.button("Save Playbook", type="primary", key="save_pb"):
        if p_name:
            res = conn.query(
                "CALL SNOWFLAKE_XDR.RESPONSE.SAVE_PLAYBOOK('', %s, %s, %s, NULL, NULL, %s, %s, %s, %s, %s, PARSE_JSON(%s), %s)",
                params=(p_name, p_desc, p_sev, p_entity or None, p_thresh, p_window,
                        p_cooldown, p_action, p_config_str, p_enabled))
            st.success(f"Playbook {res.iloc[0][0]}")
            st.rerun()
        else:
            st.warning("Playbook name is required.")
else:
    row = playbooks.iloc[sel - 1]
    pid = row['PLAYBOOK_ID']
    st.markdown("---")
    st.subheader(f"Edit: {row['NAME']}")

    col1, col2 = st.columns(2)
    with col1:
        e_name = st.text_input("Name", value=row['NAME'], key="e_pb_name")
        e_sev = st.slider("Minimum Severity", 1, 5, int(row['TRIGGER_SEVERITY_MIN']), key="e_pb_sev")
        e_thresh = st.number_input("Threshold", 1, 100, int(row['THRESHOLD_COUNT']), key="e_pb_thresh")
        e_cooldown = st.number_input("Cooldown (min)", 1, 1440, int(row['COOLDOWN_MINUTES']), key="e_pb_cooldown")
        e_enabled = st.checkbox("Enabled", value=bool(row['ENABLED']), key="e_pb_enabled")
    with col2:
        e_action = st.selectbox("Action Type",
            ["email", "webhook", "api_call", "create_incident", "ai_triage"],
            index=["email", "webhook", "api_call", "create_incident", "ai_triage"].index(row['ACTION_TYPE']),
            key="e_pb_action")
        cfg = row['ACTION_CONFIG']
        if cfg and isinstance(cfg, str):
            try:
                cfg = json.loads(cfg)
            except Exception:
                cfg = {}
        if e_action == "email":
            e_to = st.text_input("Recipient(s)", value=(cfg or {}).get('to', ''), key="e_pb_to")
            e_cfg = json.dumps({"to": e_to})
        elif e_action == "api_call":
            e_url = st.text_input("API URL", value=(cfg or {}).get('url', ''), key="e_pb_url")
            e_auth = st.text_input("Auth header", value=(cfg or {}).get('auth_header', ''), key="e_pb_auth")
            e_cfg = json.dumps({"url": e_url, "auth_header": e_auth})
        else:
            e_cfg = '{}'

    c1, c2 = st.columns(2)
    with c1:
        if st.button("Save Changes", key="save_pb_edit", type="primary"):
            res = conn.query(
                "CALL SNOWFLAKE_XDR.RESPONSE.SAVE_PLAYBOOK(%s, %s, %s, %s, NULL, NULL, NULL, %s, %s, %s, %s, PARSE_JSON(%s), %s)",
                params=(pid, e_name, e_sev, e_thresh, e_thresh, 1440, e_cooldown,
                        e_action, e_cfg, e_enabled))
            st.success(f"Playbook {res.iloc[0][0]}")
            st.rerun()
    with c2:
        if st.button("Test Against Latest Finding", key="test_pb"):
            finding = conn.query("""
                SELECT finding_id FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
                WHERE severity >= %s ORDER BY severity DESC, detection_time DESC LIMIT 1
            """, params=(int(e_sev),))
            if not finding.empty:
                fid = finding.iloc[0]['FINDING_ID']
                with st.spinner("Firing playbook against finding..."):
                    res = conn.query(
                        "CALL SNOWFLAKE_XDR.RESPONSE.EVALUATE_RESPONSE(%s)", params=(fid,))
                st.success(res.iloc[0][0])
            else:
                st.info("No matching finding to test with.")

# ---------------- Action log ----------------
st.markdown("---")
st.subheader("Action Log")
log = conn.query("""
    SELECT executed_at, playbook_name, action_type, status,
           LEFT(detail, 100) AS detail
    FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS
    ORDER BY executed_at DESC
    LIMIT 50
""")
if not log.empty:
    st.dataframe(log, use_container_width=True)
else:
    st.info("No playbook actions yet.")

# ---------------- Batch evaluation ----------------
st.markdown("---")
if st.button("Evaluate All New Findings Now", key="eval_all"):
    with st.spinner("Evaluating findings against all enabled playbooks..."):
        res = conn.query("CALL SNOWFLAKE_XDR.RESPONSE.EVALUATE_ALL_NEW_FINDINGS()")
    st.success(res.iloc[0][0])
    st.rerun()
