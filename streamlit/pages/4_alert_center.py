import streamlit as st
import json
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Alert Center", layout="wide")
show_deprecation_banner("alert_center")
st.title("Alert Center")

conn = st.connection("snowflake")

st.markdown("""
History of all notifications sent by response playbooks — emails, webhooks,
and external API calls — with delivery status.
""")

# ---------------- Filters ----------------
col1, col2 = st.columns(2)
with col1:
    status_f = st.multiselect("Status", ['success', 'error', 'suppressed_cooldown', 'skipped'],
                              default=['success', 'error'], key="ac_status")
with col2:
    action_f = st.multiselect("Action Type", ['email', 'webhook', 'api_call', 'create_incident', 'ai_triage'],
                              default=['email', 'webhook', 'api_call'], key="ac_action")

where = []
if status_f:
    where.append("status IN ({})".format(','.join(f"'{s}'" for s in status_f)))
if action_f:
    where.append("action_type IN ({})".format(','.join(f"'{a}'" for a in action_f)))

where_sql = "WHERE " + " AND ".join(where) if where else ""

# ---------------- Stats ----------------
stats = conn.query(f"""
    SELECT action_type, status, COUNT(*) AS cnt
    FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS {where_sql}
    GROUP BY action_type, status
""")
total = conn.query(f"SELECT COUNT(*) AS total FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS {where_sql}")

c1, c2, c3 = st.columns(3)
c1.metric("Total Notifications", total.iloc[0]['TOTAL'])
if not stats.empty:
    by_type = stats.groupby('ACTION_TYPE')['CNT'].sum()
    c2.metric("Emails", by_type.get('email', 0))
    c3.metric("Webhooks + APIs", by_type.get('webhook', 0) + by_type.get('api_call', 0))
    st.bar_chart(stats.groupby('ACTION_TYPE')['CNT'].sum())
else:
    c2.metric("Emails", 0)
    c3.metric("Webhooks + APIs", 0)

# ---------------- Full log ----------------
st.markdown("---")
st.subheader("Notification History")
log = conn.query(f"""
    SELECT a.executed_at, a.playbook_name, a.action_type, a.status, a.detail,
           f.severity, COALESCE(f.user_name, f.src, f.dest) AS entity
    FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS a
    LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
        ON f.finding_id = a.finding_id
    {where_sql}
    ORDER BY a.executed_at DESC
    LIMIT 200
""")
if not log.empty:
    st.dataframe(log, use_container_width=True, height=400)

    # Success rate
    errors = len(log[log['STATUS'] == 'error'])
    st.caption(f"{errors} errors in last {len(log)} actions")
else:
    st.info("No notifications match the filters. Configure playbooks in Response Automation.")

# ---------------- Control-covered alerts ----------------
st.markdown("---")
st.subheader("Mitigated by Existing Controls")
st.caption("Genuine findings whose remediation is already covered - no action needed, nothing hidden")
mitigated = conn.query("""
    SELECT detection_time, rule_id, LEFT(description, 90) AS description,
           COALESCE(user_name, src, dest) AS entity, risk_score, triage_notes
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE disposition = 'mitigated_by_control'
    ORDER BY triaged_at DESC LIMIT 20
""")
if not mitigated.empty:
    st.dataframe(mitigated, use_container_width=True, hide_index=True)
    st.caption("Findings auto-assessed by the compensating controls engine - blocked by firewall/EDR policies in scope.")
else:
    st.info("No control-mitigated findings yet. Blocked attacks into protected assets will appear here after 'Assess Control Coverage' runs in the Triage Queue.")
