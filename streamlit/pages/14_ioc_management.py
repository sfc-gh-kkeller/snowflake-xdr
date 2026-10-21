import streamlit as st
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="IOC Manager", layout="wide")
show_deprecation_banner("ioc_management")
st.title("IOC & Watchlist Management")

conn = st.connection("snowflake")

st.markdown("""
Manage indicators of compromise. Manually added IOCs feed the
`DETECT_KNOWN_BAD_IOC` detection in the next detection run.
""")

# ---------------- Current IOCs ----------------
iocs = conn.query("""
    SELECT ioc_type, ioc_value, threat_type, threat_name, severity,
           confidence, source, first_seen, active
    FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
    ORDER BY severity DESC, first_seen DESC
""")
st.metric("Active IOCs", len(iocs[iocs['ACTIVE'] == True]) if not iocs.empty else 0)
if not iocs.empty:
    st.dataframe(iocs, use_container_width=True, height=300)

# ---------------- Add IOC ----------------
st.markdown("---")
st.subheader("Add IOC")
col1, col2 = st.columns(2)
with col1:
    n_type = st.selectbox("IOC Type", ["ip", "domain", "url", "hash_md5", "hash_sha256", "email", "user_agent"], key="i_type")
    n_value = st.text_input("IOC Value", key="i_value")
    n_ttype = st.selectbox("Threat Type", ["malware", "phishing", "c2", "botnet", "ransomware", "apt", "credential_abuse"], key="i_ttype")
with col2:
    n_name = st.text_input("Threat Name", key="i_name")
    n_sev = st.slider("Severity", 1, 5, 3, key="i_sev")
    n_source = st.text_input("Source", value="manual", key="i_source")

b1, b2 = st.columns(2)
with b1:
    if st.button("Add IOC", type="primary", key="add_ioc"):
        if n_value:
            res = conn.query(
                "CALL SNOWFLAKE_XDR.REFERENCE.ADD_IOC(%s, %s, %s, %s, %s, %s)",
                params=(n_type, n_value, n_ttype, n_name or n_ttype, n_sev, n_source))
            st.success(f"IOC {res.iloc[0][0]}")
            st.rerun()
        else:
            st.warning("IOC value is required.")

with b2:
    r_value = st.text_input("IOC Value to Remove", key="r_value")
    r_type = st.selectbox("Type of IOC to Remove", ["ip", "domain", "url", "hash_md5", "hash_sha256", "email", "user_agent"], key="r_type")
    if st.button("Remove IOC", key="remove_ioc"):
        if r_value:
            res = conn.query(
                "CALL SNOWFLAKE_XDR.REFERENCE.REMOVE_IOC(%s, %s)", params=(r_type, r_value))
            st.success(f"IOC {res.iloc[0][0]}")
            st.rerun()
        else:
            st.warning("Enter the IOC value to remove.")

# ---------------- Bulk IOC matches in data ----------------
st.markdown("---")
st.subheader("IOC Matches in Current Data")
matches = conn.query("""
    SELECT i.ioc_value, i.threat_name, COUNT(n.id) AS match_count
    FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS i
    LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS n
        ON n.rule_id = 'DET-021'
    WHERE i.active = TRUE
    GROUP BY i.ioc_value, i.threat_name
    LIMIT 20
""")
st.caption("IOC detection (DET-021) checks network traffic and DNS against active indicators.")
if st.button("Run IOC Detection Now", key="run_ioc"):
    with st.spinner("Scanning telemetry for IOC matches..."):
        res = conn.query("CALL SNOWFLAKE_XDR.DETECTIONS.RUN_ALL_DETECTIONS()")
    st.success(res.iloc[0][0])
