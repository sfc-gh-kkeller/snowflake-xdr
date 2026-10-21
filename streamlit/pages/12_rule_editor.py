import streamlit as st
import json
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Rule Editor", layout="wide")
show_deprecation_banner("rule_editor")
st.title("Detection Rule Editor")

conn = st.connection("snowflake")

st.markdown("""
Create detection rules manually in **SQL**, **Python**, or **JavaScript** — or let
**Cortex AI** generate one from a natural-language description. Test rules against
live data before enabling them.
""")

# ---------------- AI-assisted generation ----------------
with st.expander("Generate a Rule with AI", expanded=False):
    nl_desc = st.text_area(
        "Describe the detection you want",
        placeholder="e.g., Detect failed logins from the same source to multiple user accounts within 10 minutes",
        height=80, key="nl_desc")
    if st.button("Generate with Cortex AI", type="primary", key="gen_ai"):
        if nl_desc:
            with st.spinner("Cortex AI is writing your detection..."):
                result = conn.query(
                    "CALL SNOWFLAKE_XDR.DETECTIONS.AI_GENERATE_RULE(%s)",
                    params=(nl_desc,))
                raw = result.iloc[0][0]
                if isinstance(raw, str):
                    raw = json.loads(raw)
                if raw and 'error' not in raw:
                    st.success(f"Draft rule created: {raw.get('name', 'unnamed')}")
                    st.markdown("**Generated SQL:**")
                    st.code(raw.get('rule_sql', ''), language="sql")
                    st.info("The draft is saved (disabled). Select it below to review, test, and enable.")
                else:
                    st.error(f"AI generation failed: {raw}")
        else:
            st.warning("Enter a description first.")

# ---------------- Rule list + editor ----------------
rules = conn.query("""
    SELECT rule_id, name, description, category, severity, language,
           LEFT(code, 60) AS code_preview, threshold_count, threshold_window_minutes,
           lookback_minutes, enabled, created_by, version
    FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
    ORDER BY created_at DESC
""")

st.subheader("Custom Rules")

# Select existing rule or create new
rule_options = ["+ New Rule"] + [
    f"{r['NAME']} ({r['LANGUAGE']}, sev {r['SEVERITY']}, {'enabled' if r['ENABLED'] else 'disabled'})"
    for _, r in rules.iterrows()
] if not rules.empty else ["+ New Rule"]

selected_idx = st.selectbox("Select rule to edit", range(len(rule_options)),
                            format_func=lambda i: rule_options[i], key="rule_sel")

if selected_idx == 0:
    # New rule form
    st.markdown("---")
    st.subheader("New Rule")
    col1, col2 = st.columns(2)
    with col1:
        r_name = st.text_input("Rule Name", key="n_name")
        r_lang = st.selectbox("Language", ["sql", "python", "javascript"], key="n_lang")
        r_cat = st.selectbox("Category",
            ["identity", "endpoint", "network", "cloud", "application", "custom"], key="n_cat")
        r_sev = st.slider("Severity", 1, 5, 3, key="n_sev")
        r_tactic = st.text_input("MITRE Tactic ID (optional)", key="n_tactic")
        r_tech = st.text_input("MITRE Technique ID (optional)", key="n_tech")
    with col2:
        if r_lang == "sql":
            st.caption("SQL must return columns: _time, user_name, src, dest, description")
        else:
            st.caption("Define a function `detect(row)` returning 1 (match) or 0. `row` is a VARIANT of the log row.")
        r_source = st.text_input("Source table (python/js only)", "AUTHENTICATION", key="n_source")
        r_thresh = st.number_input("Threshold (events to fire)", 1, 1000, 1, key="n_thresh")
        r_window = st.number_input("Threshold window (minutes)", 1, 1440, 60, key="n_window")
        r_lookback = st.number_input("Lookback (minutes)", 1, 20160, 1440, key="n_lookback")
        r_enabled = st.checkbox("Enabled", value=False, key="n_enabled")

    r_code = st.text_area("Rule Code", height=200, key="n_code",
        placeholder="SELECT _time, user_name, src, dest, description FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION WHERE ..." if r_lang == "sql"
        else "def detect(row):\n    return 1 if row['action'] == 'failure' else 0")

    c1, c2 = st.columns(2)
    with c1:
        if st.button("Save Rule", key="save_new"):
            if r_name and r_code:
                res = conn.query(
                    "CALL SNOWFLAKE_XDR.DETECTIONS.SAVE_CUSTOM_RULE('', %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    params=(r_name, "", r_cat, r_sev, r_tactic or None, r_tech or None,
                            r_lang, r_source if r_lang != "sql" else None, r_code,
                            r_thresh, r_window, r_lookback, r_enabled))
                st.success(f"Rule {res.iloc[0][0]}")
                st.rerun()
            else:
                st.warning("Name and code are required.")
    with c2:
        if st.button("Refresh List", key="refresh"):
            st.rerun()

else:
    # Edit existing rule
    row = rules.iloc[selected_idx - 1]
    rid = row['RULE_ID']
    st.markdown("---")
    st.subheader(f"Edit: {row['NAME']}")

    col1, col2 = st.columns(2)
    with col1:
        e_name = st.text_input("Rule Name", value=row['NAME'], key="e_name")
        e_lang = st.selectbox("Language", ["sql", "python", "javascript"],
                              index=["sql", "python", "javascript"].index(row['LANGUAGE']), key="e_lang")
        e_cat = st.selectbox("Category",
            ["identity", "endpoint", "network", "cloud", "application", "custom"],
            index=["identity", "endpoint", "network", "cloud", "application", "custom"].index(row['CATEGORY']) if row['CATEGORY'] in ["identity", "endpoint", "network", "cloud", "application", "custom"] else 5,
            key="e_cat")
        e_sev = st.slider("Severity", 1, 5, int(row['SEVERITY']), key="e_sev")
    with col2:
        e_thresh = st.number_input("Threshold", 1, 1000, int(row['THRESHOLD_COUNT']), key="e_thresh")
        e_window = st.number_input("Window (min)", 1, 1440, int(row['THRESHOLD_WINDOW_MINUTES']), key="e_window")
        e_lookback = st.number_input("Lookback (min)", 1, 20160, int(row['LOOKBACK_MINUTES']), key="e_lookback")
        e_enabled = st.checkbox("Enabled", value=bool(row['ENABLED']), key="e_enabled")

    # Load full code
    full_code = conn.query(
        "SELECT code, mitre_tactic_id, mitre_technique_id, source_table FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE rule_id = %s",
        params=(rid,))
    e_code = st.text_area("Rule Code", value=full_code.iloc[0]['CODE'], height=200, key="e_code")
    e_tactic = st.text_input("MITRE Tactic", value=full_code.iloc[0]['MITRE_TACTIC_ID'] or '', key="e_tactic")
    e_tech = st.text_input("MITRE Technique", value=full_code.iloc[0]['MITRE_TECHNIQUE_ID'] or '', key="e_tech")
    e_source = st.text_input("Source table", value=full_code.iloc[0]['SOURCE_TABLE'] or '', key="e_source")

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Save Changes", key="save_edit", type="primary"):
            res = conn.query(
                "CALL SNOWFLAKE_XDR.DETECTIONS.SAVE_CUSTOM_RULE(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                params=(rid, e_name, "", e_cat, e_sev, e_tactic or None, e_tech or None,
                        e_lang, e_source or None, e_code, e_thresh, e_window, e_lookback, e_enabled))
            st.success(f"Rule {res.iloc[0][0]}")
            st.rerun()
    with c2:
        if st.button("Test Rule (Dry Run)", key="test_rule"):
            with st.spinner("Running rule against live data (no findings inserted)..."):
                result = conn.query(
                    "CALL SNOWFLAKE_XDR.DETECTIONS.TEST_CUSTOM_RULE(%s)",
                    params=(rid,))
                raw = result.iloc[0][0]
                if isinstance(raw, str):
                    try:
                        parsed = json.loads(raw)
                    except Exception:
                        parsed = {'status': raw}
                else:
                    parsed = raw
                matches = parsed if isinstance(parsed, list) else parsed.get('matches', parsed)
                if isinstance(matches, list) and len(matches) > 0:
                    st.success(f"Rule would match {len(matches)} events. Sample:")
                    st.json(matches[:5])
                else:
                    st.info(f"No matches in current data. Result: {json.dumps(parsed)[:300]}")
    with c3:
        if st.button("Run Now (Insert Findings)", key="run_now"):
            res = conn.query(
                "CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULES()")
            st.success(res.iloc[0][0])

    # Errors for this rule
    errors = conn.query("""
        SELECT error_time, LEFT(error_message, 120) AS err, stage
        FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_ERRORS
        WHERE rule_id = %s ORDER BY error_time DESC LIMIT 5
    """, params=(rid,))
    if not errors.empty:
        st.markdown("#### Recent Errors")
        st.dataframe(errors, use_container_width=True)

    # Version history for this rule
    st.markdown("#### Version History")
    st.caption("Every save snapshots the previous version — rollback audited in Snowflake")
    history = conn.query("""
        SELECT changed_at, version, LEFT(name, 40) AS name, language,
               severity, enabled, changed_by
        FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_HISTORY
        WHERE rule_id = %s ORDER BY changed_at DESC LIMIT 10
    """, params=(rid,))
    if not history.empty:
        st.dataframe(history, use_container_width=True, hide_index=True)
    else:
        st.info("No saved versions yet — history is snapshotted on every update.")
