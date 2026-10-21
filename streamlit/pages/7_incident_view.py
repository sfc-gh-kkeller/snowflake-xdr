import streamlit as st
import pandas as pd
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Incident View", layout="wide")
show_deprecation_banner("incident_view")
st.title("Incident Investigation")

conn = st.connection("snowflake")

# Incident selector
incidents = conn.query("""
    SELECT incident_id, title, severity, priority, status, primary_entity, first_seen
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
    ORDER BY created_at DESC LIMIT 20
""")

if incidents.empty:
    st.info("No incidents to display. Run detection and correlation first.")
    st.stop()

selected_incident = st.selectbox(
    "Select Incident",
    incidents['INCIDENT_ID'].tolist(),
    format_func=lambda x: f"{incidents[incidents['INCIDENT_ID']==x]['PRIORITY'].iloc[0]} | {incidents[incidents['INCIDENT_ID']==x]['TITLE'].iloc[0]}"
)

if selected_incident:
    # Incident header
    inc = conn.query(f"SELECT * FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE incident_id = '{selected_incident}'")
    if not inc.empty:
        row = inc.iloc[0]
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Severity", f"{row['SEVERITY']}/5")
        col2.metric("Priority", row['PRIORITY'])
        col3.metric("Status", row['STATUS'])
        col4.metric("Duration", f"{(row.get('DURATION_HOURS') or 0):.1f}h")

        st.markdown(f"**Primary Entity:** {row['PRIMARY_ENTITY']} ({row['ENTITY_TYPE']})")
        st.markdown(f"**Description:** {row['DESCRIPTION']}")

        # AI Campaign Story - the attacker narrative
        st.markdown("---")
        st.subheader("AI Campaign Story")
        st.caption("Cortex AI narrates how this incident's events connect as an attack campaign")
        if st.button("Generate Campaign Story", type="primary"):
            with st.spinner("Cortex AI is tracing paths and writing the campaign narrative..."):
                try:
                    import json
                    r = conn.query(
                        "CALL SNOWFLAKE_XDR.INCIDENTS.AI_CAMPAIGN_STORY(%s)",
                        params=(selected_incident,), ttl=0)
                    story = json.loads(r.iloc[0][0]).get("story", "")
                    st.markdown(story)
                except Exception as e:
                    st.error(f"Story generation failed: {e}")

    # Kill Chain Progression
    st.markdown("---")
    st.subheader("Kill Chain Progression")
    kc = conn.query(f"""
        SELECT stage_order, tactic_name, finding_count, first_observed, last_observed
        FROM SNOWFLAKE_XDR.INCIDENTS.KILL_CHAIN_PROGRESSION
        WHERE incident_id = '{selected_incident}'
        ORDER BY stage_order
    """)
    if not kc.empty:
        # Visual kill chain
        stages = kc['TACTIC_NAME'].tolist()
        st.markdown(" → ".join([f"**{s}**" for s in stages]))
        st.dataframe(kc, use_container_width=True)
    else:
        st.info("No kill chain data yet.")

    # Entity Graph
    st.markdown("---")
    st.subheader("Entity Relationship Graph")
    graph = conn.query(f"""
        SELECT src_entity_type, src_entity_value,
               relationship_type,
               dst_entity_type, dst_entity_value,
               event_count, first_seen
        FROM SNOWFLAKE_XDR.INCIDENTS.ENTITY_GRAPH
        WHERE incident_id = '{selected_incident}'
        ORDER BY first_seen
    """)
    if not graph.empty:
        for _, edge in graph.iterrows():
            st.markdown(f"  `{edge['SRC_ENTITY_VALUE']}` ({edge['SRC_ENTITY_TYPE']}) "
                       f"--[{edge['RELATIONSHIP_TYPE']}]--> "
                       f"`{edge['DST_ENTITY_VALUE']}` ({edge['DST_ENTITY_TYPE']}) "
                       f"[{edge['EVENT_COUNT']} events]")
    else:
        st.info("No entity graph data.")

    # Attacker Timeline
    st.markdown("---")
    st.subheader("Attacker Timeline")
    timeline = conn.query(f"""
        SELECT event_time, action_summary, tactic_id, technique_id,
               actor_entity, target_entity
        FROM SNOWFLAKE_XDR.INCIDENTS.ATTACKER_TIMELINE
        WHERE incident_id = '{selected_incident}'
        ORDER BY event_time
    """)
    if not timeline.empty:
        st.dataframe(timeline, use_container_width=True)
    else:
        st.info("No timeline data.")

    # Associated Findings
    st.markdown("---")
    st.subheader("Associated Findings")
    findings = conn.query(f"""
        SELECT f.finding_id, f.rule_id, f.detection_time, f.severity, f.confidence,
               f.category, f.mitre_technique_id, LEFT(f.description, 200) as description,
               f.detection_source
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
        WHERE f.incident_id = '{selected_incident}'
        ORDER BY f.event_time
    """)
    if not findings.empty:
        st.dataframe(findings, use_container_width=True)
