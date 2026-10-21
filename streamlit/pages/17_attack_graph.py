import streamlit as st
import json
import pandas as pd
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Attack Graph", layout="wide")
show_deprecation_banner("attack_graph")
st.title("Attack Graph & Lateral Movement Explorer")
st.caption("Graph analysis across all telemetry - how an attacker traversed the network")

conn = st.connection("snowflake")

# Build graph control
col1, col2, col3 = st.columns([2, 1, 1])
with col1:
    if st.button("Rebuild Attack Graph", type="primary"):
        with st.spinner("Building edges from all telemetry..."):
            r = conn.query("CALL SNOWFLAKE_XDR.DETECTIONS.BUILD_ATTACK_GRAPH()", ttl=0)
            st.success(r.iloc[0][0])
with col2:
    if st.button("Run Door-Rattling Scan"):
        with st.spinner("Scanning for door-rattling behavior..."):
            r = conn.query("CALL SNOWFLAKE_XDR.DETECTIONS.DOOR_RATTLING_SCAN()", ttl=0)
            st.success(r.iloc[0][0])
with col3:
    if st.button("Refresh Entity List"):
        st.cache_data.clear()

# Entity selector
@st.cache_data(ttl=120)
def load_entities():
    return conn.query("""
        SELECT src_entity, COUNT(DISTINCT dst_entity) AS fan_out, COUNT(*) AS edges
        FROM SNOWFLAKE_XDR.DETECTIONS.ATTACK_PATH_EDGES
        GROUP BY 1
        ORDER BY fan_out DESC
        LIMIT 200
    """)

entities = load_entities()
if entities.empty:
    st.info("No attack graph edges yet. Click 'Rebuild Attack Graph' first.")
    st.stop()

options = [f"{r.SRC_ENTITY}  ({int(r.FAN_OUT)} doors)" for r in entities.itertuples()]
selected_idx = st.selectbox(
    "Start entity (sources with the most doors first)",
    range(len(options)),
    format_func=lambda i: options[i],
)
entity = entities.iloc[selected_idx]["SRC_ENTITY"]

st.markdown("---")

# Trace paths
if st.button("Trace Attack Paths", type="primary"):
    with st.spinner(f"Tracing multi-hop paths from {entity}..."):
        r = conn.query(
            "CALL SNOWFLAKE_XDR.DETECTIONS.TRACE_ATTACK_PATHS(%s)",
            params=(entity,), ttl=0,
        )
        result = json.loads(r.iloc[0][0])
        paths = result.get("paths", [])

    if not paths:
        st.warning(f"No outbound paths found from {entity}.")
    else:
        # Sort by hops desc
        paths.sort(key=lambda p: p.get("hops", 0), reverse=True)
        st.subheader(f"Paths from {entity}")
        st.caption(f"{len(paths)} paths found. Deep paths (3+ hops) and paths reaching domains are flagged suspicious.")

        # Render the deepest path as a graphviz chart
        best = paths[0]
        ents = best.get("entities", [])
        edges = best.get("edges", [])
        dot_lines = ["digraph attack {", '  rankdir=LR;', '  bgcolor="transparent";',
                     '  node [shape=box, style="rounded,filled", fillcolor="#e74c3c", fontcolor="white", color="#c0392b"];']
        for i, e in enumerate(ents):
            color = "#e74c3c" if i > 0 else "#8e44ad"
            dot_lines.append(f'  n{i} [label="{e}", fillcolor="{color}"];')
        for i, ed in enumerate(edges):
            label = f"{ed.get('type','')}: {ed.get('action','')}"
            dot_lines.append(f'  n{i} -> n{i+1} [label="{label}"];')
        dot_lines.append("}")
        st.graphviz_chart("\n".join(dot_lines))

        # Path details table
        st.markdown("### Path Details")
        rows = []
        for p in paths[:10]:
            rows.append({
                "Hops": p.get("hops"),
                "Chain": " -> ".join(p.get("entities", [])),
                "Suspicious": "YES" if p.get("suspicious") else "",
                "Last Seen": p.get("last_seen"),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        # The campaign story button
        st.markdown("### AI Campaign Story")
        st.caption("Generate an AI narrative of the attack campaign")
        if st.button("Generate Campaign Story"):
            with st.spinner("Cortex AI is writing the campaign narrative..."):
                try:
                    inc = conn.query(
                        "SELECT incident_id FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS "
                        "WHERE primary_entity = %s ORDER BY created_at DESC LIMIT 1",
                        params=(entity.replace("host:", "").replace("user:", ""),), ttl=0)
                    if not inc.empty:
                        r2 = conn.query(
                            "CALL SNOWFLAKE_XDR.INCIDENTS.AI_CAMPAIGN_STORY(%s)",
                            params=(inc.iloc[0][0],), ttl=0)
                        story = json.loads(r2.iloc[0][0]).get("story", "")
                        st.markdown(story)
                    else:
                        st.info("No incident linked to this entity - correlate findings first.")
                except Exception as e:
                    st.error(f"Story generation failed: {e}")

st.markdown("---")

# Door-rattling findings
st.subheader("Door-Rattling Findings")
rattle = conn.query("""
    SELECT src, description, severity, risk_score, status, detection_time
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE rule_id = 'GRAPH-RATTLE-001'
    ORDER BY detection_time DESC LIMIT 10
""")
if not rattle.empty:
    st.dataframe(rattle, use_container_width=True, hide_index=True)
else:
    st.info("No door-rattling findings. Run the scan above.")
