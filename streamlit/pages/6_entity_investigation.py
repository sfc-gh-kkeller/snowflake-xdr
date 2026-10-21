import streamlit as st
import json
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Entity Investigation", layout="wide")
show_deprecation_banner("entity_investigation")
st.title("Entity Investigation")

conn = st.connection("snowflake")

st.markdown("""
Search any **user, IP address, or hostname** across all telemetry —
authentication, endpoint, network, DNS, web, cloud, and XDR findings —
then let Cortex AI produce an investigation summary.
""")

col1, col2 = st.columns([3, 1])
with col1:
    entity = st.text_input("Entity (user / IP / hostname)",
                           placeholder="e.g., jsmith or 10.1.5.107", key="entity")
with col2:
    days = st.selectbox("Lookback", [1, 7, 30], index=1, key="days")

if entity:
    with st.spinner(f"Searching all telemetry for {entity}..."):
        result = conn.query(
            "CALL SNOWFLAKE_XDR.DETECTIONS.SEARCH_ENTITY(%s, %s)",
            params=(entity, days))
        raw = result.iloc[0][0]
        data = json.loads(raw) if isinstance(raw, str) else raw

    events = data.get('events', [])
    st.metric("Events Found", len(events))

    if events:
        # Timeline grouped by source
        st.subheader("Activity Timeline")
        import pandas as pd
        rows = []
        for e in events:
            if isinstance(e, str):
                try:
                    e = json.loads(e)
                except Exception:
                    e = {'detail': e}
            rows.append({
                'time': e.get('time', ''),
                'source': e.get('source', ''),
                'action': e.get('action', ''),
                'detail': e.get('detail', '') or e.get('process', '') or e.get('query', '') or e.get('url', ''),
                'user': e.get('user', ''),
                'src': e.get('src', ''),
                'dest': e.get('dest', ''),
            })
        df = pd.DataFrame(rows)
        df['time'] = pd.to_datetime(df['time'], errors='coerce', utc=True)
        df = df.sort_values('time', ascending=False)

        source_counts = df['source'].value_counts()
        c1, c2 = st.columns([1, 3])
        with c1:
            st.caption("Events by source")
            st.bar_chart(source_counts)
        with c2:
            st.dataframe(df, use_container_width=True, height=350)

        # AI investigation
        st.markdown("---")
        st.subheader("AI Investigation Summary")
        if st.button("Run Cortex AI Investigation", type="primary", key="ai_inv"):
            with st.spinner("Cortex AI is analyzing the timeline..."):
                ai = conn.query(
                    "CALL SNOWFLAKE_XDR.DETECTIONS.AI_INVESTIGATE_ENTITY(%s, %s)",
                    params=(entity, days))
                ai_raw = ai.iloc[0][0]
                ai_data = json.loads(ai_raw) if isinstance(ai_raw, str) else ai_raw
            st.markdown(ai_data.get('summary', 'No summary available'))
    else:
        st.info(f"No activity found for {entity} in the last {days} day(s).")
else:
    st.info("Enter an entity above to begin an investigation.")

# Related findings shortcut
st.markdown("---")
st.subheader("Known Suspicious Entities")
suspicious = conn.query("""
    SELECT COALESCE(user_name, src, dest) AS entity, COUNT(*) AS findings,
           MAX(severity) AS max_severity
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE COALESCE(user_name, src, dest) IS NOT NULL
    GROUP BY 1 ORDER BY findings DESC LIMIT 10
""")
if not suspicious.empty:
    st.dataframe(suspicious, use_container_width=True)
