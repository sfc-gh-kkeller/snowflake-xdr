import streamlit as st
import pandas as pd
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Live Tail", layout="wide")
show_deprecation_banner("live_tail")
st.title("Live Tail")
st.caption("Real-time event stream with per-source ingestion lag")

conn = st.connection("snowflake")

# Emit control (demo driver)
c1, c2 = st.columns([1, 3])
with c1:
    batches = st.number_input("Batches to emit", min_value=1, max_value=20, value=3)
    if st.button("Emit Live Events", type="primary"):
        with st.spinner("Generating telemetry with staggered source delays..."):
            r = conn.query(
                "CALL SNOWFLAKE_XDR.RAW_LOGS.EMIT_LIVE_EVENTS(%s)",
                params=(int(batches),), ttl=0)
            st.success(r.iloc[0][0])

st.markdown("---")

# Source lag health
st.subheader("Source Health & Lag")
lag = conn.query("SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.V_SOURCE_LAG ORDER BY source_table")
if not lag.empty:
    for _, row in lag.iterrows():
        health = row["HEALTH"]
        state = row["MAX_LAG_MIN"]
        if "fresh (known" in str(health):
            color = "🟡"
        elif "STALE" in str(health):
            color = "🔴"
        else:
            color = "🟢"
        st.markdown(
            f"{color} **{row['SOURCE_TABLE']}** - latest event {row['LATEST_EVENT']} "
            f"(ingestion lag up to {int(state)} min) - {health}")
    st.caption("Endpoint (EDR) intentionally lags 20-45 min to demonstrate lagged-source awareness.")

st.markdown("---")

# Live feed table with auto-refresh
@st.fragment(run_every=10)
def live_feed():
    feed = conn.query("""
        SELECT source_table, event_time, ingestion_time, lag_seconds,
               source_state, entity, action, detail
        FROM SNOWFLAKE_XDR.DETECTIONS.V_LIVE_FEED
    """)
    if not feed.empty:
        def state_color(s):
            if s == "real-time":
                return "background-color: #28a745"
            if s == "delayed":
                return "background-color: #ffc107"
            return "background-color: #dc3545"

        display = feed.rename(columns={
            "SOURCE_TABLE": "Source", "EVENT_TIME": "Event Time",
            "INGESTION_TIME": "Ingested", "LAG_SECONDS": "Lag (s)",
            "SOURCE_STATE": "State", "ENTITY": "Entity",
            "ACTION": "Action", "DETAIL": "Detail",
        })
        st.dataframe(
            display.style.apply(lambda row: [state_color(display.loc[row.name, "State"])] * len(row), axis=1)
                .format({"Lag (s)": "{:,.0f}"}),
            use_container_width=True, hide_index=True,
        )
        counts = feed["SOURCE_STATE"].value_counts()
        st.caption(
            f"{counts.get('real-time', 0)} real-time | "
            f"{counts.get('delayed', 0)} delayed | "
            f"{counts.get('lagging', 0)} lagging (auto-refreshes every 10s)"
        )
    else:
        st.info("No recent events. Click 'Emit Live Events' to start the stream.")

live_feed()
