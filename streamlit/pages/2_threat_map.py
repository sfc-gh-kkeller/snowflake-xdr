import streamlit as st
import pandas as pd
from utils.deprecation import show_deprecation_banner

st.set_page_config(page_title="Threat Map", layout="wide")
show_deprecation_banner("threat_map")
st.title("Threat Map")
st.caption("Geographic view of authentication activity, sized by risk")

conn = st.connection("snowflake")

@st.cache_data(ttl=60)
def load_map_data():
    return conn.query("""
        SELECT GEO_LAT, GEO_LON, GEO_CITY, GEO_COUNTRY,
               COUNT(*) as event_count,
               SUM(IFF(action = 'failure', 1, 0)) as failures
        FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
        WHERE GEO_LAT IS NOT NULL AND GEO_LON IS NOT NULL
          AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
        GROUP BY 1, 2, 3, 4
    """)

data = load_map_data()

if data.empty:
    st.info("No geolocated authentication events in the last 7 days.")
else:
    col1, col2 = st.columns([3, 1])
    with col1:
        st.map(data, latitude="GEO_LAT", longitude="GEO_LON", size="failures", color="#FF4C4C")
    with col2:
        st.subheader("Top Risk Locations")
        st.dataframe(
            data.sort_values("failures", ascending=False)
                [["GEO_CITY", "GEO_COUNTRY", "event_count", "failures"]]
                .rename(columns={
                    "GEO_CITY": "City", "GEO_COUNTRY": "Country",
                    "event_count": "Events", "failures": "Failures"
                })
                .head(10),
            use_container_width=True, hide_index=True,
        )

st.markdown("---")

st.subheader("High-Volume Sources (potential brute force)")
sources = conn.query("""
    SELECT src, COUNT(*) as attempts,
           COUNT(DISTINCT user_name) as users_targeted,
           SUM(IFF(action = 'failure', 1, 0)) as failures
    FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
    WHERE _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
      AND src IS NOT NULL
    GROUP BY 1
    ORDER BY failures DESC
    LIMIT 10
""")
if not sources.empty:
    st.dataframe(
        sources.rename(columns={
            "SRC": "Source IP", "ATTEMPTS": "Attempts",
            "USERS_TARGETED": "Users Targeted", "FAILURES": "Failures"
        }),
        use_container_width=True, hide_index=True,
    )

st.subheader("Findings by Category (7 days)")
cat = conn.query("""
    SELECT COALESCE(category, 'other') as category, COUNT(*) as count
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    GROUP BY 1 ORDER BY 2 DESC
""")
if not cat.empty:
    st.bar_chart(cat.set_index("CATEGORY"))
