# Splunk DB Connect — XDR Demo Queries

This guide shows how to query the Snowflake XDR platform from Splunk using DB Connect
(`dbxquery`). The schema is Splunk CIM-compatible, so no field aliasing is needed.

## 1. DB Connect Setup

1. Install the **Splunk DB Connect** app on your Splunk instance.
2. Add an identity (Snowflake user) and a connection:
   - **Type**: Snowflake
   - **Account**: your Snowflake account identifier (e.g. `SFSENORTHAMERICA-SECFIELDKELLER`)
   - **Warehouse**: `XDR_WH`
   - **Database**: `SNOWFLAKE_XDR`
3. Set the connection's default schema to `SPLUNK_VIEWS`.

Available views (all CIM-aligned): `V_AUTHENTICATION`, `V_ENDPOINT_PROCESSES`,
`V_ENDPOINT_FILESYSTEM`, `V_ENDPOINT_REGISTRY`, `V_NETWORK_TRAFFIC`, `V_DNS`,
`V_WEB`, `V_CLOUD_CHANGE`, `V_INTRUSION_DETECTION`, `V_ALL_EVENTS`.

## 2. Investigating XDR Findings from Splunk

The XDR detection engine writes findings to
`SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS`. Splunk can join its own indexed
data against these findings:

```
| dbxquery query="
    SELECT rule_id, description, severity, user_name, src, dest,
           detection_time, ai_fp_probability, status
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE detection_time > DATEADD('hour', -24, CURRENT_TIMESTAMP())
    ORDER BY severity DESC, detection_time DESC"
    connection="snowflake_xdr"
```

## 3. Brute Force Hunting (CIM Authentication)

```
| dbxquery query="
    SELECT src, user_name, COUNT(*) AS failures,
           MIN(_time) AS first_seen, MAX(_time) AS last_seen
    FROM SNOWFLAKE_XDR.SPLUNK_VIEWS.V_AUTHENTICATION
    WHERE action = 'failure'
      AND _time > DATEADD('hour', -1, CURRENT_TIMESTAMP())
    GROUP BY src, user_name
    HAVING COUNT(*) >= 10
    ORDER BY failures DESC"
    connection="snowflake_xdr"
```

## 4. Impossible Travel (CTE)

```
| dbxquery query="
    WITH logins AS (
        SELECT user_name, _time, src, geo_country
        FROM SNOWFLAKE_XDR.SPLUNK_VIEWS.V_AUTHENTICATION
        WHERE action = 'success'
          AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
    )
    SELECT a.user_name,
           a.geo_country AS country_a,
           b.geo_country AS country_b,
           a._time AS login_a,
           b._time AS login_b,
           TIMESTAMPDIFF('minute', a._time, b._time) AS minutes_apart
    FROM logins a
    JOIN logins b
      ON a.user_name = b.user_name
     AND a._time < b._time
     AND TIMESTAMPDIFF('minute', a._time, b._time) < 60
     AND a.geo_country != b.geo_country"
    connection="snowflake_xdr"
```

## 5. Hybrid Join — Splunk Alerts + Snowflake XDR Findings

Join Splunk-indexed alerts (e.g. from IDS) against XDR findings for the same
source IP:

```
`notable` src=*
| lookup snowflake_xdr_findings src OUTPUT rule_id, severity, status
| stats count by src, rule_id, severity, status
```

Or push a Splunk search's result set into a Snowflake comparison:

```
| dbxquery query="
    SELECT f.src, f.rule_id, f.severity,
           (SELECT COUNT(*) FROM CTF.PUBLIC.ACCESS_LOGS a
            WHERE a.IP_ADDRESS = f.src
              AND a.STATUS_CODE >= 400) AS web_errors_same_ip
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
    WHERE f.status = 'investigating'"
    connection="snowflake_xdr"
```

This last query joins XDR findings against the pre-built CTF demo dataset
(`CTF.PUBLIC.ACCESS_LOGS`, 100K rows of web attack logs) — a good way to show
"one Snowflake account, many security data sources" in a single Splunk panel.

## 6. Incident Drill-Down

```
| dbxquery query="
    SELECT i.incident_id, i.description, i.severity, i.priority,
           i.kill_chain_stages_observed, i.first_event_time, i.last_event_time,
           f.rule_id, f.user_name
    FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS i
    JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
      ON f.incident_id = i.incident_id
    ORDER BY i.severity DESC, i.first_event_time DESC"
    connection="snowflake_xdr"
```

## 7. Scheduled Alert: New Critical Findings

Create a Splunk scheduled alert (every 5 minutes) that pages the SOC when XDR
emits a severity-5 finding:

```
| dbxquery query="
    SELECT finding_id, rule_id, description, user_name, src, severity
    FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
    WHERE severity = 5
      AND detection_time > DATEADD('minute', -5, CURRENT_TIMESTAMP())"
    connection="snowflake_xdr"
| eval urgency=severe
```

## 8. Dashboard Starting Point

For an import-ready Splunk dashboard (KPI panels, request method distribution,
status code breakdown, CTE risk assessment, Z-score anomaly detection), see the
companion repo: `Splunk_Connect/splunk/dashboards/snowflake_security_lake.xml`.
Paste it into **Settings > User Interface > Dashboards > Create New Dashboard >
Source (XML)** and point its dbxquery searches at `SNOWFLAKE_XDR` views and
`CTF.PUBLIC` tables.

## Migration Path — Native Federated Search

Cisco announced **Splunk Federated Search for Snowflake** at .conf25 with GA
planned for July 2026 on Splunk Cloud AWS. When GA arrives, only the query
syntax changes (`from snowflake://...`), the Snowflake data model stays
identical — everything above keeps working.
