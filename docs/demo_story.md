# XDR Demo Story — Snowflake-Native Security Analytics

A talk track for demoing this account, from the coexistence pitch to the
live XDR platform.

## The Hook: The SIEM Cost Problem

Traditional SIEM architectures force a trade-off: ingest everything into Splunk
(expensive) or lose visibility. The numbers:

| | All-Splunk | Hybrid (Splunk + Snowflake) |
|---|---|---|
| Ingestion cost | $$$$$$ | $$ (**70-80% savings**) |
| Real-time detection | Full | Critical data subset |
| Historical investigation | Limited by cost | **Years of data** |
| Retention/compliance | Very expensive | Cheap (years) |

- Splunk Cloud: ~$1,500-$3,000 per GB/year
- Snowflake: ~$276-$480 per TB/year — **50-100x cheaper** for historical data

Run `python3 tools/savings_calculator.py --total <daily GB>` (from the
Splunk_Connect repo) to personalize this with the prospect's own volumes.

## The Strategy: Route, Don't Rip

```
ALL LOG SOURCES (Firewall, EDR, Auth, Cloud, Web, DNS)
        |
   ROUTING LAYER (Vector / Kafka / Cribl)
       |                    |
 ALL DATA            CRITICAL ONLY (~20%)
       |                    |
   SNOWFLAKE              SPLUNK
 (Security Data Lake)   (Real-time Detection)
 Years of retention      30-90 day retention
 Threat hunting           ES detections
```

Keep 7-30 days in Splunk for real-time; keep 1-5 years in Snowflake for
investigations and compliance. Federated search (DB Connect today, native
SPL integration GA July 2026) bridges the gap. See
[docs/splunk_xdr_demo_queries.md](splunk_xdr_demo_queries.md).

## The Demo: Three Chapters on One Account

### Chapter 1 — The Data Lake (coexistence)

The `CTF` database holds a pre-built security data lake:

- `ACCESS_LOGS` — 100,000 rows of web access logs with realistic attack
  patterns (SQL injection, XSS, path traversal, brute force)
- `ASSET_INVENTORY` — 844 servers with OS, specs, cloud provider
- `VULNERABILITIES` — 15,000 vulnerability scan results
- `SECURITY_FINDINGS` — 106 findings derived from access-log anomalies

Show a Splunk dashboard querying this via DB Connect (import
`snowflake_security_lake.xml` from the Splunk_Connect repo). Point: "your
Splunk dashboards keep working — the data lives in Snowflake at 1/50th the
storage cost."

### Chapter 2 — Snowflake-Native XDR (the replacement)

Now flip the story: Snowflake doesn't just store logs — it **detects,
correlates, and investigates**. The `SNOWFLAKE_XDR` database contains:

- **8 CIM-compatible log tables** with ~90,000 events across 7 days, including
  5 embedded attack campaigns (brute force chain, phishing-to-ransomware,
  cloud privilege escalation, insider exfiltration, web app exploitation)
- **30 detection rules** (19 active procedures) mapped to MITRE ATT&CK
- **Incident correlation** with kill-chain tracking and entity graphs
- **3 Cortex AI agents**: detection re-analysis, automated triage with
  FP-probability scoring, and proactive threat hunting

Live commands (run on `XDR_WH`):

```sql
-- See what the detection engine found
SELECT rule_id, severity, user_name, description
FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
ORDER BY severity DESC;

-- Show the correlated incident with its kill chain
SELECT incident_id, description, severity, kill_chain_stages_observed
FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS;

-- AI triage in action: LLM-scored false-positive probabilities
SELECT finding_id, ai_fp_probability, ai_explanation, status
FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
WHERE ai_fp_probability IS NOT NULL;

-- Let the hunting agent loose
CALL SNOWFLAKE_XDR.DETECTIONS.AI_HUNTING_AGENT('lateral_movement', 24);
```

### Chapter 3 — Where This Goes (the close)

- Splunk ES is a rules engine on expensive storage; this is the same
  detections + AI reasoning + unlimited retention on Snowflake economics.
- The detection rules are the same analytics your Splunk Content Management
  already knows — mapped 1:1 to MITRE ATT&CK, with the originating Splunk
  analytic story and detection name stored on every rule.
- Add Cortex Agents/Streamlit for the SOC UI; add Snowflake Horizon for
  governance; keep Splunk only for the real-time 20% — or migrate it too when
  Federated Search GA makes the query language a non-issue.

## Key Talking Points

- "70-80% ingestion savings" — routing, not ripping
- "50-100x cheaper retention" — investigations over years, not 90 days
- "The same MITRE ATT&CK coverage, with an LLM triaging your queue"
- "Your Splunk dashboards keep working — today via DB Connect, natively next year"
