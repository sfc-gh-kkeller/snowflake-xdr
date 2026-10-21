# Snowflake XDR - Security Analytics Platform

A Snowflake-native XDR/SIEM: telemetry, detections, incident correlation,
attack-graph analysis, Cortex AI agents, response automation and the analyst
UI all run inside one Snowflake account — no external infrastructure.

## What's in it

- **Detection engine** — 30 MITRE ATT&CK-mapped rules (stored procedures), custom
  rules in SQL / Python / JavaScript with an AI rule generator, ML anomaly
  detection with per-user baselines
- **Correlation** — findings grouped into incidents with kill-chain stages, entity
  graphs and attacker timelines
- **Attack graph** — every auth/network/process event becomes a graph edge; a
  recursive query traces multi-hop lateral movement and flags "door rattling"
- **Noise reduction** — an FP model learned from analyst verdicts auto-suppresses
  repeat false positives; a compensating-controls engine marks real findings that
  existing controls already mitigate (`disposition = 'mitigated_by_control'`)
- **Cortex AI** — triage, hunting, detection agents, AI_CLASSIFY categorization,
  semantic similarity, campaign stories, daily briefings, exec reports, and the
  **XDR_ANALYST Cortex Agent** (Cortex Analyst over a semantic view + Cortex Search)
- **Live tail** — streaming telemetry with realistic per-source ingestion lag
- **Response** — playbooks firing email, Slack/Teams webhooks, external API calls
- **XDR Console** — the analyst UI, a Snowflake App Runtime (Next.js) app with
  persona-grouped views for SOC analysts, detection engineers and the CISO
- **Splunk CIM compatible** — DB Connect can query `SPLUNK_VIEWS` directly

## Deploy end to end

One command builds everything on a Snowflake account (role ACCOUNTADMIN) using
the Snowflake CLI:

```bash
scripts/deploy_demo.sh                      # idempotent: safe to re-run, keeps demo state
scripts/deploy_demo.sh --fresh --yes-drop-everything   # drop and rebuild from zero (~18 min)
```

| Option | Effect |
|---|---|
| `--connection NAME` | snow CLI connection (default `aws_demo_kevin`) |
| `--fresh --yes-drop-everything` | Drop `SNOWFLAKE_XDR` and `CTF` (cases, notes, dispositions) and rebuild |
| `--skip-app` | Don't deploy the XDR Console |
| `--skip-ai` | Skip the Cortex AI triage/classification pipeline steps |
| `--legacy-streamlit` | Also redeploy the deprecated `XDR_SOC` Streamlit app (implied by `--fresh`) |
| `--with-notifications` | Evaluate playbooks — sends real email / webhook / API calls |
| `--events-per-day N` | Synthetic telemetry volume on a fresh build (default 5000) |

The runner goes through 8 phases: preflight, teardown (fresh only), schema and code (`setup/*.sql` in
order), data (CTF dataset, synthetic telemetry, the 4-stage campaign, geo seed,
demo clock), the detection → correlation → AI pipeline (on a fresh build this includes a
detection replay over the dataset's historical hot hours), the console deploy, the
legacy app, and 11 verification checks. Logs go to `output/deploy_logs/`.

Before a demo, bring the timestamps back to "now":

```bash
scripts/reset_demo_clock.sh
```

### Slack webhook secret

The webhook token is never stored in the repo. On a build that has to create
`RESPONSE.SLACK_WEBHOOK`, pass it via the environment:

```bash
SLACK_WEBHOOK_TOKEN='T000/B000/XXXX' scripts/deploy_demo.sh --fresh --yes-drop-everything
```

Otherwise a placeholder is stored; set it later with
`ALTER SECRET SNOWFLAKE_XDR.RESPONSE.SLACK_WEBHOOK SET SECRET_STRING = '<token>'`.

## UI

| App | Status | Where |
|---|---|---|
| **XDR Console** | Current | `SNOWFLAKE_XDR.DASHBOARDS.XDR_CONSOLE` (Snowflake App Runtime) — URL printed by the runner, or `cd xdr-console && snow app open` |
| XDR_SOC (Streamlit) | **Deprecated** — shows a banner linking to the console | `SNOWFLAKE_XDR.DASHBOARDS.XDR_SOC` |

Console views:

| Persona | View | Replaces (Streamlit pages) |
|---|---|---|
| SOC analyst | Overview | SOC Overview |
| | Triage & Cases | Triage Queue, Case Management |
| | Investigations | Incident View |
| | Entity 360 | Entity Investigation |
| | Attack Graph (lateral movement, door rattling, threat map) | Attack Graph, Threat Map |
| | Live Tail | Live Tail |
| | Threat Hunting | Hunting Console, Agent Comparison |
| | Ask XDR | Ask XDR |
| Detection engineer | Detections (library, MITRE coverage, health) | Detection Library, MITRE Coverage, Health Monitor |
| | Rules & IOCs | Rule Editor, IOC Manager |
| | Response (playbooks, alert center, controls) | Response Automation, Alert Center |
| CISO | Security Posture | Security Posture |

Console development: see [`xdr-console/README.md`](xdr-console/README.md).

## Splunk DB Connect Integration

The schema uses Splunk CIM field names natively. To query from Splunk:

1. Configure Splunk DB Connect with your Snowflake credentials
2. Point at `SNOWFLAKE_XDR.SPLUNK_VIEWS.V_AUTHENTICATION` (or any view)
3. Data maps directly to CIM — no field aliasing needed

```
| dbxquery query="SELECT * FROM SNOWFLAKE_XDR.SPLUNK_VIEWS.V_AUTHENTICATION WHERE action='failure' AND _time > DATEADD('hour', -1, CURRENT_TIMESTAMP())" connection="snowflake_xdr"
```

## Detection Coverage

| Category | Rules | MITRE Tactics |
|----------|-------|---------------|
| Identity | 6 | Credential Access, Initial Access, Privilege Escalation |
| Endpoint | 8 | Execution, Persistence, Defense Evasion, Credential Access, Impact |
| Network | 7 | Lateral Movement, C2, Exfiltration, Discovery |
| Cloud | 5 | Defense Evasion, Collection, Persistence |
| Application | 4 | Initial Access, Persistence, Collection, Credential Access |

Plus ML anomaly detection (`ML-ANOMALY-001`), door rattling (`GRAPH-RATTLE-001`),
protected-asset access (`DET-019`) and any custom rules.

Rule windows are relative to a detection clock, `DETECTIONS.DETECTION_NOW()`,
which is real time unless `REPLAY_DETECTIONS(days)` is stepping it through past
hours. That lets a freshly generated week of telemetry be detected end to end,
even though the built-in rules only look back 15–60 minutes.

## Synthetic Attack Campaigns

The generator embeds 5 scenarios — brute force chain, phishing to ransomware, cloud
privilege escalation, insider exfiltration, web application exploitation — and
`setup/17_campaign_data.sql` adds a 4-stage lateral-movement campaign:
`10.1.5.107` sprays VPN credentials → lands `jsmith` → `WS-042` → `FS-FILE01` →
`DC-01` (blocked by a firewall control), with DNS beaconing.

## Project Structure

```
snowflake-xdr/
├── scripts/
│   ├── deploy_demo.sh          # end-to-end builder (idempotent / --fresh)
│   └── reset_demo_clock.sh     # move demo timestamps to "now"
├── setup/                      # SQL, run in order by the runner
│   ├── 00_ctf_schema.sql, 00b_ctf_load.sql    # CTF dataset (data/ctf/*.csv.gz)
│   ├── 01 … 10                 # schemas, CIM log tables, detections, correlation, tasks, AI agents
│   ├── 11, 11b, 12, 13         # custom rules, response channels, API UDF, playbooks
│   ├── 14, 15                  # platform ops, semantic view, Cortex Search, ML, posture
│   ├── 16 … 21                 # attack graph, campaign data, controls, FP model, live feed, Cortex Agent
│   └── 22, 23                  # demo seed state, demo clock + dedupe
├── data/ctf/                   # compressed CTF CSVs
├── xdr-console/                # XDR Console (Snowflake App Runtime, Next.js)
├── streamlit/                  # deprecated XDR_SOC Streamlit app
└── docs/                       # demo walkthrough, story, Splunk queries
```

## Requirements

- Snowflake account with ACCOUNTADMIN
- Snowflake CLI 3.26+ (`app.yml` v2 support for the console deploy)
- Cortex AI access (COMPLETE, AI_CLASSIFY, AI_SIMILARITY, Cortex Search, Cortex Agents)
- Snowflake App Runtime enabled on the account (console); Streamlit in Snowflake (legacy app)
- Scheduled tasks are created suspended; the UI runs detections on demand
