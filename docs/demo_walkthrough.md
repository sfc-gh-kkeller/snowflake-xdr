# XDR Demo Walkthrough

A step-by-step demo script for the XDR platform on
SFSENORTHAMERICA-SECFIELDKELLER (AWS eu-central-1).

- **XDR Console** (current): `cd xdr-console && snow app open -c aws_demo_kevin`
  (the URL is also printed at the end of `scripts/deploy_demo.sh`; it changes
  when the service is recreated by a `--fresh` build)
- XDR_SOC Streamlit (deprecated, kept for reference): https://app.snowflake.com/SFSENORTHAMERICA/secfieldkeller/#/streamlit-apps/SNOWFLAKE_XDR.DASHBOARDS.XDR_SOC

## Before the demo

```bash
scripts/reset_demo_clock.sh        # newest telemetry = now; ~1 minute
```

If the account was rebuilt or anything looks off, `scripts/deploy_demo.sh` is
idempotent and ends with 11 verification checks.

## The story in five minutes

1. **Overview** — 7 KPIs. Call out the two green tiles: findings *covered by
   controls* and *FP auto-suppressed*. "The platform removed noise before an
   analyst saw it." Generate the **Analyst Daily Briefing** (Cortex AI, ~7s).
2. **Attack Graph → Lateral movement** — starts on `host:10.1.5.107`. The graph
   reads top-down: credential spraying against several users (auth failures),
   success on `jsmith`, pivot through `VPN-GW-01` / `WS-042` to `FS-FILE01`, then
   `DC-01` where the edge says **blocked**. Repeated traversals collapse into a
   few unique chains — the deepest is 4 hops. Generate the **AI Campaign Story**.
3. **Triage & Cases** — click a finding to open the case drawer: pivots, evidence,
   **Find similar** (Cortex AI similarity), status/assignee/disposition workflow.
   Select several rows → **Dismiss as FP**; then **Train FP model** + **Apply FP
   scoring** to show the model learning from those verdicts.
4. **Response → Compensating controls** — the controls catalog and the findings
   they mitigate: "genuine, but already handled — nothing hidden".
5. **Ask XDR** — "Which findings were already mitigated by existing controls?"
   The agent uses Cortex Analyst over the `XDR_SECURITY` semantic view and returns
   the count and the top rule (~20–40s).

## Full tour by persona

### SOC analyst

| View | What to show |
|---|---|
| Overview | KPIs, event-time timeline by severity, category mix, recent incidents, top entities, AI briefing |
| Triage & Cases | Filters (status, severity, category, source, search), AI FP %, historical FP %, control coverage, bulk TP/FP, case drawer |
| Investigations | Incident list by risk; kill-chain stepper, entity graph, attacker timeline, linked findings, campaign story, status changes |
| Entity 360 | Search `jsmith`: ~170 events across sources, XDR findings, events by source, **Run AI investigation** |
| Attack Graph | Lateral movement (click a node to re-trace), Door rattling scan, Threat map (auth origins by failures) |
| Live Tail | Emit live events; source-health cards — EDR lags 20–45 min by design; feed auto-refreshes every 10s |
| Threat Hunting | Hunting agent by focus area, detection agent per entity, AI-vs-rules comparison and coverage gaps closed by AI |
| Ask XDR | Chat with the XDR_ANALYST Cortex Agent; tool badges show which tools it used |

### Detection engineer

| View | What to show |
|---|---|
| Detections | Rule library with 7-day hits; MITRE tactic heatmap and technique gap finder; rule health and data freshness |
| Rules & IOCs | **Generate with Cortex AI** from plain English → draft (disabled) → **Test (dry run)** → enable; SQL/Python/JS; version history. IOC add/remove feeds DET-021 |
| Response | Playbooks (severity, threshold, cooldown, action), alert center with delivery status, compensating controls |

Suggested AI rule prompt:

> Detect authentication failures from the same source IP to more than 5 different user accounts within 30 minutes

### CISO

**Security Posture** — 8 KPIs (MTTR, tactic coverage, response success), signal-vs-noise
trend, response health, ATT&CK coverage bars, and the **AI executive report**.

## Response channels on this account

- **Email**: `XDR_EMAIL` notification integration
- **Webhook**: `XDR_WEBHOOK` integration + `RESPONSE.SLACK_WEBHOOK` secret (Slack/Teams format)
- **API**: `RESPONSE.CALL_API` UDF via `XDR_API_EAI` external access integration

All are created by `setup/11b_response_channels.sql`. Playbook evaluation sends
real notifications, so the runner only evaluates them with `--with-notifications`.

## Backend objects (deep-dive audience)

| Object | Purpose |
|---|---|
| `DETECTIONS.RUN_ALL_DETECTIONS()` | 30 built-in rules |
| `DETECTIONS.CUSTOM_RULES`, `RUN_CUSTOM_RULES()`, `AI_GENERATE_RULE()` | Detection-as-code + AI rule builder |
| `INCIDENTS.CORRELATE_INCIDENTS()` | Findings → incidents, kill chain, entity graph, timeline |
| `DETECTIONS.ATTACK_PATH_EDGES`, `BUILD_ATTACK_GRAPH()`, `TRACE_ATTACK_PATHS()` | Graph edges + recursive path tracing |
| `DETECTIONS.DOOR_RATTLING_SCAN()` | One source probing many doors |
| `REFERENCE.SECURITY_CONTROLS`, `DETECTIONS.APPLY_CONTROL_ASSESSMENT()` | Compensating controls |
| `DETECTIONS.FP_PATTERNS`, `TRAIN_FP_MODEL()`, `SCORE_FINDINGS_FP()` | FP model from analyst verdicts |
| `DETECTIONS.AI_CLASSIFY_FINDINGS()` | AI_CLASSIFY categorization |
| `DETECTIONS.FIND_SIMILAR_FINDINGS()` | AI_SIMILARITY |
| `INCIDENTS.AI_CAMPAIGN_STORY()` | Narrative, stored in `INCIDENTS.ai_campaign_story` |
| `DASHBOARDS.XDR_SECURITY` | Semantic view (Cortex Analyst) |
| `DASHBOARDS.XDR_ANALYST` | Cortex Agent |
| `RAW_LOGS.EMIT_LIVE_EVENTS()`, `V_LIVE_FEED`, `V_SOURCE_LAG` | Live tail with lag |
| `REFERENCE.SHIFT_DEMO_TIME()`, `DETECTIONS.DEDUPE_FINDINGS()` | Demo clock + re-run hygiene |
| `DETECTIONS.DETECTION_NOW()`, `REPLAY_DETECTIONS()` | Detection clock + historical backfill |
| `DASHBOARDS.XDR_CONSOLE` | The console (application service) |

## Notes

- Scheduled tasks stay suspended; detections and playbooks run on demand from the
  console. Resume with `ALTER TASK ... RESUME` when needed.
- The console runs with owner's rights. Custom rules execute as the app owner —
  demo account only; production would need an approval workflow for rule changes.
