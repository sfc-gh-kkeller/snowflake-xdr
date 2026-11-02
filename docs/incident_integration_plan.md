# Phase 3 plan: incident reporting and tracking (Jira, ServiceNow, native)

Status: built. Files: `setup/32_incident_tracking.sql`, `setup/33_ticketing.sql`, the console
**Cases & Tickets** view, and the receiver's `/v1/webhooks/{connection}` route. See the README
section "Cases, tickets and incident reports".

How the build differs from this plan:

- **Field and state maps:** these live in each connection's `config` JSON rather than separate
  `TICKET_FIELD_MAPS` / `TICKET_STATE_MAPS` tables. That makes a connection one editable document.
- **Owner system:** the ticket system is fixed as the workflow owner once a ticket exists; there is
  no per-incident `owner_system` column.
- **Demo connector:** a `mock` connector (a tracker kept in Snowflake) carries the demo round trip.
- **Testing:** the Jira and ServiceNow connectors follow their documented REST APIs but have not
  been run against a live site. The mock path and the HTTPS webhook path were tested end to end.

Original plan below.

## Goal

An XDR incident becomes a ticket where the customer already works, stays in sync both
ways, and closes with a report, without the analyst copying anything by hand.

Three targets share one model:

- **Jira**: Jira Software, or Jira Service Management for SOC teams that run on JSM.
- **ServiceNow**: Security Incident Response (`sn_si_incident`) when SecOps is licensed,
  otherwise ITSM `incident`.
- **Native XDR case management**: for customers with neither, and as the system of
  record either way, since the XDR always keeps its own history.

Design rule: **the XDR incident is the source of truth for detection data** (findings,
entities, kill chain, evidence). **The ticket is the source of truth for workflow**
(assignee, state, comments) once it exists. Sync carries each side's fields to the
other; it never overwrites the owner.

## What exists today

| Piece | Where |
|---|---|
| `INCIDENTS.INCIDENTS` (status, severity, priority P1-P5, kill chain, entities, assignee, resolution) | `04_incident_ontology_tables.sql` |
| Correlation of findings into incidents, timelines, entity graph | `08_incident_correlation.sql` |
| Playbooks firing email / Slack / Teams / generic API calls through `XDR_API_EAI` | `11b_response_channels.sql`, `13_response_playbooks.sql` |
| Agent action `set_incident_status`, console Investigations view | `24_agent_actions.sql`, `xdr-console` |
| Calibrated confidence and HITL dispositions on findings | `29_confidence.sql` |

What is missing: an incident lifecycle with an audit trail, outbound ticket
creation, inbound status sync, field mapping per customer, and a report.

## Architecture

```
               XDR incident (INCIDENTS)                         Jira / ServiceNow
  correlate ──▶ incident created / escalated ──▶ OUTBOX ──▶ SYNC_TICKETS (EAI) ──▶ create / update ticket
                     ▲                                                               │
                     │  apply (state map, comments)       poll (task, 1-2 min)        │
  INCIDENT_EVENTS ◀──┴──────────── TICKET_INBOX ◀───────────┬────────────────────────┘
  (audit trail)                                             │ push (optional): Jira Automation /
                                                            │ ServiceNow outbound REST -> receiver
                                                            ▼ /v1/webhooks/{system}
```

- **Transactional outbox.** Every incident change that should reach a ticket writes an
  `INCIDENT_OUTBOX` row in the same transaction as the change. A task drains it. Ticket
  creation is never coupled to correlation, and a ticketing outage only delays sync.
- **Idempotency.** Each outbound call carries the XDR incident id as an external
  reference:
  - Jira: an issue property `xdr.incident_id`, plus a label for JQL.
  - ServiceNow: `correlation_id` plus `correlation_display = 'Snowflake XDR'`.

  A retry first looks up that reference, so a retry can never create a second ticket.
- **One connector interface.** `create`, `update`, `comment`, `transition`, `fetch_changes`.
  Jira, ServiceNow and native implement the same five calls, so routing, retries and
  the console do not care which system is behind them.

## Data model (`setup/32_incident_tracking.sql`)

| Table | Purpose |
|---|---|
| `INCIDENT_EVENTS` | Append-only audit trail: status change, assignment, comment, finding added, ticket linked, sync error, report generated. Who (user, agent, autopilot, ticket system), when, before/after. This makes native tracking and compliance reporting work. |
| `INCIDENT_TASKS` | Response tasks per incident (contain host, reset credentials, notify legal): owner, due, done. Playbooks can create them; Jira sub-tasks or ServiceNow response tasks can mirror them. |
| `TICKET_CONNECTIONS` | One row per configured target: system (`jira`, `jsm`, `servicenow_sir`, `servicenow_itsm`), base URL, project / assignment group, secret name, enabled, routing filter. |
| `TICKET_FIELD_MAPS` | Per connection: XDR field → target field, with a transform (`severity → priority`, `priority → urgency + impact`, MITRE technique → label / custom field). Editable in the console; validated against the target's field metadata. |
| `TICKET_STATE_MAPS` | Per connection: target workflow state ↔ XDR status (`In Progress → investigating`, ServiceNow SIR `Contain → contained`, `Resolved` / `Closed` → `closed`, plus resolution code mapping). |
| `INCIDENT_TICKETS` | Link table: incident_id, connection, external key / sys_id, URL, last synced hash, last inbound timestamp, sync status, last error. |
| `INCIDENT_OUTBOX` | Pending outbound operations (op, payload, attempts, next_attempt_at, status). |
| `TICKET_INBOX` | Raw inbound changes from polling or push, processed once (dedupe on system + key + updated timestamp). |
| `INCIDENT_SLA_POLICY` | Per priority: time to acknowledge, contain and resolve. Breaches become `INCIDENT_EVENTS` and can trigger playbooks. |

`INCIDENTS` gains a few columns:

- `acknowledged_at`, `contained_at`, `sla_due_at`;
- `report_artifact`;
- `owner_system`: `xdr` or the connection that owns workflow.

## Outbound: creating and updating tickets

**When an incident gets a ticket** (routing rules on `TICKET_CONNECTIONS`, evaluated in order):

- priority P1/P2, or severity ≥ 4 with confidence band `high`, creates a ticket immediately;
- lower priorities create one on analyst escalation, or when an agent or playbook calls
  `create_ticket`;
- findings auto-suppressed or dismissed by the confidence model never create tickets.
  This is where phase 1.5's FP control pays off downstream: ticket noise is the cost
  customers notice most.

**Ticket content**, built by `BUILD_TICKET_PAYLOAD(incident_id, connection)`:

- title: `[XDR P1] Credential brute force → lateral movement: tlee (bastion-01)`;
- summary from the existing incident narrative, with confidence and its main factors;
- entities, MITRE tactics/techniques, kill-chain stage, first/last seen;
- top findings with rule, evidence count and a console deep link
  (`<console>/investigations?id=...`);
- recommended actions from the matching playbook.

Long evidence goes as an attachment (JSON / CSV), not into the description.

**Jira** (REST v3, Cloud):

- **Calls:**
  - `POST /rest/api/3/issue`, description in Atlassian Document Format;
  - `PUT /rest/api/3/issue/{key}` for updates;
  - `POST /rest/api/3/issue/{key}/comment`;
  - `POST /rest/api/3/issue/{key}/transitions`.

  Transition ids are discovered from `GET .../transitions`, not hard-coded, because
  workflows differ per project.
- **JSM:** `POST /rest/servicedeskapi/request` when the customer uses a service desk
  request type.
- **Auth:** Atlassian account email plus API token in a `PASSWORD` secret, or OAuth 2.0
  (3LO) through an `API_AUTHENTICATION` security integration and an `OAUTH2` secret.
- **Network:** a network rule for `<site>.atlassian.net` and `api.atlassian.com`.

**ServiceNow** (Table API):

- **Calls:**
  - `POST /api/now/table/sn_si_incident` (or `/incident`);
  - `PATCH /api/now/table/<table>/{sys_id}`;
  - work notes through the `work_notes` field.
- **Auth:** OAuth (client credentials or refresh token via an `API_AUTHENTICATION`
  integration), or basic auth for a dedicated integration user.
- **SIR roles:** the integration user needs the SIR integration role (`sn_si.integration_user`).
- **Fields to map:** `short_description`, `description`, `priority` (or `urgency` +
  `impact`), `assignment_group`, `category` / `subcategory`, `correlation_id`; on
  close, `close_code` + `close_notes`.
- **Optional:** observables (IPs, hashes, domains) through the SIR observable tables, so
  ServiceNow threat-intel lookups run on XDR indicators.

**Implementation.**

- One Python procedure `SYNC_TICKETS()` drains the outbox, using
  `EXTERNAL_ACCESS_INTEGRATIONS = (XDR_TICKETING_EAI)` and one secret per connection.
- Failure handling: retries with exponential backoff, and `429` / `Retry-After`
  handling.
- After N failures the error is written to `INCIDENT_TICKETS.last_error`, and an
  `INCIDENT_EVENTS` row makes it visible in the console. Nothing is dropped silently.

## Inbound: keeping the XDR in sync

Analysts often work the ticket, not the XDR. State changes, assignee and comments
made there must flow back.

**Default: polling** (works everywhere, no inbound network path needed):

- Jira: JQL `issue.property[xdr.incident_id].exists = true AND updated >= "-5m"`, or the
  label as a fallback, every 1-2 minutes.
- ServiceNow: `sysparm_query=correlation_display=Snowflake XDR^sys_updated_on>=<watermark>`.
- Changes land in `TICKET_INBOX`. `APPLY_TICKET_CHANGES()` then maps state through
  `TICKET_STATE_MAPS`, copies comments into `INCIDENT_EVENTS` (with their origin
  marked, so they are never echoed back), and updates assignee and resolution.

**Optional: push** for sub-minute sync:

- **The constraint:** the SPCS public endpoint authenticates every caller with Snowflake,
  so a sender must send `Authorization: Snowflake Token="<PAT>"`.
  - Jira's native admin webhooks cannot add custom headers. They sign payloads with
    HMAC-SHA256 in `X-Hub-Signature` instead.
  - Jira **Automation** "Send web request" and ServiceNow outbound REST messages can set
    headers. Those two are the supported push paths.
- **The receiver:** the phase-2 receiver gains `POST /v1/webhooks/{connection}`. It:
  - writes to `TICKET_INBOX` through an owner's-rights procedure, the same pattern as
    `INGEST_OTLP_LOGS`;
  - verifies an HMAC secret per connection as a second factor;
  - rejects replays (deduplicated on the delivery id and the updated timestamp).
- Polling stays on as a reconciliation pass, because webhooks can be lost.

**Conflict rules:**

- workflow fields: the owner system wins (`owner_system`);
- detection fields: the XDR wins;
- comments: append-only on both sides;
- when the XDR adds new findings to an incident whose ticket is closed, the sync
  reopens the ticket (or creates a linked follow-up, per connection setting) instead of
  quietly attaching data to a closed ticket.

## Native incident report and tracking

For customers without Jira or ServiceNow, and as a better view for those with them.

- **Lifecycle:** `new → acknowledged → investigating → contained → eradicated → recovered →
  closed` (NIST 800-61 phases), with resolution codes (`true_positive`, `benign`,
  `false_positive`, `duplicate`, `test`). Every transition is an `INCIDENT_EVENTS` row
  with actor and reason. Agent and autopilot transitions are marked as such, the same
  provenance rule as `disposition_source` in phase 1.5.
- **Console Cases view:**
  - board and list by status;
  - SLA timers and breach markers;
  - tasks;
  - timeline built from `INCIDENT_EVENTS` merged with attacker activity from
    `ATTACKER_TIMELINE`;
  - comments;
  - a linked-ticket chip with sync status.
- **Incident report:** `GENERATE_INCIDENT_REPORT(incident_id)` writes an HTML/Markdown
  report.
  - **Contents:**
    - executive summary;
    - timeline;
    - affected entities;
    - ATT&CK mapping;
    - evidence tables;
    - actions taken (playbooks, tasks, agent actions);
    - root cause;
    - lessons learned and detection gaps (feeds the autopilot backlog).
  - **How it is written:** Cortex drafts the narrative sections from structured data
    only, and every number in the report comes from SQL, not the model.
  - **Where it goes:** stored as a Snowflake Intelligence report artifact or on a stage,
    linked from the incident and attached to the Jira/ServiceNow ticket on close.
- **Metrics:** MTTA, MTTC and MTTR per priority and source, SLA compliance, reopen rate,
  and tickets per true incident (ticket noise). These go to the CISO Posture view and the
  weekly digest.
- **Agent tools:** `create_ticket`, `get_incident_timeline`, `add_incident_comment`,
  `generate_incident_report`. "Open a P1 in Jira for this and assign it to the IR
  on-call" becomes one request to Ask XDR.

## Security

- Credentials live only in Snowflake secrets. Procedures read them through
  `SECRETS = (...)`; the console never sees them.
- Egress goes only to the hosts in each connection's network rule. Each customer site
  is a separate rule, so adding a connection is a reviewed change.
- Least privilege on the far side: a Jira user limited to the target project; a
  ServiceNow integration user with only the SIR or ITSM integration role.
- Ticket text is built from data and goes out as JSON payloads. It is never
  string-concatenated into SQL. Inbound comments are stored as text and rendered
  escaped in the console.
- Data minimisation: per connection, a setting decides whether raw evidence (`_raw`,
  command lines) may leave Snowflake, or only summaries and links back to the console.

## Work items

1. `32_incident_tracking.sql`:
   - `INCIDENT_EVENTS`, `INCIDENT_TASKS`, SLA policy;
   - lifecycle procedure `SET_INCIDENT_STATE(id, state, reason, actor)`, replacing
     direct updates;
   - backfill events from current incidents.
2. Native Cases view in the console (board, timeline, tasks, SLA), plus the agent tools
   for timeline and comments.
3. `GENERATE_INCIDENT_REPORT` with Cortex narrative over SQL facts, stored as an
   artifact, plus a console "Report" button.
4. `33_ticketing.sql`:
   - connections, field/state maps, link table, outbox and inbox;
   - `XDR_TICKETING_EAI`;
   - the `SYNC_TICKETS` and `APPLY_TICKET_CHANGES` procedures;
   - tasks (suspended by default).
5. Jira connector: create/update/comment/transition, transition discovery, ADF builder,
   JQL polling.
6. ServiceNow connector: SIR and ITSM tables, priority via urgency+impact, close
   codes, polling, optional observables.
7. Receiver `/v1/webhooks/{connection}` with HMAC verification, plus Jira Automation and
   ServiceNow outbound REST examples.
8. Console Integrations page:
   - connections, field-map editor validated against the target's field metadata
     (Jira `createmeta`, ServiceNow `sys_dictionary`);
   - a test button that creates and deletes a ticket;
   - sync log.
9. Metrics (MTTA/MTTC/MTTR, ticket noise) in the Posture view and the digest.
10. Demo: a mock ticketing endpoint for accounts without Jira/ServiceNow, so the
    round trip (create → analyst moves ticket → XDR status follows → close → report
    attached) is demoable offline. Plus a free Jira Cloud / ServiceNow PDI recipe for
    a live demo.

## Decisions to make before building

- **Default target per demo:** Jira Cloud (free tier, quick to set up) or a ServiceNow
  developer instance (SIR is a plugin and may not be available on a PDI).
- **Who owns workflow when a ticket exists:** the recommendation is the ticket system.
  The XDR keeps its own status mirrored, and its incident view shows the ticket as the
  authority.
- **What evidence may leave Snowflake by default:** the recommendation is summary plus
  deep links, with raw evidence opt-in per connection.
