# XDR Console

The analyst UI for Snowflake XDR — a Next.js app on Snowflake App Runtime,
deployed as the application service `SNOWFLAKE_XDR.DASHBOARDS.XDR_CONSOLE`.
It replaces the deprecated `XDR_SOC` Streamlit app.

## How it works

```
browser ──▶ POST /api/xdr/<handler-name>  { params }
              │
              ▼
        lib/handlers/*      named handlers: validate params, bind values (?)
              │
              ▼
        lib/xdr.ts          rows() / one() / scalar(): normalize keys, numbers,
              │             timestamps, VARIANT JSON
              ▼
        lib/snowflake.ts    template SDK helper (owner's rights in SPCS)
```

- **The client never sends SQL.** Every query and procedure call is a named
  handler in `lib/handlers/`; `app/api/xdr/[name]/route.ts` dispatches only
  registered names. Unknown names return 404, invalid input 400.
- **User values are always binds.** Enums are allow-listed (`oneOf`, `listOf`),
  numbers are clamped (`int`), ids match `^[A-Za-z0-9_-]{1,64}$`, entities a
  conservative charset.
- **Cortex AI calls** (briefings, stories, agent, hunting) use
  `querySnowflakeLongRunning` so they survive long LLM runs.
- AI output is rendered by `components/xdr/markdown.tsx`, which builds React
  elements only — no raw HTML.

| Path | Contents |
|---|---|
| `app/<route>/page.tsx` | 12 views (`/`, `/triage`, `/investigations`, `/entity`, `/attack-graph`, `/live`, `/hunt`, `/ask`, `/detections`, `/rules`, `/response`, `/posture`) |
| `components/views/` | One client component per view |
| `components/xdr/` | Kit (panels, KPIs, badges, forms, drawer), data table, charts (recharts), graph canvas (React Flow), markdown |
| `lib/handlers/` | Server handlers by area: overview, triage, investigate, operate, engineer |
| `lib/client.ts` | `useXdr` / `useXdrAction` (TanStack Query) |
| `lib/graph.ts` | Layered graph layout |

The SQL in the handlers was ported from the Streamlit pages in `../streamlit/pages/`.

## Develop locally

```bash
npm install
SNOWFLAKE_CONNECTION_NAME=aws_demo_kevin npm run dev    # http://localhost:3000
npm test                                                # vitest, Snowflake mocked
```

Pin `SNOWFLAKE_CONNECTION_NAME`: local dev otherwise uses your default
connection, which may be a different account.

## Deploy

```bash
snow app validate -c aws_demo_kevin
snow app deploy --verbose -c aws_demo_kevin     # remote build + promote, ~2 min
snow app open --print-only -c aws_demo_kevin    # console URL
snow app events --last 200 -c aws_demo_kevin    # live service logs
```

`app.yml` (version 2) holds both the deployment config (database, schema,
warehouse) and the build phases. `../scripts/deploy_demo.sh` runs the deploy as
part of the end-to-end build and records the URL in
`REFERENCE.PLATFORM_SETTINGS` for the legacy app's deprecation banner.

## Data access

The service runs with **owner's rights** (the deploying role). Every viewer sees
the same data and can trigger the same procedures — fine for a demo account. For
production, switch read handlers to `callersRights: true` and gate write
handlers (case updates, rule saves, playbook changes) by role.
