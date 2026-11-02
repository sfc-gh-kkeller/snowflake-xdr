"use client"

import { useState } from "react"
import { Cable, Play } from "lucide-react"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtAgo, fmtNum, fmtTime, truncate } from "@/lib/format"
import {
  PageHeader, Panel, QueryState, Kpi, KpiGrid, Pill, ActionButton, ActionResult, Select, TextInput, Field,
  Empty, JsonView, Disclosure, Drawer,
} from "@/components/xdr/kit"
import { DataTable, type Column } from "@/components/xdr/data-table"

const KINDS = ["okta", "linux_auth", "cloudtrail", "windows", "firewall", "vpn", "proxy", "dns", "edr", "unknown"] as const
const STATUS_TONE: Record<string, string> = {
  mapped: "success", unmapped: "contained", mapping_proposed: "investigating", paused: "dismissed",
  live: "success", draft: "investigating", retired: "dismissed",
}

export function Sources() {
  const status = useXdr<Row>("sources.status", {}, { refetchInterval: 30_000 })
  const list = useXdr<Row[]>("sources.list", {}, { refetchInterval: 30_000 })
  const apply = useXdrAction("sources.apply", { invalidate: ["sources."] })
  const [open, setOpen] = useState<string | null>(null)
  const s = status.data ?? {}
  const all = list.data ?? []
  const waiting = all.filter((r) => r.status === "unmapped" || r.status === "mapping_proposed").length

  const columns: Column[] = [
    { key: "status", label: "Status", render: (r) => <Pill tone={STATUS_TONE[r.status]}>{String(r.status).replace(/_/g, " ")}</Pill> },
    { key: "source_id", label: "Source", className: "font-mono text-xs", render: (r) => (
      <button type="button" className="text-left text-primary hover:underline" onClick={() => setOpen(r.source_id)}>{r.source_id}</button>
    ) },
    { key: "name", label: "Name", wrap: true },
    { key: "kind", label: "Kind" },
    { key: "records_24h", label: "Records 24h", align: "right", render: (r) => fmtNum(r.records_24h) },
    { key: "avg_lag_seconds", label: "Lag", align: "right", render: (r) => r.avg_lag_seconds === null ? "-" : `${fmtNum(r.avg_lag_seconds, 1)}s` },
    { key: "last_received", label: "Last record", render: (r) => r.last_received ? fmtAgo(r.last_received) : "never", sortValue: (r) => r.last_received },
    { key: "mappings", label: "Mapped into", wrap: true, sortable: false, render: (r) => (
      <div className="flex flex-wrap gap-1">
        {(r.mappings as Row[]).map((m) => (
          <span key={m.mapping_id} title={m.error ?? ""} className="rounded border border-border px-1.5 py-0.5 text-[11px]">
            {m.target} <span className="text-muted-foreground">{m.status}{m.status === "live" ? ` · ${fmtNum(m.rows)}` : ""}</span>
            {m.error ? <span className="text-red-600 dark:text-red-400"> · error</span> : null}
          </span>
        ))}
        {r.pending_change_id ? <Pill tone="investigating">autopilot proposal</Pill> : null}
      </div>
    ) },
    { key: "has_token", label: "Token", render: (r) => r.has_token ? "yes" : <span className="text-muted-foreground">service.name</span> },
  ]

  return (
    <div className="space-y-4">
      <PageHeader
        persona="Detection Engineer"
        title="Data Sources"
        description="OpenTelemetry ingestion. Any OTel Collector or OTLP sender ships logs to the XDR receiver; CIM mappings turn each source into the tables every detection already uses. New sources register themselves, and the Detection Autopilot proposes their mapping for approval."
        actions={<ActionButton action={apply} variant="default"><Play className="h-3.5 w-3.5" /> Map new records now</ActionButton>}
      />
      <ActionResult action={apply} />

      <KpiGrid>
        <Kpi label="Records (24h)" value={fmtNum(s.records_24h ?? 0)} hint={`${s.sources_24h ?? 0} sources sending`} />
        <Kpi label="Avg ingest lag" value={s.avg_lag_seconds === null || s.avg_lag_seconds === undefined ? "-" : `${fmtNum(s.avg_lag_seconds, 1)}s`} hint="event time to landed" />
        <Kpi label="Live mappings" value={s.live_mappings ?? "-"} tone={Number(s.failing_mappings) ? "warn" : "good"} hint={`${s.failing_mappings ?? 0} failing`} />
        <Kpi label="Rows mapped into CIM" value={fmtNum(s.rows_mapped ?? 0)} />
        <Kpi label="Waiting for a mapping" value={waiting} tone={waiting ? "warn" : "default"} hint="unmapped or proposal pending" />
      </KpiGrid>

      <Endpoint endpoint={s.endpoint} />

      <Panel title="Sources" description="Click a source for sample records and its mappings.">
        <QueryState q={list}>
          {(rowsList) => <DataTable rows={rowsList} columns={columns} rowKey="source_id" dense empty="No sources yet. Send OTLP logs to the endpoint above." />}
        </QueryState>
      </Panel>

      <Register />

      <Drawer open={!!open} onClose={() => setOpen(null)}>
        {open && <SourceDetail sourceId={open} source={all.find((r) => r.source_id === open)} />}
      </Drawer>
    </div>
  )
}

function Endpoint({ endpoint }: { endpoint?: string | null }) {
  return (
    <Panel
      title={<span className="flex items-center gap-1.5"><Cable className="h-4 w-4 text-primary" />OTLP endpoint</span>}
      description="OTLP/HTTP (protobuf or JSON, gzip). Authenticate with a Snowflake Programmatic Access Token for a user granted XDR_OTLP_SENDER. Add X-XDR-Source-Token to pin records to a registered source; otherwise the resource attribute service.name names the source."
    >
      {endpoint ? (
        <div className="space-y-3">
          <code className="block rounded-md bg-muted px-3 py-2 font-mono text-sm">{endpoint}</code>
          <Disclosure title="OpenTelemetry Collector exporter">
            <pre className="overflow-auto rounded-md bg-slate-950 p-3 font-mono text-xs text-emerald-200">{`exporters:
  otlphttp/xdr:
    logs_endpoint: ${endpoint}
    compression: gzip
    headers:
      Authorization: Snowflake Token="\${env:XDR_PAT}"
      X-XDR-Source-Token: \${env:XDR_SOURCE_TOKEN}   # optional
service:
  pipelines:
    logs:
      receivers: [filelog]
      processors: [batch]
      exporters: [otlphttp/xdr]`}</pre>
            <p className="mt-2 text-xs text-muted-foreground">More examples (Okta, sshd, CloudTrail) in otel-receiver/collector-examples/.</p>
          </Disclosure>
        </div>
      ) : (
        <Empty>Receiver not deployed. Run scripts/deploy_otel_receiver.sh, or call SNOWFLAKE_XDR.RAW_LOGS.INGEST_OTLP_LOGS directly with OTLP/JSON.</Empty>
      )}
    </Panel>
  )
}

function Register() {
  const reg = useXdrAction("sources.register", { invalidate: ["sources."] })
  const [sid, setSid] = useState("")
  const [name, setName] = useState("")
  const [kind, setKind] = useState<(typeof KINDS)[number]>("unknown")
  return (
    <Panel title="Register a source" description="Issues a source token for the X-XDR-Source-Token header. The token is shown once; only its hash is stored. Registering an existing source rotates its token.">
      <div className="flex flex-wrap items-end gap-2">
        <Field label="Source id"><TextInput className="w-48" value={sid} onChange={(e) => setSid(e.target.value)} placeholder="e.g. paloalto_fw" /></Field>
        <Field label="Name"><TextInput className="w-64" value={name} onChange={(e) => setName(e.target.value)} placeholder="Palo Alto edge firewalls" /></Field>
        <Field label="Kind"><Select value={kind} onChange={setKind} options={KINDS.map((k) => ({ value: k, label: k.replace(/_/g, " ") }))} className="w-40" /></Field>
        <ActionButton action={reg} variant="default" params={{ source_id: sid, name, kind }} disabled={!sid.trim()}>Register / rotate token</ActionButton>
      </div>
      <ActionResult action={reg} />
    </Panel>
  )
}

function SourceDetail({ sourceId, source }: { sourceId: string; source?: Row }) {
  const samples = useXdr<Row[]>("sources.samples", { source_id: sourceId })
  const maps = useXdr<Row[]>("sources.mappings", { source_id: sourceId })
  const setStatus = useXdrAction("sources.setStatus", { invalidate: ["sources."] })
  const decide = useXdrAction("autopilot.decide", { invalidate: ["sources.", "autopilot."] })
  const paused = source?.status === "paused"
  return (
    <div className="space-y-4">
      <div>
        <div className="flex items-center gap-2">
          <h2 className="font-mono text-lg font-semibold">{sourceId}</h2>
          {source && <Pill tone={STATUS_TONE[source.status]}>{String(source.status).replace(/_/g, " ")}</Pill>}
        </div>
        <p className="text-sm text-muted-foreground">{source?.name} · first seen {source?.first_seen ? fmtTime(source.first_seen) : "-"}</p>
        <div className="mt-2 flex gap-2">
          <ActionButton action={setStatus} params={{ source_id: sourceId, action: paused ? "resume" : "pause" }}
            confirm={paused ? undefined : `Pause ${sourceId}? Records sent with its token are rejected until resumed.`}>
            {paused ? "Resume" : "Pause"}
          </ActionButton>
        </div>
        <ActionResult action={setStatus} />
      </div>

      {source?.pending_change_id && (
        <Panel title="Autopilot proposal" description="The Detection Autopilot wrote a mapping for this source and validated it on recent records. Approve to go live and backfill everything already received.">
          <div className="flex gap-2">
            <ActionButton action={decide} variant="default" params={{ change_id: source.pending_change_id, action: "approve", note: "approved in Data Sources" }}>Approve mapping</ActionButton>
            <ActionButton action={decide} variant="ghost" params={{ change_id: source.pending_change_id, action: "reject", note: "rejected in Data Sources" }}>Reject</ActionButton>
          </div>
          <ActionResult action={decide} />
        </Panel>
      )}

      <Panel title="Mappings">
        <QueryState q={maps}>
          {(list) => list.length === 0 ? <Empty>No mapping yet. The autopilot proposes one once a few records have arrived.</Empty> : (
            <div className="space-y-3">{list.map((m) => <MappingCard key={m.mapping_id} m={m} />)}</div>
          )}
        </QueryState>
      </Panel>

      <Panel title="Recent records">
        <QueryState q={samples}>
          {(list) => list.length === 0 ? <Empty>No records received.</Empty> : (
            <div className="space-y-2">
              {list.map((r, i) => (
                <div key={i} className="rounded-md border border-border p-2">
                  <div className="flex gap-2 text-xs text-muted-foreground">
                    <span>{fmtTime(r.event_time)}</span>{r.severity_text && <Pill>{r.severity_text}</Pill>}
                  </div>
                  {typeof r.body === "string"
                    ? <code className="mt-1 block break-all font-mono text-xs">{truncate(r.body, 400)}</code>
                    : <JsonView value={r.body} maxHeight={180} />}
                </div>
              ))}
            </div>
          )}
        </QueryState>
      </Panel>
    </div>
  )
}

function MappingCard({ m }: { m: Row }) {
  const activate = useXdrAction("sources.activate", { invalidate: ["sources."] })
  const retire = useXdrAction("sources.retire", { invalidate: ["sources."] })
  const v = (m.validation ?? {}) as Row
  const coverage = Object.entries((v.coverage ?? {}) as Record<string, number>).filter(([, f]) => f > 0)
  return (
    <div className="rounded-lg border border-border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Pill tone={STATUS_TONE[m.status]}>{m.status}</Pill>
        <strong className="text-sm">{m.target_table}</strong>
        <span className="text-xs text-muted-foreground">by {m.created_by} · {fmtAgo(m.updated_at)}</span>
        {m.status === "live" && <span className="text-xs">{fmtNum(m.rows_mapped)} rows · last run {m.last_run_at ? fmtAgo(m.last_run_at) : "never"}</span>}
      </div>
      {m.last_error && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{truncate(m.last_error, 300)}</p>}
      {coverage.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {coverage.map(([c, f]) => (
            <span key={c} className="rounded border border-border px-1.5 py-0.5 font-mono text-[11px]">{c.toLowerCase()} {Math.round(f * 100)}%</span>
          ))}
        </div>
      )}
      <Disclosure title="Mapping SQL">
        <pre className="overflow-auto rounded-md bg-slate-950 p-3 font-mono text-xs text-emerald-200" style={{ maxHeight: 360 }}>{m.mapping_sql}</pre>
      </Disclosure>
      <div className="mt-2 flex flex-wrap gap-2">
        {m.status !== "live" && m.status !== "retired" && (
          <ActionButton action={activate} variant="default" params={{ mapping_id: m.mapping_id, backfill: true }}>Activate + backfill</ActionButton>
        )}
        {m.status === "live" && (
          <>
            <ActionButton action={retire} params={{ mapping_id: m.mapping_id, delete_rows: false }} confirm="Stop this mapping? Rows already mapped stay.">Retire</ActionButton>
            <ActionButton action={retire} variant="destructive" params={{ mapping_id: m.mapping_id, delete_rows: true }}
              confirm={`Retire and delete every ${m.target_table} row this source produced?`}>Retire + delete rows</ActionButton>
          </>
        )}
      </div>
      <ActionResult action={activate} />
      <ActionResult action={retire} />
    </div>
  )
}
