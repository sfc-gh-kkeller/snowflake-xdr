"use client"

import { useState } from "react"
import { useSearchParams } from "next/navigation"
import Link from "next/link"
import { RefreshCw, FileText, Ticket } from "lucide-react"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtAgo, fmtNum, fmtTime, truncate } from "@/lib/format"
import {
  PageHeader, Panel, QueryState, Kpi, KpiGrid, Pill, SeverityBadge, ActionButton, ActionResult, Select, TextInput,
  TextArea, Field, Tabs, Empty, Drawer, Disclosure,
} from "@/components/xdr/kit"
import { DataTable, type Column } from "@/components/xdr/data-table"

type Tab = "cases" | "integrations" | "tracker" | "metrics"
const FILTERS = ["active", "breached", "closed", "all"] as const
const STATES = ["acknowledged", "investigating", "contained", "eradicated", "recovered"] as const
const RESOLUTIONS = ["true_positive", "benign", "false_positive", "duplicate", "test"] as const
const MOCK_STATES = ["To Do", "In Progress", "Contained", "Done"] as const
const STATE_TONE: Record<string, string> = {
  open: "new", acknowledged: "investigating", investigating: "investigating", contained: "contained",
  eradicated: "contained", recovered: "contained", closed: "resolved",
}
const SYNC_TONE: Record<string, string> = { ok: "success", pending: "investigating", error: "error" }

function label(s: unknown) { return String(s ?? "").replace(/_/g, " ") }

function TicketChip({ t }: { t: Row }) {
  const text = `${t.key ?? "pending"}${t.state ? ` · ${t.state}` : ""}`
  return (
    <span className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-[11px]">
      <Ticket className="h-3 w-3" />
      {t.url && String(t.url).startsWith("https://") && !String(t.url).includes("/cases?ticket=")
        ? <a href={t.url} target="_blank" rel="noreferrer" className="text-primary hover:underline">{text}</a>
        : <span>{text}</span>}
      <span className={t.sync_status === "error" ? "text-red-600 dark:text-red-400" : "text-muted-foreground"}>{t.connection_id}</span>
    </span>
  )
}

export function Cases() {
  const params = useSearchParams()
  const [tab, setTab] = useState<Tab>("cases")
  const [open, setOpen] = useState<string | null>(params.get("id"))
  const status = useXdr<Row>("tickets.status", {}, { refetchInterval: 30_000 })
  const metrics = useXdr<Row[]>("cases.metrics")
  const sync = useXdrAction("tickets.sync", { invalidate: ["cases.", "tickets."] })
  const st = status.data ?? {}
  const m: Row[] = metrics.data ?? []
  const openCount = m.reduce((a, r) => a + Number(r.open_incidents ?? 0), 0)
  const p1 = m.find((r) => r.priority === "P1")
  const conns: Row[] = st.connections ?? []
  const active = conns.filter((c) => c.enabled)

  return (
    <div className="space-y-4">
      <PageHeader
        persona="SOC Analyst"
        title="Cases & Tickets"
        description="Incident lifecycle with an audit trail, response tasks, SLAs and reports, synced both ways with Jira or ServiceNow. Detection data comes from the XDR; once a ticket exists, its workflow state is the authority and the XDR follows it."
        actions={<ActionButton action={sync} variant="default"><RefreshCw className="h-3.5 w-3.5" /> Sync tickets now</ActionButton>}
      />
      <ActionResult action={sync} />
      <KpiGrid>
        <Kpi label="Open cases" value={openCount} />
        <Kpi label="P1 MTTA" value={p1?.mtta_minutes == null ? "-" : `${fmtNum(p1.mtta_minutes, 0)} min`} hint="time to acknowledge" />
        <Kpi label="P1 SLA compliance" value={p1?.sla_compliance == null ? "-" : `${Math.round(Number(p1.sla_compliance) * 100)}%`}
          tone={Number(p1?.sla_compliance ?? 1) < 0.9 ? "warn" : "good"} />
        <Kpi label="Linked tickets" value={st.tickets?.linked ?? "-"} tone={Number(st.tickets?.error) ? "warn" : "default"}
          hint={`${st.tickets?.error ?? 0} sync errors`} />
        <Kpi label="Sync queue" value={st.queues?.outbox_pending ?? "-"} hint={`${st.queues?.outbox_failed ?? 0} failed · ${st.queues?.inbox_pending ?? 0} inbound`} />
        <Kpi label="Ticket systems" value={active.length} hint={active.map((c) => c.connection_id).join(", ") || "none enabled"} />
      </KpiGrid>

      <Tabs value={tab} onChange={setTab} tabs={[
        { value: "cases", label: "Cases" },
        { value: "tracker", label: "Demo tracker" },
        { value: "integrations", label: "Integrations" },
        { value: "metrics", label: "Metrics" },
      ]} />
      {tab === "cases" && <CaseList onOpen={setOpen} />}
      {tab === "tracker" && <Tracker onOpen={setOpen} />}
      {tab === "integrations" && <Integrations />}
      {tab === "metrics" && <Metrics rows={m} />}

      <Drawer open={!!open} onClose={() => setOpen(null)} width="52rem">
        {open && <CaseDetail key={open} incidentId={open} />}
      </Drawer>
    </div>
  )
}

// ------------------------------------------------------------------ list
function CaseList({ onOpen }: { onOpen: (id: string) => void }) {
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("active")
  const q = useXdr<Row[]>("cases.list", { filter }, { refetchInterval: 30_000 })
  const columns: Column[] = [
    { key: "priority", label: "Pri", render: (r) => <Pill tone={r.priority === "P1" ? "error" : undefined}>{r.priority}</Pill> },
    { key: "title", label: "Case", wrap: true, render: (r) => (
      <button type="button" className="text-left text-primary hover:underline" onClick={() => onOpen(r.incident_id)}>{r.title}</button>
    ) },
    { key: "status", label: "Status", render: (r) => <Pill tone={STATE_TONE[r.status]}>{label(r.status)}</Pill> },
    { key: "assignee", label: "Assignee", render: (r) => r.assignee ?? <span className="text-muted-foreground">unassigned</span> },
    { key: "next_due_at", label: "SLA", sortValue: (r) => r.next_due_at, render: (r) => r.status === "closed"
      ? <span className="text-muted-foreground">{label(r.resolution)}</span>
      : <span className={r.breached ? "font-semibold text-red-600 dark:text-red-400" : ""}>
          {r.next_milestone} {r.breached ? "overdue" : `due ${fmtAgo(r.next_due_at)}`}
        </span> },
    { key: "open_tasks", label: "Tasks", align: "right" },
    { key: "tickets", label: "Ticket", sortable: false, render: (r) => (
      <div className="flex flex-wrap gap-1">{(r.tickets as Row[]).map((t) => <TicketChip key={t.connection_id} t={t} />)}</div>
    ) },
    { key: "updated_at", label: "Updated", render: (r) => fmtAgo(r.updated_at), sortValue: (r) => r.updated_at },
  ]
  return (
    <Panel title="Cases" actions={<Select value={filter} onChange={setFilter} options={FILTERS.map((f) => ({ value: f, label: f }))} className="w-36" />}>
      <QueryState q={q}>{(list) => <DataTable rows={list} columns={columns} rowKey="incident_id" dense empty="No cases." />}</QueryState>
    </Panel>
  )
}

// ------------------------------------------------------------------ detail
function CaseDetail({ incidentId }: { incidentId: string }) {
  const q = useXdr<Row>("cases.detail", { incident_id: incidentId }, { refetchInterval: 20_000 })
  const inv = ["cases.", "tickets.", "incidents.", "overview."]
  const setState = useXdrAction("cases.setState", { invalidate: inv })
  const assign = useXdrAction("cases.assign", { invalidate: inv })
  const comment = useXdrAction("cases.comment", { invalidate: inv })
  const task = useXdrAction("cases.task", { invalidate: inv })
  const report = useXdrAction("cases.report", { invalidate: inv })
  const ticket = useXdrAction("tickets.create", { invalidate: inv })
  const [resolution, setResolution] = useState<(typeof RESOLUTIONS)[number]>("true_positive")
  const [reason, setReason] = useState("")
  const [assignee, setAssignee] = useState("")
  const [note, setNote] = useState("")
  const [taskTitle, setTaskTitle] = useState("")
  const [taskOwner, setTaskOwner] = useState("")
  const [reportId, setReportId] = useState<string | null>(null)

  return (
    <QueryState q={q}>
      {(d) => {
        const i = d.incident as Row
        const events: Row[] = d.events ?? []
        const tasks: Row[] = d.tasks ?? []
        const tickets: Row[] = d.tickets ?? []
        const reports: Row[] = d.reports ?? []
        const sla = (d.sla ?? {}) as Row
        return (
          <div className="space-y-4">
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <Pill tone={i.priority === "P1" ? "error" : undefined}>{i.priority}</Pill>
                <SeverityBadge severity={i.severity} />
                <Pill tone={STATE_TONE[i.status]}>{label(i.status)}</Pill>
                {i.resolution && <Pill>{label(i.resolution)}</Pill>}
                {tickets.map((t) => <TicketChip key={t.connection_id} t={t} />)}
              </div>
              <h2 className="mt-1 text-lg font-semibold">{i.title}</h2>
              <p className="text-xs text-muted-foreground">
                <span className="font-mono">{i.incident_id}</span> · created {fmtTime(i.created_at)} ·{" "}
                <Link className="text-primary hover:underline" href={`/investigations?id=${i.incident_id}`}>investigation</Link>
              </p>
              {i.status !== "closed" && sla.next_milestone && (
                <p className={`mt-1 text-sm ${(sla.ack_breached || sla.contain_breached || sla.resolve_breached) ? "text-red-600 dark:text-red-400" : ""}`}>
                  Next: {sla.next_milestone} by {fmtTime(sla.next_due_at)}
                  {(sla.ack_breached || sla.contain_breached || sla.resolve_breached) ? " (SLA breached)" : ""}
                </p>
              )}
            </div>

            <Panel title="Lifecycle" description="Each change is recorded with who made it and is sent to linked tickets.">
              <div className="flex flex-wrap gap-2">
                {STATES.map((s) => (
                  <ActionButton key={s} action={setState} params={{ incident_id: incidentId, state: s, reason: reason || undefined }}
                    disabled={i.status === s} variant={i.status === s ? "default" : "outline"}>{label(s)}</ActionButton>
                ))}
                {i.status === "closed" && (
                  <ActionButton action={setState} params={{ incident_id: incidentId, state: "investigating", reason: reason || "reopened" }}>Reopen</ActionButton>
                )}
              </div>
              <div className="mt-2 flex flex-wrap items-end gap-2">
                <Field label="Reason / notes"><TextInput className="w-72" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="optional" /></Field>
                <Field label="Resolution"><Select value={resolution} onChange={setResolution} options={RESOLUTIONS.map((r) => ({ value: r, label: label(r) }))} className="w-40" /></Field>
                <ActionButton action={setState} variant="destructive" disabled={i.status === "closed"}
                  params={{ incident_id: incidentId, state: "closed", resolution, reason: reason || undefined }}
                  confirm={`Close as ${label(resolution)}?`}>Close case</ActionButton>
              </div>
              <ActionResult action={setState} />
              <div className="mt-3 flex flex-wrap items-end gap-2">
                <Field label="Assignee"><TextInput className="w-56" value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder={i.assignee ?? "unassigned"} /></Field>
                <ActionButton action={assign} params={{ incident_id: incidentId, assignee }} disabled={!assignee.trim()}>Assign</ActionButton>
              </div>
              <ActionResult action={assign} />
            </Panel>

            <Panel title="Ticket" description="Ticket text carries summaries and a link back to the console; raw evidence leaves Snowflake only if the connection allows it.">
              {tickets.length === 0 ? (
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">No ticket yet.</span>
                  <ActionButton action={ticket} variant="default" params={{ incident_id: incidentId }}>Create ticket</ActionButton>
                </div>
              ) : (
                <div className="space-y-1 text-sm">
                  {tickets.map((t) => (
                    <div key={t.connection_id} className="flex flex-wrap items-center gap-2">
                      <TicketChip t={t} />
                      <Pill tone={SYNC_TONE[t.sync_status]}>{t.sync_status}</Pill>
                      {t.error && <span className="text-xs text-red-600 dark:text-red-400">{truncate(t.error, 200)}</span>}
                    </div>
                  ))}
                </div>
              )}
              <ActionResult action={ticket} />
            </Panel>

            <Panel title={`Tasks (${tasks.filter((t) => t.status === "open").length} open)`}>
              <div className="space-y-1">
                {tasks.map((t) => (
                  <div key={t.task_id} className="flex flex-wrap items-center gap-2 text-sm">
                    <Pill tone={t.status === "done" ? "success" : t.status === "cancelled" ? "dismissed" : "investigating"}>{t.status}</Pill>
                    <span className={t.status !== "open" ? "text-muted-foreground line-through" : ""}>{t.title}</span>
                    {t.owner && <span className="text-xs text-muted-foreground">{t.owner}</span>}
                    {t.due_at && t.status === "open" && <span className="text-xs text-muted-foreground">due {fmtAgo(t.due_at)}</span>}
                    {t.status === "open" && (
                      <ActionButton action={task} size="sm" variant="ghost" params={{ incident_id: incidentId, task_id: t.task_id, status: "done" }}>Done</ActionButton>
                    )}
                  </div>
                ))}
              </div>
              <div className="mt-2 flex flex-wrap items-end gap-2">
                <TextInput className="w-72" value={taskTitle} onChange={(e) => setTaskTitle(e.target.value)} placeholder="New task, e.g. Reset credentials for tlee" />
                <TextInput className="w-40" value={taskOwner} onChange={(e) => setTaskOwner(e.target.value)} placeholder="owner" />
                <ActionButton action={task} params={{ incident_id: incidentId, title: taskTitle, owner: taskOwner, due_hours: 24 }} disabled={!taskTitle.trim()}>Add task</ActionButton>
              </div>
              <ActionResult action={task} />
            </Panel>

            <Panel title="Report" description="Figures come from XDR tables; Cortex writes the narrative from those facts only. Attached to linked tickets.">
              <div className="flex flex-wrap items-center gap-2">
                <ActionButton action={report} variant="default" params={{ incident_id: incidentId }}><FileText className="h-3.5 w-3.5" /> Generate report</ActionButton>
                {reports.map((r) => (
                  <button key={r.report_id} type="button" onClick={() => setReportId(r.report_id)}
                    className="rounded border border-border px-2 py-0.5 text-xs hover:bg-muted">{fmtTime(r.created_at)}</button>
                ))}
              </div>
              <ActionResult action={report} />
              {reportId && <ReportView reportId={reportId} />}
            </Panel>

            <Panel title="Timeline">
              <div className="mb-3 flex gap-2">
                <TextArea rows={2} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a comment (also posted to linked tickets)" />
                <ActionButton action={comment} params={{ incident_id: incidentId, text: note }} disabled={!note.trim()}>Comment</ActionButton>
              </div>
              <ActionResult action={comment} />
              <ol className="space-y-2 border-l border-border pl-4">
                {[...events].reverse().map((e, n) => (
                  <li key={n} className="text-sm">
                    <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                      <span>{fmtTime(e.time)}</span>
                      <Pill tone={e.actor_type === "ticket" ? "investigating" : e.type === "sla_breach" || e.type === "ticket_sync_error" ? "error" : undefined}>
                        {label(e.type)}
                      </Pill>
                      <span>{e.actor} ({e.actor_type}{e.source && e.source !== "xdr" ? ` via ${e.source}` : ""})</span>
                    </div>
                    {e.type === "comment" ? <p className="mt-0.5 whitespace-pre-wrap">{e.detail?.text}</p>
                      : e.to ? <p className="mt-0.5">{e.from ? `${label(e.from)} → ` : ""}<strong>{label(e.to)}</strong>
                          {e.detail?.reason ? <span className="text-muted-foreground"> · {e.detail.reason}</span> : null}
                          {e.detail?.title ? <span className="text-muted-foreground"> · {e.detail.title}</span> : null}
                          {e.detail?.error ? <span className="text-red-600 dark:text-red-400"> · {truncate(e.detail.error, 200)}</span> : null}</p>
                      : null}
                  </li>
                ))}
              </ol>
              {(d.attacker_activity ?? []).length > 0 && (
                <Disclosure title={`Attacker activity (${d.attacker_activity.length})`}>
                  <ul className="space-y-1 text-xs">
                    {(d.attacker_activity as Row[]).map((a, n) => (
                      <li key={n}><span className="text-muted-foreground">{fmtTime(a.time)}</span> {a.technique && <span className="font-mono">{a.technique}</span>} {a.description}</li>
                    ))}
                  </ul>
                </Disclosure>
              )}
            </Panel>
          </div>
        )
      }}
    </QueryState>
  )
}

function ReportView({ reportId }: { reportId: string }) {
  const q = useXdr<Row>("cases.reportBody", { report_id: reportId })
  return (
    <QueryState q={q}>
      {(r) => (
        <pre className="mt-3 max-h-[480px] overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 font-mono text-xs">{r.markdown}</pre>
      )}
    </QueryState>
  )
}

// ------------------------------------------------------------------ demo tracker
function Tracker({ onOpen }: { onOpen: (id: string) => void }) {
  const q = useXdr<Row[]>("tickets.mockList", {}, { refetchInterval: 20_000 })
  return (
    <Panel title="Demo tracker" description="A Jira-style ticket system kept in Snowflake, so the round trip is demoable without credentials. Act as the analyst working the ticket: the XDR picks the change up on the next poll.">
      <QueryState q={q}>
        {(list) => list.length === 0 ? <Empty>No tickets yet. P1 and P2 cases get one on the next sync.</Empty> : (
          <div className="space-y-3">{list.map((t) => <MockTicket key={t.ticket_key} t={t} onOpen={onOpen} />)}</div>
        )}
      </QueryState>
    </Panel>
  )
}

function MockTicket({ t, onOpen }: { t: Row; onOpen: (id: string) => void }) {
  const act = useXdrAction("tickets.mockAction", { invalidate: ["tickets.", "cases.", "incidents."] })
  const [comment, setComment] = useState("")
  const [assignee, setAssignee] = useState("")
  const comments: Row[] = t.comments ?? []
  return (
    <div className="rounded-lg border border-border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm font-semibold">{t.ticket_key}</span>
        <Pill>{t.state}</Pill>
        <Pill tone={t.priority === "Highest" ? "error" : undefined}>{t.priority}</Pill>
        <span className="text-xs text-muted-foreground">{t.assignee ?? "unassigned"} · updated {fmtAgo(t.updated_at)} by {t.updated_by}</span>
        <button type="button" className="text-xs text-primary hover:underline" onClick={() => onOpen(t.xdr_reference)}>XDR case</button>
        {(t.attachments ?? []).map((a: Row, n: number) => <span key={n} className="rounded border border-border px-1.5 text-[11px]">📎 {a.name}</span>)}
      </div>
      <p className="mt-1 text-sm font-medium">{t.summary}</p>
      <Disclosure title={`Comments (${comments.length})`}>
        <ul className="space-y-1 text-xs">
          {comments.map((c, n) => <li key={n}><strong>{c.author}</strong> <span className="text-muted-foreground">{fmtTime(c.created)}</span> {c.body}</li>)}
        </ul>
      </Disclosure>
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {MOCK_STATES.map((s) => (
          <ActionButton key={s} action={act} size="sm" variant={t.state === s ? "default" : "outline"} disabled={t.state === s}
            params={{ ticket_key: t.ticket_key, state: s, as: "jira.analyst" }}>{s}</ActionButton>
        ))}
        <TextInput className="w-40" value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="assign to" />
        <TextInput className="w-64" value={comment} onChange={(e) => setComment(e.target.value)} placeholder="comment as the Jira analyst" />
        <ActionButton action={act} size="sm" params={{ ticket_key: t.ticket_key, assignee, comment, as: "jira.analyst" }}
          disabled={!comment.trim() && !assignee.trim()}>Save in tracker</ActionButton>
      </div>
      <ActionResult action={act} />
    </div>
  )
}

// ------------------------------------------------------------------ integrations
function Integrations() {
  const conns = useXdr<Row[]>("tickets.connections")
  const outbox = useXdr<Row[]>("tickets.outbox", {}, { refetchInterval: 30_000 })
  const inbox = useXdr<Row[]>("tickets.inbox", {}, { refetchInterval: 30_000 })
  return (
    <div className="space-y-4">
      <Panel title="Ticket systems" description="Credentials live in Snowflake secrets (SNOWFLAKE_XDR.INCIDENTS.JIRA_CREDENTIALS / SERVICENOW_CREDENTIALS); egress is allowed only to the configured host. Incidents at or above the minimum priority get a ticket automatically, unless everything in them was dismissed as a false positive.">
        <QueryState q={conns}>{(list) => <div className="space-y-3">{list.map((c) => <ConnectionCard key={c.connection_id} c={c} />)}</div>}</QueryState>
      </Panel>
      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Outbound (XDR → ticket)">
          <QueryState q={outbox}>
            {(list) => <DataTable rows={list} rowKey="op_id" dense maxHeight={420} empty="Nothing sent yet." columns={[
              { key: "status", label: "Status", render: (r) => <Pill tone={r.status === "done" ? "success" : r.status === "failed" ? "error" : "investigating"}>{r.status}</Pill> },
              { key: "op", label: "Op" },
              { key: "external_key", label: "Ticket", className: "font-mono text-xs" },
              { key: "attempts", label: "Tries", align: "right" },
              { key: "last_error", label: "Error", wrap: true, render: (r) => <span className="text-xs text-red-600 dark:text-red-400">{truncate(r.last_error, 140)}</span> },
              { key: "created_at", label: "Queued", render: (r) => fmtAgo(r.created_at), sortValue: (r) => r.created_at },
            ]} />}
          </QueryState>
        </Panel>
        <Panel title="Inbound (ticket → XDR)">
          <QueryState q={inbox}>
            {(list) => <DataTable rows={list} rowKey="inbox_id" dense maxHeight={420} empty="No ticket changes yet." columns={[
              { key: "status", label: "Status", render: (r) => <Pill tone={r.status === "applied" ? "success" : r.status === "error" ? "error" : "dismissed"}>{r.status}</Pill> },
              { key: "external_key", label: "Ticket", className: "font-mono text-xs" },
              { key: "kind", label: "Change" },
              { key: "value", label: "Value", wrap: true, render: (r) => truncate(r.value, 100) },
              { key: "via", label: "Via" },
              { key: "result", label: "Result", wrap: true, render: (r) => <span className="text-xs text-muted-foreground">{truncate(r.result, 120)}</span> },
              { key: "received_at", label: "When", render: (r) => fmtAgo(r.received_at), sortValue: (r) => r.received_at },
            ]} />}
          </QueryState>
        </Panel>
      </div>
    </div>
  )
}

function ConnectionCard({ c }: { c: Row }) {
  const configure = useXdrAction("tickets.configure", { invalidate: ["tickets."] })
  const cfg = (c.config ?? {}) as Row
  const [base, setBase] = useState<string>(c.base_url ?? "")
  const [project, setProject] = useState<string>(cfg.project_key ?? cfg.assignment_group ?? "")
  const [prio, setPrio] = useState<string>(c.min_priority ?? "P2")
  const isMock = c.system === "mock"
  const isJira = c.system === "jira"
  return (
    <div className="rounded-lg border border-border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Pill tone={c.enabled ? "success" : "dismissed"}>{c.enabled ? "enabled" : "disabled"}</Pill>
        <strong className="text-sm">{c.name}</strong>
        <span className="font-mono text-xs text-muted-foreground">{c.connection_id} · {c.system}</span>
        <span className="text-xs text-muted-foreground">auto-create ≥ {c.min_priority} · last poll {c.last_poll_at ? fmtAgo(c.last_poll_at) : "never"}</span>
        {c.last_poll_status && <span className={`text-xs ${String(c.last_poll_status).startsWith("error") ? "text-red-600 dark:text-red-400" : "text-muted-foreground"}`}>{truncate(c.last_poll_status, 160)}</span>}
      </div>
      <div className="mt-2 flex flex-wrap items-end gap-2">
        {!isMock && <Field label="Site URL"><TextInput className="w-72" value={base} onChange={(e) => setBase(e.target.value)} placeholder={isJira ? "https://acme.atlassian.net" : "https://acme.service-now.com"} /></Field>}
        {!isMock && <Field label={isJira ? "Project key" : "Assignment group"}><TextInput className="w-40" value={project} onChange={(e) => setProject(e.target.value)} /></Field>}
        <Field label="Auto-create from"><Select value={prio} onChange={setPrio} options={["P1", "P2", "P3", "P4", "P5"].map((p) => ({ value: p, label: p }))} className="w-24" /></Field>
        <ActionButton action={configure} params={{
          connection_id: c.connection_id, min_priority: prio,
          ...(isMock ? {} : { base_url: base || undefined, ...(isJira ? { project_key: project || undefined } : { assignment_group: project || undefined }) }),
        }}>Save</ActionButton>
        <ActionButton action={configure} variant={c.enabled ? "ghost" : "default"} params={{ connection_id: c.connection_id, enabled: !c.enabled }}
          confirm={!c.enabled && !isMock ? `Enable ${c.name}? Set its credentials secret first.` : undefined}>{c.enabled ? "Disable" : "Enable"}</ActionButton>
      </div>
      {!isMock && (
        <p className="mt-2 text-xs text-muted-foreground">
          Credentials: <code>ALTER SECRET SNOWFLAKE_XDR.INCIDENTS.{isJira ? "JIRA_CREDENTIALS SET USERNAME = 'you@acme.com' PASSWORD = '&lt;API token&gt;'" : "SERVICENOW_CREDENTIALS SET USERNAME = 'xdr.integration' PASSWORD = '…'"}</code>
        </p>
      )}
      <ActionResult action={configure} />
    </div>
  )
}

// ------------------------------------------------------------------ metrics
function Metrics({ rows: m }: { rows: Row[] }) {
  return (
    <Panel title="Response metrics" description="From the incident lifecycle: time to acknowledge, contain and resolve per priority, SLA compliance and reopen rate.">
      <DataTable rows={m} rowKey="priority" dense empty="No incidents." columns={[
        { key: "priority", label: "Priority" },
        { key: "incidents", label: "Cases", align: "right" },
        { key: "open_incidents", label: "Open", align: "right" },
        { key: "mtta_minutes", label: "MTTA", align: "right", render: (r) => r.mtta_minutes == null ? "-" : `${fmtNum(r.mtta_minutes, 0)} min` },
        { key: "mttc_minutes", label: "MTTC", align: "right", render: (r) => r.mttc_minutes == null ? "-" : `${fmtNum(r.mttc_minutes, 0)} min` },
        { key: "mttr_minutes", label: "MTTR", align: "right", render: (r) => r.mttr_minutes == null ? "-" : `${fmtNum(r.mttr_minutes, 0)} min` },
        { key: "sla_compliance", label: "SLA met", align: "right", render: (r) => r.sla_compliance == null ? "-" : `${Math.round(Number(r.sla_compliance) * 100)}%` },
        { key: "reopen_rate", label: "Reopened", align: "right", render: (r) => r.reopen_rate == null ? "-" : `${Math.round(Number(r.reopen_rate) * 100)}%` },
        { key: "true_positive", label: "True positive", align: "right" },
        { key: "not_real", label: "FP / benign", align: "right" },
        { key: "tickets", label: "Tickets", align: "right" },
      ]} />
    </Panel>
  )
}
