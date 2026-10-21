"use client"

import { useEffect, useMemo, useState } from "react"
import { Plus, ShieldCheck } from "lucide-react"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtNum, fmtTime, fmtAgo, truncate } from "@/lib/format"
import {
  PageHeader, Panel, QueryState, SeverityBadge, Pill, ActionButton, ActionResult, Select, TextInput,
  NumberInput, Field, Chips, Tabs, Empty, Kpi,
} from "@/components/xdr/kit"
import { DataTable } from "@/components/xdr/data-table"
import { RankBars } from "@/components/xdr/charts"
import { Button } from "@/components/ui/button"

const ACTION_TYPES = ["email", "webhook", "api_call", "create_incident", "ai_triage"] as const
const ACTION_STATUSES = ["success", "error", "suppressed_cooldown", "skipped"] as const
type ActionType = (typeof ACTION_TYPES)[number]

export function Response() {
  const [tab, setTab] = useState<"playbooks" | "alerts" | "controls">("playbooks")
  const evaluateAll = useXdrAction("response.evaluateAll", { invalidate: ["response.", "overview."] })
  return (
    <div className="space-y-4">
      <PageHeader
        persona="Detection Engineer"
        title="Response"
        description="Playbooks fire email, Slack/Teams webhooks, external API calls, incident creation or AI triage when findings match. Compensating controls mark genuine findings whose risk is already mitigated."
        actions={<ActionButton action={evaluateAll} variant="default" confirm="Evaluate all new findings against enabled playbooks? This sends real notifications.">Evaluate all new findings</ActionButton>}
      />
      <ActionResult action={evaluateAll} />
      <Tabs value={tab} onChange={setTab} tabs={[
        { value: "playbooks", label: "Playbooks" },
        { value: "alerts", label: "Alert center" },
        { value: "controls", label: "Compensating controls" },
      ]} />
      {tab === "playbooks" && <Playbooks />}
      {tab === "alerts" && <AlertCenter />}
      {tab === "controls" && <Controls />}
    </div>
  )
}

function Playbooks() {
  const list = useXdr("response.playbooks")
  const [selected, setSelected] = useState<string | null>(null)
  const current = useMemo(() => (list.data ?? []).find((p) => p.playbook_id === selected) ?? null, [list.data, selected])
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      <Panel title="Playbooks" actions={<Button size="sm" variant="outline" onClick={() => setSelected("")}><Plus className="h-3.5 w-3.5" /> New playbook</Button>}>
        <QueryState q={list}>
          {(rows) => (
            <DataTable
              rows={rows} rowKey="playbook_id" dense maxHeight={520} selectedKey={selected}
              onRowClick={(r) => setSelected(String(r.playbook_id))} empty="No playbooks yet."
              columns={[
                { key: "name", label: "Playbook", wrap: true },
                { key: "trigger_severity_min", label: "Sev ≥", render: (r) => <SeverityBadge severity={r.trigger_severity_min} /> },
                { key: "action_type", label: "Action", render: (r) => <Pill>{String(r.action_type).replace("_", " ")}</Pill> },
                { key: "threshold_count", label: "Thresh", align: "right" },
                { key: "cooldown_minutes", label: "Cooldown", align: "right", render: (r) => `${fmtNum(r.cooldown_minutes)}m` },
                { key: "enabled", label: "On", render: (r) => r.enabled ? <Pill tone="success">on</Pill> : <Pill tone="dismissed">off</Pill> },
              ]}
            />
          )}
        </QueryState>
      </Panel>
      <div>
        {selected === null
          ? <Panel title="Playbook editor"><Empty>Select a playbook, or create a new one.</Empty></Panel>
          : <PlaybookForm key={selected || "new"} playbook={current} />}
      </div>
    </div>
  )
}

function parseConfig(v: unknown): Record<string, string> {
  if (!v) return {}
  if (typeof v === "object") return v as Record<string, string>
  try { return JSON.parse(String(v)) } catch { return {} }
}

function PlaybookForm({ playbook }: { playbook: Row | null }) {
  const save = useXdrAction("response.savePlaybook", { invalidate: ["response."] })
  const test = useXdrAction("response.testPlaybook", { invalidate: ["response."] })
  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [sev, setSev] = useState(4)
  const [entity, setEntity] = useState("")
  const [threshold, setThreshold] = useState(1)
  const [windowMin, setWindowMin] = useState(60)
  const [cooldown, setCooldown] = useState(60)
  const [action, setAction] = useState<ActionType>("webhook")
  const [to, setTo] = useState("")
  const [url, setUrl] = useState("")
  const [auth, setAuth] = useState("")
  const [enabled, setEnabled] = useState(true)

  useEffect(() => {
    if (!playbook) return
    const cfg = parseConfig(playbook.action_config)
    setName(playbook.name ?? ""); setDescription(playbook.description ?? "")
    setSev(Number(playbook.trigger_severity_min) || 4); setEntity(playbook.trigger_entity ?? "")
    setThreshold(Number(playbook.threshold_count) || 1); setWindowMin(Number(playbook.threshold_window_minutes) || 60)
    setCooldown(Number(playbook.cooldown_minutes) || 60)
    setAction((ACTION_TYPES as readonly string[]).includes(playbook.action_type) ? playbook.action_type : "webhook")
    setTo(cfg.to ?? ""); setUrl(cfg.url ?? ""); setAuth(cfg.auth_header ?? ""); setEnabled(Boolean(playbook.enabled))
  }, [playbook])

  const params = {
    playbook_id: playbook?.playbook_id ?? "", name, description, trigger_severity_min: sev, trigger_entity: entity,
    threshold_count: threshold, threshold_window_minutes: windowMin, cooldown_minutes: cooldown,
    action_type: action, to, url, auth_header: auth, enabled,
  }

  return (
    <Panel title={playbook ? `Edit: ${playbook.name}` : "New playbook"} bodyClassName="space-y-3">
      <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Trigger</div>
      <Field label="Name"><TextInput value={name} onChange={(e) => setName(e.target.value)} /></Field>
      <Field label="Description"><TextInput value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Minimum severity"><NumberInput value={sev} onChange={setSev} min={1} max={5} /></Field>
        <Field label="Entity filter (blank = any)"><TextInput value={entity} onChange={(e) => setEntity(e.target.value)} className="font-mono" /></Field>
        <Field label="Threshold (findings in window)"><NumberInput value={threshold} onChange={setThreshold} min={1} max={100} /></Field>
        <Field label="Window (minutes)"><NumberInput value={windowMin} onChange={setWindowMin} min={1} max={1440} /></Field>
        <Field label="Cooldown per entity (minutes)"><NumberInput value={cooldown} onChange={setCooldown} min={1} max={1440} /></Field>
      </div>
      <div className="pt-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Action</div>
      <Field label="Action type"><Select value={action} onChange={setAction} options={ACTION_TYPES} /></Field>
      {action === "email" && <Field label="Recipients (comma-separated)" hint="Must be verified email addresses in this account"><TextInput value={to} onChange={(e) => setTo(e.target.value)} /></Field>}
      {action === "api_call" && <>
        <Field label="API endpoint URL"><TextInput value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://soar.example.com/hooks/xdr" /></Field>
        <Field label="Authorization header (optional)"><TextInput value={auth} onChange={(e) => setAuth(e.target.value)} type="password" /></Field>
      </>}
      {action === "webhook" && <p className="text-xs text-muted-foreground">Posts the finding as JSON through the XDR_WEBHOOK notification integration (Slack/Teams). The webhook secret is stored in Snowflake.</p>}
      <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enabled</label>
      <div className="flex flex-wrap gap-2">
        <ActionButton action={save} params={params} variant="default" disabled={!name.trim()}>{playbook ? "Save changes" : "Save playbook"}</ActionButton>
        {playbook && <ActionButton action={test} params={{ severity: sev }} confirm="Fire this playbook logic against the latest matching finding? This can send a real notification.">Test against latest finding</ActionButton>}
      </div>
      <ActionResult action={save} /><ActionResult action={test} />
    </Panel>
  )
}

function AlertCenter() {
  const [statuses, setStatuses] = useState<(typeof ACTION_STATUSES)[number][]>(["success", "error"])
  const [types, setTypes] = useState<ActionType[]>([])
  const q = useXdr<{ stats: Row[]; log: Row[] }>("response.actions", { statuses, types })

  const byType = useMemo(() => {
    const m = new Map<string, number>()
    for (const s of q.data?.stats ?? []) m.set(String(s.action_type), (m.get(String(s.action_type)) ?? 0) + Number(s.cnt))
    return [...m.entries()].map(([action_type, count]) => ({ action_type, count })).sort((a, b) => b.count - a.count)
  }, [q.data])
  const total = byType.reduce((s, x) => s + x.count, 0)
  const errors = (q.data?.stats ?? []).filter((s) => s.status === "error").reduce((s, x) => s + Number(x.cnt), 0)

  return (
    <div className="space-y-4">
      <Panel bodyClassName="flex flex-wrap gap-6">
        <Field label="Status"><Chips options={ACTION_STATUSES} value={statuses} onChange={setStatuses} /></Field>
        <Field label="Action type (none = all)"><Chips options={ACTION_TYPES} value={types} onChange={setTypes} /></Field>
      </Panel>
      <QueryState q={q}>
        {(d) => (
          <>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Kpi label="Notifications" value={fmtNum(total)} />
              <Kpi label="Delivery errors" value={fmtNum(errors)} tone={errors ? "danger" : "good"} />
              <Kpi label="Webhooks + API" value={fmtNum((byType.find((t) => t.action_type === "webhook")?.count ?? 0) + (byType.find((t) => t.action_type === "api_call")?.count ?? 0))} />
              <Kpi label="Emails" value={fmtNum(byType.find((t) => t.action_type === "email")?.count ?? 0)} />
            </div>
            <div className="grid gap-4 xl:grid-cols-[18rem_minmax(0,1fr)]">
              <Panel title="By action type">{byType.length ? <RankBars data={byType} labelKey="action_type" valueKey="count" /> : <Empty>No actions.</Empty>}</Panel>
              <Panel title="Notification history">
                <DataTable
                  rows={d.log} dense maxHeight={520}
                  empty="No notifications match the filters. Configure playbooks, then evaluate findings."
                  columns={[
                    { key: "executed_at", label: "When", render: (r) => <span title={fmtTime(r.executed_at)}>{fmtAgo(r.executed_at)}</span> },
                    { key: "playbook_name", label: "Playbook" },
                    { key: "action_type", label: "Action", render: (r) => <Pill>{r.action_type}</Pill> },
                    { key: "status", label: "Status", render: (r) => <Pill tone={String(r.status)}>{r.status}</Pill> },
                    { key: "severity", label: "Sev", render: (r) => r.severity ? <SeverityBadge severity={r.severity} /> : null },
                    { key: "entity", label: "Entity", className: "font-mono text-xs" },
                    { key: "detail", label: "Detail", wrap: true, render: (r) => truncate(r.detail, 140) },
                  ]}
                />
              </Panel>
            </div>
          </>
        )}
      </QueryState>
    </div>
  )
}

function Controls() {
  const mitigated = useXdr("response.mitigated")
  const controls = useXdr("response.controls")
  const assess = useXdrAction("triage.assessControls", { invalidate: ["response.", "triage.", "overview."] })
  return (
    <div className="space-y-4">
      <Panel
        title={<span className="flex items-center gap-1.5"><ShieldCheck className="h-4 w-4 text-emerald-500" />Security controls in scope</span>}
        description="Firewall rules, EDR policies and other compensating controls the assessment engine matches findings against (by MITRE technique and covered entity)"
        actions={<ActionButton action={assess} variant="default">Assess control coverage</ActionButton>}
        bodyClassName="space-y-3"
      >
        <ActionResult action={assess} />
        <QueryState q={controls}>
          {(rows) => (
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
              {rows.map((c) => (
                <div key={String(c.control_id)} className="rounded-lg border border-border p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <div className="font-mono text-[10px] text-muted-foreground">{c.control_id} · {String(c.control_type).replace(/_/g, " ")}</div>
                      <div className="text-sm font-semibold">{c.name}</div>
                    </div>
                    <Pill tone={c.status === "active" ? "success" : "dismissed"}>{c.status}</Pill>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{c.description}</p>
                  <div className="mt-2 flex flex-wrap gap-1 text-[11px]">
                    {(Array.isArray(c.mitre_technique_ids) ? c.mitre_technique_ids : []).map((t: string) => <span key={t} className="rounded bg-muted px-1.5 py-0.5 font-mono">{t}</span>)}
                    {(Array.isArray(c.covered_entities) ? c.covered_entities : []).map((e: string) => <span key={e} className="rounded bg-teal-500/10 px-1.5 py-0.5 font-mono text-teal-700 dark:text-teal-300">{e}</span>)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </QueryState>
      </Panel>
      <Panel title="Mitigated by existing controls" description="Genuine findings whose risk is already covered — no action needed, nothing hidden">
        <QueryState q={mitigated}>
          {(rows) => (
            <DataTable
              rows={rows} rowKey="finding_id" dense maxHeight={420}
              empty="No control-mitigated findings yet — run the assessment."
              columns={[
                { key: "detection_time", label: "Detected", render: (r) => fmtAgo(r.detection_time) },
                { key: "rule_id", label: "Rule", className: "font-mono text-xs" },
                { key: "entity", label: "Entity", className: "font-mono text-xs" },
                { key: "description", label: "Finding", wrap: true },
                { key: "triage_notes", label: "Covering control", wrap: true, render: (r) => <span className="text-teal-700 dark:text-teal-300">{r.triage_notes}</span> },
              ]}
            />
          )}
        </QueryState>
      </Panel>
    </div>
  )
}

