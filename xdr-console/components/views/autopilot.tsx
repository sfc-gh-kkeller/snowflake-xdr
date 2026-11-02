"use client"

import { useEffect, useState } from "react"
import { Bot, Pin, RotateCcw } from "lucide-react"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtAgo, fmtTime } from "@/lib/format"
import {
  PageHeader, Panel, QueryState, Kpi, KpiGrid, Pill, ActionButton, ActionResult, Select, TextInput,
  NumberInput, Tabs, Drawer, JsonView, Disclosure, Loading, ErrorNote, Empty,
} from "@/components/xdr/kit"
import { DataTable, type Column } from "@/components/xdr/data-table"

const FILTERS = ["open", "all", "proposed", "shadow", "promoted", "applied", "approved", "rolled_back", "rejected", "failed"] as const
type Filter = (typeof FILTERS)[number]
const MODES = ["auto_live", "shadow_then_promote", "propose_only", "off"] as const
type Mode = (typeof MODES)[number]

const MODE_LABEL: Record<Mode, string> = {
  auto_live: "Apply automatically",
  shadow_then_promote: "Shadow, then auto-promote",
  propose_only: "Propose, human approves",
  off: "Off",
}

const STATUS_TONE: Record<string, string> = {
  proposed: "contained", shadow: "investigating", promoted: "success", applied: "success",
  approved: "success", rolled_back: "error", rejected: "dismissed", failed: "error",
}

const TYPE_LABEL: Record<string, string> = {
  new_rule: "New rule", fix_broken: "Fix broken rule", tune_filter: "Tune (FP exclusions)",
  tune_threshold: "Tune threshold", disable_noisy: "Disable noisy rule", retire_silent: "Retire silent rule",
  new_parser: "New parser",
  auto_suppress: "Auto-suppress (confidence)",
  suppress_entity: "Suppress entity",
  intel_allowlist: "Allowlist indicator",
  revoke_suppression: "Revoke suppression",
  recheck_verdicts: "Re-check verdicts",
}

function StatusPill({ status }: { status: unknown }) {
  const s = String(status ?? "")
  return <Pill tone={STATUS_TONE[s]}>{s.replace(/_/g, " ")}</Pill>
}

function MetricLine({ m }: { m: Row | null | undefined }) {
  if (!m || typeof m !== "object") return <span className="text-muted-foreground">-</span>
  if (m.error) return <span className="text-red-600 dark:text-red-400">error</span>
  const recall = m.recall === null || m.recall === undefined ? "n/a" : `${Math.round(Number(m.recall) * 100)}%`
  return <span className="tabular-nums">recall {recall} · {m.matches ?? 0} match · {m.benign ?? 0} benign</span>
}

export function Autopilot() {
  const [tab, setTab] = useState<"feed" | "policy">("feed")
  const summary = useXdr<Row>("autopilot.summary", {}, { refetchInterval: 20_000 })
  const run = useXdrAction("autopilot.runCycle", { invalidate: ["autopilot."] })
  const digest = useXdrAction<{ message: string; body: string }>("autopilot.digest")
  const s = summary.data

  return (
    <div className="space-y-4">
      <PageHeader
        persona="Detection Engineer"
        title="Detection Autopilot"
        description="Detections that write and maintain themselves. The autopilot finds MITRE gaps, broken and noisy rules, drafts changes with Cortex AI, backtests them against labelled attack data, and applies them according to your policy. Shadow rules run silently until they prove themselves. You stay in control: approve, reject, roll back or pin."
        actions={<>
          <ActionButton action={digest} variant="outline">Email digest now</ActionButton>
          <ActionButton action={run} variant="default" disabled={Boolean(s?.running)}>
            <Bot className="h-3.5 w-3.5" /> {s?.running ? "Cycle running…" : "Run cycle now"}
          </ActionButton>
        </>}
      />
      <ActionResult action={run} />
      <ActionResult action={digest} />

      <KpiGrid>
        <Kpi label="Waiting for you" value={s?.pending ?? "-"} tone={Number(s?.pending) ? "warn" : "default"} hint="proposals to approve" />
        <Kpi label="In shadow" value={s?.shadow ?? "-"} tone="accent" hint="running silently" />
        <Kpi label="Went live (7d)" value={s?.went_live_7d ?? "-"} tone="good" hint="applied, promoted, approved" />
        <Kpi label="Changes (7d)" value={s?.changes_7d ?? "-"} />
        <Kpi label="Auto rollbacks (7d)" value={s?.auto_rollbacks_7d ?? "-"} tone={Number(s?.auto_rollbacks_7d) ? "danger" : "default"} hint="guardrail reverted" />
        <Kpi label="Techniques covered" value={s?.techniques_live ?? "-"} hint="by live autopilot rules" />
        <Kpi label="Last cycle" value={s?.last_run ? fmtAgo(s.last_run) : "-"} hint={s?.last_state ? String(s.last_state).toLowerCase() : "runs every 6h when resumed"} />
      </KpiGrid>

      <Tabs value={tab} onChange={setTab} tabs={[{ value: "feed", label: "Change feed" }, { value: "policy", label: "Autonomy policy" }]} />
      {tab === "feed" ? <Feed /> : <Policy />}
    </div>
  )
}

function Feed() {
  const [filter, setFilter] = useState<Filter>("open")
  const list = useXdr<Row[]>("autopilot.changes", { status: filter }, { refetchInterval: 20_000 })
  const [open, setOpen] = useState<string | null>(null)

  const columns: Column[] = [
    { key: "status", label: "Status", render: (r) => <StatusPill status={r.status} /> },
    { key: "change_type", label: "Type", render: (r) => TYPE_LABEL[r.change_type] ?? r.change_type },
    { key: "title", label: "Change", wrap: true, className: "min-w-[22rem]" },
    { key: "metrics", label: "Backtest", render: (r) => <MetricLine m={r.metrics} />, sortable: false },
    { key: "reason", label: "Why", wrap: true, className: "min-w-[16rem] text-muted-foreground" },
    { key: "updated_at", label: "Updated", render: (r) => fmtAgo(r.updated_at), sortValue: (r) => r.updated_at },
  ]

  return (
    <Panel
      title="Change feed"
      description="Everything the autopilot proposed, shadowed, applied or rolled back. Click a change for the evidence and to decide."
      actions={<Select value={filter} onChange={setFilter} options={FILTERS.map((f) => ({ value: f, label: f.replace(/_/g, " ") }))} className="w-40" />}
    >
      <QueryState q={list}>
        {(rows) => (
          <DataTable columns={columns} rows={rows} rowKey="change_id" onRowClick={(r) => setOpen(String(r.change_id))}
            selectedKey={open} empty={filter === "open" ? "Nothing waiting. The autopilot will report here." : "No changes."} />
        )}
      </QueryState>
      <Drawer open={Boolean(open)} onClose={() => setOpen(null)}>
        {open && <ChangeDetail changeId={open} onDone={() => setOpen(null)} />}
      </Drawer>
    </Panel>
  )
}

function ChangeDetail({ changeId, onDone }: { changeId: string; onDone: () => void }) {
  const q = useXdr<Row>("autopilot.detail", { change_id: changeId })
  const decide = useXdrAction("autopilot.decide", { invalidate: ["autopilot."] })
  const pin = useXdrAction("autopilot.pin", { invalidate: ["autopilot."] })
  const [note, setNote] = useState("")
  useEffect(() => { if (decide.isSuccess) { const t = setTimeout(onDone, 1200); return () => clearTimeout(t) } }, [decide.isSuccess, onDone])

  if (q.isLoading) return <Loading />
  if (q.error) return <ErrorNote error={q.error} />
  const { change, rule, target, shadow } = q.data ?? {}
  if (!change) return <Empty>Change not found.</Empty>
  const ev: Row = change.evidence ?? {}
  const metrics: Row | undefined = ev.last_evaluation?.metrics ?? ev.metrics
  const openStatus = ["proposed", "shadow"].includes(change.status)
  const liveStatus = ["applied", "promoted", "approved"].includes(change.status)
  const before: string | undefined = ev.before?.code
  const after: string | undefined = ev.sql ?? rule?.code
  const pinRuleId: string | undefined = change.target_rule_id ?? change.rule_id

  return (
    <div className="space-y-4">
      <div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusPill status={change.status} />
          <Pill>{TYPE_LABEL[change.change_type] ?? change.change_type}</Pill>
          <Pill>{MODE_LABEL[change.mode as Mode] ?? change.mode}</Pill>
          {change.technique_id && <Pill>{change.technique_id}</Pill>}
        </div>
        <h2 className="mt-2 text-base font-semibold">{change.title}</h2>
        <div className="text-xs text-muted-foreground">
          Created {fmtTime(change.created_at)} · updated {fmtAgo(change.updated_at)}
          {change.decided_by && <> · decided by {change.decided_by}</>}
        </div>
      </div>

      {change.rationale && <Panel title="Rationale"><p className="whitespace-pre-wrap text-sm">{change.rationale}</p></Panel>}

      <Panel title="Validation" description="7-day backtest against labelled attack campaigns (ground truth) and benign telemetry">
        {metrics ? (
          <div className="space-y-2 text-sm">
            <div className="grid grid-cols-2 gap-2 md:grid-cols-4">
              <Kpi label="Recall" value={metrics.recall === null || metrics.recall === undefined ? "n/a" : `${Math.round(Number(metrics.recall) * 100)}%`} />
              <Kpi label="Matches" value={metrics.matches ?? 0} />
              <Kpi label="Benign matches" value={metrics.benign ?? 0} tone={Number(metrics.benign) ? "warn" : "good"} />
              <Kpi label="Shadow findings" value={metrics.shadow_findings ?? 0} />
            </div>
            <div className="text-muted-foreground">
              Campaigns caught: {(metrics.hit_campaigns ?? []).join(", ") || "none"}
              {(metrics.expected_campaigns ?? []).length > 0 && <> · expected: {metrics.expected_campaigns.join(", ")}</>}
            </div>
            {(ev.last_evaluation?.reason || ev.gate?.reason || change.decision_note) && (
              <div><strong>Gate:</strong> {change.decision_note ?? ev.last_evaluation?.reason ?? ev.gate?.reason}</div>
            )}
          </div>
        ) : change.change_type === "recheck_verdicts" ? (
          <div className="space-y-1 text-sm">
            <div>{ev.analyst_fp_verdicts} analyst false-positive verdicts for <span className="font-mono">{ev.entity}</span>, contradicted by:</div>
            <ul className="list-disc pl-5 text-muted-foreground">{(ev.corroboration ?? []).map((c: string, i: number) => <li key={i}>{c}</li>)}</ul>
          </div>
        ) : ["suppress_entity", "intel_allowlist"].includes(change.change_type) ? (
          <div className="text-sm">
            {change.change_type === "suppress_entity"
              ? <>{ev.fp} of {ev.total} human verdicts for <span className="font-mono">{ev.entity}</span> were false positives; no true positives, no corroborating detections. Suppression expires after {ev.expires_days} days and stays spot-checked.</>
              : <>{ev.fp} analyst false positives on <span className="font-mono">{ev.ioc_value}</span>; never confirmed or corroborated.</>}
          </div>
        ) : ev.fp_rate !== undefined ? (
          <div className="text-sm">
            {ev.false_positives} of {ev.judged} reviewed findings in 14 days were false positives ({Math.round(Number(ev.fp_rate) * 100)}%).
            {ev.fp_entities?.length > 0 && <div className="mt-1 text-muted-foreground">FP entities: {ev.fp_entities.join(", ")}</div>}
          </div>
        ) : <Empty>No backtest for this change type.</Empty>}
      </Panel>

      {Array.isArray(ev.revision_log) && ev.revision_log.length > 0 && (
        <Panel title="Self-correction" description="The autopilot rewrote this rule after it missed labelled attacks">
          <ul className="space-y-2 text-sm">
            {ev.revision_log.map((r: Row) => (
              <li key={r.revision}>
                <strong>Revision {r.revision}:</strong> recall {r.before?.recall ?? "n/a"} to {r.after?.recall ?? "n/a"}
                <div className="text-muted-foreground">{r.why}</div>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {(before || after) && (
        <Panel title={before ? "Rule change" : "Rule SQL"}>
          <div className={before ? "grid gap-3 lg:grid-cols-2" : ""}>
            {before && (
              <div>
                <div className="mb-1 text-xs font-medium text-muted-foreground">Current version</div>
                <pre className="max-h-72 overflow-auto rounded-md bg-slate-950 p-3 font-mono text-xs text-slate-300">{before}</pre>
              </div>
            )}
            {after && (
              <div>
                {before && <div className="mb-1 text-xs font-medium text-muted-foreground">Proposed version</div>}
                <pre className="max-h-72 overflow-auto rounded-md bg-slate-950 p-3 font-mono text-xs text-emerald-200">{after}</pre>
              </div>
            )}
          </div>
        </Panel>
      )}

      {Array.isArray(shadow) && shadow.length > 0 && (
        <Panel title="Shadow findings" description="What this rule would have alerted on. Analysts never saw these.">
          <ul className="space-y-1 text-sm">
            {shadow.map((f: Row, i: number) => (
              <li key={i}><span className="text-muted-foreground">{fmtTime(f.event_time)}</span> {f.description}</li>
            ))}
          </ul>
        </Panel>
      )}

      {target && (
        <div className="text-xs text-muted-foreground">
          Target rule: {target.name} ({target.rule_id}) · {target.enabled ? "enabled" : "disabled"}{target.pinned ? " · pinned" : ""}
        </div>
      )}

      <Panel title="Your decision" bodyClassName="space-y-2">
        {(openStatus || liveStatus) && (
          <TextInput value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note for the audit trail (optional)" />
        )}
        <div className="flex flex-wrap gap-2">
          {openStatus && <>
            <ActionButton action={decide} params={{ change_id: change.change_id, action: "approve", note }} variant="default">
              Approve{change.status === "shadow" ? " and go live now" : ""}
            </ActionButton>
            <ActionButton action={decide} params={{ change_id: change.change_id, action: "reject", note }} variant="outline">Reject</ActionButton>
          </>}
          {liveStatus && (
            <ActionButton action={decide} params={{ change_id: change.change_id, action: "rollback", note }} variant="destructive"
              confirm="Roll back this change? The previous version is restored from rule history.">
              <RotateCcw className="h-3.5 w-3.5" /> Roll back
            </ActionButton>
          )}
          {pinRuleId && !String(pinRuleId).startsWith("DET-") && (
            <ActionButton action={pin} params={{ rule_id: pinRuleId, action: target?.pinned || rule?.pinned ? "unpin" : "pin" }} variant="ghost">
              <Pin className="h-3.5 w-3.5" /> {target?.pinned || rule?.pinned ? "Unpin rule" : "Pin rule (autopilot hands off)"}
            </ActionButton>
          )}
        </div>
        {!openStatus && !liveStatus && <div className="text-sm text-muted-foreground">No decision needed for a {String(change.status).replace(/_/g, " ")} change.</div>}
        <ActionResult action={decide} />
        <ActionResult action={pin} />
      </Panel>

      <Disclosure title="Raw evidence">
        <JsonView value={ev} />
      </Disclosure>
    </div>
  )
}

function Policy() {
  const q = useXdr<Row[]>("autopilot.policy")
  return (
    <Panel
      title="Autonomy policy"
      description="How far the autopilot may go on its own, per change type. Hard limits always apply: it never deletes data or rules, never edits pinned rules, never auto-disables severity 4-5 or built-in rules."
    >
      <QueryState q={q}>
        {(rows) => (
          <div className="space-y-2">
            {rows.map((r) => <PolicyRow key={r.change_type} row={r} />)}
          </div>
        )}
      </QueryState>
    </Panel>
  )
}

function PolicyRow({ row }: { row: Row }) {
  const save = useXdrAction("autopilot.setPolicy", { invalidate: ["autopilot.policy"] })
  const [mode, setMode] = useState<Mode>(row.mode)
  const [maxPer, setMaxPer] = useState<number>(Number(row.max_per_cycle ?? 1))
  const [promote, setPromote] = useState<number>(Number(row.promote_after_hours ?? 24))
  const [recall, setRecall] = useState<number>(Number(row.min_recall ?? 0.5))
  const [benign, setBenign] = useState<number>(Number(row.max_benign_matches ?? 10))
  const dirty = mode !== row.mode || maxPer !== Number(row.max_per_cycle) || promote !== Number(row.promote_after_hours)
    || recall !== Number(row.min_recall) || benign !== Number(row.max_benign_matches)
  const gated = ["new_rule", "fix_broken", "tune_filter", "new_parser"].includes(row.change_type)

  return (
    <div className="grid items-end gap-2 rounded-lg border border-border p-3 md:grid-cols-[14rem_14rem_repeat(4,6.5rem)_auto]">
      <div>
        <div className="text-sm font-medium">{TYPE_LABEL[row.change_type] ?? row.change_type}</div>
        <div className="text-xs text-muted-foreground">{row.description}</div>
      </div>
      <label className="text-xs text-muted-foreground">Mode
        <Select value={mode} onChange={setMode} options={MODES.map((m) => ({ value: m, label: MODE_LABEL[m] }))} />
      </label>
      <label className="text-xs text-muted-foreground">Max / cycle
        <NumberInput value={maxPer} onChange={setMaxPer} min={0} max={20} />
      </label>
      <label className="text-xs text-muted-foreground">Shadow hours
        <NumberInput value={promote} onChange={setPromote} min={0} max={720} disabled={!gated} />
      </label>
      <label className="text-xs text-muted-foreground">Min recall
        <NumberInput value={recall} onChange={setRecall} min={0} max={1} step={0.1} disabled={!gated} />
      </label>
      <label className="text-xs text-muted-foreground">Max benign
        <NumberInput value={benign} onChange={setBenign} min={0} max={10000} disabled={!gated} />
      </label>
      <div className="flex flex-col gap-1">
        <ActionButton action={save} disabled={!dirty} variant={dirty ? "default" : "outline"}
          params={{ change_type: row.change_type, mode, max_per_cycle: maxPer, promote_after_hours: promote, min_recall: recall, max_benign_matches: benign }}>
          Save
        </ActionButton>
        {save.isError && <ErrorNote error={save.error} />}
        {save.isSuccess && <span className="text-[11px] text-emerald-600">saved</span>}
      </div>
    </div>
  )
}

