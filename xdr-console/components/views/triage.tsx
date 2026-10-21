"use client"

import { useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { useRouter, useSearchParams } from "next/navigation"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtTime, fmtAgo, fmtNum, truncate } from "@/lib/format"
import {
  PageHeader, Panel, QueryState, SeverityBadge, Pill, DispositionPill, ActionButton, ActionResult,
  Chips, Select, TextInput, TextArea, Field, JsonView, Disclosure, Loading, ErrorNote, Drawer,
} from "@/components/xdr/kit"
import { Markdown } from "@/components/xdr/markdown"
import { DataTable } from "@/components/xdr/data-table"
import { Button } from "@/components/ui/button"

const STATUSES = ["new", "investigating", "contained", "resolved", "dismissed"] as const
const SEVERITIES = ["5", "4", "3", "2", "1"] as const
const CATEGORIES = ["all", "identity", "endpoint", "network", "cloud", "application", "custom"] as const
const SOURCES = ["all", "stored_procedure", "custom_rule", "attack_graph", "ml_anomaly", "ai_detection_agent", "ai_hunting_agent"] as const
const DISPOSITIONS = ["", "true_positive", "false_positive", "benign", "mitigated_by_control"] as const

type Status = (typeof STATUSES)[number]
type Sev = (typeof SEVERITIES)[number]

export function Triage() {
  const params = useSearchParams()
  const router = useRouter()
  const [statuses, setStatuses] = useState<Status[]>(["new", "investigating"])
  const [severities, setSeverities] = useState<Sev[]>(["5", "4", "3"])
  const [category, setCategory] = useState<(typeof CATEGORIES)[number]>("all")
  const [source, setSource] = useState<(typeof SOURCES)[number]>("all")
  const [search, setSearch] = useState("")
  const [debounced, setDebounced] = useState("")
  const [selected, setSelected] = useState<string[]>([])
  const selectedId = params.get("id")

  useEffect(() => {
    const t = setTimeout(() => setDebounced(search), 350)
    return () => clearTimeout(t)
  }, [search])

  const filter = { statuses, severities, category, source, search: debounced }
  const list = useXdr("triage.list", filter)
  const invalidate = { invalidate: ["triage.", "overview."] }
  const trainFp = useXdrAction("triage.trainFp", invalidate)
  const scoreFp = useXdrAction("triage.scoreFp", invalidate)
  const assess = useXdrAction("triage.assessControls", invalidate)
  const bulk = useXdrAction("triage.bulk", invalidate)

  const stats = useMemo(() => {
    const r = list.data ?? []
    const scored = r.filter((x) => x.ai_fp_probability !== null && x.ai_fp_probability !== undefined)
    return {
      total: r.length,
      likelyTp: scored.filter((x) => Number(x.ai_fp_probability) < 0.3).length,
      likelyFp: scored.filter((x) => Number(x.ai_fp_probability) > 0.7).length,
      covered: r.filter((x) => x.control_covered).length,
    }
  }, [list.data])

  const open = (id: string | null) => {
    const q = new URLSearchParams(params.toString())
    if (id) q.set("id", id); else q.delete("id")
    router.replace(`/triage${q.toString() ? `?${q}` : ""}`, { scroll: false })
  }

  return (
    <div className="space-y-4">
      <PageHeader
        persona="SOC Analyst"
        title="Triage & Cases"
        description="Risk-ranked findings with Cortex AI triage, the learned false-positive model and compensating-control coverage. Click a finding to work the case."
        actions={<>
          <ActionButton action={trainFp}>Train FP model</ActionButton>
          <ActionButton action={scoreFp}>Apply FP scoring</ActionButton>
          <ActionButton action={assess}>Assess control coverage</ActionButton>
        </>}
      />
      <ActionResult action={trainFp} /><ActionResult action={scoreFp} /><ActionResult action={assess} />

      <Panel bodyClassName="grid gap-3 md:grid-cols-2 xl:grid-cols-[auto_auto_10rem_12rem_1fr]">
        <Field label="Status"><Chips options={STATUSES} value={statuses} onChange={setStatuses} /></Field>
        <Field label="Severity"><Chips options={SEVERITIES} value={severities} onChange={setSeverities} /></Field>
        <Field label="Category"><Select value={category} onChange={setCategory} options={CATEGORIES} /></Field>
        <Field label="Detection source"><Select value={source} onChange={setSource} options={SOURCES} /></Field>
        <Field label="Search entity / description">
          <TextInput value={search} onChange={(e) => setSearch(e.target.value)} placeholder="e.g. jsmith, 10.1.5.107, lateral" />
        </Field>
      </Panel>

      <div>
        <Panel
          title={`${fmtNum(stats.total)} findings`}
          description={`AI triage: ${stats.likelyTp} likely true positive · ${stats.likelyFp} likely false positive · ${stats.covered} covered by controls`}
          actions={selected.length > 0 && <>
            <span className="text-xs text-muted-foreground">{selected.length} selected</span>
            <ActionButton action={bulk} params={{ finding_ids: selected, action: "confirm_true_positive" }} variant="destructive">Confirm TP</ActionButton>
            <ActionButton action={bulk} params={{ finding_ids: selected, action: "dismiss_false_positive" }}>Dismiss as FP</ActionButton>
            <Button size="sm" variant="ghost" onClick={() => setSelected([])}>Clear</Button>
          </>}
        >
          <ActionResult action={bulk} />
          <QueryState q={list}>
            {(rows) => (
              <DataTable
                rows={rows} rowKey="finding_id" maxHeight={640} dense
                selectable selected={selected} onSelectedChange={setSelected}
                selectedKey={selectedId} onRowClick={(r) => open(r.finding_id)}
                empty="Queue is clear for these filters."
                columns={[
                  { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
                  { key: "risk_score", label: "Risk", align: "right", render: (r) => fmtNum(r.risk_score, 0) },
                  { key: "rule_id", label: "Rule", className: "font-mono text-xs whitespace-nowrap" },
                  { key: "entity", label: "Entity", className: "font-mono text-xs" },
                  { key: "description", label: "Description", wrap: true, render: (r) => <span title={r.description}>{truncate(r.description, 110)}</span> },
                  { key: "status", label: "Status", render: (r) => <Pill>{r.status}</Pill> },
                  {
                    key: "signals", label: "Signals", sortable: false,
                    render: (r) => (
                      <div className="flex flex-wrap gap-1">
                        <DispositionPill value={r.disposition} />
                        {r.ai_fp_probability !== null && r.ai_fp_probability !== undefined &&
                          <Pill tone={Number(r.ai_fp_probability) > 0.7 ? "dismissed" : Number(r.ai_fp_probability) < 0.3 ? "error" : undefined}>
                            AI FP {Math.round(Number(r.ai_fp_probability) * 100)}%
                          </Pill>}
                        {r.fp_rate_pct !== null && r.fp_rate_pct !== undefined && Number(r.fp_rate_pct) > 0 &&
                          <Pill tone="dismissed">hist FP {fmtNum(r.fp_rate_pct)}%</Pill>}
                        {r.incident_id && <Pill tone="investigating">incident</Pill>}
                      </div>
                    ),
                  },
                  { key: "detection_time", label: "Detected", render: (r) => <span title={fmtTime(r.detection_time)}>{fmtAgo(r.detection_time)}</span> },
                ]}
              />
            )}
          </QueryState>
        </Panel>

      </div>

      <Drawer open={Boolean(selectedId)} onClose={() => open(null)}>
        {selectedId && <CaseDetail key={selectedId} findingId={selectedId} onClose={() => open(null)} />}
      </Drawer>
    </div>
  )
}

function CaseDetail({ findingId, onClose }: { findingId: string; onClose: () => void }) {
  const detail = useXdr<Row>("triage.detail", { finding_id: findingId })
  const similar = useXdrAction<Row[]>("triage.similar")
  const update = useXdrAction("triage.update", { invalidate: ["triage.", "overview."] })
  const aiTriage = useXdrAction("triage.aiTriage", { invalidate: ["triage."] })

  const [status, setStatus] = useState<Status>("new")
  const [assignee, setAssignee] = useState("")
  const [disposition, setDisposition] = useState<(typeof DISPOSITIONS)[number]>("")
  const [notes, setNotes] = useState("")

  useEffect(() => {
    const f = detail.data
    if (!f) return
    setStatus((STATUSES as readonly string[]).includes(f.status) ? f.status : "new")
    setAssignee(f.assigned_to ?? "")
    setDisposition((DISPOSITIONS as readonly string[]).includes(f.disposition ?? "") ? (f.disposition ?? "") : "")
    setNotes(f.triage_notes ?? "")
  }, [detail.data])

  if (detail.isLoading) return <Panel title="Case detail"><Loading /></Panel>
  if (detail.error) return <Panel title="Case detail"><ErrorNote error={detail.error} /></Panel>
  const f = detail.data!

  return (
    <Panel
      title={<span className="flex items-center gap-2"><SeverityBadge severity={f.severity} /> {f.rule_name ?? f.rule_id}</span>}
      description={<span className="font-mono">{f.finding_id}</span>}
      actions={<Button size="sm" variant="ghost" onClick={onClose}>Close</Button>}
      bodyClassName="space-y-4"
    >
      <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
        <Meta label="Risk score" value={fmtNum(f.risk_score, 1)} />
        <Meta label="Confidence" value={fmtNum(f.confidence)} />
        <Meta label="MITRE" value={[f.mitre_tactic_id, f.mitre_technique_id].filter(Boolean).join(" · ") || "–"} />
        <Meta label="AI FP probability" value={f.ai_fp_probability === null || f.ai_fp_probability === undefined ? "not scored" : `${Math.round(Number(f.ai_fp_probability) * 100)}%`} />
      </div>

      <p className="text-sm">{f.description}</p>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-muted-foreground">Pivot:</span>
        {f.user_name && <Link className="rounded border border-border px-2 py-0.5 font-mono hover:bg-muted" href={`/entity?q=${encodeURIComponent(f.user_name)}`}>user {f.user_name}</Link>}
        {f.src && <Link className="rounded border border-border px-2 py-0.5 font-mono hover:bg-muted" href={`/entity?q=${encodeURIComponent(f.src)}`}>src {f.src}</Link>}
        {f.dest && <Link className="rounded border border-border px-2 py-0.5 font-mono hover:bg-muted" href={`/entity?q=${encodeURIComponent(f.dest)}`}>dest {f.dest}</Link>}
        {f.incident_id && <Link className="rounded border border-violet-500/40 px-2 py-0.5 hover:bg-muted" href={`/investigations?id=${encodeURIComponent(f.incident_id)}`}>incident →</Link>}
        <Link className="rounded border border-border px-2 py-0.5 hover:bg-muted" href={`/detections?rule=${encodeURIComponent(f.rule_id)}`}>rule {f.rule_id}</Link>
      </div>

      {f.disposition && (
        <div className="flex items-start gap-2 text-sm">
          <DispositionPill value={f.disposition} />
          {f.triage_notes && <span className="text-muted-foreground">{f.triage_notes}</span>}
        </div>
      )}

      {f.ai_explanation && (
        <Disclosure title="Cortex AI triage explanation" defaultOpen>
          <Markdown text={String(f.ai_explanation)} />
        </Disclosure>
      )}
      {f.evidence && <Disclosure title="Evidence"><JsonView value={f.evidence} /></Disclosure>}

      <div className="rounded-md border border-border p-3">
        <div className="mb-2 flex items-center justify-between">
          <div>
            <div className="text-sm font-medium">Similar findings</div>
            <div className="text-xs text-muted-foreground">Cortex AI semantic similarity — is this part of a bigger campaign?</div>
          </div>
          <ActionButton action={similar} params={{ finding_id: findingId }}>Find similar</ActionButton>
        </div>
        {similar.isPending && <Loading label="Comparing embeddings…" />}
        {similar.isError && <ErrorNote error={similar.error} />}
        {similar.data && (
          <DataTable
            rows={similar.data} dense maxHeight={240} empty="No similar findings."
            columns={[
              { key: "similarity", label: "Sim", align: "right", render: (r) => fmtNum(r.similarity, 2) },
              { key: "rule_id", label: "Rule", className: "font-mono text-xs" },
              { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
              { key: "user_name", label: "User", className: "font-mono text-xs" },
              { key: "description", label: "Description", render: (r) => truncate(r.description, 70) },
            ]}
          />
        )}
      </div>

      <div className="space-y-3 rounded-md border border-border p-3">
        <div className="text-sm font-medium">Case workflow</div>
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Status"><Select value={status} onChange={setStatus} options={STATUSES} /></Field>
          <Field label="Assign to"><TextInput value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="analyst" /></Field>
          <Field label="Disposition">
            <Select value={disposition} onChange={setDisposition}
              options={DISPOSITIONS.map((d) => ({ value: d, label: d ? d.replace(/_/g, " ") : "— unchanged —" }))} />
          </Field>
        </div>
        <Field label="Triage notes"><TextArea rows={2} value={notes} onChange={(e) => setNotes(e.target.value)} /></Field>
        <div className="flex flex-wrap gap-2">
          <ActionButton action={update} variant="default"
            params={{ finding_id: findingId, status, assigned_to: assignee, disposition, triage_notes: notes }}>
            Update case
          </ActionButton>
          <ActionButton action={aiTriage} params={{ batch: 1 }}>Run AI triage (next untriaged)</ActionButton>
        </div>
        <ActionResult action={update} /><ActionResult action={aiTriage} />
      </div>
    </Panel>
  )
}

function Meta({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-md bg-muted px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="font-medium">{value}</div>
    </div>
  )
}
