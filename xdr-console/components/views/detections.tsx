"use client"

import { useMemo, useState } from "react"
import { useSearchParams } from "next/navigation"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtNum, fmtAgo, truncate } from "@/lib/format"
import {
  PageHeader, Panel, QueryState, SeverityBadge, Pill, ActionButton, ActionResult, Select, Tabs, Kpi,
} from "@/components/xdr/kit"
import { DataTable } from "@/components/xdr/data-table"
import { RankBars } from "@/components/xdr/charts"
import { cn } from "@/lib/utils"

const CATEGORIES = ["all", "identity", "endpoint", "network", "cloud", "application", "custom"] as const
const TYPES = ["all", "ttp", "anomaly", "hunting", "correlation"] as const

export function Detections() {
  const params = useSearchParams()
  const [tab, setTab] = useState<"library" | "coverage" | "health">(params.get("tab") === "health" ? "health" : params.get("tab") === "coverage" ? "coverage" : "library")
  return (
    <div className="space-y-4">
      <PageHeader
        persona="Detection Engineer"
        title="Detections"
        description="The detection catalog mapped to MITRE ATT&CK, where coverage is thin, and whether every rule and data source is healthy."
      />
      <Tabs value={tab} onChange={setTab} tabs={[
        { value: "library", label: "Rule library" },
        { value: "coverage", label: "MITRE coverage" },
        { value: "health", label: "Health & freshness" },
      ]} />
      {tab === "library" && <Library initialRule={params.get("rule")} />}
      {tab === "coverage" && <Coverage />}
      {tab === "health" && <Health />}
    </div>
  )
}

function Library({ initialRule }: { initialRule: string | null }) {
  const [category, setCategory] = useState<(typeof CATEGORIES)[number]>("all")
  const [type, setType] = useState<(typeof TYPES)[number]>("all")
  const [enabledOnly, setEnabledOnly] = useState(true)
  const q = useXdr("detections.library", { category, type, enabledOnly })
  const runAll = useXdrAction("detections.runAll", { invalidate: ["detections.", "overview.", "triage."] })

  return (
    <Panel
      title={q.data ? `${q.data.length} rules` : "Rules"}
      actions={<>
        <div className="w-36"><Select value={category} onChange={setCategory} options={CATEGORIES} /></div>
        <div className="w-36"><Select value={type} onChange={setType} options={TYPES} /></div>
        <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <input type="checkbox" checked={enabledOnly} onChange={(e) => setEnabledOnly(e.target.checked)} /> enabled only
        </label>
        <ActionButton action={runAll} variant="default">Run all detections</ActionButton>
      </>}
      bodyClassName="space-y-3"
    >
      <ActionResult action={runAll} />
      <QueryState q={q}>
        {(rows) => (
          <DataTable
            rows={rows} rowKey="rule_id" dense maxHeight={680} selectedKey={initialRule}
            columns={[
              { key: "rule_id", label: "Rule", className: "font-mono text-xs" },
              { key: "rule_name", label: "Name", wrap: true },
              { key: "category", label: "Category", render: (r) => <Pill>{r.category}</Pill> },
              { key: "detection_type", label: "Type" },
              { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
              { key: "mitre_technique_id", label: "Technique", className: "font-mono text-xs", render: (r) => <span title={r.mitre_technique}>{r.mitre_technique_id}</span> },
              { key: "mitre_tactic", label: "Tactic" },
              { key: "findings_7d", label: "7d", align: "right" },
              { key: "findings_total", label: "Total", align: "right" },
              { key: "last_fired", label: "Last fired", render: (r) => fmtAgo(r.last_fired) },
              { key: "enabled", label: "On", render: (r) => r.enabled ? <Pill tone="success">on</Pill> : <Pill tone="dismissed">off</Pill> },
            ]}
          />
        )}
      </QueryState>
    </Panel>
  )
}

function coverageTone(r: Row): { label: string; cls: string } {
  if (Number(r.ttp_count) > 0) return { label: "TTP coverage", cls: "border-emerald-500/50 bg-emerald-500/15" }
  if (Number(r.anomaly_count) > 0) return { label: "Anomaly only", cls: "border-amber-500/50 bg-amber-500/15" }
  if (Number(r.rule_count) > 0) return { label: "Other rules", cls: "border-sky-500/50 bg-sky-500/15" }
  return { label: "Gap", cls: "border-red-500/50 bg-red-500/15" }
}

function Coverage() {
  const coverage = useXdr("detections.coverage")
  const gaps = useXdr("detections.gaps")
  const covered = useMemo(() => (coverage.data ?? []).filter((r) => Number(r.rule_count) > 0).length, [coverage.data])

  return (
    <div className="space-y-4">
      <QueryState q={coverage}>
        {(rows) => (
          <>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Kpi label="Tactics covered" value={`${covered}/${rows.length}`} tone={covered === rows.length ? "good" : "warn"} />
              <Kpi label="Enabled rules mapped" value={fmtNum(rows.reduce((s, r) => s + Number(r.rule_count), 0))} />
              <Kpi label="Findings (7d)" value={fmtNum(rows.reduce((s, r) => s + Number(r.findings_7d), 0))} />
              <Kpi label="Technique gaps" value={fmtNum(gaps.data?.length ?? 0)} tone={(gaps.data?.length ?? 0) > 0 ? "danger" : "good"} />
            </div>
            <Panel title="ATT&CK tactic heatmap" description="Ordered along the kill chain. Green = TTP rule · amber = anomaly only · red = no coverage">
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7">
                {rows.map((r) => {
                  const t = coverageTone(r)
                  return (
                    <div key={String(r.tactic_id)} className={cn("rounded-lg border p-3", t.cls)}>
                      <div className="font-mono text-[10px] text-muted-foreground">{r.tactic_id}</div>
                      <div className="text-sm font-semibold leading-tight">{r.tactic_name}</div>
                      <div className="mt-2 text-xs">{fmtNum(r.rule_count)} rules · {fmtNum(r.findings_7d)} hits</div>
                      <div className="text-[11px] text-muted-foreground">{t.label}</div>
                    </div>
                  )
                })}
              </div>
            </Panel>
            <Panel title="Findings by tactic (7 days)">
              <RankBars data={rows.filter((r) => Number(r.findings_7d) > 0)} labelKey="tactic_name" valueKey="findings_7d" valueLabel="findings" />
            </Panel>
          </>
        )}
      </QueryState>
      <Panel title="Coverage gap finder" description="MITRE techniques with no enabled detection rule — where the platform is blind. Close them with the AI rule generator in Rules & IOCs.">
        <QueryState q={gaps}>
          {(rows) => (
            <DataTable
              rows={rows} dense maxHeight={420} empty="Full technique coverage — no gaps."
              columns={[
                { key: "technique_id", label: "Technique", className: "font-mono text-xs" },
                { key: "technique_name", label: "Name" },
                { key: "tactic_name", label: "Tactic" },
                { key: "description", label: "Description", wrap: true, render: (r) => truncate(r.description, 120) },
              ]}
            />
          )}
        </QueryState>
      </Panel>
    </div>
  )
}

function Health() {
  const q = useXdr<{ health: Row[]; freshness: Row[]; errors: Row[] }>("detections.health")
  return (
    <QueryState q={q}>
      {(d) => {
        const fired = d.health.filter((r) => Number(r.findings_7d) > 0).length
        const erroring = d.health.filter((r) => Number(r.recent_errors) > 0).length
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Kpi label="Rules" value={fmtNum(d.health.length)} />
              <Kpi label="Fired in 7d" value={fmtNum(fired)} tone="good" />
              <Kpi label="Silent rules" value={fmtNum(d.health.length - fired)} tone="warn" hint="no findings in 7d" />
              <Kpi label="Rules with errors" value={fmtNum(erroring)} tone={erroring ? "danger" : "good"} />
            </div>
            <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
              <Panel title="Detection health">
                <DataTable
                  rows={d.health} rowKey="rule_id" dense maxHeight={520}
                  columns={[
                    { key: "status", label: "Health", sortable: false, render: (r) => Number(r.recent_errors) > 0 ? <Pill tone="error">errors</Pill> : r.last_fired ? <Pill tone="success">firing</Pill> : <Pill tone="contained">silent</Pill> },
                    { key: "rule_id", label: "Rule", className: "font-mono text-xs" },
                    { key: "rule_name", label: "Name", wrap: true },
                    { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
                    { key: "findings_7d", label: "7d", align: "right" },
                    { key: "last_fired", label: "Last fired", render: (r) => fmtAgo(r.last_fired) },
                    { key: "recent_errors", label: "Errors", align: "right" },
                  ]}
                />
              </Panel>
              <div className="space-y-4">
                <Panel title="Data pipeline freshness">
                  <DataTable
                    rows={d.freshness} rowKey="source_table" dense
                    columns={[
                      { key: "source_table", label: "Source", className: "font-mono text-xs" },
                      { key: "event_count", label: "Events", align: "right", render: (r) => fmtNum(r.event_count) },
                      { key: "latest_event", label: "Latest", render: (r) => fmtAgo(r.latest_event) },
                      { key: "hours_old", label: "Age", align: "right", render: (r) => <span className={Number(r.hours_old) > 24 ? "text-red-500" : ""}>{fmtNum(r.hours_old)}h</span> },
                    ]}
                  />
                </Panel>
                <Panel title="Recent custom rule errors">
                  <DataTable
                    rows={d.errors} dense maxHeight={260} empty="No custom rule errors — all rules healthy."
                    columns={[
                      { key: "error_time", label: "When", render: (r) => fmtAgo(r.error_time) },
                      { key: "rule_name", label: "Rule" },
                      { key: "stage", label: "Stage" },
                      { key: "error_message", label: "Error", wrap: true },
                    ]}
                  />
                </Panel>
              </div>
            </div>
          </div>
        )
      }}
    </QueryState>
  )
}
