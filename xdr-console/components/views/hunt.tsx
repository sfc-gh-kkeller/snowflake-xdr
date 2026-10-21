"use client"

import { useState } from "react"
import { useXdr, useXdrAction } from "@/lib/client"
import { fmtNum, fmtAgo, truncate } from "@/lib/format"
import {
  PageHeader, Panel, QueryState, SeverityBadge, Pill, ActionButton, JsonView, Select, TextInput,
  NumberInput, Field, Loading, ErrorNote, Kpi,
} from "@/components/xdr/kit"
import { DataTable } from "@/components/xdr/data-table"

const FOCUS = ["general", "lateral_movement", "exfiltration", "persistence", "initial_access"] as const

export function Hunt() {
  const [focus, setFocus] = useState<(typeof FOCUS)[number]>("lateral_movement")
  const [hours, setHours] = useState(24)
  const [target, setTarget] = useState("jsmith")
  const [detHours, setDetHours] = useState(4)
  const [cmpHours, setCmpHours] = useState(24)

  const huntFindings = useXdr("hunt.findings")
  const compare = useXdr<{ rule: Record<string, unknown>[]; ai: Record<string, unknown>[]; aiOnly: Record<string, unknown>[] }>(
    "hunt.compare", { hours: cmpHours })
  const run = useXdrAction<unknown>("hunt.run", { invalidate: ["hunt.", "overview."] })
  const detect = useXdrAction<unknown>("hunt.detect", { invalidate: ["hunt.", "overview."] })

  return (
    <div className="space-y-4">
      <PageHeader
        persona="SOC Analyst"
        title="Threat Hunting"
        description="Cortex AI agents hunt with MITRE ATT&CK context and reason about log patterns heuristically — finding what static rules cannot — then report it as findings alongside rule-based detections."
      />

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="AI hunting agent" description="Proactive hunt across all telemetry for a focus area" bodyClassName="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Hunting focus"><Select value={focus} onChange={setFocus} options={FOCUS} /></Field>
            <Field label="Lookback (hours)"><NumberInput value={hours} onChange={setHours} min={1} max={48} /></Field>
          </div>
          <ActionButton action={run} params={{ focus, hours }} variant="default">Launch hunting agent</ActionButton>
          {run.isPending && <Loading label="AI hunting agent analyzing logs…" />}
          {run.isError && <ErrorNote error={run.error} />}
          {run.data !== undefined && <JsonView value={run.data} maxHeight={260} />}
        </Panel>
        <Panel title="AI detection agent" description="Targeted re-analysis of one entity for what rules missed" bodyClassName="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <Field label="Target entity"><TextInput value={target} onChange={(e) => setTarget(e.target.value)} className="font-mono" /></Field>
            <Field label="Lookback (hours)"><NumberInput value={detHours} onChange={setDetHours} min={1} max={24} /></Field>
          </div>
          <ActionButton action={detect} params={{ target, hours: detHours }} variant="default" disabled={!target.trim()}>Run detection agent</ActionButton>
          {detect.isPending && <Loading label={`AI detection agent analyzing ${target}…`} />}
          {detect.isError && <ErrorNote error={detect.error} />}
          {detect.data !== undefined && <JsonView value={detect.data} maxHeight={260} />}
        </Panel>
      </div>

      <Panel title="Recent hunting findings">
        <QueryState q={huntFindings}>
          {(rows) => (
            <DataTable
              rows={rows} rowKey="finding_id" dense maxHeight={320}
              empty="No hunting findings yet — launch the hunting agent above."
              columns={[
                { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
                { key: "focus_area", label: "Focus", render: (r) => r.focus_area ? <Pill>{String(r.focus_area).replace(/_/g, " ")}</Pill> : null },
                { key: "mitre_technique_id", label: "Technique", className: "font-mono text-xs" },
                { key: "confidence", label: "Conf", align: "right" },
                { key: "description", label: "Description", render: (r) => truncate(r.description, 120) },
                { key: "detection_time", label: "Detected", render: (r) => fmtAgo(r.detection_time) },
              ]}
            />
          )}
        </QueryState>
      </Panel>

      <Panel
        title="AI agents vs. rules"
        description="Same window, two detection approaches — where does AI add coverage beyond static pattern matching?"
        actions={<Field label="Window (hours)"><NumberInput value={cmpHours} onChange={setCmpHours} min={1} max={168} className="w-24" /></Field>}
        bodyClassName="space-y-4"
      >
        <QueryState q={compare}>
          {(d) => (
            <>
              <div className="grid grid-cols-3 gap-3">
                <Kpi label="Rule-based findings (top 25)" value={fmtNum(d.rule.length)} />
                <Kpi label="AI agent findings (top 25)" value={fmtNum(d.ai.length)} tone="accent" />
                <Kpi label="Techniques only AI caught" value={fmtNum(new Set(d.aiOnly.map((r) => r.mitre_technique_id)).size)} tone={d.aiOnly.length ? "good" : "default"} />
              </div>
              <div className="grid gap-4 xl:grid-cols-2">
                <DataTable
                  rows={d.rule} dense maxHeight={300} empty="No rule-based findings in this window."
                  columns={[
                    { key: "rule_id", label: "Rule", className: "font-mono text-xs" },
                    { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
                    { key: "mitre_technique_id", label: "Technique", className: "font-mono text-xs" },
                    { key: "description", label: "Rule finding", render: (r) => truncate(r.description, 70) },
                  ]}
                />
                <DataTable
                  rows={d.ai} dense maxHeight={300} empty="No AI findings in this window — run an agent above."
                  columns={[
                    { key: "detection_source", label: "Agent", render: (r) => <Pill>{String(r.detection_source).replace("ai_", "").replace("_agent", "")}</Pill> },
                    { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
                    { key: "mitre_technique_id", label: "Technique", className: "font-mono text-xs" },
                    { key: "description", label: "AI finding", render: (r) => truncate(r.description, 70) },
                  ]}
                />
              </div>
              {d.aiOnly.length > 0 && (
                <div>
                  <div className="mb-2 text-sm font-medium">Coverage gaps closed by AI</div>
                  <DataTable
                    rows={d.aiOnly} dense maxHeight={240}
                    columns={[
                      { key: "mitre_technique_id", label: "Technique", className: "font-mono text-xs" },
                      { key: "finding", label: "Finding", render: (r) => truncate(r.finding, 120) },
                      { key: "detection_source", label: "Agent" },
                      { key: "confidence", label: "Conf", align: "right" },
                    ]}
                  />
                </div>
              )}
            </>
          )}
        </QueryState>
      </Panel>
    </div>
  )
}
