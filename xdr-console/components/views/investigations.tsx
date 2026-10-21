"use client"

import { useMemo, useState } from "react"
import Link from "next/link"
import { useRouter, useSearchParams } from "next/navigation"
import { ChevronRight } from "lucide-react"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtTime, fmtNum, fmtAgo, truncate } from "@/lib/format"
import { layoutEdges } from "@/lib/graph"
import {
  PageHeader, Panel, QueryState, SeverityBadge, Pill, DispositionPill, ActionButton, ActionResult,
  AiTextPanel, Empty, Loading, ErrorNote, Tabs,
} from "@/components/xdr/kit"
import { DataTable } from "@/components/xdr/data-table"
import { GraphCanvas, GraphLegend } from "@/components/xdr/graph-canvas"
import { Button } from "@/components/ui/button"

export function Investigations() {
  const params = useSearchParams()
  const router = useRouter()
  const [status, setStatus] = useState<"all" | "open" | "closed">("open")
  const list = useXdr("incidents.list", { status })
  const selectedId = params.get("id")

  const open = (id: string | null) =>
    router.replace(id ? `/investigations?id=${encodeURIComponent(id)}` : "/investigations", { scroll: false })

  return (
    <div className="space-y-4">
      <PageHeader
        persona="SOC Analyst"
        title="Investigations"
        description="Findings correlated into incidents by entity and kill-chain stage. Open one for the kill chain, entity graph, attacker timeline and an AI-written campaign story."
      />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <Panel
          title="Incidents"
          actions={<Tabs value={status} onChange={setStatus}
            tabs={[{ value: "open", label: "Open" }, { value: "all", label: "All" }, { value: "closed", label: "Closed" }]} />}
          bodyClassName="pt-0"
        >
          <QueryState q={list}>
            {(rows) => (
              <DataTable
                rows={rows} rowKey="incident_id" maxHeight={720} dense
                selectedKey={selectedId} onRowClick={(r) => open(r.incident_id)}
                empty="No incidents for this filter."
                columns={[
                  { key: "priority", label: "Pri", render: (r) => <Pill tone={r.priority === "P1" ? "error" : undefined}>{r.priority}</Pill> },
                  { key: "title", label: "Incident", render: (r) => <span title={r.title}>{truncate(r.title, 48)}</span> },
                  { key: "risk_score", label: "Risk", align: "right", render: (r) => fmtNum(r.risk_score, 0) },
                  { key: "tactic_count", label: "Tactics", align: "right" },
                  { key: "finding_count", label: "Findings", align: "right" },
                  { key: "last_seen", label: "Last seen", render: (r) => fmtAgo(r.last_seen) },
                ]}
              />
            )}
          </QueryState>
        </Panel>
        <div>
          {selectedId
            ? <IncidentDetail key={selectedId} incidentId={selectedId} onClose={() => open(null)} />
            : <Panel title="Incident detail"><Empty>Select an incident to investigate.</Empty></Panel>}
        </div>
      </div>
    </div>
  )
}

function IncidentDetail({ incidentId, onClose }: { incidentId: string; onClose: () => void }) {
  const router = useRouter()
  const q = useXdr<{ incident: Row; killChain: Row[]; graph: Row[]; timeline: Row[]; findings: Row[] }>(
    "incidents.detail", { incident_id: incidentId })
  const story = useXdrAction("incidents.story")
  const setStatus = useXdrAction("incidents.setStatus", { invalidate: ["incidents.", "overview."] })

  const graph = useMemo(() => layoutEdges((q.data?.graph ?? []).map((e) => ({
    source: String(e.src_entity_value), target: String(e.dst_entity_value),
    label: `${e.relationship_type}${e.event_count ? ` ×${e.event_count}` : ""}`,
  }))), [q.data?.graph])

  if (q.isLoading) return <Panel title="Incident detail"><Loading /></Panel>
  if (q.error) return <Panel title="Incident detail"><ErrorNote error={q.error} /></Panel>
  const { incident: i, killChain, timeline, findings } = q.data!

  return (
    <div className="space-y-4">
      <Panel
        title={<span className="flex items-center gap-2"><Pill tone={i.priority === "P1" ? "error" : undefined}>{i.priority}</Pill>{i.title}</span>}
        description={<span className="font-mono">{i.incident_id}</span>}
        actions={<>
          <ActionButton action={setStatus} params={{ incident_id: incidentId, status: "investigating" }}>Investigating</ActionButton>
          <ActionButton action={setStatus} params={{ incident_id: incidentId, status: "contained" }}>Contained</ActionButton>
          <ActionButton action={setStatus} params={{ incident_id: incidentId, status: "closed" }} confirm="Close this incident?">Close</ActionButton>
          <Button size="sm" variant="ghost" onClick={onClose}>✕</Button>
        </>}
        bodyClassName="space-y-3"
      >
        <ActionResult action={setStatus} />
        <div className="grid grid-cols-2 gap-2 text-xs sm:grid-cols-5">
          <Stat label="Severity" value={<SeverityBadge severity={i.severity} />} />
          <Stat label="Status" value={<Pill>{i.status}</Pill>} />
          <Stat label="Risk" value={fmtNum(i.risk_score, 0)} />
          <Stat label="Duration" value={`${fmtNum(i.duration_hours, 1)} h`} />
          <Stat label="Primary entity" value={
            <Link className="font-mono text-primary hover:underline" href={`/entity?q=${encodeURIComponent(i.primary_entity)}`}>{i.primary_entity}</Link>} />
        </div>
        {i.description && <p className="text-sm text-muted-foreground">{i.description}</p>}
        <div className="text-xs text-muted-foreground">First seen {fmtTime(i.first_seen)} · last seen {fmtTime(i.last_seen)}</div>
      </Panel>

      <AiTextPanel
        title="AI Campaign Story"
        description="Cortex AI traces attack paths from the primary entity and narrates how the events connect"
        action={story} params={{ incident_id: incidentId }}
        buttonLabel="Generate campaign story"
        idleText="Generate an attacker narrative for this incident from its findings, kill chain and traced attack paths."
      />

      <Panel title="Kill chain progression" description="MITRE ATT&CK tactics observed, in order">
        {killChain.length ? (
          <div className="flex flex-wrap items-center gap-1.5">
            {killChain.map((k, idx) => (
              <div key={`${k.stage_order}-${idx}`} className="flex items-center gap-1.5">
                <div className="rounded-lg border border-primary/40 bg-primary/10 px-3 py-2">
                  <div className="text-xs font-semibold">{k.tactic_name}</div>
                  <div className="text-[11px] text-muted-foreground">{fmtNum(k.finding_count)} finding(s) · {fmtTime(k.first_observed)}</div>
                </div>
                {idx < killChain.length - 1 && <ChevronRight className="h-4 w-4 text-muted-foreground" />}
              </div>
            ))}
          </div>
        ) : <Empty>No kill-chain data for this incident.</Empty>}
      </Panel>

      <Panel title="Entity relationship graph" actions={<GraphLegend />}>
        {graph.nodes.length ? <GraphCanvas nodes={graph.nodes} edges={graph.edges} />
          : <Empty>No entity graph data for this incident.</Empty>}
      </Panel>

      <Panel title="Attacker timeline">
        <DataTable
          rows={timeline} dense maxHeight={320} empty="No timeline data."
          columns={[
            { key: "event_time", label: "Time", render: (r) => fmtTime(r.event_time) },
            { key: "action_summary", label: "Action" },
            { key: "tactic_id", label: "Tactic", className: "font-mono text-xs" },
            { key: "technique_id", label: "Technique", className: "font-mono text-xs" },
            { key: "actor_entity", label: "Actor", className: "font-mono text-xs" },
            { key: "target_entity", label: "Target", className: "font-mono text-xs" },
          ]}
        />
      </Panel>

      <Panel title={`Associated findings (${findings.length})`}>
        <DataTable
          rows={findings} rowKey="finding_id" dense maxHeight={360}
          onRowClick={(r) => router.push(`/triage?id=${encodeURIComponent(r.finding_id)}`)}
          columns={[
            { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
            { key: "rule_id", label: "Rule", className: "font-mono text-xs" },
            { key: "mitre_technique_id", label: "Technique", className: "font-mono text-xs" },
            { key: "description", label: "Description", render: (r) => truncate(r.description, 90) },
            { key: "disposition", label: "Disposition", render: (r) => <DispositionPill value={r.disposition} /> },
            { key: "detection_time", label: "Detected", render: (r) => fmtAgo(r.detection_time) },
          ]}
        />
      </Panel>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-md bg-muted px-2 py-1.5">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-0.5 font-medium">{value}</div>
    </div>
  )
}

