"use client"

import { useEffect, useMemo, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import {
  ResponsiveContainer, ScatterChart, Scatter, XAxis, YAxis, ZAxis, CartesianGrid, Tooltip, LabelList,
} from "recharts"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtNum, fmtAgo, fmtTime } from "@/lib/format"
import type { LayoutNode, LayoutEdge } from "@/lib/graph"
import {
  PageHeader, Panel, QueryState, SeverityBadge, Pill, ActionButton, ActionResult, AiTextPanel,
  Select, Tabs, Empty, Loading, ErrorNote, Kpi,
} from "@/components/xdr/kit"
import { DataTable } from "@/components/xdr/data-table"
import { GraphCanvas, GraphLegend } from "@/components/xdr/graph-canvas"

type TraceResult = {
  paths: { hops?: number; entities?: string[]; suspicious?: boolean; last_seen?: string; variants?: number }[]
  traversals: number
  graph: { nodes: LayoutNode[]; edges: LayoutEdge[] }
  incident_id: string | null
}

const CAMPAIGN_START = "host:10.1.5.107"

export function AttackGraph() {
  const [tab, setTab] = useState<"paths" | "rattle" | "map">("paths")
  return (
    <div className="space-y-4">
      <PageHeader
        persona="SOC Analyst"
        title="Attack Graph"
        description="Every authentication, network and process event becomes a graph edge in Snowflake. Trace multi-hop lateral movement with a recursive query, catch attackers trying many doors, and see where activity originates."
      />
      <Tabs value={tab} onChange={setTab} tabs={[
        { value: "paths", label: "Lateral movement" },
        { value: "rattle", label: "Door rattling" },
        { value: "map", label: "Threat map" },
      ]} />
      {tab === "paths" && <PathExplorer />}
      {tab === "rattle" && <DoorRattling />}
      {tab === "map" && <ThreatMap />}
    </div>
  )
}

function PathExplorer() {
  const params = useSearchParams()
  const router = useRouter()
  const entities = useXdr("graph.entities")
  const rebuild = useXdrAction("graph.rebuild", { invalidate: ["graph."] })
  const [start, setStart] = useState<string>(params.get("start") ?? "")

  // Default to the seeded campaign entry point when present, else the top fan-out source
  useEffect(() => {
    if (start || !entities.data?.length) return
    const hasCampaign = entities.data.some((e) => e.src_entity === CAMPAIGN_START)
    setStart(hasCampaign ? CAMPAIGN_START : String(entities.data[0].src_entity))
  }, [entities.data, start])

  const trace = useXdr<TraceResult>("graph.trace", { entity: start }, { enabled: Boolean(start) })
  const story = useXdrAction("incidents.story")

  const options = useMemo(() => {
    const list = (entities.data ?? []).map((e) => ({
      value: String(e.src_entity), label: `${e.src_entity}  (${fmtNum(e.fan_out)} doors)`,
    }))
    if (start && !list.some((o) => o.value === start)) list.unshift({ value: start, label: start })
    return list
  }, [entities.data, start])

  const deepest = trace.data?.paths?.[0]
  return (
    <div className="space-y-4">
      <Panel bodyClassName="flex flex-wrap items-end gap-3">
        <div className="min-w-[20rem] flex-1">
          <div className="mb-1 text-xs font-medium text-muted-foreground">Start entity (sources with the most doors first)</div>
          {entities.isLoading ? <Loading label="Loading graph sources…" className="py-1" />
            : <Select value={start} onChange={(v) => { setStart(v); router.replace(`/attack-graph?start=${encodeURIComponent(v)}`, { scroll: false }) }} options={options} />}
        </div>
        <ActionButton action={rebuild}>Rebuild attack graph</ActionButton>
      </Panel>
      <ActionResult action={rebuild} />

      {!start ? <Empty>Pick a start entity.</Empty> : trace.isLoading ? <Loading label={`Tracing multi-hop paths from ${start}…`} />
        : trace.error ? <ErrorNote error={trace.error} /> : trace.data && (
          <>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Kpi label="Unique paths" value={fmtNum(trace.data.paths.length)} hint={`${fmtNum(trace.data.traversals)} traversals`} />
              <Kpi label="Deepest path" value={`${fmtNum(deepest?.hops ?? 0)} hops`} tone={(deepest?.hops ?? 0) >= 3 ? "danger" : "default"} />
              <Kpi label="Suspicious paths" value={fmtNum(trace.data.paths.filter((p) => p.suspicious).length)} tone="warn" />
              <Kpi label="Entities reached" value={fmtNum(trace.data.graph.nodes.length)} />
            </div>

            <Panel
              title={`Paths from ${start}`}
              description="Merged view of the deepest traced paths. Deep chains (3+ hops) and paths reaching domain assets are flagged suspicious."
              actions={<GraphLegend />}
            >
              {trace.data.graph.nodes.length
                ? <GraphCanvas nodes={trace.data.graph.nodes} edges={trace.data.graph.edges}
                    onNodeClick={(id) => { setStart(id); router.replace(`/attack-graph?start=${encodeURIComponent(id)}`, { scroll: false }) }} />
                : <Empty>No outbound paths from {start}.</Empty>}
              <p className="mt-2 text-xs text-muted-foreground">Click a node to re-trace from it.</p>
            </Panel>

            {deepest?.entities && deepest.entities.length > 1 && (
              <Panel title="Deepest chain">
                <div className="flex flex-wrap items-center gap-1 font-mono text-xs">
                  {deepest.entities.map((e, i) => (
                    <span key={`${e}-${i}`} className="flex items-center gap-1">
                      <span className="rounded bg-muted px-2 py-1">{e}</span>
                      {i < deepest.entities!.length - 1 && <span className="text-primary">→</span>}
                    </span>
                  ))}
                </div>
              </Panel>
            )}

            <div className="grid gap-4 xl:grid-cols-2">
              <Panel title="Path details">
                <DataTable
                  rows={trace.data.paths.slice(0, 15) as Row[]} dense maxHeight={360}
                  columns={[
                    { key: "hops", label: "Hops", align: "right" },
                    { key: "variants", label: "Seen", align: "right", render: (r) => `${fmtNum(r.variants)}×` },
                    { key: "entities", label: "Chain", sortable: false, render: (r) => <span className="font-mono text-xs">{(r.entities ?? []).join(" → ")}</span> },
                    { key: "suspicious", label: "Flag", render: (r) => r.suspicious ? <Pill tone="error">suspicious</Pill> : null },
                    { key: "last_seen", label: "Last seen", render: (r) => fmtAgo(r.last_seen) },
                  ]}
                />
              </Panel>
              {trace.data.incident_id ? (
                <AiTextPanel
                  title="AI Campaign Story"
                  description="Cortex AI narrates the campaign for the incident on this entity"
                  action={story} params={{ incident_id: trace.data.incident_id }}
                  buttonLabel="Generate campaign story"
                  idleText="Turn these paths and the linked incident's findings into an attacker narrative."
                />
              ) : (
                <Panel title="AI Campaign Story"><Empty>No incident is linked to {start} yet — run correlation first.</Empty></Panel>
              )}
            </div>
          </>
        )}
    </div>
  )
}

function DoorRattling() {
  const rattle = useXdr("graph.rattle")
  const scan = useXdrAction("graph.rattleScan", { invalidate: ["graph.", "overview."] })
  const router = useRouter()
  return (
    <Panel
      title="Door-rattling findings"
      description="One source probing many distinct hosts/ports/accounts in a short window — an attacker trying different doors"
      actions={<ActionButton action={scan} variant="default">Run door-rattling scan</ActionButton>}
      bodyClassName="space-y-3"
    >
      <ActionResult action={scan} />
      <QueryState q={rattle}>
        {(rows) => (
          <DataTable
            rows={rows} rowKey="finding_id" empty="No door-rattling findings. Run the scan."
            onRowClick={(r) => router.push(`/attack-graph?start=${encodeURIComponent(String(r.src))}`)}
            columns={[
              { key: "src", label: "Source", className: "font-mono text-xs" },
              { key: "description", label: "Description" },
              { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
              { key: "risk_score", label: "Risk", align: "right", render: (r) => fmtNum(r.risk_score, 0) },
              { key: "status", label: "Status", render: (r) => <Pill>{r.status}</Pill> },
              { key: "detection_time", label: "Detected", render: (r) => fmtTime(r.detection_time) },
            ]}
          />
        )}
      </QueryState>
      <p className="text-xs text-muted-foreground">Click a row to trace attack paths from that source.</p>
    </Panel>
  )
}

function ThreatMap() {
  const points = useXdr("map.points")
  const sources = useXdr("map.sources")
  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      <Panel title="Authentication origins" description="Last 7 days · bubble size = failed logins · equirectangular lat/lon">
        <QueryState q={points} empty={(d) => !d.length}>
          {(d) => (
            <ResponsiveContainer width="100%" height={420}>
              <ScatterChart margin={{ top: 10, right: 20, bottom: 10, left: 0 }}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="2 4" />
                <XAxis type="number" dataKey="lon" domain={[-180, 180]} ticks={[-180, -120, -60, 0, 60, 120, 180]}
                  tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} name="lon" unit="°" />
                <YAxis type="number" dataKey="lat" domain={[-60, 80]} ticks={[-60, -30, 0, 30, 60]}
                  tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} name="lat" unit="°" width={40} />
                <ZAxis type="number" dataKey="failures" range={[60, 1400]} name="failures" />
                <Tooltip
                  cursor={{ strokeDasharray: "3 3" }}
                  content={({ payload }) => {
                    const p = payload?.[0]?.payload as Row | undefined
                    if (!p) return null
                    return (
                      <div className="rounded-md border border-border bg-popover px-3 py-2 text-xs text-popover-foreground shadow">
                        <div className="font-semibold">{p.city}, {p.country}</div>
                        <div>{fmtNum(p.events)} events · {fmtNum(p.failures)} failures</div>
                      </div>
                    )
                  }}
                />
                <Scatter data={d} fill="#e11d48" fillOpacity={0.55} stroke="#9f1239">
                  <LabelList dataKey="city" position="top" style={{ fontSize: 10, fill: "var(--foreground)" }} />
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
          )}
        </QueryState>
      </Panel>
      <div className="space-y-4">
        <Panel title="Top risk locations">
          <QueryState q={points}>
            {(d) => (
              <DataTable
                rows={d.slice(0, 10)} dense
                columns={[
                  { key: "city", label: "City" },
                  { key: "country", label: "Country" },
                  { key: "events", label: "Events", align: "right" },
                  { key: "failures", label: "Failures", align: "right" },
                ]}
              />
            )}
          </QueryState>
        </Panel>
        <Panel title="High-volume sources" description="Potential brute force">
          <QueryState q={sources}>
            {(d) => (
              <DataTable
                rows={d} dense rowKey="src"
                columns={[
                  { key: "src", label: "Source IP", className: "font-mono text-xs" },
                  { key: "attempts", label: "Attempts", align: "right" },
                  { key: "users_targeted", label: "Users", align: "right" },
                  { key: "failures", label: "Failures", align: "right" },
                ]}
              />
            )}
          </QueryState>
        </Panel>
      </div>
    </div>
  )
}

