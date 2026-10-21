"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtNum, fmtTime, fmtHour, SEVERITY_COLOR, sevLabel } from "@/lib/format"
import { PageHeader, Panel, Kpi, KpiGrid, QueryState, SeverityBadge, Pill, AiTextPanel } from "@/components/xdr/kit"
import { DataTable } from "@/components/xdr/data-table"
import { StackedBars, RankBars, PALETTE } from "@/components/xdr/charts"

const SEV_SERIES = [5, 4, 3, 2, 1].map((s) => ({ key: `sev${s}`, label: sevLabel(s), color: SEVERITY_COLOR[s] }))

export function Overview() {
  const router = useRouter()
  const kpis = useXdr<Row>("overview.kpis")
  const timeline = useXdr("overview.timeline")
  const bySev = useXdr("overview.bySeverity")
  const byCat = useXdr("overview.byCategory")
  const incidents = useXdr("overview.recentIncidents")
  const entities = useXdr("overview.topEntities")
  const briefing = useXdrAction("overview.briefing")

  const k = kpis.data ?? {}
  return (
    <div className="space-y-5">
      <PageHeader
        persona="SOC Analyst"
        title="SOC Overview"
        description="Live posture of the XDR pipeline: what fired, what correlated into incidents, and how much noise Snowflake removed before it reached an analyst."
      />

      <KpiGrid>
        <Kpi label="Open incidents" value={fmtNum(k.open_incidents)} tone="danger" />
        <Kpi label="Findings (24h)" value={fmtNum(k.findings_24h)} />
        <Kpi label="Critical/high untriaged" value={fmtNum(k.critical_untriaged)} tone="warn" />
        <Kpi label="Avg MTTR (min)" value={fmtNum(k.mttr_minutes, 1)} />
        <Kpi label="AI findings (24h)" value={fmtNum(k.ai_findings_24h)} tone="accent" />
        <Kpi label="Covered by controls" value={fmtNum(k.mitigated_by_control)} tone="good" hint="real, but already mitigated" />
        <Kpi label="FP auto-suppressed" value={fmtNum(k.auto_suppressed)} tone="good" hint="learned from analyst verdicts" />
      </KpiGrid>

      <AiTextPanel
        title="Analyst Daily Briefing"
        description="Cortex AI summary of live platform data — the morning read"
        action={briefing}
        buttonLabel="Generate briefing"
        idleText="Generate a briefing written by Cortex AI from the last 24 hours of findings, incidents and response activity."
      />

      <Panel title="Detection findings over time" description="When the detected activity happened — hourly, stacked by severity (last 7 days)">
        <QueryState q={timeline} empty={(d) => !d.length}>
          {(d) => <StackedBars data={d} xKey="hour" series={SEV_SERIES} xFormat={fmtHour} />}
        </QueryState>
      </Panel>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="Findings by severity" description="Last 7 days">
          <QueryState q={bySev} empty={(d) => !d.length}>
            {(d) => <RankBars data={d} labelKey="label" valueKey="count"
              colors={d.map((r) => SEVERITY_COLOR[Number(r.severity)] ?? PALETTE[6])} />}
          </QueryState>
        </Panel>
        <Panel title="Findings by category" description="Last 7 days">
          <QueryState q={byCat} empty={(d) => !d.length}>
            {(d) => <RankBars data={d} labelKey="category" valueKey="count" />}
          </QueryState>
        </Panel>
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Panel title="Recent incidents" className="xl:col-span-2"
          actions={<Link href="/investigations" className="text-xs text-primary hover:underline">All investigations →</Link>}>
          <QueryState q={incidents}>
            {(d) => (
              <DataTable
                rows={d} rowKey="incident_id" maxHeight={380}
                onRowClick={(r) => router.push(`/investigations?id=${encodeURIComponent(r.incident_id)}`)}
                columns={[
                  { key: "priority", label: "Pri", render: (r) => <Pill tone={r.priority === "P1" ? "error" : undefined}>{r.priority}</Pill> },
                  { key: "title", label: "Incident", className: "max-w-[22rem] truncate" },
                  { key: "severity", label: "Severity", render: (r) => <SeverityBadge severity={r.severity} /> },
                  { key: "status", label: "Status", render: (r) => <Pill>{r.status}</Pill> },
                  { key: "primary_entity", label: "Entity", className: "font-mono text-xs" },
                  { key: "last_seen", label: "Last seen", render: (r) => fmtTime(r.last_seen) },
                ]}
              />
            )}
          </QueryState>
        </Panel>
        <Panel title="Top affected entities" description="Most findings, last 7 days">
          <QueryState q={entities}>
            {(d) => (
              <DataTable
                rows={d} rowKey="entity" maxHeight={380}
                onRowClick={(r) => router.push(`/entity?q=${encodeURIComponent(r.entity)}`)}
                columns={[
                  { key: "entity", label: "Entity", className: "font-mono text-xs" },
                  { key: "finding_count", label: "Findings", align: "right" },
                  { key: "max_severity", label: "Max sev", render: (r) => <SeverityBadge severity={r.max_severity} /> },
                ]}
              />
            )}
          </QueryState>
        </Panel>
      </div>
    </div>
  )
}
