"use client"

import { useEffect, useMemo, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { Search } from "lucide-react"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtTime, fmtNum, fmtAgo, truncate } from "@/lib/format"
import {
  PageHeader, Panel, QueryState, SeverityBadge, Pill, DispositionPill, AiTextPanel, Select, TextInput,
  Empty, Kpi,
} from "@/components/xdr/kit"
import { DataTable } from "@/components/xdr/data-table"
import { RankBars } from "@/components/xdr/charts"
import { Button } from "@/components/ui/button"

const DAYS = [{ value: "1", label: "24 hours" }, { value: "7", label: "7 days" }, { value: "30", label: "30 days" }] as const

export function Entity360() {
  const params = useSearchParams()
  const router = useRouter()
  const q = params.get("q") ?? ""
  const [input, setInput] = useState(q)
  const [days, setDays] = useState<"1" | "7" | "30">("7")
  useEffect(() => setInput(q), [q])

  const search = useXdr<{ events: Row[]; findings: Row[] }>(
    "entity.search", { entity: q, days: Number(days) }, { enabled: Boolean(q) })
  const investigate = useXdrAction("entity.investigate")
  const suspicious = useXdr("entity.suspicious")

  const bySource = useMemo(() => {
    const m = new Map<string, number>()
    for (const e of search.data?.events ?? []) m.set(String(e.source || "other"), (m.get(String(e.source || "other")) ?? 0) + 1)
    return [...m.entries()].map(([source, count]) => ({ source, count })).sort((a, b) => b.count - a.count)
  }, [search.data])

  const go = (entity: string) => {
    const e = entity.trim()
    if (e) router.push(`/entity?q=${encodeURIComponent(e)}`)
  }

  return (
    <div className="space-y-4">
      <PageHeader
        persona="SOC Analyst"
        title="Entity 360"
        description="Search a user, IP or hostname across every telemetry source — authentication, endpoint, network, DNS, web, cloud — plus its XDR findings, then let Cortex AI write the investigation summary."
      />

      <Panel bodyClassName="flex flex-wrap items-end gap-3">
        <form className="flex min-w-[18rem] flex-1 items-center gap-2" onSubmit={(e) => { e.preventDefault(); go(input) }}>
          <TextInput value={input} onChange={(e) => setInput(e.target.value)} placeholder="jsmith · 10.1.5.107 · WS-042" className="h-9 font-mono" />
          <Button type="submit"><Search className="h-4 w-4" /> Search</Button>
        </form>
        <div className="w-36"><Select value={days} onChange={setDays} options={DAYS} /></div>
      </Panel>

      {!q ? (
        <Panel title="Known suspicious entities" description="Most findings across the platform — click to investigate">
          <QueryState q={suspicious}>
            {(rows) => (
              <DataTable
                rows={rows} rowKey="entity" onRowClick={(r) => go(r.entity)}
                columns={[
                  { key: "entity", label: "Entity", className: "font-mono text-xs" },
                  { key: "findings", label: "Findings", align: "right" },
                  { key: "max_severity", label: "Max severity", render: (r) => <SeverityBadge severity={r.max_severity} /> },
                  { key: "last_seen", label: "Last finding", render: (r) => fmtAgo(r.last_seen) },
                ]}
              />
            )}
          </QueryState>
        </Panel>
      ) : (
        <QueryState q={search} loadingLabel={`Searching all telemetry for ${q}…`}>
          {(d) => (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                <Kpi label="Entity" value={<span className="font-mono text-lg">{q}</span>} />
                <Kpi label="Events" value={fmtNum(d.events.length)} />
                <Kpi label="Sources" value={fmtNum(bySource.length)} />
                <Kpi label="XDR findings" value={fmtNum(d.findings.length)} tone={d.findings.length ? "danger" : "default"} />
              </div>

              <AiTextPanel
                title="AI investigation summary"
                description="Cortex AI reads the cross-source timeline and summarizes what this entity did"
                action={investigate} params={{ entity: q, days: Number(days) }}
                buttonLabel="Run AI investigation"
                idleText="Generate an analyst-style summary of this entity's activity, risk and recommended next steps."
              />

              {d.findings.length > 0 && (
                <Panel title="XDR findings for this entity">
                  <DataTable
                    rows={d.findings} rowKey="finding_id" dense maxHeight={300}
                    onRowClick={(r) => router.push(`/triage?id=${encodeURIComponent(r.finding_id)}`)}
                    columns={[
                      { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
                      { key: "rule_id", label: "Rule", className: "font-mono text-xs" },
                      { key: "description", label: "Description", render: (r) => truncate(r.description, 100) },
                      { key: "status", label: "Status", render: (r) => <Pill>{r.status}</Pill> },
                      { key: "disposition", label: "Disposition", render: (r) => <DispositionPill value={r.disposition} /> },
                      { key: "detection_time", label: "Detected", render: (r) => fmtAgo(r.detection_time) },
                    ]}
                  />
                </Panel>
              )}

              <div className="grid gap-4 xl:grid-cols-[18rem_minmax(0,1fr)]">
                <Panel title="Events by source">
                  {bySource.length ? <RankBars data={bySource} labelKey="source" valueKey="count" /> : <Empty>No events.</Empty>}
                </Panel>
                <Panel title="Activity timeline" description="Newest first, all telemetry sources">
                  <DataTable
                    rows={d.events} dense maxHeight={480}
                    empty={`No activity for ${q} in the last ${days} day(s).`}
                    columns={[
                      { key: "time", label: "Time", render: (r) => fmtTime(r.time) },
                      { key: "source", label: "Source", render: (r) => <Pill>{r.source}</Pill> },
                      { key: "action", label: "Action" },
                      { key: "detail", label: "Detail", render: (r) => <span className="font-mono text-xs" title={String(r.detail)}>{truncate(r.detail, 80)}</span> },
                      { key: "user", label: "User", className: "font-mono text-xs" },
                      { key: "src", label: "Src", className: "font-mono text-xs" },
                      { key: "dest", label: "Dest", className: "font-mono text-xs" },
                    ]}
                  />
                </Panel>
              </div>
            </div>
          )}
        </QueryState>
      )}
    </div>
  )
}
