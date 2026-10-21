"use client"

import { useState } from "react"
import { Pause, Play } from "lucide-react"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtNum, fmtTime, fmtAgo, truncate } from "@/lib/format"
import { PageHeader, Panel, QueryState, Pill, ActionButton, ActionResult, NumberInput, Field } from "@/components/xdr/kit"
import { DataTable } from "@/components/xdr/data-table"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

function healthTone(health: unknown): "good" | "warn" | "bad" {
  const h = String(health ?? "")
  if (h.includes("STALE")) return "bad"
  if (h.includes("fresh (known")) return "warn"
  return "good"
}

export function LiveTail() {
  const [paused, setPaused] = useState(false)
  const [batches, setBatches] = useState(3)
  const lag = useXdr("live.lag", {}, { refetchInterval: paused ? false : 30_000, staleTime: 0 })
  const feed = useXdr("live.feed", {}, { refetchInterval: paused ? false : 10_000, staleTime: 0 })
  const emit = useXdrAction("live.emit", { invalidate: ["live."] })

  const counts = (feed.data ?? []).reduce<Record<string, number>>((acc, r) => {
    acc[String(r.source_state)] = (acc[String(r.source_state)] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="space-y-4">
      <PageHeader
        persona="SOC Analyst"
        title="Live Tail"
        description="Real-time event stream with per-source ingestion lag. Sources arrive at different speeds — EDR intentionally lags 20–45 minutes — so detections must reason about late data instead of assuming everything is current."
        actions={<>
          <Field label="Batches"><NumberInput value={batches} onChange={setBatches} min={1} max={20} className="w-20" /></Field>
          <ActionButton action={emit} params={{ batches }} variant="default">Emit live events</ActionButton>
          <Button size="sm" variant="outline" onClick={() => setPaused(!paused)}>
            {paused ? <><Play className="h-3.5 w-3.5" /> Resume</> : <><Pause className="h-3.5 w-3.5" /> Pause</>}
          </Button>
        </>}
      />
      <ActionResult action={emit} />

      <Panel title="Source health & lag" description="Expected lag per source vs. what is actually arriving">
        <QueryState q={lag} empty={(d) => !d.length}>
          {(rows) => (
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              {rows.map((r) => {
                const tone = healthTone(r.health)
                return (
                  <div key={String(r.source_table)} className={cn("rounded-lg border p-3",
                    tone === "bad" ? "border-red-500/50 bg-red-500/5" : tone === "warn" ? "border-amber-500/50 bg-amber-500/5" : "border-emerald-500/50 bg-emerald-500/5")}>
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-semibold">{r.source_table}</span>
                      <span className={cn("h-2.5 w-2.5 rounded-full", tone === "bad" ? "bg-red-500" : tone === "warn" ? "bg-amber-500" : "bg-emerald-500 animate-pulse")} />
                    </div>
                    <div className="mt-2 text-xs text-muted-foreground">Latest event {fmtAgo(r.latest_event)}</div>
                    <div className="text-xs text-muted-foreground">Ingestion lag {fmtNum(r.min_lag_min, 1)}–{fmtNum(r.max_lag_min, 1)} min</div>
                    <div className="mt-1 text-xs">{String(r.health)}</div>
                  </div>
                )
              })}
            </div>
          )}
        </QueryState>
      </Panel>

      <Panel
        title="Live feed"
        description={`${counts["real-time"] ?? 0} real-time · ${counts["delayed"] ?? 0} delayed · ${counts["lagging"] ?? 0} lagging · ${paused ? "paused" : "auto-refresh every 10s"}`}
      >
        <QueryState q={feed}>
          {(rows) => (
            <DataTable
              rows={rows} dense maxHeight={620}
              empty="No recent events. Click “Emit live events” to start the stream."
              columns={[
                { key: "source_state", label: "State", render: (r) => <Pill tone={String(r.source_state)}>{r.source_state}</Pill> },
                { key: "source_table", label: "Source", className: "font-mono text-xs" },
                { key: "event_time", label: "Event time", render: (r) => fmtTime(r.event_time) },
                { key: "ingestion_time", label: "Ingested", render: (r) => fmtAgo(r.ingestion_time) },
                { key: "lag_seconds", label: "Lag", align: "right", render: (r: Row) => lagLabel(r.lag_seconds) },
                { key: "entity", label: "Entity", className: "font-mono text-xs" },
                { key: "action", label: "Action" },
                { key: "detail", label: "Detail", render: (r) => <span className="font-mono text-xs" title={String(r.detail ?? "")}>{truncate(r.detail, 70)}</span> },
              ]}
            />
          )}
        </QueryState>
      </Panel>
    </div>
  )
}

function lagLabel(sec: unknown): string {
  const s = Number(sec)
  if (Number.isNaN(s)) return "–"
  if (s < 60) return `${Math.round(s)}s`
  return `${(s / 60).toFixed(1)}m`
}
