"use client"

import { useState } from "react"
import { RefreshCw, ShieldCheck } from "lucide-react"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtAgo, fmtNum, fmtTime, truncate } from "@/lib/format"
import {
  PageHeader, Panel, QueryState, Kpi, KpiGrid, Pill, SeverityBadge, ActionButton, ActionResult, Select,
  TextInput, Tabs, Empty,
} from "@/components/xdr/kit"
import { DataTable, type Column } from "@/components/xdr/data-table"
import { ConfidenceBadge } from "@/components/views/triage"

type Tab = "review" | "iocs" | "feeds" | "quality" | "catalogs"
const IOC_STATUSES = ["all", "active", "low_confidence", "warninglisted", "allowlisted", "expired", "revoked"] as const

const FEED_TONE: Record<string, string> = { ok: "success", error: "error", needs_key: "contained" }

export function Intel() {
  const [tab, setTab] = useState<Tab>("review")
  const intel = useXdr<Row>("intel.status", {}, { refetchInterval: 30_000 })
  const conf = useXdr<Row>("confidence.status", {}, { refetchInterval: 30_000 })
  const sync = useXdrAction("intel.sync", { invalidate: ["intel."] })
  const i = intel.data?.iocs ?? {}
  const c = conf.data ?? {}
  const bands = c.open_by_band ?? {}
  const feeds: Row[] = intel.data?.feeds ?? []
  const healthy = feeds.filter((f) => f.status === "ok").length

  return (
    <div className="space-y-4">
      <PageHeader
        persona="Detection Engineer"
        title="Threat Intel & Confidence"
        description="Live threat intelligence (abuse.ch, MISP warninglists, MITRE ATT&CK, CISA KEV, Sigma) and the controls that keep false positives down without hiding real attacks: calibrated confidence on every finding, warninglists, expiring indicators, and human spot checks of everything automation dismissed."
        actions={<ActionButton action={sync} variant="default"><RefreshCw className="h-3.5 w-3.5" /> Sync feeds now</ActionButton>}
      />
      <ActionResult action={sync} />

      <KpiGrid>
        <Kpi label="Spot checks waiting" value={c.review_open ?? "-"} tone={Number(c.review_open) ? "warn" : "default"} hint="machine dismissals to verify" />
        <Kpi label="Open: high confidence" value={bands.high ?? 0} tone="danger" hint={`${bands.medium ?? 0} medium · ${bands.low ?? 0} low`} />
        <Kpi label="Auto-suppressed (7d)" value={c.auto_suppressed_7d ?? "-"} hint="low confidence + human FP pattern" />
        <Kpi label="Active IOCs" value={i.active ?? "-"} hint={`${i.high_confidence ?? 0} high confidence`} />
        <Kpi label="Neutralised IOCs" value={(Number(i.warninglisted ?? 0) + Number(i.allowlisted ?? 0) + Number(i.low_confidence ?? 0)) || 0} tone="good" hint="warninglist, allowlist, low confidence" />
        <Kpi label="Feeds healthy" value={feeds.length ? `${healthy}/${feeds.length}` : "-"} tone={healthy === feeds.length ? "good" : "warn"} />
        <Kpi label="Catalogs" value={fmtNum(intel.data?.attack_techniques ?? 0)} hint={`ATT&CK · ${fmtNum(intel.data?.kev_total ?? 0)} KEV · ${fmtNum(intel.data?.sigma_rules ?? 0)} Sigma`} />
      </KpiGrid>

      <Tabs value={tab} onChange={setTab} tabs={[
        { value: "review", label: `Spot checks${c.review_open ? ` (${c.review_open})` : ""}` },
        { value: "quality", label: "Confidence quality" },
        { value: "iocs", label: "Indicators" },
        { value: "feeds", label: "Feeds" },
        { value: "catalogs", label: "ATT&CK · KEV · Sigma" },
      ]} />
      {tab === "review" && <Reviews />}
      {tab === "quality" && <Quality status={c} />}
      {tab === "iocs" && <Iocs />}
      {tab === "feeds" && <Feeds />}
      {tab === "catalogs" && <Catalogs status={intel.data} />}
    </div>
  )
}

// --------------------------------------------------------------- spot checks
function Reviews() {
  const q = useXdr<Row[]>("confidence.reviews")
  const history = useXdr<Row[]>("confidence.reviewHistory")
  const sample = useXdrAction("confidence.sample", { invalidate: ["confidence."] })
  return (
    <div className="space-y-4">
      <Panel
        title="Spot checks"
        description="A sample of findings that automation dismissed (FP model, confidence model, suppression rules). If one is real, its suppression is revoked, every finding it hid is re-opened and the FP model retrains."
        actions={<ActionButton action={sample}>Sample now</ActionButton>}
      >
        <ActionResult action={sample} />
        <QueryState q={q}>
          {(list) => list.length === 0 ? <Empty>Nothing to review. Automation dismissals are sampled every 15 minutes when the confidence task runs.</Empty> : (
            <div className="space-y-3">{list.map((r) => <ReviewCard key={r.review_id} r={r} />)}</div>
          )}
        </QueryState>
      </Panel>
      <Panel title="Recent decisions">
        <QueryState q={history}>
          {(list) => (
            <DataTable rows={list} rowKey="review_id" dense empty="No reviews yet." columns={[
              { key: "verdict", label: "Verdict", render: (r) => <Pill tone={r.verdict === "true_positive" ? "error" : "dismissed"}>{String(r.verdict).replace(/_/g, " ")}</Pill> },
              { key: "rule_id", label: "Rule", className: "font-mono text-xs" },
              { key: "entity", label: "Entity", className: "font-mono text-xs" },
              { key: "suppressed_by", label: "Dismissed by" },
              { key: "outcome", label: "Outcome", wrap: true },
              { key: "reviewed_by", label: "Reviewer" },
              { key: "reviewed_at", label: "When", render: (r) => fmtAgo(r.reviewed_at), sortValue: (r) => r.reviewed_at },
            ]} />
          )}
        </QueryState>
      </Panel>
    </div>
  )
}

function ReviewCard({ r }: { r: Row }) {
  const decide = useXdrAction("confidence.decide", { invalidate: ["confidence.", "triage.", "intel."] })
  const [note, setNote] = useState("")
  return (
    <div className="rounded-lg border border-border p-3">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={r.severity} />
        <ConfidenceBadge band={r.conf_band} score={r.conf_score} />
        <span className="font-mono text-xs">{r.rule_id}</span>
        <span className="font-mono text-xs text-muted-foreground">{r.entity}</span>
        <Pill>dismissed by {String(r.suppressed_by ?? "automation").replace(/_/g, " ")}</Pill>
        <span className="text-xs text-muted-foreground">{fmtTime(r.event_time)}</span>
      </div>
      <p className="mt-1 text-sm">{r.description}</p>
      {r.triage_notes && <p className="mt-1 text-xs text-muted-foreground">{truncate(r.triage_notes, 260)}</p>}
      {Array.isArray(r.conf_factors) && (
        <div className="mt-1 flex flex-wrap gap-1">
          {r.conf_factors.map((x: Row, i: number) => (
            <span key={i} title={x.detail} className="rounded border border-border px-1.5 py-0.5 text-[11px] text-muted-foreground">
              {x.factor} {Number(x.effect) > 0 ? "+" : ""}{fmtNum(x.effect, 1)}
            </span>
          ))}
        </div>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <TextInput className="max-w-xs" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Note (optional)" />
        <ActionButton action={decide} params={{ review_id: r.review_id, verdict: "true_positive", note }} variant="destructive">
          Real attack (revoke suppression)
        </ActionButton>
        <ActionButton action={decide} params={{ review_id: r.review_id, verdict: "false_positive", note }}>Correctly suppressed</ActionButton>
        <ActionButton action={decide} params={{ review_id: r.review_id, verdict: "benign", note }} variant="ghost">Benign activity</ActionButton>
      </div>
      <ActionResult action={decide} />
    </div>
  )
}

// --------------------------------------------------------------- quality
function Quality({ status }: { status: Row }) {
  const precision = useXdr<Row[]>("confidence.rulePrecision")
  const calib: Row[] = status.calibration ?? []
  const supp: Row[] = status.suppression_quality ?? []
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="Calibration" description="For findings analysts judged: how often each confidence band was a real attack. High should be mostly confirmed, low mostly not.">
        {calib.length === 0 ? <Empty>No human verdicts on scored findings yet.</Empty> : (
          <DataTable rows={calib} rowKey="BAND" dense columns={[
            { key: "BAND", label: "Band", render: (r) => <ConfidenceBadge band={r.BAND} score={r.MEAN_SCORE} /> },
            { key: "HUMAN_VERDICTS", label: "Verdicts", align: "right" },
            { key: "CONFIRMED", label: "Confirmed", align: "right" },
            { key: "OBSERVED_PRECISION", label: "Observed precision", align: "right", render: (r) => r.OBSERVED_PRECISION === null ? "-" : `${Math.round(Number(r.OBSERVED_PRECISION) * 100)}%` },
          ]} />
        )}
      </Panel>
      <Panel title="Suppression quality (30d)" description="Each automatic dismissal path, how much it dismissed, and how often spot checks found it hid a real attack.">
        {supp.length === 0 ? <Empty>No automatic dismissals in 30 days.</Empty> : (
          <DataTable rows={supp} rowKey="PATH" dense columns={[
            { key: "PATH", label: "Path", render: (r) => String(r.PATH).replace(/_/g, " ") },
            { key: "DISMISSED_30D", label: "Dismissed", align: "right" },
            { key: "REVIEWED", label: "Spot-checked", align: "right" },
            { key: "MISSES", label: "Real attacks found", align: "right", render: (r) => <span className={Number(r.MISSES) ? "font-semibold text-red-600 dark:text-red-400" : ""}>{r.MISSES}</span> },
            { key: "MISS_RATE", label: "Miss rate", align: "right", render: (r) => r.MISS_RATE === null ? "-" : `${Math.round(Number(r.MISS_RATE) * 100)}%` },
            { key: "EST_HIDDEN_TRUE_POSITIVES", label: "Est. hidden", align: "right" },
          ]} />
        )}
      </Panel>
      <Panel className="xl:col-span-2" title="Rule precision" description="Measured from human verdicts only, starting from a prior (autopilot backtest or the rule's stated confidence, shrunk toward 50%). This is the base of every finding's confidence.">
        <QueryState q={precision}>
          {(list) => (
            <DataTable rows={list} rowKey="rule_id" dense maxHeight={420} columns={[
              { key: "rule_id", label: "Rule", className: "font-mono text-xs" },
              { key: "name", label: "Name", wrap: true },
              { key: "kind", label: "Kind" },
              { key: "tp", label: "TP", align: "right" },
              { key: "fp", label: "FP", align: "right" },
              { key: "benign", label: "Benign", align: "right" },
              { key: "prior", label: "Prior", align: "right", render: (r) => `${Math.round(Number(r.prior) * 100)}%` },
              { key: "precision", label: "Precision", align: "right", render: (r) => <strong>{Math.round(Number(r.precision) * 100)}%</strong> },
            ]} />
          )}
        </QueryState>
      </Panel>
    </div>
  )
}

// --------------------------------------------------------------- indicators
function Iocs() {
  const [status, setStatus] = useState<(typeof IOC_STATUSES)[number]>("all")
  const [search, setSearch] = useState("")
  const q = useXdr<Row[]>("intel.iocs", { status, search })
  const act = useXdrAction("intel.iocAction", { invalidate: ["intel."] })
  const columns: Column[] = [
    { key: "confidence", label: "Conf", align: "right", render: (r) => <strong className="tabular-nums">{r.confidence}</strong> },
    { key: "status", label: "Status", render: (r) => <Pill tone={r.status === "active" ? "success" : r.status === "revoked" ? "error" : "dismissed"}>{String(r.status).replace(/_/g, " ")}</Pill> },
    { key: "ioc_value", label: "Indicator", className: "font-mono text-xs", render: (r) => <span title={r.ioc_type}>{r.ioc_value}{r.pinned ? " (pinned)" : ""}</span> },
    { key: "threat_name", label: "Threat", wrap: true },
    { key: "sources", label: "Sources", render: (r) => (r.sources ?? []).join(", ") },
    {
      key: "why", label: "Why", wrap: true, sortable: false,
      render: (r) => r.status_reason ?? (r.confidence_factors ?? []).map((f: Row) => `${f.factor} ${f.value}`).join(" · "),
    },
    { key: "last_seen", label: "Last seen", render: (r) => fmtAgo(r.last_seen), sortValue: (r) => r.last_seen },
    {
      key: "act", label: "", sortable: false,
      render: (r) => (
        <div className="flex gap-1">
          <ActionButton action={act} size="sm" variant="ghost" params={{ action: r.pinned ? "unpin" : "pin", ioc_type: r.ioc_type, ioc_value: r.ioc_value }}>{r.pinned ? "Unpin" : "Pin"}</ActionButton>
          {r.status === "active"
            ? <ActionButton action={act} size="sm" variant="ghost" params={{ action: "allowlist", ioc_type: r.ioc_type, ioc_value: r.ioc_value }} confirm={`Allowlist ${r.ioc_value}? It will stop alerting.`}>Allowlist</ActionButton>
            : <ActionButton action={act} size="sm" variant="ghost" params={{ action: "restore", ioc_type: r.ioc_type, ioc_value: r.ioc_value }}>Restore</ActionButton>}
        </div>
      ),
    },
  ]
  return (
    <Panel
      title="Indicators"
      description="Effective confidence = feed confidence x source reliability x age decay (half-life by type), plus corroboration and analyst feedback. Warninglisted, expired and low-confidence indicators do not alert. Pin to override."
      actions={<>
        <TextInput className="w-56" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search indicator" />
        <Select value={status} onChange={setStatus} options={IOC_STATUSES.map((s) => ({ value: s, label: s.replace(/_/g, " ") }))} className="w-40" />
      </>}
    >
      <ActionResult action={act} />
      <QueryState q={q}>{(list) => <DataTable rows={list} columns={columns} rowKey="ioc_value" dense maxHeight={560} empty="No indicators." />}</QueryState>
    </Panel>
  )
}

// --------------------------------------------------------------- feeds
function Feeds() {
  const q = useXdr<Row[]>("intel.feeds")
  const one = useXdrAction("intel.syncFeed", { invalidate: ["intel."] })
  return (
    <Panel title="Feeds" description="Pulled daily by TASK_SYNC_THREAT_INTEL through an External Access Integration. ThreatFox and URLhaus need a free abuse.ch Auth-Key in SNOWFLAKE_XDR.REFERENCE.ABUSE_CH_AUTH_KEY.">
      <ActionResult action={one} />
      <QueryState q={q}>
        {(list) => (
          <DataTable rows={list} rowKey="feed_id" dense columns={[
            { key: "last_status", label: "Status", render: (r) => <Pill tone={FEED_TONE[r.last_status]}>{String(r.last_status ?? "never").replace(/_/g, " ")}</Pill> },
            { key: "name", label: "Feed", wrap: true },
            { key: "kind", label: "Kind" },
            { key: "reliability", label: "Reliability", align: "right", render: (r) => fmtNum(r.reliability, 2) },
            { key: "last_count", label: "Items", align: "right", render: (r) => fmtNum(r.last_count) },
            { key: "last_new", label: "New", align: "right", render: (r) => fmtNum(r.last_new) },
            { key: "last_run_at", label: "Last run", render: (r) => r.last_run_at ? fmtAgo(r.last_run_at) : "never", sortValue: (r) => r.last_run_at },
            { key: "last_error", label: "Detail", wrap: true, render: (r) => <span className="text-xs text-muted-foreground">{truncate(r.last_error, 120)}</span> },
            { key: "sync", label: "", sortable: false, render: (r) => <ActionButton action={one} size="sm" variant="ghost" params={{ feed: r.feed_id }}>Sync</ActionButton> },
          ]} />
        )}
      </QueryState>
    </Panel>
  )
}

// --------------------------------------------------------------- catalogs
function Catalogs({ status }: { status?: Row }) {
  const kev = useXdr<Row[]>("intel.kev")
  const sigma = useXdr<Row[]>("intel.sigmaCoverage")
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel
        title={<span className="flex items-center gap-1.5"><ShieldCheck className="h-4 w-4 text-primary" />Autopilot backlog from community content</span>}
        description="Techniques with Sigma rules for log sources we collect. Uncovered ones feed the Detection Autopilot, which translates the Sigma logic, backtests it and runs it in shadow first."
      >
        <QueryState q={sigma}>
          {(list) => (
            <DataTable rows={list} rowKey="technique_id" dense maxHeight={480} columns={[
              { key: "covered", label: "Covered", render: (r) => r.covered ? <Pill tone="success">yes</Pill> : <Pill tone="contained">gap</Pill> },
              { key: "technique_id", label: "Technique", className: "font-mono text-xs" },
              { key: "technique_name", label: "Name", wrap: true },
              { key: "origin", label: "Origin" },
              { key: "sigma_rules", label: "Sigma", align: "right" },
              { key: "priority", label: "Priority", align: "right" },
            ]} />
          )}
        </QueryState>
      </Panel>
      <Panel title="CISA Known Exploited Vulnerabilities" description={`${fmtNum(status?.kev_total ?? 0)} vulnerabilities exploited in the wild; newest first.`}>
        <QueryState q={kev}>
          {(list) => (
            <DataTable rows={list} rowKey="cve_id" dense maxHeight={480} columns={[
              { key: "date_added", label: "Added", render: (r) => String(r.date_added ?? "").slice(0, 10) },
              { key: "cve_id", label: "CVE", className: "font-mono text-xs" },
              { key: "product", label: "Product", wrap: true, render: (r) => `${r.vendor} ${r.product}` },
              { key: "ransomware", label: "Ransomware", render: (r) => r.ransomware === "Known" ? <Pill tone="error">known</Pill> : "" },
              { key: "name", label: "Vulnerability", wrap: true },
            ]} />
          )}
        </QueryState>
      </Panel>
      {(status?.new_techniques ?? []).length > 0 && (
        <Panel className="xl:col-span-2" title="New in MITRE ATT&CK since the previous sync">
          <ul className="list-disc pl-5 text-sm">{status!.new_techniques.map((t: string) => <li key={t}>{t}</li>)}</ul>
        </Panel>
      )}
    </div>
  )
}
