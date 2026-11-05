"use client"

import { useState } from "react"
import Link from "next/link"
import { OctagonPause, Play, Undo2, Mail, Package, Target, ShieldCheck } from "lucide-react"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtAgo, fmtNum, fmtTime, truncate } from "@/lib/format"
import {
  PageHeader, Panel, QueryState, Kpi, KpiGrid, Pill, ActionButton, ActionResult, TextInput, NumberInput, Field, TextArea,
  Empty, JsonView, Disclosure, Drawer, Tabs, SeverityBadge,
} from "@/components/xdr/kit"
import { DataTable, type Column } from "@/components/xdr/data-table"
import { Button } from "@/components/ui/button"

const KIND_LABEL: Record<string, string> = {
  change_approval: "approve change", parser_approval: "approve parser", autonomy_promotion: "autonomy promotion",
  spot_check: "spot check", response_approval: "approve response", sla_breach: "SLA breach",
  ticket_sync_failed: "ticket sync failed", canary_failing: "canary failing", autonomy_review: "review AI change",
}
const KIND_TONE: Record<string, string> = {
  response_approval: "critical", sla_breach: "high", canary_failing: "high", change_approval: "investigating",
  parser_approval: "investigating", autonomy_promotion: "investigating", spot_check: "contained", ticket_sync_failed: "dismissed",
  autonomy_review: "contained",
}
const STATUS_TONE: Record<string, string> = {
  applied: "success", promoted: "success", approved: "success", done: "success", executed: "success", live: "success",
  shadow: "investigating", proposed: "investigating", pending: "investigating", pending_approval: "investigating",
  rolled_back: "dismissed", rejected: "dismissed", undone: "dismissed", retired: "dismissed", failed: "critical",
}
const PACK_TONE: Record<string, string> = { active: "success", installing: "investigating", no_data: "dismissed" }
const WINDOWS = [{ value: "24h", label: "Last 24h" }, { value: "7d", label: "7 days" }, { value: "30d", label: "30 days" }] as const
const WHO = [{ value: "machine", label: "AI and automation" }, { value: "human", label: "People" }, { value: "all", label: "Everyone" }] as const
const ACTION_LABEL: Record<string, string> = {
  approve: "Approve", reject: "Reject", true_positive: "True positive", false_positive: "False positive", benign: "Benign",
  retry: "Retry", agree: "Agree", disagree: "Disagree",
}

export function Mission() {
  const status = useXdr<Row>("mission.status", {}, { refetchInterval: 30_000 })
  const s = status.data ?? {}
  const paused = !!s.paused
  return (
    <div className="space-y-4">
      <PageHeader
        persona="SOC Lead"
        title="Mission Control"
        description="The AI runs detection engineering, triage and case work on its own. This page is where you stay in charge: what needs a decision, everything the AI changed and why, one-click undo, and a kill switch that stops all automation at once."
        actions={<KillSwitch paused={paused} />}
      />
      {paused && (
        <div className="flex items-start gap-2 rounded-xl border border-red-500/50 bg-red-500/10 px-4 py-3 text-sm text-red-700 dark:text-red-300">
          <OctagonPause className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <div className="font-semibold">Autonomy is paused</div>
            <div>{s.paused_reason || "No reason given"} · by {s.paused_by ?? "?"} {s.paused_changed_at ? fmtAgo(s.paused_changed_at) : ""}.
              The autopilot, auto-suppression, pack installs, ticket routing and automatic response are stopped. Analysts can still act manually.</div>
          </div>
        </div>
      )}

      <KpiGrid>
        <Kpi label="Needs you" value={s.needs_you ?? "-"} tone={Number(s.needs_you) ? "warn" : "good"} hint="ranked queue below" />
        <Kpi label="AI actions (24h)" value={fmtNum(s.ai_actions_24h ?? 0)} hint="ledger entries" />
        <Kpi label="In shadow" value={s.in_shadow ?? "-"} hint="tested before going live" />
        <Kpi label="Rollbacks (7d)" value={s.rollbacks_7d ?? "-"} tone={Number(s.rollbacks_7d) ? "warn" : "default"} hint="guardrail or human" />
        <Kpi label="Change budget" value={`${s.changes_24h ?? 0} / ${s.daily_change_budget ?? "-"}`}
          tone={Number(s.changes_24h) >= Number(s.daily_change_budget) ? "danger" : "default"} hint="autopilot changes, 24h" />
        <Kpi label="Autonomy" value={paused ? "Paused" : "Running"} tone={paused ? "danger" : "good"} />
      </KpiGrid>

      <NeedsYou />
      <ThreatPanel />
      <Ledger />
      <RulePacks />
      <SigmaPanel />
      <Verification />
      <Scorecard />
      <Guardrails status={s} />
      <Briefing />
    </div>
  )
}

function KillSwitch({ paused }: { paused: boolean }) {
  const set = useXdrAction("mission.setAutonomy", { invalidate: ["mission."] })
  const [reason, setReason] = useState("")
  return (
    <div className="flex flex-wrap items-center gap-2">
      {!paused && <TextInput className="w-64" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason for pausing" />}
      {paused ? (
        <ActionButton action={set} variant="default" params={{ paused: false, reason: "resumed in Mission Control" }}>
          <Play className="h-3.5 w-3.5" /> Resume autonomy
        </ActionButton>
      ) : (
        <ActionButton action={set} variant="destructive" params={{ paused: true, reason }} disabled={!reason.trim()}
          confirm="Pause all automation? The autopilot, auto-suppression, pack installs, ticket routing and automatic response stop until resumed.">
          <OctagonPause className="h-3.5 w-3.5" /> Pause all autonomy
        </ActionButton>
      )}
      <div className="w-full"><ActionResult action={set} /></div>
    </div>
  )
}

function NeedsYou() {
  const needs = useXdr<Row[]>("mission.needs", {}, { refetchInterval: 30_000 })
  const decide = useXdrAction("mission.decide", { invalidate: ["mission.", "autopilot.", "confidence."] })
  return (
    <Panel title="Needs you" description="Everything waiting on a human, ranked by urgency, severity and age. Decide here; each item links to its full evidence.">
      <ActionResult action={decide} />
      <QueryState q={needs}>
        {(list) => list.length === 0 ? <Empty>Nothing needs you right now. The AI is handling the rest; see the ledger below.</Empty> : (
          <div className="mt-2 divide-y divide-border">
            {list.slice(0, 40).map((it) => (
              <div key={it.item_id} className="flex flex-wrap items-start justify-between gap-3 py-2.5">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Pill tone={KIND_TONE[it.kind]}>{KIND_LABEL[it.kind] ?? it.kind}</Pill>
                    <SeverityBadge severity={it.severity} />
                    <span className="text-sm font-medium">{it.title}</span>
                  </div>
                  {it.detail && <p className="mt-1 text-xs text-muted-foreground">{truncate(it.detail, 320)}</p>}
                  <div className="mt-0.5 text-[11px] text-muted-foreground">score {fmtNum(it.score)} · {fmtAgo(it.created_at)}</div>
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  {(it.actions as string[]).filter((a) => ACTION_LABEL[a]).map((a) => (
                    <ActionButton key={a} action={decide} variant={a === "approve" || a === "true_positive" ? "default" : "outline"}
                      params={{ item_id: it.item_id, action: a }}
                      confirm={it.kind === "response_approval" && a === "approve" ? `Run ${it.title}? This changes access in Snowflake (undo restores it).` : undefined}>
                      {ACTION_LABEL[a]}
                    </ActionButton>
                  ))}
                  <Link href={it.link ?? "/"} className="text-xs text-primary hover:underline">Open</Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </QueryState>
    </Panel>
  )
}

function Ledger() {
  const [win, setWin] = useState<(typeof WINDOWS)[number]["value"]>("24h")
  const [who, setWho] = useState<(typeof WHO)[number]["value"]>("machine")
  const ledger = useXdr<Row[]>("mission.ledger", { window: win, who }, { refetchInterval: 60_000 })
  const undo = useXdrAction("mission.undo", { invalidate: ["mission.", "autopilot.", "packs."] })
  const [open, setOpen] = useState<Row | null>(null)
  const columns: Column[] = [
    { key: "at", label: "When", render: (r) => fmtAgo(r.at), sortValue: (r) => r.at },
    { key: "source", label: "Source", render: (r) => <span className="text-xs">{r.source}</span> },
    { key: "actor", label: "Actor", render: (r) => <span className="text-xs">{r.actor}<span className="text-muted-foreground"> · {r.actor_type}</span></span> },
    { key: "title", label: "What changed", wrap: true, render: (r) => (
      <button type="button" className="text-left hover:underline" onClick={() => setOpen(r)}>
        <span className="font-mono text-[11px] text-muted-foreground">{r.action}</span> {r.title}
      </button>
    ) },
    { key: "reason", label: "Why", wrap: true, render: (r) => <span className="text-xs text-muted-foreground">{truncate(r.reason, 90)}</span> },
    { key: "status", label: "Status", render: (r) => <Pill tone={STATUS_TONE[r.status]}>{String(r.status ?? "").replace(/_/g, " ")}</Pill> },
    { key: "undo", label: "", sortable: false, render: (r) => r.undo ? (
      <ActionButton action={undo} variant="ghost" params={{ ledger_id: r.ledger_id, reason: "undone in Mission Control" }}
        confirm={`${r.undo.replace(/_/g, " ")}: ${r.title}?`}>
        <Undo2 className="h-3.5 w-3.5" /> {r.undo.replace(/_/g, " ")}
      </ActionButton>
    ) : null },
  ]
  return (
    <Panel title="What the AI did" description="Every machine-made change in one ledger: autopilot and pack rules, agent actions, auto-suppressions, case and ticket updates, parsers and response actions. Each row says why; anything reversible has an undo.">
      <div className="flex flex-wrap gap-3">
        <Tabs tabs={WINDOWS} value={win} onChange={setWin} />
        <Tabs tabs={WHO} value={who} onChange={setWho} />
      </div>
      <ActionResult action={undo} />
      <QueryState q={ledger}>
        {(list) => <DataTable rows={list} columns={columns} rowKey="ledger_id" dense empty="No actions in this window." />}
      </QueryState>
      <Drawer open={!!open} onClose={() => setOpen(null)}>
        {open && (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Pill tone={STATUS_TONE[open.status]}>{open.status}</Pill>
              <span className="font-mono text-xs text-muted-foreground">{open.ledger_id}</span>
            </div>
            <h2 className="text-lg font-semibold">{open.title}</h2>
            <p className="text-sm text-muted-foreground">{fmtTime(open.at)} · {open.actor} ({open.actor_type}) · {open.source}/{open.action}</p>
            {open.reason && <p className="whitespace-pre-wrap text-sm">{open.reason}</p>}
            <Panel title="Evidence"><JsonView value={open.evidence} maxHeight={420} /></Panel>
            {open.link && <Link href={open.link} className="text-sm text-primary hover:underline">Open in context</Link>}
          </div>
        )}
      </Drawer>
    </Panel>
  )
}

function RulePacks() {
  const list = useXdr<Row[]>("packs.list", {}, { refetchInterval: 60_000 })
  const install = useXdrAction("packs.install", { invalidate: ["packs.", "mission."] })
  const [open, setOpen] = useState<Row | null>(null)
  const columns: Column[] = [
    { key: "status", label: "Status", render: (r) => <Pill tone={PACK_TONE[r.status]}>{String(r.status).replace(/_/g, " ")}</Pill> },
    { key: "name", label: "Pack", render: (r) => (
      <button type="button" className="text-left text-primary hover:underline" onClick={() => setOpen(r)}>{r.name}</button>
    ) },
    { key: "vendor", label: "Vendor" },
    { key: "rules", label: "Rules", align: "right" },
    { key: "live", label: "Live", align: "right" },
    { key: "pending", label: "Shadow / proposed", align: "right" },
    { key: "waiting_for_data", label: "Waiting for data", align: "right" },
    { key: "version", label: "Version", align: "right" },
  ]
  return (
    <Panel
      title={<span className="flex items-center gap-1.5"><Package className="h-4 w-4 text-primary" />Rule packs</span>}
      description="Vetted best-practice detections per platform. A rule installs itself (shadow first) as soon as its data source has data; rules for systems you have not connected wait. Every install is an autopilot change you can roll back."
      actions={<ActionButton action={install} params={{ pack_id: "all" }}>Check for data now</ActionButton>}
    >
      <ActionResult action={install} />
      <QueryState q={list}>
        {(rowsList) => <DataTable rows={rowsList} columns={columns} rowKey="pack_id" dense empty="No packs loaded. Run scripts/load_rule_packs.sh." />}
      </QueryState>
      <Drawer open={!!open} onClose={() => setOpen(null)}>{open && <PackDetail pack={open} />}</Drawer>
    </Panel>
  )
}

const SIGMA_TONE: Record<string, string> = {
  verified: "good", installed: "info", canary_failing: "bad", verification_failed: "bad",
  catalogued: "muted", waiting_for_data: "muted", filtered: "muted", not_compiled: "warn",
}

function SigmaPanel() {
  const q = useXdr<Row>("packs.sigma", {}, { refetchInterval: 120_000 })
  const sync = useXdrAction("packs.sigma_sync", { invalidate: ["packs.", "mission."] })
  return (
    <Panel
      title={<span className="flex items-center gap-1.5"><ShieldCheck className="h-4 w-4 text-primary" />Sigma community rules</span>}
      description="SigmaHQ rules compiled to SQL without AI. Each gets synthesised canaries (one per branch, plus a must-not-fire case) and must pass them before it can install. A weekly sync pulls new releases."
      actions={<ActionButton action={sync} params={{}}>Sync latest release</ActionButton>}
    >
      <ActionResult action={sync} />
      <QueryState q={q}>
        {(d) => {
          const byPack: Record<string, Row[]> = {}
          for (const r of (d.by_state as Row[]) ?? []) (byPack[r.pack_id] ??= []).push(r)
          const res = (d.last_sync?.result ?? {}) as Row
          return (
            <div className="space-y-3 text-sm">
              {d.last_sync && (
                <p className="text-muted-foreground">
                  Last sync {fmtAgo(d.last_sync.started_at)} from <span className="font-mono">{d.last_sync.origin}</span>:{" "}
                  {fmtNum(res.files)} files, {fmtNum(res.compiled)} compiled, {fmtNum(res.new)} new, {fmtNum(res.updated)} updated.
                </p>
              )}
              <div className="grid gap-2 md:grid-cols-4">
                {Object.entries(byPack).map(([pid, states]) => (
                  <div key={pid} className="rounded border p-2">
                    <div className="mb-1 font-mono text-xs">{pid}</div>
                    <div className="flex flex-wrap gap-1">
                      {states.map((s) => (
                        <Pill key={s.state} tone={SIGMA_TONE[s.state] ?? "muted"}>{String(s.state).replace(/_/g, " ")} {fmtNum(s.n)}</Pill>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              {((d.not_compiled as Row[]) ?? []).length > 0 && (
                <Disclosure title="Why some rules are not compiled">
                  <ul className="list-disc pl-5 text-xs text-muted-foreground">
                    {(d.not_compiled as Row[]).map((r) => <li key={r.reason}>{r.reason}: {fmtNum(r.n)}</li>)}
                  </ul>
                </Disclosure>
              )}
            </div>
          )
        }}
      </QueryState>
    </Panel>
  )
}

function PackDetail({ pack }: { pack: Row }) {
  const rules = useXdr<Row[]>("packs.rules", { pack_id: pack.pack_id })
  const install = useXdrAction("packs.install", { invalidate: ["packs.", "mission."] })
  const columns: Column[] = [
    { key: "rule_id", label: "Rule", className: "font-mono text-xs" },
    { key: "name", label: "Name", wrap: true },
    { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
    { key: "mitre_technique_id", label: "ATT&CK", className: "font-mono text-xs" },
    { key: "install_state", label: "State", render: (r) => <span title={r.state_reason ?? ""}><Pill tone={STATUS_TONE[r.install_state]}>{String(r.install_state).replace(/_/g, " ")}</Pill></span> },
    { key: "findings_7d", label: "Findings 7d", align: "right" },
    { key: "shadow_findings", label: "Shadow", align: "right" },
  ]
  return (
    <div className="space-y-3">
      <h2 className="text-lg font-semibold">{pack.name} <span className="text-sm text-muted-foreground">v{pack.version}</span></h2>
      <p className="text-sm text-muted-foreground">{pack.description}</p>
      <Disclosure title="How to connect the data"><p className="text-sm">{pack.onboarding}</p></Disclosure>
      <div className="flex gap-2">
        <ActionButton action={install} params={{ pack_id: pack.pack_id }}>Install rules with data</ActionButton>
        <ActionButton action={install} variant="ghost" params={{ pack_id: pack.pack_id, force: true }}
          confirm="Install every rule, including those whose data source has no rows yet? They run in shadow until promoted.">
          Install all (shadow)
        </ActionButton>
      </div>
      <ActionResult action={install} />
      <QueryState q={rules}>{(list) => <DataTable rows={list} columns={columns} rowKey="rule_id" dense />}</QueryState>
    </div>
  )
}

function Guardrails({ status }: { status: Row }) {
  const set = useXdrAction("mission.setAutonomy", { invalidate: ["mission."] })
  const [budget, setBudget] = useState<number | null>(null)
  const perType = (status.per_type as Row[] | undefined) ?? []
  return (
    <Panel title="Guardrails" description="Fixed rules: severity 4+ changes, built-in rules and response actions always need a person; every automatic change is reversible. The daily budget caps how many changes the autopilot may record in 24 hours.">
      <div className="flex flex-wrap items-end gap-2">
        <Field label="Daily change budget">
          <NumberInput value={budget ?? Number(status.daily_change_budget ?? 60)} onChange={setBudget} min={0} max={1000} />
        </Field>
        <ActionButton action={set} params={{ daily_change_budget: budget ?? status.daily_change_budget, reason: "set in Mission Control" }}
          disabled={budget === null}>Save budget</ActionButton>
      </div>
      <ActionResult action={set} />
      <div className="mt-3 flex flex-wrap gap-1.5">
        {perType.map((p) => (
          <span key={p.change_type} className="rounded border border-border px-2 py-0.5 text-[11px]">
            {p.change_type} <span className="text-muted-foreground">{String(p.mode).replace(/_/g, " ")} · {p.used_24h} today{p.budget !== undefined && p.budget !== null ? ` / ${p.budget}` : ""}</span>
          </span>
        ))}
      </div>
    </Panel>
  )
}

function Briefing() {
  const brief = useXdrAction<Row>("mission.briefing")
  return (
    <Panel
      title={<span className="flex items-center gap-1.5"><Mail className="h-4 w-4 text-primary" />Morning briefing</span>}
      description="Sent daily at 07:00 UTC by email and webhook (TASK_MORNING_BRIEFING): what changed overnight, what needs you, new P1/P2 cases, Trust Center findings and exposure news."
      actions={<>
        <ActionButton action={brief} params={{ send: false }}>Preview</ActionButton>
        <ActionButton action={brief} params={{ send: true }} confirm="Send the briefing now?">Send now</ActionButton>
      </>}
    >
      {brief.data?.body ? <pre className="whitespace-pre-wrap rounded-md bg-muted p-3 font-mono text-xs">{String(brief.data.body)}</pre>
        : <Empty>Preview to see today&apos;s briefing.</Empty>}
      <ActionResult action={brief} />
    </Panel>
  )
}

const COVERAGE_CLS: Record<string, string> = {
  verified: "border-emerald-500/60 bg-emerald-500/15",
  claimed: "border-sky-500/60 bg-sky-500/10",
  shadow: "border-amber-500/60 bg-amber-500/10",
  gap: "border-red-500/60 bg-red-500/15",
}

function ThreatPanel() {
  const prof = useXdr<Row>("threat.profile")
  const heat = useXdr<Row[]>("threat.heatmap", {}, { refetchInterval: 120_000 })
  const exp = useXdr<Row[]>("threat.exposures", {}, { refetchInterval: 120_000 })
  const save = useXdrAction("threat.setProfile", { invalidate: ["threat.", "mission."] })
  const refresh = useXdrAction("threat.refresh", { invalidate: ["threat.", "mission."] })
  const [text, setText] = useState<string | null>(null)
  const p = prof.data?.profile as Row | null | undefined
  const env = prof.data?.environment as Row | null | undefined
  const tactics = new Map<string, Row[]>()
  for (const t of heat.data ?? []) {
    const k = t.tactic_name ?? t.tactic_id ?? "Other"
    tactics.set(k, [...(tactics.get(k) ?? []), t])
  }
  const counts = (heat.data ?? []).reduce<Record<string, number>>((a, t) => ({ ...a, [t.coverage]: (a[t.coverage] ?? 0) + 1 }), {})
  return (
    <Panel
      title={<span className="flex items-center gap-1.5"><Target className="h-4 w-4 text-primary" />Threat profile and coverage</span>}
      description="Tell the AI who you are and what worries you; it maps that to ATT&CK groups and techniques, adds your own incident history and KEV entries for products you run, and ranks the autopilot backlog by threat. The heatmap shows posture against that threat: verified (canary passes), claimed (rule live, unproven), shadow, or gap."
      actions={<ActionButton action={refresh}>Rebuild profile and hunt new threats</ActionButton>}
    >
      <ActionResult action={refresh} />
      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <div className="space-y-2">
          <Field label="Your organisation and concerns" hint="e.g. EU fintech, ransomware and insider theft">
            <TextArea rows={3} value={text ?? String(p?.statement ?? "")} onChange={(e) => setText(e.target.value)} />
          </Field>
          <ActionButton action={save} variant="default" params={{ statement: text ?? p?.statement }} disabled={!(text ?? p?.statement)}>
            Save and re-rank backlog
          </ActionButton>
          <ActionResult action={save} />
          {p && (
            <div className="space-y-1 text-xs">
              <div><span className="text-muted-foreground">Industry:</span> {p.industry} · <span className="text-muted-foreground">concerns:</span> {(p.concerns as string[]).join(", ")}</div>
              <div className="flex flex-wrap gap-1">{(p.groups as Row[]).map((g) => <span key={g.name} title={g.why} className="rounded border border-border px-1.5 py-0.5">{g.name}</span>)}</div>
              <div className="text-muted-foreground">updated {fmtAgo(p.updated_at)} by {p.updated_by}</div>
            </div>
          )}
          {env && (
            <div className="rounded-md border border-border p-2 text-xs">
              <div className="font-medium">Environment (built {fmtAgo(env.built_at)})</div>
              <div className="mt-1 text-muted-foreground">{(env.products as string[]).join(" · ")}</div>
              <div className="mt-1">{env.privileged_identities} privileged identities · {env.crown_jewels} crown-jewel objects
                {(env.data_gaps as string[]).length ? <> · no data in {(env.data_gaps as string[]).join(", ")}</> : null}</div>
            </div>
          )}
          <div className="pt-2">
            <div className="mb-1 text-xs font-medium">Exposure news</div>
            <QueryState q={exp}>
              {(list) => list.length === 0 ? <Empty>No new KEV or ATT&CK items match your environment.</Empty> : (
                <ul className="space-y-1.5">
                  {list.slice(0, 6).map((e) => (
                    <li key={e.exposure_id} className="text-xs">
                      <Pill tone={e.hunt_hits ? "critical" : "investigating"}>{e.kind === "kev" ? "KEV" : "ATT&CK"}</Pill>{" "}
                      <span className="font-medium">{e.title}</span>
                      <div className="text-muted-foreground">{truncate(e.detail, 220)}</div>
                    </li>
                  ))}
                </ul>
              )}
            </QueryState>
          </div>
        </div>
        <div>
          <div className="mb-2 flex flex-wrap gap-2 text-[11px]">
            {(["verified", "claimed", "shadow", "gap"] as const).map((c) => (
              <span key={c} className={`rounded border px-1.5 py-0.5 ${COVERAGE_CLS[c]}`}>{c} {counts[c] ?? 0}</span>
            ))}
          </div>
          <QueryState q={heat}>
            {(list) => list.length === 0 ? <Empty>Save a threat profile to score techniques.</Empty> : (
              <div className="max-h-[440px] space-y-2 overflow-auto pr-1">
                {[...tactics.entries()].map(([tac, items]) => (
                  <div key={tac}>
                    <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">{tac}</div>
                    <div className="flex flex-wrap gap-1.5">
                      {items.map((t) => (
                        <div key={t.technique_id} className={`w-40 rounded-md border px-2 py-1 text-[11px] ${COVERAGE_CLS[t.coverage]}`}
                          title={`${(t.reasons as string[]).join("\n")}${t.rank_reason ? "\nBacklog: " + t.rank_reason : ""}`}>
                          <div className="flex justify-between font-mono"><span>{t.technique_id}</span><span>{fmtNum(t.score)}</span></div>
                          <div className="truncate">{t.name}</div>
                          <div className="text-muted-foreground">{t.coverage}{t.live_rules ? ` · ${t.live_rules} live` : ""}{t.verified_rules ? ` · ${t.verified_rules} verified` : ""}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </QueryState>
        </div>
      </div>
    </Panel>
  )
}

const VERIFY_TONE: Record<string, string> = { verified: "success", failing: "critical", untested: "investigating", no_fixture: "dismissed" }

const pct = (v: unknown) => (v === null || v === undefined ? "-" : `${fmtNum(Number(v) * 100, 0)}%`)

function Scorecard() {
  const [grain, setGrain] = useState<"week" | "month">("week")
  const q = useXdr<Row>("mission.scorecard", { grain }, { refetchInterval: 300_000 })
  const sample = useXdrAction("mission.sampleReviews", { invalidate: ["mission."] })
  const cols: Column[] = [
    { key: "period_start", label: grain === "week" ? "Week of" : "Month", className: "font-mono text-xs" },
    { key: "changes", label: "Changes", align: "right" },
    { key: "went_live_unattended", label: "Live unattended", align: "right" },
    { key: "approved_by_human", label: "Approved", align: "right" },
    { key: "rejected_by_human", label: "Rejected", align: "right" },
    { key: "reversal_rate", label: "Reversed", align: "right", render: (r) => pct(r.reversal_rate) },
    { key: "canary_pass_rate", label: "Canary pass", align: "right", render: (r) => pct(r.canary_pass_rate) },
    { key: "branch_coverage", label: "Branches fired", align: "right", render: (r) => pct(r.branch_coverage) },
    { key: "ai_rule_precision", label: "AI rule precision", align: "right",
      render: (r) => r.ai_verdicts ? `${pct(r.ai_rule_precision)} (${r.ai_verdicts})` : "-" },
    { key: "pack_rule_precision", label: "Pack precision", align: "right",
      render: (r) => r.pack_verdicts ? `${pct(r.pack_rule_precision)} (${r.pack_verdicts})` : "-" },
    { key: "median_detect_minutes", label: "MTTD (min)", align: "right" },
    { key: "median_contain_hours", label: "MTTC (h)", align: "right" },
    { key: "reviewer_agreement", label: "Reviewer agreed", align: "right",
      render: (r) => (r.reviews_agreed + r.reviews_disagreed) ? `${pct(r.reviewer_agreement)} of ${r.reviews_agreed + r.reviews_disagreed}` : "-" },
  ]
  return (
    <Panel
      title="Autonomy track record"
      description="What the AI changed, how much went live without a human, how often a guardrail or a person reversed it, and how good its rules are by analyst verdict. Each week a random sample of unattended changes lands in Needs you for a quick agree / disagree."
      actions={
        <div className="flex gap-2 print:hidden">
          <Button size="sm" variant={grain === "week" ? "default" : "ghost"} onClick={() => setGrain("week")}>Weekly</Button>
          <Button size="sm" variant={grain === "month" ? "default" : "ghost"} onClick={() => setGrain("month")}>Monthly</Button>
          <ActionButton action={sample} params={{}} variant="ghost">Sample changes for review</ActionButton>
          <Button size="sm" variant="ghost" onClick={() => window.print()}>Print / PDF</Button>
        </div>
      }
    >
      <ActionResult action={sample} />
      <QueryState q={q}>
        {(d) => (
          <div className="space-y-3">
            <DataTable rows={(d.periods as Row[]) ?? []} columns={cols} rowKey="period_start" dense />
            <Disclosure title="By change type (90 days)">
              <DataTable dense rowKey="change_type" rows={(d.by_type as Row[]) ?? []} columns={[
                { key: "change_type", label: "Type", className: "font-mono text-xs" },
                { key: "mode", label: "Mode" },
                { key: "total", label: "Total", align: "right" },
                { key: "automatic_live", label: "Unattended", align: "right" },
                { key: "approvals", label: "Approved", align: "right" },
                { key: "rejections", label: "Rejected", align: "right" },
                { key: "rollbacks", label: "Rolled back", align: "right" },
                { key: "canary_pass_rate", label: "Canary", align: "right", render: (r) => pct(r.canary_pass_rate) },
                { key: "precision", label: "Precision", align: "right", render: (r) => r.verdicts ? `${pct(r.precision)} (${r.verdicts})` : "-" },
                { key: "reviews_agreed", label: "Reviews +/-", align: "right", render: (r) => `${r.reviews_agreed}/${r.reviews_disagreed}` },
              ]} />
            </Disclosure>
          </div>
        )}
      </QueryState>
    </Panel>
  )
}

function Verification() {
  const can = useXdr<Row[]>("mission.canaries", {}, { refetchInterval: 120_000 })
  const track = useXdr<Row[]>("mission.trackRecord", {}, { refetchInterval: 120_000 })
  const run = useXdrAction("mission.runCanaries", { invalidate: ["mission.", "threat."] })
  const canCols: Column[] = [
    { key: "verification", label: "Verified", render: (r) => <Pill tone={VERIFY_TONE[r.verification]}>{String(r.verification).replace(/_/g, " ")}</Pill> },
    { key: "rule_id", label: "Rule", className: "font-mono text-xs" },
    { key: "name", label: "Name", wrap: true },
    { key: "latency_seconds", label: "Latency", align: "right", render: (r) => r.latency_seconds === null || r.latency_seconds < 0 ? "-" : `${fmtNum(r.latency_seconds, 1)}s` },
    { key: "passes_30d", label: "Pass 30d", align: "right", render: (r) => r.runs_30d ? `${r.passes_30d}/${r.runs_30d}` : "-" },
    { key: "last_canary", label: "Last run", render: (r) => r.last_canary ? fmtAgo(r.last_canary) : "never", sortValue: (r) => r.last_canary },
    { key: "canary_message", label: "Result", wrap: true, render: (r) => <span className="text-xs text-muted-foreground">{r.canary_message ?? ""}</span> },
  ]
  const trCols: Column[] = [
    { key: "change_type", label: "Change type", className: "font-mono text-xs" },
    { key: "mode", label: "Mode", render: (r) => String(r.mode).replace(/_/g, " ") },
    { key: "approvals", label: "Approved", align: "right" },
    { key: "rejections", label: "Rejected", align: "right" },
    { key: "rollbacks", label: "Rolled back", align: "right" },
    { key: "automatic_live", label: "Auto live", align: "right" },
    { key: "canary_pass_rate", label: "Canary pass", align: "right", render: (r) => r.canary_pass_rate === null ? "-" : `${fmtNum(Number(r.canary_pass_rate) * 100)}%` },
    { key: "precision", label: "Precision", align: "right", render: (r) => r.precision === null ? "-" : `${fmtNum(Number(r.precision) * 100)}%` },
  ]
  return (
    <Panel title="Verified coverage and the trust ladder"
      description="Canaries inject each rule's attack and benign fixtures daily and check the rule fires on the first and not the second; a failure queues a fix. Each change type earns autonomy from its track record: the system proposes a promotion for you to approve, and demotes itself after a rollback or canary failure."
      actions={<ActionButton action={run}>Run canaries now</ActionButton>}>
      <ActionResult action={run} />
      <QueryState q={can}>{(list) => <DataTable rows={list} columns={canCols} rowKey="rule_id" dense maxHeight={320} empty="No active custom or pack rules." />}</QueryState>
      <div className="mt-4 mb-1 text-xs font-medium">Track record (90 days)</div>
      <QueryState q={track}>{(list) => <DataTable rows={list} columns={trCols} rowKey="change_type" dense maxHeight={320} />}</QueryState>
    </Panel>
  )
}
