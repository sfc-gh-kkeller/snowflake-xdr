"use client"

import { useEffect, useState } from "react"
import { Plus, Sparkles } from "lucide-react"
import { useXdr, useXdrAction, type Row } from "@/lib/client"
import { fmtTime, fmtAgo } from "@/lib/format"
import {
  PageHeader, Panel, QueryState, SeverityBadge, Pill, ActionButton, ActionResult, Select, TextInput,
  TextArea, NumberInput, Field, CodeArea, JsonView, Tabs, Loading, ErrorNote, Empty,
} from "@/components/xdr/kit"
import { DataTable } from "@/components/xdr/data-table"
import { Button } from "@/components/ui/button"

const LANGUAGES = ["sql", "python", "javascript"] as const
const CATEGORIES = ["identity", "endpoint", "network", "cloud", "application", "custom"] as const
const IOC_TYPES = ["ip", "domain", "url", "hash_md5", "hash_sha256", "email", "user_agent"] as const
const THREAT_TYPES = ["malware", "phishing", "c2", "botnet", "ransomware", "apt", "credential_abuse", "exfiltration", "scanner"] as const

type Lang = (typeof LANGUAGES)[number]
type Cat = (typeof CATEGORIES)[number]

interface RuleForm {
  rule_id: string; name: string; description: string; category: Cat; severity: number
  mitre_tactic_id: string; mitre_technique_id: string; language: Lang; source_table: string; code: string
  threshold_count: number; threshold_window_minutes: number; lookback_minutes: number; enabled: boolean
}

const SQL_TEMPLATE = `-- Must return: _time, user_name, src, dest, description
SELECT _time, user_name, src, dest,
       'Failed login burst for ' || user_name AS description
FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
WHERE action = 'failure'
  AND _time > DATEADD('hour', -24, CURRENT_TIMESTAMP())`

const PY_TEMPLATE = `def detect(row):
    # row is the log record as a dict; return 1 to match, 0 otherwise
    return 1 if row.get("action") == "failure" else 0`

const EMPTY: RuleForm = {
  rule_id: "", name: "", description: "", category: "identity", severity: 3, mitre_tactic_id: "",
  mitre_technique_id: "", language: "sql", source_table: "AUTHENTICATION", code: SQL_TEMPLATE,
  threshold_count: 1, threshold_window_minutes: 60, lookback_minutes: 1440, enabled: false,
}

export function Rules() {
  const [tab, setTab] = useState<"rules" | "iocs">("rules")
  return (
    <div className="space-y-4">
      <PageHeader
        persona="Detection Engineer"
        title="Rules & IOCs"
        description="Detection-as-code inside Snowflake: write rules in SQL, Python or JavaScript, or let Cortex AI draft one from plain English. Test against live data before enabling. Every save is versioned."
      />
      <Tabs value={tab} onChange={setTab} tabs={[{ value: "rules", label: "Custom rules" }, { value: "iocs", label: "IOCs & watchlist" }]} />
      {tab === "rules" ? <RuleEditor /> : <Iocs />}
    </div>
  )
}

function RuleEditor() {
  const list = useXdr("rules.list")
  const [selected, setSelected] = useState<string | null>(null)
  const generate = useXdrAction<Row>("rules.generate", { invalidate: ["rules."] })
  const [nl, setNl] = useState("")

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
      <div className="space-y-4">
        <Panel
          title={<span className="flex items-center gap-1.5"><Sparkles className="h-4 w-4 text-primary" />Generate a rule with Cortex AI</span>}
          description="Describe the behavior; the draft is saved disabled for review"
          bodyClassName="space-y-2"
        >
          <TextArea rows={3} value={nl} onChange={(e) => setNl(e.target.value)}
            placeholder="e.g. Detect failed logins from the same source to 5+ different user accounts within 10 minutes" />
          <ActionButton action={generate} params={{ description: nl }} variant="default" disabled={!nl.trim()}>Generate with Cortex AI</ActionButton>
          {generate.isPending && <Loading label="Cortex AI is writing your detection…" />}
          {generate.isError && <ErrorNote error={generate.error} />}
          {generate.data && (
            <div className="space-y-2">
              <div className="text-sm">Draft created: <strong>{String(generate.data.name ?? "unnamed")}</strong> — select it in the list to review, test and enable.</div>
              <pre className="max-h-56 overflow-auto rounded-md bg-slate-950 p-3 font-mono text-xs text-emerald-200">{String(generate.data.rule_sql ?? "")}</pre>
            </div>
          )}
        </Panel>
        <Panel
          title="Custom rules"
          actions={<Button size="sm" variant="outline" onClick={() => setSelected("")}><Plus className="h-3.5 w-3.5" /> New rule</Button>}
        >
          <QueryState q={list}>
            {(rows) => (
              <DataTable
                rows={rows} rowKey="rule_id" dense maxHeight={460} selectedKey={selected}
                onRowClick={(r) => setSelected(String(r.rule_id))}
                empty="No custom rules yet."
                columns={[
                  { key: "name", label: "Rule", wrap: true },
                  { key: "language", label: "Lang", render: (r) => <Pill>{r.language}</Pill> },
                  { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
                  { key: "version", label: "v", align: "right" },
                  { key: "enabled", label: "On", render: (r) => r.enabled ? <Pill tone="success">on</Pill> : <Pill tone="dismissed">off</Pill> },
                ]}
              />
            )}
          </QueryState>
        </Panel>
      </div>
      <div>
        {selected === null
          ? <Panel title="Rule editor"><Empty>Select a rule, or create a new one.</Empty></Panel>
          : <RuleForm key={selected || "new"} ruleId={selected} onSaved={(id) => setSelected(id)} />}
      </div>
    </div>
  )
}

function RuleForm({ ruleId, onSaved }: { ruleId: string; onSaved: (id: string | null) => void }) {
  const isNew = !ruleId
  const detail = useXdr<{ rule: Row; errors: Row[]; history: Row[] }>("rules.detail", { rule_id: ruleId }, { enabled: !isNew })
  const save = useXdrAction("rules.save", { invalidate: ["rules.", "detections."] })
  const test = useXdrAction<{ matches: unknown[]; count: number; raw: unknown }>("rules.test")
  const runAll = useXdrAction("rules.runAll", { invalidate: ["rules.", "triage.", "overview."] })
  const [f, setF] = useState<RuleForm>(EMPTY)

  useEffect(() => {
    const r = detail.data?.rule
    if (!r) return
    setF({
      rule_id: String(r.rule_id), name: r.name ?? "", description: r.description ?? "",
      category: (CATEGORIES as readonly string[]).includes(r.category) ? r.category : "custom",
      severity: Number(r.severity) || 3, mitre_tactic_id: r.mitre_tactic_id ?? "", mitre_technique_id: r.mitre_technique_id ?? "",
      language: (LANGUAGES as readonly string[]).includes(r.language) ? r.language : "sql",
      source_table: r.source_table ?? "", code: r.code ?? "",
      threshold_count: Number(r.threshold_count) || 1, threshold_window_minutes: Number(r.threshold_window_minutes) || 60,
      lookback_minutes: Number(r.lookback_minutes) || 1440, enabled: Boolean(r.enabled),
    })
  }, [detail.data])

  if (!isNew && detail.isLoading) return <Panel title="Rule editor"><Loading /></Panel>
  if (!isNew && detail.error) return <Panel title="Rule editor"><ErrorNote error={detail.error} /></Panel>

  const set = <K extends keyof RuleForm>(k: K, v: RuleForm[K]) => setF((prev) => ({ ...prev, [k]: v }))

  return (
    <div className="space-y-4">
      <Panel title={isNew ? "New rule" : `Edit: ${f.name}`} description={isNew ? undefined : <span className="font-mono">{ruleId}</span>} bodyClassName="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Rule name"><TextInput value={f.name} onChange={(e) => set("name", e.target.value)} /></Field>
          <Field label="Description"><TextInput value={f.description} onChange={(e) => set("description", e.target.value)} /></Field>
        </div>
        <div className="grid gap-3 sm:grid-cols-4">
          <Field label="Language">
            <Select value={f.language} onChange={(v) => setF((prev) => ({
              ...prev, language: v,
              code: prev.code && prev.code !== SQL_TEMPLATE && prev.code !== PY_TEMPLATE ? prev.code : v === "sql" ? SQL_TEMPLATE : PY_TEMPLATE,
            }))} options={LANGUAGES} />
          </Field>
          <Field label="Category"><Select value={f.category} onChange={(v) => set("category", v)} options={CATEGORIES} /></Field>
          <Field label="Severity (1-5)"><NumberInput value={f.severity} onChange={(v) => set("severity", v)} min={1} max={5} /></Field>
          <Field label="Source table" hint={f.language === "sql" ? "SQL rules query tables directly" : undefined}>
            <TextInput value={f.source_table} disabled={f.language === "sql"} onChange={(e) => set("source_table", e.target.value)} />
          </Field>
        </div>
        <div className="grid gap-3 sm:grid-cols-5">
          <Field label="MITRE tactic"><TextInput value={f.mitre_tactic_id} onChange={(e) => set("mitre_tactic_id", e.target.value)} placeholder="TA0006" /></Field>
          <Field label="MITRE technique"><TextInput value={f.mitre_technique_id} onChange={(e) => set("mitre_technique_id", e.target.value)} placeholder="T1110" /></Field>
          <Field label="Threshold"><NumberInput value={f.threshold_count} onChange={(v) => set("threshold_count", v)} min={1} max={1000} /></Field>
          <Field label="Window (min)"><NumberInput value={f.threshold_window_minutes} onChange={(v) => set("threshold_window_minutes", v)} min={1} max={1440} /></Field>
          <Field label="Lookback (min)"><NumberInput value={f.lookback_minutes} onChange={(v) => set("lookback_minutes", v)} min={1} max={20160} /></Field>
        </div>
        <Field label={f.language === "sql" ? "Rule SQL — must return _time, user_name, src, dest, description" : "Rule code — define detect(row) returning 1 (match) or 0"}>
          <CodeArea value={f.code} onChange={(v) => set("code", v)} rows={14} />
        </Field>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Enabled (runs with the next detection cycle)
        </label>
        <div className="flex flex-wrap gap-2">
          <ActionButton action={save} params={{ ...f }} variant="default" disabled={!f.name.trim() || !f.code.trim()}>
            {isNew ? "Save rule" : "Save changes"}
          </ActionButton>
          {!isNew && <ActionButton action={test} params={{ rule_id: ruleId }}>Test (dry run)</ActionButton>}
          {!isNew && <ActionButton action={runAll} confirm="Run all enabled custom rules and insert findings?">Run all custom rules now</ActionButton>}
        </div>
        <ActionResult action={save} /><ActionResult action={runAll} />
        {test.isPending && <Loading label="Running rule against live data (no findings inserted)…" />}
        {test.isError && <ErrorNote error={test.error} />}
        {test.data && (
          test.data.count > 0
            ? <div className="space-y-2"><div className="text-sm text-emerald-600 dark:text-emerald-400">Rule would match {test.data.count} event(s). Sample:</div><JsonView value={test.data.matches.slice(0, 5)} maxHeight={260} /></div>
            : <div className="text-sm text-muted-foreground">No matches in current data. <JsonView value={test.data.raw} maxHeight={160} /></div>
        )}
      </Panel>

      {!isNew && detail.data && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="Version history" description="Every save snapshots the previous version">
            <DataTable
              rows={detail.data.history} dense maxHeight={260} empty="No prior versions yet."
              columns={[
                { key: "version", label: "v", align: "right" },
                { key: "changed_at", label: "Changed", render: (r) => fmtTime(r.changed_at) },
                { key: "changed_by", label: "By" },
                { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
                { key: "enabled", label: "On", render: (r) => r.enabled ? "on" : "off" },
              ]}
            />
          </Panel>
          <Panel title="Recent errors">
            <DataTable
              rows={detail.data.errors} dense maxHeight={260} empty="No errors for this rule."
              columns={[
                { key: "error_time", label: "When", render: (r) => fmtAgo(r.error_time) },
                { key: "stage", label: "Stage" },
                { key: "error_message", label: "Error", wrap: true },
              ]}
            />
          </Panel>
        </div>
      )}
    </div>
  )
}

function Iocs() {
  const list = useXdr("iocs.list")
  const add = useXdrAction("iocs.add", { invalidate: ["iocs."] })
  const remove = useXdrAction("iocs.remove", { invalidate: ["iocs."] })
  const [type, setType] = useState<(typeof IOC_TYPES)[number]>("ip")
  const [value, setValue] = useState("")
  const [threat, setThreat] = useState<(typeof THREAT_TYPES)[number]>("c2")
  const [name, setName] = useState("")
  const [sev, setSev] = useState(4)
  const [source, setSource] = useState("manual")

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
      <Panel title="Threat intel IOCs" description="Active indicators feed DET-021 (known-bad IOC) on the next detection run">
        <QueryState q={list}>
          {(rows) => (
            <DataTable
              rows={rows} dense maxHeight={560}
              columns={[
                { key: "ioc_type", label: "Type", render: (r) => <Pill>{r.ioc_type}</Pill> },
                { key: "ioc_value", label: "Value", className: "font-mono text-xs" },
                { key: "threat_name", label: "Threat" },
                { key: "threat_type", label: "Kind" },
                { key: "severity", label: "Sev", render: (r) => <SeverityBadge severity={r.severity} /> },
                { key: "source", label: "Source" },
                { key: "active", label: "Active", render: (r) => r.active ? <Pill tone="success">active</Pill> : <Pill tone="dismissed">removed</Pill> },
                {
                  key: "actions", label: "", sortable: false,
                  render: (r) => r.active ? (
                    <ActionButton action={remove} params={{ ioc_type: r.ioc_type, ioc_value: r.ioc_value }} variant="ghost"
                      confirm={`Deactivate IOC ${r.ioc_value}?`}>Remove</ActionButton>
                  ) : null,
                },
              ]}
            />
          )}
        </QueryState>
        <div className="mt-2"><ActionResult action={remove} /></div>
      </Panel>
      <Panel title="Add IOC" bodyClassName="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <Field label="Type"><Select value={type} onChange={setType} options={IOC_TYPES} /></Field>
          <Field label="Threat type"><Select value={threat} onChange={setThreat} options={THREAT_TYPES} /></Field>
        </div>
        <Field label="Value"><TextInput value={value} onChange={(e) => setValue(e.target.value)} className="font-mono" placeholder="203.0.113.50 or evil.example" /></Field>
        <Field label="Threat name"><TextInput value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Cobalt Strike Beacon" /></Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Severity (1-5)"><NumberInput value={sev} onChange={setSev} min={1} max={5} /></Field>
          <Field label="Source"><TextInput value={source} onChange={(e) => setSource(e.target.value)} /></Field>
        </div>
        <ActionButton action={add} variant="default" disabled={!value.trim()}
          params={{ ioc_type: type, ioc_value: value, threat_type: threat, threat_name: name, severity: sev, source }}>
          Add IOC
        </ActionButton>
        <ActionResult action={add} />
      </Panel>
    </div>
  )
}
