"use client"

/** Shared building blocks for every XDR view. */

import React, { useState } from "react"
import { Loader2, AlertTriangle, CheckCircle2, Sparkles } from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { sevLabel } from "@/lib/format"
import { Markdown } from "@/components/xdr/markdown"
import type { UseMutationResult } from "@tanstack/react-query"

// ---------------------------------------------------------------------------
// Page + panel layout
// ---------------------------------------------------------------------------

export function PageHeader({ title, description, persona, actions }: {
  title: string; description?: string; persona?: string; actions?: React.ReactNode
}) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        {persona && <div className="text-[11px] font-semibold uppercase tracking-wider text-primary">{persona}</div>}
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Panel({ title, description, actions, children, className, bodyClassName }: {
  title?: React.ReactNode; description?: React.ReactNode; actions?: React.ReactNode
  children: React.ReactNode; className?: string; bodyClassName?: string
}) {
  return (
    <section className={cn("rounded-xl border border-border bg-card text-card-foreground shadow-sm", className)}>
      {(title || actions) && (
        <div className="flex flex-wrap items-start justify-between gap-2 border-b border-border px-4 py-3">
          <div>
            {title && <h2 className="text-sm font-semibold">{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>}
          </div>
          {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className={cn("p-4", bodyClassName)}>{children}</div>
    </section>
  )
}

// ---------------------------------------------------------------------------
// KPIs
// ---------------------------------------------------------------------------

export function Kpi({ label, value, hint, tone = "default" }: {
  label: string; value: React.ReactNode; hint?: React.ReactNode
  tone?: "default" | "danger" | "warn" | "good" | "accent"
}) {
  const toneCls = {
    default: "", danger: "text-red-600 dark:text-red-400", warn: "text-amber-600 dark:text-amber-400",
    good: "text-emerald-600 dark:text-emerald-400", accent: "text-primary",
  }[tone]
  return (
    <div className="rounded-xl border border-border bg-card px-4 py-3 shadow-sm">
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div className={cn("mt-1 text-2xl font-semibold tabular-nums", toneCls)}>{value}</div>
      {hint && <div className="mt-0.5 text-[11px] text-muted-foreground">{hint}</div>}
    </div>
  )
}

export function KpiGrid({ children }: { children: React.ReactNode }) {
  return <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">{children}</div>
}

// ---------------------------------------------------------------------------
// Badges
// ---------------------------------------------------------------------------

const SEV_CLS: Record<number, string> = {
  5: "bg-red-600 text-white",
  4: "bg-orange-500 text-white",
  3: "bg-amber-400 text-slate-900",
  2: "bg-blue-500 text-white",
  1: "bg-slate-400 text-white",
}

export function SeverityBadge({ severity }: { severity: unknown }) {
  const s = Number(severity) || 1
  return (
    <span className={cn("inline-flex min-w-[4.5rem] justify-center whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-semibold", SEV_CLS[s] ?? SEV_CLS[1])}>
      {s} · {sevLabel(s)}
    </span>
  )
}

const STATUS_CLS: Record<string, string> = {
  new: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  open: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  investigating: "border-violet-500/40 bg-violet-500/10 text-violet-700 dark:text-violet-300",
  contained: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  resolved: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  closed: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  dismissed: "border-slate-500/40 bg-slate-500/10 text-slate-600 dark:text-slate-300",
  success: "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  error: "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300",
  "real-time": "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  delayed: "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  lagging: "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300",
}

export function Pill({ children, tone }: { children: React.ReactNode; tone?: string }) {
  const key = String(tone ?? children ?? "").toLowerCase()
  return (
    <span className={cn("inline-flex items-center whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium",
      STATUS_CLS[key] ?? "border-border bg-muted text-muted-foreground")}>
      {children}
    </span>
  )
}

/** Disposition pill: highlights the noise-reduction outcomes. */
export function DispositionPill({ value }: { value: unknown }) {
  if (!value) return null
  const v = String(value)
  const cls = v === "mitigated_by_control" ? "border-teal-500/40 bg-teal-500/10 text-teal-700 dark:text-teal-300"
    : v === "true_positive" ? "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300"
      : "border-slate-500/40 bg-slate-500/10 text-slate-600 dark:text-slate-300"
  const label = v === "mitigated_by_control" ? "covered by control" : v.replace(/_/g, " ")
  return <span className={cn("inline-flex whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium", cls)}>{label}</span>
}

// ---------------------------------------------------------------------------
// States
// ---------------------------------------------------------------------------

export function Loading({ label = "Loading…", className }: { label?: string; className?: string }) {
  return (
    <div className={cn("flex items-center gap-2 py-6 text-sm text-muted-foreground", className)}>
      <Loader2 className="h-4 w-4 animate-spin" /> {label}
    </div>
  )
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null
  const msg = error instanceof Error ? error.message : String(error)
  return (
    <div className="flex items-start gap-2 rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-700 dark:text-red-300">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /> <span className="break-words">{msg}</span>
    </div>
  )
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <div className="py-6 text-center text-sm text-muted-foreground">{children}</div>
}

/** Renders query state: spinner, error, empty, or children(data). */
export function QueryState<T>({ q, empty, children, loadingLabel }: {
  q: { data?: T; isLoading: boolean; error: unknown }
  empty?: (d: T) => boolean
  children: (d: T) => React.ReactNode
  loadingLabel?: string
}) {
  if (q.isLoading) return <Loading label={loadingLabel} />
  if (q.error) return <ErrorNote error={q.error} />
  if (q.data === undefined || q.data === null) return <Empty>No data.</Empty>
  if (empty && empty(q.data)) return <Empty>Nothing to show yet.</Empty>
  return <>{children(q.data)}</>
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

type AnyMutation = UseMutationResult<any, Error, any, unknown>

/** Button bound to a mutation; shows a spinner and the result message inline. */
export function ActionButton({ action, params, children, variant = "outline", size = "sm", confirm, disabled }: {
  action: AnyMutation; params?: Record<string, unknown>; children: React.ReactNode
  variant?: "default" | "outline" | "secondary" | "destructive" | "ghost"; size?: "sm" | "default"
  confirm?: string; disabled?: boolean
}) {
  return (
    <Button
      variant={variant} size={size}
      disabled={disabled || action.isPending}
      onClick={() => {
        if (confirm && !window.confirm(confirm)) return
        action.mutate(params ?? {})
      }}
    >
      {action.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
      {children}
    </Button>
  )
}

export function ActionResult({ action }: { action: AnyMutation }) {
  if (action.isError) return <ErrorNote error={action.error} />
  const msg = action.data?.message
  if (action.isSuccess && msg) {
    return (
      <div className="flex items-start gap-2 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-700 dark:text-emerald-300">
        <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> <span className="break-words">{String(msg)}</span>
      </div>
    )
  }
  return null
}

/** Panel that generates Cortex AI text on demand (briefing, story, report). */
export function AiTextPanel({ title, description, action, params, buttonLabel, idleText, className }: {
  title: string; description?: string; action: AnyMutation; params?: Record<string, unknown>
  buttonLabel: string; idleText: string; className?: string
}) {
  return (
    <Panel
      className={className}
      title={<span className="flex items-center gap-1.5"><Sparkles className="h-4 w-4 text-primary" />{title}</span>}
      description={description}
      actions={<ActionButton action={action} params={params} variant="default">{buttonLabel}</ActionButton>}
    >
      {action.isPending ? <Loading label="Cortex AI is writing…" />
        : action.isError ? <ErrorNote error={action.error} />
          : action.data?.text ? <Markdown text={action.data.text} />
            : <p className="text-sm text-muted-foreground">{idleText}</p>}
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// Form controls (native elements, themed)
// ---------------------------------------------------------------------------

const fieldCls = "h-8 w-full rounded-md border border-input bg-background px-2 text-sm outline-none focus:ring-2 focus:ring-ring"

export function Field({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <label className="flex flex-col gap-1 text-xs font-medium text-muted-foreground">
      {label}
      {children}
      {hint && <span className="font-normal">{hint}</span>}
    </label>
  )
}

export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cn(fieldCls, "text-foreground", props.className)} />
}

export function NumberInput({ value, onChange, min, max, ...rest }: {
  value: number; onChange: (v: number) => void; min?: number; max?: number
} & Omit<React.InputHTMLAttributes<HTMLInputElement>, "value" | "onChange">) {
  return (
    <input
      type="number" value={value} min={min} max={max} {...rest}
      onChange={(e) => onChange(Number(e.target.value))}
      className={cn(fieldCls, "text-foreground", rest.className)}
    />
  )
}

export function Select<T extends string>({ value, onChange, options, className }: {
  value: T; onChange: (v: T) => void; options: readonly (T | { value: T; label: string })[]; className?: string
}) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value as T)} className={cn(fieldCls, "text-foreground", className)}>
      {options.map((o) => {
        const v = typeof o === "string" ? o : o.value
        const l = typeof o === "string" ? o.replace(/_/g, " ") : o.label
        return <option key={v} value={v}>{l}</option>
      })}
    </select>
  )
}

export function TextArea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      className={cn("w-full rounded-md border border-input bg-background p-2 text-sm text-foreground outline-none focus:ring-2 focus:ring-ring", props.className)}
    />
  )
}

/** Code editor surface: monospace textarea with tab support. */
export function CodeArea({ value, onChange, rows = 12, placeholder }: {
  value: string; onChange: (v: string) => void; rows?: number; placeholder?: string
}) {
  return (
    <textarea
      value={value} rows={rows} placeholder={placeholder} spellCheck={false}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={(e) => {
        if (e.key === "Tab") {
          e.preventDefault()
          const t = e.currentTarget
          const { selectionStart: s, selectionEnd: en } = t
          const next = `${value.slice(0, s)}    ${value.slice(en)}`
          onChange(next)
          requestAnimationFrame(() => { t.selectionStart = t.selectionEnd = s + 4 })
        }
      }}
      className="w-full rounded-md border border-input bg-slate-950 p-3 font-mono text-xs leading-relaxed text-emerald-200 outline-none focus:ring-2 focus:ring-ring"
    />
  )
}

/** Toggle chips for multi-select filters. */
export function Chips<T extends string>({ options, value, onChange, render }: {
  options: readonly T[]; value: T[]; onChange: (v: T[]) => void; render?: (o: T) => React.ReactNode
}) {
  return (
    <div className="flex flex-wrap gap-1">
      {options.map((o) => {
        const on = value.includes(o)
        return (
          <button
            key={o} type="button"
            onClick={() => onChange(on ? value.filter((x) => x !== o) : [...value, o])}
            className={cn("rounded-full border px-2.5 py-0.5 text-xs transition-colors",
              on ? "border-primary bg-primary text-primary-foreground" : "border-border bg-background text-muted-foreground hover:bg-muted")}
          >
            {render ? render(o) : o.replace(/_/g, " ")}
          </button>
        )
      })}
    </div>
  )
}

export function Tabs<T extends string>({ tabs, value, onChange }: {
  tabs: readonly { value: T; label: string }[]; value: T; onChange: (v: T) => void
}) {
  return (
    <div className="mb-4 inline-flex rounded-lg border border-border bg-muted p-0.5">
      {tabs.map((t) => (
        <button
          key={t.value} type="button" onClick={() => onChange(t.value)}
          className={cn("rounded-md px-3 py-1 text-sm transition-colors",
            value === t.value ? "bg-background font-medium text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground")}
        >
          {t.label}
        </button>
      ))}
    </div>
  )
}

export function JsonView({ value, maxHeight = 320 }: { value: unknown; maxHeight?: number }) {
  return (
    <pre className="overflow-auto rounded-md bg-muted p-3 font-mono text-xs" style={{ maxHeight }}>
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

/** Collapsible section (native details). */
export function Disclosure({ title, children, defaultOpen = false }: {
  title: React.ReactNode; children: React.ReactNode; defaultOpen?: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <details open={open} onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)} className="rounded-md border border-border">
      <summary className="cursor-pointer select-none px-3 py-2 text-sm font-medium">{title}</summary>
      <div className="border-t border-border p-3">{children}</div>
    </details>
  )
}

/** Right-hand slide-over for detail views (case detail, rule detail). */
export function Drawer({ open, onClose, children, width = "44rem" }: {
  open: boolean; onClose: () => void; children: React.ReactNode; width?: string
}) {
  React.useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose() }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-[60] flex justify-end">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} aria-hidden />
      <aside
        role="dialog" aria-modal="true"
        className="relative h-full overflow-y-auto border-l border-border bg-background p-4 shadow-2xl"
        style={{ width: `min(${width}, 100vw)` }}
      >
        {children}
      </aside>
    </div>
  )
}
