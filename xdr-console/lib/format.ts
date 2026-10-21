/** Pure formatting helpers shared by all views (no React). */

export const SEVERITY_LABEL: Record<number, string> = {
  5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Info",
}

/** Hex colors per severity, used by charts (CSS classes handle badges). */
export const SEVERITY_COLOR: Record<number, string> = {
  5: "#dc2626", 4: "#f97316", 3: "#eab308", 2: "#3b82f6", 1: "#64748b",
}

export function sevLabel(sev: unknown): string {
  return SEVERITY_LABEL[Number(sev)] ?? "Info"
}

export function fmtNum(v: unknown, digits = 0): string {
  const n = Number(v)
  if (v === null || v === undefined || Number.isNaN(n)) return "–"
  return n.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: 0 })
}

export function fmtPct(v: unknown, digits = 0): string {
  const n = Number(v)
  if (v === null || v === undefined || Number.isNaN(n)) return "–"
  return `${n.toFixed(digits)}%`
}

/** "2026-10-19 14:05" in the viewer's local time. */
export function fmtTime(v: unknown): string {
  if (!v) return "–"
  const d = new Date(String(v))
  if (Number.isNaN(d.getTime())) return String(v)
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** "5m ago", "3h ago", "2d ago"; future times read "in 4m". */
export function fmtAgo(v: unknown, now: number = Date.now()): string {
  if (!v) return "–"
  const t = new Date(String(v)).getTime()
  if (Number.isNaN(t)) return String(v)
  const diff = Math.round((now - t) / 1000)
  const abs = Math.abs(diff)
  const unit = abs < 60 ? `${abs}s` : abs < 3600 ? `${Math.round(abs / 60)}m`
    : abs < 86400 ? `${Math.round(abs / 3600)}h` : `${Math.round(abs / 86400)}d`
  return diff >= 0 ? `${unit} ago` : `in ${unit}`
}

/** Short hour label for chart axes: "Oct 19 14h". */
export function fmtHour(v: unknown): string {
  const d = new Date(String(v))
  if (Number.isNaN(d.getTime())) return String(v)
  return `${d.toLocaleString(undefined, { month: "short" })} ${d.getDate()} ${String(d.getHours()).padStart(2, "0")}h`
}

export function fmtDay(v: unknown): string {
  const d = new Date(String(v))
  if (Number.isNaN(d.getTime())) return String(v)
  return `${d.toLocaleString(undefined, { month: "short" })} ${d.getDate()}`
}

export function truncate(s: unknown, n: number): string {
  const str = s === null || s === undefined ? "" : String(s)
  return str.length > n ? `${str.slice(0, n - 1)}…` : str
}

export function shortId(v: unknown): string {
  const s = String(v ?? "")
  return s.length > 12 ? s.slice(0, 8) : s
}
