/**
 * Server-side data layer for the XDR console.
 *
 * Every query the UI can run is a named handler (lib/handlers/*). Handlers
 * validate their inputs with the helpers below and pass user values only as
 * `?` binds — the client never sends SQL.
 */

import { querySnowflake, querySnowflakeLongRunning } from "@/lib/snowflake"

export type Row = Record<string, unknown>
export type Binds = (string | number | boolean | null)[]

/** Error whose message is safe to show to the user (bad input, not found). */
export class InputError extends Error {}

// ---------------------------------------------------------------------------
// Value normalization
// ---------------------------------------------------------------------------

/** ISO-8601 string for Date-like values; everything else unchanged. */
export function toIso(value: unknown): unknown {
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString()
  }
  // snowflake-sdk SfDate/SfTimestamp objects expose toJSON()
  if (value && typeof value === "object" && "toJSON" in value &&
      typeof (value as { toJSON: unknown }).toJSON === "function" &&
      !Array.isArray(value)) {
    const json = (value as { toJSON: () => unknown }).toJSON()
    if (typeof json === "string") return json
  }
  return value
}

/** Parse VARIANT values that arrive as JSON strings; leave other values alone. */
export function parseVariant<T = unknown>(value: unknown): T {
  if (typeof value === "string") {
    const s = value.trim()
    if (s.startsWith("{") || s.startsWith("[")) {
      try {
        return JSON.parse(s) as T
      } catch {
        return value as T
      }
    }
  }
  return value as T
}

// Plain decimal with no leading zeros (keeps "007", IPs, ids as text)
const NUMERIC_RE = /^-?(0|[1-9]\d{0,14})(\.\d+)?$/

/** The SDK returns NUMBER columns as strings; turn clean numerics into numbers. */
export function toNumberIfNumeric(value: unknown): unknown {
  if (typeof value === "string" && NUMERIC_RE.test(value)) return Number(value)
  return value
}

// "2026-10-19 05:39:03.441 -0700" (Snowflake TO_VARCHAR of TIMESTAMP_TZ)
const SF_TS_RE = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*([+-]\d{2}):?(\d{2})$/

/** Snowflake-formatted timestamp strings -> ISO-8601; other values unchanged. */
export function normalizeTimestamp(value: unknown): unknown {
  if (typeof value !== "string") return value
  const m = SF_TS_RE.exec(value.trim())
  if (!m) return value
  const d = new Date(`${m[1]}T${m[2]}${m[3]}:${m[4]}`)
  return Number.isNaN(d.getTime()) ? value : d.toISOString()
}

/** Lower-case column names and normalize dates/numbers so the UI gets stable JSON. */
export function normalizeRow(row: Row): Row {
  const out: Row = {}
  for (const [k, v] of Object.entries(row)) {
    out[k.toLowerCase()] = toNumberIfNumeric(toIso(v))
  }
  return out
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

export async function rows(sql: string, binds: Binds = []): Promise<Row[]> {
  const result = await querySnowflake(sql, binds.length ? { binds } : {})
  return result.map(normalizeRow)
}

export async function one(sql: string, binds: Binds = []): Promise<Row | null> {
  const r = await rows(sql, binds)
  return r[0] ?? null
}

/**
 * Run a CALL (or single-value SELECT) and return its first column, parsed if
 * it is a VARIANT JSON string. `long` uses async submit + polling for AI calls
 * that can take tens of seconds.
 */
export async function scalar<T = unknown>(
  sql: string,
  binds: Binds = [],
  opts: { long?: boolean } = {},
): Promise<T> {
  const options = binds.length ? { binds } : {}
  const result = opts.long
    ? await querySnowflakeLongRunning(sql, { ...options, pollIntervalMs: 2000 })
    : await querySnowflake(sql, options)
  const first = result[0]
  if (!first) return null as T
  return parseVariant<T>(toIso(Object.values(first)[0]))
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

type Params = Record<string, unknown>

export function str(p: Params, key: string, opts: { max?: number; required?: boolean } = {}): string {
  const v = p[key]
  const max = opts.max ?? 500
  if (v === undefined || v === null || v === "") {
    if (opts.required) throw new InputError(`${key} is required`)
    return ""
  }
  if (typeof v !== "string" && typeof v !== "number") throw new InputError(`${key} must be text`)
  const s = String(v).trim()
  if (s.length > max) throw new InputError(`${key} is too long (max ${max})`)
  if (opts.required && !s) throw new InputError(`${key} is required`)
  return s
}

/** Optional string: returns null instead of "" so it binds as SQL NULL. */
export function optStr(p: Params, key: string, max = 500): string | null {
  return str(p, key, { max }) || null
}

export function int(p: Params, key: string, opts: { min: number; max: number; def: number }): number {
  const v = p[key]
  if (v === undefined || v === null || v === "") return opts.def
  const n = typeof v === "number" ? v : Number(v)
  if (!Number.isFinite(n)) throw new InputError(`${key} must be a number`)
  return Math.min(opts.max, Math.max(opts.min, Math.round(n)))
}

export function bool(p: Params, key: string, def = false): boolean {
  const v = p[key]
  if (v === undefined || v === null) return def
  if (typeof v === "boolean") return v
  if (v === "true") return true
  if (v === "false") return false
  throw new InputError(`${key} must be true or false`)
}

export function oneOf<T extends string>(p: Params, key: string, allowed: readonly T[], def?: T): T {
  const v = p[key]
  if ((v === undefined || v === null || v === "") && def !== undefined) return def
  if (typeof v === "string" && (allowed as readonly string[]).includes(v)) return v as T
  throw new InputError(`${key} must be one of: ${allowed.join(", ")}`)
}

export function listOf<T extends string>(p: Params, key: string, allowed: readonly T[]): T[] {
  const v = p[key]
  if (v === undefined || v === null) return []
  if (!Array.isArray(v)) throw new InputError(`${key} must be a list`)
  for (const item of v) {
    if (typeof item !== "string" || !(allowed as readonly string[]).includes(item)) {
      throw new InputError(`${key} contains an invalid value`)
    }
  }
  return v as T[]
}

/** Finding / incident / rule IDs are UUIDs or short rule codes. */
const ID_RE = /^[A-Za-z0-9_-]{1,64}$/

export function id(p: Params, key: string): string {
  const v = p[key]
  if (typeof v !== "string" || !ID_RE.test(v)) throw new InputError(`${key} is not a valid id`)
  return v
}

export function ids(p: Params, key: string, maxCount = 200): string[] {
  const v = p[key]
  if (!Array.isArray(v) || v.length === 0) throw new InputError(`${key} must be a non-empty list`)
  if (v.length > maxCount) throw new InputError(`${key}: at most ${maxCount} ids`)
  return v.map((item, i) => {
    if (typeof item !== "string" || !ID_RE.test(item)) throw new InputError(`${key}[${i}] is not a valid id`)
    return item
  })
}

/** `?, ?, ?` placeholder list for an IN clause. */
export function placeholders(n: number): string {
  return Array.from({ length: n }, () => "?").join(", ")
}
