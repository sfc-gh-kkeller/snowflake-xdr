/**
 * Data sources: OpenTelemetry ingestion (setup/30_otel_ingest.sql, 31_otel_receiver.sql).
 * Source health, sample records, CIM mappings (activate / retire with rollback),
 * source tokens, and the OTLP endpoint collectors send to.
 */

import { rows, scalar, str, oneOf, id, bool, InputError, parseVariant, type Row } from "@/lib/xdr"

const SOURCE_RE = /^[a-z0-9_.-]{1,100}$/
const KINDS = ["okta", "linux_auth", "cloudtrail", "windows", "firewall", "vpn", "proxy", "dns", "edr", "unknown"] as const
const SOURCE_ACTIONS = ["pause", "resume"] as const

function sourceId(p: Record<string, unknown>, key = "source_id"): string {
  const v = typeof p[key] === "string" ? (p[key] as string).trim().toLowerCase() : ""
  if (!SOURCE_RE.test(v)) throw new InputError(`${key} must be lowercase letters, digits, '.', '_' or '-'`)
  return v
}

export const sources = {
  "sources.list": async () => {
    const list = await rows(`
      SELECT h.*,
             (SELECT MAX(c.change_id) FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES c
               WHERE c.change_type = 'new_parser' AND c.status = 'proposed'
                 AND c.evidence:source_id::VARCHAR = h.source_id) AS pending_change_id
      FROM SNOWFLAKE_XDR.REFERENCE.V_OTEL_SOURCE_HEALTH h
      ORDER BY IFF(h.status IN ('unmapped', 'mapping_proposed'), 0, 1), h.last_received DESC NULLS LAST`)
    return list.map((r) => ({ ...r, mappings: parseVariant(r.mappings) ?? [] }))
  },

  /** OTLP endpoint and totals. The endpoint is empty until the receiver service is deployed. */
  "sources.status": async () => {
    const totals = await rows(`
      SELECT COUNT(*) AS records_24h, COUNT(DISTINCT source_id) AS sources_24h,
             ROUND(AVG(DATEDIFF('millisecond', event_time, received_at)) / 1000, 1) AS avg_lag_seconds
      FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS WHERE received_at > DATEADD('hour', -24, CURRENT_TIMESTAMP())`)
    const mapped = await rows(`
      SELECT COALESCE(SUM(rows_mapped), 0) AS rows_mapped, COUNT_IF(status = 'live') AS live_mappings,
             COUNT_IF(status = 'live' AND last_error IS NOT NULL) AS failing_mappings
      FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS`)
    let endpoint: string | null = null
    try {
      const eps = await rows("SHOW ENDPOINTS IN SERVICE SNOWFLAKE_XDR.RAW_LOGS.XDR_OTLP_RECEIVER")
      const url = eps.find((e) => e.name === "otlp")?.ingress_url
      endpoint = typeof url === "string" && url.endsWith(".snowflakecomputing.app") ? `https://${url}/v1/logs` : null
    } catch {
      endpoint = null // receiver not deployed, or no privilege on the service
    }
    return { ...totals[0], ...mapped[0], endpoint }
  },

  "sources.samples": async (p: Record<string, unknown>) => {
    const sid = sourceId(p)
    const list = await rows(`
      SELECT received_at, event_time, severity_text, body, attributes, resource
      FROM SNOWFLAKE_XDR.RAW_LOGS.OTEL_LOGS WHERE source_id = ?
      ORDER BY received_at DESC LIMIT 20`, [sid])
    return list.map((r) => ({ ...r, body: parseVariant(r.body), attributes: parseVariant(r.attributes), resource: parseVariant(r.resource) }))
  },

  "sources.mappings": async (p: Record<string, unknown>) => {
    const sid = sourceId(p)
    const list = await rows(`
      SELECT mapping_id, target_table, status, version, created_by, created_at, updated_at, watermark, rows_mapped,
             last_run_at, last_error, mapping_sql, validation
      FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS WHERE source_id = ?
      ORDER BY IFF(status = 'live', 0, IFF(status = 'draft', 1, 2)), updated_at DESC LIMIT 20`, [sid])
    return list.map((r) => ({ ...r, validation: parseVariant(r.validation) }))
  },

  /** Issue (or rotate) a source token. Shown once; only its hash is stored. */
  "sources.register": async (p: Record<string, unknown>) => {
    const sid = sourceId(p)
    const name = str(p, "name", { max: 200 })
    const kind = oneOf(p, "kind", KINDS, "unknown")
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.REFERENCE.REGISTER_OTEL_SOURCE(?, ?, ?)", [sid, name || null, kind])
    if (!r?.ok) throw new InputError(String(r?.message ?? "registration failed"))
    return { message: `Source ${r.source_id} registered. Token (shown once): ${r.token}`, token: r.token, source_id: r.source_id }
  },

  "sources.setStatus": async (p: Record<string, unknown>) => {
    const sid = sourceId(p)
    const action = oneOf(p, "action", SOURCE_ACTIONS)
    await rows(`
      UPDATE SNOWFLAKE_XDR.REFERENCE.OTEL_SOURCES
      SET status = IFF(? = 'pause', 'paused',
                       IFF(EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.REFERENCE.CIM_MAPPINGS m
                                    WHERE m.source_id = OTEL_SOURCES.source_id AND m.status = 'live'), 'mapped', 'unmapped'))
      WHERE source_id = ?`, [action, sid])
    return { message: action === "pause" ? `${sid} paused: its token is rejected until resumed.` : `${sid} resumed.` }
  },

  "sources.activate": async (p: Record<string, unknown>) => {
    const mid = id(p, "mapping_id")
    const backfill = bool(p, "backfill", true)
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.REFERENCE.ACTIVATE_CIM_MAPPING(?, ?)", [mid, backfill], { long: true })
    if (!r?.ok) throw new InputError(String(r?.message ?? "activation failed"))
    const applied = await scalar<Row>("CALL SNOWFLAKE_XDR.REFERENCE.APPLY_CIM_MAPPINGS()", [], { long: true })
    const n = Object.values(applied ?? {}).filter((v) => typeof v === "number").reduce((a, b) => a + Number(b), 0)
    return { message: `${r.message}. ${n} records mapped.` }
  },

  "sources.retire": async (p: Record<string, unknown>) => {
    const mid = id(p, "mapping_id")
    const deleteRows = bool(p, "delete_rows", false)
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.REFERENCE.RETIRE_CIM_MAPPING(?, ?)", [mid, deleteRows], { long: true })
    if (!r?.ok) throw new InputError(String(r?.message ?? "retire failed"))
    return { message: String(r.message) }
  },

  "sources.apply": async () => {
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.REFERENCE.APPLY_CIM_MAPPINGS()", [], { long: true })
    const parts = Object.entries(r ?? {}).map(([k, v]) => `${k}: ${v}`)
    return { message: parts.length ? `Mapped - ${parts.join(" · ")}` : "No live mappings." }
  },
}
