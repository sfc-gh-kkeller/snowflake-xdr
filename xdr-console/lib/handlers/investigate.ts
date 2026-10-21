/**
 * Investigations (incidents), Entity 360, Attack Graph and Threat Map.
 * Ported from 7_incident_view.py, 6_entity_investigation.py,
 * 17_attack_graph.py and 2_threat_map.py.
 */

import { rows, one, scalar, str, int, id, oneOf, InputError, normalizeTimestamp } from "@/lib/xdr"
import { entityKind, type LayoutNode, type LayoutEdge } from "@/lib/graph"

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

export const investigations = {
  "incidents.list": async (p: Record<string, unknown>) => {
    const status = oneOf(p, "status", ["all", "open", "closed"] as const, "all")
    return rows(`
      SELECT i.incident_id, i.title, i.severity, i.priority, i.status, i.primary_entity,
             i.entity_type, i.first_seen, i.last_seen, i.risk_score,
             ARRAY_SIZE(i.tactics_observed) AS tactic_count,
             (SELECT COUNT(*) FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_FINDINGS x
               WHERE x.incident_id = i.incident_id) AS finding_count
      FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS i
      ${status === "all" ? "" : "WHERE i.status = ?"}
      ORDER BY i.risk_score DESC NULLS LAST, i.created_at DESC
      LIMIT 100`, status === "all" ? [] : [status])
  },

  "incidents.detail": async (p: Record<string, unknown>) => {
    const iid = id(p, "incident_id")
    const incident = await one(
      "SELECT * FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS WHERE incident_id = ?", [iid])
    if (!incident) throw new InputError("Incident not found")
    const [killChain, graph, timeline, findings] = await Promise.all([
      rows(`
        SELECT stage_order, tactic_name, finding_count, first_observed, last_observed
        FROM SNOWFLAKE_XDR.INCIDENTS.KILL_CHAIN_PROGRESSION
        WHERE incident_id = ? ORDER BY stage_order`, [iid]),
      rows(`
        SELECT src_entity_type, src_entity_value, relationship_type,
               dst_entity_type, dst_entity_value, event_count, first_seen
        FROM SNOWFLAKE_XDR.INCIDENTS.ENTITY_GRAPH
        WHERE incident_id = ? ORDER BY first_seen`, [iid]),
      rows(`
        SELECT event_time, action_summary, tactic_id, technique_id, actor_entity, target_entity
        FROM SNOWFLAKE_XDR.INCIDENTS.ATTACKER_TIMELINE
        WHERE incident_id = ? ORDER BY event_time`, [iid]),
      rows(`
        SELECT finding_id, rule_id, detection_time, severity, confidence, category,
               mitre_technique_id, LEFT(description, 200) AS description, detection_source,
               status, disposition
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE incident_id = ? ORDER BY event_time`, [iid]),
    ])
    return { incident, killChain, graph, timeline, findings }
  },

  "incidents.story": async (p: Record<string, unknown>) => {
    const iid = id(p, "incident_id")
    const r = await scalar<{ story?: string }>(
      "CALL SNOWFLAKE_XDR.INCIDENTS.AI_CAMPAIGN_STORY(?)", [iid], { long: true })
    return { text: r?.story ?? "" }
  },

  "incidents.setStatus": async (p: Record<string, unknown>) => {
    const iid = id(p, "incident_id")
    const status = oneOf(p, "status", ["open", "investigating", "contained", "closed"] as const)
    await rows(`
      UPDATE SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
      SET status = ?, closed_at = IFF(? = 'closed', CURRENT_TIMESTAMP(), NULL)
      WHERE incident_id = ?`, [status, status, iid])
    return { message: `Incident ${status}` }
  },
}

// ---------------------------------------------------------------------------
// Entity 360
// ---------------------------------------------------------------------------

/** Entities are users, IPs, or hostnames: keep to a conservative charset. */
function entity(p: Record<string, unknown>): string {
  const e = str(p, "entity", { max: 128, required: true })
  if (!/^[A-Za-z0-9._:@\\/-]+$/.test(e)) throw new InputError("entity contains unsupported characters")
  return e
}

type EntityEvent = Record<string, unknown>

/** Flatten SEARCH_ENTITY events into uniform table rows (newest first). */
export function flattenEntityEvents(events: unknown[]): EntityEvent[] {
  return events
    .map((raw) => {
      let e = raw as Record<string, unknown>
      if (typeof raw === "string") {
        try { e = JSON.parse(raw) } catch { e = { detail: raw } }
      }
      return {
        time: normalizeTimestamp(e.time ?? null),
        source: e.source ?? "",
        action: e.action ?? "",
        detail: e.detail || e.process || e.query || e.url || "",
        user: e.user ?? "",
        src: e.src ?? "",
        dest: e.dest ?? "",
      }
    })
    .sort((a, b) => String(b.time ?? "").localeCompare(String(a.time ?? "")))
}

export const entityHandlers = {
  "entity.search": async (p: Record<string, unknown>) => {
    const e = entity(p)
    const days = int(p, "days", { min: 1, max: 30, def: 7 })
    const r = await scalar<{ events?: unknown[] }>(
      "CALL SNOWFLAKE_XDR.DETECTIONS.SEARCH_ENTITY(?, ?)", [e, days], { long: true })
    const events = flattenEntityEvents(r?.events ?? [])
    const findings = await rows(`
      SELECT finding_id, rule_id, detection_time, severity, status, disposition,
             LEFT(description, 160) AS description
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      WHERE (user_name = ? OR src = ? OR dest = ?)
        AND detection_time > DATEADD('day', ?, CURRENT_TIMESTAMP())
      ORDER BY detection_time DESC LIMIT 50`, [e, e, e, -days])
    return { events, findings }
  },

  "entity.investigate": async (p: Record<string, unknown>) => {
    const e = entity(p)
    const days = int(p, "days", { min: 1, max: 30, def: 7 })
    const r = await scalar<{ summary?: string }>(
      "CALL SNOWFLAKE_XDR.DETECTIONS.AI_INVESTIGATE_ENTITY(?, ?)", [e, days], { long: true })
    return { text: r?.summary ?? "No summary available" }
  },

  "entity.suspicious": async () =>
    rows(`
      SELECT COALESCE(user_name, src, dest) AS entity, COUNT(*) AS findings,
             MAX(severity) AS max_severity, MAX(detection_time) AS last_seen
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      WHERE COALESCE(user_name, src, dest) IS NOT NULL
      GROUP BY 1 ORDER BY findings DESC LIMIT 12`),
}

// ---------------------------------------------------------------------------
// Attack graph + threat map
// ---------------------------------------------------------------------------

export interface PathEdge { type?: string; action?: string; [k: string]: unknown }
export interface AttackPath {
  hops?: number
  entities?: string[]
  edges?: PathEdge[]
  suspicious?: boolean
  last_seen?: string
}


/**
 * The trace returns one path per traversal, so the same entity chain shows up
 * once per underlying event. Collapse to unique chains (deepest first) with a
 * `variants` count and the latest last_seen.
 */
export function uniqueChains(paths: AttackPath[]): (AttackPath & { variants: number })[] {
  const byChain = new Map<string, AttackPath & { variants: number }>()
  for (const p of paths) {
    const key = (p.entities ?? []).join("\u0000")
    const existing = byChain.get(key)
    if (!existing) {
      byChain.set(key, { ...p, variants: 1 })
    } else {
      existing.variants += 1
      existing.suspicious = Boolean(existing.suspicious || p.suspicious)
      if (String(p.last_seen ?? "") > String(existing.last_seen ?? "")) existing.last_seen = p.last_seen
    }
  }
  return [...byChain.values()].sort((a, b) =>
    (b.hops ?? 0) - (a.hops ?? 0) || String(b.last_seen ?? "").localeCompare(String(a.last_seen ?? "")))
}

/**
 * Merge traced paths into one layered graph: each entity sits at the hop
 * distance where it first appears, edges are de-duplicated.
 */
export function pathsToGraph(paths: AttackPath[], maxPaths = 12): { nodes: LayoutNode[]; edges: LayoutEdge[] } {
  const sorted = [...paths].sort((a, b) => (b.hops ?? 0) - (a.hops ?? 0)).slice(0, maxPaths)
  const layerOf = new Map<string, number>()
  const edgeMap = new Map<string, LayoutEdge>()
  for (const path of sorted) {
    const ents = path.entities ?? []
    ents.forEach((e, i) => {
      if (!layerOf.has(e) || (layerOf.get(e) as number) > i) layerOf.set(e, i)
    })
    for (let i = 0; i < ents.length - 1; i++) {
      const key = `${ents[i]}->${ents[i + 1]}`
      const ed = path.edges?.[i]
      const label = ed ? [ed.type, ed.action].filter(Boolean).join(": ") : ""
      const existing = edgeMap.get(key)
      if (existing) {
        existing.suspicious = existing.suspicious || Boolean(path.suspicious)
      } else {
        edgeMap.set(key, { id: key, source: ents[i], target: ents[i + 1], label, suspicious: Boolean(path.suspicious) })
      }
    }
  }
  const rowsPerLayer = new Map<number, number>()
  const nodes: LayoutNode[] = [...layerOf.entries()]
    .sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0]))
    .map(([e, layer]) => {
      const row = rowsPerLayer.get(layer) ?? 0
      rowsPerLayer.set(layer, row + 1)
      return { id: e, label: e, layer, row, start: layer === 0, kind: entityKind(e) }
    })
  return { nodes, edges: [...edgeMap.values()] }
}

export const graph = {
  "graph.entities": async () =>
    rows(`
      SELECT src_entity, COUNT(DISTINCT dst_entity) AS fan_out, COUNT(*) AS edges
      FROM SNOWFLAKE_XDR.DETECTIONS.ATTACK_PATH_EDGES
      GROUP BY 1 ORDER BY fan_out DESC LIMIT 200`),

  "graph.trace": async (p: Record<string, unknown>) => {
    const start = str(p, "entity", { max: 160, required: true })
    if (!/^[A-Za-z0-9._:@\\/-]+$/.test(start)) throw new InputError("entity contains unsupported characters")
    const r = await scalar<{ paths?: AttackPath[] }>(
      "CALL SNOWFLAKE_XDR.DETECTIONS.TRACE_ATTACK_PATHS(?)", [start], { long: true })
    const all = r?.paths ?? []
    const paths = uniqueChains(all)
    // Most recent incident on the start entity, for the campaign story button
    const bare = start.replace(/^(host|user|domain):/, "")
    const incident = await one(`
      SELECT incident_id FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS
      WHERE primary_entity = ? ORDER BY created_at DESC LIMIT 1`, [bare])
    return {
      paths: paths.slice(0, 25), traversals: all.length,
      graph: pathsToGraph(paths), incident_id: incident?.incident_id ?? null,
    }
  },

  "graph.rattle": async () =>
    rows(`
      SELECT finding_id, src, description, severity, risk_score, status, detection_time
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      WHERE rule_id = 'GRAPH-RATTLE-001'
      ORDER BY detection_time DESC LIMIT 15`),

  "graph.rebuild": async () => ({
    message: await scalar<string>("CALL SNOWFLAKE_XDR.DETECTIONS.BUILD_ATTACK_GRAPH()", [], { long: true }),
  }),
  "graph.rattleScan": async () => ({
    message: await scalar<string>("CALL SNOWFLAKE_XDR.DETECTIONS.DOOR_RATTLING_SCAN()", [], { long: true }),
  }),

  "map.points": async () =>
    rows(`
      SELECT geo_lat AS lat, geo_lon AS lon, geo_city AS city, geo_country AS country,
             COUNT(*) AS events, SUM(IFF(action = 'failure', 1, 0)) AS failures
      FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
      WHERE geo_lat IS NOT NULL AND geo_lon IS NOT NULL
        AND _time > DATEADD('day', -7, CURRENT_TIMESTAMP())
      GROUP BY 1, 2, 3, 4 ORDER BY failures DESC`),

  "map.sources": async () =>
    rows(`
      SELECT src, COUNT(*) AS attempts, COUNT(DISTINCT user_name) AS users_targeted,
             SUM(IFF(action = 'failure', 1, 0)) AS failures
      FROM SNOWFLAKE_XDR.RAW_LOGS.AUTHENTICATION
      WHERE _time > DATEADD('day', -7, CURRENT_TIMESTAMP()) AND src IS NOT NULL
      GROUP BY 1 ORDER BY failures DESC LIMIT 10`),
}
