/**
 * Triage & Cases (persona: SOC analyst). Merges 3_triage_queue.py (risk-ranked
 * queue, FP engine, control coverage, bulk actions) and 5_case_management.py
 * (case detail, similar findings, workflow updates).
 */

import {
  rows, one, scalar, str, int, oneOf, listOf, id, ids, placeholders,
  InputError, type Binds,
} from "@/lib/xdr"

export const STATUSES = ["new", "investigating", "contained", "resolved", "dismissed"] as const
export const CATEGORIES = ["identity", "endpoint", "network", "cloud", "application", "custom"] as const
export const SOURCES = ["stored_procedure", "ai_detection_agent", "ai_hunting_agent", "custom_rule",
  "ml_anomaly", "attack_graph", "control_engine"] as const
export const DISPOSITIONS = ["true_positive", "false_positive", "benign", "mitigated_by_control"] as const
export const BULK_ACTIONS = ["confirm_true_positive", "dismiss_false_positive"] as const

const SEVERITIES = ["1", "2", "3", "4", "5"] as const

/** Build the WHERE clause + binds for the finding list from validated filters. */
export function buildTriageFilter(p: Record<string, unknown>): { where: string; binds: Binds } {
  const clauses: string[] = []
  const binds: Binds = []

  const statuses = listOf(p, "statuses", STATUSES)
  if (statuses.length) {
    clauses.push(`f.status IN (${placeholders(statuses.length)})`)
    binds.push(...statuses)
  }
  const severities = listOf(p, "severities", SEVERITIES)
  if (severities.length) {
    clauses.push(`f.severity IN (${placeholders(severities.length)})`)
    binds.push(...severities.map(Number))
  }
  const category = oneOf(p, "category", ["all", ...CATEGORIES] as const, "all")
  if (category !== "all") {
    clauses.push("f.category = ?")
    binds.push(category)
  }
  const source = oneOf(p, "source", ["all", ...SOURCES] as const, "all")
  if (source !== "all") {
    clauses.push("f.detection_source = ?")
    binds.push(source)
  }
  const search = str(p, "search", { max: 200 }).toLowerCase()
  if (search) {
    clauses.push("(LOWER(COALESCE(f.user_name, f.src, f.dest, '')) LIKE ? OR LOWER(f.description) LIKE ?)")
    const like = `%${search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`
    binds.push(like, like)
  }
  return { where: clauses.length ? `WHERE ${clauses.join(" AND ")}` : "", binds }
}

export const triage = {
  "triage.list": async (p: Record<string, unknown>) => {
    const { where, binds } = buildTriageFilter(p)
    return rows(`
      SELECT f.finding_id, f.rule_id, f.detection_time, f.severity, f.confidence, f.risk_score,
             f.category, f.mitre_technique_id, f.status, f.detection_source,
             COALESCE(f.user_name, f.src, f.dest) AS entity,
             LEFT(f.description, 220) AS description,
             f.ai_fp_probability, f.assigned_to, f.disposition, f.incident_id,
             LEFT(f.triage_notes, 160) AS triage_notes,
             IFF(f.disposition = 'mitigated_by_control', TRUE, FALSE) AS control_covered,
             ROUND(fp.fp_rate * 100) AS fp_rate_pct
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
      -- FP_PATTERNS holds one row per (rule_id, entity), so this join cannot fan out
      LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.FP_PATTERNS fp
        ON fp.rule_id = f.rule_id
       AND fp.entity = COALESCE(f.user_name, f.src, f.dest, 'unknown')
      ${where}
      ORDER BY f.severity DESC, f.risk_score DESC, f.detection_time DESC
      LIMIT 200`, binds)
  },

  "triage.detail": async (p: Record<string, unknown>) => {
    const fid = id(p, "finding_id")
    const finding = await one(`
      SELECT f.finding_id, f.rule_id, r.rule_name, f.detection_time, f.event_time, f.severity,
             f.confidence, f.risk_score, f.category, f.mitre_tactic_id, f.mitre_technique_id,
             f.status, f.detection_source, f.user_name, f.src, f.dest,
             COALESCE(f.user_name, f.src, f.dest) AS entity,
             f.description, f.evidence, f.ai_explanation, f.ai_fp_probability,
             f.assigned_to, f.disposition, f.triage_notes, f.incident_id
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
      LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES r ON r.rule_id = f.rule_id
      WHERE f.finding_id = ?`, [fid])
    if (!finding) throw new InputError("Finding not found")
    return finding
  },

  /** Cortex AI semantic similarity: is this part of a bigger campaign? */
  "triage.similar": async (p: Record<string, unknown>) => {
    const fid = id(p, "finding_id")
    const r = await scalar<{ similar?: unknown[] }>(
      "CALL SNOWFLAKE_XDR.DETECTIONS.FIND_SIMILAR_FINDINGS(?)", [fid], { long: true })
    return r?.similar ?? []
  },

  "triage.update": async (p: Record<string, unknown>) => {
    const fid = id(p, "finding_id")
    const status = oneOf(p, "status", STATUSES)
    const disposition = oneOf(p, "disposition", ["", ...DISPOSITIONS] as const, "")
    const assignee = str(p, "assigned_to", { max: 100 })
    const notes = str(p, "triage_notes", { max: 2000 })
    await rows(`
      UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      SET status = ?,
          assigned_to = NULLIF(?, ''),
          disposition = COALESCE(NULLIF(?, ''), disposition),
          triage_notes = NULLIF(?, ''),
          triaged_at = CURRENT_TIMESTAMP()
      WHERE finding_id = ?`, [status, assignee, disposition, notes, fid])
    return { message: `Case updated: ${status}` }
  },

  "triage.bulk": async (p: Record<string, unknown>) => {
    const targets = ids(p, "finding_ids")
    const action = oneOf(p, "action", BULK_ACTIONS)
    const [status, disposition] = action === "dismiss_false_positive"
      ? ["dismissed", "false_positive"]
      : ["investigating", "true_positive"]
    await rows(`
      UPDATE SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      SET status = ?, disposition = ?, triaged_at = CURRENT_TIMESTAMP()
      WHERE finding_id IN (${placeholders(targets.length)})`, [status, disposition, ...targets])
    return { message: `${action.replace(/_/g, " ")} applied to ${targets.length} finding(s)` }
  },

  "triage.trainFp": async () => ({
    message: await scalar<string>("CALL SNOWFLAKE_XDR.DETECTIONS.TRAIN_FP_MODEL()", [], { long: true }),
  }),
  "triage.scoreFp": async () => ({
    message: await scalar<string>("CALL SNOWFLAKE_XDR.DETECTIONS.SCORE_FINDINGS_FP()", [], { long: true }),
  }),
  "triage.assessControls": async () => ({
    message: await scalar<string>("CALL SNOWFLAKE_XDR.DETECTIONS.APPLY_CONTROL_ASSESSMENT()", [], { long: true }),
  }),
  "triage.aiTriage": async (p: Record<string, unknown>) => {
    const batch = int(p, "batch", { min: 1, max: 25, def: 5 })
    return {
      message: await scalar<string>("CALL SNOWFLAKE_XDR.DETECTIONS.AI_TRIAGE_AGENT(?)", [batch], { long: true }),
    }
  },
}
