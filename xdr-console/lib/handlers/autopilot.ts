/**
 * Detection Autopilot: the self-maintaining detection loop (setup/26_autopilot.sql).
 * Read the change feed and policy, take human decisions, edit policy, and start
 * a cycle. Cycles run as a Snowflake task because they take minutes.
 */

import { rows, one, scalar, str, oneOf, id, InputError, parseVariant, type Row } from "@/lib/xdr"

export const CHANGE_TYPES = [
  "new_rule", "fix_broken", "tune_filter", "tune_threshold", "disable_noisy", "retire_silent", "new_parser",
  "auto_suppress", "suppress_entity", "intel_allowlist", "revoke_suppression", "recheck_verdicts", "pack_rule",
] as const
export const MODES = ["auto_live", "shadow_then_promote", "propose_only", "off"] as const
const STATUSES = [
  "all", "open", "proposed", "shadow", "applied", "promoted", "approved", "rejected", "rolled_back", "failed",
] as const
const DECISIONS = ["approve", "reject", "rollback"] as const
const ACTOR_RE = /^[A-Za-z0-9_.@$-]{1,255}$/

/** Signed-in console user (from the ingress header via the API route), for the audit trail. */
function actor(p: Record<string, unknown>): string | null {
  const a = typeof p.__actor === "string" ? p.__actor.trim() : ""
  return ACTOR_RE.test(a) ? a : null
}

const CH = "SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES"

export const autopilot = {
  "autopilot.summary": async () => {
    const [kpis, coverage, lastRun] = await Promise.all([
      one(`
        SELECT COUNT_IF(updated_at > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS changes_7d,
               COUNT_IF(status = 'proposed') AS pending,
               COUNT_IF(status = 'shadow') AS shadow,
               COUNT_IF(status IN ('applied', 'promoted', 'approved')
                        AND updated_at > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS went_live_7d,
               COUNT_IF(status = 'rolled_back' AND decided_by LIKE 'autopilot%'
                        AND updated_at > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS auto_rollbacks_7d,
               COUNT_IF(status = 'failed' AND updated_at > DATEADD('day', -7, CURRENT_TIMESTAMP())) AS failed_7d
        FROM ${CH}`),
      one(`
        SELECT COUNT(DISTINCT mitre_technique_id) AS techniques_live
        FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
        WHERE managed_by = 'autopilot' AND enabled`),
      one(`
        SELECT MAX(completed_time) AS last_run, MAX_BY(state, completed_time) AS last_state
        FROM TABLE(SNOWFLAKE_XDR.INFORMATION_SCHEMA.TASK_HISTORY(
          TASK_NAME => 'TASK_AUTOPILOT', SCHEDULED_TIME_RANGE_START => DATEADD('day', -7, CURRENT_TIMESTAMP())))
        WHERE state IN ('SUCCEEDED', 'FAILED')`),
    ])
    const running = await one(`
      SELECT COUNT(*) AS n FROM TABLE(SNOWFLAKE_XDR.INFORMATION_SCHEMA.TASK_HISTORY(
        TASK_NAME => 'TASK_AUTOPILOT', SCHEDULED_TIME_RANGE_START => DATEADD('hour', -1, CURRENT_TIMESTAMP())))
      WHERE state IN ('EXECUTING', 'SCHEDULED') AND scheduled_time <= CURRENT_TIMESTAMP()`)
    return { ...kpis, ...coverage, ...lastRun, running: Number(running?.n ?? 0) > 0 }
  },

  "autopilot.changes": async (p: Record<string, unknown>) => {
    const status = oneOf(p, "status", STATUSES, "all")
    const where = status === "all" ? "" : status === "open"
      ? "WHERE status IN ('proposed', 'shadow')" : "WHERE status = ?"
    return rows(`
      SELECT change_id, created_at, updated_at, change_type, mode, status, title, technique_id,
             rule_id, target_rule_id, severity, decided_by,
             COALESCE(decision_note, evidence:last_evaluation:reason::VARCHAR, evidence:gate:reason::VARCHAR,
                      LEFT(rationale, 220)) AS reason,
             COALESCE(evidence:last_evaluation:metrics, evidence:metrics) AS metrics
      FROM ${CH} ${where}
      ORDER BY IFF(status IN ('proposed', 'shadow'), 0, 1), updated_at DESC
      LIMIT 200`, status === "all" || status === "open" ? [] : [status])
      .then((list) => list.map((r) => ({ ...r, metrics: parseVariant(r.metrics) })))
  },

  "autopilot.detail": async (p: Record<string, unknown>) => {
    const cid = id(p, "change_id")
    const change = await one(`SELECT * FROM ${CH} WHERE change_id = ?`, [cid])
    if (!change) throw new InputError("Change not found")
    const ruleId = (change.rule_id ?? change.target_rule_id) as string | null
    const [current, target, shadow] = await Promise.all([
      change.rule_id ? one(`
        SELECT rule_id, name, code, enabled, test_mode, version, managed_by, pinned
        FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE rule_id = ?`, [change.rule_id as string]) : null,
      change.target_rule_id ? one(`
        SELECT rule_id, name, code, enabled, version, pinned FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
        WHERE rule_id = ?
        UNION ALL
        SELECT rule_id, rule_name, NULL, enabled, NULL, NULL FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES
        WHERE rule_id = ?`, [change.target_rule_id as string, change.target_rule_id as string]) : null,
      ruleId ? rows(`
        SELECT event_time, user_name, src, dest, description FROM SNOWFLAKE_XDR.DETECTIONS.SHADOW_FINDINGS
        WHERE rule_id = ? ORDER BY event_time DESC LIMIT 10`, [ruleId]) : [],
    ])
    return { change: { ...change, evidence: parseVariant(change.evidence) }, rule: current, target, shadow }
  },

  "autopilot.decide": async (p: Record<string, unknown>) => {
    const cid = id(p, "change_id")
    const action = oneOf(p, "action", DECISIONS)
    const note = str(p, "note", { max: 1000 })
    const r = await scalar<Row>(
      "CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT(?, ?, ?)",
      [`decide:${action}`, cid, JSON.stringify({ note, actor: actor(p) })], { long: true })
    if (!r?.ok) throw new InputError(String(r?.message ?? "decision failed"))
    return { message: String(r.message) }
  },

  "autopilot.pin": async (p: Record<string, unknown>) => {
    const rid = id(p, "rule_id")
    const action = oneOf(p, "action", ["pin", "unpin"] as const)
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_DECIDE(?, ?, NULL)", [rid, action])
    return { message: String(r?.message ?? "done") }
  },

  "autopilot.policy": async () =>
    rows(`
      SELECT change_type, mode, max_per_cycle, promote_after_hours, min_recall, max_benign_matches,
             description, updated_by, updated_at
      FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_POLICY
      ORDER BY ARRAY_POSITION(change_type::VARIANT, PARSE_JSON(?))`, [JSON.stringify(CHANGE_TYPES)]),

  "autopilot.setPolicy": async (p: Record<string, unknown>) => {
    const changeType = oneOf(p, "change_type", CHANGE_TYPES)
    const arg: Record<string, unknown> = { change_type: changeType, actor: actor(p) }
    if (p.mode !== undefined) arg.mode = oneOf(p, "mode", MODES)
    for (const [k, lo, hi] of [
      ["max_per_cycle", 0, 20], ["promote_after_hours", 0, 720], ["max_benign_matches", 0, 10000],
    ] as const) {
      if (p[k] === undefined || p[k] === "") continue
      const n = Number(p[k])
      if (!Number.isFinite(n) || n < lo || n > hi) throw new InputError(`${k} must be between ${lo} and ${hi}`)
      arg[k] = n
    }
    if (p.min_recall !== undefined && p.min_recall !== "") {
      const n = Number(p.min_recall)
      if (!Number.isFinite(n) || n < 0 || n > 1) throw new InputError("min_recall must be between 0 and 1")
      arg.min_recall = n
    }
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT('set_policy', ?, NULL)", [JSON.stringify(arg)])
    if (!r?.ok) throw new InputError(String(r?.message ?? "policy update failed"))
    return { message: String(r.message) }
  },

  /** Cycles take minutes: run them as the task so the request returns at once. */
  "autopilot.runCycle": async () => {
    await scalar("EXECUTE TASK SNOWFLAKE_XDR.DETECTIONS.TASK_AUTOPILOT")
    return { message: "Autopilot cycle started. New changes appear in the feed within a few minutes." }
  },

  "autopilot.digest": async () => {
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_DIGEST()", [], { long: true })
    return {
      message: r?.sent ? `Digest emailed to ${r.to}` : `Digest not sent: ${String(r?.reason ?? "unknown")}`,
      body: r?.body ?? "",
    }
  },
}
