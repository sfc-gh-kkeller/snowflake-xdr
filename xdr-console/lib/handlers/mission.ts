/**
 * Mission Control: human oversight of the autonomous SOC (setup/36_oversight.sql)
 * and rule packs (setup/34_rule_packs.sql).
 * One queue of what needs a human, one ledger of what the AI did (with undo),
 * the kill switch and the daily change budget.
 */

import { rows, one, scalar, str, oneOf, bool, InputError, parseVariant, type Row } from "@/lib/xdr"

const LEDGER_RE = /^[a-z_]+:[A-Za-z0-9_.|:-]{1,200}$/
const ITEM_RE = /^(change|review|response|sla|ticket|canary|areview):[A-Za-z0-9_.|-]{1,100}$/
const PACK_RE = /^[a-z][a-z0-9_]{1,40}$/
const ACTOR_RE = /^[A-Za-z0-9_.@$-]{1,255}$/
const WINDOWS = { "24h": 24, "7d": 168, "30d": 720 } as const
const WHO = ["machine", "all", "human"] as const
const SOURCES = ["all", "autopilot", "agent", "confidence", "case", "ticketing", "parser", "response", "guardrail"] as const
const VERDICTS = ["true_positive", "false_positive", "benign"] as const

function actor(p: Record<string, unknown>): string | null {
  const a = typeof p.__actor === "string" ? p.__actor.trim() : ""
  return ACTOR_RE.test(a) ? a : null
}

function ok(r: Row | null, fallback: string): { message: string } {
  if (!r?.ok) throw new InputError(String(r?.message ?? fallback))
  return { message: String(r.message) }
}

export const mission = {
  "mission.status": async () => {
    const s = await one("SELECT * FROM SNOWFLAKE_XDR.DASHBOARDS.V_AUTONOMY_STATUS")
    const counts = await one(`
      SELECT (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DASHBOARDS.V_NEEDS_HUMAN) AS needs_you,
             (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DASHBOARDS.V_AI_ACTION_LEDGER
               WHERE actor_type <> 'human' AND at >= DATEADD('hour', -24, CURRENT_TIMESTAMP())) AS ai_actions_24h,
             (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES
               WHERE status IN ('rolled_back') AND updated_at >= DATEADD('day', -7, CURRENT_TIMESTAMP())) AS rollbacks_7d,
             (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT_CHANGES WHERE status = 'shadow') AS in_shadow`)
    return { ...(s ?? {}), per_type: parseVariant(s?.per_type) ?? [], ...(counts ?? {}) }
  },

  "mission.needs": async () =>
    rows(`
      SELECT item_id, kind, sub_kind, title, detail, severity, score, created_at, ref_id, actions, link
      FROM SNOWFLAKE_XDR.DASHBOARDS.V_NEEDS_HUMAN ORDER BY score DESC, created_at LIMIT 200`)
      .then((list) => list.map((r) => ({ ...r, actions: parseVariant(r.actions) ?? [] }))),

  "mission.ledger": async (p: Record<string, unknown>) => {
    const hours = WINDOWS[oneOf(p, "window", Object.keys(WINDOWS) as (keyof typeof WINDOWS)[], "24h")]
    const who = oneOf(p, "who", WHO, "machine")
    const source = oneOf(p, "source", SOURCES, "all")
    const list = await rows(`
      SELECT ledger_id, at, source, actor, actor_type, action, title, reason, status, severity, undo, link, evidence
      FROM SNOWFLAKE_XDR.DASHBOARDS.V_AI_ACTION_LEDGER
      WHERE at >= DATEADD('hour', -?, CURRENT_TIMESTAMP())
        AND (? = 'all' OR (? = 'machine' AND actor_type <> 'human') OR (? = 'human' AND actor_type = 'human'))
        AND (? = 'all' OR source = ?)
      ORDER BY at DESC LIMIT 500`, [hours, who, who, who, source, source])
    return list.map((r) => ({ ...r, evidence: parseVariant(r.evidence) }))
  },

  "mission.undo": async (p: Record<string, unknown>) => {
    const lid = str(p, "ledger_id", { max: 220, required: true })
    if (!LEDGER_RE.test(lid)) throw new InputError("ledger_id is not valid")
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.DASHBOARDS.UNDO_AI_ACTION(?, ?, ?)",
      [lid, str(p, "reason", { max: 900 }) || null, actor(p)], { long: true })
    return ok(r, "undo failed")
  },

  /** One-click decision on a Needs-you item; routed to the owning procedure. */
  "mission.decide": async (p: Record<string, unknown>) => {
    const item = str(p, "item_id", { max: 120, required: true })
    if (!ITEM_RE.test(item)) throw new InputError("item_id is not valid")
    const [kind, ref] = [item.slice(0, item.indexOf(":")), item.slice(item.indexOf(":") + 1)]
    const note = str(p, "note", { max: 1000 })
    const who = actor(p)
    if (kind === "change") {
      const action = oneOf(p, "action", ["approve", "reject"] as const)
      return ok(await scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT(?, ?, ?)",
        [`decide:${action}`, ref, JSON.stringify({ note: note || `${action}d in Mission Control`, actor: who })], { long: true }),
        "decision failed")
    }
    if (kind === "review") {
      const verdict = oneOf(p, "action", VERDICTS)
      return ok(await scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.REVIEW_DECIDE(?, ?, ?, ?)",
        [ref, verdict, note || null, who], { long: true }), "review failed")
    }
    if (kind === "response") {
      const action = oneOf(p, "action", ["approve", "reject"] as const)
      return ok(await scalar<Row>("CALL SNOWFLAKE_XDR.INCIDENTS.DECIDE_RESPONSE_ACTION(?, ?, ?, ?)",
        [ref, action, note || null, who], { long: true }), "response decision failed")
    }
    if (kind === "ticket") {
      oneOf(p, "action", ["retry"] as const)
      return ok(await scalar<Row>("CALL SNOWFLAKE_XDR.DASHBOARDS.UNDO_AI_ACTION(?, ?, ?)",
        [`ticket:${ref}`, "retry from Mission Control", who]), "retry failed")
    }
    if (kind === "areview") {
      const verdict = oneOf(p, "action", ["agree", "disagree"] as const)
      return ok(await scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.DECIDE_AUTONOMY_REVIEW(?, ?, ?, ?)",
        [ref, verdict, note || null, who], { long: true }), "review failed")
    }
    throw new InputError(`${kind} items are handled on their own page`)
  },

  /** Autonomy track record (setup/45_track_record.sql): weekly / monthly scorecard and per-type record. */
  "mission.scorecard": async (p: Record<string, unknown>) => {
    const grain = oneOf(p, "grain", ["week", "month"] as const, "week")
    const [periods, byType] = await Promise.all([
      rows(`SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.V_AUTONOMY_SCORECARD WHERE grain = ? ORDER BY period_start DESC`, [grain]),
      rows(`SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.V_AUTONOMY_SCORECARD_BY_TYPE ORDER BY total DESC`),
    ])
    return { grain, periods, by_type: byType }
  },

  "mission.sampleReviews": async () =>
    ok(await scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.SAMPLE_AUTONOMY_REVIEWS(5)", []), "sampling failed"),

  "mission.setAutonomy": async (p: Record<string, unknown>) => {
    const arg: Record<string, unknown> = { actor: actor(p), reason: str(p, "reason", { max: 1000 }) }
    if (p.paused !== undefined) {
      arg.paused = bool(p, "paused")
      if (arg.paused && !arg.reason) throw new InputError("say why you are pausing autonomy")
    }
    if (p.daily_change_budget !== undefined) {
      const b = Number(p.daily_change_budget)
      // a guardrail is never silently clamped: out of range is an error
      if (!Number.isInteger(b) || b < 0 || b > 1000) throw new InputError("daily_change_budget must be a whole number 0-1000")
      arg.daily_change_budget = b
    }
    if (Object.keys(arg).length === 2) throw new InputError("nothing to change")
    return ok(await scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.SET_AUTONOMY(?)", [JSON.stringify(arg)]), "update failed")
  },

  "mission.trackRecord": async () =>
    rows(`
      SELECT change_type, mode, approvals, rejections, rollbacks, automatic_live, total, canary_runs,
             canary_pass_rate, precision, verdicts
      FROM SNOWFLAKE_XDR.DETECTIONS.AUTONOMY_TRACK_RECORD WHERE total > 0 OR mode <> 'off' ORDER BY total DESC, change_type`),

  "mission.canaries": async () =>
    rows(`
      SELECT rule_id, name, pack_id, verification, canary_status, last_canary, latency_seconds, canary_message,
             runs_30d, passes_30d
      FROM SNOWFLAKE_XDR.DETECTIONS.V_VERIFIED_COVERAGE
      ORDER BY ARRAY_POSITION(verification::VARIANT, ARRAY_CONSTRUCT('failing', 'untested', 'verified', 'no_fixture')), rule_id`),

  "mission.runCanaries": async () => {
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CANARIES('all')", [], { long: true })
    const l = await scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.TRUST_LADDER(NULL)", [], { long: true })
    const prop = Array.isArray(l?.proposed) ? l.proposed.length : 0
    return { message: `${r?.passed ?? 0} of ${r?.rules ?? 0} canaries passed${Number(r?.failed) ? `, ${r?.failed} failing (fix_broken queued)` : ""}; trust ladder: ${prop} promotion proposal(s)` }
  },

  "mission.briefing": async (p: Record<string, unknown>) => {
    const send = bool(p, "send")
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.DASHBOARDS.MORNING_BRIEFING(NULL, ?)", [send], { long: true })
    return { ...(r ?? {}), message: send ? `Briefing sent: ${JSON.stringify(r?.sent ?? {})}` : "Preview ready" }
  },
}

export const threat = {
  "threat.profile": async () => {
    const p = await one(`
      SELECT statement, industry, regions, concerns, groups_ AS groups, techniques, model, updated_by, updated_at
      FROM SNOWFLAKE_XDR.REFERENCE.THREAT_PROFILE WHERE profile_id = 'current'`)
    const env = await one(`
      SELECT built_at, profile:products AS products, profile:data_gaps AS data_gaps,
             ARRAY_SIZE(profile:privileged_identities) AS privileged_identities,
             ARRAY_SIZE(profile:crown_jewels:sensitive_tagged) + ARRAY_SIZE(profile:crown_jewels:most_read) AS crown_jewels
      FROM SNOWFLAKE_XDR.REFERENCE.ENVIRONMENT_PROFILE ORDER BY built_at DESC LIMIT 1`)
    const parse = (r: Row | null, keys: string[]) =>
      r ? { ...r, ...Object.fromEntries(keys.map((k) => [k, parseVariant(r[k]) ?? []])) } : null
    return { profile: parse(p, ["regions", "concerns", "groups", "techniques"]), environment: parse(env, ["products", "data_gaps"]) }
  },

  "threat.setProfile": async (p: Record<string, unknown>) => {
    const statement = str(p, "statement", { max: 4000, required: true })
    if (statement.length < 5) throw new InputError("describe your organisation and concerns in a sentence or two")
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.REFERENCE.THREAT_PROFILE_ENGINE('set_profile', ?)",
      [JSON.stringify({ statement, actor: actor(p) })], { long: true })
    return ok(r, "profile failed")
  },

  "threat.heatmap": async () =>
    rows(`
      SELECT technique_id, name, tactic_id, tactic_name, likelihood, impact, score, coverage, live_rules,
             shadow_rules, verified_rules, reasons, rank_reason
      FROM SNOWFLAKE_XDR.REFERENCE.V_THREAT_HEATMAP ORDER BY score DESC, technique_id LIMIT 200`)
      .then((list) => list.map((r) => ({ ...r, reasons: parseVariant(r.reasons) ?? [] }))),

  "threat.exposures": async () =>
    rows(`
      SELECT exposure_id, created_at, kind, ref, title, detail, products, score, retro_hunt:hits::NUMBER AS hunt_hits, status
      FROM SNOWFLAKE_XDR.REFERENCE.THREAT_EXPOSURES ORDER BY created_at DESC, score DESC LIMIT 50`)
      .then((list) => list.map((r) => ({ ...r, products: parseVariant(r.products) ?? [] }))),

  "threat.refresh": async () => {
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.REFERENCE.THREAT_PROFILE_ENGINE('cycle', '3')", [], { long: true })
    if (r?.paused) throw new InputError(String(r.message))
    const n = (r?.emerging as Row | undefined)?.new_exposures
    return { message: `Profile rebuilt, ${Array.isArray(n) ? n.length : 0} new exposure(s), backlog re-ranked` }
  },
}

export const packs = {
  "packs.list": async () =>
    rows(`
      SELECT pack_id, name, vendor, version, description, onboarding, auto_install, requires, coverage, coverage_at,
             rules, live, pending, waiting_for_data, status
      FROM SNOWFLAKE_XDR.REFERENCE.V_RULE_PACKS ORDER BY IFF(status = 'no_data', 1, 0), pack_id`)
      .then((list) => list.map((r) => ({ ...r, requires: parseVariant(r.requires) ?? [], coverage: parseVariant(r.coverage) ?? {} }))),

  "packs.rules": async (p: Record<string, unknown>) => {
    const pid = str(p, "pack_id", { max: 41, required: true })
    if (!PACK_RE.test(pid)) throw new InputError("pack_id is not valid")
    return rows(`
      SELECT rule_id, name, severity, mitre_technique_id, source_table, vendor_product, version, install_state,
             state_reason, enabled, test_mode, pinned, findings_7d, shadow_findings
      FROM SNOWFLAKE_XDR.REFERENCE.V_RULE_PACK_RULES WHERE pack_id = ? ORDER BY rule_id`, [pid])
  },

  "packs.install": async (p: Record<string, unknown>) => {
    const pid = str(p, "pack_id", { max: 41, required: true })
    if (pid !== "all" && !PACK_RE.test(pid)) throw new InputError("pack_id is not valid")
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.REFERENCE.INSTALL_RULE_PACK(?, ?)", [pid, bool(p, "force")], { long: true })
    if (!r?.ok) throw new InputError(String(r?.message ?? "install failed"))
    const n = Array.isArray(r.installed) ? r.installed.length : 0
    const w = Array.isArray(r.waiting_for_data) ? r.waiting_for_data.length : 0
    return { message: r.message ? String(r.message) : `${n} rule(s) installed (${r.mode}), ${w} waiting for data`, result: r }
  },

  /** Sigma import (setup/41_sigma.sql): catalogue state per pack, last sync, and rules that did not make it. */
  "packs.sigma": async () => {
    const [byState, lastSync, problems] = await Promise.all([
      rows(`SELECT COALESCE(pack_id, 'unmapped') AS pack_id, state, COUNT(*) AS n
            FROM SNOWFLAKE_XDR.REFERENCE.V_SIGMA_STATUS GROUP BY 1, 2 ORDER BY 1, 3 DESC`),
      rows(`SELECT origin, started_at, result FROM SNOWFLAKE_XDR.REFERENCE.SIGMA_SYNC_RUNS
            ORDER BY started_at DESC LIMIT 1`),
      rows(`SELECT SPLIT_PART(compile_reason, ':', 1) AS reason, COUNT(*) AS n
            FROM SNOWFLAKE_XDR.REFERENCE.V_SIGMA_STATUS WHERE state = 'not_compiled'
            GROUP BY 1 ORDER BY 2 DESC LIMIT 8`),
    ])
    const sync = lastSync[0] ? { ...lastSync[0], result: parseVariant(lastSync[0].result) ?? {} } : null
    return { by_state: byState, last_sync: sync, not_compiled: problems }
  },

  "packs.sigma_sync": async () => {
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.REFERENCE.SIGMA_IMPORT('github')", [], { long: true })
    if (!r?.ok) throw new InputError(String(r?.message ?? "Sigma sync failed"))
    return { message: r.message ? String(r.message) : `${r.origin}: ${r.new} new, ${r.updated} updated, ${r.unchanged} unchanged`, result: r }
  },
}
