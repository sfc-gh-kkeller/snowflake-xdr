/**
 * Detection engineering + CISO views: Detections (library, MITRE coverage,
 * health), Rules & IOCs, Response (playbooks + alert center), Posture.
 * Ported from pages 4, 10, 11, 12, 13, 14, 15 and 16.
 */

import {
  rows, one, scalar, str, optStr, int, bool, oneOf, listOf, id, placeholders,
  InputError, type Binds,
} from "@/lib/xdr"

const RULE_CATEGORIES = ["identity", "endpoint", "network", "cloud", "application", "custom"] as const
const DETECTION_TYPES = ["ttp", "anomaly", "hunting", "correlation"] as const
const LANGUAGES = ["sql", "python", "javascript"] as const
const IOC_TYPES = ["ip", "domain", "url", "hash_md5", "hash_sha256", "email", "user_agent"] as const
const THREAT_TYPES = ["malware", "phishing", "c2", "botnet", "ransomware", "apt", "credential_abuse",
  "exfiltration", "scanner"] as const
export const ACTION_TYPES = ["email", "webhook", "api_call", "create_incident", "ai_triage"] as const
const ACTION_STATUSES = ["success", "error", "suppressed_cooldown", "skipped"] as const
const MITRE_ID = /^(TA|T)\d{4}(\.\d{3})?$/

function mitre(p: Record<string, unknown>, key: string): string | null {
  const v = optStr(p, key, 16)
  if (v && !MITRE_ID.test(v)) throw new InputError(`${key} must look like TA0001 or T1110.001`)
  return v
}

// ---------------------------------------------------------------------------
// Detections: library, MITRE coverage, health
// ---------------------------------------------------------------------------

export const detections = {
  "detections.library": async (p: Record<string, unknown>) => {
    const clauses: string[] = []
    const binds: Binds = []
    const cat = oneOf(p, "category", ["all", ...RULE_CATEGORIES] as const, "all")
    if (cat !== "all") { clauses.push("r.category = ?"); binds.push(cat) }
    const type = oneOf(p, "type", ["all", ...DETECTION_TYPES] as const, "all")
    if (type !== "all") { clauses.push("r.detection_type = ?"); binds.push(type) }
    if (bool(p, "enabledOnly", true)) clauses.push("r.enabled = TRUE")
    return rows(`
      SELECT r.rule_id, r.rule_name, r.category, r.detection_type, r.severity,
             r.mitre_tactic, r.mitre_technique_id, r.mitre_technique, r.enabled,
             r.lookback_minutes, r.splunk_analytic_story,
             COUNT(f.finding_id) AS findings_total,
             COUNT(CASE WHEN f.detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP()) THEN 1 END) AS findings_7d,
             MAX(f.detection_time) AS last_fired
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES r
      LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f ON f.rule_id = r.rule_id
      ${clauses.length ? `WHERE ${clauses.join(" AND ")}` : ""}
      GROUP BY r.rule_id, r.rule_name, r.category, r.detection_type, r.severity,
               r.mitre_tactic, r.mitre_technique_id, r.mitre_technique, r.enabled,
               r.lookback_minutes, r.splunk_analytic_story
      ORDER BY r.category, r.severity DESC`, binds)
  },

  "detections.coverage": async () =>
    rows(`
      SELECT t.tactic_id, t.tactic_name, t.tactic_order,
             COUNT(DISTINCT r.rule_id) AS rule_count,
             COUNT(DISTINCT CASE WHEN r.detection_type = 'ttp' THEN r.rule_id END) AS ttp_count,
             COUNT(DISTINCT CASE WHEN r.detection_type = 'anomaly' THEN r.rule_id END) AS anomaly_count,
             COUNT(DISTINCT f.finding_id) AS findings_7d
      FROM SNOWFLAKE_XDR.REFERENCE.MITRE_TACTICS t
      LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES r
        ON r.mitre_tactic_id = t.tactic_id AND r.enabled = TRUE
      LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f
        ON f.mitre_tactic_id = t.tactic_id
       AND f.detection_time > DATEADD('day', -7, CURRENT_TIMESTAMP())
      GROUP BY t.tactic_id, t.tactic_name, t.tactic_order
      ORDER BY t.tactic_order`),

  "detections.gaps": async () =>
    rows(`
      SELECT technique_id, technique_name, tactic_name, LEFT(description, 120) AS description
      FROM SNOWFLAKE_XDR.DETECTIONS.V_MITRE_GAPS
      ORDER BY tactic_name, technique_id`),

  "detections.health": async () => {
    const [health, freshness, errors] = await Promise.all([
      rows(`
        SELECT rule_id, rule_name, category, severity, enabled,
               findings_total, findings_7d, last_fired, recent_errors
        FROM SNOWFLAKE_XDR.DETECTIONS.V_DETECTION_HEALTH
        ORDER BY recent_errors DESC, findings_7d DESC, severity DESC`),
      rows(`
        SELECT source_table, latest_event, event_count,
               DATEDIFF('hour', latest_event, CURRENT_TIMESTAMP()) AS hours_old
        FROM SNOWFLAKE_XDR.DETECTIONS.V_DATA_FRESHNESS
        ORDER BY hours_old ASC`),
      rows(`
        SELECT e.error_time, r.name AS rule_name, e.stage, LEFT(e.error_message, 160) AS error_message
        FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_ERRORS e
        LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES r ON r.rule_id = e.rule_id
        ORDER BY e.error_time DESC LIMIT 20`),
    ])
    return { health, freshness, errors }
  },

  "detections.runAll": async () => ({
    message: await scalar<string>("CALL SNOWFLAKE_XDR.DETECTIONS.RUN_ALL_DETECTIONS()", [], { long: true }),
  }),
}

// ---------------------------------------------------------------------------
// Rules (custom rule editor) + IOCs
// ---------------------------------------------------------------------------

export const rules = {
  "rules.list": async () =>
    rows(`
      SELECT rule_id, name, description, category, severity, language,
             threshold_count, threshold_window_minutes, lookback_minutes,
             enabled, created_by, version, updated_at
      FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES
      ORDER BY created_at DESC`),

  "rules.detail": async (p: Record<string, unknown>) => {
    const rid = id(p, "rule_id")
    const rule = await one(`
      SELECT rule_id, name, description, category, severity, mitre_tactic_id, mitre_technique_id,
             language, source_table, code, threshold_count, threshold_window_minutes,
             lookback_minutes, enabled, version
      FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE rule_id = ?`, [rid])
    if (!rule) throw new InputError("Rule not found")
    const [errors, history] = await Promise.all([
      rows(`
        SELECT error_time, LEFT(error_message, 160) AS error_message, stage
        FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_ERRORS
        WHERE rule_id = ? ORDER BY error_time DESC LIMIT 5`, [rid]),
      rows(`
        SELECT changed_at, version, LEFT(name, 60) AS name, language, severity, enabled, changed_by
        FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULE_HISTORY
        WHERE rule_id = ? ORDER BY changed_at DESC LIMIT 10`, [rid]),
    ])
    return { rule, errors, history }
  },

  "rules.save": async (p: Record<string, unknown>) => {
    const rid = p.rule_id ? id(p, "rule_id") : ""
    const language = oneOf(p, "language", LANGUAGES)
    const binds: Binds = [
      rid,
      str(p, "name", { max: 200, required: true }),
      str(p, "description", { max: 2000 }),
      oneOf(p, "category", RULE_CATEGORIES, "custom"),
      int(p, "severity", { min: 1, max: 5, def: 3 }),
      mitre(p, "mitre_tactic_id"),
      mitre(p, "mitre_technique_id"),
      language,
      language === "sql" ? null : optStr(p, "source_table", 64),
      str(p, "code", { max: 20000, required: true }),
      int(p, "threshold_count", { min: 1, max: 1000, def: 1 }),
      int(p, "threshold_window_minutes", { min: 1, max: 1440, def: 60 }),
      int(p, "lookback_minutes", { min: 1, max: 20160, def: 1440 }),
      bool(p, "enabled", false),
    ]
    const message = await scalar<string>(
      `CALL SNOWFLAKE_XDR.DETECTIONS.SAVE_CUSTOM_RULE(${placeholders(14)})`, binds)
    return { message: `Rule ${message}` }
  },

  "rules.generate": async (p: Record<string, unknown>) => {
    const desc = str(p, "description", { max: 2000, required: true })
    const r = await scalar<Record<string, unknown>>(
      "CALL SNOWFLAKE_XDR.DETECTIONS.AI_GENERATE_RULE(?)", [desc], { long: true })
    if (!r || typeof r !== "object" || "error" in r) {
      throw new InputError(`AI generation failed: ${JSON.stringify(r).slice(0, 300)}`)
    }
    return r
  },

  "rules.test": async (p: Record<string, unknown>) => {
    const rid = id(p, "rule_id")
    const r = await scalar<unknown>("CALL SNOWFLAKE_XDR.DETECTIONS.TEST_CUSTOM_RULE(?)", [rid], { long: true })
    const matches = Array.isArray(r) ? r
      : r && typeof r === "object" && Array.isArray((r as Record<string, unknown>).matches)
        ? (r as Record<string, unknown[]>).matches : []
    return { matches: matches.slice(0, 20), count: matches.length, raw: matches.length ? null : r }
  },

  "rules.runAll": async () => ({
    message: await scalar<string>("CALL SNOWFLAKE_XDR.DETECTIONS.RUN_CUSTOM_RULES()", [], { long: true }),
  }),

  "iocs.list": async () =>
    rows(`
      SELECT ioc_type, ioc_value, threat_type, threat_name, severity, confidence,
             source, first_seen, active
      FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
      ORDER BY active DESC, severity DESC, first_seen DESC`),

  "iocs.add": async (p: Record<string, unknown>) => {
    const type = oneOf(p, "ioc_type", IOC_TYPES)
    const threat = oneOf(p, "threat_type", THREAT_TYPES)
    const binds: Binds = [
      type,
      str(p, "ioc_value", { max: 500, required: true }),
      threat,
      str(p, "threat_name", { max: 200 }) || threat,
      int(p, "severity", { min: 1, max: 5, def: 3 }),
      str(p, "source", { max: 100 }) || "manual",
    ]
    const message = await scalar<string>("CALL SNOWFLAKE_XDR.REFERENCE.ADD_IOC(?, ?, ?, ?, ?, ?)", binds)
    return { message: `IOC ${message}` }
  },

  "iocs.remove": async (p: Record<string, unknown>) => {
    const binds: Binds = [oneOf(p, "ioc_type", IOC_TYPES), str(p, "ioc_value", { max: 500, required: true })]
    const message = await scalar<string>("CALL SNOWFLAKE_XDR.REFERENCE.REMOVE_IOC(?, ?)", binds)
    return { message: `IOC ${message}` }
  },
}

// ---------------------------------------------------------------------------
// Response: playbooks + alert center
// ---------------------------------------------------------------------------

/** Validated action_config JSON for a playbook action type. */
export function actionConfig(p: Record<string, unknown>, action: (typeof ACTION_TYPES)[number]): string {
  if (action === "email") {
    const to = str(p, "to", { max: 500 })
    if (to && !to.split(",").every((a) => /^[^\s@,]+@[^\s@,]+\.[^\s@,]+$/.test(a.trim()))) {
      throw new InputError("to must be a comma-separated list of email addresses")
    }
    return JSON.stringify({ to })
  }
  if (action === "api_call") {
    const url = str(p, "url", { max: 1000 })
    if (url && !/^https?:\/\//.test(url)) throw new InputError("url must start with http:// or https://")
    return JSON.stringify({ url, auth_header: str(p, "auth_header", { max: 1000 }) })
  }
  return "{}"
}

export const response = {
  "response.playbooks": async () =>
    rows(`
      SELECT playbook_id, name, description, trigger_severity_min, trigger_entity,
             threshold_count, threshold_window_minutes, cooldown_minutes,
             action_type, action_config, enabled
      FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOKS
      ORDER BY created_at DESC`),

  /** All 13 SAVE_PLAYBOOK parameters bound in signature order. */
  "response.savePlaybook": async (p: Record<string, unknown>) => {
    const pid = p.playbook_id ? id(p, "playbook_id") : ""
    const action = oneOf(p, "action_type", ACTION_TYPES)
    const binds: Binds = [
      pid,
      str(p, "name", { max: 200, required: true }),
      str(p, "description", { max: 1000 }),
      int(p, "trigger_severity_min", { min: 1, max: 5, def: 4 }),
      optStr(p, "trigger_entity", 128),
      int(p, "threshold_count", { min: 1, max: 100, def: 1 }),
      int(p, "threshold_window_minutes", { min: 1, max: 1440, def: 60 }),
      int(p, "cooldown_minutes", { min: 1, max: 1440, def: 60 }),
      action,
      actionConfig(p, action),
      bool(p, "enabled", true),
    ]
    const message = await scalar<string>(
      "CALL SNOWFLAKE_XDR.RESPONSE.SAVE_PLAYBOOK(?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, PARSE_JSON(?), ?)",
      binds)
    return { message: `Playbook ${message}` }
  },

  /** Fire a playbook's logic against the newest finding at its severity. */
  "response.testPlaybook": async (p: Record<string, unknown>) => {
    const sev = int(p, "severity", { min: 1, max: 5, def: 4 })
    const f = await one(`
      SELECT finding_id FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      WHERE severity >= ? ORDER BY severity DESC, detection_time DESC LIMIT 1`, [sev])
    if (!f) return { message: "No matching finding to test with." }
    const message = await scalar<string>(
      "CALL SNOWFLAKE_XDR.RESPONSE.EVALUATE_RESPONSE(?)", [String(f.finding_id)], { long: true })
    return { message }
  },

  "response.evaluateAll": async () => ({
    message: await scalar<string>("CALL SNOWFLAKE_XDR.RESPONSE.EVALUATE_ALL_NEW_FINDINGS()", [], { long: true }),
  }),

  "response.actions": async (p: Record<string, unknown>) => {
    const statuses = listOf(p, "statuses", ACTION_STATUSES)
    const types = listOf(p, "types", ACTION_TYPES)
    const clauses: string[] = []
    const binds: Binds = []
    if (statuses.length) { clauses.push(`a.status IN (${placeholders(statuses.length)})`); binds.push(...statuses) }
    if (types.length) { clauses.push(`a.action_type IN (${placeholders(types.length)})`); binds.push(...types) }
    const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : ""
    const [stats, log] = await Promise.all([
      rows(`
        SELECT a.action_type, a.status, COUNT(*) AS cnt
        FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS a ${where}
        GROUP BY 1, 2 ORDER BY 1, 2`, binds),
      rows(`
        SELECT a.executed_at, a.playbook_name, a.action_type, a.status, LEFT(a.detail, 300) AS detail,
               f.severity, COALESCE(f.user_name, f.src, f.dest) AS entity
        FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS a
        LEFT JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f ON f.finding_id = a.finding_id
        ${where}
        ORDER BY a.executed_at DESC LIMIT 200`, binds),
    ])
    return { stats, log }
  },

  "response.mitigated": async () =>
    rows(`
      SELECT finding_id, detection_time, rule_id, LEFT(description, 120) AS description,
             COALESCE(user_name, src, dest) AS entity, risk_score, LEFT(triage_notes, 200) AS triage_notes
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      WHERE disposition = 'mitigated_by_control'
      ORDER BY triaged_at DESC NULLS LAST LIMIT 25`),

  "response.controls": async () =>
    rows(`
      SELECT control_id, name, control_type, description, mitre_technique_ids,
             covered_entities, scope_note, status
      FROM SNOWFLAKE_XDR.REFERENCE.SECURITY_CONTROLS ORDER BY control_id`),
}

// ---------------------------------------------------------------------------
// Posture (CISO)
// ---------------------------------------------------------------------------

export const posture = {
  "posture.metrics": async () => one("SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.V_POSTURE_METRICS"),

  "posture.responseHealth": async () =>
    rows(`
      SELECT action_type, COUNT(*) AS executed, SUM(IFF(status = 'success', 1, 0)) AS succeeded
      FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS
      GROUP BY 1 ORDER BY 2 DESC`),

  "posture.trend": async () =>
    rows(`
      SELECT DATE_TRUNC('day', COALESCE(event_time, detection_time)) AS day,
             COUNT(*) AS findings,
             SUM(IFF(severity >= 4, 1, 0)) AS critical_high,
             SUM(IFF(disposition IN ('false_positive', 'benign', 'mitigated_by_control'), 1, 0)) AS noise_removed
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      WHERE COALESCE(event_time, detection_time) > DATEADD('day', -14, CURRENT_TIMESTAMP())
      GROUP BY 1 ORDER BY 1`),

  "posture.platform": async () =>
    one(`
      SELECT
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS) AS total_findings,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS) AS total_incidents,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.RESPONSE.PLAYBOOK_ACTIONS) AS playbook_actions,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES WHERE enabled = TRUE) AS active_custom_rules,
        (SELECT COUNT(*) FROM SNOWFLAKE_XDR.REFERENCE.SECURITY_CONTROLS WHERE status = 'active') AS active_controls`),

  "posture.report": async () => {
    const r = await scalar<{ report?: string }>(
      "CALL SNOWFLAKE_XDR.DETECTIONS.AI_EXEC_REPORT()", [], { long: true })
    return { text: r?.report ?? "" }
  },
}
