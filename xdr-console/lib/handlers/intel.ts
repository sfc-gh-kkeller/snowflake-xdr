/**
 * Threat intelligence and confidence (setup/28_threat_intel.sql, 29_confidence.sql):
 * feed health, IOC lifecycle, ATT&CK / KEV / Sigma catalogs, the spot-check
 * review queue, and calibration of the confidence model.
 */

import { rows, scalar, str, oneOf, id, InputError, parseVariant, type Row } from "@/lib/xdr"

const IOC_STATUSES = ["all", "active", "low_confidence", "warninglisted", "allowlisted", "expired", "revoked"] as const
const IOC_ACTIONS = ["pin", "unpin", "revoke", "restore", "allowlist"] as const
const VERDICTS = ["true_positive", "false_positive", "benign"] as const
const FEEDS = ["all", "feodo", "threatfox", "urlhaus", "misp_warninglists", "mitre_attack", "cisa_kev", "sigma"] as const
const ACTOR_RE = /^[A-Za-z0-9_.@$-]{1,255}$/

function actor(p: Record<string, unknown>): string | null {
  const a = typeof p.__actor === "string" ? p.__actor.trim() : ""
  return ACTOR_RE.test(a) ? a : null
}

export const intel = {
  "intel.status": async () => scalar<Row>("CALL SNOWFLAKE_XDR.REFERENCE.INTEL_STATUS(7)"),

  "intel.feeds": async () =>
    rows(`
      SELECT feed_id, name, kind, reliability, enabled, last_run_at, last_status, last_count, last_new, last_error
      FROM SNOWFLAKE_XDR.REFERENCE.INTEL_FEEDS ORDER BY kind, feed_id`),

  /** Feed pulls take up to a minute: run the task so the request returns at once. */
  "intel.sync": async () => {
    await scalar("EXECUTE TASK SNOWFLAKE_XDR.REFERENCE.TASK_SYNC_THREAT_INTEL")
    return { message: "Threat intel sync started. Feeds refresh within about a minute." }
  },

  "intel.syncFeed": async (p: Record<string, unknown>) => {
    const feed = oneOf(p, "feed", FEEDS)
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.REFERENCE.SYNC_THREAT_INTEL(?)", [feed], { long: true })
    const f = (r?.[feed] ?? {}) as Row
    return { message: `${feed}: ${f.status ?? "done"}${f.fetched !== undefined ? `, ${f.fetched} items, ${f.new} new` : ""}` }
  },

  "intel.iocs": async (p: Record<string, unknown>) => {
    const status = oneOf(p, "status", IOC_STATUSES, "all")
    const search = str(p, "search", { max: 200 }).toLowerCase()
    const clauses: string[] = []
    const binds: (string | number)[] = []
    if (status !== "all") { clauses.push("status = ?"); binds.push(status) }
    if (search) { clauses.push("LOWER(ioc_value) LIKE ?"); binds.push(`%${search.replace(/[\\%_]/g, (c) => `\\${c}`)}%`) }
    const list = await rows(`
      SELECT ioc_type, ioc_value, threat_type, threat_name, severity, confidence, base_confidence, sources,
             sightings, status, status_reason, confidence_factors, pinned, first_seen, last_seen, expires_at
      FROM SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS
      ${clauses.length ? `WHERE ${clauses.join(" AND ")}` : ""}
      ORDER BY IFF(status = 'active', 0, 1), confidence DESC, last_seen DESC
      LIMIT 300`, binds)
    return list.map((r) => ({ ...r, sources: parseVariant(r.sources), confidence_factors: parseVariant(r.confidence_factors) }))
  },

  /** Analyst control over an indicator: pin (never decays / never neutralised), revoke, restore, allowlist. */
  "intel.iocAction": async (p: Record<string, unknown>) => {
    const action = oneOf(p, "action", IOC_ACTIONS)
    const type = oneOf(p, "ioc_type", ["ip", "domain", "url", "hash_md5", "hash_sha256", "email", "user_agent"] as const)
    const value = str(p, "ioc_value", { max: 1000, required: true })
    const who = actor(p) ?? "console"
    if (action === "allowlist") {
      await rows(`
        INSERT INTO SNOWFLAKE_XDR.REFERENCE.INTEL_WARNINGLIST (list_name, entry_type, value, ip_start, ip_end, reason, added_by)
        SELECT 'local', IFF(? = 'ip', 'cidr', IFF(? IN ('domain', 'url'), 'hostname', 'string')), LOWER(?),
               IFF(? = 'ip', TRY_CAST(PARSE_IP(? || '/32', 'INET', 1):ipv4_range_start::VARCHAR AS NUMBER), NULL),
               IFF(? = 'ip', TRY_CAST(PARSE_IP(? || '/32', 'INET', 1):ipv4_range_end::VARCHAR AS NUMBER), NULL),
               'allowlisted in the console', ?`, [type, type, value, type, value, type, value, who])
    }
    const set = {
      pin: "pinned = TRUE, status = IFF(status IN ('revoked', 'allowlisted'), status, 'active')",
      unpin: "pinned = FALSE",
      revoke: "status = 'revoked', active = FALSE, status_reason = 'revoked by ' || ?",
      restore: "status = 'active', status_reason = NULL",
      allowlist: "status = 'allowlisted', active = FALSE, status_reason = 'allowlisted by ' || ?",
    }[action]
    const binds = action === "revoke" || action === "allowlist" ? [who, type, value] : [type, value]
    await rows(`
      UPDATE SNOWFLAKE_XDR.REFERENCE.THREAT_INTEL_IOCS SET ${set}, updated_at = CURRENT_TIMESTAMP()
      WHERE ioc_type = ? AND LOWER(ioc_value) = LOWER(?)`, binds)
    await scalar("CALL SNOWFLAKE_XDR.REFERENCE.SCORE_IOCS()")
    return { message: `${value}: ${action} applied, indicators rescored` }
  },

  "intel.kev": async () =>
    rows(`
      SELECT cve_id, vendor, product, name, date_added, due_date, ransomware, short_description
      FROM SNOWFLAKE_XDR.REFERENCE.KEV_CATALOG ORDER BY date_added DESC LIMIT 100`),

  "intel.attackNew": async () =>
    rows(`
      SELECT technique_id, name, change_kind, attack_modified, url
      FROM SNOWFLAKE_XDR.REFERENCE.ATTACK_CATALOG
      WHERE change_kind IN ('new', 'updated') ORDER BY attack_modified DESC NULLS LAST LIMIT 100`),

  "intel.sigmaCoverage": async () =>
    rows(`
      SELECT b.technique_id, b.technique_name, b.origin, b.priority, ARRAY_SIZE(b.sigma_refs) AS sigma_rules,
             IFF(EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_RULES r
                          WHERE r.enabled AND r.mitre_technique_id = b.technique_id)
                 OR EXISTS (SELECT 1 FROM SNOWFLAKE_XDR.DETECTIONS.CUSTOM_RULES c
                          WHERE (c.enabled OR c.test_mode) AND c.mitre_technique_id = b.technique_id), TRUE, FALSE) AS covered
      FROM SNOWFLAKE_XDR.REFERENCE.AUTOPILOT_TECHNIQUE_BACKLOG b
      ORDER BY covered, b.priority, b.technique_id LIMIT 200`),

  // ------------------------------------------------------------- confidence
  "confidence.status": async () => scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.CONFIDENCE_STATUS()"),

  "confidence.reviews": async () =>
    rows(`
      SELECT q.review_id, q.finding_id, q.rule_id, q.entity, q.reason, q.suppressed_by, q.conf_score, q.conf_band,
             q.sampled_at, f.severity, f.description, f.event_time, LEFT(f.triage_notes, 300) AS triage_notes,
             f.conf_factors
      FROM SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE q
      JOIN SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS f ON f.finding_id = q.finding_id
      WHERE q.status = 'open'
      ORDER BY f.severity DESC, q.sampled_at
      LIMIT 100`).then((list) => list.map((r) => ({ ...r, conf_factors: parseVariant(r.conf_factors) }))),

  "confidence.reviewHistory": async () =>
    rows(`
      SELECT review_id, rule_id, entity, suppressed_by, verdict, reviewed_by, reviewed_at, note, outcome
      FROM SNOWFLAKE_XDR.DETECTIONS.REVIEW_QUEUE WHERE status = 'done' ORDER BY reviewed_at DESC LIMIT 50`),

  "confidence.decide": async (p: Record<string, unknown>) => {
    const rid = id(p, "review_id")
    const verdict = oneOf(p, "verdict", VERDICTS)
    const note = str(p, "note", { max: 1000 })
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.DETECTIONS.REVIEW_DECIDE(?, ?, ?, ?)",
      [rid, verdict, note || null, actor(p)], { long: true })
    if (!r?.ok) throw new InputError(String(r?.message ?? "review failed"))
    return { message: String(r.message) }
  },

  "confidence.sample": async () => ({
    message: await scalar<string>("CALL SNOWFLAKE_XDR.DETECTIONS.SAMPLE_REVIEWS()", [], { long: true }),
  }),

  "confidence.rulePrecision": async () =>
    rows(`
      SELECT rule_id, name, kind, severity, tp, fp, benign, judged, ROUND(prior, 2) AS prior, ROUND(precision, 2) AS precision
      FROM SNOWFLAKE_XDR.DETECTIONS.V_RULE_PRECISION
      WHERE judged > 0 OR kind <> 'built_in'
      ORDER BY judged DESC, precision LIMIT 100`),
}
