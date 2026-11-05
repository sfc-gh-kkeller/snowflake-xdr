/**
 * Console RBAC: viewer < analyst < engineer < admin.
 *
 * The signed-in Snowflake user (SPCS ingress header) is resolved to an XDR role by
 * SNOWFLAKE_XDR.DASHBOARDS.RESOLVE_CONSOLE_ROLE (explicit assignment, else mapped from
 * their Snowflake roles; unknown users are viewers). Every handler is classified
 * here; anything not listed is read-only and open to viewers.
 */

export const ROLES = ["viewer", "analyst", "engineer", "admin"] as const
export type XdrRole = (typeof ROLES)[number]
const RANK: Record<XdrRole, number> = { viewer: 0, analyst: 1, engineer: 2, admin: 3 }

/** Minimum role per write handler. */
export const REQUIRED: Record<string, XdrRole> = {
  // analysts: triage, cases, tickets, IOCs, investigations, the agent
  "triage.update": "analyst", "triage.bulk": "analyst", "triage.aiTriage": "analyst", "triage.scoreFp": "analyst",
  "triage.assessControls": "analyst", "cases.assign": "analyst", "cases.comment": "analyst", "cases.setState": "analyst",
  "cases.task": "analyst", "cases.report": "analyst", "incidents.setStatus": "analyst", "incidents.story": "analyst",
  "confidence.decide": "analyst", "confidence.sample": "analyst", "iocs.add": "analyst", "iocs.remove": "analyst", "intel.iocAction": "analyst",
  "tickets.create": "analyst", "tickets.sync": "analyst", "tickets.mockAction": "analyst", "entity.investigate": "analyst",
  "hunt.run": "analyst", "hunt.detect": "analyst", "ask.agent": "analyst", "mission.decide": "analyst",
  "mission.setAutonomy": "analyst", "overview.briefing": "analyst", "mission.briefing": "analyst",
  // engineers: detections, sources, packs, autopilot decisions, playbooks, undo
  "rules.save": "engineer", "rules.test": "engineer", "rules.generate": "engineer", "rules.runAll": "engineer",
  "detections.runAll": "engineer", "packs.install": "engineer", "packs.sigma_sync": "engineer",
  "sources.activate": "engineer", "sources.apply": "engineer", "sources.register": "engineer", "sources.retire": "engineer",
  "sources.setStatus": "engineer", "autopilot.decide": "engineer", "autopilot.pin": "engineer", "autopilot.runCycle": "engineer",
  "mission.runCanaries": "engineer", "mission.sampleReviews": "engineer", "mission.undo": "engineer",
  "response.savePlaybook": "engineer", "response.testPlaybook": "engineer", "response.evaluateAll": "engineer",
  "threat.refresh": "engineer", "threat.setProfile": "engineer", "intel.sync": "engineer", "intel.syncFeed": "engineer",
  "intel.attackNew": "engineer", "graph.rebuild": "engineer", "graph.rattleScan": "engineer", "triage.trainFp": "engineer",
  "live.emit": "engineer", "tickets.configure": "engineer", "posture.report": "engineer",
  // admins: autonomy policy
  "autopilot.setPolicy": "admin",
}

/** mission.decide routes to very different powers; the item kind sets the bar. */
const DECIDE_KIND: Record<string, XdrRole> = {
  review: "analyst", ticket: "analyst", sla: "analyst", canary: "analyst",
  change: "engineer", areview: "engineer",
  response: "admin",   // approving containment acts on real accounts and hosts
}

export function atLeast(have: XdrRole, need: XdrRole): boolean {
  return RANK[have] >= RANK[need]
}

/** The role needed to run `name` with `params`; null = open to viewers. */
export function requiredRole(name: string, params: Record<string, unknown>): XdrRole | null {
  if (name === "mission.decide") {
    const item = typeof params.item_id === "string" ? params.item_id : ""
    return DECIDE_KIND[item.slice(0, item.indexOf(":"))] ?? "admin"
  }
  if (name === "mission.setAutonomy") {
    // anyone on shift may stop the machine; restarting it or changing budgets is an admin decision
    return params.paused === true && params.daily_change_budget === undefined && params.type_budget === undefined
      ? "analyst" : "admin"
  }
  return REQUIRED[name] ?? null
}

export function isRole(v: unknown): v is XdrRole {
  return typeof v === "string" && (ROLES as readonly string[]).includes(v)
}

const TENANT_RE = /^[a-z0-9_-]{1,40}$/

/** Tenant scope injected by the API route: null = every tenant (unrestricted user). */
export function tenantsOf(p: Record<string, unknown>): string[] | null {
  const t = p.__tenants
  if (!Array.isArray(t)) return null
  const ok = t.filter((x): x is string => typeof x === "string" && TENANT_RE.test(x))
  return ok.length ? ok : ["__none__"]   // assigned but nothing valid: see nothing rather than everything
}

/** SQL predicate + binds restricting `col` (NULL = tenant 'default') to the caller's tenants. */
export function tenantClause(p: Record<string, unknown>, col: string): { sql: string; binds: string[] } | null {
  const t = tenantsOf(p)
  if (!t) return null
  return { sql: `COALESCE(${col}, 'default') IN (${t.map(() => "?").join(", ")})`, binds: t }
}
