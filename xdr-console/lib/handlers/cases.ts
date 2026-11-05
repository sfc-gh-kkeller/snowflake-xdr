/**
 * Cases: native incident tracking and Jira / ServiceNow ticket sync
 * (setup/32_incident_tracking.sql, 33_ticketing.sql).
 * Every change goes through the lifecycle procedures, so it is audited in
 * INCIDENT_EVENTS and queued for linked tickets.
 */

import { rows, scalar, str, int, id, oneOf, InputError, parseVariant, type Row } from "@/lib/xdr"
import { tenantClause } from "@/lib/rbac"

const STATES = ["open", "acknowledged", "investigating", "contained", "eradicated", "recovered", "closed"] as const
const RESOLUTIONS = ["true_positive", "benign", "false_positive", "duplicate", "test"] as const
const TASK_STATUSES = ["open", "done", "cancelled"] as const
const MOCK_STATES = ["To Do", "In Progress", "Contained", "Done"] as const
const FILTERS = ["active", "all", "closed", "breached"] as const
const CONN_RE = /^[a-z0-9_-]{1,64}$/
const TICKET_RE = /^[A-Z][A-Z0-9]{0,9}-\d{1,9}$/
const ACTOR_RE = /^[A-Za-z0-9_.@$-]{1,255}$/

function actor(p: Record<string, unknown>): string | null {
  const a = typeof p.__actor === "string" ? p.__actor.trim() : ""
  return ACTOR_RE.test(a) ? a : null
}

function connectionId(p: Record<string, unknown>, required = true): string | null {
  const v = typeof p.connection_id === "string" ? p.connection_id.trim() : ""
  if (!v && !required) return null
  if (!CONN_RE.test(v)) throw new InputError("connection_id is not valid")
  return v
}

async function call(sql: string, binds: (string | number | boolean | null)[], long = false): Promise<{ message: string }> {
  const r = await scalar<Row>(sql, binds, { long })
  if (!r?.ok) throw new InputError(String(r?.message ?? "operation failed"))
  return { message: String(r.message) }
}

export const cases = {
  "cases.list": async (p: Record<string, unknown>) => {
    const filter = oneOf(p, "filter", FILTERS, "active")
    const base = {
      active: "i.status <> 'closed'",
      all: "",
      closed: "i.status = 'closed'",
      breached: "i.status <> 'closed' AND (s.ack_breached OR s.contain_breached OR s.resolve_breached)",
    }[filter]
    const tenant = tenantClause(p, "i.tenant_id")
    const conds = [base, tenant?.sql].filter(Boolean)
    const where = conds.length ? `WHERE ${conds.join(" AND ")}` : ""
    const list = await rows(`
      SELECT i.incident_id, i.title, i.priority, i.severity, i.status, i.assignee, i.resolution, i.created_at,
             i.updated_at, i.last_seen, s.next_milestone, s.next_due_at,
             (s.ack_breached OR s.contain_breached OR s.resolve_breached) AND i.status <> 'closed' AS breached,
             (SELECT COUNT(*) FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TASKS t
               WHERE t.incident_id = i.incident_id AND t.status = 'open') AS open_tasks,
             (SELECT ARRAY_AGG(OBJECT_CONSTRUCT('connection_id', k.connection_id, 'key', k.external_key, 'url', k.url,
                                                'state', k.remote_state, 'sync_status', k.sync_status))
                FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS k WHERE k.incident_id = i.incident_id) AS tickets
      FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENTS i
      LEFT JOIN SNOWFLAKE_XDR.INCIDENTS.V_INCIDENT_SLA s ON s.incident_id = i.incident_id
      ${where}
      ORDER BY IFF(i.status = 'closed', 1, 0), i.priority, s.next_due_at NULLS LAST
      LIMIT 300`, tenant?.binds ?? [])
    return list.map((r) => ({ ...r, tickets: parseVariant(r.tickets) ?? [] }))
  },

  "cases.detail": async (p: Record<string, unknown>) => {
    const iid = id(p, "incident_id")
    const t = await scalar<Row>("CALL SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TIMELINE(?)", [iid])
    if (!t || t.error) throw new InputError(String(t?.error ?? "incident not found"))
    const sla = await rows("SELECT * FROM SNOWFLAKE_XDR.INCIDENTS.V_INCIDENT_SLA WHERE incident_id = ?", [iid])
    const reports = await rows(`
      SELECT report_id, created_at, created_by, title, model FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_REPORTS
      WHERE incident_id = ? ORDER BY created_at DESC LIMIT 10`, [iid])
    return { ...t, sla: sla[0] ?? null, reports }
  },

  "cases.setState": async (p: Record<string, unknown>) => {
    const iid = id(p, "incident_id")
    const state = oneOf(p, "state", STATES)
    const resolution = p.resolution ? oneOf(p, "resolution", RESOLUTIONS) : null
    return call("CALL SNOWFLAKE_XDR.INCIDENTS.SET_INCIDENT_STATE(?, ?, ?, ?, 'human', ?, NULL)",
      [iid, state, str(p, "reason", { max: 1000 }) || null, actor(p), resolution])
  },

  "cases.assign": async (p: Record<string, unknown>) => {
    const iid = id(p, "incident_id")
    const assignee = str(p, "assignee", { max: 255 })
    return call("CALL SNOWFLAKE_XDR.INCIDENTS.ASSIGN_INCIDENT(?, ?, ?, 'human', NULL)", [iid, assignee || null, actor(p)])
  },

  "cases.comment": async (p: Record<string, unknown>) => {
    const iid = id(p, "incident_id")
    const text = str(p, "text", { max: 8000, required: true })
    return call("CALL SNOWFLAKE_XDR.INCIDENTS.ADD_INCIDENT_COMMENT(?, ?, ?, 'human', NULL)", [iid, text, actor(p)])
  },

  "cases.task": async (p: Record<string, unknown>) => {
    const iid = id(p, "incident_id")
    const taskId = p.task_id ? id(p, "task_id") : null
    const status = oneOf(p, "status", TASK_STATUSES, "open")
    return call("CALL SNOWFLAKE_XDR.INCIDENTS.UPSERT_INCIDENT_TASK(?, ?, ?, ?, ?, ?, ?)", [
      iid, taskId, str(p, "title", { max: 500 }) || null, str(p, "owner", { max: 255 }) || null,
      p.due_hours === undefined || p.due_hours === "" ? null : int(p, "due_hours", { min: 1, max: 720, def: 24 }),
      status, actor(p),
    ])
  },

  "cases.report": async (p: Record<string, unknown>) => {
    const iid = id(p, "incident_id")
    const r = await call("CALL SNOWFLAKE_XDR.INCIDENTS.GENERATE_INCIDENT_REPORT(?, ?)", [iid, actor(p)], true)
    return r
  },

  "cases.reportBody": async (p: Record<string, unknown>) => {
    const rid = id(p, "report_id")
    const r = await rows("SELECT title, markdown, created_at FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_REPORTS WHERE report_id = ?", [rid])
    if (!r.length) throw new InputError("report not found")
    return r[0]
  },

  "cases.metrics": async () =>
    rows("SELECT * FROM SNOWFLAKE_XDR.INCIDENTS.V_INCIDENT_METRICS ORDER BY priority"),

  // ----------------------------------------------------------------- tickets
  "tickets.status": async () => scalar<Row>("CALL SNOWFLAKE_XDR.INCIDENTS.TICKETING_STATUS()"),

  "tickets.create": async (p: Record<string, unknown>) => {
    const iid = id(p, "incident_id")
    const r = await call("CALL SNOWFLAKE_XDR.INCIDENTS.CREATE_TICKET(?, ?, ?)", [iid, connectionId(p, false), actor(p)])
    // create right away so the analyst sees the key; the task would pick it up within minutes anyway
    await scalar("CALL SNOWFLAKE_XDR.INCIDENTS.SYNC_TICKETS('push')", [], { long: true })
    return r
  },

  "tickets.sync": async () => {
    const r = await scalar<Row>("CALL SNOWFLAKE_XDR.INCIDENTS.SYNC_TICKETS('all')", [], { long: true })
    const push = (r?.push ?? {}) as Row
    const apply = (r?.apply ?? {}) as Row
    const route = (r?.route ?? {}) as Row
    return {
      message: `Sync done: ${route.tickets_requested ?? 0} new tickets, ${push.pushed ?? 0} updates sent` +
        `${push.failed ? `, ${push.failed} failed` : ""}, ${apply.applied ?? 0} ticket changes applied.`,
    }
  },

  "tickets.outbox": async () =>
    rows(`
      SELECT o.op_id, o.incident_id, o.connection_id, o.op, o.status, o.attempts, o.last_error, o.created_at, o.done_at,
             t.external_key
      FROM SNOWFLAKE_XDR.INCIDENTS.INCIDENT_OUTBOX o
      LEFT JOIN SNOWFLAKE_XDR.INCIDENTS.INCIDENT_TICKETS t ON t.incident_id = o.incident_id AND t.connection_id = o.connection_id
      ORDER BY o.created_at DESC LIMIT 100`),

  "tickets.inbox": async () =>
    rows(`
      SELECT inbox_id, connection_id, external_key, kind, LEFT(value, 300) AS value, remote_actor, via, received_at, status, result
      FROM SNOWFLAKE_XDR.INCIDENTS.TICKET_INBOX ORDER BY received_at DESC LIMIT 100`),

  "tickets.connections": async () => {
    const list = await rows(`
      SELECT connection_id, system, name, base_url, enabled, auto_create, min_priority, config, last_poll_at, last_poll_status
      FROM SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS ORDER BY IFF(system = 'mock', 1, 0), connection_id`)
    return list.map((r) => ({ ...r, config: parseVariant(r.config) }))
  },

  "tickets.configure": async (p: Record<string, unknown>) => {
    const cid = connectionId(p)!
    const base = str(p, "base_url", { max: 500 })
    if (base && !/^https:\/\/[a-z0-9.-]+\/?$/i.test(base)) throw new InputError("base_url must be https://<host>")
    const enabled = typeof p.enabled === "boolean" ? p.enabled : null
    const cfg: Record<string, unknown> = {}
    for (const k of ["project_key", "issue_type", "assignment_group", "table"] as const) {
      const v = str(p, k, { max: 100 })
      if (v) {
        if (!/^[A-Za-z0-9 _.-]+$/.test(v)) throw new InputError(`${k} has invalid characters`)
        cfg[k] = v
      }
    }
    if (typeof p.include_raw_evidence === "boolean") cfg.include_raw_evidence = p.include_raw_evidence
    const r = await call("CALL SNOWFLAKE_XDR.INCIDENTS.CONFIGURE_TICKET_CONNECTION(?, ?, ?, PARSE_JSON(?))",
      [cid, base || null, enabled, JSON.stringify(cfg)], true)
    if (p.min_priority !== undefined || typeof p.auto_create === "boolean") {
      const prio = p.min_priority ? oneOf(p, "min_priority", ["P1", "P2", "P3", "P4", "P5"] as const) : null
      const auto = typeof p.auto_create === "boolean" ? p.auto_create : null
      await rows(`
        UPDATE SNOWFLAKE_XDR.INCIDENTS.TICKET_CONNECTIONS
        SET min_priority = COALESCE(?, min_priority), auto_create = COALESCE(?, auto_create), updated_at = CURRENT_TIMESTAMP()
        WHERE connection_id = ?`, [prio, auto, cid])
    }
    return r
  },

  // ------------------------------------------------- demo tracker (mock)
  "tickets.mockList": async () => {
    const list = await rows(`
      SELECT ticket_key, xdr_reference, summary, priority, state, assignee, comments, attachments, updated_at, updated_by
      FROM SNOWFLAKE_XDR.INCIDENTS.MOCK_TICKETS ORDER BY updated_at DESC LIMIT 100`)
    return list.map((r) => ({ ...r, comments: parseVariant(r.comments) ?? [], attachments: parseVariant(r.attachments) ?? [] }))
  },

  /** Plays the analyst working in the ticket system; the next poll brings the change into the XDR. */
  "tickets.mockAction": async (p: Record<string, unknown>) => {
    const key = str(p, "ticket_key", { max: 30, required: true })
    if (!TICKET_RE.test(key)) throw new InputError("ticket_key is not valid")
    const state = p.state ? oneOf(p, "state", MOCK_STATES) : null
    const who = str(p, "as", { max: 100 }) || "jira.analyst"
    if (!ACTOR_RE.test(who)) throw new InputError("as is not valid")
    const r = await call("CALL SNOWFLAKE_XDR.INCIDENTS.MOCK_TICKET_ACTION(?, ?, ?, ?, ?)",
      [key, state, str(p, "assignee", { max: 255 }) || null, str(p, "comment", { max: 4000 }) || null, who])
    await scalar("CALL SNOWFLAKE_XDR.INCIDENTS.SYNC_TICKETS('poll')", [], { long: true })
    return { message: `${r.message}; XDR synced.` }
  },
}
