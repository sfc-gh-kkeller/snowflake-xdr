import { describe, expect, it, vi, beforeEach } from "vitest"

vi.mock("../../lib/snowflake", () => ({ querySnowflake: vi.fn(), querySnowflakeLongRunning: vi.fn() }))

import { handlers } from "@/lib/handlers"
import { REQUIRED, atLeast, requiredRole, tenantClause } from "@/lib/rbac"
import { resolveIdentity, clearIdentityCache } from "@/lib/identity"
import { querySnowflake } from "@/lib/snowflake"

// Names that change state. A handler matching this must be classified in REQUIRED,
// so a new write handler can never ship open to viewers by accident.
const WRITE_VERB = /\.(add|apply|activate|assign|bulk|comment|configure|create|decide|detect|emit|evaluate|generate|install|investigate|mock|pin|rebuild|register|remove|report|retire|run|sample|save|scan|score|set|story|sync|task|test|train|undo|update|assess|aiTriage|refresh|attack|rattleScan|iocAction|agent|briefing)/i
// Reviewed: these match the verb pattern but only read
const KNOWN_READS = new Set(["sources.samples", "cases.reportBody", "tickets.mockList", "mission.scorecard"])

describe("rbac policy", () => {
  it("classifies every write handler", () => {
    const unclassified = Object.keys(handlers).filter((n) => WRITE_VERB.test(n) && !(n in REQUIRED) && !KNOWN_READS.has(n))
    expect(unclassified).toEqual([])
  })

  it("only classifies handlers that exist", () => {
    expect(Object.keys(REQUIRED).filter((n) => !(n in handlers))).toEqual([])
  })

  it("orders roles", () => {
    expect(atLeast("admin", "engineer")).toBe(true)
    expect(atLeast("analyst", "engineer")).toBe(false)
    expect(atLeast("viewer", "viewer")).toBe(true)
  })

  it("reads are open to viewers", () => {
    expect(requiredRole("overview.kpis", {})).toBeNull()
    expect(requiredRole("triage.list", {})).toBeNull()
  })

  it("mission.decide is gated by item kind; unknown kinds need admin", () => {
    expect(requiredRole("mission.decide", { item_id: "review:x" })).toBe("analyst")
    expect(requiredRole("mission.decide", { item_id: "change:x" })).toBe("engineer")
    expect(requiredRole("mission.decide", { item_id: "response:x" })).toBe("admin")
    expect(requiredRole("mission.decide", { item_id: "weird:x" })).toBe("admin")
  })

  it("anyone on shift can pause; resuming or budgets need admin", () => {
    expect(requiredRole("mission.setAutonomy", { paused: true, reason: "x" })).toBe("analyst")
    expect(requiredRole("mission.setAutonomy", { paused: false })).toBe("admin")
    expect(requiredRole("mission.setAutonomy", { paused: true, daily_change_budget: 500 })).toBe("admin")
  })

  it("tenant scope: unrestricted, restricted, and junk fails closed", () => {
    expect(tenantClause({ __tenants: null }, "f.tenant_id")).toBeNull()
    expect(tenantClause({ __tenants: ["acme", "globex"] }, "f.tenant_id"))
      .toEqual({ sql: "COALESCE(f.tenant_id, 'default') IN (?, ?)", binds: ["acme", "globex"] })
    // an assignment with nothing valid in it must not widen to everything
    expect(tenantClause({ __tenants: ["'; DROP"] }, "i.tenant_id")?.binds).toEqual(["__none__"])
  })
})

describe("identity resolution", () => {
  beforeEach(() => {
    clearIdentityCache()
    vi.mocked(querySnowflake).mockReset()
    delete process.env.XDR_LOCAL_ROLE
  })

  it("binds the user and caches the answer", async () => {
    vi.mocked(querySnowflake).mockResolvedValue([{ R: JSON.stringify({ role: "engineer", via: "assigned" }) }])
    const a = await resolveIdentity("JDOE")
    const b = await resolveIdentity("JDOE")
    expect(a.role).toBe("engineer")
    expect(b.role).toBe("engineer")
    expect(vi.mocked(querySnowflake)).toHaveBeenCalledTimes(1)
    const [sql, opts] = vi.mocked(querySnowflake).mock.calls[0]
    expect(sql).toBe("CALL SNOWFLAKE_XDR.DASHBOARDS.RESOLVE_CONSOLE_ROLE(?)")
    expect((opts as { binds: unknown[] }).binds).toEqual(["JDOE"])
  })

  it("fails closed to viewer when the lookup fails or returns junk", async () => {
    vi.mocked(querySnowflake).mockRejectedValueOnce(new Error("boom"))
    expect((await resolveIdentity("A")).role).toBe("viewer")
    vi.mocked(querySnowflake).mockResolvedValueOnce([{ R: JSON.stringify({ role: "root" }) }])
    expect((await resolveIdentity("B")).role).toBe("viewer")
  })

  it("no ingress identity is a viewer unless a dev role is set", async () => {
    expect((await resolveIdentity("")).role).toBe("viewer")
    process.env.XDR_LOCAL_ROLE = "admin"
    expect((await resolveIdentity("")).role).toBe("admin")
  })
})
