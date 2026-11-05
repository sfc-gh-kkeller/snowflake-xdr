import { describe, it, expect, vi, beforeEach } from "vitest"

vi.mock("../../lib/snowflake", () => ({
  querySnowflake: vi.fn(),
  querySnowflakeLongRunning: vi.fn(),
}))

import { querySnowflake } from "../../lib/snowflake"
import { POST } from "../../app/api/xdr/[name]/route"
import { clearIdentityCache } from "../../lib/identity"

const call = (name: string, body?: string, user?: string) =>
  POST(new Request(`http://localhost/api/xdr/${name}`, {
    method: "POST", body, headers: user ? { "sf-context-current-user": user } : {},
  }), { params: Promise.resolve({ name }) })

// RESOLVE_CONSOLE_ROLE answer for a signed-in user
const role = (r: string) => [{ R: JSON.stringify({ role: r, via: "assigned" }) }]

beforeEach(() => {
  vi.clearAllMocks()
  clearIdentityCache()
})

describe("POST /api/xdr/[name]", () => {
  it("dispatches a registered handler and normalizes rows", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([{ ENTITY: "jsmith", FINDING_COUNT: "12", MAX_SEVERITY: "5" }])
    const res = await call("overview.topEntities", "{}")
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ data: [{ entity: "jsmith", finding_count: 12, max_severity: 5 }] })
  })

  it("returns 404 for unknown or prototype names", async () => {
    expect((await call("drop.everything", "{}")).status).toBe(404)
    expect((await call("constructor", "{}")).status).toBe(404)
    expect((await call("__proto__", "{}")).status).toBe(404)
    expect(querySnowflake).not.toHaveBeenCalled()
  })

  it("returns 400 for bad JSON, non-object bodies and invalid input", async () => {
    expect((await call("triage.list", "{nope")).status).toBe(400)
    expect((await call("triage.list", "[1,2]")).status).toBe(400)
    vi.mocked(querySnowflake).mockResolvedValueOnce(role("analyst"))
    const bad = await call("triage.bulk", JSON.stringify({ finding_ids: ["x';--"], action: "dismiss_false_positive" }), "ANA")
    expect(bad.status).toBe(400)
    expect((await bad.json()).error).toMatch(/not a valid id/)
    // only the role lookup ran; the bad input never reached Snowflake
    expect(querySnowflake).toHaveBeenCalledTimes(1)
  })

  it("denies writes below the required role, before the handler runs", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {})
    expect((await call("triage.bulk", JSON.stringify({ finding_ids: ["a"], action: "dismiss_false_positive" }))).status).toBe(403)
    vi.mocked(querySnowflake).mockResolvedValueOnce(role("analyst"))
    const res = await call("autopilot.setPolicy", "{}", "ANA")
    expect(res.status).toBe(403)
    expect((await res.json()).error).toMatch(/needs the admin role; you are analyst/)
    expect(querySnowflake).toHaveBeenCalledTimes(1)
    warn.mockRestore()
  })

  it("me returns the resolved identity from the ingress header", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce(role("engineer"))
    const res = await call("me", "{}", "JDOE")
    expect(res.status).toBe(200)
    expect((await res.json()).data).toMatchObject({ user: "JDOE", role: "engineer" })
  })

  it("returns 500 with the Snowflake error message on query failure", async () => {
    vi.mocked(querySnowflake).mockRejectedValueOnce(new Error("Object does not exist"))
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {})
    const res = await call("overview.kpis", "")
    expect(res.status).toBe(500)
    expect((await res.json()).error).toBe("Object does not exist")
    errSpy.mockRestore()
  })
})
