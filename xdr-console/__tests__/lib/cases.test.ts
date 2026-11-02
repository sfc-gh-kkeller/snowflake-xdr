import { describe, it, expect, vi, beforeEach } from "vitest"

vi.mock("../../lib/snowflake", () => ({
  querySnowflake: vi.fn(),
  querySnowflakeLongRunning: vi.fn(),
}))

import { querySnowflake, querySnowflakeLongRunning } from "../../lib/snowflake"
import { cases } from "../../lib/handlers/cases"
import { investigations } from "../../lib/handlers/investigate"
import { InputError } from "../../lib/xdr"

const ok = (message: string) => [{ R: JSON.stringify({ ok: true, message }) }]

beforeEach(() => vi.clearAllMocks())

describe("Cases handlers", () => {
  it("setState goes through the lifecycle procedure with actor and resolution as binds", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce(ok("incident contained -> closed"))
    const r = await cases["cases.setState"]({ incident_id: "i-1", state: "closed", resolution: "false_positive", reason: "test box", __actor: "KELLER" })
    const [sql, opts] = vi.mocked(querySnowflake).mock.calls[0]
    expect(sql).toBe("CALL SNOWFLAKE_XDR.INCIDENTS.SET_INCIDENT_STATE(?, ?, ?, ?, 'human', ?, NULL)")
    expect(opts).toEqual({ binds: ["i-1", "closed", "test box", "KELLER", "false_positive"] })
    expect(r.message).toMatch(/closed/)
  })

  it("rejects invalid states, resolutions and ids before touching Snowflake", async () => {
    await expect(cases["cases.setState"]({ incident_id: "i-1", state: "deleted" })).rejects.toThrow(InputError)
    await expect(cases["cases.setState"]({ incident_id: "i-1", state: "closed", resolution: "whatever" })).rejects.toThrow(InputError)
    await expect(cases["cases.comment"]({ incident_id: "x'; DROP", text: "hi" })).rejects.toThrow(InputError)
    await expect(cases["cases.comment"]({ incident_id: "i-1", text: "" })).rejects.toThrow(InputError)
    await expect(cases["tickets.mockAction"]({ ticket_key: "SEC-1'; --", state: "Done" })).rejects.toThrow(InputError)
    await expect(cases["tickets.mockAction"]({ ticket_key: "SEC-101", state: "Deleted" })).rejects.toThrow(InputError)
    expect(querySnowflake).not.toHaveBeenCalled()
  })

  it("surfaces a refused transition (closing without a resolution) as an error", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([{ R: JSON.stringify({ ok: false, message: "closing an incident needs a resolution" }) }])
    await expect(cases["cases.setState"]({ incident_id: "i-1", state: "closed" })).rejects.toThrow(/needs a resolution/)
  })

  it("a malformed actor is dropped, not passed through", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce(ok("comment added"))
    await cases["cases.comment"]({ incident_id: "i-1", text: "isolated host", __actor: "x'); DROP TABLE t; --" })
    expect((vi.mocked(querySnowflake).mock.calls[0][1] as { binds: unknown[] }).binds).toEqual(["i-1", "isolated host", null])
  })

  it("configure validates the site URL and identifiers and sends config as one JSON bind", async () => {
    await expect(cases["tickets.configure"]({ connection_id: "jira", base_url: "http://evil.example" })).rejects.toThrow(/https/)
    await expect(cases["tickets.configure"]({ connection_id: "jira", project_key: "SEC'; DROP" })).rejects.toThrow(InputError)
    vi.mocked(querySnowflakeLongRunning).mockResolvedValueOnce(ok("jira configured"))
    await cases["tickets.configure"]({ connection_id: "jira", base_url: "https://acme.atlassian.net", project_key: "SEC", enabled: true })
    const [sql, opts] = vi.mocked(querySnowflakeLongRunning).mock.calls[0]
    expect(sql).toBe("CALL SNOWFLAKE_XDR.INCIDENTS.CONFIGURE_TICKET_CONNECTION(?, ?, ?, PARSE_JSON(?))")
    const binds = (opts as { binds: unknown[] }).binds
    expect(binds.slice(0, 3)).toEqual(["jira", "https://acme.atlassian.net", true])
    expect(JSON.parse(binds[3] as string)).toEqual({ project_key: "SEC" })
  })

  it("Investigations status changes also use the lifecycle (audit + ticket sync)", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce(ok("incident open -> investigating"))
    await investigations["incidents.setStatus"]({ incident_id: "i-1", status: "investigating" })
    expect(vi.mocked(querySnowflake).mock.calls[0][0]).toContain("SET_INCIDENT_STATE")
  })
})
