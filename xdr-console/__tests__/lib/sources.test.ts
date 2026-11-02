import { describe, it, expect, vi, beforeEach } from "vitest"

vi.mock("../../lib/snowflake", () => ({
  querySnowflake: vi.fn(),
  querySnowflakeLongRunning: vi.fn(),
}))

import { querySnowflake, querySnowflakeLongRunning } from "../../lib/snowflake"
import { sources } from "../../lib/handlers/sources"
import { InputError } from "../../lib/xdr"

beforeEach(() => vi.clearAllMocks())

describe("Data source handlers", () => {
  it("register binds id, name and kind and returns the one-time token", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([{ R: JSON.stringify({ ok: true, source_id: "paloalto_fw", token: "xdr_abc" }) }])
    const r = await sources["sources.register"]({ source_id: "PaloAlto_FW", name: "Edge firewalls", kind: "firewall" })
    const [sql, opts] = vi.mocked(querySnowflake).mock.calls[0]
    expect(sql).toBe("CALL SNOWFLAKE_XDR.REFERENCE.REGISTER_OTEL_SOURCE(?, ?, ?)")
    expect(opts).toEqual({ binds: ["paloalto_fw", "Edge firewalls", "firewall"] })
    expect(r.token).toBe("xdr_abc")
  })

  it("rejects malformed source ids and kinds before touching Snowflake", async () => {
    await expect(sources["sources.register"]({ source_id: "x'; DROP TABLE t; --" })).rejects.toThrow(InputError)
    await expect(sources["sources.register"]({ source_id: "ok", kind: "mainframe" })).rejects.toThrow(InputError)
    await expect(sources["sources.samples"]({ source_id: "a b" })).rejects.toThrow(InputError)
    await expect(sources["sources.setStatus"]({ source_id: "okta", action: "delete" })).rejects.toThrow(InputError)
    expect(querySnowflake).not.toHaveBeenCalled()
  })

  it("source ids with dots and dashes are accepted and bound", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([])
    await sources["sources.samples"]({ source_id: "acme-vpn.eu" })
    expect(vi.mocked(querySnowflake).mock.calls[0][1]).toEqual({ binds: ["acme-vpn.eu"] })
  })

  it("activate validates the id, surfaces a failed validation, and maps on success", async () => {
    await expect(sources["sources.activate"]({ mapping_id: "1; DROP" })).rejects.toThrow(InputError)
    vi.mocked(querySnowflakeLongRunning).mockResolvedValueOnce([{ R: JSON.stringify({ ok: false, message: "validation failed: no rows" }) }])
    await expect(sources["sources.activate"]({ mapping_id: "m-1" })).rejects.toThrow(/validation failed/)

    vi.mocked(querySnowflakeLongRunning)
      .mockResolvedValueOnce([{ R: JSON.stringify({ ok: true, message: "mapping live for edge-fw -> NETWORK_TRAFFIC" }) }])
      .mockResolvedValueOnce([{ R: JSON.stringify({ "edge-fw->NETWORK_TRAFFIC": 10, "okta->AUTHENTICATION": 0 }) }])
    const r = await sources["sources.activate"]({ mapping_id: "m-1", backfill: false })
    expect(vi.mocked(querySnowflakeLongRunning).mock.calls[1][1]).toMatchObject({ binds: ["m-1", false] })
    expect(r.message).toMatch(/10 records mapped/)
  })

  it("retire passes the delete flag as a bind", async () => {
    vi.mocked(querySnowflakeLongRunning).mockResolvedValueOnce([{ R: JSON.stringify({ ok: true, message: "mapping retired; 5 mapped rows removed" }) }])
    const r = await sources["sources.retire"]({ mapping_id: "m-2", delete_rows: true })
    expect(vi.mocked(querySnowflakeLongRunning).mock.calls[0][1]).toMatchObject({ binds: ["m-2", true] })
    expect(r.message).toMatch(/5 mapped rows removed/)
  })

  it("status reports no endpoint when the receiver service is absent", async () => {
    vi.mocked(querySnowflake)
      .mockResolvedValueOnce([{ RECORDS_24H: 3 }])
      .mockResolvedValueOnce([{ LIVE_MAPPINGS: 2 }])
      .mockRejectedValueOnce(new Error("Service does not exist"))
    const r = await sources["sources.status"]({})
    expect(r.endpoint).toBeNull()
  })
})
