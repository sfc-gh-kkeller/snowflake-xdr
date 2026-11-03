import { describe, it, expect, vi, beforeEach } from "vitest"

vi.mock("../../lib/snowflake", () => ({
  querySnowflake: vi.fn(),
  querySnowflakeLongRunning: vi.fn(),
}))

import { querySnowflake, querySnowflakeLongRunning } from "../../lib/snowflake"
import { mission, packs } from "../../lib/handlers/mission"
import { InputError } from "../../lib/xdr"

const ok = (message: string) => [{ R: JSON.stringify({ ok: true, message }) }]

beforeEach(() => vi.clearAllMocks())

describe("Mission Control handlers", () => {
  it("pausing requires a reason and sends the actor in the JSON argument", async () => {
    await expect(mission["mission.setAutonomy"]({ paused: true })).rejects.toThrow(/why/)
    vi.mocked(querySnowflake).mockResolvedValueOnce(ok("Autonomy PAUSED"))
    await mission["mission.setAutonomy"]({ paused: true, reason: "incident bridge", __actor: "KELLER" })
    const [sql, opts] = vi.mocked(querySnowflake).mock.calls[0]
    expect(sql).toBe("CALL SNOWFLAKE_XDR.DETECTIONS.SET_AUTONOMY(?)")
    expect(JSON.parse((opts as { binds: string[] }).binds[0])).toEqual({ actor: "KELLER", reason: "incident bridge", paused: true })
  })

  it("rejects an out-of-range budget and empty updates", async () => {
    await expect(mission["mission.setAutonomy"]({ daily_change_budget: 5000 })).rejects.toThrow(InputError)
    await expect(mission["mission.setAutonomy"]({})).rejects.toThrow(/nothing to change/)
    expect(querySnowflake).not.toHaveBeenCalled()
  })

  it("undo validates the ledger id and binds it", async () => {
    await expect(mission["mission.undo"]({ ledger_id: "autopilot:x'; DROP TABLE t" })).rejects.toThrow(InputError)
    vi.mocked(querySnowflakeLongRunning).mockResolvedValueOnce(ok("rolled back"))
    await mission["mission.undo"]({ ledger_id: "suppress:DET-021|2026-11-03", __actor: "KELLER" })
    const [sql, opts] = vi.mocked(querySnowflakeLongRunning).mock.calls[0]
    expect(sql).toBe("CALL SNOWFLAKE_XDR.DASHBOARDS.UNDO_AI_ACTION(?, ?, ?)")
    expect((opts as { binds: unknown[] }).binds).toEqual(["suppress:DET-021|2026-11-03", null, "KELLER"])
  })

  it("routes decisions by item kind and only allows that kind's actions", async () => {
    vi.mocked(querySnowflakeLongRunning).mockResolvedValue(ok("done"))
    await mission["mission.decide"]({ item_id: "change:abc-1", action: "approve", __actor: "KELLER" })
    expect(vi.mocked(querySnowflakeLongRunning).mock.calls[0][0]).toBe("CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT(?, ?, ?)")
    await mission["mission.decide"]({ item_id: "review:r-1", action: "false_positive" })
    expect(vi.mocked(querySnowflakeLongRunning).mock.calls[1][0]).toBe("CALL SNOWFLAKE_XDR.DETECTIONS.REVIEW_DECIDE(?, ?, ?, ?)")
    await mission["mission.decide"]({ item_id: "response:run-1", action: "approve" })
    expect(vi.mocked(querySnowflakeLongRunning).mock.calls[2][0]).toBe("CALL SNOWFLAKE_XDR.INCIDENTS.DECIDE_RESPONSE_ACTION(?, ?, ?, ?)")
    await expect(mission["mission.decide"]({ item_id: "change:abc-1", action: "true_positive" })).rejects.toThrow(InputError)
    await expect(mission["mission.decide"]({ item_id: "review:r-1", action: "approve" })).rejects.toThrow(InputError)
    await expect(mission["mission.decide"]({ item_id: "sla:i-1", action: "approve" })).rejects.toThrow(/own page/)
    await expect(mission["mission.decide"]({ item_id: "other:1", action: "approve" })).rejects.toThrow(InputError)
  })

  it("surfaces a refused decision as an error", async () => {
    vi.mocked(querySnowflakeLongRunning).mockResolvedValueOnce([{ R: JSON.stringify({ ok: false, message: "cannot approve a change in status applied" }) }])
    await expect(mission["mission.decide"]({ item_id: "change:abc-1", action: "approve" })).rejects.toThrow(/cannot approve/)
  })

  it("ledger filters are allowlisted and bound", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([])
    await mission["mission.ledger"]({ window: "7d", who: "all", source: "parser" })
    expect((vi.mocked(querySnowflake).mock.calls[0][1] as { binds: unknown[] }).binds).toEqual([168, "all", "all", "all", "parser", "parser"])
    await expect(mission["mission.ledger"]({ window: "1y" })).rejects.toThrow(InputError)
    await expect(mission["mission.ledger"]({ source: "x' OR 1=1" })).rejects.toThrow(InputError)
  })
})

describe("Rule pack handlers", () => {
  it("validates pack ids and binds force", async () => {
    await expect(packs["packs.rules"]({ pack_id: "AWS; DROP" })).rejects.toThrow(InputError)
    vi.mocked(querySnowflakeLongRunning).mockResolvedValueOnce([{ R: JSON.stringify({ ok: true, installed: [{}], waiting_for_data: [], mode: "shadow_then_promote" }) }])
    const r = await packs["packs.install"]({ pack_id: "snowflake", force: true })
    const [sql, opts] = vi.mocked(querySnowflakeLongRunning).mock.calls[0]
    expect(sql).toBe("CALL SNOWFLAKE_XDR.REFERENCE.INSTALL_RULE_PACK(?, ?)")
    expect((opts as { binds: unknown[] }).binds).toEqual(["snowflake", true])
    expect(r.message).toMatch(/1 rule\(s\) installed/)
  })
})
