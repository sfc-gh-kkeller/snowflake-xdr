import { describe, it, expect, vi, beforeEach } from "vitest"

vi.mock("../../lib/snowflake", () => ({
  querySnowflake: vi.fn(),
  querySnowflakeLongRunning: vi.fn(),
}))

import { querySnowflake, querySnowflakeLongRunning } from "../../lib/snowflake"
import { autopilot } from "../../lib/handlers/autopilot"
import { InputError } from "../../lib/xdr"

beforeEach(() => vi.clearAllMocks())

describe("Detection Autopilot handlers", () => {
  it("decide binds command, id and a JSON note carrying the console user", async () => {
    vi.mocked(querySnowflakeLongRunning).mockResolvedValueOnce([{ R: JSON.stringify({ ok: true, message: "approved: rule enabled" }) }])
    const r = await autopilot["autopilot.decide"]({ change_id: "c-1", action: "approve", note: "looks good", __actor: "KELLER" })
    expect(r).toEqual({ message: "approved: rule enabled" })
    const [sql, opts] = vi.mocked(querySnowflakeLongRunning).mock.calls[0]
    expect(sql).toBe("CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT(?, ?, ?)")
    const binds = (opts as { binds: string[] }).binds
    expect(binds.slice(0, 2)).toEqual(["decide:approve", "c-1"])
    expect(JSON.parse(binds[2])).toEqual({ note: "looks good", actor: "KELLER" })
  })

  it("drops a malformed actor instead of passing it through", async () => {
    vi.mocked(querySnowflakeLongRunning).mockResolvedValueOnce([{ R: JSON.stringify({ ok: true, message: "ok" }) }])
    await autopilot["autopilot.decide"]({ change_id: "c-1", action: "reject", __actor: "x'); DROP TABLE t; --" })
    const binds = (vi.mocked(querySnowflakeLongRunning).mock.calls[0][1] as { binds: string[] }).binds
    expect(JSON.parse(binds[2]).actor).toBeNull()
  })

  it("decide rejects unknown actions and bad ids before touching Snowflake", async () => {
    await expect(autopilot["autopilot.decide"]({ change_id: "c-1", action: "delete" })).rejects.toThrow(InputError)
    await expect(autopilot["autopilot.decide"]({ change_id: "x'; DROP", action: "approve" })).rejects.toThrow(InputError)
    expect(querySnowflakeLongRunning).not.toHaveBeenCalled()
  })

  it("decide surfaces a refused transition as an error", async () => {
    vi.mocked(querySnowflakeLongRunning).mockResolvedValueOnce([{ R: JSON.stringify({ ok: false, message: "cannot reject a change in status promoted" }) }])
    await expect(autopilot["autopilot.decide"]({ change_id: "c-1", action: "reject" })).rejects.toThrow(/cannot reject/)
  })

  it("setPolicy validates mode and bounds and sends JSON as one bind", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([{ R: JSON.stringify({ ok: true, message: "policy for new_rule updated" }) }])
    await autopilot["autopilot.setPolicy"]({ change_type: "new_rule", mode: "propose_only", max_per_cycle: 1, min_recall: 0.7, __actor: "KELLER" })
    const [sql, opts] = vi.mocked(querySnowflake).mock.calls[0]
    expect(sql).toBe("CALL SNOWFLAKE_XDR.DETECTIONS.AUTOPILOT('set_policy', ?, NULL)")
    expect(JSON.parse((opts as { binds: string[] }).binds[0])).toEqual({
      change_type: "new_rule", actor: "KELLER", mode: "propose_only", max_per_cycle: 1, min_recall: 0.7,
    })
    await expect(autopilot["autopilot.setPolicy"]({ change_type: "new_rule", mode: "yolo" })).rejects.toThrow(InputError)
    await expect(autopilot["autopilot.setPolicy"]({ change_type: "drop_tables", mode: "off" })).rejects.toThrow(InputError)
    await expect(autopilot["autopilot.setPolicy"]({ change_type: "new_rule", min_recall: 2 })).rejects.toThrow(/min_recall/)
  })

  it("changes filter binds the status and never interpolates it", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([])
    await autopilot["autopilot.changes"]({ status: "shadow" })
    const [sql, opts] = vi.mocked(querySnowflake).mock.calls[0]
    expect(sql).toContain("WHERE status = ?")
    expect(opts).toEqual({ binds: ["shadow"] })
    await expect(autopilot["autopilot.changes"]({ status: "shadow' OR 1=1" })).rejects.toThrow(InputError)
  })

  it("runCycle starts the task instead of running a long call inline", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([])
    const r = await autopilot["autopilot.runCycle"]({})
    expect(vi.mocked(querySnowflake).mock.calls[0][0]).toBe("EXECUTE TASK SNOWFLAKE_XDR.DETECTIONS.TASK_AUTOPILOT")
    expect(r.message).toMatch(/started/)
  })
})

import { intel } from "../../lib/handlers/intel"
import { triage } from "../../lib/handlers/triage"

describe("Threat intel and confidence handlers", () => {
  it("spot-check verdicts are validated and bound with the console user", async () => {
    vi.mocked(querySnowflakeLongRunning).mockResolvedValueOnce([{ R: JSON.stringify({ ok: true, message: "Suppression confirmed" }) }])
    await intel["confidence.decide"]({ review_id: "r-1", verdict: "false_positive", note: "scan", __actor: "KELLER" })
    const [sql, opts] = vi.mocked(querySnowflakeLongRunning).mock.calls[0]
    expect(sql).toBe("CALL SNOWFLAKE_XDR.DETECTIONS.REVIEW_DECIDE(?, ?, ?, ?)")
    expect(opts).toMatchObject({ binds: ["r-1", "false_positive", "scan", "KELLER"] })
    await expect(intel["confidence.decide"]({ review_id: "r-1", verdict: "delete" })).rejects.toThrow(InputError)
  })

  it("IOC actions bind the indicator and reject unknown actions", async () => {
    vi.mocked(querySnowflake).mockResolvedValue([])
    await intel["intel.iocAction"]({ action: "revoke", ioc_type: "ip", ioc_value: "1.2.3.4' OR 1=1", __actor: "KELLER" })
    const [sql, opts] = vi.mocked(querySnowflake).mock.calls[0]
    expect(sql).toContain("WHERE ioc_type = ? AND LOWER(ioc_value) = LOWER(?)")
    expect(sql).not.toContain("1.2.3.4")
    expect(opts).toEqual({ binds: ["KELLER", "ip", "1.2.3.4' OR 1=1"] })
    await expect(intel["intel.iocAction"]({ action: "drop", ioc_type: "ip", ioc_value: "x" })).rejects.toThrow(InputError)
    vi.mocked(querySnowflake).mockReset()
  })

  it("analyst verdicts in triage record provenance and the console user", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([])
    await triage["triage.bulk"]({ finding_ids: ["a1"], action: "dismiss_false_positive", __actor: "KELLER" })
    const [sql, opts] = vi.mocked(querySnowflake).mock.calls[0]
    expect(sql).toContain("disposition_source = 'analyst'")
    expect(opts).toEqual({ binds: ["dismissed", "false_positive", "KELLER", "a1"] })
  })

  it("confidence band filter is bound", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([])
    await triage["triage.list"]({ bands: ["high"] })
    const [sql, opts] = vi.mocked(querySnowflake).mock.calls[0]
    expect(sql).toContain("f.conf_band IN (?)")
    expect(opts).toEqual({ binds: ["high"] })
    await expect(triage["triage.list"]({ bands: ["urgent"] })).rejects.toThrow(InputError)
  })
})
