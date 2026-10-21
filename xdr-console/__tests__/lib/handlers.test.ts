import { describe, it, expect, vi, beforeEach } from "vitest"

vi.mock("../../lib/snowflake", () => ({
  querySnowflake: vi.fn(),
  querySnowflakeLongRunning: vi.fn(),
}))

import { querySnowflake, querySnowflakeLongRunning } from "../../lib/snowflake"
import { buildTriageFilter, triage } from "../../lib/handlers/triage"
import { extractAgentText, ask } from "../../lib/handlers/operate"
import { pathsToGraph, uniqueChains, flattenEntityEvents } from "../../lib/handlers/investigate"
import { actionConfig, response } from "../../lib/handlers/engineer"
import { pivotBySeverity } from "../../lib/handlers/overview"
import { layoutEdges, entityKind } from "../../lib/graph"
import { InputError } from "../../lib/xdr"

beforeEach(() => vi.clearAllMocks())

describe("triage filter", () => {
  it("binds every user value and never interpolates", () => {
    const { where, binds } = buildTriageFilter({
      statuses: ["new", "investigating"], severities: ["5", "4"], category: "identity",
      source: "stored_procedure", search: "js%mith",
    })
    expect(where).toBe(
      "WHERE f.status IN (?, ?) AND f.severity IN (?, ?) AND f.category = ? AND f.detection_source = ? " +
      "AND (LOWER(COALESCE(f.user_name, f.src, f.dest, '')) LIKE ? OR LOWER(f.description) LIKE ?)")
    expect(binds).toEqual(["new", "investigating", 5, 4, "identity", "stored_procedure", "%js\\%mith%", "%js\\%mith%"])
    expect(where).not.toContain("js")
  })

  it("is empty with no filters and rejects unknown enum values", () => {
    expect(buildTriageFilter({})).toEqual({ where: "", binds: [] })
    expect(() => buildTriageFilter({ category: "identity' OR 1=1" })).toThrow(InputError)
    expect(() => buildTriageFilter({ statuses: ["open"] })).toThrow(InputError)
  })

  it("bulk dismiss binds status, disposition and every id", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([])
    const r = await triage["triage.bulk"]({ finding_ids: ["a1", "b2"], action: "dismiss_false_positive" })
    expect(r).toEqual({ message: "dismiss false positive applied to 2 finding(s)" })
    const [sql, opts] = vi.mocked(querySnowflake).mock.calls[0]
    expect(sql).toContain("WHERE finding_id IN (?, ?)")
    expect(opts).toEqual({ binds: ["dismissed", "false_positive", "a1", "b2"] })
  })

  it("case update binds in column order", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([])
    await triage["triage.update"]({ finding_id: "f1", status: "resolved", assigned_to: "kevin", disposition: "benign", triage_notes: "ok" })
    expect(vi.mocked(querySnowflake).mock.calls[0][1]).toEqual({ binds: ["resolved", "kevin", "benign", "ok", "f1"] })
  })
})

describe("Ask XDR agent", () => {
  it("extracts text parts and tool names from DATA_AGENT_RUN output", () => {
    const resp = {
      role: "assistant",
      content: [
        { type: "thinking", thinking: { text: "planning" } },
        { type: "tool_use", tool_use: { name: "analyst_text_to_sql" } },
        { type: "tool_result", tool_result: { content: [] } },
        { type: "tool_use", tool_use: { name: "analyst_text_to_sql" } },
        { type: "text", text: "There are **8** findings." },
        { type: "text", text: "Mostly DET-003." },
      ],
    }
    expect(extractAgentText(resp)).toEqual({ text: "There are **8** findings.\n\nMostly DET-003.", tools: ["analyst_text_to_sql"] })
    expect(extractAgentText(JSON.stringify(resp)).text).toContain("8")
    expect(extractAgentText("garbage")).toEqual({ text: "", tools: [] })
  })

  it("builds the agent payload server-side and binds it", async () => {
    vi.mocked(querySnowflakeLongRunning).mockResolvedValueOnce([{ RESP: JSON.stringify({ content: [{ type: "text", text: "hi" }] }) }])
    const r = await ask["ask.agent"]({ messages: [{ role: "user", text: "how many findings?" }] })
    expect(r).toEqual({ text: "hi", tools: [] })
    const [sql, opts] = vi.mocked(querySnowflakeLongRunning).mock.calls[0]
    expect(sql).toBe("SELECT SNOWFLAKE.CORTEX.DATA_AGENT_RUN('SNOWFLAKE_XDR.DASHBOARDS.XDR_ANALYST', ?, TRUE) AS resp")
    expect(JSON.parse((opts as { binds: string[] }).binds[0])).toEqual({
      messages: [{ role: "user", content: [{ type: "text", text: "how many findings?" }] }],
    })
  })

  it("rejects malformed conversations", async () => {
    await expect(ask["ask.agent"]({ messages: [] })).rejects.toThrow(InputError)
    await expect(ask["ask.agent"]({ messages: [{ role: "system", text: "x" }] })).rejects.toThrow(InputError)
    await expect(ask["ask.agent"]({ messages: [{ role: "user", text: "q" }, { role: "assistant", text: "a" }] })).rejects.toThrow(/last message/)
  })
})

describe("attack graph mapping", () => {
  const paths = [
    { hops: 2, entities: ["host:10.1.5.107", "user:lgreco", "host:VPN-GW-01"], edges: [{ type: "auth", action: "failure" }, { type: "auth", action: "failure" }], suspicious: false, last_seen: "2026-10-19T01:00:00Z" },
    { hops: 4, entities: ["host:10.1.5.107", "user:jsmith", "host:WS-042", "host:FS-FILE01", "host:DC-01"], edges: [{ type: "auth", action: "success" }, { type: "auth", action: "success" }, { type: "network", action: "allowed" }, { type: "network", action: "blocked" }], suspicious: true, last_seen: "2026-10-19T02:00:00Z" },
    { hops: 4, entities: ["host:10.1.5.107", "user:jsmith", "host:WS-042", "host:FS-FILE01", "host:DC-01"], edges: [], suspicious: true, last_seen: "2026-10-19T03:00:00Z" },
  ]

  it("collapses repeated traversals into unique chains, deepest first", () => {
    const u = uniqueChains(paths)
    expect(u).toHaveLength(2)
    expect(u[0].hops).toBe(4)
    expect(u[0].variants).toBe(2)
    expect(u[0].last_seen).toBe("2026-10-19T03:00:00Z")
    expect(u[1].variants).toBe(1)
  })

  it("layers entities by first hop distance and dedupes edges", () => {
    const g = pathsToGraph(uniqueChains(paths))
    const layer = Object.fromEntries(g.nodes.map((n) => [n.id, n.layer]))
    expect(layer["host:10.1.5.107"]).toBe(0)
    expect(layer["user:jsmith"]).toBe(1)
    expect(layer["host:DC-01"]).toBe(4)
    expect(g.nodes.find((n) => n.id === "host:10.1.5.107")?.start).toBe(true)
    expect(g.nodes.find((n) => n.id === "user:jsmith")?.kind).toBe("user")
    expect(g.edges.filter((e) => e.source === "host:10.1.5.107" && e.target === "user:jsmith")).toHaveLength(1)
    expect(g.edges.find((e) => e.target === "host:DC-01")).toMatchObject({ label: "network: blocked", suspicious: true })
    // rows are unique within a layer
    const keys = g.nodes.map((n) => `${n.layer}:${n.row}`)
    expect(new Set(keys).size).toBe(keys.length)
  })

  it("layoutEdges handles cycles and classifies entity kinds", () => {
    const g = layoutEdges([
      { source: "jsmith", target: "10.0.0.5", label: "logged_into" },
      { source: "10.0.0.5", target: "evil.example", label: "dns" },
      { source: "evil.example", target: "10.0.0.5", label: "callback" },
    ])
    expect(g.nodes.map((n) => [n.id, n.layer])).toEqual([["jsmith", 0], ["10.0.0.5", 1], ["evil.example", 2]])
    expect(g.edges).toHaveLength(3)
    expect(entityKind("10.0.0.5")).toBe("ip")
    expect(entityKind("domain:corp.local")).toBe("domain")
    // pure cycle: no roots, still laid out
    expect(layoutEdges([{ source: "a", target: "b" }, { source: "b", target: "a" }]).nodes).toHaveLength(2)
  })
})

describe("view helpers", () => {
  it("pivots hourly severity counts for stacked charts", () => {
    expect(pivotBySeverity([
      { hour: "h1", severity: 5, count: 2 }, { hour: "h1", severity: 3, count: 4 }, { hour: "h2", severity: 4, count: 1 },
    ])).toEqual([
      { hour: "h1", sev1: 0, sev2: 0, sev3: 4, sev4: 0, sev5: 2 },
      { hour: "h2", sev1: 0, sev2: 0, sev3: 0, sev4: 1, sev5: 0 },
    ])
  })

  it("flattens SEARCH_ENTITY events newest first with ISO times", () => {
    const rows = flattenEntityEvents([
      { time: "2026-10-19 05:00:00.000 -0700", source: "auth", action: "failure", user: "jsmith" },
      JSON.stringify({ time: "2026-10-19 06:00:00.000 -0700", source: "dns", query: "evil.example" }),
    ])
    expect(rows[0]).toMatchObject({ source: "dns", detail: "evil.example", time: "2026-10-19T13:00:00.000Z" })
    expect(rows[1]).toMatchObject({ source: "auth", user: "jsmith", time: "2026-10-19T12:00:00.000Z" })
  })

  it("validates playbook action config", () => {
    expect(actionConfig({ to: "a@b.com, c@d.org" }, "email")).toBe('{"to":"a@b.com, c@d.org"}')
    expect(() => actionConfig({ to: "not-an-email" }, "email")).toThrow(InputError)
    expect(() => actionConfig({ url: "file:///etc/passwd" }, "api_call")).toThrow(InputError)
    expect(actionConfig({}, "webhook")).toBe("{}")
  })

  it("binds all 13 SAVE_PLAYBOOK parameters in signature order", async () => {
    vi.mocked(querySnowflake).mockResolvedValueOnce([{ SAVE_PLAYBOOK: "created: PB-1" }])
    const r = await response["response.savePlaybook"]({
      name: "Crit to Slack", description: "d", trigger_severity_min: 5, trigger_entity: "jsmith",
      threshold_count: 2, threshold_window_minutes: 30, cooldown_minutes: 15, action_type: "webhook", enabled: true,
    })
    expect(r).toEqual({ message: "Playbook created: PB-1" })
    const [sql, opts] = vi.mocked(querySnowflake).mock.calls[0]
    expect(sql).toBe("CALL SNOWFLAKE_XDR.RESPONSE.SAVE_PLAYBOOK(?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, PARSE_JSON(?), ?)")
    expect(opts).toEqual({ binds: ["", "Crit to Slack", "d", 5, "jsmith", 2, 30, 15, "webhook", "{}", true] })
  })
})
