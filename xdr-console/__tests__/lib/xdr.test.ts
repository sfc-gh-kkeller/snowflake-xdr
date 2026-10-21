import { describe, it, expect } from "vitest"
import {
  toIso, normalizeRow, toNumberIfNumeric, normalizeTimestamp, parseVariant,
  str, int, oneOf, listOf, id, ids, placeholders, InputError,
} from "../../lib/xdr"

describe("value normalization", () => {
  it("toIso converts Date and toJSON objects, leaves others", () => {
    expect(toIso(new Date("2026-10-19T12:00:00Z"))).toBe("2026-10-19T12:00:00.000Z")
    expect(toIso({ toJSON: () => "2026-10-19T12:00:00Z" })).toBe("2026-10-19T12:00:00Z")
    expect(toIso(new Date("not a date"))).toBeNull()
    expect(toIso("text")).toBe("text")
    expect(toIso([1, 2])).toEqual([1, 2])
  })

  it("converts clean numeric strings but keeps ids, IPs and padded codes as text", () => {
    expect(toNumberIfNumeric("4")).toBe(4)
    expect(toNumberIfNumeric("-12.5")).toBe(-12.5)
    expect(toNumberIfNumeric("0")).toBe(0)
    expect(toNumberIfNumeric("007")).toBe("007")
    expect(toNumberIfNumeric("10.1.5.107")).toBe("10.1.5.107")
    expect(toNumberIfNumeric("DET-001")).toBe("DET-001")
    expect(toNumberIfNumeric("8d3959fd-9676")).toBe("8d3959fd-9676")
    expect(toNumberIfNumeric("12345678901234567890")).toBe("12345678901234567890")
  })

  it("normalizeRow lower-cases keys and normalizes values", () => {
    const row = normalizeRow({ SEVERITY: "4", DETECTION_TIME: new Date("2026-10-19T00:00:00Z"), SRC: "10.1.5.107", EVIDENCE: { a: 1 } })
    expect(row).toEqual({ severity: 4, detection_time: "2026-10-19T00:00:00.000Z", src: "10.1.5.107", evidence: { a: 1 } })
  })

  it("normalizes Snowflake TIMESTAMP_TZ strings to ISO", () => {
    expect(normalizeTimestamp("2026-10-19 05:39:03.441 -0700")).toBe("2026-10-19T12:39:03.441Z")
    expect(normalizeTimestamp("2026-10-19 05:39:03 +02:00")).toBe("2026-10-19T03:39:03.000Z")
    expect(normalizeTimestamp("yesterday")).toBe("yesterday")
    expect(normalizeTimestamp(null)).toBeNull()
  })

  it("parseVariant parses JSON strings only", () => {
    expect(parseVariant('{"briefing":"hi"}')).toEqual({ briefing: "hi" })
    expect(parseVariant("[1,2]")).toEqual([1, 2])
    expect(parseVariant("{not json")).toBe("{not json")
    expect(parseVariant("plain")).toBe("plain")
    expect(parseVariant({ already: true })).toEqual({ already: true })
  })
})

describe("input validation", () => {
  it("str enforces required and max length", () => {
    expect(str({ a: "  x  " }, "a")).toBe("x")
    expect(str({}, "a")).toBe("")
    expect(() => str({}, "a", { required: true })).toThrow(InputError)
    expect(() => str({ a: "x".repeat(11) }, "a", { max: 10 })).toThrow(/too long/)
    expect(() => str({ a: { nested: 1 } }, "a")).toThrow(/must be text/)
  })

  it("int clamps and defaults", () => {
    expect(int({ n: 500 }, "n", { min: 1, max: 48, def: 24 })).toBe(48)
    expect(int({ n: "-3" }, "n", { min: 1, max: 48, def: 24 })).toBe(1)
    expect(int({}, "n", { min: 1, max: 48, def: 24 })).toBe(24)
    expect(() => int({ n: "abc" }, "n", { min: 1, max: 48, def: 24 })).toThrow(InputError)
  })

  it("oneOf and listOf only accept allow-listed values", () => {
    expect(oneOf({ s: "new" }, "s", ["new", "resolved"] as const)).toBe("new")
    expect(oneOf({}, "s", ["new", "resolved"] as const, "resolved")).toBe("resolved")
    expect(() => oneOf({ s: "new'; DROP TABLE x;--" }, "s", ["new", "resolved"] as const)).toThrow(InputError)
    expect(listOf({ l: ["new"] }, "l", ["new", "resolved"] as const)).toEqual(["new"])
    expect(() => listOf({ l: ["new", "evil"] }, "l", ["new", "resolved"] as const)).toThrow(InputError)
  })

  it("id/ids accept UUIDs and rule codes, reject injection", () => {
    expect(id({ i: "8d3959fd-9676-4597-8493-c59241e148ee" }, "i")).toBe("8d3959fd-9676-4597-8493-c59241e148ee")
    expect(id({ i: "DET-001" }, "i")).toBe("DET-001")
    expect(() => id({ i: "x' OR '1'='1" }, "i")).toThrow(InputError)
    expect(() => ids({ i: [] }, "i")).toThrow(InputError)
    expect(() => ids({ i: ["ok", "bad;id"] }, "i")).toThrow(/\[1\]/)
  })

  it("placeholders builds bind lists", () => {
    expect(placeholders(3)).toBe("?, ?, ?")
    expect(placeholders(0)).toBe("")
  })
})
