/**
 * Live Tail, Threat Hunting and Ask XDR (Cortex Agent).
 * Ported from 18_live_tail.py, 8_hunting_console.py, 9_agent_comparison.py
 * and 19_ask_xdr.py.
 */

import { rows, scalar, str, int, oneOf, InputError } from "@/lib/xdr"

export const live = {
  "live.lag": async () =>
    rows("SELECT * FROM SNOWFLAKE_XDR.DETECTIONS.V_SOURCE_LAG ORDER BY source_table"),

  "live.feed": async () =>
    rows(`
      SELECT source_table, event_time, ingestion_time, lag_seconds, source_state,
             entity, action, detail
      FROM SNOWFLAKE_XDR.DETECTIONS.V_LIVE_FEED
      LIMIT 200`),

  "live.emit": async (p: Record<string, unknown>) => {
    const batches = int(p, "batches", { min: 1, max: 20, def: 3 })
    return {
      message: await scalar<string>("CALL SNOWFLAKE_XDR.RAW_LOGS.EMIT_LIVE_EVENTS(?)", [batches], { long: true }),
    }
  },
}

export const HUNT_FOCUS = ["general", "lateral_movement", "exfiltration", "persistence", "initial_access"] as const

export const hunt = {
  "hunt.findings": async () =>
    rows(`
      SELECT finding_id, detection_time, severity, confidence, mitre_technique_id,
             LEFT(description, 300) AS description, evidence:focus::VARCHAR AS focus_area
      FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
      WHERE detection_source = 'ai_hunting_agent'
      ORDER BY detection_time DESC LIMIT 20`),

  "hunt.run": async (p: Record<string, unknown>) => {
    const focus = oneOf(p, "focus", HUNT_FOCUS, "general")
    const hours = int(p, "hours", { min: 1, max: 48, def: 24 })
    return scalar("CALL SNOWFLAKE_XDR.DETECTIONS.AI_HUNTING_AGENT(?, ?)", [focus, hours], { long: true })
  },

  "hunt.detect": async (p: Record<string, unknown>) => {
    const target = str(p, "target", { max: 128, required: true })
    if (!/^[A-Za-z0-9._:@\\/-]+$/.test(target)) throw new InputError("target contains unsupported characters")
    const hours = int(p, "hours", { min: 1, max: 24, def: 4 })
    return scalar("CALL SNOWFLAKE_XDR.DETECTIONS.AI_DETECTION_AGENT(?, ?)", [target, hours], { long: true })
  },

  /** Rule-based vs AI-agent findings over the same window (agent comparison). */
  "hunt.compare": async (p: Record<string, unknown>) => {
    const hours = int(p, "hours", { min: 1, max: 168, def: 24 })
    const [rule, ai, aiOnly] = await Promise.all([
      rows(`
        SELECT rule_id, severity, confidence, category, mitre_technique_id,
               LEFT(description, 150) AS description, detection_time
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE detection_source = 'stored_procedure'
          AND detection_time > DATEADD('hour', ?, CURRENT_TIMESTAMP())
        ORDER BY risk_score DESC LIMIT 25`, [-hours]),
      rows(`
        SELECT rule_id, severity, confidence, category, mitre_technique_id,
               LEFT(description, 150) AS description, detection_time, detection_source
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE detection_source IN ('ai_detection_agent', 'ai_hunting_agent')
          AND detection_time > DATEADD('hour', ?, CURRENT_TIMESTAMP())
        ORDER BY risk_score DESC LIMIT 25`, [-hours]),
      rows(`
        SELECT DISTINCT mitre_technique_id, LEFT(description, 200) AS finding,
               detection_source, confidence
        FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
        WHERE detection_source IN ('ai_detection_agent', 'ai_hunting_agent')
          AND detection_time > DATEADD('hour', ?, CURRENT_TIMESTAMP())
          AND mitre_technique_id IS NOT NULL
          AND mitre_technique_id NOT IN (
              SELECT DISTINCT mitre_technique_id
              FROM SNOWFLAKE_XDR.DETECTIONS.DETECTION_FINDINGS
              WHERE detection_source = 'stored_procedure'
                AND detection_time > DATEADD('hour', ?, CURRENT_TIMESTAMP())
                AND mitre_technique_id IS NOT NULL)`, [-hours, -hours]),
    ])
    return { rule, ai, aiOnly }
  },
}

// ---------------------------------------------------------------------------
// Ask XDR - Cortex Agent
// ---------------------------------------------------------------------------

export interface ChatMessage { role: "user" | "assistant"; text: string }

const AGENT = "SNOWFLAKE_XDR.DASHBOARDS.XDR_ANALYST"

/** Pull the user-facing text parts out of a DATA_AGENT_RUN response. */
export function extractAgentText(resp: unknown): { text: string; tools: string[] } {
  const r = (typeof resp === "string" ? safeJson(resp) : resp) as Record<string, unknown> | null
  const content = Array.isArray(r?.content) ? (r?.content as Record<string, unknown>[]) : []
  const texts: string[] = []
  const tools: string[] = []
  for (const part of content) {
    if (part?.type === "text" && typeof part.text === "string") texts.push(part.text)
    if (part?.type === "tool_use") {
      const tu = part.tool_use as Record<string, unknown> | undefined
      if (tu && typeof tu.name === "string") tools.push(tu.name)
    }
  }
  return { text: texts.join("\n\n").trim(), tools: [...new Set(tools)] }
}

function safeJson(s: string): unknown {
  try { return JSON.parse(s) } catch { return null }
}

/**
 * DATA_AGENT_RUN accepts exactly one user message (no assistant turns), so prior
 * turns are folded into that message as conversation context.
 */
function foldHistory(turns: { role: string; text: string }[]): string {
  const question = turns[turns.length - 1].text
  const history = turns.slice(0, -1).slice(-10)
  if (history.length === 0) return question
  const ctx = history.map((t) => `${t.role === "user" ? "User" : "Assistant"}: ${t.text}`).join("\n\n")
  return `Conversation so far:\n${ctx}\n\nFollow-up question (answer this, using the context above): ${question}`
}

export const ask = {
  "ask.agent": async (p: Record<string, unknown>) => {
    const raw = p.messages
    if (!Array.isArray(raw) || raw.length === 0 || raw.length > 30) {
      throw new InputError("messages must be a list of 1-30 chat turns")
    }
    const turns = raw.map((m, i) => {
      const msg = m as Record<string, unknown>
      const role = msg?.role === "assistant" ? "assistant" : msg?.role === "user" ? "user" : null
      if (!role) throw new InputError(`messages[${i}].role must be user or assistant`)
      return { role, text: str(msg, "text", { max: 4000, required: true }) }
    })
    if (turns[turns.length - 1].role !== "user") throw new InputError("last message must be from the user")
    const resp = await scalar(
      `SELECT SNOWFLAKE.CORTEX.DATA_AGENT_RUN('${AGENT}', ?, TRUE) AS resp`,
      [JSON.stringify({ messages: [{ role: "user", content: [{ type: "text", text: foldHistory(turns) }] }] })],
      { long: true })
    const parsed = (typeof resp === "string" ? safeJson(resp) : resp) as Record<string, unknown> | null
    if (parsed?.error_code || (parsed?.code && parsed?.message && !parsed?.content)) {
      throw new Error(`Agent error ${parsed.error_code ?? parsed.code}: ${parsed.message}`)
    }
    const { text, tools } = extractAgentText(parsed)
    return { text: text || "(The agent returned no text response.)", tools }
  },
}
