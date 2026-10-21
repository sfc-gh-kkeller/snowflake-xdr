/**
 * POST /api/xdr/<handler-name>   body: JSON params object
 *
 * Single dispatch point for every console query and action. Only handler
 * names registered in lib/handlers are accepted; each handler validates its
 * own params and binds user values. Responses: { data } or { error }.
 */

import { getHandler } from "@/lib/handlers"
import { InputError } from "@/lib/xdr"

export const dynamic = "force-dynamic"
// AI calls (agent, briefings, campaign stories) can take a minute or more
export const maxDuration = 300

export async function POST(request: Request, ctx: { params: Promise<{ name: string }> }) {
  const { name } = await ctx.params
  const handler = getHandler(name)
  if (!handler) {
    return Response.json({ error: `Unknown operation: ${name}` }, { status: 404 })
  }

  let params: Record<string, unknown> = {}
  try {
    const text = await request.text()
    if (text) {
      const parsed = JSON.parse(text)
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return Response.json({ error: "Body must be a JSON object" }, { status: 400 })
      }
      params = parsed
    }
  } catch {
    return Response.json({ error: "Body must be valid JSON" }, { status: 400 })
  }

  const started = Date.now()
  try {
    const data = await handler(params)
    return Response.json({ data })
  } catch (e) {
    if (e instanceof InputError) {
      return Response.json({ error: e.message }, { status: 400 })
    }
    // Snowflake errors carry useful text (e.g. procedure failures) for an
    // operator console; log the full error server-side.
    const message = e instanceof Error ? e.message : String(e)
    console.error(`[xdr] ${name} failed after ${Date.now() - started}ms:`, message)
    return Response.json({ error: message.slice(0, 500) }, { status: 500 })
  }
}
