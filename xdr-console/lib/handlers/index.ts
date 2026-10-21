/**
 * Handler registry: the complete set of operations the console can perform.
 * The API route only dispatches names found here.
 */

import { overview } from "@/lib/handlers/overview"
import { triage } from "@/lib/handlers/triage"
import { investigations, entityHandlers, graph } from "@/lib/handlers/investigate"
import { live, hunt, ask } from "@/lib/handlers/operate"
import { detections, rules, response, posture } from "@/lib/handlers/engineer"

export type Handler = (params: Record<string, unknown>) => Promise<unknown>

export const handlers: Record<string, Handler> = {
  ...overview,
  ...triage,
  ...investigations,
  ...entityHandlers,
  ...graph,
  ...live,
  ...hunt,
  ...ask,
  ...detections,
  ...rules,
  ...response,
  ...posture,
}

export function getHandler(name: string): Handler | null {
  return Object.prototype.hasOwnProperty.call(handlers, name) ? handlers[name] : null
}
