/**
 * Server-side role resolution for the signed-in console user, cached briefly so a
 * page of parallel queries costs one lookup. Kept apart from lib/rbac.ts (pure
 * policy) so the policy can be unit-tested without Snowflake.
 */

import { scalar } from "@/lib/xdr"
import { isRole, type XdrRole } from "@/lib/rbac"

export type Identity = { user: string; role: XdrRole; via: string; tenants: string[] | null }

const TTL_MS = 60_000
const cache = new Map<string, { at: number; id: Identity }>()

export async function resolveIdentity(user: string): Promise<Identity> {
  if (!user) {
    // No ingress identity (local `next dev`): opt-in role for development only
    const dev = process.env.XDR_LOCAL_ROLE
    return { user: "", role: isRole(dev) ? dev : "viewer", via: isRole(dev) ? "XDR_LOCAL_ROLE" : "no identity", tenants: null }
  }
  const hit = cache.get(user)
  if (hit && Date.now() - hit.at < TTL_MS) return hit.id
  let id: Identity
  try {
    const r = await scalar<{ role?: string; via?: string; tenants?: string[] | null }>(
      "CALL SNOWFLAKE_XDR.DASHBOARDS.RESOLVE_CONSOLE_ROLE(?)", [user])
    id = { user, role: isRole(r?.role) ? r.role : "viewer", via: String(r?.via ?? "default"), tenants: r?.tenants ?? null }
  } catch {
    // fail closed: if roles cannot be read, the user can still look but not change anything
    id = { user, role: "viewer", via: "role lookup failed", tenants: null }
  }
  cache.set(user, { at: Date.now(), id })
  return id
}

export function clearIdentityCache(): void {
  cache.clear()
}
