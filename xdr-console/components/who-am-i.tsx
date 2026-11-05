"use client"

import { useXdr } from "@/lib/client"

type Me = { user: string; role: string; via: string; tenants: string[] | null }

/** Signed-in user and their XDR role (lib/rbac.ts); tenant scope when restricted. */
export function WhoAmI() {
  const q = useXdr<Me>("me", {}, { staleTime: 60_000 })
  const me = q.data
  if (!me) return null
  return (
    <span className="hidden items-center gap-2 text-xs text-slate-300 sm:flex" title={`Role from: ${me.via}`}>
      <span className="font-mono">{me.user || "local"}</span>
      <span className="rounded border border-white/20 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider">{me.role}</span>
      {me.tenants ? <span className="text-[10px] uppercase tracking-wider">tenant: {me.tenants.join(", ")}</span> : null}
    </span>
  )
}
