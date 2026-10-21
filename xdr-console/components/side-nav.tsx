"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  LayoutDashboard, ListChecks, FolderSearch, UserSearch, Network, Radio, Crosshair,
  MessageSquareText, ShieldCheck, FileCode2, Zap, Gauge, type LucideIcon,
} from "lucide-react"
import { NAV } from "@/lib/constants"
import { cn } from "@/lib/utils"

const ICONS: Record<string, LucideIcon> = {
  LayoutDashboard, ListChecks, FolderSearch, UserSearch, Network, Radio, Crosshair,
  MessageSquareText, ShieldCheck, FileCode2, Zap, Gauge,
}

/** Persona-grouped sidebar navigation. */
export function SideNav() {
  const pathname = usePathname()
  return (
    <nav className="sticky top-14 hidden h-[calc(100vh-3.5rem)] w-56 shrink-0 overflow-y-auto border-r border-border bg-[var(--brand-nav-bg)] px-3 py-4 text-[var(--brand-nav-fg)] md:block">
      {NAV.map((group) => (
        <div key={group.persona} className="mb-5">
          <div className="mb-1.5 px-2 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
            {group.persona}
          </div>
          <ul className="space-y-0.5">
            {group.items.map((item) => {
              const Icon = ICONS[item.icon]
              const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href)
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    className={cn(
                      "flex items-center gap-2 rounded-md px-2 py-1.5 text-sm transition-colors",
                      active ? "bg-[var(--brand-primary)] font-medium text-white"
                        : "text-slate-300 hover:bg-white/10 hover:text-white",
                    )}
                  >
                    {Icon && <Icon className="h-4 w-4 shrink-0" />}
                    {item.label}
                  </Link>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
      <div className="mt-6 border-t border-white/10 px-2 pt-3 text-[10px] leading-relaxed text-slate-400">
        Runs natively on Snowflake: telemetry, detections, Cortex AI and this app share one governed platform.
      </div>
    </nav>
  )
}

/** Compact nav for small screens. */
export function MobileNav() {
  const pathname = usePathname()
  const items = NAV.flatMap((g) => g.items)
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-border px-3 py-2 md:hidden">
      {items.map((item) => {
        const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href)
        return (
          <Link
            key={item.href} href={item.href}
            className={cn("whitespace-nowrap rounded-md px-2 py-1 text-xs",
              active ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:bg-muted")}
          >
            {item.label}
          </Link>
        )
      })}
    </div>
  )
}
