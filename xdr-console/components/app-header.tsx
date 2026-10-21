import Image from "next/image"
import { APP_TITLE, LOGO_SRC } from "@/lib/constants"
import { ThemeToggle } from "@/components/theme-toggle"

/** Top navigation bar. Title and logo come from lib/constants.ts. */
export function AppHeader() {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-white/10 bg-[var(--brand-nav-bg)] text-[var(--brand-nav-fg)]">
      <div className="flex h-14 w-full items-center gap-3 px-4">
        {LOGO_SRC && (
          <Image src={LOGO_SRC} alt={`${APP_TITLE} logo`} width={28} height={28} className="shrink-0" />
        )}
        <span className="text-sm font-semibold tracking-tight">{APP_TITLE}</span>
        <span className="hidden rounded border border-white/20 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-slate-300 sm:inline">
          Snowflake XDR
        </span>
        <div className="ml-auto">
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}
