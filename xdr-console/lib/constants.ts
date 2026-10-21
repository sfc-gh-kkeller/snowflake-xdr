/** App title — displayed in the nav header and browser tab */
export const APP_TITLE = "XDR Console"

/** Path to the logo in /public (used in the header and as favicon) */
export const LOGO_SRC = "/icon.svg"

/** Navigation, grouped by the persona each view is built for. */
export interface NavItem { href: string; label: string; icon: string }
export interface NavGroup { persona: string; items: NavItem[] }

export const NAV: NavGroup[] = [
  {
    persona: "SOC Analyst",
    items: [
      { href: "/", label: "Overview", icon: "LayoutDashboard" },
      { href: "/triage", label: "Triage & Cases", icon: "ListChecks" },
      { href: "/investigations", label: "Investigations", icon: "FolderSearch" },
      { href: "/entity", label: "Entity 360", icon: "UserSearch" },
      { href: "/attack-graph", label: "Attack Graph", icon: "Network" },
      { href: "/live", label: "Live Tail", icon: "Radio" },
      { href: "/hunt", label: "Threat Hunting", icon: "Crosshair" },
      { href: "/ask", label: "Ask XDR", icon: "MessageSquareText" },
    ],
  },
  {
    persona: "Detection Engineer",
    items: [
      { href: "/detections", label: "Detections", icon: "ShieldCheck" },
      { href: "/rules", label: "Rules & IOCs", icon: "FileCode2" },
      { href: "/response", label: "Response", icon: "Zap" },
    ],
  },
  {
    persona: "CISO",
    items: [{ href: "/posture", label: "Security Posture", icon: "Gauge" }],
  },
]
