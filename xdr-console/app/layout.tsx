import type { Metadata } from "next"
import type React from "react"
import { AppHeader } from "@/components/app-header"
import { ThemeProvider } from "@/components/theme-provider"
import { QueryProvider } from "@/components/query-provider"
import { SideNav, MobileNav } from "@/components/side-nav"
import { APP_TITLE, LOGO_SRC } from "@/lib/constants"
import "./globals.css"

export const metadata: Metadata = {
  title: APP_TITLE,
  description: "Snowflake-native XDR: triage, investigations, attack-graph correlation, detection engineering and response",
  icons: { icon: LOGO_SRC },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased">
        <ThemeProvider>
          <QueryProvider>
            <AppHeader />
            <MobileNav />
            <div className="flex">
              <SideNav />
              <main className="min-w-0 flex-1 px-4 py-5 md:px-6">{children}</main>
            </div>
          </QueryProvider>
        </ThemeProvider>
      </body>
    </html>
  )
}
