"use client"

import { useEffect, useRef, useState } from "react"
import { Bot, Send, User, Wrench, RotateCcw } from "lucide-react"
import { callXdr } from "@/lib/client"
import { PageHeader, Panel, ErrorNote, Loading } from "@/components/xdr/kit"
import { Markdown } from "@/components/xdr/markdown"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

interface Turn { role: "user" | "assistant"; text: string; tools?: string[] }

const EXAMPLES = [
  "How many high severity findings are there this week?",
  "What happened with the user jsmith?",
  "Trace the attack path from host:10.1.5.107",
  "Which MITRE tactics have no detection coverage?",
  "Create and enable a rule for external port scanning",
  "Add 185.220.101.42 as a C2 IOC with severity 5",
  "Find alerts similar to SMB lateral movement",
]

const TOOL_LABELS: Record<string, string> = {
  analyst_text_to_sql: "Cortex Analyst (semantic view)",
  finding_search: "Cortex Search (findings)",
  search_entity: "Entity search",
  ai_investigate_entity: "AI entity investigation",
  trace_attack_paths: "Attack-path trace",
  create_detection_rule: "Created rule",
  set_rule_enabled: "Changed rule state",
  add_ioc: "Added IOC",
  update_finding: "Updated finding",
  set_incident_status: "Updated incident",
  create_playbook: "Created playbook",
  run_detections: "Ran detections",
  data_to_chart: "Chart",
}

export function AskXdr() {
  const [turns, setTurns] = useState<Turn[]>([])
  const [input, setInput] = useState("")
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<unknown>(null)
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }) }, [turns, pending])

  const send = async (text: string) => {
    const q = text.trim()
    if (!q || pending) return
    const next: Turn[] = [...turns, { role: "user", text: q }]
    setTurns(next)
    setInput("")
    setError(null)
    setPending(true)
    try {
      // Send the conversation as plain text turns; the server builds the agent payload
      const r = await callXdr<{ text: string; tools: string[] }>("ask.agent", {
        messages: next.slice(-20).map((t) => ({ role: t.role, text: t.text })),
      })
      setTurns([...next, { role: "assistant", text: r.text, tools: r.tools }])
    } catch (e) {
      setError(e)
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        persona="SOC Analyst"
        title="Ask XDR"
        description="Chat with the XDR_ANALYST Cortex Agent. It answers with Cortex Analyst, Cortex Search, entity investigation and attack-path tracing, and can act: create and enable rules, add IOCs, triage findings and incidents, create playbooks and run detections. Every action is logged in DASHBOARDS.AGENT_ACTION_LOG."
        actions={turns.length > 0 && (
          <Button size="sm" variant="outline" onClick={() => { setTurns([]); setError(null) }}>
            <RotateCcw className="h-3.5 w-3.5" /> New chat
          </Button>
        )}
      />

      <Panel bodyClassName="flex h-[calc(100vh-15rem)] min-h-[28rem] flex-col p-0">
        <div className="flex-1 space-y-4 overflow-y-auto p-4">
          {turns.length === 0 && (
            <div className="mx-auto max-w-2xl py-6 text-center">
              <Bot className="mx-auto h-10 w-10 text-primary" />
              <div className="mt-2 text-sm font-medium">Ask a security question in plain English</div>
              <div className="mt-4 flex flex-wrap justify-center gap-2">
                {EXAMPLES.map((ex) => (
                  <button key={ex} type="button" onClick={() => send(ex)}
                    className="rounded-full border border-border px-3 py-1 text-xs text-muted-foreground hover:bg-muted hover:text-foreground">
                    {ex}
                  </button>
                ))}
              </div>
            </div>
          )}
          {turns.map((t, i) => (
            <div key={i} className={cn("flex gap-3", t.role === "user" && "flex-row-reverse")}>
              <div className={cn("flex h-7 w-7 shrink-0 items-center justify-center rounded-full",
                t.role === "user" ? "bg-muted" : "bg-primary text-primary-foreground")}>
                {t.role === "user" ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
              </div>
              <div className={cn("max-w-[80%] rounded-xl px-4 py-2.5",
                t.role === "user" ? "bg-primary/10" : "border border-border bg-card")}>
                {t.role === "user" ? <p className="whitespace-pre-wrap text-sm">{t.text}</p> : <Markdown text={t.text} />}
                {t.tools && t.tools.length > 0 && (
                  <div className="mt-2 flex flex-wrap items-center gap-1 border-t border-border pt-2 text-[11px] text-muted-foreground">
                    <Wrench className="h-3 w-3" /> used:
                    {t.tools.map((tool) => (
                      <span key={tool} className="rounded bg-muted px-1.5 py-0.5">{TOOL_LABELS[tool] ?? tool}</span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
          {pending && <Loading label="XDR Analyst agent is thinking — planning, calling tools, writing the answer…" />}
          {Boolean(error) && <ErrorNote error={error} />}
          <div ref={endRef} />
        </div>
        <form
          className="flex items-end gap-2 border-t border-border p-3"
          onSubmit={(e) => { e.preventDefault(); send(input) }}
        >
          <textarea
            value={input} rows={2} maxLength={4000}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(input) } }}
            placeholder="Ask about findings, entities, attack paths, coverage…  (Enter to send, Shift+Enter for newline)"
            className="flex-1 resize-none rounded-md border border-input bg-background p-2 text-sm outline-none focus:ring-2 focus:ring-ring"
          />
          <Button type="submit" disabled={pending || !input.trim()}><Send className="h-4 w-4" /> Send</Button>
        </form>
      </Panel>
    </div>
  )
}
