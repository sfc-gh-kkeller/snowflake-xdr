"use client"

/**
 * Minimal, safe markdown renderer for Cortex AI output (briefings, campaign
 * stories, agent answers). Renders React elements only — never raw HTML —
 * so model output cannot inject markup. Supports headings, bullet/numbered
 * lists, bold, inline code, fenced code, and paragraphs.
 */

import React from "react"

function inline(text: string, keyBase: string): React.ReactNode[] {
  const out: React.ReactNode[] = []
  // **bold**, `code`
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g
  let last = 0
  let m: RegExpExecArray | null
  let i = 0
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) out.push(text.slice(last, m.index))
    const tok = m[0]
    if (tok.startsWith("**")) {
      out.push(<strong key={`${keyBase}-b${i++}`} className="font-semibold">{tok.slice(2, -2)}</strong>)
    } else {
      out.push(<code key={`${keyBase}-c${i++}`} className="rounded bg-muted px-1 py-0.5 font-mono text-[0.85em]">{tok.slice(1, -1)}</code>)
    }
    last = m.index + tok.length
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}

export function Markdown({ text, className = "" }: { text: string; className?: string }) {
  const lines = (text ?? "").replace(/\r\n/g, "\n").split("\n")
  const blocks: React.ReactNode[] = []
  let list: { ordered: boolean; items: string[] } | null = null
  let para: string[] = []
  let code: string[] | null = null

  const flushPara = () => {
    if (para.length) {
      const k = `p${blocks.length}`
      blocks.push(<p key={k} className="leading-relaxed">{inline(para.join(" "), k)}</p>)
      para = []
    }
  }
  const flushList = () => {
    if (list) {
      const k = `l${blocks.length}`
      const items = list.items.map((it, i) => <li key={`${k}-${i}`}>{inline(it, `${k}-${i}`)}</li>)
      blocks.push(list.ordered
        ? <ol key={k} className="list-decimal space-y-1 pl-5">{items}</ol>
        : <ul key={k} className="list-disc space-y-1 pl-5">{items}</ul>)
      list = null
    }
  }

  for (const raw of lines) {
    const line = raw.trimEnd()
    if (code) {
      if (line.trim().startsWith("```")) {
        blocks.push(<pre key={`k${blocks.length}`} className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs">{code.join("\n")}</pre>)
        code = null
      } else {
        code.push(raw)
      }
      continue
    }
    if (line.trim().startsWith("```")) { flushPara(); flushList(); code = []; continue }
    const h = /^(#{1,4})\s+(.*)$/.exec(line)
    const bullet = /^\s*[-*•]\s+(.*)$/.exec(line)
    const num = /^\s*\d+[.)]\s+(.*)$/.exec(line)
    if (h) {
      flushPara(); flushList()
      const k = `h${blocks.length}`
      const cls = h[1].length <= 2 ? "text-base font-semibold mt-2" : "text-sm font-semibold mt-1"
      blocks.push(<div key={k} className={cls}>{inline(h[2], k)}</div>)
    } else if (bullet || num) {
      flushPara()
      const ordered = Boolean(num)
      if (!list || list.ordered !== ordered) { flushList(); list = { ordered, items: [] } }
      list.items.push((bullet ?? num)![1])
    } else if (!line.trim()) {
      flushPara(); flushList()
    } else {
      flushList()
      para.push(line.trim())
    }
  }
  if (code) blocks.push(<pre key={`k${blocks.length}`} className="overflow-x-auto rounded-md bg-muted p-3 font-mono text-xs">{(code as string[]).join("\n")}</pre>)
  flushPara(); flushList()
  return <div className={`space-y-2 text-sm ${className}`}>{blocks}</div>
}
