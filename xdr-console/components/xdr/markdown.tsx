"use client"

/**
 * Minimal, safe markdown renderer for Cortex AI output (briefings, campaign
 * stories, agent answers). Renders React elements only — never raw HTML —
 * so model output cannot inject markup. Supports headings, bullet/numbered
 * lists, GFM tables, bold, inline code, fenced code, and paragraphs.
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

/** Split a GFM table row into trimmed cells, ignoring the outer pipes. */
function cells(row: string): string[] {
  return row.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim())
}

const TABLE_ROW = /^\s*\|.*\|\s*$/
const TABLE_SEP = /^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/

export function Markdown({ text, className = "" }: { text: string; className?: string }) {
  const lines = (text ?? "").replace(/\r\n/g, "\n").split("\n")
  const blocks: React.ReactNode[] = []
  let list: { ordered: boolean; items: string[] } | null = null
  let para: string[] = []
  let code: string[] | null = null
  let table: string[][] | null = null

  const flushTable = () => {
    if (table) {
      const k = `t${blocks.length}`
      const [head, ...body] = table
      blocks.push(
        <div key={k} className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr>{head.map((c, i) => (
                <th key={i} className="border-b border-border px-2 py-1.5 font-semibold">{inline(c, `${k}-h${i}`)}</th>
              ))}</tr>
            </thead>
            <tbody>{body.map((r, ri) => (
              <tr key={ri} className="border-b border-border/50 align-top">{head.map((_, ci) => (
                <td key={ci} className="px-2 py-1.5">{inline(r[ci] ?? "", `${k}-${ri}-${ci}`)}</td>
              ))}</tr>
            ))}</tbody>
          </table>
        </div>)
      table = null
    }
  }

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

  for (let li = 0; li < lines.length; li++) {
    const raw = lines[li]
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
    if (table) {
      if (TABLE_ROW.test(line)) { table.push(cells(line)); continue }
      flushTable()
    }
    // A table starts with a header row immediately followed by a --- separator row
    if (TABLE_ROW.test(line) && TABLE_SEP.test(lines[li + 1] ?? "")) {
      flushPara(); flushList()
      table = [cells(line)]
      li++
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
  flushTable(); flushPara(); flushList()
  return <div className={`space-y-2 text-sm ${className}`}>{blocks}</div>
}
