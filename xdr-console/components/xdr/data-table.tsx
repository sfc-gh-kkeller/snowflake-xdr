"use client"

/**
 * DataTable — the console's result grid. Sortable headers, optional row
 * checkboxes (bulk actions), row click to open a detail view, sticky header.
 */

import React, { useMemo, useState } from "react"
import { ArrowDown, ArrowUp } from "lucide-react"
import { cn } from "@/lib/utils"
import { Empty } from "@/components/xdr/kit"
import type { Row } from "@/lib/client"

export interface Column {
  key: string
  label: string
  render?: (row: Row) => React.ReactNode
  align?: "left" | "right" | "center"
  className?: string
  /** Value used for sorting when render() shows something else. */
  sortValue?: (row: Row) => unknown
  sortable?: boolean
  /** Allow this column's text to wrap (others stay on one line). */
  wrap?: boolean
}

export function DataTable({
  columns, rows, rowKey, onRowClick, selectedKey, selectable, selected, onSelectedChange,
  maxHeight = 520, empty = "No rows.", dense = false,
}: {
  columns: Column[]
  rows: Row[]
  rowKey?: string
  onRowClick?: (row: Row) => void
  selectedKey?: string | null
  selectable?: boolean
  selected?: string[]
  onSelectedChange?: (keys: string[]) => void
  maxHeight?: number
  empty?: React.ReactNode
  dense?: boolean
}) {
  const [sort, setSort] = useState<{ key: string; dir: 1 | -1 } | null>(null)
  const keyOf = (r: Row, i: number) => String(rowKey ? r[rowKey] : i)

  const sorted = useMemo(() => {
    if (!sort) return rows
    const col = columns.find((c) => c.key === sort.key)
    const val = (r: Row) => (col?.sortValue ? col.sortValue(r) : r[sort.key])
    return [...rows].sort((a, b) => {
      const va = val(a), vb = val(b)
      if (va === vb) return 0
      if (va === null || va === undefined) return 1
      if (vb === null || vb === undefined) return -1
      const na = Number(va), nb = Number(vb)
      const cmp = !Number.isNaN(na) && !Number.isNaN(nb) && typeof va !== "string"
        ? na - nb : String(va).localeCompare(String(vb))
      return cmp * sort.dir
    })
  }, [rows, sort, columns])

  if (!rows.length) return <Empty>{empty}</Empty>

  const sel = new Set(selected ?? [])
  const allKeys = sorted.map(keyOf)
  const allOn = allKeys.length > 0 && allKeys.every((k) => sel.has(k))
  const pad = dense ? "px-2 py-1" : "px-3 py-1.5"

  return (
    <div className="overflow-auto rounded-md border border-border" style={{ maxHeight }}>
      <table className="w-full border-collapse text-sm">
        <thead className="sticky top-0 z-10 bg-muted/95 backdrop-blur">
          <tr>
            {selectable && (
              <th className={cn(pad, "w-8 text-left")}>
                <input
                  type="checkbox" checked={allOn} aria-label="Select all"
                  onChange={() => onSelectedChange?.(allOn ? [] : allKeys)}
                />
              </th>
            )}
            {columns.map((c) => {
              const active = sort?.key === c.key
              const canSort = c.sortable !== false
              return (
                <th
                  key={c.key}
                  className={cn(pad, "whitespace-nowrap text-xs font-semibold text-muted-foreground",
                    c.align === "right" ? "text-right" : c.align === "center" ? "text-center" : "text-left",
                    canSort && "cursor-pointer select-none hover:text-foreground")}
                  onClick={() => canSort && setSort(active ? (sort!.dir === -1 ? { key: c.key, dir: 1 } : null) : { key: c.key, dir: -1 })}
                >
                  <span className="inline-flex items-center gap-1">
                    {c.label}
                    {active && (sort!.dir === -1 ? <ArrowDown className="h-3 w-3" /> : <ArrowUp className="h-3 w-3" />)}
                  </span>
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r, i) => {
            const k = keyOf(r, i)
            return (
              <tr
                key={k}
                onClick={onRowClick ? () => onRowClick(r) : undefined}
                className={cn("border-t border-border",
                  onRowClick && "cursor-pointer hover:bg-muted/60",
                  selectedKey && selectedKey === k && "bg-primary/10 hover:bg-primary/15")}
              >
                {selectable && (
                  <td className={cn(pad, "align-middle")} onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox" checked={sel.has(k)} aria-label="Select row"
                      onChange={() => onSelectedChange?.(sel.has(k) ? [...sel].filter((x) => x !== k) : [...sel, k])}
                    />
                  </td>
                )}
                {columns.map((c) => (
                  <td
                    key={c.key}
                    className={cn(pad, "align-middle",
                      c.wrap ? "min-w-[16rem] whitespace-normal" : "whitespace-nowrap",
                      c.align === "right" ? "text-right tabular-nums" : c.align === "center" ? "text-center" : "",
                      c.className)}
                  >
                    {c.render ? c.render(r) : formatCell(r[c.key])}
                  </td>
                ))}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function formatCell(v: unknown): React.ReactNode {
  if (v === null || v === undefined || v === "") return <span className="text-muted-foreground">–</span>
  if (typeof v === "boolean") return v ? "yes" : "no"
  if (typeof v === "object") return <code className="text-xs">{JSON.stringify(v).slice(0, 120)}</code>
  return String(v)
}
