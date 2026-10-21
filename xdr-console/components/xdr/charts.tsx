"use client"

/** Recharts wrappers with the console's theming and the template's tooltip. */

import React from "react"
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  AreaChart, Area, Cell,
} from "recharts"
import { ChartTooltip, getYAxisWidth, formatTick } from "@/components/chart-utils"

const AXIS = { fontSize: 11, fill: "var(--muted-foreground)" }
export const PALETTE = ["#e11d48", "#f97316", "#eab308", "#0ea5e9", "#8b5cf6", "#14b8a6", "#64748b", "#ec4899"]

export interface Series { key: string; label: string; color: string }

export function StackedBars({ data, xKey, series, height = 240, xFormat }: {
  data: Record<string, unknown>[]; xKey: string; series: Series[]; height?: number
  xFormat?: (v: unknown) => string
}) {
  const totals = data.map((d) => ({ t: series.reduce((s, x) => s + (Number(d[x.key]) || 0), 0) }))
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
        <XAxis dataKey={xKey} tick={AXIS} tickFormatter={xFormat} minTickGap={24} />
        <YAxis tick={AXIS} width={getYAxisWidth(totals, "t")} tickFormatter={formatTick} allowDecimals={false} />
        <Tooltip content={<ChartTooltip />} labelFormatter={xFormat} cursor={{ fill: "var(--muted)" }} />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        {series.map((s) => <Bar key={s.key} dataKey={s.key} name={s.label} stackId="a" fill={s.color} />)}
      </BarChart>
    </ResponsiveContainer>
  )
}

/** Horizontal bars for ranked categories; per-bar colors optional. */
export function RankBars({ data, labelKey, valueKey, height, colors, valueLabel = "count" }: {
  data: Record<string, unknown>[]; labelKey: string; valueKey: string; height?: number
  colors?: string[]; valueLabel?: string
}) {
  const h = height ?? Math.max(120, data.length * 30 + 20)
  const labelWidth = Math.min(160, Math.max(60, ...data.map((d) => String(d[labelKey] ?? "").length * 7)))
  return (
    <ResponsiveContainer width="100%" height={h}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, bottom: 0, left: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
        <XAxis type="number" tick={AXIS} tickFormatter={formatTick} allowDecimals={false} />
        <YAxis type="category" dataKey={labelKey} tick={AXIS} width={labelWidth} />
        <Tooltip content={<ChartTooltip />} cursor={{ fill: "var(--muted)" }} />
        <Bar dataKey={valueKey} name={valueLabel} radius={[0, 4, 4, 0]}>
          {data.map((_, i) => <Cell key={i} fill={colors?.[i] ?? PALETTE[i % PALETTE.length]} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function TrendArea({ data, xKey, series, height = 220, xFormat }: {
  data: Record<string, unknown>[]; xKey: string; series: Series[]; height?: number
  xFormat?: (v: unknown) => string
}) {
  const maxRow = data.map((d) => ({ t: Math.max(...series.map((s) => Number(d[s.key]) || 0)) }))
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
        <XAxis dataKey={xKey} tick={AXIS} tickFormatter={xFormat} minTickGap={24} />
        <YAxis tick={AXIS} width={getYAxisWidth(maxRow, "t")} tickFormatter={formatTick} allowDecimals={false} />
        <Tooltip content={<ChartTooltip />} labelFormatter={xFormat} />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        {series.map((s) => (
          <Area key={s.key} type="monotone" dataKey={s.key} name={s.label} stroke={s.color} fill={s.color} fillOpacity={0.15} strokeWidth={2} />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  )
}
