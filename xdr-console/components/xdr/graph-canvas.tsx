"use client"

/** React Flow canvas for layered entity graphs (attack paths, incident graphs). */

import { useMemo } from "react"
import { ReactFlow, Background, Controls, MarkerType, type Node, type Edge } from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import type { LayoutNode, LayoutEdge } from "@/lib/graph"
import { useTheme } from "@/components/theme-provider"

const KIND_STYLE: Record<string, { bg: string; border: string }> = {
  user: { bg: "#7c3aed", border: "#5b21b6" },
  host: { bg: "#e11d48", border: "#9f1239" },
  ip: { bg: "#0ea5e9", border: "#0369a1" },
  domain: { bg: "#f59e0b", border: "#b45309" },
  entity: { bg: "#475569", border: "#334155" },
}

const LAYER_GAP = 120   // vertical distance between hops
const ROW_GAP = 210     // horizontal distance between nodes in the same hop
const NODE_WIDTH = 180

/** Top-to-bottom layout: each hop is a row, nodes centered within it. */
export function GraphCanvas({ nodes, edges, height, onNodeClick }: {
  nodes: LayoutNode[]; edges: LayoutEdge[]; height?: number; onNodeClick?: (id: string) => void
}) {
  const { resolvedTheme } = useTheme()
  const dark = resolvedTheme === "dark"

  const perLayer = useMemo(() => {
    const m = new Map<number, number>()
    for (const n of nodes) m.set(n.layer, Math.max(m.get(n.layer) ?? 0, n.row + 1))
    return m
  }, [nodes])
  const layers = perLayer.size ? Math.max(...perLayer.keys()) + 1 : 1
  const h = height ?? Math.min(640, Math.max(260, layers * LAYER_GAP + 80))

  const rfNodes: Node[] = useMemo(() => nodes.map((n) => {
    const s = KIND_STYLE[n.kind] ?? KIND_STYLE.entity
    const count = perLayer.get(n.layer) ?? 1
    return {
      id: n.id,
      position: { x: (n.row - (count - 1) / 2) * ROW_GAP - NODE_WIDTH / 2, y: n.layer * LAYER_GAP },
      data: { label: n.label },
      sourcePosition: "bottom" as Node["sourcePosition"],
      targetPosition: "top" as Node["targetPosition"],
      style: {
        background: s.bg, color: "#fff", border: `2px solid ${n.start ? "#facc15" : s.border}`,
        borderRadius: 10, fontSize: 12, fontFamily: "ui-monospace, monospace", width: NODE_WIDTH, padding: 6,
        boxShadow: n.start ? "0 0 0 3px rgba(250,204,21,0.35)" : undefined,
      },
    }
  }), [nodes, perLayer])

  const rfEdges: Edge[] = useMemo(() => edges.map((e) => ({
    id: e.id, source: e.source, target: e.target, label: e.label || undefined,
    animated: e.suspicious,
    markerEnd: { type: MarkerType.ArrowClosed, color: e.suspicious ? "#e11d48" : "#94a3b8" },
    style: { stroke: e.suspicious ? "#e11d48" : "#94a3b8", strokeWidth: e.suspicious ? 2.2 : 1.4 },
    labelStyle: { fontSize: 10, fill: dark ? "#e2e8f0" : "#0f172a" },
    labelBgStyle: { fill: dark ? "#1e293b" : "#ffffff", fillOpacity: 0.9 },
  })), [edges, dark])

  return (
    <div className="overflow-hidden rounded-md border border-border" style={{ height: h }}>
      <ReactFlow
        nodes={rfNodes} edges={rfEdges} fitView fitViewOptions={{ padding: 0.12, maxZoom: 1.1 }}
        nodesConnectable={false} colorMode={dark ? "dark" : "light"} minZoom={0.2}
        onNodeClick={onNodeClick ? (_, n) => onNodeClick(n.id) : undefined}
      >
        <Background gap={20} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  )
}

export function GraphLegend() {
  return (
    <div className="flex flex-wrap gap-3 text-[11px] text-muted-foreground">
      {Object.entries({ user: "user", host: "host", ip: "IP", domain: "domain" }).map(([k, label]) => (
        <span key={k} className="inline-flex items-center gap-1">
          <span className="inline-block h-2.5 w-2.5 rounded-sm" style={{ background: KIND_STYLE[k].bg }} /> {label}
        </span>
      ))}
      <span className="inline-flex items-center gap-1"><span className="inline-block h-2.5 w-2.5 rounded-sm border-2 border-yellow-400" /> start / root</span>
      <span className="inline-flex items-center gap-1"><span className="inline-block h-0.5 w-4 bg-rose-600" /> suspicious path (animated)</span>
    </div>
  )
}
