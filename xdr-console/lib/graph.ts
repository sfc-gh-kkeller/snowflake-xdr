/**
 * Pure graph layout helpers (no React) shared by the attack-graph and
 * incident views. Nodes get a layer (left-to-right hop distance) and a row.
 */

export interface LayoutNode { id: string; label: string; layer: number; row: number; start: boolean; kind: string }
export interface LayoutEdge { id: string; source: string; target: string; label: string; suspicious: boolean }

export function entityKind(id: string): string {
  if (id.startsWith("user:")) return "user"
  if (id.startsWith("host:")) return "host"
  if (id.startsWith("domain:")) return "domain"
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(id)) return "ip"
  return "entity"
}

/**
 * Layer a directed edge list: roots (no inbound edges) sit in layer 0 and
 * every other node one layer past its nearest predecessor (BFS). Cycles are
 * safe — each node is placed once.
 */
export function layoutEdges(
  edges: { source: string; target: string; label?: string; suspicious?: boolean }[],
): { nodes: LayoutNode[]; edges: LayoutEdge[] } {
  const ids = new Set<string>()
  const inbound = new Map<string, number>()
  const out = new Map<string, string[]>()
  const edgeMap = new Map<string, LayoutEdge>()
  for (const e of edges) {
    ids.add(e.source); ids.add(e.target)
    inbound.set(e.target, (inbound.get(e.target) ?? 0) + 1)
    out.set(e.source, [...(out.get(e.source) ?? []), e.target])
    const key = `${e.source}->${e.target}`
    if (!edgeMap.has(key)) {
      edgeMap.set(key, { id: key, source: e.source, target: e.target, label: e.label ?? "", suspicious: Boolean(e.suspicious) })
    }
  }
  const layer = new Map<string, number>()
  let roots = [...ids].filter((n) => !inbound.get(n))
  if (!roots.length && ids.size) roots = [[...ids].sort()[0]]
  const queue: string[] = []
  for (const r of roots) { layer.set(r, 0); queue.push(r) }
  while (queue.length) {
    const n = queue.shift() as string
    for (const t of out.get(n) ?? []) {
      if (!layer.has(t)) { layer.set(t, (layer.get(n) as number) + 1); queue.push(t) }
    }
  }
  // Anything unreachable from a root (inside a pure cycle) goes to layer 0
  for (const n of ids) if (!layer.has(n)) layer.set(n, 0)

  const rowsPerLayer = new Map<number, number>()
  const nodes = [...ids]
    .sort((a, b) => (layer.get(a)! - layer.get(b)!) || a.localeCompare(b))
    .map((n) => {
      const l = layer.get(n) as number
      const row = rowsPerLayer.get(l) ?? 0
      rowsPerLayer.set(l, row + 1)
      return { id: n, label: n, layer: l, row, start: l === 0, kind: entityKind(n) }
    })
  return { nodes, edges: [...edgeMap.values()] }
}
