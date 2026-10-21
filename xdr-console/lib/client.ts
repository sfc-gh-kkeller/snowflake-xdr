"use client"

/**
 * Client hooks for the XDR API. Components call named server handlers;
 * they never build SQL.
 *
 *   const { data } = useXdr<Row[]>("triage.list", { statuses: ["new"] })
 *   const update = useXdrAction("triage.update", { invalidate: ["triage."] })
 */

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

export type Row = Record<string, any>

export async function callXdr<T = unknown>(name: string, params: Record<string, unknown> = {}): Promise<T> {
  const res = await fetch(`/api/xdr/${encodeURIComponent(name)}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  })
  let body: { data?: T; error?: string } = {}
  try {
    body = await res.json()
  } catch {
    throw new Error(`Request failed (HTTP ${res.status})`)
  }
  if (!res.ok || body.error) throw new Error(body.error ?? `Request failed (HTTP ${res.status})`)
  return body.data as T
}

export function useXdr<T = Row[]>(
  name: string,
  params: Record<string, unknown> = {},
  opts: { enabled?: boolean; refetchInterval?: number | false; staleTime?: number } = {},
) {
  return useQuery<T, Error>({
    queryKey: [name, params],
    queryFn: () => callXdr<T>(name, params),
    enabled: opts.enabled ?? true,
    refetchInterval: opts.refetchInterval ?? false,
    staleTime: opts.staleTime ?? 30_000,
    refetchOnWindowFocus: false,
    retry: 1,
  })
}

/**
 * Mutation for an action handler. `invalidate` lists handler-name prefixes
 * whose cached queries are refetched on success (e.g. "triage.").
 */
export function useXdrAction<T = { message?: string }>(name: string, opts: { invalidate?: string[] } = {}) {
  const qc = useQueryClient()
  return useMutation<T, Error, Record<string, unknown> | void>({
    mutationFn: (params) => callXdr<T>(name, params ?? {}),
    onSuccess: () => {
      const prefixes = opts.invalidate ?? []
      if (prefixes.length) {
        qc.invalidateQueries({
          predicate: (q) => prefixes.some((p) => String(q.queryKey[0]).startsWith(p)),
        })
      }
    },
  })
}
