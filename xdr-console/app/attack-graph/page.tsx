import { Suspense } from "react"
import { AttackGraph } from "@/components/views/attack-graph"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <AttackGraph />
    </Suspense>
  )
}
