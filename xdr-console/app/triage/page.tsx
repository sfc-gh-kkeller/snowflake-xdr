import { Suspense } from "react"
import { Triage } from "@/components/views/triage"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Triage />
    </Suspense>
  )
}
