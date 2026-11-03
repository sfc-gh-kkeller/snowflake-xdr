import { Suspense } from "react"
import { Mission } from "@/components/views/mission"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Mission />
    </Suspense>
  )
}
