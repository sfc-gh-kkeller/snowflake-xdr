import { Suspense } from "react"
import { Entity360 } from "@/components/views/entity"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Entity360 />
    </Suspense>
  )
}
