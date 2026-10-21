import { Suspense } from "react"
import { Hunt } from "@/components/views/hunt"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Hunt />
    </Suspense>
  )
}
