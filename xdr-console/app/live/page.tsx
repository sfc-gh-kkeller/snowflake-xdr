import { Suspense } from "react"
import { LiveTail } from "@/components/views/live"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <LiveTail />
    </Suspense>
  )
}
