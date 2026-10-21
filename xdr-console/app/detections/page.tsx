import { Suspense } from "react"
import { Detections } from "@/components/views/detections"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Detections />
    </Suspense>
  )
}
