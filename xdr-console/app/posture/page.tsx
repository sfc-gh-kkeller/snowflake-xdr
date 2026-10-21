import { Suspense } from "react"
import { Posture } from "@/components/views/posture"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Posture />
    </Suspense>
  )
}
