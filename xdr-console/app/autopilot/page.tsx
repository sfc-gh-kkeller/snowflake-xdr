import { Suspense } from "react"
import { Autopilot } from "@/components/views/autopilot"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Autopilot />
    </Suspense>
  )
}
