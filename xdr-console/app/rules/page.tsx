import { Suspense } from "react"
import { Rules } from "@/components/views/rules"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Rules />
    </Suspense>
  )
}
