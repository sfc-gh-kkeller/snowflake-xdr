import { Suspense } from "react"
import { Intel } from "@/components/views/intel"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Intel />
    </Suspense>
  )
}
