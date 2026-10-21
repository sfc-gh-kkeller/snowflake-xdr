import { Suspense } from "react"
import { Investigations } from "@/components/views/investigations"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Investigations />
    </Suspense>
  )
}
