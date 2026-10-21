import { Suspense } from "react"
import { Response } from "@/components/views/response"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Response />
    </Suspense>
  )
}
