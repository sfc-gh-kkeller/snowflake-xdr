import { Suspense } from "react"
import { Cases } from "@/components/views/cases"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <Cases />
    </Suspense>
  )
}
