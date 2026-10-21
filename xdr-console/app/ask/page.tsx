import { Suspense } from "react"
import { AskXdr } from "@/components/views/ask"
import { Loading } from "@/components/xdr/kit"

export const dynamic = "force-dynamic"

export default function Page() {
  return (
    <Suspense fallback={<Loading />}>
      <AskXdr />
    </Suspense>
  )
}
