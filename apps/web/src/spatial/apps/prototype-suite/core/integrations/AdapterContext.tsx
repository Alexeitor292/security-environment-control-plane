import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import type { ControlPlaneAdapter } from './adapter'
import { mockAdapter } from './mock-adapter'

const AdapterContext = createContext<ControlPlaneAdapter>(mockAdapter)

export function AdapterProvider({
  adapter = mockAdapter,
  children,
}: {
  adapter?: ControlPlaneAdapter
  children: ReactNode
}) {
  return <AdapterContext.Provider value={adapter}>{children}</AdapterContext.Provider>
}

export function useAdapter(): ControlPlaneAdapter {
  return useContext(AdapterContext)
}

export interface QueryState<T> {
  data: T | undefined
  loading: boolean
  error: string | undefined
}

/**
 * Minimal read-query hook over the adapter. Deliberately simple: the
 * prototype only reads fixture data. `deps` must capture everything the
 * fetcher closes over.
 */
export function useQuery<T>(
  fetcher: (adapter: ControlPlaneAdapter) => Promise<T>,
  deps: unknown[] = [],
): QueryState<T> {
  const adapter = useAdapter()
  const [state, setState] = useState<QueryState<T>>({
    data: undefined,
    loading: true,
    error: undefined,
  })

  useEffect(() => {
    let cancelled = false
    setState((prev) => ({ ...prev, loading: true, error: undefined }))
    fetcher(adapter)
      .then((data) => {
        if (!cancelled) setState({ data, loading: false, error: undefined })
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setState({
            data: undefined,
            loading: false,
            error: err instanceof Error ? err.message : 'request_failed',
          })
      })
    return () => {
      cancelled = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [adapter, ...deps])

  return useMemo(() => state, [state])
}
