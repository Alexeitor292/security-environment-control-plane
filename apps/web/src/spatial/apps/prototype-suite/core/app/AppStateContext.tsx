import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

/**
 * Prototype-local UI state. Persisted to localStorage for convenience.
 *
 * NOTE: `advancedMode` is a display preference only. Visibility and
 * permission are separate concerns — remembering this preference must never
 * grant authorization (see docs/09_DESIGN_DECISIONS.md).
 */
interface AppState {
  sidebarCollapsed: boolean
  toggleSidebar(): void
  advancedMode: boolean
  setAdvancedMode(on: boolean): void
  acknowledgedAlerts: string[]
  acknowledgeAlert(id: string): void
}

const STORAGE_KEY = 'secp-proto:ui-state'

interface PersistedState {
  sidebarCollapsed?: boolean
  advancedMode?: boolean
  acknowledgedAlerts?: string[]
}

function loadPersisted(): PersistedState {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as PersistedState) : {}
  } catch {
    return {}
  }
}

function persist(patch: PersistedState) {
  try {
    const next = { ...loadPersisted(), ...patch }
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next))
  } catch {
    // Storage unavailable — state stays session-only.
  }
}

const AppStateContext = createContext<AppState | undefined>(undefined)

export function AppStateProvider({ children }: { children: ReactNode }) {
  const initial = loadPersisted()
  const [sidebarCollapsed, setSidebarCollapsed] = useState(initial.sidebarCollapsed ?? false)
  const [advancedMode, setAdvancedModeState] = useState(initial.advancedMode ?? false)
  const [acknowledgedAlerts, setAcknowledgedAlerts] = useState<string[]>(
    initial.acknowledgedAlerts ?? [],
  )

  const toggleSidebar = useCallback(() => {
    setSidebarCollapsed((prev) => {
      persist({ sidebarCollapsed: !prev })
      return !prev
    })
  }, [])

  const setAdvancedMode = useCallback((on: boolean) => {
    setAdvancedModeState(on)
    persist({ advancedMode: on })
  }, [])

  const acknowledgeAlert = useCallback((id: string) => {
    setAcknowledgedAlerts((prev) => {
      if (prev.includes(id)) return prev
      const next = [...prev, id]
      persist({ acknowledgedAlerts: next })
      return next
    })
  }, [])

  const value = useMemo(
    () => ({
      sidebarCollapsed,
      toggleSidebar,
      advancedMode,
      setAdvancedMode,
      acknowledgedAlerts,
      acknowledgeAlert,
    }),
    [
      sidebarCollapsed,
      toggleSidebar,
      advancedMode,
      setAdvancedMode,
      acknowledgedAlerts,
      acknowledgeAlert,
    ],
  )

  return <AppStateContext.Provider value={value}>{children}</AppStateContext.Provider>
}

export function useAppState(): AppState {
  const ctx = useContext(AppStateContext)
  if (!ctx) throw new Error('useAppState must be used inside AppStateProvider')
  return ctx
}
