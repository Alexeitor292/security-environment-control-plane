import { NavLink } from 'react-router-dom'
import { clsx } from 'clsx'

export interface TabDef {
  key: string
  label: string
}

/** Local-state tabs (in-page sections). */
export function Tabs({
  tabs,
  active,
  onSelect,
}: {
  tabs: TabDef[]
  active: string
  onSelect: (key: string) => void
}) {
  return (
    <div className="c-tabs" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.key}
          role="tab"
          type="button"
          aria-selected={tab.key === active}
          className={clsx('c-tabs__tab', tab.key === active && 'is-active')}
          onClick={() => onSelect(tab.key)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  )
}

export interface RouteTabDef {
  to: string
  label: string
  end?: boolean
}

/**
 * Replaceable slot: contextual workspace tabs (event/scenario/deployment
 * workspaces). Router-driven so tabs are deep-linkable.
 */
export function WorkspaceTabs({ tabs }: { tabs: RouteTabDef[] }) {
  return (
    <nav className="c-tabs c-tabs--workspace" aria-label="Workspace sections">
      {tabs.map((tab) => (
        <NavLink
          key={tab.to}
          to={tab.to}
          end={tab.end}
          className={({ isActive }) => clsx('c-tabs__tab', isActive && 'is-active')}
        >
          {tab.label}
        </NavLink>
      ))}
    </nav>
  )
}
