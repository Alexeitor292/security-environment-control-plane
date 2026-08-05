import { Outlet } from 'react-router-dom'
import { WorkspaceTabs } from '../components'
import type { RouteTabDef } from '../components'

interface SectionLayoutProps {
  title: string
  tabs: RouteTabDef[]
  onAddInfrastructure?: () => void
}

export function SectionLayout({ title, tabs, onAddInfrastructure }: SectionLayoutProps) {
  return (
    <div className="l-workspace">
      <header className="l-workspace__head">
        <div className="prototype-section-title-row">
          <h1>{title}</h1>

          {title === 'Infrastructure' && onAddInfrastructure ? (
            <button className="prototype-enroll-link" type="button" onClick={onAddInfrastructure}>
              Add infrastructure
            </button>
          ) : null}
        </div>

        <WorkspaceTabs tabs={tabs} />
      </header>

      <Outlet />
    </div>
  )
}

export function InfrastructureLayout({
  onAddInfrastructure,
}: {
  onAddInfrastructure?: () => void
}) {
  return (
    <SectionLayout
      title="Infrastructure"
      onAddInfrastructure={onAddInfrastructure}
      tabs={[
        {
          to: '/infrastructure/targets',
          label: 'Targets',
        },
        {
          to: '/infrastructure/placement',
          label: 'Capacity & Placement',
        },
        {
          to: '/infrastructure/workers',
          label: 'Workers',
        },
        {
          to: '/infrastructure/providers',
          label: 'Providers & Plugins',
        },
        {
          to: '/infrastructure/inventory',
          label: 'Inventory & Discovery',
        },
      ]}
    />
  )
}

export function PlatformLayout() {
  return (
    <SectionLayout
      title="Platform"
      tabs={[
        {
          to: '/platform',
          label: 'Overview',
          end: true,
        },
        {
          to: '/platform/organizations',
          label: 'Organizations & Teams',
        },
        {
          to: '/platform/identity',
          label: 'Identity & Access',
        },
        {
          to: '/platform/secrets',
          label: 'Secrets & Credentials',
        },
        {
          to: '/platform/workflows',
          label: 'Workflow Engine',
        },
        {
          to: '/platform/integrations',
          label: 'Integrations',
        },
        {
          to: '/platform/audit',
          label: 'Audit & Evidence',
        },
        {
          to: '/platform/settings',
          label: 'Settings',
        },
        {
          to: '/platform/retention',
          label: 'Retention & Backup',
        },
      ]}
    />
  )
}
