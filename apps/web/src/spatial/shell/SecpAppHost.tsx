import { ActivityApp } from '../apps/activity/ActivityApp'
import { AdministrationApp } from '../apps/administration/AdministrationApp'
import { CyberRangesApp } from '../apps/cyber-ranges/CyberRangesApp'
import { DeploymentsApp } from '../apps/deployments/DeploymentsApp'
import { InfrastructureApp } from '../apps/infrastructure/InfrastructureApp'
import { ReportsApp } from '../apps/reports/ReportsApp'
import { ScenariosApp } from '../apps/scenarios/ScenariosApp'
import { type GlassStrength, SettingsApp } from '../apps/settings/SettingsApp'
import { LiquidGlass } from '../components/liquid-glass'
import { appById } from './appRegistry'
import { SecpGlyph } from './SecpGlyph'
import type { ShellActivity } from './shellData'
import type { SecpAppId, SecpGlyphName } from './shellTypes'

interface SecpAppHostProps {
  activeApp: SecpAppId
  activeEntry?: string
  activities: ShellActivity[]
  glassStrength: GlassStrength
  spatialMotion: boolean
  onGlassStrengthChange: (strength: GlassStrength) => void
  onSpatialMotionChange: (enabled: boolean) => void
}

export function SecpAppHost({
  activeApp,
  activeEntry,
  activities,
  glassStrength,
  spatialMotion,
  onGlassStrengthChange,
  onSpatialMotionChange,
}: SecpAppHostProps) {
  if (activeApp === 'infrastructure' || activeApp === 'environments' || activeApp === 'discovery') {
    return <InfrastructureApp initialEntry={activeEntry ?? '/infrastructure/targets'} />
  }

  if (activeApp === 'cyber-ranges') {
    return <CyberRangesApp initialEntry={activeEntry ?? '/events'} />
  }

  if (activeApp === 'scenarios') {
    return <ScenariosApp initialEntry={activeEntry ?? '/scenarios'} />
  }

  if (activeApp === 'deployments' || activeApp === 'network-map') {
    return <DeploymentsApp initialEntry={activeEntry ?? '/deployments'} />
  }

  if (activeApp === 'reports') {
    return <ReportsApp initialEntry={activeEntry ?? '/reports'} />
  }

  if (
    activeApp === 'administration' ||
    activeApp === 'integrations' ||
    activeApp === 'evidence' ||
    activeApp === 'ai-operations'
  ) {
    return <AdministrationApp initialEntry={activeEntry ?? '/platform'} />
  }

  if (activeApp === 'activity') {
    return <ActivityApp activities={activities} />
  }

  if (activeApp === 'settings') {
    return (
      <SettingsApp
        glassStrength={glassStrength}
        spatialMotion={spatialMotion}
        onGlassStrengthChange={onGlassStrengthChange}
        onSpatialMotionChange={onSpatialMotionChange}
      />
    )
  }

  const app =
    activeApp === 'home' ? null : appById.get(activeApp as Exclude<SecpAppId, 'home' | 'activity'>)

  const glyph: SecpGlyphName = app?.glyph ?? 'activity'

  return (
    <div className="placeholder-app">
      <LiquidGlass className="placeholder-app__panel liquid-glass--strong">
        <span className="placeholder-app__icon">
          <SecpGlyph name={glyph} />
        </span>

        <p>SECP application</p>
        <h2>{app?.name ?? 'Application'}</h2>

        <span>{app?.description ?? 'This operational workspace is ready for implementation.'}</span>
      </LiquidGlass>
    </div>
  )
}
