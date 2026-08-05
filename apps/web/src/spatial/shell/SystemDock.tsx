import { useEffect, useState } from 'react'
import { AiCoreOrbButton } from '../components/ai-core/AiCoreOrb'
import { AiPromptBox } from '../components/ai-core/AiPromptBox'
import { LiquidGlass } from '../components/liquid-glass'
import { appById } from './appRegistry'
import { SecpGlyph } from './SecpGlyph'
import type { SecpAppId, SecpGlyphName } from './shellTypes'

interface SystemDockProps {
  activeApp: SecpAppId
  aiActive?: boolean
  onOpenApp: (appId: SecpAppId) => void
  onOpenAi: () => void
}

const leftDockApps: SecpAppId[] = ['home', 'infrastructure', 'cyber-ranges', 'scenarios']

const rightDockApps: SecpAppId[] = ['deployments', 'reports', 'administration', 'activity']

function getDockDefinition(appId: SecpAppId): {
  name: string
  glyph: SecpGlyphName
} {
  if (appId === 'home') {
    return {
      name: 'Home',
      glyph: 'home',
    }
  }

  if (appId === 'activity') {
    return {
      name: 'Activity',
      glyph: 'activity',
    }
  }

  const app = appById.get(appId as Exclude<SecpAppId, 'home' | 'activity'>)

  return {
    name: app?.shortName ?? appId,
    glyph: app?.glyph ?? 'activity',
  }
}

function DockApp({
  activeApp,
  appId,
  onOpenApp,
}: {
  activeApp: SecpAppId
  appId: SecpAppId
  onOpenApp: (appId: SecpAppId) => void
}) {
  const definition = getDockDefinition(appId)
  const isActive = activeApp === appId

  return (
    <button
      className={['dock-app', isActive ? 'dock-app--active' : ''].filter(Boolean).join(' ')}
      type="button"
      title={definition.name}
      aria-current={isActive ? 'page' : undefined}
      onClick={() => onOpenApp(appId)}
    >
      <span className="dock-app__icon">
        <SecpGlyph name={definition.glyph} />
      </span>

      <span className="dock-app__label">{definition.name}</span>

      <span className="dock-app__indicator" />
    </button>
  )
}

export function SystemDock({ activeApp, aiActive = false, onOpenApp, onOpenAi }: SystemDockProps) {
  const [promptOpen, setPromptOpen] = useState(false)

  useEffect(() => {
    if (aiActive) {
      setPromptOpen(false)
    }
  }, [aiActive])

  const activeDefinition = getDockDefinition(activeApp)

  return (
    <div className="system-dock-shell">
      <div className="system-dock__prompt">
        <AiPromptBox
          contextLabel={activeDefinition.name}
          open={promptOpen}
          onClose={() => setPromptOpen(false)}
          onOpenFullAi={() => {
            setPromptOpen(false)
            onOpenAi()
          }}
        />
      </div>

      <LiquidGlass className="system-dock liquid-glass--strong">
        <nav className="system-dock__content" aria-label="SECP dock">
          <div className="system-dock__group">
            {leftDockApps.map((appId) => (
              <DockApp activeApp={activeApp} appId={appId} key={appId} onOpenApp={onOpenApp} />
            ))}
          </div>

          <span className="system-dock__core-space" aria-hidden="true" />

          <div className="system-dock__group">
            {rightDockApps.map((appId) => (
              <DockApp activeApp={activeApp} appId={appId} key={appId} onOpenApp={onOpenApp} />
            ))}
          </div>
        </nav>
      </LiquidGlass>

      <div className="system-dock__ai-core">
        <AiCoreOrbButton
          active={promptOpen || aiActive}
          label={promptOpen ? 'Close SECP Core' : aiActive ? 'SECP Core active' : 'Ask SECP'}
          onClick={() => {
            if (aiActive) {
              onOpenAi()
              return
            }

            setPromptOpen((current) => !current)
          }}
        />
      </div>
    </div>
  )
}
