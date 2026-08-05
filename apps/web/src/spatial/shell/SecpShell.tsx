import { useEffect, useState } from 'react'
import type { GlassStrength } from '../apps/settings/SettingsApp'
import { CommandMenuOverlay } from '../components/ai-core'
import { LiquidGlassFilter } from '../components/liquid-glass'
import { DynamicIsland } from './DynamicIsland'
import { SecpAppHost } from './SecpAppHost'
import { SecpHome } from './SecpHome'
import { shellActivities } from './shellData'
import { SystemDock } from './SystemDock'
import type { SecpAppId } from './shellTypes'
import './SecpShell.css'
const glassStorageKey = 'secp-spatial-os-glass-strength'
const motionStorageKey = 'secp-spatial-os-motion'

function loadGlassStrength(): GlassStrength {
  const value = window.localStorage.getItem(glassStorageKey)
  return value === 'subtle' || value === 'strong' ? value : 'balanced'
}

function loadSpatialMotion() {
  return window.localStorage.getItem(motionStorageKey) !== 'false'
}

export function SecpShell() {
  const [activeApp, setActiveApp] = useState<SecpAppId>('home')
  const [activeEntry, setActiveEntry] = useState<string>()
  const [notchExpanded, setNotchExpanded] = useState(false)
  const [commandMenuOpen, setCommandMenuOpen] = useState(false)
  const [glassStrength, setGlassStrength] = useState<GlassStrength>(loadGlassStrength)
  const [spatialMotion, setSpatialMotion] = useState(loadSpatialMotion)

  useEffect(() => {
    window.localStorage.setItem(glassStorageKey, glassStrength)
  }, [glassStrength])

  useEffect(() => {
    window.localStorage.setItem(motionStorageKey, String(spatialMotion))
  }, [spatialMotion])

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      const target = event.target
      const userIsTyping =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement ||
        (target instanceof HTMLElement && target.isContentEditable)

      if (userIsTyping) {
        return
      }

      if (event.key.toLowerCase() === 'k' && (event.ctrlKey || event.metaKey) && event.shiftKey) {
        event.preventDefault()
        setCommandMenuOpen((current) => !current)
      }

      if (event.key === 'Escape') {
        if (commandMenuOpen) {
          setCommandMenuOpen(false)
          return
        }

        if (notchExpanded) {
          setNotchExpanded(false)
          return
        }

        if (activeApp !== 'home') {
          setActiveApp('home')
        }
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [activeApp, commandMenuOpen, notchExpanded])

  function openApp(appId: SecpAppId, entry?: string) {
    if (appId === 'ai-operations') {
      setCommandMenuOpen(true)
      return
    }

    setNotchExpanded(false)
    setActiveEntry(entry)
    setActiveApp(appId)
  }

  return (
    <main
      className={[
        'secp-shell',
        `secp-shell--glass-${glassStrength}`,
        spatialMotion ? 'secp-shell--motion' : 'secp-shell--motion-off',
        activeApp === 'home' ? 'secp-shell--home' : 'secp-shell--app-open',
        commandMenuOpen ? 'secp-shell--command-open' : '',
      ]
        .filter(Boolean)
        .join(' ')}
    >
      <LiquidGlassFilter />

      <div className="secp-wallpaper" aria-hidden="true">
        <span className="secp-wallpaper__aurora secp-wallpaper__aurora--one" />
        <span className="secp-wallpaper__aurora secp-wallpaper__aurora--two" />
        <span className="secp-wallpaper__grid" />
        <span className="secp-wallpaper__core" />
      </div>

      <div className="secp-shell__notch">
        <DynamicIsland
          activeApp={activeApp}
          activities={shellActivities}
          expanded={notchExpanded}
          onToggle={() => setNotchExpanded((current) => !current)}
          onOpenActivity={() => openApp('activity')}

          onSearchNavigate={(appId, entry) => openApp(appId, entry)}
        />
      </div>

      <section className="secp-shell__workspace">
        <div className="secp-home-stage" aria-hidden={activeApp !== 'home'}>
          <SecpHome onOpenApp={openApp} onOpenAi={() => setCommandMenuOpen(true)} />
        </div>

        <div className="secp-app-stage" aria-hidden={activeApp === 'home'}>
          {activeApp !== 'home' ? (
            <SecpAppHost
              activeApp={activeApp}
              activities={shellActivities}
              glassStrength={glassStrength}
              spatialMotion={spatialMotion}
              onGlassStrengthChange={setGlassStrength}
              onSpatialMotionChange={setSpatialMotion}

              key={`${activeApp}:${activeEntry ?? ''}`}

              activeEntry={activeEntry}
            />
          ) : null}
        </div>
      </section>

      <div className="secp-shell__dock">
        <SystemDock
          activeApp={activeApp}
          onOpenApp={openApp}
          onOpenAi={() => setCommandMenuOpen(true)}
          aiActive={commandMenuOpen}
        />
      </div>

      <CommandMenuOverlay open={commandMenuOpen} onClose={() => setCommandMenuOpen(false)} />
    </main>
  )
}
