import { LiquidGlass } from '../../components/liquid-glass'
import './SettingsApp.css'

export type GlassStrength = 'subtle' | 'balanced' | 'strong'

interface SettingsAppProps {
  glassStrength: GlassStrength
  spatialMotion: boolean
  onGlassStrengthChange: (strength: GlassStrength) => void
  onSpatialMotionChange: (enabled: boolean) => void
}

export function SettingsApp({
  glassStrength,
  spatialMotion,
  onGlassStrengthChange,
  onSpatialMotionChange,
}: SettingsAppProps) {
  return (
    <div className="settings-app">
      <div className="settings-app__content">
        <header className="settings-app__header">
          <p>Personalization</p>
          <h1>Settings</h1>
          <span>Adjust the SECP Spatial OS experience.</span>
        </header>

        <LiquidGlass className="settings-panel liquid-glass--strong">
          <section className="settings-section">
            <div>
              <strong>Glass strength</strong>
              <span>Control how translucent and reflective system surfaces appear.</span>
            </div>

            <div className="segmented-control">
              {(['subtle', 'balanced', 'strong'] as const).map((strength) => (
                <button
                  className={glassStrength === strength ? 'is-active' : ''}
                  key={strength}
                  type="button"
                  onClick={() => onGlassStrengthChange(strength)}
                >
                  {strength}
                </button>
              ))}
            </div>
          </section>

          <section className="settings-section">
            <div>
              <strong>Spatial motion</strong>
              <span>Enable aurora movement and animated workspace transitions.</span>
            </div>

            <button
              className={['settings-switch', spatialMotion ? 'settings-switch--active' : '']
                .filter(Boolean)
                .join(' ')}
              type="button"
              aria-pressed={spatialMotion}
              onClick={() => onSpatialMotionChange(!spatialMotion)}
            >
              <span />
            </button>
          </section>

          <section className="settings-section settings-section--info">
            <div>
              <strong>Home layout</strong>
              <span>
                Drag app icons directly on the Home screen. Their order is saved automatically.
              </span>
            </div>
          </section>
        </LiquidGlass>
      </div>
    </div>
  )
}
