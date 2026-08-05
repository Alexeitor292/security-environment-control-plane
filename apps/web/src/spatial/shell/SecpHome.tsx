import { HomeAppGrid } from './HomeAppGrid'
import { WidgetGrid } from './WidgetGrid'
import type { SecpAppId } from './shellTypes'

interface SecpHomeProps {
  onOpenApp: (appId: SecpAppId) => void
  onOpenAi: () => void
}

export function SecpHome({ onOpenApp, onOpenAi }: SecpHomeProps) {
  return (
    <div className="secp-home">
      <header className="secp-home__intro">
        <p>SECP Spatial OS</p>
        <h1>Good evening, Juan</h1>
        <span>Your security environments are ready.</span>
      </header>

      <WidgetGrid onOpenApp={onOpenApp} onOpenAi={onOpenAi} />

      <HomeAppGrid onOpenApp={onOpenApp} />

      <div className="home-page-dots" aria-label="Home page 1 of 3">
        <span className="home-page-dot home-page-dot--active" />
        <span className="home-page-dot" />
        <span className="home-page-dot" />
      </div>
    </div>
  )
}
