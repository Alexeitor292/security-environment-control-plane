import type { CSSProperties, DragEvent } from 'react'
import { LiquidGlass } from '../components/liquid-glass'
import { SecpGlyph } from './SecpGlyph'
import type { SecpAppDefinition } from './shellTypes'

interface HomeAppIconProps {
  app: SecpAppDefinition
  draggable?: boolean
  isDragging?: boolean
  onOpen: () => void
  onDragStart?: (event: DragEvent<HTMLButtonElement>) => void
  onDragOver?: (event: DragEvent<HTMLButtonElement>) => void
  onDrop?: (event: DragEvent<HTMLButtonElement>) => void
  onDragEnd?: () => void
}

export function HomeAppIcon({
  app,
  draggable = false,
  isDragging = false,
  onOpen,
  onDragStart,
  onDragOver,
  onDrop,
  onDragEnd,
}: HomeAppIconProps) {
  return (
    <button
      className={['home-app', isDragging ? 'home-app--dragging' : ''].filter(Boolean).join(' ')}
      type="button"
      draggable={draggable}
      onClick={onOpen}
      onDragStart={onDragStart}
      onDragOver={onDragOver}
      onDrop={onDrop}
      onDragEnd={onDragEnd}
    >
      <LiquidGlass
        className="home-app__icon liquid-glass--interactive"
        style={{ '--app-accent': app.accent } as CSSProperties}
      >
        <SecpGlyph className="home-app__glyph" name={app.glyph} />
        {app.badge ? <span className="home-app__badge">{app.badge}</span> : null}
      </LiquidGlass>

      <span className="home-app__name">{app.name}</span>
    </button>
  )
}
