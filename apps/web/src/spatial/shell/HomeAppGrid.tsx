import { type DragEvent, useEffect, useMemo, useState } from 'react'
import { secpApps } from './appRegistry'
import { initialAppOrder } from './shellData'
import { HomeAppIcon } from './HomeAppIcon'
import type { SecpAppId } from './shellTypes'

interface HomeAppGridProps {
  onOpenApp: (appId: SecpAppId) => void
}

const storageKey = 'secp-spatial-os-app-order'

function loadOrder() {
  try {
    const stored = window.localStorage.getItem(storageKey)
    if (!stored) {
      return [...initialAppOrder]
    }

    const parsed = JSON.parse(stored)
    if (!Array.isArray(parsed)) {
      return [...initialAppOrder]
    }

    type HomeAppId = (typeof initialAppOrder)[number]

    const validIds = new Set<string>(secpApps.map((app) => app.id))

    const filtered = parsed.filter(
      (id: unknown): id is HomeAppId => typeof id === 'string' && validIds.has(id),
    )

    for (const id of initialAppOrder) {
      if (!filtered.includes(id)) {
        filtered.push(id)
      }
    }

    return filtered
  } catch {
    return [...initialAppOrder]
  }
}

export function HomeAppGrid({ onOpenApp }: HomeAppGridProps) {
  const [order, setOrder] = useState(loadOrder)
  const [draggingId, setDraggingId] = useState<string | null>(null)

  useEffect(() => {
    window.localStorage.setItem(storageKey, JSON.stringify(order))
  }, [order])

  const orderedApps = useMemo(() => {
    const appLookup = new Map(secpApps.map((app) => [app.id, app]))
    return order.map((id) => appLookup.get(id)).filter(Boolean)
  }, [order])

  function handleDrop(event: DragEvent<HTMLButtonElement>, targetId: string) {
    event.preventDefault()

    if (!draggingId || draggingId === targetId) {
      setDraggingId(null)
      return
    }

    setOrder((current) => {
      const next = [...current]
      const sourceIndex = next.indexOf(draggingId as (typeof initialAppOrder)[number])
      const targetIndex = next.indexOf(targetId as (typeof initialAppOrder)[number])

      if (sourceIndex < 0 || targetIndex < 0) {
        return current
      }

      const [moved] = next.splice(sourceIndex, 1)
      next.splice(targetIndex, 0, moved)
      return next
    })

    setDraggingId(null)
  }

  return (
    <section className="home-app-grid" aria-label="SECP applications">
      {orderedApps.map((app) =>
        app ? (
          <HomeAppIcon
            key={app.id}
            app={app}
            draggable
            isDragging={draggingId === app.id}
            onOpen={() => onOpenApp(app.id)}
            onDragStart={(event) => {
              setDraggingId(app.id)
              event.dataTransfer.effectAllowed = 'move'
              event.dataTransfer.setData('text/plain', app.id)
            }}
            onDragOver={(event) => {
              event.preventDefault()
              event.dataTransfer.dropEffect = 'move'
            }}
            onDrop={(event) => handleDrop(event, app.id)}
            onDragEnd={() => setDraggingId(null)}
          />
        ) : null,
      )}
    </section>
  )
}
