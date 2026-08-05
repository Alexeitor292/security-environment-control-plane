import { useEffect } from 'react'

interface CommandMenuOverlayProps {
  open: boolean
  onClose: () => void
}

const commands = [
  {
    key: 'N',
    title: 'Enroll infrastructure',
    description: 'Connect a new Proxmox or on-prem environment.',
  },
  {
    key: 'D',
    title: 'Open discovery',
    description: 'Review controlled infrastructure discovery.',
  },
  {
    key: 'W',
    title: 'Workers',
    description: 'Inspect enrolled workers and their current state.',
  },
  {
    key: 'E',
    title: 'Evidence',
    description: 'Review signed evidence and validation records.',
  },
]

export function CommandMenuOverlay({ open, onClose }: CommandMenuOverlayProps) {
  useEffect(() => {
    if (!open) {
      return
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        onClose()
      }
    }

    window.addEventListener('keydown', handleKeyDown)

    return () => {
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [open, onClose])

  if (!open) {
    return null
  }

  return (
    <div
      className="ai-command-menu"
      role="dialog"
      aria-modal="true"
      aria-label="SECP command center"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose()
        }
      }}
    >
      <section className="ai-command-menu__panel">
        <header className="ai-command-menu__header">
          <div>
            <p>SECP intelligence layer</p>
            <h2>Command center</h2>
          </div>

          <button type="button" aria-label="Close command center" onClick={onClose}>
            ×
          </button>
        </header>

        <label className="ai-command-menu__search">
          <span>⌕</span>

          <input autoFocus type="search" placeholder="Search actions, infrastructure, workers..." />

          <kbd>ESC</kbd>
        </label>

        <div className="ai-command-menu__commands">
          {commands.map((command) => (
            <button key={command.key} type="button" className="ai-command-menu__command">
              <kbd>{command.key}</kbd>

              <span>
                <strong>{command.title}</strong>

                <small>{command.description}</small>
              </span>

              <span aria-hidden="true">→</span>
            </button>
          ))}
        </div>
      </section>
    </div>
  )
}
