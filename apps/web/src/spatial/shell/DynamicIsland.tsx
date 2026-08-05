import { Bell, Check, ChevronRight, Settings2, UserRound, X } from 'lucide-react'
import { createPortal } from 'react-dom'
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { SpatialGlobalSearch } from './global-search/SpatialGlobalSearch'
import { SecpGlyph } from './SecpGlyph'
import type { ShellActivity } from './shellData'
import type { SecpAppId } from './shellTypes'
import './DynamicIsland.css'

interface DynamicIslandProps {
  activeApp: SecpAppId
  activities: ShellActivity[]
  expanded: boolean
  onToggle: () => void
  onOpenActivity: () => void
  onSearchNavigate: (appId: SecpAppId, entry: string) => void
}

interface NotificationItem {
  id: string
  title: string
  detail: string
  tone: 'info' | 'attention' | 'success'
  unread: boolean
}

type LocalPanel = 'notifications' | 'profile' | null

type HeaderPanel = 'operations' | 'notifications' | 'profile' | null

const notifications: NotificationItem[] = [
  {
    id: 'approval-range-beta',
    title: 'Approval requested',
    detail: 'Range Beta is waiting for operator review.',
    tone: 'attention',
    unread: true,
  },
  {
    id: 'discovery-changes',
    title: 'Discovery completed',
    detail: 'Seven infrastructure changes were detected.',
    tone: 'info',
    unread: true,
  },
  {
    id: 'worker-recovered',
    title: 'Worker recovered',
    detail: 'The local container worker is healthy again.',
    tone: 'success',
    unread: false,
  },
]

const appLabels: Partial<Record<SecpAppId, string>> = {
  home: 'Home',
  infrastructure: 'Infrastructure',
  'cyber-ranges': 'Events & Ranges',
  scenarios: 'Scenarios',
  deployments: 'Deployments',
  reports: 'Reports',
  administration: 'Platform',
  activity: 'Activity',
  settings: 'OS Settings',
}

function getAppLabel(activeApp: SecpAppId) {
  return (
    appLabels[activeApp] ??
    activeApp
      .split('-')
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join(' ')
  )
}

export function DynamicIsland({
  activeApp,
  activities,
  expanded,
  onToggle,
  onOpenActivity,
  onSearchNavigate,
}: DynamicIslandProps) {
  const rootRef = useRef<HTMLDivElement>(null)
  const panelRef = useRef<HTMLElement>(null)
  const operationsButtonRef = useRef<HTMLButtonElement>(null)
  const notificationsButtonRef = useRef<HTMLButtonElement>(null)
  const profileButtonRef = useRef<HTMLButtonElement>(null)

  const [localPanel, setLocalPanel] = useState<LocalPanel>(null)
  const [searchOpen, setSearchOpen] = useState(false)
  const [popoverStyle, setPopoverStyle] = useState<CSSProperties | null>(null)

  const currentPanel: HeaderPanel = expanded ? 'operations' : localPanel

  const unreadCount = notifications.filter((notification) => notification.unread).length

  const currentApp = getAppLabel(activeApp)

  const closePanels = useCallback(() => {
    setLocalPanel(null)

    if (expanded) {
      onToggle()
    }
  }, [expanded, onToggle])

  const positionPanel = useCallback(() => {
    if (!currentPanel) {
      setPopoverStyle(null)
      return
    }

    const anchor =
      currentPanel === 'operations'
        ? operationsButtonRef.current
        : currentPanel === 'notifications'
          ? notificationsButtonRef.current
          : profileButtonRef.current

    if (!anchor) {
      return
    }

    const anchorRect = anchor.getBoundingClientRect()

    const width = currentPanel === 'profile' ? 270 : 350

    const viewportPadding = 12

    const left = Math.min(
      Math.max(viewportPadding, anchorRect.right - width),
      Math.max(viewportPadding, window.innerWidth - width - viewportPadding),
    )

    const panelHeight = panelRef.current?.offsetHeight ?? 0

    const belowTop = anchorRect.bottom + 12

    const aboveTop = anchorRect.top - panelHeight - 12

    const top =
      panelHeight > 0 && belowTop + panelHeight > window.innerHeight - viewportPadding
        ? Math.max(viewportPadding, aboveTop)
        : belowTop

    setPopoverStyle({
      left,
      maxHeight: 'calc(100vh - 24px)',
      position: 'fixed',
      right: 'auto',
      top,
      width,
      zIndex: 10000,
    })
  }, [currentPanel])

  useLayoutEffect(() => {
    if (!currentPanel) {
      setPopoverStyle(null)
      return
    }

    positionPanel()

    const frame = window.requestAnimationFrame(positionPanel)

    window.addEventListener('resize', positionPanel)

    window.addEventListener('scroll', positionPanel, true)

    return () => {
      window.cancelAnimationFrame(frame)

      window.removeEventListener('resize', positionPanel)

      window.removeEventListener('scroll', positionPanel, true)
    }
  }, [currentPanel, positionPanel])

  useEffect(() => {
    function handlePointerDown(event: PointerEvent) {
      const target = event.target as Node

      if (rootRef.current?.contains(target) || panelRef.current?.contains(target)) {
        return
      }

      closePanels()
    }

    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape' && currentPanel) {
        event.preventDefault()
        event.stopPropagation()
        closePanels()
      }
    }

    document.addEventListener('pointerdown', handlePointerDown)

    window.addEventListener('keydown', handleEscape)

    return () => {
      document.removeEventListener('pointerdown', handlePointerDown)

      window.removeEventListener('keydown', handleEscape)
    }
  }, [closePanels, currentPanel])

  function toggleOperations() {
    setLocalPanel(null)
    onToggle()
  }

  function toggleNotifications() {
    if (expanded) {
      onToggle()
    }

    setLocalPanel((current) => (current === 'notifications' ? null : 'notifications'))
  }

  function toggleProfile() {
    if (expanded) {
      onToggle()
    }

    setLocalPanel((current) => (current === 'profile' ? null : 'profile'))
  }

  function openActivity() {
    setLocalPanel(null)

    if (expanded) {
      onToggle()
    }

    onOpenActivity()
  }

  const fallbackPanelStyle: CSSProperties = {
    left: -2000,
    position: 'fixed',
    right: 'auto',
    top: -2000,
    width: currentPanel === 'profile' ? 270 : 350,
    zIndex: 10000,
  }

  const panel =
    currentPanel && typeof document !== 'undefined'
      ? createPortal(
          <section
            className={[
              'spatial-topbar-popover',
              'spatial-topbar-popover--portal',
              `spatial-topbar-popover--${currentPanel}`,
            ].join(' ')}
            data-panel={currentPanel}
            ref={panelRef}
            style={popoverStyle ?? fallbackPanelStyle}
            onPointerDown={(event) => event.stopPropagation()}
          >
            {currentPanel === 'operations' ? (
              <>
                <header className="spatial-topbar-popover__header">
                  <div>
                    <small>Active operations</small>
                    <strong>Live system activity</strong>
                  </div>

                  <button type="button" aria-label="Close active operations" onClick={closePanels}>
                    <X size={14} aria-hidden />
                  </button>
                </header>

                <div className="spatial-topbar-activity-list">
                  {activities.map((activity) => (
                    <button
                      className="spatial-topbar-activity"
                      key={activity.id}
                      type="button"
                      onClick={openActivity}
                    >
                      <span className="spatial-topbar-activity__icon">
                        <SecpGlyph name={activity.glyph} />
                      </span>

                      <span className="spatial-topbar-activity__copy">
                        <strong>{activity.title}</strong>
                        <span>{activity.detail}</span>
                      </span>

                      <b
                        className={`spatial-topbar-activity__value spatial-topbar-activity__value--${activity.state}`}
                      >
                        {activity.value}
                      </b>
                    </button>
                  ))}
                </div>

                <button
                  className="spatial-topbar-popover__footer"
                  type="button"
                  onClick={openActivity}
                >
                  Open Activity
                  <ChevronRight size={13} aria-hidden />
                </button>
              </>
            ) : null}

            {currentPanel === 'notifications' ? (
              <>
                <header className="spatial-topbar-popover__header">
                  <div>
                    <small>Notification Center</small>
                    <strong>Needs your attention</strong>
                  </div>

                  <button type="button" aria-label="Close notifications" onClick={closePanels}>
                    <X size={14} aria-hidden />
                  </button>
                </header>

                <div className="spatial-topbar-notification-list">
                  {notifications.map((notification) => (
                    <button
                      className={[
                        'spatial-topbar-notification',
                        notification.unread ? 'is-unread' : '',
                      ]
                        .filter(Boolean)
                        .join(' ')}
                      key={notification.id}
                      type="button"
                      onClick={openActivity}
                    >
                      <span
                        className={`spatial-topbar-notification__tone spatial-topbar-notification__tone--${notification.tone}`}
                      />

                      <span>
                        <strong>{notification.title}</strong>
                        <small>{notification.detail}</small>
                      </span>

                      {notification.unread ? <i /> : <Check size={13} aria-hidden />}
                    </button>
                  ))}
                </div>

                <button
                  className="spatial-topbar-popover__footer"
                  type="button"
                  onClick={openActivity}
                >
                  View all notifications
                  <ChevronRight size={13} aria-hidden />
                </button>
              </>
            ) : null}

            {currentPanel === 'profile' ? (
              <>
                <header className="spatial-topbar-profile">
                  <span>
                    <UserRound size={18} aria-hidden />
                  </span>

                  <div>
                    <strong>Juan Campos</strong>
                    <small>SECP operator</small>
                  </div>
                </header>

                <button
                  className="spatial-topbar-profile-action"
                  type="button"
                  onClick={() => {
                    setLocalPanel(null)

                    onSearchNavigate('settings', '/settings')
                  }}
                >
                  <Settings2 size={15} aria-hidden />
                  OS Settings
                  <ChevronRight size={13} aria-hidden />
                </button>
              </>
            ) : null}
          </section>,
          document.body,
        )
      : null

  return (
    <>
      <div
        className={['spatial-topbar', searchOpen ? 'spatial-topbar--search-open' : '']
          .filter(Boolean)
          .join(' ')}
        ref={rootRef}
      >
        <button
          className="spatial-topbar__identity"
          type="button"
          onClick={() =>
            onSearchNavigate(activeApp, activeApp === 'home' ? '/home' : `/${activeApp}`)
          }
        >
          <span className="spatial-topbar__identity-dot" />

          <span className="spatial-topbar__identity-brand">SECP</span>

          <span className="spatial-topbar__identity-separator" aria-hidden="true">
            {'\u2022'}
          </span>

          <span className="spatial-topbar__identity-page">{currentApp}</span>
        </button>

        <div className="spatial-topbar__search">
          <SpatialGlobalSearch
            onNavigate={onSearchNavigate}
            onOpenChange={(open) => {
              setSearchOpen(open)

              if (open) {
                closePanels()
              }
            }}
          />
        </div>

        <div className="spatial-topbar__utilities">
          <div className="spatial-topbar__operations-wrap">
            <button
              className={['spatial-topbar__operations', expanded ? 'is-active' : '']
                .filter(Boolean)
                .join(' ')}
              ref={operationsButtonRef}
              type="button"
              aria-expanded={expanded}
              onPointerDown={(event) => event.stopPropagation()}
              onClick={toggleOperations}
            >
              <span />
              <strong>{activities.length} active</strong>
              <ChevronRight size={12} aria-hidden />
            </button>
          </div>

          <div className="spatial-topbar__notifications-wrap">
            <button
              className={[
                'spatial-topbar__icon-button',
                localPanel === 'notifications' ? 'is-active' : '',
              ]
                .filter(Boolean)
                .join(' ')}
              ref={notificationsButtonRef}
              type="button"
              title="Notifications"
              aria-label={`${unreadCount} unread notifications`}
              aria-expanded={localPanel === 'notifications'}
              onPointerDown={(event) => event.stopPropagation()}
              onClick={toggleNotifications}
            >
              <Bell size={18} aria-hidden />

              {unreadCount > 0 ? (
                <span className="spatial-topbar__notification-dot">{unreadCount}</span>
              ) : null}
            </button>
          </div>

          <div className="spatial-topbar__profile-wrap">
            <button
              className={['spatial-topbar__avatar', localPanel === 'profile' ? 'is-active' : '']
                .filter(Boolean)
                .join(' ')}
              ref={profileButtonRef}
              type="button"
              title="Account"
              aria-label="Open account menu"
              aria-expanded={localPanel === 'profile'}
              onPointerDown={(event) => event.stopPropagation()}
              onClick={toggleProfile}
            >
              J
            </button>
          </div>
        </div>
      </div>

      {panel}
    </>
  )
}
