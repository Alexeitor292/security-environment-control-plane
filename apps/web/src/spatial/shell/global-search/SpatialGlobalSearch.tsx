import { createPortal } from 'react-dom'
import { useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties, KeyboardEvent as ReactKeyboardEvent } from 'react'
import {
  Boxes,
  CalendarDays,
  CornerDownLeft,
  FileText,
  Gauge,
  Network,
  Search,
  Server,
  Users,
  X,
} from 'lucide-react'
import {
  deployments,
  events,
  reports,
  scenarios,
  targets,
  teams,
} from '../../apps/prototype-suite/core/mocks'
import type { SecpAppId } from '../shellTypes'
import './SpatialGlobalSearch.css'

type SearchCategory =
  'destination' | 'event' | 'scenario' | 'deployment' | 'team' | 'infrastructure' | 'report'

interface SearchDocument {
  id: string
  label: string
  category: SearchCategory
  appId: SecpAppId
  entry: string
  context?: string
  status?: string
  keywords: string[]
}

interface SpatialGlobalSearchProps {
  onNavigate: (appId: SecpAppId, entry: string) => void
  onOpenChange?: (open: boolean) => void
}

interface PalettePosition {
  top: number
  left: number
  width: number
}

const recentKey = 'secp-spatial-global-search-recent'

const categoryOrder: SearchCategory[] = [
  'destination',
  'event',
  'scenario',
  'deployment',
  'team',
  'infrastructure',
  'report',
]

const categoryLabels: Record<SearchCategory, string> = {
  destination: 'Pages',
  event: 'Events',
  scenario: 'Scenarios',
  deployment: 'Deployments',
  team: 'Teams',
  infrastructure: 'Infrastructure',
  report: 'Reports',
}

const categoryIcons = {
  destination: Gauge,
  event: CalendarDays,
  scenario: Boxes,
  deployment: Network,
  team: Users,
  infrastructure: Server,
  report: FileText,
} satisfies Record<SearchCategory, typeof Search>

const destinations: SearchDocument[] = [
  {
    id: 'destination:infrastructure-targets',
    label: 'Infrastructure targets',
    category: 'destination',
    appId: 'infrastructure',
    entry: '/infrastructure/targets',
    context: 'Targets, onboarding, health, and capacity',
    keywords: ['infrastructure', 'targets', 'providers', 'capacity'],
  },
  {
    id: 'destination:infrastructure-placement',
    label: 'Capacity and placement',
    category: 'destination',
    appId: 'infrastructure',
    entry: '/infrastructure/placement',
    context: 'Placement policies and target capacity',
    keywords: ['placement', 'capacity', 'policy', 'infrastructure'],
  },
  {
    id: 'destination:infrastructure-workers',
    label: 'Infrastructure workers',
    category: 'destination',
    appId: 'infrastructure',
    entry: '/infrastructure/workers',
    context: 'Worker identities, queues, and heartbeats',
    keywords: ['workers', 'queues', 'heartbeat'],
  },
  {
    id: 'destination:infrastructure-providers',
    label: 'Providers and plugins',
    category: 'destination',
    appId: 'infrastructure',
    entry: '/infrastructure/providers',
    context: 'Provider adapters and capability truth',
    keywords: ['providers', 'plugins', 'proxmox', 'aws', 'azure', 'gcp', 'kubernetes'],
  },
  {
    id: 'destination:infrastructure-inventory',
    label: 'Inventory and discovery',
    category: 'destination',
    appId: 'infrastructure',
    entry: '/infrastructure/inventory',
    context: 'Observed resources and discovery evidence',
    keywords: ['inventory', 'discovery', 'evidence'],
  },
  {
    id: 'destination:events',
    label: 'Events and ranges',
    category: 'destination',
    appId: 'cyber-ranges',
    entry: '/events',
    context: 'Events, control rooms, teams, and scoring',
    keywords: ['events', 'ranges', 'competition', 'control room'],
  },
  {
    id: 'destination:scenarios',
    label: 'Scenario library',
    category: 'destination',
    appId: 'scenarios',
    entry: '/scenarios',
    context: 'Builder, versions, and validation',
    keywords: ['scenario', 'builder', 'versions', 'validation'],
  },
  {
    id: 'destination:deployments',
    label: 'Deployment portfolio',
    category: 'destination',
    appId: 'deployments',
    entry: '/deployments',
    context: 'Lifecycle, resources, topology, and operations',
    keywords: ['deployments', 'resources', 'topology', 'operations'],
  },
  {
    id: 'destination:reports',
    label: 'Report catalog',
    category: 'destination',
    appId: 'reports',
    entry: '/reports',
    context: 'Executive, technical, scoring, and audit reports',
    keywords: ['reports', 'executive', 'technical', 'audit'],
  },
  {
    id: 'destination:platform-overview',
    label: 'Platform overview',
    category: 'destination',
    appId: 'administration',
    entry: '/platform',
    context: 'Organizations, identity, workflows, and evidence',
    keywords: ['platform', 'administration', 'overview'],
  },
  {
    id: 'destination:platform-organizations',
    label: 'Organizations and teams',
    category: 'destination',
    appId: 'administration',
    entry: '/platform/organizations',
    context: 'Organizations, membership, and ownership',
    keywords: ['organizations', 'teams', 'ownership'],
  },
  {
    id: 'destination:platform-identity',
    label: 'Identity and access',
    category: 'destination',
    appId: 'administration',
    entry: '/platform/identity',
    context: 'Human and service identities',
    keywords: ['identity', 'access', 'roles', 'users'],
  },
  {
    id: 'destination:platform-workflows',
    label: 'Workflow engine',
    category: 'destination',
    appId: 'administration',
    entry: '/platform/workflows',
    context: 'Workflow runs, queues, and automation',
    keywords: ['workflows', 'temporal', 'queues', 'automation', 'ai operations'],
  },
  {
    id: 'destination:platform-integrations',
    label: 'Integrations',
    category: 'destination',
    appId: 'administration',
    entry: '/platform/integrations',
    context: 'Platform and provider connections',
    keywords: ['integrations', 'connections', 'providers'],
  },
  {
    id: 'destination:platform-audit',
    label: 'Audit and evidence',
    category: 'destination',
    appId: 'administration',
    entry: '/platform/audit',
    context: 'Audit ledger, receipts, and evidence',
    keywords: ['audit', 'evidence', 'receipts', 'hash'],
  },
  {
    id: 'destination:platform-retention',
    label: 'Retention and backup',
    category: 'destination',
    appId: 'administration',
    entry: '/platform/retention',
    context: 'Retention policy and backup posture',
    keywords: ['retention', 'backup', 'storage'],
  },
]

function titleCase(value: string) {
  return value
    .split('-')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ')
}

function buildIndex(): SearchDocument[] {
  const eventNames = new Map(events.map((event) => [event.id, event.name]))

  return [
    ...destinations,
    ...events.map((event) => ({
      id: `event:${event.id}`,
      label: event.name,
      category: 'event' as const,
      appId: 'cyber-ranges' as const,
      entry: `/events/${event.id}`,
      context: `${titleCase(event.type)} Â· ${event.connectedParticipants}/${event.totalParticipants} connected`,
      status: event.status,
      keywords: [
        event.id,
        event.description,
        event.type,
        event.status,
        event.health,
        ...event.rules,
      ],
    })),
    ...scenarios.map((scenario) => ({
      id: `scenario:${scenario.id}`,
      label: scenario.name,
      category: 'scenario' as const,
      appId: 'scenarios' as const,
      entry: `/scenarios/${scenario.id}`,
      context: `v${scenario.currentVersion} Â· ${titleCase(scenario.difficulty)} Â· ${scenario.teamRange[0]}-${scenario.teamRange[1]} teams`,
      status: scenario.validation,
      keywords: [
        scenario.id,
        scenario.purpose,
        scenario.difficulty,
        scenario.currentVersion,
        ...scenario.tags,
        ...scenario.supportedProviders,
        ...scenario.requiredPlugins,
      ],
    })),
    ...deployments.map((deployment) => ({
      id: `deployment:${deployment.id}`,
      label: deployment.name,
      category: 'deployment' as const,
      appId: 'deployments' as const,
      entry: `/deployments/${deployment.id}`,
      context: `${titleCase(deployment.provider)} Â· ${deployment.region}${deployment.eventId ? ` Â· ${eventNames.get(deployment.eventId) ?? deployment.eventId}` : ''}`,
      status: deployment.state,
      keywords: [
        deployment.id,
        deployment.provider,
        deployment.region,
        deployment.state,
        deployment.health,
        deployment.owner,
        deployment.lastOperation,
      ],
    })),
    ...teams.map((team) => ({
      id: `team:${team.id}`,
      label: team.name,
      category: 'team' as const,
      appId: 'cyber-ranges' as const,
      entry: `/events/${team.eventId}/teams`,
      context: `${team.subnet} Â· ${eventNames.get(team.eventId) ?? team.eventId}`,
      status: team.connection,
      keywords: [
        team.id,
        team.subnet,
        team.connection,
        team.gatewayHealth,
        team.vpnEndpoint,
        ...team.systems,
        ...team.objectives,
      ],
    })),
    ...targets.map((target) => ({
      id: `target:${target.id}`,
      label: target.name,
      category: 'infrastructure' as const,
      appId: 'infrastructure' as const,
      entry: '/infrastructure/targets',
      context: `${titleCase(target.provider)} Â· ${target.location}`,
      status: target.health,
      keywords: [
        target.id,
        target.provider,
        target.location,
        target.health,
        target.onboardingState,
        target.credentialStatus,
        ...target.capabilities,
      ],
    })),
    ...reports.map((report) => ({
      id: `report:${report.id}`,
      label: report.title,
      category: 'report' as const,
      appId: 'reports' as const,
      entry: '/reports',
      context: titleCase(report.category),
      status: report.generatedAt ? 'Generated' : 'Available',
      keywords: [report.id, report.category, report.description, report.eventId ?? ''],
    })),
  ]
}

const index = buildIndex()

function normalized(value: string) {
  return value
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
}

function scoreDocument(document: SearchDocument, query: string) {
  const needle = normalized(query.trim())

  if (!needle) {
    return 0
  }

  const label = normalized(document.label)
  const context = normalized(document.context ?? '')
  const keywords = normalized(document.keywords.join(' '))

  if (label === needle) {
    return 1000
  }

  if (label.startsWith(needle)) {
    return 760
  }

  if (label.includes(needle)) {
    return 560
  }

  if (context.includes(needle)) {
    return 330
  }

  if (keywords.includes(needle)) {
    return 220
  }

  const tokens = needle.split(/\s+/).filter(Boolean)

  if (
    tokens.length > 1 &&
    tokens.every(
      (token) => label.includes(token) || context.includes(token) || keywords.includes(token),
    )
  ) {
    return 180
  }

  return -1
}

function readRecent(): SearchDocument[] {
  try {
    const raw = window.localStorage.getItem(recentKey)

    if (!raw) {
      return []
    }

    const ids = JSON.parse(raw) as unknown

    if (!Array.isArray(ids)) {
      return []
    }

    return ids
      .map((id) => index.find((document) => document.id === id))
      .filter((document): document is SearchDocument => Boolean(document))
      .slice(0, 5)
  } catch {
    return []
  }
}

function saveRecent(document: SearchDocument) {
  const next = [
    document.id,
    ...readRecent()
      .map((item) => item.id)
      .filter((id) => id !== document.id),
  ].slice(0, 5)

  window.localStorage.setItem(recentKey, JSON.stringify(next))
}

export function SpatialGlobalSearch({ onNavigate, onOpenChange }: SpatialGlobalSearchProps) {
  const rawId = useId()
  const id = rawId.replace(/[^a-zA-Z0-9_-]/g, '')

  const rootRef = useRef<HTMLDivElement>(null)
  const paletteRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const [query, setQuery] = useState('')
  const [listOpen, setListOpen] = useState(false)
  const [focusWithin, setFocusWithin] = useState(false)
  const [activeCategory, setActiveCategory] = useState<SearchCategory | 'all'>('all')
  const [activeIndex, setActiveIndex] = useState(0)
  const [recent, setRecent] = useState<SearchDocument[]>([])
  const [announce, setAnnounce] = useState('')
  const [palettePosition, setPalettePosition] = useState<PalettePosition>({
    top: 74,
    left: window.innerWidth / 2,
    width: Math.min(640, window.innerWidth - 24),
  })

  const trimmed = query.trim()
  const queryMode = trimmed !== ''
  const showPalette = listOpen
  const expanded = focusWithin || queryMode

  useEffect(() => {
    setRecent(readRecent())
  }, [])

  useEffect(() => {
    onOpenChange?.(showPalette)
  }, [onOpenChange, showPalette])

  useEffect(() => {
    function handleGlobalKey(event: KeyboardEvent) {
      if (event.key.toLowerCase() === 'k' && (event.ctrlKey || event.metaKey) && !event.shiftKey) {
        event.preventDefault()
        setListOpen(true)
        setFocusWithin(true)

        window.requestAnimationFrame(() => {
          inputRef.current?.focus()
        })
      }
    }

    window.addEventListener('keydown', handleGlobalKey)

    return () => {
      window.removeEventListener('keydown', handleGlobalKey)
    }
  }, [])

  useLayoutEffect(() => {
    if (!showPalette) {
      return
    }

    function updatePosition() {
      const anchor = rootRef.current

      if (!anchor) {
        return
      }

      const rect = anchor.getBoundingClientRect()
      const viewportPadding = 12
      const width = Math.min(640, window.innerWidth - viewportPadding * 2)
      const half = width / 2
      const requestedCenter = rect.left + rect.width / 2
      const center = Math.min(
        window.innerWidth - half - viewportPadding,
        Math.max(half + viewportPadding, requestedCenter),
      )

      setPalettePosition({
        top: rect.bottom + 10,
        left: center,
        width,
      })
    }

    updatePosition()

    window.addEventListener('resize', updatePosition)
    window.addEventListener('scroll', updatePosition, true)

    return () => {
      window.removeEventListener('resize', updatePosition)
      window.removeEventListener('scroll', updatePosition, true)
    }
  }, [showPalette])

  useEffect(() => {
    if (!showPalette) {
      return
    }

    function handlePointerDown(event: MouseEvent) {
      const target = event.target as Node

      if (rootRef.current?.contains(target) || paletteRef.current?.contains(target)) {
        return
      }

      setListOpen(false)
      setFocusWithin(false)
    }

    document.addEventListener('mousedown', handlePointerDown)

    return () => {
      document.removeEventListener('mousedown', handlePointerDown)
    }
  }, [showPalette])

  const rankedAll = useMemo(() => {
    if (!queryMode) {
      return []
    }

    return index
      .map((document) => ({
        document,
        score: scoreDocument(document, trimmed),
      }))
      .filter((result) => result.score >= 0)
      .sort(
        (left, right) =>
          right.score - left.score || left.document.label.localeCompare(right.document.label),
      )
  }, [queryMode, trimmed])

  const categoryCounts = useMemo(() => {
    const counts = Object.fromEntries(categoryOrder.map((category) => [category, 0])) as Record<
      SearchCategory,
      number
    >

    const documents = queryMode ? rankedAll.map((result) => result.document) : index

    for (const document of documents) {
      counts[document.category] += 1
    }

    return counts
  }, [queryMode, rankedAll])

  const visibleQueryDocuments = useMemo(() => {
    if (!queryMode) {
      return []
    }

    const filtered = rankedAll.filter(
      (result) => activeCategory === 'all' || result.document.category === activeCategory,
    )

    const perCategory = new Map<SearchCategory, number>()
    const visible: SearchDocument[] = []

    for (const result of filtered) {
      const current = perCategory.get(result.document.category) ?? 0

      if (current >= 3) {
        continue
      }

      visible.push(result.document)
      perCategory.set(result.document.category, current + 1)

      if (visible.length >= 14) {
        break
      }
    }

    return visible
  }, [activeCategory, queryMode, rankedAll])

  const quickAccess = useMemo(() => {
    const quickIds = [
      'destination:infrastructure-targets',
      'destination:events',
      'destination:scenarios',
      'destination:deployments',
      'destination:reports',
      'destination:platform-overview',
    ]

    return quickIds
      .map((documentId) => destinations.find((document) => document.id === documentId))
      .filter((document): document is SearchDocument => Boolean(document))
  }, [])

  const groups = useMemo(() => {
    if (!queryMode) {
      return [
        {
          key: 'recent',
          label: 'Recent searches',
          documents: recent,
          total: recent.length,
        },
        {
          key: 'quick',
          label: 'Quick access',
          documents: quickAccess,
          total: quickAccess.length,
        },
      ].filter((group) => group.documents.length > 0)
    }

    return categoryOrder
      .map((category) => {
        const documents = visibleQueryDocuments.filter((document) => document.category === category)

        return {
          key: category,
          label: categoryLabels[category],
          category,
          documents,
          total: categoryCounts[category],
        }
      })
      .filter((group) => group.documents.length > 0)
  }, [categoryCounts, queryMode, quickAccess, recent, visibleQueryDocuments])

  const flat = useMemo(() => groups.flatMap((group) => group.documents), [groups])

  const activeOption = flat.length === 0 ? -1 : Math.min(Math.max(activeIndex, 0), flat.length - 1)

  useEffect(() => {
    setActiveIndex(0)
  }, [activeCategory, query])

  useEffect(() => {
    if (!showPalette || activeOption < 0) {
      return
    }

    document.getElementById(`spatial-search-option-${id}-${activeOption}`)?.scrollIntoView({
      block: 'nearest',
    })
  }, [activeOption, id, showPalette])

  useEffect(() => {
    const message = !showPalette
      ? ''
      : queryMode
        ? flat.length === 0
          ? 'No results'
          : `${flat.length} visible result${flat.length === 1 ? '' : 's'}`
        : `${flat.length} quick access item${flat.length === 1 ? '' : 's'}`

    const timer = window.setTimeout(() => {
      setAnnounce(message)
    }, 250)

    return () => {
      window.clearTimeout(timer)
    }
  }, [flat.length, queryMode, showPalette])

  function openSearch() {
    setListOpen(true)
    setFocusWithin(true)

    window.requestAnimationFrame(() => {
      inputRef.current?.focus()
    })
  }

  function closeSearch() {
    setListOpen(false)
    setFocusWithin(false)
    inputRef.current?.blur()
  }

  function clearSearch() {
    setQuery('')
    setActiveCategory('all')
    setActiveIndex(0)
    setListOpen(true)

    window.requestAnimationFrame(() => {
      inputRef.current?.focus()
    })
  }

  function select(document: SearchDocument) {
    saveRecent(document)
    setRecent(readRecent())
    setQuery('')
    setActiveCategory('all')
    closeSearch()
    onNavigate(document.appId, document.entry)
  }

  function handleKeyDown(event: ReactKeyboardEvent<HTMLInputElement>) {
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault()

        if (!showPalette) {
          openSearch()
          return
        }

        if (flat.length > 0) {
          setActiveIndex((activeOption + 1) % flat.length)
        }
        break

      case 'ArrowUp':
        event.preventDefault()

        if (!showPalette) {
          openSearch()
          return
        }

        if (flat.length > 0) {
          setActiveIndex((activeOption - 1 + flat.length) % flat.length)
        }
        break

      case 'Home':
        if (showPalette && flat.length > 0) {
          event.preventDefault()
          setActiveIndex(0)
        }
        break

      case 'End':
        if (showPalette && flat.length > 0) {
          event.preventDefault()
          setActiveIndex(flat.length - 1)
        }
        break

      case 'Enter':
        if (showPalette && activeOption >= 0) {
          event.preventDefault()
          select(flat[activeOption])
        }
        break

      case 'Escape':
        event.preventDefault()

        if (showPalette) {
          closeSearch()
        } else if (query !== '') {
          clearSearch()
        }
        break

      default:
        break
    }
  }

  const paletteStyle: CSSProperties = {
    top: palettePosition.top,
    left: palettePosition.left,
    width: palettePosition.width,
  }

  const palette =
    showPalette && typeof document !== 'undefined'
      ? createPortal(
          <section className="spatial-search-palette" ref={paletteRef} style={paletteStyle}>
            <p className="spatial-search-palette__intent">I&apos;m looking for...</p>

            <div className="spatial-search-categories" aria-label="Search categories">
              {(['all', ...categoryOrder] as const).map((value) => {
                const count =
                  value === 'all'
                    ? queryMode
                      ? rankedAll.length
                      : index.length
                    : categoryCounts[value]

                const label = value === 'all' ? 'All' : categoryLabels[value]

                if (!queryMode) {
                  return (
                    <span
                      className="spatial-search-category spatial-search-category--static"
                      key={value}
                    >
                      <span>{label}</span>
                      <b>{count}</b>
                    </span>
                  )
                }

                return (
                  <button
                    className={[
                      'spatial-search-category',
                      activeCategory === value ? 'is-active' : '',
                    ]
                      .filter(Boolean)
                      .join(' ')}
                    key={value}
                    type="button"
                    onMouseDown={(event) => event.preventDefault()}
                    onClick={() => {
                      setActiveCategory(value)
                      setActiveIndex(0)
                      inputRef.current?.focus()
                    }}
                  >
                    <span>{label}</span>
                    <b>{count}</b>
                  </button>
                )
              })}
            </div>

            <p className="spatial-search-palette__prompt">
              {queryMode
                ? `Search results for "${trimmed}"`
                : 'Search events, scenarios, deployments, teams, infrastructure, reports, and platform pages.'}
            </p>

            <div
              className="spatial-search-results"
              id={`spatial-search-results-${id}`}
              role="listbox"
              aria-label="Search results"
            >
              {flat.length === 0 ? (
                <div className="spatial-search-empty">
                  <strong>No results for "{trimmed}"</strong>
                  <span>Try a shorter term or search all categories.</span>

                  {activeCategory !== 'all' ? (
                    <button
                      type="button"
                      onClick={() => {
                        setActiveCategory('all')
                        inputRef.current?.focus()
                      }}
                    >
                      Search all categories
                    </button>
                  ) : null}
                </div>
              ) : (
                groups.map((group) => {
                  const GroupIcon =
                    'category' in group && group.category
                      ? categoryIcons[group.category as SearchCategory]
                      : group.key === 'recent'
                        ? Gauge
                        : Search

                  let rowOffset = 0

                  for (const preceding of groups) {
                    if (preceding.key === group.key) {
                      break
                    }

                    rowOffset += preceding.documents.length
                  }

                  return (
                    <section className="spatial-search-group" key={group.key}>
                      <header>
                        <GroupIcon size={13} aria-hidden />
                        <span>{group.label}</span>
                        <b>{group.total}</b>

                        {!queryMode && group.key === 'recent' ? (
                          <button
                            type="button"
                            onMouseDown={(event) => event.preventDefault()}
                            onClick={() => {
                              window.localStorage.removeItem(recentKey)
                              setRecent([])
                              inputRef.current?.focus()
                            }}
                          >
                            Clear
                          </button>
                        ) : null}
                      </header>

                      {group.documents.map((document, groupIndex) => {
                        const rowIndex = rowOffset + groupIndex
                        const Icon = categoryIcons[document.category]

                        return (
                          <button
                            className={[
                              'spatial-search-result',
                              rowIndex === activeOption ? 'is-active' : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
                            id={`spatial-search-option-${id}-${rowIndex}`}
                            key={document.id}
                            type="button"
                            role="option"
                            aria-selected={rowIndex === activeOption}
                            onMouseDown={(event) => event.preventDefault()}
                            onMouseEnter={() => setActiveIndex(rowIndex)}
                            onClick={() => select(document)}
                          >
                            <span className="spatial-search-result__icon">
                              <Icon size={16} aria-hidden />
                            </span>

                            <span className="spatial-search-result__body">
                              <strong>{document.label}</strong>
                              <span>{document.context}</span>
                            </span>

                            {document.status ? (
                              <span className="spatial-search-result__status">
                                {document.status}
                              </span>
                            ) : null}

                            <span className="spatial-search-result__open">
                              Open
                              {rowIndex === activeOption ? (
                                <CornerDownLeft size={12} aria-hidden />
                              ) : null}
                            </span>
                          </button>
                        )
                      })}

                      {queryMode && group.total > group.documents.length ? (
                        <p className="spatial-search-group__more">
                          +{group.total - group.documents.length} more
                        </p>
                      ) : null}
                    </section>
                  )
                })
              )}
            </div>

            <footer className="spatial-search-footer">
              <span>
                <kbd>Up</kbd>
                <kbd>Down</kbd>
                Navigate
              </span>
              <span>
                <kbd>Enter</kbd>
                Open
              </span>
              <span>
                <kbd>Esc</kbd>
                Close
              </span>
              <span>
                <kbd>Ctrl K</kbd>
                Search
              </span>
            </footer>
          </section>,
          document.body,
        )
      : null

  return (
    <>
      <div
        className="spatial-global-search"
        data-expanded={expanded || undefined}
        data-open={showPalette || undefined}
        ref={rootRef}
        onClick={(event) => event.stopPropagation()}
      >
        <svg
          className="spatial-global-search__defs"
          aria-hidden="true"
          focusable="false"
          width="0"
          height="0"
        >
          <defs>
            <filter id={`spatial-search-goo-${id}`} colorInterpolationFilters="sRGB">
              <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
              <feColorMatrix
                in="blur"
                type="matrix"
                values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 16 -7"
                result="goo"
              />
              <feComposite in="SourceGraphic" in2="goo" operator="atop" />
            </filter>
          </defs>
        </svg>

        <div
          className="spatial-global-search__goo"
          aria-hidden="true"
          style={{
            filter: `url(#spatial-search-goo-${id})`,
          }}
        >
          <span className="spatial-global-search__blob spatial-global-search__blob--field" />
          <span className="spatial-global-search__blob spatial-global-search__blob--neck" />
        </div>

        <div
          className="spatial-global-search__field"
          onMouseDown={(event) => event.preventDefault()}
          onClick={openSearch}
        >
          <Search className="spatial-global-search__field-icon" size={14} aria-hidden />

          <span className="spatial-global-search__label" aria-hidden="true">
            Search
          </span>

          <input
            ref={inputRef}
            className="spatial-global-search__input"
            type="text"
            role="combobox"
            aria-label="Search SECP"
            aria-expanded={showPalette}
            aria-controls={showPalette ? `spatial-search-results-${id}` : undefined}
            aria-autocomplete="list"
            aria-activedescendant={
              showPalette && activeOption >= 0
                ? `spatial-search-option-${id}-${activeOption}`
                : undefined
            }
            autoComplete="off"
            spellCheck={false}
            placeholder="Search SECP..."
            value={query}
            onFocus={() => {
              setFocusWithin(true)
              setListOpen(true)
            }}
            onChange={(event) => {
              const next = event.target.value

              setQuery(next)
              setListOpen(true)
              setActiveIndex(0)

              if (next.trim() === '') {
                setActiveCategory('all')
              }
            }}
            onKeyDown={handleKeyDown}
          />

          {query !== '' ? (
            <button
              className="spatial-global-search__clear"
              type="button"
              aria-label="Clear search"
              onMouseDown={(event) => event.preventDefault()}
              onClick={(event) => {
                event.stopPropagation()
                clearSearch()
              }}
            >
              <X size={13} aria-hidden />
            </button>
          ) : null}
        </div>
      </div>

      {palette}

      <span className="sr-only" role="status" aria-live="polite">
        {announce}
      </span>
    </>
  )
}
