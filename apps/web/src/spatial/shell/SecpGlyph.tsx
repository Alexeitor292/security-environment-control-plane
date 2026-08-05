import type { SVGProps } from 'react'
import type { SecpGlyphName } from './shellTypes'

interface SecpGlyphProps extends SVGProps<SVGSVGElement> {
  name: SecpGlyphName
}

export function SecpGlyph({ name, ...props }: SecpGlyphProps) {
  const common = {
    fill: 'none',
    stroke: 'currentColor',
    strokeWidth: 1.7,
    strokeLinecap: 'round' as const,
    strokeLinejoin: 'round' as const,
  }

  const content = {
    home: (
      <>
        <path d="M4 11.5 12 5l8 6.5" />
        <path d="M6.5 10.5V20h11v-9.5" />
        <path d="M10 20v-5h4v5" />
      </>
    ),
    infrastructure: (
      <>
        <rect x="4" y="4" width="16" height="6" rx="1.6" />
        <rect x="4" y="14" width="16" height="6" rx="1.6" />
        <path d="M8 7h.01M8 17h.01M12 7h5M12 17h5" />
      </>
    ),
    environments: (
      <>
        <rect x="4" y="5" width="7" height="7" rx="1.5" />
        <rect x="13" y="5" width="7" height="7" rx="1.5" />
        <rect x="8.5" y="14" width="7" height="6" rx="1.5" />
        <path d="M7.5 12v2M16.5 12v2M12 12v2" />
      </>
    ),
    discovery: (
      <>
        <circle cx="11" cy="11" r="6" />
        <path d="m16 16 4 4M11 8v6M8 11h6" />
      </>
    ),
    ranges: (
      <>
        <path d="M12 3 20 7.5v9L12 21 4 16.5v-9Z" />
        <path d="m8 10 4-2 4 2-4 2Z" />
        <path d="M8 10v4l4 2 4-2v-4" />
      </>
    ),
    scenarios: (
      <>
        <path d="M5 5.5h14v13H5Z" />
        <path d="M8 9h8M8 12h5M8 15h7" />
        <path d="M9 3.5v4M15 3.5v4" />
      </>
    ),
    deployments: (
      <>
        <path d="M5 19 19 5M11 5h8v8" />
        <path d="M5 11v8h8" />
      </>
    ),
    network: (
      <>
        <circle cx="12" cy="5" r="2.3" />
        <circle cx="5" cy="18" r="2.3" />
        <circle cx="19" cy="18" r="2.3" />
        <path d="m10.8 7-4.6 8.8M13.2 7l4.6 8.8M7.3 18h9.4" />
      </>
    ),
    ai: (
      <>
        <path d="m12 3 1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8Z" />
        <path d="m18.5 15 .9 2.6L22 18.5l-2.6.9-.9 2.6-.9-2.6-2.6-.9 2.6-.9Z" />
      </>
    ),
    evidence: (
      <>
        <path d="M7 3h8l4 4v14H7Z" />
        <path d="M15 3v5h5M10 12h6M10 16h6M10 8h2" />
      </>
    ),
    reports: (
      <>
        <path d="M5 20V9M10 20V4M15 20v-7M20 20V7" />
        <path d="M3 20h19" />
      </>
    ),
    integrations: (
      <>
        <path d="M9 8 7 6a3 3 0 0 0-4 4l3 3a3 3 0 0 0 4 0l2-2" />
        <path d="m15 16 2 2a3 3 0 1 0 4-4l-3-3a3 3 0 0 0-4 0l-2 2" />
        <path d="m9 15 6-6" />
      </>
    ),
    administration: (
      <>
        <circle cx="12" cy="8" r="4" />
        <path d="M5 21a7 7 0 0 1 14 0" />
        <path d="M18 4v4M16 6h4" />
      </>
    ),
    settings: (
      <>
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" />
      </>
    ),
    activity: (
      <>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7v5l3 2" />
      </>
    ),
  } satisfies Record<SecpGlyphName, React.ReactNode>

  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false" {...common} {...props}>
      {content[name]}
    </svg>
  )
}
