import { FlaskConical } from 'lucide-react'

/**
 * Permanent truthfulness disclosure. Mirrors the source repo's top-bar
 * pattern ("Simulated environment…"): the prototype must always identify
 * itself and its data as mock.
 */
export function PrototypeBanner() {
  return (
    <span
      className="p-banner"
      role="note"
      title="UX Prototype — mock data only, no real infrastructure"
    >
      <FlaskConical size={12} aria-hidden />
      {/* Progressive tiers. Narrow viewports hide the tail *visually* only —
          each tier drops to `.sr-only`, never `display: none`, so the complete
          disclosure stays in the accessibility tree at every width. */}
      <strong className="p-banner__label">UX Prototype</strong>
      <span className="p-banner__mock">
        <span aria-hidden>·</span> Mock data
      </span>
      <span className="p-banner__detail">— no real infrastructure</span>
    </span>
  )
}
