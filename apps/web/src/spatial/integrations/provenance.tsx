/**
 * Data provenance for the spatial frontend.
 *
 * WHY THIS EXISTS
 *
 * The migrated prototype reaches its data through `ControlPlaneAdapter`. That
 * boundary shipped with a default that is correct for a prototype and unsafe
 * for a product:
 *
 *     const AdapterContext = createContext<ControlPlaneAdapter>(mockAdapter)
 *     export function AdapterProvider({ adapter = mockAdapter, ... })
 *
 * Fixture data is what you get when nobody says otherwise, in every build, with
 * no signal of any kind. A page served from `mocks/` and a page served from the
 * real control plane render identically. That is the same shape of defect this
 * repository has already shipped once: a banner reading "Simulated execution
 * only -- no real infrastructure" stayed green in tests for months after it
 * became false, while two real vulnerable containers were running. The lesson
 * taken from that incident was that a *claim* about data ("this is simulated")
 * is worthless unless it is derived from the thing it describes and is
 * observable at runtime.
 *
 * So provenance here is not a string a component prints. It is a required field
 * on the adapter itself, declared by the implementation that serves the data,
 * published to the DOM, and rendered as a badge. A page cannot show fixture
 * data without also carrying `data-secp-data-provenance="fixture"` and a
 * visible label, because both are read off the same adapter object that
 * produced the rows.
 *
 * HOW THIS IS TESTED
 *
 * Not by asserting the badge's copy -- that would just restate a string this
 * file wrote. The test mounts the *same* component twice against two adapters
 * whose only relevant difference is the provenance they declare, and asserts
 * the observable differs accordingly. The expectation is read from the adapter
 * object, never from a literal duplicated in the test. See
 * `provenance.render.test.tsx`.
 */

import type { ReactNode } from 'react'
import './provenance.css'

/**
 * Where the rows on screen actually came from.
 *
 * `fixture` -- static data compiled into the bundle. No infrastructure was
 *   contacted. Nothing on screen reflects the state of any real system.
 * `live`    -- data read from the SECP control-plane API for the caller's
 *   authenticated principal.
 */
export type AdapterProvenance = 'fixture' | 'live'

/** DOM attribute carrying the provenance of the subtree beneath it. */
export const PROVENANCE_ATTRIBUTE = 'data-secp-data-provenance'

/**
 * Anything that can serve the spatial UI its data must say where the data came
 * from. This is a required field, deliberately: a new adapter cannot compile
 * without answering the question, so "we forgot to mark it" is not reachable.
 */
export interface ProvenanceDeclaring {
  readonly provenance: AdapterProvenance
}

/** True when the subtree is being served static, compiled-in fixture data. */
export function isFixture(source: ProvenanceDeclaring): boolean {
  return source.provenance === 'fixture'
}

/**
 * Wraps a subtree and publishes its data provenance.
 *
 * The attribute is always emitted -- for `live` as much as for `fixture` -- so
 * that "no attribute" is a detectable bug rather than an implicit claim of
 * being real. The badge renders only for fixture data.
 */
export function ProvenanceBoundary({
  source,
  className,
  children,
}: {
  source: ProvenanceDeclaring
  className?: string
  children: ReactNode
}) {
  const provenance = source.provenance

  return (
    <div
      className={['secp-provenance', className].filter(Boolean).join(' ')}
      {...{ [PROVENANCE_ATTRIBUTE]: provenance }}
    >
      {provenance === 'fixture' ? <FixtureBadge /> : null}
      {children}
    </div>
  )
}

/**
 * Persistent, visible marker that the surrounding surface is showing fixture
 * data.
 *
 * Deliberately not dismissible and not suppressed in production builds. The
 * point of the badge is the production case: a demo build handed to someone who
 * did not build it must not be able to pass fixture rows off as the state of
 * their estate. `role="status"` rather than `alert` -- it is a standing
 * condition of the surface, not an event.
 */
export function FixtureBadge() {
  return (
    <div className="secp-fixture-badge" role="status" data-testid="secp-fixture-badge">
      <span className="secp-fixture-badge__dot" aria-hidden="true" />
      <span className="secp-fixture-badge__text">
        Sample data &mdash; not your environment. Nothing here reflects real infrastructure.
      </span>
    </div>
  )
}
