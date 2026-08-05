import type { TopologyNode } from '../models/types'
import { AccordionSection, AdvancedSection } from './Accordion'
import { CapabilityTag } from './CapabilityNotice'
import { KeyValueGrid } from './KeyValueGrid'
import { StatusBadge } from './StatusBadge'

/**
 * Replaceable slot: right-side resource inspector.
 * Level 1: basic settings. Level 2: collapsed operational sections.
 * Level 3: expert sections behind the Advanced Controls toggle.
 */
export function ResourceInspector({ node, teamName }: { node: TopologyNode; teamName?: string }) {
  return (
    <div className="c-inspector">
      <div className="u-spread">
        <StatusBadge state={node.status} />
        <span className="u-muted u-xs u-mono">{node.id}</span>
      </div>

      <KeyValueGrid
        columns={1}
        items={[
          { key: 'Name', value: node.label },
          { key: 'Role', value: node.meta?.role ?? node.kind },
          ...(node.meta?.os ? [{ key: 'Image', value: node.meta.os }] : []),
          ...(node.ip ? [{ key: 'Address', value: node.ip, mono: true }] : []),
          ...(node.subnet ? [{ key: 'Network', value: node.subnet, mono: true }] : []),
          ...(teamName ? [{ key: 'Team ownership', value: teamName }] : []),
          ...(node.meta?.placement ? [{ key: 'Placement', value: node.meta.placement }] : []),
        ]}
      />

      <AccordionSection title="Advanced networking" hint="collapsed by default">
        <p className="u-secondary u-small">
          Interface, VLAN, and route configuration would appear here.{' '}
          <CapabilityTag status="planned" />
        </p>
      </AccordionSection>
      <AccordionSection title="Firewall policy">
        <p className="u-secondary u-small">
          Zone policy and per-phase rules would appear here. <CapabilityTag status="planned" />
        </p>
      </AccordionSection>
      <AccordionSection title="Vulnerabilities">
        <p className="u-secondary u-small">
          Attached vulnerability packs ({node.meta?.packs ?? 'none'}) with activation schedules.{' '}
          <CapabilityTag status="planned" />
        </p>
      </AccordionSection>
      <AccordionSection title="Monitoring">
        <p className="u-secondary u-small">
          Agent coverage and telemetry destinations. <CapabilityTag status="planned" />
        </p>
      </AccordionSection>
      <AccordionSection title="Scoring">
        <p className="u-secondary u-small">
          Availability checks and objectives bound to this resource.{' '}
          <CapabilityTag status="planned" />
        </p>
      </AccordionSection>

      <AdvancedSection title="Secrets">
        <p className="u-secondary u-small">
          Opaque secret references only — values never leave the worker.{' '}
          <CapabilityTag status="sealed" />
        </p>
      </AdvancedSection>
      <AdvancedSection title="Provider placement">
        <KeyValueGrid
          columns={1}
          items={[{ key: 'Provider ref', value: node.meta?.placement ?? 'auto', mono: true }]}
        />
      </AdvancedSection>
      <AdvancedSection title="Raw configuration">
        <pre className="c-raw">{JSON.stringify(node, null, 2)}</pre>
      </AdvancedSection>
    </div>
  )
}
