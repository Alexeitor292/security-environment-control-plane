import { Lock } from 'lucide-react'
import {
  AccordionSection,
  Button,
  CapabilityTag,
  Card,
  DataTable,
  StatusBadge,
} from '../../components'
import type { Column } from '../../components'
import type { ScenarioVersion } from '../../models/types'
import { useScenarioWorkspace } from '../../layouts/ScenarioWorkspaceLayout'

export default function ScenarioVersionsPage() {
  const { scenario } = useScenarioWorkspace()

  const columns: Column<ScenarioVersion>[] = [
    {
      key: 'version',
      header: 'Version',
      width: '120px',
      render: (v) => (
        <span className="u-row">
          <strong className="u-mono">v{v.version}</strong>
          {v.version === scenario.currentVersion && <span className="u-muted u-xs">(current)</span>}
        </span>
      ),
    },
    {
      key: 'createdAt',
      header: 'Created',
      width: '150px',
      render: (v) => (
        <span className="u-mono u-small">{v.createdAt.slice(0, 16).replace('T', ' ')} UTC</span>
      ),
    },
    {
      key: 'changelog',
      header: 'Changelog',
      render: (v) => <span className="u-small">{v.changelog}</span>,
    },
    {
      key: 'immutable',
      header: 'Immutability',
      width: '150px',
      render: (v) =>
        v.immutable ? (
          <span
            className="u-row"
            title="Content-hashed at publish time — the definition can never change under this version (ADR-002)"
          >
            <Lock size={12} aria-hidden className="u-muted" />
            <StatusBadge state="immutable" label="immutable" tone="info" />
          </span>
        ) : (
          <StatusBadge state="draft" label="mutable draft" />
        ),
    },
    {
      key: 'validation',
      header: 'Validation',
      width: '120px',
      render: (v) => <StatusBadge state={v.validation} />,
    },
  ]

  return (
    <div className="u-page">
      <Card
        heading="Version history"
        actions={
          <>
            <Button
              size="sm"
              disabled
              title="Prototype: version diffing is a proposed capability — not wired"
            >
              Compare…
            </Button>
            <Button
              size="sm"
              disabled
              title="Prototype: rollback is proposed. Immutable versions keep prior content addressable, but no rollback flow exists in the repo"
            >
              Roll back…
            </Button>
          </>
        }
      >
        <DataTable
          columns={columns}
          rows={scenario.versions}
          rowKey={(v) => v.version}
          label={`Versions of ${scenario.name}`}
          emptyTitle="No versions yet"
          emptyBody="Publish from the Builder to create the first immutable version."
        />
      </Card>

      <AccordionSection
        title="Immutability contract (ADR-002)"
        hint="why versions are locked"
        defaultOpen
      >
        <p className="u-secondary u-small" style={{ marginTop: 0 }}>
          Published environment versions are content-hashed and immutable in the platform{' '}
          <CapabilityTag status="implemented" /> — a real repo capability, not a prototype fiction.
          Editing never changes an existing version; it produces a new one. Deployments and
          approvals pin an exact version <em>and</em> its content hash, so an approval decision
          always refers to the precise definition that was reviewed — the definition cannot drift
          underneath a granted approval.
        </p>
        <p className="u-muted u-xs" style={{ marginBottom: 0 }}>
          Draft versions (not yet published) remain mutable and cannot be deployed.
        </p>
      </AccordionSection>
    </div>
  )
}
