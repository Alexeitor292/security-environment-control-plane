import { Archive, DatabaseBackup } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  CapabilityTag,
  Card,
  CardGrid,
  KeyValueGrid,
} from '../../components'

export default function RetentionPage() {
  return (
    <div className="u-page">
      <CapabilityNotice capKey="platform.retention" />

      <p className="u-secondary u-small">
        Proposed retention, backup, and residue policies (SECP-006 future work). All figures below
        are mock policy sketches — nothing is enforced or executable.
      </p>

      <CardGrid min={320}>
        <Card heading="Evidence retention" actions={<CapabilityTag status="planned" />}>
          <KeyValueGrid
            columns={1}
            items={[
              { key: 'Policy (mock)', value: 'Retain 365 days, then archive' },
              { key: 'Scope', value: 'Plans, apply/reset receipts, discovery snapshots, captures' },
              { key: 'Integrity', value: 'Hash-bound records; archive keeps SHA-256 index' },
            ]}
          />
          <Button
            size="sm"
            variant="ghost"
            disabled
            title="Prototype: retention policies are proposed — nothing is editable"
          >
            Edit policy
          </Button>
        </Card>

        <Card heading="Audit retention" actions={<CapabilityTag status="planned" />}>
          <p className="u-secondary u-small">
            The audit ledger is append-only with <strong>no deletion path</strong> — deletion is
            deliberately not a feature, so there is no retention window to configure. A proposed
            cold-storage tier would move (never remove) records older than 2 years.
          </p>
        </Card>

        <Card
          heading="Backups"
          actions={
            <span className="u-row">
              <DatabaseBackup size={14} aria-hidden className="u-muted" />
              <CapabilityTag status="planned" />
            </span>
          }
        >
          <KeyValueGrid
            columns={1}
            items={[
              { key: 'Schedule (mock)', value: 'Daily · 03:00 UTC · control-plane database' },
              {
                key: 'Last backup (mock)',
                value: '2026-07-18 03:00 UTC · verified checksum',
                mono: true,
              },
              { key: 'Restore drill', value: 'Planned — quarterly rehearsal, not yet scheduled' },
            ]}
          />
          <div className="u-row">
            <Button
              size="sm"
              variant="ghost"
              disabled
              title="Prototype: backup execution is proposed (no backend)"
            >
              Run backup now
            </Button>
            <Button
              size="sm"
              variant="ghost"
              disabled
              title="Prototype: restore drills are planned, not implemented"
            >
              Start restore drill
            </Button>
          </div>
        </Card>

        <Card
          heading="Destroyed-environment residue"
          actions={
            <span className="u-row">
              <Archive size={14} aria-hidden className="u-muted" />
              <CapabilityTag status="planned" />
            </span>
          }
        >
          <p className="u-secondary u-small">
            Zero-residue verification (ADR-020 concept): after a deployment is destroyed, a
            read-only discovery pass re-scans the target and verifies no orphaned VMs, networks, or
            storage remain, producing a hash-bound residue report. Destruction without verification
            is treated as incomplete.
          </p>
          <Button
            size="sm"
            variant="ghost"
            disabled
            title="Prototype: residue verification is a design concept (ADR-020), not implemented"
          >
            View residue reports
          </Button>
        </Card>
      </CardGrid>
    </div>
  )
}
