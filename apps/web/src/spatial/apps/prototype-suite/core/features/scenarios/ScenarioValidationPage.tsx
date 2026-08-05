import { Link } from 'react-router-dom'
import { PlayCircle } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  CapabilityTag,
  Card,
  DataTable,
  StatusBadge,
} from '../../components'
import type { Column, StatusTone } from '../../components'
import type { CapabilityStatus, ValidationStatus } from '../../models/types'
import { useScenarioWorkspace } from '../../layouts/ScenarioWorkspaceLayout'

interface ValidationCheck {
  key: string
  name: string
  cap: CapabilityStatus
  result: { state: string; tone: StatusTone }
  detail: string
}

/** Maps the scenario's overall validation status to a per-check mock result. */
function mirrorResult(validation: ValidationStatus): { state: string; tone: StatusTone } {
  switch (validation) {
    case 'validated':
      return { state: 'passed', tone: 'ok' }
    case 'pending':
      return { state: 'pending', tone: 'neutral' }
    case 'failed':
      return { state: 'failed', tone: 'error' }
    case 'draft':
      return { state: 'not run', tone: 'neutral' }
  }
}

export default function ScenarioValidationPage() {
  const { scenario } = useScenarioWorkspace()
  const mirror = mirrorResult(scenario.validation)

  const checks: ValidationCheck[] = [
    {
      key: 'schema',
      name: 'Definition schema validation',
      cap: 'implemented',
      result: mirror,
      detail: 'YAML definition checked against the template schema server-side on every save.',
    },
    {
      key: 'topology',
      name: 'Topology validation',
      cap: 'implemented',
      result: mirror,
      detail: 'Nodes, links, and per-team CIDR reservations validated in the topology workspace.',
    },
    {
      key: 'plan-dry',
      name: 'Plan generation dry-check',
      cap: 'simulated',
      result: mirror,
      detail:
        'A deterministic plan is generated against the simulated lifecycle; no target is ever contacted.',
    },
    {
      key: 'provider-cap',
      name: 'Provider capability check',
      cap: 'partial',
      result: { state: 'partial coverage', tone: 'warn' },
      detail:
        'Proxmox target capabilities are checkable; cloud provider checks are mock (SECP-006 future work).',
    },
    {
      key: 'vuln-packs',
      name: 'Vulnerability pack validation',
      cap: 'planned',
      result: { state: 'not run', tone: 'neutral' },
      detail: 'Pack content exists as a documented YAML example only (SECP-003 not implemented).',
    },
    {
      key: 'scoring',
      name: 'Scoring check validation',
      cap: 'planned',
      result: { state: 'not run', tone: 'neutral' },
      detail: 'Scoring checks are not implemented in the platform (SECP-004).',
    },
  ]

  const columns: Column<ValidationCheck>[] = [
    { key: 'name', header: 'Check', render: (c) => <span className="u-small">{c.name}</span> },
    {
      key: 'cap',
      header: 'Capability',
      width: '130px',
      render: (c) => <CapabilityTag status={c.cap} />,
    },
    {
      key: 'result',
      header: 'Last result (mock)',
      width: '160px',
      render: (c) => <StatusBadge state={c.result.state} tone={c.result.tone} />,
    },
    {
      key: 'detail',
      header: 'Detail',
      render: (c) => <span className="u-muted u-xs">{c.detail}</span>,
    },
  ]

  return (
    <div className="u-page">
      <CapabilityNotice capKey="scenarios.validation" />

      <Card
        heading="Validation checks"
        actions={
          <Button
            size="sm"
            variant="primary"
            icon={<PlayCircle size={14} aria-hidden />}
            disabled
            title="Prototype: validation runs are not wired here — in the repo, definition and topology validation execute server-side on template save"
          >
            Run validation
          </Button>
        }
      >
        <DataTable
          columns={columns}
          rows={checks}
          rowKey={(c) => c.key}
          label={`Validation checks for ${scenario.name}`}
        />
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)', marginBottom: 0 }}>
          Mock results derive from this scenario's overall validation status (
          <StatusBadge state={scenario.validation} />
          ). Deeper deployment validation checks are proposed.
        </p>
      </Card>

      <Card heading="Test deployment chain">
        <p className="u-secondary u-small" style={{ marginTop: 0 }}>
          The strongest validation is a short-lived test deployment. The platform's chain is real
          end-to-end with simulated execution:
        </p>
        <ol
          className="u-small u-secondary"
          style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 6 }}
        >
          <li>
            Generate a deterministic plan from the pinned scenario version{' '}
            <CapabilityTag status="implemented" />
          </li>
          <li>
            Explicit approval with the content hash pinned — a decision only, never an execution{' '}
            <CapabilityTag status="implemented" />
          </li>
          <li>
            Deploy against the simulated lifecycle; effects are database records, not real
            infrastructure <CapabilityTag status="simulated" />
          </li>
        </ol>
        <p className="u-small" style={{ marginBottom: 0 }}>
          Test deployments would appear alongside the rest of the portfolio in{' '}
          <Link to="/deployments">Deployments</Link>.
        </p>
      </Card>
    </div>
  )
}
