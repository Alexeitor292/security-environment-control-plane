import {
  AccordionSection,
  AdvancedSection,
  CapabilityNotice,
  CapabilityTag,
  DataTable,
  KeyValueGrid,
  StatusBadge,
} from '../../components'
import type { Column } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import { useDeploymentWorkspace } from '../../layouts/DeploymentWorkspaceLayout'
import type { DeploymentResource, EvidenceRecord, SecretRef } from '../../models/types'

const fmt = (t?: string) => (t ? `${t.slice(0, 10)} ${t.slice(11, 16)} UTC` : '—')

const MOCK_LOG_LINES = [
  '2026-07-18T12:45:01Z INFO  worker    task=discovery target=[redacted] mode=read-only',
  '2026-07-18T12:45:02Z INFO  planner   plan hash pinned sha256:1acc59… (content-addressed)',
  '2026-07-18T12:45:02Z INFO  gate      approval check: decision recorded, execution NOT triggered',
  '2026-07-18T12:45:03Z WARN  runner    apply requested — refused: _B1A_SUBPROCESS_SEALED=True',
  '2026-07-18T12:45:03Z INFO  audit     refusal recorded resource=[redacted] outcome=denied',
]

export default function DeploymentAdvancedPage() {
  const { deployment } = useDeploymentWorkspace()
  const runsQ = useQuery(
    (a) => a.listWorkflowRuns({ deploymentId: deployment.id }),
    [deployment.id],
  )
  const targetsQ = useQuery((a) => a.listTargets())
  const workersQ = useQuery((a) => a.listWorkers())
  const evidenceQ = useQuery((a) => a.listEvidence())
  const secretsQ = useQuery((a) => a.listSecretRefs())

  const runs = runsQ.data ?? []
  const target = (targetsQ.data ?? []).find((t) => t.id === deployment.targetId)
  const worker = (workersQ.data ?? []).find((w) => w.id === target?.workerId)
  const evidence = (evidenceQ.data ?? []).filter(
    (e) => e.subject.includes(deployment.id) || e.subject.includes(deployment.name),
  )
  const secretRefs = (secretsQ.data ?? []).filter((s) => s.provider === deployment.provider)

  const refColumns: Column<DeploymentResource>[] = [
    {
      key: 'name',
      header: 'Resource',
      render: (r) => <span className="u-mono u-small">{r.name}</span>,
    },
    {
      key: 'kind',
      header: 'Kind',
      render: (r) => <span className="u-small">{r.kind.replace(/-/g, ' ')}</span>,
    },
    {
      key: 'ref',
      header: 'Provider ref (mock)',
      render: (r) => <span className="u-mono u-xs">{r.providerRef}</span>,
    },
  ]

  const evidenceColumns: Column<EvidenceRecord>[] = [
    {
      key: 'time',
      header: 'Time',
      render: (e) => <span className="u-mono u-xs">{fmt(e.time)}</span>,
    },
    {
      key: 'kind',
      header: 'Kind',
      render: (e) => <span className="u-small">{e.kind.replace(/-/g, ' ')}</span>,
    },
    {
      key: 'subject',
      header: 'Subject',
      render: (e) => <span className="u-small">{e.subject}</span>,
    },
    {
      key: 'sha',
      header: 'sha256',
      render: (e) => <span className="u-mono u-xs">{e.sha256}</span>,
    },
    {
      key: 'store',
      header: 'Store path',
      render: (e) => <span className="u-mono u-xs">{e.store}</span>,
    },
  ]

  const secretColumns: Column<SecretRef>[] = [
    {
      key: 'name',
      header: 'Reference',
      render: (s) => <span className="u-mono u-small">{s.name}</span>,
    },
    {
      key: 'type',
      header: 'Credential type',
      render: (s) => <span className="u-small">{s.credentialType}</span>,
    },
    {
      key: 'consumer',
      header: 'Consumer',
      render: (s) => <span className="u-xs">{s.consumer}</span>,
    },
    {
      key: 'rotation',
      header: 'Rotation',
      render: (s) => <span className="u-xs">{s.rotationSchedule}</span>,
    },
    { key: 'health', header: 'Health', render: (s) => <StatusBadge state={s.health} /> },
  ]

  return (
    <div className="u-page">
      <p className="u-muted u-small" role="note">
        Level 3 detail — implementation technology names appear here, never in primary navigation.
      </p>

      <AccordionSection title="OpenTofu plan & state references" hint="plan-only">
        <p className="u-secondary u-small">
          {/* This previously read "the apply subprocess is hard-sealed ... no real host has
              ever been contacted". That was an absolute safety assertion the page cannot
              observe, and it had already been falsified by the time it was migrated: the
              Proxmox apply and destroy paths shipped in SECP-PROXMOX. Whether an apply can
              reach a host is a property of the running control plane, not of this component. */}
          Plan generation is hash-pinned. Whether an apply can execute against a real host, and
          under what authorization, is determined by the control plane — this page does not
          observe it and does not assert it either way.
        </p>
        <KeyValueGrid
          columns={1}
          items={[
            {
              key: 'Plan artifact',
              value: `plans/${deployment.id}/tofu-plan.bin (mock ref)`,
              mono: true,
            },
            { key: 'Plan hash', value: 'sha256:1acc59…7e0b (mock)', mono: true },
            {
              key: 'State reference',
              value: `states/${deployment.id}/terraform.tfstate (mock ref)`,
              mono: true,
            },
            { key: 'Backend', value: 'S3-compatible evidence/state store (mock ref)', mono: true },
          ]}
        />
      </AccordionSection>

      <AccordionSection title="Configuration runs / Ansible" hint="planned">
        <p className="u-secondary u-small">
          Configuration runs (Ansible) are documented in the scenario contract, but no runner exists
          — SECP-003 content/configuration packs are not implemented.{' '}
          <CapabilityTag status="planned" />
        </p>
      </AccordionSection>

      <AccordionSection title="Provider API details" hint="mock refs">
        <p className="u-secondary u-small">
          Realized provider identifiers for this deployment's resources. All values are mock
          fixtures.
        </p>
        <DataTable
          columns={refColumns}
          rows={deployment.resources}
          rowKey={(r) => r.id}
          label="Provider references"
          emptyTitle="No realized resources"
          emptyBody="This deployment is plan-only — no provider objects exist."
        />
      </AccordionSection>

      <AccordionSection title="Workflow engine details" hint="Temporal">
        <p className="u-secondary u-small">
          Durable dispatch (inline default + Temporal path + transactional outbox) is implemented;
          this console view is proposed. <CapabilityTag status="partial" />
        </p>
        {runs.length === 0 ? (
          <p className="u-secondary u-small">No workflow runs recorded for this deployment.</p>
        ) : (
          <KeyValueGrid
            columns={1}
            items={runs.map((r) => ({
              key: r.id,
              value: (
                <span className="u-row">
                  <span className="u-mono u-xs">queue {r.taskQueue}</span>
                  <StatusBadge state={r.status} />
                  <span className="u-muted u-xs">{fmt(r.startedAt)}</span>
                </span>
              ),
              mono: true,
            }))}
          />
        )}
      </AccordionSection>

      <AccordionSection title="Evidence & receipts">
        <p className="u-secondary u-small">
          Hash-bound evidence records tied to this deployment. Records are real platform capability;
          storage browsing is proposed. <CapabilityTag status="partial" />
        </p>
        <DataTable
          columns={evidenceColumns}
          rows={evidence}
          rowKey={(e) => e.id}
          label="Evidence records"
          emptyTitle="No evidence records"
          emptyBody="No evidence fixture entries reference this deployment."
        />
      </AccordionSection>

      <AdvancedSection title="Worker execution">
        <p className="u-secondary u-small">
          Execution is worker-owned; the control plane only dispatches and records receipts.{' '}
          <CapabilityTag status="partial" />
        </p>
        {worker ? (
          <KeyValueGrid
            columns={1}
            items={[
              { key: 'Worker', value: `${worker.name} (${worker.id})`, mono: true },
              { key: 'Status', value: <StatusBadge state={worker.status} /> },
              { key: 'Task queues', value: worker.taskQueues.join(', '), mono: true },
              { key: 'Last heartbeat', value: fmt(worker.lastHeartbeat), mono: true },
              { key: 'Version', value: worker.version, mono: true },
              {
                key: 'Receipts',
                value: `${evidence.length} hash-bound receipt(s) in the evidence store (mock)`,
              },
            ]}
          />
        ) : (
          <p className="u-secondary u-small">
            No worker is bound to this deployment's target in the fixtures.
          </p>
        )}
      </AdvancedSection>

      <AdvancedSection title="Secret references">
        <CapabilityNotice capKey="platform.secrets" />
        <p className="u-secondary u-small">
          Metadata only — secret values never reach the control plane or this UI. References scoped
          to provider: {deployment.provider}.
        </p>
        <DataTable
          columns={secretColumns}
          rows={secretRefs}
          rowKey={(s) => s.id}
          label="Secret references"
          emptyTitle="No secret references"
          emptyBody="No secret-reference fixtures exist for this provider."
        />
      </AdvancedSection>

      <AdvancedSection title="Raw logs">
        <p className="u-muted u-xs">
          Mock, redacted excerpt — there is no live log pipeline in the prototype.
        </p>
        <pre className="c-raw">{MOCK_LOG_LINES.join('\n')}</pre>
      </AdvancedSection>
    </div>
  )
}
