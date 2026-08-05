import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Button,
  CapabilityNotice,
  CapabilityTag,
  DangerousOperationDialog,
  DataTable,
  Drawer,
  ErrorState,
  KeyValueGrid,
  LoadingState,
  ProviderBadge,
  StatusBadge,
} from '../../components'
import type { Column, StatusTone } from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { InfraTarget } from '../../models/types'

/**
 * Execution targets with the repo's onboarding lifecycle mapped onto each
 * card: registered → preflight → review → approved → activated. The fixture
 * `onboardingState` folds that chain into four funnel states ("plan-only"
 * corresponds to approved-for-plan).
 */

const CHAIN_STEPS = [
  { key: 'registered', label: 'Registered', detail: 'Target recorded with an immutable boundary' },
  {
    key: 'preflight',
    label: 'Preflight',
    detail: 'Hash-bound preflight evidence collected (fake-only today)',
  },
  { key: 'review', label: 'Review', detail: 'Operator reviews the pinned evidence bundle' },
  {
    key: 'approved',
    label: 'Approved',
    detail: 'Approval recorded — plan-only operation permitted',
  },
  { key: 'activated', label: 'Activated', detail: 'Eligible for gated execution' },
]

function chainIndex(state: InfraTarget['onboardingState']): number {
  switch (state) {
    case 'registered':
      return 0
    case 'preflight':
      return 1
    case 'plan-only':
      return 3
    case 'activated':
      return 4
  }
}

function fmtUtc(iso?: string): string {
  return iso ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : '—'
}

const COST_META: Record<InfraTarget['costStatus'], { tone: StatusTone; label: string }> = {
  ok: { tone: 'ok', label: 'on budget' },
  warning: { tone: 'warn', label: 'warning' },
  'over-budget': { tone: 'error', label: 'over budget' },
  'n/a': { tone: 'neutral', label: 'n/a' },
}

function CapacityBar({ usedPercent, detail }: { usedPercent: number; detail: string }) {
  const warn = usedPercent > 80
  return (
    <div className={`inf-capbar${warn ? ' inf-capbar--warn' : ''}`}>
      <div className="inf-capbar__track" role="img" aria-label={`${usedPercent}% capacity used`}>
        <div className="inf-capbar__fill" style={{ width: `${usedPercent}%` }} />
      </div>
      <span className="inf-capbar__label">
        {usedPercent}% · {detail}
      </span>
    </div>
  )
}

export default function TargetsPage() {
  const targetsQ = useQuery((a) => a.listTargets())
  const workersQ = useQuery((a) => a.listWorkers())
  const [selected, setSelected] = useState<InfraTarget | undefined>()
  const [disabling, setDisabling] = useState<InfraTarget | undefined>()

  if (targetsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (targetsQ.error || !targetsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={targetsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const targets = targetsQ.data
  const workers = workersQ.data ?? []
  const workerName = (id?: string) => workers.find((w) => w.id === id)?.name

  const columns: Column<InfraTarget>[] = [
    {
      key: 'name',
      header: 'Target',
      render: (t) => (
        <div>
          <strong className="u-small">{t.name}</strong>
          <span className="u-muted u-xs u-mono" style={{ display: 'block' }}>
            {t.id}
          </span>
        </div>
      ),
    },
    {
      key: 'provider',
      header: 'Provider',
      render: (t) => (
        <div className="u-row" style={{ flexWrap: 'wrap' }}>
          <ProviderBadge provider={t.provider} />
          <span className="u-muted u-xs">{t.location}</span>
        </div>
      ),
    },
    { key: 'health', header: 'Health', render: (t) => <StatusBadge state={t.health} /> },
    {
      key: 'capacity',
      header: 'Capacity',
      render: (t) => (
        <CapacityBar usedPercent={t.capacity.usedPercent} detail={t.capacity.detail} />
      ),
    },
    {
      key: 'cost',
      header: 'Cost',
      render: (t) => (
        <StatusBadge
          state={t.costStatus}
          label={COST_META[t.costStatus].label}
          tone={COST_META[t.costStatus].tone}
        />
      ),
    },
    {
      key: 'worker',
      header: 'Worker',
      render: (t) =>
        workerName(t.workerId) ? (
          <Link
            to="/infrastructure/workers"
            className="u-small u-mono"
            onClick={(e) => e.stopPropagation()}
          >
            {workerName(t.workerId)}
          </Link>
        ) : (
          <span className="u-muted u-xs">unassigned</span>
        ),
    },
    {
      key: 'credential',
      header: 'Credential',
      render: (t) => <StatusBadge state={t.credentialStatus} />,
    },
    {
      key: 'capabilities',
      header: 'Capabilities',
      render: (t) => (
        <div className="inf-chips">
          {t.capabilities.map((c) => (
            <span key={c} className="inf-chip">
              {c}
            </span>
          ))}
        </div>
      ),
    },
    { key: 'deployments', header: 'Deploys', align: 'right', render: (t) => t.deploymentCount },
    {
      key: 'discovery',
      header: 'Last discovery',
      render: (t) => <span className="u-xs u-mono">{fmtUtc(t.lastDiscovery)}</span>,
    },
    {
      key: 'onboarding',
      header: 'Onboarding',
      render: (t) => <StatusBadge state={t.onboardingState} />,
    },
  ]

  return (
    <div className="u-page">
      <CapabilityNotice capKey="infrastructure.targets" />
      <p className="u-secondary u-small" style={{ margin: 0 }}>
        Execution targets are the substrates deployments run on. The onboarding column maps the
        repo&rsquo;s registered → preflight → review → approved → activated lifecycle onto each
        target; only activated targets are eligible for gated execution. Click a row for the
        onboarding chain and actions.
      </p>

      <DataTable
        columns={columns}
        rows={targets}
        rowKey={(t) => t.id}
        onRowClick={setSelected}
        selectedKey={selected?.id}
        label="Execution targets"
        emptyTitle="No targets registered"
        emptyBody="Register a target to begin the onboarding funnel."
      />

      {selected && (
        <Drawer
          open
          title={selected.name}
          onClose={() => setSelected(undefined)}
          footer={
            <div className="u-spread">
              <span className="u-muted u-xs">Prototype — nothing executes.</span>
              <div className="u-row">
                <Button
                  size="sm"
                  disabled
                  title="Proposed guided registration wizard (replaces the current 7-step milestone wizard) — not wired in this prototype"
                >
                  Register target
                </Button>
                <Button
                  size="sm"
                  disabled
                  title="Discovery is queue-only and worker-owned; enqueueing is not wired in this prototype"
                >
                  Request discovery
                </Button>
                <Button size="sm" variant="danger" onClick={() => setDisabling(selected)}>
                  Disable…
                </Button>
              </div>
            </div>
          }
        >
          <div className="c-inspector">
            <div className="u-row" style={{ flexWrap: 'wrap' }}>
              <ProviderBadge provider={selected.provider} />
              <StatusBadge state={selected.health} />
              <StatusBadge state={selected.onboardingState} />
              <StatusBadge
                state={selected.credentialStatus}
                label={`credential: ${selected.credentialStatus}`}
              />
            </div>

            <KeyValueGrid
              columns={2}
              items={[
                { key: 'Target id', value: selected.id, mono: true },
                { key: 'Location', value: selected.location },
                {
                  key: 'Assigned worker',
                  value: workerName(selected.workerId) ? (
                    <Link to="/infrastructure/workers" className="u-mono">
                      {workerName(selected.workerId)}
                    </Link>
                  ) : (
                    'unassigned'
                  ),
                },
                { key: 'Deployments', value: selected.deploymentCount },
                {
                  key: 'Capacity',
                  value: `${selected.capacity.usedPercent}% · ${selected.capacity.detail}`,
                },
                { key: 'Cost status', value: COST_META[selected.costStatus].label },
                { key: 'Last discovery', value: fmtUtc(selected.lastDiscovery), mono: true },
                {
                  key: 'Capabilities',
                  value: (
                    <span className="inf-chips">
                      {selected.capabilities.map((c) => (
                        <span key={c} className="inf-chip">
                          {c}
                        </span>
                      ))}
                    </span>
                  ),
                },
              ]}
            />

            <section>
              <h4
                className="u-xs u-muted"
                style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
              >
                Onboarding chain
              </h4>
              <ol className="inf-chain">
                {CHAIN_STEPS.map((step, i) => {
                  const idx = chainIndex(selected.onboardingState)
                  const cls = i < idx ? 'is-done' : i === idx ? 'is-current' : undefined
                  return (
                    <li key={step.key} className={cls}>
                      <span>
                        {step.label}
                        <span className="u-muted u-xs" style={{ display: 'block' }}>
                          {step.detail}
                        </span>
                      </span>
                    </li>
                  )
                })}
              </ol>
              <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-1)' }}>
                Card state &ldquo;{selected.onboardingState}&rdquo; maps onto this chain;
                &ldquo;plan-only&rdquo; corresponds to approved (plans permitted, apply still
                sealed).
              </p>
            </section>

            <section>
              <h4
                className="u-xs u-muted"
                style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}
              >
                Preflight evidence
              </h4>
              <p className="u-secondary u-small" style={{ margin: '6px 0 0' }}>
                Onboarding decisions pin hash-bound preflight evidence bundles. Today the platform
                records fake-only evidence; the live-evidence path stays sealed.{' '}
                <CapabilityTag status="sealed" />
              </p>
            </section>
          </div>
        </Drawer>
      )}

      {disabling && (
        <DangerousOperationDialog
          open
          title={`Disable ${disabling.name}`}
          operation={`disable execution target ${disabling.id}`}
          requiredApprovals={['Platform operator', 'Infrastructure owner']}
          onClose={() => setDisabling(undefined)}
          preview={
            <ul style={{ margin: 0, paddingLeft: 18 }} className="u-small u-secondary">
              <li>New plans and applies for this target are refused</li>
              <li>
                {disabling.deploymentCount} existing deployment
                {disabling.deploymentCount === 1 ? '' : 's'} keep running but cannot be reset or
                repaired here
              </li>
              <li>Discovery requests stop being enqueued</li>
              <li>Re-enabling requires passing the onboarding chain again</li>
            </ul>
          }
        />
      )}
    </div>
  )
}
