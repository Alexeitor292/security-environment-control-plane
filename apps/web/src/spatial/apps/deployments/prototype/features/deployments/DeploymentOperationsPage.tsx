import { useState } from 'react'
import {
  Camera,
  FileText,
  Hammer,
  RefreshCcw,
  Scaling,
  SlidersHorizontal,
  Trash2,
} from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  CapabilityTag,
  Card,
  CardGrid,
  DangerousOperationDialog,
  Drawer,
  KeyValueGrid,
  LoadingState,
  StatusBadge,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import { useDeploymentWorkspace } from '../../layouts/DeploymentWorkspaceLayout'

const fmt = (t?: string) => (t ? `${t.slice(0, 10)} ${t.slice(11, 16)} UTC` : '—')

interface DangerousAction {
  key: string
  title: string
  operation: string
  approvals: string[]
  preview: string[]
}

export default function DeploymentOperationsPage() {
  const { deployment } = useDeploymentWorkspace()
  const runsQ = useQuery(
    (a) => a.listWorkflowRuns({ deploymentId: deployment.id }),
    [deployment.id],
  )

  const [planOpen, setPlanOpen] = useState(false)
  const [action, setAction] = useState<DangerousAction | undefined>()

  const runs = runsQ.data ?? []
  const currentRun =
    runs.find(
      (r) => r.status === 'running' || r.status === 'retrying' || r.status === 'awaiting-approval',
    ) ?? runs[0]

  const createCount = deployment.resources.length > 0 ? deployment.resources.length : 11

  const dangerousActions: Record<string, DangerousAction> = {
    reset: {
      key: 'reset',
      title: 'Reset deployment',
      operation: `reset ${deployment.name} to its scenario baseline`,
      approvals: ['Deployment owner', 'Platform operator'],
      preview: [
        `Roll back all resources to scenario version ${deployment.scenarioVersion} baseline`,
        'Capture evidence snapshots before any change',
        'Participant access suspended during the reset window',
        'Reset receipt (hash-bound) recorded in the evidence store',
      ],
    },
    repair: {
      key: 'repair',
      title: 'Repair unhealthy resources',
      operation: `repair unhealthy resources in ${deployment.name}`,
      approvals: ['Platform operator'],
      preview: [
        `Target only resources reporting degraded/unhealthy (${deployment.resources.filter((r) => r.health !== 'healthy').length} today)`,
        'Replace or restart per-resource, healthy resources untouched',
        'Pre-repair evidence capture, then health verification',
      ],
    },
    destroy: {
      key: 'destroy',
      title: 'Destroy deployment',
      operation: `destroy ${deployment.name} and all its resources`,
      approvals: ['Deployment owner', 'Platform admin'],
      preview: [
        `Destroy plan is generated and approved separately — the original apply approval does not cover destruction`,
        `${deployment.resources.length} resources would be removed (mock counts)`,
        'Evidence and audit records are retained; the environment is not recoverable',
        'High-risk: linked event surfaces lose this deployment',
      ],
    },
  }

  return (
    <div className="u-page">
      <CapabilityNotice capKey="deployments.apply" />

      <div
        className="u-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))' }}
      >
        <Card heading="Deployment plan" actions={<CapabilityTag status="implemented" />}>
          <p className="u-secondary u-small">
            Plans are deterministic, immutable, and hash-pinned. Approval pins the exact content
            hash — a changed plan requires a new approval.
          </p>
          <KeyValueGrid
            columns={1}
            items={[
              { key: 'Scenario version', value: `v${deployment.scenarioVersion} (immutable)` },
              { key: 'Approved plan hash', value: 'sha256:1acc59…7e0b (mock)', mono: true },
              { key: 'Generated', value: fmt(deployment.createdAt), mono: true },
            ]}
          />
          <Button
            size="sm"
            variant="secondary"
            icon={<FileText size={13} aria-hidden />}
            onClick={() => setPlanOpen(true)}
            style={{ marginTop: 'var(--sp-2)' }}
          >
            View plan summary
          </Button>
        </Card>

        <Card heading="Current workflow">
          {runsQ.loading ? (
            <LoadingState lines={4} />
          ) : !currentRun ? (
            <p className="u-secondary u-small">No workflow runs recorded for this deployment.</p>
          ) : (
            <>
              <div className="u-spread" style={{ marginBottom: 'var(--sp-2)' }}>
                <span className="u-small">{currentRun.name}</span>
                <StatusBadge state={currentRun.status} />
              </div>
              <ol style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                {currentRun.steps.map((s) => (
                  <li key={s.name} className="u-spread u-small" style={{ padding: '4px 0' }}>
                    <span>
                      {s.name}
                      {s.detail && <span className="u-muted u-xs"> — {s.detail}</span>}
                    </span>
                    <StatusBadge state={s.status} />
                  </li>
                ))}
              </ol>
              <p className="u-muted u-xs u-mono" style={{ marginTop: 'var(--sp-2)' }}>
                {currentRun.id} · queue {currentRun.taskQueue} · started {fmt(currentRun.startedAt)}
              </p>
            </>
          )}
        </Card>
      </div>

      <h2 className="u-small" style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        Operations
      </h2>
      <p className="u-muted u-xs">
        Every operation below is preview-and-confirm only. Real provisioning is sealed; the
        simulator is the only complete lifecycle.
      </p>
      <CardGrid min={260}>
        <Card heading="Reset" actions={<CapabilityTag status="simulated" />}>
          <p className="u-secondary u-small">
            Roll back to the scenario baseline. Evidence captured first; approval required.
          </p>
          <Button
            size="sm"
            variant="danger"
            icon={<RefreshCcw size={13} aria-hidden />}
            onClick={() => setAction(dangerousActions.reset)}
          >
            Reset…
          </Button>
        </Card>
        <Card heading="Snapshot" actions={<CapabilityTag status="planned" />}>
          <p className="u-secondary u-small">Capture a point-in-time snapshot of all resources.</p>
          <Button
            size="sm"
            disabled
            icon={<Camera size={13} aria-hidden />}
            title="Planned — snapshot lifecycle is not implemented in the platform"
          >
            Snapshot
          </Button>
        </Card>
        <Card heading="Reconfigure" actions={<CapabilityTag status="planned" />}>
          <p className="u-secondary u-small">
            Apply a newer scenario version via plan → approval → apply.
          </p>
          <Button
            size="sm"
            disabled
            icon={<SlidersHorizontal size={13} aria-hidden />}
            title="Planned — in-place reconfiguration is not implemented"
          >
            Reconfigure
          </Button>
        </Card>
        <Card heading="Repair" actions={<CapabilityTag status="planned" />}>
          <p className="u-secondary u-small">
            Replace or restart unhealthy resources only. No repair operation exists in the platform
            yet — this is a proposal.
          </p>
          <Button
            size="sm"
            variant="danger"
            icon={<Hammer size={13} aria-hidden />}
            onClick={() => setAction(dangerousActions.repair)}
          >
            Repair…
          </Button>
        </Card>
        <Card heading="Scale" actions={<CapabilityTag status="planned" />}>
          <p className="u-secondary u-small">
            Add or remove team zones within the scenario's team range.
          </p>
          <Button
            size="sm"
            disabled
            icon={<Scaling size={13} aria-hidden />}
            title="Planned — scaling operations are not implemented"
          >
            Scale
          </Button>
        </Card>
        <Card heading="Destroy" actions={<CapabilityTag status="simulated" />}>
          <p className="u-secondary u-small">
            Full destruction. A separate destroy plan and approval are required — high risk.
          </p>
          <Button
            size="sm"
            variant="danger"
            icon={<Trash2 size={13} aria-hidden />}
            onClick={() => setAction(dangerousActions.destroy)}
          >
            Destroy…
          </Button>
        </Card>
      </CardGrid>

      <Drawer open={planOpen} title="Plan summary (mock)" onClose={() => setPlanOpen(false)}>
        <p className="u-secondary u-small">
          Summary of the approved plan for <span className="u-mono">{deployment.name}</span>. The
          full plan artifact lives in the evidence store; this drawer shows mock fixture data only.
        </p>
        <KeyValueGrid
          columns={1}
          items={[
            { key: 'Resources to create', value: String(createCount), mono: true },
            { key: 'Resources to change', value: '0', mono: true },
            { key: 'Resources to destroy', value: '0', mono: true },
            { key: 'Approved hash', value: 'sha256:1acc59…7e0b (mock)', mono: true },
            { key: 'Scenario version', value: `v${deployment.scenarioVersion} (immutable)` },
            { key: 'Execution target', value: deployment.targetId, mono: true },
          ]}
        />
        <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)' }}>
          Approval is a decision only — it never executes. Apply composition is sealed (
          <CapabilityTag status="sealed" />
          ).
        </p>
      </Drawer>

      {action && (
        <DangerousOperationDialog
          open
          title={action.title}
          operation={action.operation}
          requiredApprovals={action.approvals}
          onClose={() => setAction(undefined)}
          preview={
            <ul style={{ margin: 0, paddingLeft: 18 }} className="u-small u-secondary">
              {action.preview.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          }
        />
      )}
    </div>
  )
}
