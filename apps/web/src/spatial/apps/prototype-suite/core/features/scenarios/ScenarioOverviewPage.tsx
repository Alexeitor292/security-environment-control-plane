import { Link } from 'react-router-dom'
import { Bug, FlaskConical } from 'lucide-react'
import {
  Button,
  CapabilityNotice,
  CapabilityTag,
  Card,
  KeyValueGrid,
  LoadingState,
  ProviderBadge,
  StatusBadge,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import { useScenarioWorkspace } from '../../layouts/ScenarioWorkspaceLayout'

const EXAMPLE_PACKS = [
  {
    id: 'weak-ssh',
    name: 'weak-ssh',
    summary:
      'Weak SSH configuration pack: password auth enabled, guessable credentials, permissive sshd policy. Exists in the repo as a documented YAML example only.',
  },
  {
    id: 'outdated-cms',
    name: 'outdated-cms',
    summary:
      'Outdated CMS pack: known-vulnerable web application versions with seeded misconfigurations. Proposed companion pack — not in the repo.',
  },
]

export default function ScenarioOverviewPage() {
  const { scenario } = useScenarioWorkspace()
  const deploymentsQ = useQuery((a) => a.listDeployments())
  const eventsQ = useQuery((a) => a.listEvents())

  const usedByDeployments = (deploymentsQ.data ?? []).filter((d) => d.scenarioId === scenario.id)
  const usedByEvents = (eventsQ.data ?? []).filter((e) => e.scenarioId === scenario.id)
  const latestVersions = scenario.versions.slice(0, 3)

  return (
    <div className="u-page">
      <p className="u-secondary" style={{ margin: 0, maxWidth: '70ch' }}>
        {scenario.purpose}
      </p>

      <Card heading="Profile">
        <KeyValueGrid
          columns={3}
          items={[
            { key: 'Difficulty', value: <StatusBadge state={scenario.difficulty} tone="info" /> },
            { key: 'Team range', value: `${scenario.teamRange[0]}–${scenario.teamRange[1]} teams` },
            {
              key: 'Estimated resources',
              value: `${scenario.estimatedResources.vms} VMs · ${scenario.estimatedResources.containers} containers · ${scenario.estimatedResources.networks} networks`,
            },
            { key: 'Est. cost', value: `$${scenario.estimatedCostPerHour.toFixed(2)}/h (mock)` },
            {
              key: 'Providers',
              value: (
                <span className="u-row" style={{ flexWrap: 'wrap' }}>
                  {scenario.supportedProviders.map((p) => (
                    <ProviderBadge key={p} provider={p} />
                  ))}
                </span>
              ),
            },
            { key: 'Required plugins', value: scenario.requiredPlugins.join(', '), mono: true },
            { key: 'Current version', value: `v${scenario.currentVersion}`, mono: true },
            {
              key: 'Updated',
              value: scenario.updatedAt.slice(0, 16).replace('T', ' ') + ' UTC',
              mono: true,
            },
          ]}
        />
      </Card>

      <div
        className="u-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}
      >
        <Card
          heading="Versions"
          actions={
            <Link to={`/scenarios/${scenario.id}/versions`} className="u-xs">
              all versions →
            </Link>
          }
        >
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {latestVersions.map((v) => (
              <li key={v.version} style={{ padding: '6px 0' }}>
                <div className="u-spread">
                  <span className="u-row u-small">
                    <strong className="u-mono">v{v.version}</strong>
                    {v.version === scenario.currentVersion && (
                      <span className="u-muted u-xs">(current)</span>
                    )}
                  </span>
                  <StatusBadge state={v.validation} />
                </div>
                <p className="u-muted u-xs" style={{ margin: '2px 0 0' }}>
                  {v.createdAt.slice(0, 10)} — {v.changelog}
                </p>
              </li>
            ))}
          </ul>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)', marginBottom: 0 }}>
            Published versions are immutable and content-hashed (real repo capability).
          </p>
        </Card>

        <Card
          heading="Vulnerability packs"
          actions={<Bug size={14} aria-hidden className="u-muted" />}
        >
          <CapabilityNotice capKey="scenarios.vulnerabilities" />
          <p className="u-secondary u-small">
            Proposed model: reusable packs attach to scenario resources and activate per competition
            phase — dormant during hardening, armed when the attack phase opens.
          </p>
          <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
            {EXAMPLE_PACKS.map((pack) => (
              <li key={pack.id} style={{ padding: '5px 0' }}>
                <strong className="u-small u-mono">{pack.name}</strong>
                <p className="u-muted u-xs" style={{ margin: '2px 0 0' }}>
                  {pack.summary}
                </p>
              </li>
            ))}
          </ul>
        </Card>

        <Card
          heading="Test deployment"
          actions={<FlaskConical size={14} aria-hidden className="u-muted" />}
        >
          <p className="u-secondary u-small">
            Spin up a short-lived instance of this scenario to verify it end-to-end before an event:
            plan → approval → deploy, with automatic destruction.
          </p>
          <div className="u-row">
            <Button
              variant="secondary"
              disabled
              title="Test deployment uses the simulated lifecycle — no real infrastructure is provisioned; not wired in the prototype"
            >
              Start test deployment
            </Button>
            <CapabilityTag status="simulated" />
          </div>
        </Card>

        <Card heading="Used by">
          {deploymentsQ.loading || eventsQ.loading ? (
            <LoadingState lines={3} />
          ) : usedByDeployments.length === 0 && usedByEvents.length === 0 ? (
            <p className="u-secondary u-small">
              No deployments or events currently use this scenario.
            </p>
          ) : (
            <>
              {usedByEvents.length > 0 && (
                <>
                  <h4
                    className="u-xs u-muted"
                    style={{
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em',
                      margin: '0 0 4px',
                    }}
                  >
                    Events
                  </h4>
                  <ul style={{ listStyle: 'none', margin: '0 0 var(--sp-2)', padding: 0 }}>
                    {usedByEvents.map((e) => (
                      <li key={e.id} className="u-spread u-small" style={{ padding: '4px 0' }}>
                        <Link to={`/events/${e.id}`}>{e.name}</Link>
                        <span className="u-row">
                          <span className="u-muted u-xs u-mono">v{e.scenarioVersion}</span>
                          <StatusBadge state={e.status} />
                        </span>
                      </li>
                    ))}
                  </ul>
                </>
              )}
              {usedByDeployments.length > 0 && (
                <>
                  <h4
                    className="u-xs u-muted"
                    style={{
                      textTransform: 'uppercase',
                      letterSpacing: '0.06em',
                      margin: '0 0 4px',
                    }}
                  >
                    Deployments
                  </h4>
                  <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                    {usedByDeployments.map((d) => (
                      <li key={d.id} className="u-spread u-small" style={{ padding: '4px 0' }}>
                        <Link to={`/deployments/${d.id}`}>{d.name}</Link>
                        <span className="u-row">
                          <span className="u-muted u-xs u-mono">v{d.scenarioVersion}</span>
                          <StatusBadge state={d.state} />
                        </span>
                      </li>
                    ))}
                  </ul>
                </>
              )}
            </>
          )}
        </Card>
      </div>
    </div>
  )
}
