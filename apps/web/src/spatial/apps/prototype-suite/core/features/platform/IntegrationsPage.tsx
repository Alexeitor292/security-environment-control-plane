import {
  Button,
  CapabilityTag,
  Card,
  CardGrid,
  ErrorState,
  KeyValueGrid,
  LoadingState,
} from '../../components'
import { useQuery } from '../../integrations/AdapterContext'
import type { IntegrationInfo } from '../../models/types'

const CATEGORIES: { key: IntegrationInfo['category']; label: string }[] = [
  { key: 'cloud', label: 'Cloud providers' },
  { key: 'virtualization', label: 'Virtualization' },
  { key: 'orchestration', label: 'Orchestration' },
  { key: 'identity', label: 'Identity' },
  { key: 'secrets', label: 'Secrets' },
  { key: 'storage', label: 'Storage' },
  { key: 'monitoring', label: 'Monitoring' },
  { key: 'automation', label: 'Automation' },
]

const CONCEPT_MAP = [
  { key: 'Temporal', value: 'Workflow Runs (Platform → Workflow Engine)' },
  { key: 'OpenBao', value: 'Secrets & Credentials' },
  { key: 'Keycloak', value: 'Identity & Access' },
  { key: 'WireGuard', value: 'Team Access (inside each event)' },
  { key: 'OpenTofu', value: 'Deployment Plan' },
  { key: 'Ansible', value: 'Configuration Run' },
  { key: 'MinIO', value: 'Evidence Storage' },
]

export default function IntegrationsPage() {
  const integrationsQ = useQuery((a) => a.listIntegrations())

  if (integrationsQ.loading) {
    return (
      <div className="u-page">
        <LoadingState lines={6} />
      </div>
    )
  }
  if (integrationsQ.error || !integrationsQ.data) {
    return (
      <div className="u-page">
        <ErrorState message={integrationsQ.error ?? 'Mock data unavailable.'} />
      </div>
    )
  }

  const integrations = integrationsQ.data

  return (
    <div className="u-page">
      <p className="u-secondary u-small">
        Everyday surfaces never expose these implementation names — users see product concepts, and
        this registry is where the mapping lives. Each entry carries its grounded capability status
        from the source repository.
      </p>

      <Card heading="Where integrations surface in the product">
        <KeyValueGrid columns={2} items={CONCEPT_MAP} />
      </Card>

      {CATEGORIES.map((cat) => {
        const list = integrations.filter((i) => i.category === cat.key)
        if (list.length === 0) return null
        return (
          <section key={cat.key} aria-label={cat.label}>
            <h2
              className="u-small"
              style={{
                textTransform: 'uppercase',
                letterSpacing: '0.06em',
                marginBottom: 'var(--sp-2)',
              }}
            >
              {cat.label}
            </h2>
            <CardGrid min={280}>
              {list.map((i) => (
                <Card key={i.id} heading={i.name} actions={<CapabilityTag status={i.status} />}>
                  <p className="u-secondary u-small">{i.detail}</p>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled
                    title="Prototype: integration configuration is not implemented"
                  >
                    Configure
                  </Button>
                </Card>
              ))}
            </CardGrid>
          </section>
        )
      })}
    </div>
  )
}
