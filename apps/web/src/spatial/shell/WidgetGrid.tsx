import type { SecpAppId } from './shellTypes'
import { AiSummaryWidget } from './widgets/AiSummaryWidget'
import { DeploymentsWidget } from './widgets/DeploymentsWidget'
import { DiscoveryWidget } from './widgets/DiscoveryWidget'
import { EnvironmentHealthWidget } from './widgets/EnvironmentHealthWidget'

interface WidgetGridProps {
  onOpenApp: (appId: SecpAppId) => void
  onOpenAi: () => void
}

export function WidgetGrid({ onOpenApp, onOpenAi }: WidgetGridProps) {
  return (
    <section className="widget-grid" aria-label="Operational widgets">
      <EnvironmentHealthWidget onOpen={() => onOpenApp('infrastructure')} />
      <DeploymentsWidget onOpen={() => onOpenApp('deployments')} />
      <DiscoveryWidget onOpen={() => onOpenApp('infrastructure')} />
      <AiSummaryWidget onOpen={onOpenAi} />
    </section>
  )
}
