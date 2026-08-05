import { LiquidGlass } from '../../components/liquid-glass'

interface EnvironmentHealthWidgetProps {
  onOpen: () => void
}

export function EnvironmentHealthWidget({ onOpen }: EnvironmentHealthWidgetProps) {
  return (
    <LiquidGlass
      as="button"
      type="button"
      className="secp-widget secp-widget--health liquid-glass--strong liquid-glass--interactive"
      contentClassName="secp-widget__content"
      onClick={onOpen}
    >
      <div className="secp-widget__header">
        <span>Environment health</span>
        <span className="secp-widget__live">Live</span>
      </div>

      <div className="health-score">
        <strong>92%</strong>
        <span>Operational</span>
      </div>

      <div className="health-breakdown">
        <span>
          <i className="health-dot health-dot--healthy" />
          12 healthy
        </span>
        <span>
          <i className="health-dot health-dot--degraded" />1 degraded
        </span>
        <span>
          <i className="health-dot health-dot--offline" />0 offline
        </span>
      </div>

      <span className="secp-widget__action">Open infrastructure</span>
    </LiquidGlass>
  )
}
