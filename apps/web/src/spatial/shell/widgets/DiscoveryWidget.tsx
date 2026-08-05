import { LiquidGlass } from '../../components/liquid-glass'

interface DiscoveryWidgetProps {
  onOpen: () => void
}

export function DiscoveryWidget({ onOpen }: DiscoveryWidgetProps) {
  return (
    <LiquidGlass
      as="button"
      type="button"
      className="secp-widget secp-widget--compact liquid-glass--strong liquid-glass--interactive"
      contentClassName="secp-widget__content"
      onClick={onOpen}
    >
      <div className="secp-widget__header">
        <span>Discovery</span>
        <span className="secp-widget__pulse" />
      </div>

      <div className="metric-row">
        <div>
          <strong>148</strong>
          <span>Assets</span>
        </div>

        <div>
          <strong>7</strong>
          <span>Changes</span>
        </div>
      </div>

      <p className="secp-widget__footer">Last scan 4 minutes ago</p>
      <span className="secp-widget__action">Open inventory & discovery</span>
    </LiquidGlass>
  )
}
