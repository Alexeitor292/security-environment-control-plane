import { LiquidGlass } from '../../components/liquid-glass'
import { SecpGlyph } from '../SecpGlyph'

interface AiSummaryWidgetProps {
  onOpen: () => void
}

export function AiSummaryWidget({ onOpen }: AiSummaryWidgetProps) {
  return (
    <LiquidGlass
      as="button"
      type="button"
      className="secp-widget secp-widget--compact secp-widget--ai liquid-glass--strong liquid-glass--interactive"
      contentClassName="secp-widget__content"
      onClick={onOpen}
    >
      <div className="secp-widget__header">
        <span>AI Core</span>
        <SecpGlyph className="ai-spark" name="ai" />
      </div>

      <div className="ai-widget-copy">
        <strong>3 recommendations</strong>
        <span>1 approval required</span>
      </div>

      <p className="secp-widget__footer">Open command center</p>
      <span className="secp-widget__action">Review recommendations</span>
    </LiquidGlass>
  )
}
