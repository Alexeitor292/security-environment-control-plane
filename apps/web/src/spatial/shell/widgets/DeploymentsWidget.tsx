import { LiquidGlass } from '../../components/liquid-glass'

const deployments = [
  { name: 'Range Alpha', state: 'Running', progress: 100 },
  { name: 'Range Beta', state: 'Provisioning', progress: 72 },
  { name: 'Lab Gamma', state: 'Paused', progress: 38 },
]

interface DeploymentsWidgetProps {
  onOpen: () => void
}

export function DeploymentsWidget({ onOpen }: DeploymentsWidgetProps) {
  return (
    <LiquidGlass
      as="button"
      type="button"
      className="secp-widget secp-widget--deployments liquid-glass--strong liquid-glass--interactive"
      contentClassName="secp-widget__content"
      onClick={onOpen}
    >
      <div className="secp-widget__header">
        <span>Active deployments</span>
        <strong>3</strong>
      </div>

      <div className="deployment-list">
        {deployments.map((deployment) => (
          <div className="deployment-item" key={deployment.name}>
            <div>
              <strong>{deployment.name}</strong>
              <span>{deployment.state}</span>
            </div>

            <div className="deployment-progress" aria-label={`${deployment.progress}%`}>
              <span style={{ width: `${deployment.progress}%` }} />
            </div>
          </div>
        ))}
      </div>

      <span className="secp-widget__action">Open deployments</span>
    </LiquidGlass>
  )
}
