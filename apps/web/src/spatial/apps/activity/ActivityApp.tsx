import { LiquidGlass } from '../../components/liquid-glass'
import { SecpGlyph } from '../../shell/SecpGlyph'
import type { ShellActivity } from '../../shell/shellData'
import './ActivityApp.css'

interface ActivityAppProps {
  activities: ShellActivity[]
}

export function ActivityApp({ activities }: ActivityAppProps) {
  return (
    <div className="activity-app">
      <div className="activity-app__content">
        <header className="activity-app__header">
          <p>Live operations</p>
          <h1>Activity Center</h1>
          <span>Current enrollment, discovery, AI, and deployment events.</span>
        </header>

        <div className="activity-app__grid">
          {activities.map((activity) => (
            <LiquidGlass className="activity-card liquid-glass--strong" key={activity.id}>
              <div className="activity-card__icon">
                <SecpGlyph name={activity.glyph} />
              </div>

              <div className="activity-card__copy">
                <strong>{activity.title}</strong>
                <span>{activity.detail}</span>
              </div>

              <div className={`activity-card__state activity-card__state--${activity.state}`}>
                {activity.value}
              </div>
            </LiquidGlass>
          ))}
        </div>

        <LiquidGlass className="activity-timeline liquid-glass--strong">
          <div className="activity-timeline__header">
            <strong>Recent timeline</strong>
            <span>Today</span>
          </div>

          <div className="timeline-row">
            <i />
            <div>
              <strong>Container topology refreshed</strong>
              <span>9 workloads and 10 service paths observed</span>
            </div>
            <time>4m</time>
          </div>

          <div className="timeline-row">
            <i />
            <div>
              <strong>Proxmox enrollment profile prepared</strong>
              <span>Controlled read-only discovery selected</span>
            </div>
            <time>18m</time>
          </div>

          <div className="timeline-row">
            <i />
            <div>
              <strong>AI recommendation requires approval</strong>
              <span>Review before any execution capability is enabled</span>
            </div>
            <time>31m</time>
          </div>
        </LiquidGlass>
      </div>
    </div>
  )
}
