import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { CheckCircle2 } from 'lucide-react'
import { Button, CapabilityTag, Card, PageHeader, ProviderBadge } from '../../components'
import type { Provider, ScenarioDifficulty } from '../../models/types'

const ALL_PROVIDERS: Provider[] = ['proxmox', 'aws', 'azure', 'gcp', 'kubernetes', 'vmware']

export default function NewScenarioPage() {
  const navigate = useNavigate()
  const [name, setName] = useState('')
  const [purpose, setPurpose] = useState('')
  const [difficulty, setDifficulty] = useState<ScenarioDifficulty>('intro')
  const [teamMin, setTeamMin] = useState(1)
  const [teamMax, setTeamMax] = useState(4)
  const [providers, setProviders] = useState<Provider[]>(['proxmox'])
  const [confirmed, setConfirmed] = useState(false)

  const toggleProvider = (p: Provider) => {
    setConfirmed(false)
    setProviders((prev) => (prev.includes(p) ? prev.filter((x) => x !== p) : [...prev, p]))
  }

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    setConfirmed(true)
  }

  return (
    <div className="u-page">
      <PageHeader
        title="New scenario"
        capabilityStatus="ui-only"
        description="A proposed friendlier front for creating an Environment Template. The underlying repo flow — YAML definition editor, server-side validation, immutable content-hashed versions — is implemented; this simple form is a design draft on top of it."
        actions={
          <Button variant="ghost" onClick={() => navigate('/scenarios')}>
            Back to library
          </Button>
        }
      />

      <div
        className="u-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))' }}
      >
        <Card heading="Scenario basics">
          <form className="sf-form" onSubmit={onSubmit} aria-label="New scenario">
            <label className="sf-field">
              <span>Name</span>
              <input
                type="text"
                value={name}
                onChange={(e) => {
                  setName(e.target.value)
                  setConfirmed(false)
                }}
                placeholder="e.g. Coastal Grid Defense"
                required
              />
            </label>

            <label className="sf-field">
              <span>Purpose</span>
              <textarea
                value={purpose}
                onChange={(e) => {
                  setPurpose(e.target.value)
                  setConfirmed(false)
                }}
                placeholder="What is this scenario for? Who plays it, and what should it teach or test?"
              />
            </label>

            <label className="sf-field">
              <span>Difficulty</span>
              <select
                value={difficulty}
                onChange={(e) => {
                  setDifficulty(e.target.value as ScenarioDifficulty)
                  setConfirmed(false)
                }}
              >
                <option value="intro">Intro</option>
                <option value="intermediate">Intermediate</option>
                <option value="advanced">Advanced</option>
                <option value="expert">Expert</option>
              </select>
            </label>

            <div className="sf-field">
              <span>Team range</span>
              <div className="sf-range">
                <input
                  type="number"
                  min={1}
                  max={teamMax}
                  value={teamMin}
                  onChange={(e) => {
                    setTeamMin(Number(e.target.value) || 1)
                    setConfirmed(false)
                  }}
                  aria-label="Minimum teams"
                />
                <span className="u-muted u-small">to</span>
                <input
                  type="number"
                  min={teamMin}
                  value={teamMax}
                  onChange={(e) => {
                    setTeamMax(Number(e.target.value) || teamMin)
                    setConfirmed(false)
                  }}
                  aria-label="Maximum teams"
                />
                <span className="u-muted u-small">teams</span>
              </div>
            </div>

            <fieldset className="sf-field" style={{ border: 'none', margin: 0, padding: 0 }}>
              <span>Target providers</span>
              <div className="sf-checks">
                {ALL_PROVIDERS.map((p) => (
                  <label key={p} className="sf-check">
                    <input
                      type="checkbox"
                      checked={providers.includes(p)}
                      onChange={() => toggleProvider(p)}
                    />
                    <ProviderBadge provider={p} />
                  </label>
                ))}
              </div>
              <p className="u-muted u-xs" style={{ margin: '4px 0 0' }}>
                Only Proxmox has a real provider path today (simulated execution). Cloud providers
                are SECP-006 future work.
              </p>
            </fieldset>

            <div className="u-row">
              <Button
                type="submit"
                variant="primary"
                disabled={!name.trim()}
                title={
                  name.trim()
                    ? 'Prototype: captures this draft locally in your browser only — nothing is created on any backend'
                    : 'Enter a scenario name first'
                }
              >
                Create draft scenario (prototype)
              </Button>
            </div>

            {confirmed && (
              <div className="sf-confirm" role="status">
                <span className="u-row u-small">
                  <CheckCircle2 size={14} aria-hidden />
                  <strong>Draft captured locally — nothing was created.</strong>
                </span>
                <p className="u-secondary u-small" style={{ margin: 0 }}>
                  “{name.trim()}” ({difficulty}, {teamMin}–{teamMax} teams,{' '}
                  {providers.length > 0 ? providers.join(', ') : 'no providers'}) exists only in
                  this page's state. In the implemented platform flow, this step would create an
                  Environment Template draft and open the Builder.
                </p>
                <span className="u-small">
                  <Link to="/scenarios">Return to the library</Link>
                </span>
              </div>
            )}
          </form>
        </Card>

        <Card heading="What happens after “Create”">
          <p className="u-secondary u-small">
            Creating a scenario opens the Builder. The platform's template flow is real end-to-end
            (with simulated execution):
          </p>
          <ol
            className="u-small u-secondary"
            style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 6 }}
          >
            <li>
              A template draft is created <CapabilityTag status="implemented" />
            </li>
            <li>
              You edit the YAML definition and topology in the Builder{' '}
              <CapabilityTag status="implemented" />
            </li>
            <li>
              The server validates the definition and topology on every save{' '}
              <CapabilityTag status="implemented" />
            </li>
            <li>
              Publishing produces an immutable, content-hashed version that deployments pin{' '}
              <CapabilityTag status="implemented" />
            </li>
          </ol>
          <p className="u-muted u-xs" style={{ marginTop: 'var(--sp-2)', marginBottom: 0 }}>
            This form itself is a proposed simplification <CapabilityTag status="ui-only" /> — the
            repo's flow starts directly in the definition editor.
          </p>
        </Card>
      </div>
    </div>
  )
}
