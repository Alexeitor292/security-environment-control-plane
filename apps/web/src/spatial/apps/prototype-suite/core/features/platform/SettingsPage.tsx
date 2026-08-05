import { AccordionSection, CapabilityNotice } from '../../components'

const DISABLED_TITLE = 'Prototype: platform settings are proposed — nothing here is editable'

export default function SettingsPage() {
  return (
    <div className="u-page">
      <CapabilityNotice capKey="platform.settings" />

      <p className="u-secondary u-small">
        A read-only sketch of proposed platform settings. Every input is disabled; the source
        repository ships Settings as a truthfully disabled navigation stub.
      </p>

      <AccordionSection title="General" hint="organization identity" defaultOpen>
        <label className="p-field">
          <span>Organization name</span>
          <input value="SECP Operations" disabled title={DISABLED_TITLE} />
        </label>
        <label className="p-field">
          <span>Base URL</span>
          <input value="https://secp.example" disabled title={DISABLED_TITLE} />
        </label>
      </AccordionSection>

      <AccordionSection title="Display" hint="density, motion">
        <label className="p-field">
          <span>Interface density</span>
          <select disabled title={DISABLED_TITLE} value="compact">
            <option value="comfortable">Comfortable</option>
            <option value="compact">Compact</option>
          </select>
        </label>
        <p className="u-muted u-xs">
          Reduced motion is honored automatically from the operating-system preference — there is no
          per-user override to configure.
        </p>
      </AccordionSection>

      <AccordionSection title="Safety" hint="seals & kill-switches">
        <p className="u-secondary u-small">
          Platform kill-switches (subprocess seal, live-evidence seal) are documented, deliberate,
          and <strong>not executable from any UI</strong>. Changing a seal requires a code-level
          change and redeploy — by design, no settings toggle can open one.
        </p>
      </AccordionSection>

      <AccordionSection title="API" hint="origin policy">
        <p className="u-secondary u-small">
          The web client talks only to the same-origin control-plane API; no cross-origin API
          surface is exposed and no API keys are configured through this UI.
        </p>
      </AccordionSection>
    </div>
  )
}
