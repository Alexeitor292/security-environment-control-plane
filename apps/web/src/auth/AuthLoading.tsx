// Minimal, safe auth status screen (ADR-018 / OIDC-B). Shown while authentication is resolving or a
// redirect is in flight; renders no token, claim, code, state, or provider detail.

export function AuthLoading({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="layout">
      <main className="content" style={{ maxWidth: 480, margin: "10vh auto" }}>
        <div className="panel" role="status" aria-live="polite">
          <p className="muted">{label}</p>
        </div>
      </main>
    </div>
  );
}
