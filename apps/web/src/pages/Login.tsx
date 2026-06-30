import { useNavigate } from "react-router-dom";

/**
 * Bootstrap/login placeholder appropriate for local development.
 *
 * SECP-001 uses a dev fallback principal on the API; full OIDC login against the
 * Keycloak dev realm is a documented placeholder (design §11). This screen exists
 * to represent the seam and let a developer "enter" the app.
 */
export function Login() {
  const navigate = useNavigate();
  return (
    <div className="layout">
      <main className="content" style={{ maxWidth: 480, margin: "10vh auto" }}>
        <div className="panel">
          <h2>Sign in</h2>
          <p className="muted">
            Development bootstrap. In local mode the API authenticates you as the
            seeded <code>dev-admin</code> principal.
          </p>
          <div className="error-box" style={{ background: "transparent" }}>
            Development only. Real OIDC login (Keycloak) is a SECP-001 placeholder.
          </div>
          <button onClick={() => navigate("/")}>Continue as dev-admin</button>
        </div>
      </main>
    </div>
  );
}
