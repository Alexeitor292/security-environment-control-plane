# SECP-PR5H-B2 threat model — supported installation, operator auth, UI, acceptance

Companion to [ADR-028](../adr/ADR-028-supported-installation-auth-ui-acceptance.md). Scope: the *new* attack surface introduced by making PR5H-B1's sealed enrollment mechanisms operable — the root-gated installer, interactive operator authentication + credential storage, the minimal enrollment UI, and the two-host acceptance path. Pre-existing PR5H-B1 controls (evidence-driven exchange, root-gated signer boundary, exact-bind replay, observed health, least-privilege DB lease, fixed signer locations) are assumed and preserved.

## Assets

1. Controller enrollment **private signing key** (0600 root file; signs offers).
2. Signer **DB role credentials** (least-privilege `secp_enrollment_signer`).
3. Operator **OIDC access/refresh tokens** (grant `enrollment:manage`).
4. Worker **enrollment private key** (proves worker possession).
5. The persisted **ACTIVE controller identity** (trust anchor for offers).
6. Host **integrity** (units, non-root API boundary, fixed socket/key locations).
7. Enrollment **state integrity** (durable, tamper-evident, revocable).

## Trust boundaries

- **Root installer ↔ non-root runtime.** Only `secpctl` install/upgrade/uninstall runs as root; the API and worker run non-root; the browser/API never triggers root work.
- **Operator ↔ controller API.** Operator commands authenticate over pinned HTTPS with a short-lived bearer; the worker path authenticates cryptographically (never the operator token).
- **Controller host ↔ worker host.** Worker→controller is outbound HTTPS pinned to the invitation's CA/origin; no inbound path to the worker; no controller→worker push.
- **CLI process ↔ OS credential store.** Tokens live in the OS keyring, not in argv/env/files-in-repo.

## Threats & mitigations

| # | Threat | Mitigation (this PR) |
|---|---|---|
| T1 | Installer coerced to write to an attacker path / follow a symlink | All writes go through `RealFilesystem` (dir-fd/`O_NOFOLLOW`, trusted-ancestor, `O_EXCL`, `renameat2 RENAME_NOREPLACE`); fixed code-owned paths only; `layout.assert_unit_writable` allowlist; no arbitrary path/SQL/shell/socket args. |
| T2 | Partial install leaves an active identity without a usable signer, or a broker unit without its key | Identity written first / evidence last; reobserve-then-commit; per-op compensation ledger; a failed compensation raises a *distinct* code (never silent partial). |
| T3 | Private key leaks to PostgreSQL / HTTP / logs / audit / evidence / API image | Key is 0600 root, read only by the root broker over AF_UNIX; identity table stores public material only; redacted reprs + `scan_forbidden`; signer-boundary guards assert the API image never contains/mounts the key. |
| T4 | Operator token captured from argv/env/logs/shell history/output | Device grant (no password); token only in the OS keyring via the non-serializable `OperatorAccessToken`; never printed in human/JSON output or telemetry; bearer attached only to the pinned origin, never on a redirect. |
| T5 | Credential store unavailable → silent plaintext fallback | No silent fallback; a missing backend returns a bounded setup error; the token *file* remains only a sealed/test/recovery seam. |
| T6 | Rogue/`authorization_pending`/`slow_down` device-flow abuse or issuer spoofing | Reviewed issuer only (no prod override); bounded poll interval/timeout/cancellation; verify issuer/audience/signature/expiry/claims + org/role mapping; expired/revoked fail closed. |
| T7 | UI exposes secrets or lets a low-privilege operator mutate | Only public enrollment material rendered (no keys/tokens/raw attestations/state digests/txn internals/DB ids); `enrollment:read` view / `enrollment:manage` mutate gates in the UI **and** authoritatively re-checked in `services/worker_enrollment.py`. |
| T8 | Worker installer redirected to a hostile controller / arbitrary URL/CA/token | Worker takes controller identity/trust ONLY from the invitation; installer accepts no controller URL/CA/signer/token/provider/queue/shell args; outbound HTTPS only. |
| T9 | Uninstall leaves residual secrets/services/roles/state, or deletes pre-existing host state | Compensation removes only artifacts this transaction created (receipt/ledger); acceptance proves zero residual; never touches pre-existing state. |
| T10 | Acceptance "passes" by skipping a required step | Fail-closed JUnit no-skip gate; explicit assertions per numbered step; zero-mutation proofs (no provider/OpenTofu/operator/controlled-live/queue/SSH). |
| T11 | Restart mid-exchange corrupts or loses enrollment | Durable CAS + exact-bind replay (C2) + controller-authoritative resume (C3); fixed-path restart marker is a hint only. |
| T12 | Device-capable dev IdP client widens prod exposure | The device grant is enabled only on a dedicated public **CLI** client in the dev realm; production issuer/client are reviewed config, not CLI/env selectable. |

## Residual / out of scope

Provider/cloud/Kubernetes mutation, OpenTofu, operator activation, controlled-live submission, PR6, and remote root SSH remain unreachable by construction (guarded); this PR adds no path to them. Secrets-at-rest hardening of the OS keyring backend itself is delegated to the platform. Network-level MITM is mitigated by CA-pinned TLS (PR5H-B1) and is not re-litigated here.
