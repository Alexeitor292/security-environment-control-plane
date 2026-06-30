# ADR-007 — Provider secret references and worker-only resolution

- **Status:** Accepted
- **Date:** 2026-06-30
- **Milestone:** SECP-002A
- **Related:** Charter §13 (security), Invariants 6, 7; ADR-006, ADR-010

## Context

Real providers need credentials. The charter forbids plaintext secrets in source
control and requires secure references instead (§11, §13) and forbids the API from
performing privileged actions (Invariants 6, 7). We must never store, log, or expose
a secret, and the API must never even resolve one.

## Decision

- An `ExecutionTarget` stores only an **opaque `secret_ref`** — a `<scheme>:<locator>`
  pointer that says *where* a secret lives, never the secret itself. No tokens,
  passwords, keys, or certs are ever persisted.
- **Worker-only resolution.** A `SecretResolver` abstraction resolves a `secret_ref`
  **only in the worker**, **immediately before** a provider operation. The API may
  validate `secret_ref` *syntax* but must never resolve it.
- Local dev ships `EnvSecretResolver` (`env:NAME` → read env var `NAME` at run time),
  documented as a placeholder for a real secret manager. Tests use a `FakeResolver`
  and never read real environment secrets.
- **Redaction is mandatory.** Resolution errors never echo the secret or value.
  Resolved secrets are never persisted and never reach logs, audit events, API
  responses, workflow `detail`, or frontend state.
- The interface is shaped to accept additional schemes (e.g. `vault:`, `aws-sm:`)
  without changing callers, so a production secret manager is a drop-in.

## Consequences

**Positive:** secrets cannot leak through the database, audit, API, or UI; the API
boundary stays clean; future secret managers integrate without refactoring callers.

**Negative / risks:** the dev `env:` resolver could be misused to read arbitrary env
vars. Mitigated by namespacing (`SECP_PROVIDER_SECRET__*`), worker-only use, never
running real resolution in tests/CI, and architecture tests proving the API cannot
resolve.

**Placeholder:** production secret manager integration is future work; only the
`env:` dev scheme ships in SECP-002A.
