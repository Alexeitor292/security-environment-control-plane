"""Isolated-lab activation helpers (SECP-002B-1A, ADR-013) — worker-only.

Real provisioning is disabled by default. The full activation gate is enforced in
``execution.run_real_provisioning``; this module provides:

- ``RealLabActivationGrant`` — an internal, worker-only capability token that can be
  produced **only after** the complete real-lab gate succeeds. Configuration alone
  (``SECP_ENABLE_OPENTOFU_SUBPROCESS=true``) can never construct a real subprocess
  executor.
- ``build_process_executor`` — returns a ``FakeProcessExecutor`` unless a valid grant is
  present AND the real subprocess is unsealed. **In B1-A a hard seal keeps it Fake in all
  cases**, so no real process can ever run.
- just-in-time secret env building for a would-be lab apply.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from secp_api.config import Settings

from secp_worker.provisioning.process_executor import (
    FakeProcessExecutor,
    ProcessExecutor,
    SubprocessProcessExecutor,
)

# HARD B1-A SEAL: the real subprocess executor is never constructed in this slice, even
# with a valid grant + config. Unsealing is a reviewed disposable-lab (B1-B) change.
_B1A_SUBPROCESS_SEALED = True


@dataclass(frozen=True)
class RealLabActivationGrant:
    """A worker-only capability produced only after the full real-lab gate succeeds.

    Opaque and non-forgeable in practice (random nonce); carries no secret. It is never
    serialized, persisted, logged, or returned by the API.
    """

    manifest_id: str
    _nonce: str = field(repr=False)

    def is_valid(self) -> bool:
        return bool(self._nonce)


def grant_real_lab_activation(*, manifest_id: object, gate_passed: bool) -> RealLabActivationGrant:
    """Mint a grant. Refuses unless the caller attests the full gate has passed."""
    if not gate_passed:
        raise RuntimeError(
            "cannot grant real-lab activation before the complete isolated-lab gate succeeds"
        )
    return RealLabActivationGrant(manifest_id=str(manifest_id), _nonce=secrets.token_hex(8))


def _real_subprocess_allowed(settings: Settings, grant: RealLabActivationGrant | None) -> bool:
    if _B1A_SUBPROCESS_SEALED:
        return False  # B1-A: never construct a real subprocess executor
    return (  # pragma: no cover - B1-B only
        isinstance(grant, RealLabActivationGrant)
        and grant.is_valid()
        and settings.enable_opentofu_subprocess
        and not settings.is_production
    )


def build_process_executor(
    settings: Settings, *, grant: RealLabActivationGrant | None = None
) -> ProcessExecutor:
    """Return the process executor allowed by policy.

    A configuration flag alone can NOT construct a real subprocess executor: a valid
    ``RealLabActivationGrant`` (produced only after the full gate) is required, and in
    B1-A a hard seal keeps this a ``FakeProcessExecutor`` regardless.
    """
    if _real_subprocess_allowed(settings, grant):
        return SubprocessProcessExecutor(armed=True)  # pragma: no cover - B1-B only
    return FakeProcessExecutor()


def build_lab_secret_env(config: dict, token_value: str) -> dict[str, str]:
    """Build TF_VAR_* env for a lab apply from JIT-resolved material (worker-only).

    ``token_value`` is resolved just-in-time in the worker (never in the API, never
    persisted). Only the endpoint (non-secret config) and the token are exposed, and both
    flow through the environment allowlist + redaction in the process executor.
    """
    endpoint = str(config.get("base_url", ""))
    env: dict[str, str] = {}
    if endpoint:
        env["TF_VAR_pm_endpoint"] = endpoint
    if token_value:
        env["TF_VAR_pm_api_token"] = token_value
    return env
