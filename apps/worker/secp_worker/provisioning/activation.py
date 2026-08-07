"""Isolated-lab activation helpers (SECP-002B-1A, ADR-013) — worker-only.

Real provisioning is disabled by default. The full activation gate is enforced in
``execution.run_real_provisioning``; this module provides:

- ``RealLabActivationGrant`` — an internal, worker-only capability token that can be
  produced **only after** the complete real-lab gate succeeds. Configuration alone
  (``SECP_ENABLE_OPENTOFU_SUBPROCESS=true``) can never construct a real subprocess
  executor.
- ``build_process_executor`` — returns a ``FakeProcessExecutor``, always. It no longer consults a
  settings flag or a grant; see the function for why that is severance rather than a check.
- ``issue_authorized_executor`` — the ONLY way to obtain a real executor, and it takes the durable
  operation authority rather than any form of permission a caller can assert.
- just-in-time secret env building for a would-be lab apply.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from secp_api.config import Settings

from secp_worker.provisioning.process_executor import (
    FakeProcessExecutor,
    ProcessExecutionError,
    ProcessExecutor,
    SubprocessProcessExecutor,
)


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


def build_process_executor(
    settings: Settings, *, grant: RealLabActivationGrant | None = None
) -> ProcessExecutor:
    """The settings-driven factory. Returns the fake, and structurally cannot return anything else.

    This used to read ``settings.enable_opentofu_subprocess`` together with a grant, held shut by
    `_B1A_SUBPROCESS_SEALED`. ADR-030 retired that seal, and retiring it is exactly what made the
    rest unacceptable rather than merely dormant: a configuration field or a caller-attested
    ``gate_passed`` boolean that widens what may execute is the ambient bypass §2 forbids, and both
    would have gone live the moment the seal went.

    So the branch is deleted rather than re-gated, and the two parameters are now **severed** from
    real execution: they are accepted for call-site compatibility and cannot influence the result.
    A real executor requires the durable operation authority, which this function is never handed
    and must never synthesize — see :func:`issue_authorized_executor`.
    """
    del settings, grant
    return FakeProcessExecutor()


def issue_authorized_executor(authority: object) -> SubprocessProcessExecutor:
    """The ONLY way to obtain a real process executor.

    Takes the ``AuthorizedExecution`` that ``authorize_provisioning_execution`` returns after every
    ADR-030 condition has held against durable rows. There is deliberately no ``settings``
    parameter, no grant, and no flag: the argument list is the whole authorization surface, and
    nothing in it is a value a caller can assert about itself.

    The refusal for a missing or forged authority comes from the executor's own constructor rather
    than from a check here, so a caller that bypasses this function and constructs the executor
    directly is refused identically. This function exists to give the worker one obvious door, not
    to be the lock.
    """
    if authority is None:
        raise ProcessExecutionError(
            "a real process executor requires the durable operation authority; none was supplied"
        )
    return SubprocessProcessExecutor(authority=authority)


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
