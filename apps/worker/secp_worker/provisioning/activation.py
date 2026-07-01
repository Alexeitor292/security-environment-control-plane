"""Isolated-lab activation helpers (SECP-002B-1A, ADR-013) — worker-only.

Real provisioning is disabled by default. The gate itself is enforced in
``execution.run_real_provisioning`` (so refusals reuse the audited ``_refuse`` path);
this module provides the process-executor factory and just-in-time secret env building.

The ``SubprocessProcessExecutor`` is only ever constructed here, and only when the
explicit runtime arm (``SECP_ENABLE_OPENTOFU_SUBPROCESS``) is set — which is **never** in
B1-A. Every B1-A caller injects a ``FakeProcessExecutor`` instead.
"""

from __future__ import annotations

from secp_api.config import Settings

from secp_worker.provisioning.process_executor import (
    FakeProcessExecutor,
    ProcessExecutor,
    SubprocessProcessExecutor,
)


def build_process_executor(settings: Settings) -> ProcessExecutor:
    """Return the process executor allowed by configuration.

    In B1-A this always returns a ``FakeProcessExecutor``: the subprocess arm is off by
    default and is refused in production. The real ``SubprocessProcessExecutor`` is
    constructed only when explicitly armed for a reviewed disposable lab (B1-B).
    """
    if settings.enable_opentofu_subprocess and not settings.is_production:
        # Reachable only in a future B1-B session that explicitly arms the subprocess
        # executor. Not exercised anywhere in B1-A.
        return SubprocessProcessExecutor(armed=True)  # pragma: no cover - B1-B only
    return FakeProcessExecutor()


def build_lab_secret_env(config: dict, token_value: str) -> dict[str, str]:
    """Build TF_VAR_* env for a lab apply from JIT-resolved material (worker-only).

    ``token_value`` is resolved just-in-time in the worker (never in the API, never
    persisted). Only the endpoint (non-secret config) and the token are exposed, and
    both flow through the environment allowlist + redaction in the process executor.
    """
    endpoint = str(config.get("base_url", ""))
    env: dict[str, str] = {}
    if endpoint:
        env["TF_VAR_pm_endpoint"] = endpoint
    if token_value:
        env["TF_VAR_pm_api_token"] = token_value
    return env
