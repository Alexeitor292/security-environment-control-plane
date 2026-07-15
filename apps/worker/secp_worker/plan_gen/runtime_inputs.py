"""Typed plan-only runtime inputs + the explicit child environment (B1B-PR5B, ADR-022 §10) — worker.

The provider endpoint and the remote-state backend address/lock/unlock endpoints are NONSECRET but
SENSITIVE operational values. They are derived only from authoritative target/composition data,
validated fail-closed (HTTPS-only, no userinfo, no fragment, no unreviewed query, no
localhost/link-local/metadata destination, exact same-origin across address/lock/unlock, TLS
verification on), and redacted from logs/results/audit/errors.

Remote-state LOCKING is enabled explicitly: the OpenTofu ``http`` backend only locks when a lock
address is present, so ``TF_HTTP_LOCK_ADDRESS`` / ``TF_HTTP_UNLOCK_ADDRESS`` (+ the ``LOCK`` /
``UNLOCK`` methods) are always projected — locking can never be silently disabled.

The child process environment is constructed EXPLICITLY: this module never reads or inherits
``os.environ``. No ``PATH``, ambient ``HOME``, proxy, ``SSH_AUTH_SOCK``, cloud credential, cloud SDK
config, shell, loader (``LD_PRELOAD`` / ``LD_LIBRARY_PATH`` / ``PYTHONPATH`` / ``DYLD_*``), or
ambient
OpenTofu configuration is inherited. The produced key set is EXACTLY
:data:`PLAN_ONLY_CHILD_ENV_KEYS` — the executor re-validates that exact closed set independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from secp_api.plan_activation_contract import PLAN_PROVIDER_ENV_ALLOWLIST, PLAN_STATE_ENV_ALLOWLIST

from secp_worker.plan_gen.secret_env import combined_plan_env
from secp_worker.preflight.secret_resolution import SecretMaterial

# --- the exact closed child-environment key set --------------------------------------------------
_PROVIDER_ENDPOINT_VAR = "TF_VAR_pm_endpoint"
_STATE_ADDRESS_VAR = "TF_HTTP_ADDRESS"
_STATE_USERNAME_VAR = "TF_HTTP_USERNAME"
_STATE_LOCK_ADDRESS_VAR = "TF_HTTP_LOCK_ADDRESS"
_STATE_UNLOCK_ADDRESS_VAR = "TF_HTTP_UNLOCK_ADDRESS"
_STATE_LOCK_METHOD_VAR = "TF_HTTP_LOCK_METHOD"
_STATE_UNLOCK_METHOD_VAR = "TF_HTTP_UNLOCK_METHOD"
_STATE_RETRY_MAX_VAR = "TF_HTTP_RETRY_MAX"

LOCK_METHOD = "LOCK"
UNLOCK_METHOD = "UNLOCK"
_RETRY_MAX = "2"

_NONSECRET_RUNTIME_VARS = frozenset(
    {
        _PROVIDER_ENDPOINT_VAR,
        _STATE_ADDRESS_VAR,
        _STATE_USERNAME_VAR,
        _STATE_LOCK_ADDRESS_VAR,
        _STATE_UNLOCK_ADDRESS_VAR,
        _STATE_LOCK_METHOD_VAR,
        _STATE_UNLOCK_METHOD_VAR,
        _STATE_RETRY_MAX_VAR,
    }
)
_OPERATIONAL_VARS = frozenset({"HOME", "TMPDIR", "TF_DATA_DIR", "TF_CLI_CONFIG_FILE"})

# The EXACT closed set the plan child env must contain — no more, no less. The executor re-validates
# ``set(env) == PLAN_ONLY_CHILD_ENV_KEYS`` independently, so no loader/PATH/OpenTofu-config key can
# ever appear even if a caller tried to inject one.
PLAN_ONLY_CHILD_ENV_KEYS: frozenset[str] = (
    frozenset(PLAN_PROVIDER_ENV_ALLOWLIST)
    | frozenset(PLAN_STATE_ENV_ALLOWLIST)
    | _NONSECRET_RUNTIME_VARS
    | _OPERATIONAL_VARS
)

# Never a plausible plan-read destination: loopback, link-local (incl. the cloud metadata IP), and
# the unspecified address. A reviewed disposable lab legitimately lives on a private LAN, so
# RFC-1918
# ranges are NOT forbidden here — the SSRF targets that matter are loopback/link-local/metadata.
_FORBIDDEN_HOST_PREFIXES = ("127.", "169.254.", "0.")
_FORBIDDEN_HOSTS = frozenset({"localhost", "::1", "0.0.0.0", "169.254.169.254", "metadata"})
_MAX_URL_BYTES = 2048


class RuntimeInputError(Exception):
    """A runtime input failed validation (bounded reason code; never echoes the value)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, repr=False)
class ProviderRuntimeInput:
    """The validated, redacted provider HTTPS endpoint (nonsecret but sensitive)."""

    endpoint: str

    def __repr__(self) -> str:  # never leak the endpoint into logs/errors
        return "ProviderRuntimeInput(<redacted>)"

    __str__ = __repr__


@dataclass(frozen=True, repr=False)
class StateRuntimeInput:
    """The validated, redacted remote-state HTTPS backend address + lock/unlock + nonsecret user."""

    address: str
    lock_address: str
    unlock_address: str
    username: str

    def __repr__(self) -> str:
        return "StateRuntimeInput(<redacted>)"

    __str__ = __repr__


def _split_https(value: object, *, reason_prefix: str):  # noqa: ANN202
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > _MAX_URL_BYTES:
        raise RuntimeInputError(f"{reason_prefix}_invalid")
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise RuntimeInputError(f"{reason_prefix}_invalid") from exc
    if parts.scheme != "https":
        raise RuntimeInputError(f"{reason_prefix}_not_https")
    if parts.username or parts.password or "@" in parts.netloc:
        raise RuntimeInputError(f"{reason_prefix}_has_userinfo")
    if parts.fragment:
        raise RuntimeInputError(f"{reason_prefix}_has_fragment")
    host = (parts.hostname or "").lower()
    if not host:
        raise RuntimeInputError(f"{reason_prefix}_invalid")
    if host in _FORBIDDEN_HOSTS or any(host.startswith(p) for p in _FORBIDDEN_HOST_PREFIXES):
        raise RuntimeInputError(f"{reason_prefix}_forbidden_destination")
    return parts


def _validate_https_url(value: object, *, reason_prefix: str, allow_query: bool = False) -> str:
    parts = _split_https(value, reason_prefix=reason_prefix)
    if parts.query and not allow_query:
        raise RuntimeInputError(f"{reason_prefix}_has_query")
    return value  # type: ignore[return-value]


def _origin(parts) -> tuple[str, str, int]:  # noqa: ANN001
    return (parts.scheme, (parts.hostname or "").lower(), parts.port or 443)


def build_provider_runtime_input(endpoint: object) -> ProviderRuntimeInput:
    """Validate and wrap the provider HTTPS endpoint (fail closed)."""
    return ProviderRuntimeInput(endpoint=_validate_https_url(endpoint, reason_prefix="endpoint"))


def build_state_runtime_input(
    address: object, lock_address: object, unlock_address: object, username: object
) -> StateRuntimeInput:
    """Validate the remote-state HTTPS address + lock + unlock (same origin) + nonsecret username.

    The three endpoints must share the EXACT same origin (scheme/host/port); the lock/unlock
    endpoints may carry a query (the lock id), the base address may not. Locking cannot be disabled:
    both lock and unlock addresses are required.
    """
    if not isinstance(username, str) or not username or "\n" in username or "\x00" in username:
        raise RuntimeInputError("state_username_invalid")
    addr_parts = _split_https(address, reason_prefix="state_address")
    if addr_parts.query:
        raise RuntimeInputError("state_address_has_query")
    lock_parts = _split_https(lock_address, reason_prefix="state_lock_address")
    unlock_parts = _split_https(unlock_address, reason_prefix="state_unlock_address")
    if _origin(lock_parts) != _origin(addr_parts) or _origin(unlock_parts) != _origin(addr_parts):
        raise RuntimeInputError("state_lock_origin_mismatch")
    return StateRuntimeInput(
        address=str(address),
        lock_address=str(lock_address),
        unlock_address=str(unlock_address),
        username=username,
    )


@dataclass(frozen=True)
class OperationalPaths:
    """Worker-derived, nonsecret operation-local paths for the child (never inherited)."""

    home: str
    tmpdir: str
    tf_data_dir: str
    cli_config_file: str


def build_child_environment(
    *,
    provider_material: SecretMaterial,
    state_material: SecretMaterial,
    provider_input: ProviderRuntimeInput,
    state_input: StateRuntimeInput,
    operational: OperationalPaths,
) -> dict[str, str]:
    """Construct the EXACT explicit plan child environment — no ``os.environ`` inheritance.

    The produced key set is EXACTLY :data:`PLAN_ONLY_CHILD_ENV_KEYS`: the two allowlisted SECRET
    variables (each projected from its own :class:`SecretMaterial`); the nonsecret provider
    endpoint;
    the state address + lock/unlock addresses + LOCK/UNLOCK methods + a bounded retry cap +
    username;
    and the worker-derived operational directories/config. Nothing else may appear.
    """
    env: dict[str, str] = {}
    env.update(combined_plan_env(provider_material, state_material))
    env[_PROVIDER_ENDPOINT_VAR] = provider_input.endpoint
    env[_STATE_ADDRESS_VAR] = state_input.address
    env[_STATE_LOCK_ADDRESS_VAR] = state_input.lock_address
    env[_STATE_UNLOCK_ADDRESS_VAR] = state_input.unlock_address
    env[_STATE_LOCK_METHOD_VAR] = LOCK_METHOD
    env[_STATE_UNLOCK_METHOD_VAR] = UNLOCK_METHOD
    env[_STATE_RETRY_MAX_VAR] = _RETRY_MAX
    env[_STATE_USERNAME_VAR] = state_input.username
    for var, value in (
        ("HOME", operational.home),
        ("TMPDIR", operational.tmpdir),
        ("TF_DATA_DIR", operational.tf_data_dir),
        ("TF_CLI_CONFIG_FILE", operational.cli_config_file),
    ):
        if not isinstance(value, str) or not value or "\x00" in value or "\n" in value:
            raise RuntimeInputError("operational_path_invalid")
        env[var] = value
    # The produced set must be EXACTLY the closed allowlist — never a subset, never an extra key.
    if set(env) != PLAN_ONLY_CHILD_ENV_KEYS:  # pragma: no cover - unreachable by construction
        raise RuntimeInputError("child_env_key_set_mismatch")
    return env
