"""Authoritative destination binding for plan-only execution (B1B-PR5B, ADR-022 §5/§6).

Closes the destination-binding defect: the provider endpoint, the remote-state readiness transport,
and the OpenTofu HTTP state runtime inputs were independently supplied deployment-local values, so
readiness could validate backend A while OpenTofu planned against backend B, and the provider
endpoint could differ from the approved Proxmox target.

This module derives BOTH the provider endpoint and the state-backend addresses from the
AUTHORITATIVE
records — the immutable ``ExecutionTarget`` config for the provider, and the immutable
``ToolchainProfile.state_backend.reference`` for the state backend — and proves the composition-
supplied values equal them EXACTLY, canonically, before any lease, secret resolution, workspace
creation, or process. Raw endpoints stay memory-only and redacted: no endpoint/host/path/reference
enters audit, logs, errors, durable state, Temporal arguments, or result provenance — only bounded,
closed reason codes surface. This module performs NO I/O and imports no transport/HTTP/socket code.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

_MAX_URL_BYTES = 2048
_DOT_SEGMENTS = frozenset({".", ".."})


class DestinationBindingError(Exception):
    """A destination binding failed (bounded reason code; never echoes an endpoint/host/path)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _canonical_path(path: str, *, reason: str) -> str:
    """Normalize a URL path (strip trailing slash); refuse traversal / backslash / percent-esc."""
    if "\\" in path or "%" in path:
        raise DestinationBindingError(f"{reason}_path")
    normalized = path.rstrip("/")
    if any(segment in _DOT_SEGMENTS for segment in normalized.split("/")):
        raise DestinationBindingError(f"{reason}_path")
    return normalized


def canonicalize_https(value: object, *, allow_query: bool, reason: str) -> tuple[str, str, str]:
    """Canonicalize an HTTPS URL WITHOUT DNS; return ``(canonical, origin, path)`` or fail closed.

    HTTPS only; lowercase hostname; an omitted port normalized to 443 and always rendered; no
    userinfo/fragment; a query only when ``allow_query``; a normalized safe path. The canonical form
    is what exact equality is compared on, so two spellings of the same destination compare equal
    and
    two different destinations never do.
    """
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value.encode("utf-8")) > _MAX_URL_BYTES
    ):
        raise DestinationBindingError(f"{reason}_invalid")
    try:
        parts = urlsplit(value.strip())
    except ValueError as exc:
        raise DestinationBindingError(f"{reason}_invalid") from exc
    if parts.scheme != "https":
        raise DestinationBindingError(f"{reason}_not_https")
    if parts.username or parts.password or "@" in parts.netloc:
        raise DestinationBindingError(f"{reason}_userinfo")
    if parts.fragment:
        raise DestinationBindingError(f"{reason}_fragment")
    query = parts.query
    if query and not allow_query:
        raise DestinationBindingError(f"{reason}_query")
    host = (parts.hostname or "").lower()
    if not host:
        raise DestinationBindingError(f"{reason}_host")
    try:
        port = parts.port or 443
    except ValueError as exc:
        raise DestinationBindingError(f"{reason}_port") from exc
    if not (1 <= port <= 65535):
        raise DestinationBindingError(f"{reason}_port")
    path = _canonical_path(parts.path, reason=reason)
    origin = f"https://{host}:{port}"
    canonical = origin + path + (f"?{query}" if query else "")
    return canonical, origin, path


def canonical_provider_endpoint(value: object) -> str:
    """The canonical provider HTTPS endpoint (no query/fragment/userinfo; exact reviewed path)."""
    canonical, _origin, _path = canonicalize_https(
        value, allow_query=False, reason="provider_endpoint"
    )
    return canonical


# --- 1. provider endpoint bound to the authoritative approved target ------------------------------


def assert_provider_endpoint_bound(*, target: object, composition_endpoint: object) -> object:
    """Refuse unless the composition provider endpoint EXACTLY equals the authoritative target's.

    Requires ``plugin_name == "proxmox"``; re-validates the immutable ``config`` against its stored
    ``config_hash`` (a stale/tampered config refuses); derives the canonical Proxmox endpoint ONLY
    from ``target.config["base_url"]`` (no DNS); and requires exact canonical equality with the
    composition copy. Returns a :class:`~secp_worker.plan_gen.runtime_inputs.ProviderRuntimeInput`
    derived from the AUTHORITATIVE target (never the composition copy). Fails closed with a bounded
    reason BEFORE any external contact; the endpoint never surfaces.
    """
    from secp_scenario_schema import content_hash

    from secp_worker.plan_gen.runtime_inputs import RuntimeInputError, build_provider_runtime_input

    if getattr(target, "plugin_name", None) != "proxmox":
        raise DestinationBindingError("provider_plugin_not_proxmox")
    config = getattr(target, "config", None)
    if not isinstance(config, dict):
        raise DestinationBindingError("target_config_invalid")
    if content_hash(config) != getattr(target, "config_hash", None):
        raise DestinationBindingError("target_config_hash_stale")
    canonical_target = canonical_provider_endpoint(config.get("base_url"))
    canonical_comp = canonical_provider_endpoint(composition_endpoint)
    if canonical_target != canonical_comp:
        raise DestinationBindingError("provider_endpoint_mismatch")
    try:
        # Derive the runtime input from the AUTHORITATIVE target endpoint (also refuses a forbidden
        # loopback/link-local/metadata destination — defence in depth on the reviewed target).
        return build_provider_runtime_input(canonical_target)
    except RuntimeInputError as exc:
        raise DestinationBindingError(exc.reason_code) from exc


# --- 2. one authoritative HTTP state-backend binding derived from the ToolchainProfile ------------


@dataclass(frozen=True, repr=False)
class AuthoritativeStateBackendBinding:
    """The ONE typed, immutable, redacted in-memory HTTP state-backend binding for a plan-only op.

    Derived from the validated immutable ``ToolchainProfile.state_backend`` (its ``reference`` is
    the
    exact canonical HTTP state address). It governs BOTH remote-state readiness (via the control
    origin) and the OpenTofu ``TF_HTTP_ADDRESS`` / ``LOCK_ADDRESS`` / ``UNLOCK_ADDRESS`` runtime
    inputs, so the two can never point at different backends. Raw addresses stay memory-only; the
    ``__repr__`` is redacted. The durable anchor is the immutable ``toolchain_profile_hash`` + the
    server-derived ``state_namespace_identity`` — never a raw URL/host/path or a digest of one.
    """

    state_address: str
    lock_address: str
    unlock_address: str
    control_origin: str
    backend_kind: str
    toolchain_profile_id: str
    toolchain_profile_hash: str
    state_namespace_identity: str

    def __repr__(self) -> str:
        return "AuthoritativeStateBackendBinding(<redacted>)"

    __str__ = __repr__


# The reviewed, deterministic derivation of the lock/unlock addresses from the state address: the
# OpenTofu ``http`` backend locks the EXACT same object, so lock/unlock share the state object's
# origin+path and differ only by the reviewed ``lock`` / ``unlock`` query marker. This is a fixed
# reviewed contract — never a guess and never caller free text.
_LOCK_QUERY = "lock"
_UNLOCK_QUERY = "unlock"


def derive_state_backend_binding(
    *,
    reference: object,
    backend_kind: str,
    toolchain_profile_id: object,
    toolchain_profile_hash: str,
    state_namespace_identity: str,
) -> AuthoritativeStateBackendBinding:
    """Derive the authoritative binding from the immutable ``ToolchainProfile.state_backend``.

    The ``reference`` is required to be the exact canonical HTTPS state address; the lock/unlock
    addresses are derived from it by the reviewed contract. A non-HTTPS / query-bearing / traversal
    reference fails closed.
    """
    state_address, origin, _path = canonicalize_https(
        reference, allow_query=False, reason="state_reference"
    )
    return AuthoritativeStateBackendBinding(
        state_address=state_address,
        lock_address=f"{state_address}?{_LOCK_QUERY}",
        unlock_address=f"{state_address}?{_UNLOCK_QUERY}",
        control_origin=origin,
        backend_kind=backend_kind,
        toolchain_profile_id=str(toolchain_profile_id),
        toolchain_profile_hash=toolchain_profile_hash,
        state_namespace_identity=state_namespace_identity,
    )


def assert_state_runtime_bound(
    *, binding: AuthoritativeStateBackendBinding, composition_state_source: object
) -> object:
    """Refuse unless the composition state runtime inputs EXACTLY equal the authoritative binding.

    The address/lock/unlock the OpenTofu child would receive must canonically equal the addresses
    derived from the ToolchainProfile reference — so a second, unrelated state backend supplied via
    the composition is refused. Returns a
    :class:`~secp_worker.plan_gen.runtime_inputs.StateRuntimeInput` built from the AUTHORITATIVE
    binding (never the composition copy), carrying only the composition's nonsecret username.
    """
    from secp_worker.plan_gen.runtime_inputs import RuntimeInputError, build_state_runtime_input

    address = getattr(composition_state_source, "address", None)
    lock_address = getattr(composition_state_source, "lock_address", None)
    unlock_address = getattr(composition_state_source, "unlock_address", None)
    username = getattr(composition_state_source, "username", None)
    if canonicalize_https(address, allow_query=False, reason="state_address")[0] != (
        binding.state_address
    ):
        raise DestinationBindingError("state_address_mismatch")
    if canonicalize_https(lock_address, allow_query=True, reason="state_lock")[0] != (
        binding.lock_address
    ):
        raise DestinationBindingError("state_lock_mismatch")
    if canonicalize_https(unlock_address, allow_query=True, reason="state_unlock")[0] != (
        binding.unlock_address
    ):
        raise DestinationBindingError("state_unlock_mismatch")
    try:
        return build_state_runtime_input(
            binding.state_address, binding.lock_address, binding.unlock_address, username
        )
    except RuntimeInputError as exc:
        raise DestinationBindingError(exc.reason_code) from exc


def assert_readiness_backend_equals(
    *, binding: AuthoritativeStateBackendBinding, readiness_toolchain_profile_hash: str
) -> None:
    """Prove the readiness evidence's backend anchor equals the authoritative binding's.

    Both are the immutable ToolchainProfile content hash. Equality means remote-state readiness was
    collected for the EXACT backend the plan runtime will use — never a different one. No raw URL is
    involved; the anchor is the high-entropy profile hash (§4).
    """
    if not binding.toolchain_profile_hash:
        raise DestinationBindingError("state_backend_anchor_missing")
    if binding.toolchain_profile_hash != readiness_toolchain_profile_hash:
        raise DestinationBindingError("readiness_backend_mismatch")
