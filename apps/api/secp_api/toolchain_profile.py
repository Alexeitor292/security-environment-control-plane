"""Immutable, provider-neutral toolchain profile validation (ADR-013, SECP-002B-1A).

A ``ToolchainProfile`` binds an ``ExecutionTarget`` to a worker-side IaC runtime. It is
**secret-free** and **provider-neutral at the core level**: this module validates the
*shape and safety* of a profile (pinned versions, present integrity hashes, remote state,
offline provider mirror, known adapter, eligible activation class) without importing any
runner, provider client, OpenTofu, or process-execution code. Provider-specific rendering lives only
in the worker adapter.

The profile REJECTS: floating/``latest``/wildcard/empty/unpinned versions; missing
integrity or bundle/lockfile hashes; local-only OpenTofu state; direct-internet provider
download; unknown adapter types; and permissive / unconfigured production-style profiles
(only ``isolated_lab`` is eligible in B1).
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from secp_api.errors import ValidationFailedError

# Exactly-pinned semantic version: MAJOR.MINOR.PATCH with an optional pre-release.
# Anything floating (latest, ranges, wildcards) is refused.
_EXACT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?$")
_FLOATING_TOKENS = {"latest", "*", "", "x", "x.x.x", "any", "stable", "edge", "main", "head"}
_RANGE_CHARS = set("><=~^ ")
# A well-formed content digest: <alg>:<hex>. Fixtures use fake but well-formed values.
_DIGEST_RE = re.compile(r"^[a-z0-9]+:[0-9a-fA-F]{32,128}$")

_KNOWN_RUNNER_KINDS = {"opentofu"}
# Adapter identifiers understood by the worker rendering seam. Provider-specific
# rendering lives in the worker; this is only an allowlist of known adapter *types*.
_KNOWN_ADAPTER_KINDS = {"proxmox"}
# Only an isolated disposable lab is eligible for B1. Production-style activation is
# refused (a permissive/unconfigured production profile must not validate).
_ELIGIBLE_ACTIVATION_CLASSES = {"isolated_lab"}
# State-backend kinds that are NOT local. "local"/"local-state"/"" are refused so that
# OpenTofu state can never live only on the worker's disk.
_LOCAL_STATE_TOKENS = {"local", "local-state", "localfs", "file", "disk", ""}
# Provider-mirror network postures. Only a fully offline, pinned mirror is accepted.
_OFFLINE_NETWORK_TOKENS = {"offline", "none", "air-gapped", "airgapped", "mirror-only"}
_ONLINE_NETWORK_TOKENS = {"online", "internet", "direct", "registry", "public"}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _require_digest(value: str, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise ValueError(
            f"{field} must be a well-formed content digest '<alg>:<hex>' "
            f"(e.g. 'sha256:<64 hex>'); missing/invalid integrity is refused"
        )
    return value


class StateBackend(_Strict):
    """Remote state backend reference. Local-only state is refused."""

    kind: str
    reference: str = Field(min_length=1)

    @field_validator("kind")
    @classmethod
    def _not_local(cls, v: str) -> str:
        if not isinstance(v, str) or v.strip().lower() in _LOCAL_STATE_TOKENS:
            raise ValueError(
                "state_backend.kind must be a REMOTE backend; local-only OpenTofu "
                "state is refused (no state may live only on the worker disk)"
            )
        return v


class ProviderMirror(_Strict):
    """Offline, pinned provider/plugin mirror. Runtime internet download is refused."""

    identity: str = Field(min_length=1)
    network_access: str = "offline"
    allow_runtime_download: bool = False

    @field_validator("network_access")
    @classmethod
    def _must_be_offline(cls, v: str) -> str:
        token = (v or "").strip().lower()
        if token in _ONLINE_NETWORK_TOKENS or token not in _OFFLINE_NETWORK_TOKENS:
            raise ValueError(
                "provider_mirror.network_access must be offline "
                f"(one of {sorted(_OFFLINE_NETWORK_TOKENS)}); "
                "direct-internet provider download is refused"
            )
        return token

    @field_validator("allow_runtime_download")
    @classmethod
    def _no_runtime_download(cls, v: bool) -> bool:
        if v:
            raise ValueError(
                "provider_mirror.allow_runtime_download must be false; providers and "
                "modules must come from an offline, pinned, verified worker-side mirror"
            )
        return v


class ToolchainProfileSpec(_Strict):
    """Immutable, secret-free toolchain provenance (ADR-013)."""

    runner_kind: str
    executable: str = Field(min_length=1)
    opentofu_version: str
    binary_integrity: str
    adapter_kind: str
    module_bundle_id: str = Field(min_length=1)
    module_bundle_hash: str
    provider_lockfile_hash: str
    renderer_version: str = Field(min_length=1)
    state_backend: StateBackend
    provider_mirror: ProviderMirror
    activation_class: str

    @field_validator("runner_kind")
    @classmethod
    def _known_runner(cls, v: str) -> str:
        if v not in _KNOWN_RUNNER_KINDS:
            raise ValueError(
                f"runner_kind '{v}' is not supported; expected one of {sorted(_KNOWN_RUNNER_KINDS)}"
            )
        return v

    @field_validator("adapter_kind")
    @classmethod
    def _known_adapter(cls, v: str) -> str:
        if v not in _KNOWN_ADAPTER_KINDS:
            raise ValueError(
                f"adapter_kind '{v}' is unknown; expected one of {sorted(_KNOWN_ADAPTER_KINDS)}"
            )
        return v

    @field_validator("opentofu_version")
    @classmethod
    def _exact_version(cls, v: str) -> str:
        token = (v or "").strip().lower()
        if token in _FLOATING_TOKENS:
            raise ValueError(
                f"opentofu_version '{v}' is floating/unpinned; an EXACT version "
                "(MAJOR.MINOR.PATCH) is required"
            )
        if any(ch in _RANGE_CHARS for ch in v):
            raise ValueError(
                f"opentofu_version '{v}' looks like a range/constraint; an EXACT "
                "pinned version is required (no >=, ~>, ^, spaces, etc.)"
            )
        if not _EXACT_VERSION_RE.match(v):
            raise ValueError(f"opentofu_version '{v}' must be an exact MAJOR.MINOR.PATCH version")
        return v

    @field_validator("binary_integrity")
    @classmethod
    def _binary_digest(cls, v: str) -> str:
        return _require_digest(v, "binary_integrity")

    @field_validator("module_bundle_hash")
    @classmethod
    def _bundle_digest(cls, v: str) -> str:
        return _require_digest(v, "module_bundle_hash")

    @field_validator("provider_lockfile_hash")
    @classmethod
    def _lockfile_digest(cls, v: str) -> str:
        return _require_digest(v, "provider_lockfile_hash")

    @field_validator("activation_class")
    @classmethod
    def _eligible_activation(cls, v: str) -> str:
        if v not in _ELIGIBLE_ACTIVATION_CLASSES:
            raise ValueError(
                f"activation_class '{v}' is not eligible in B1; only "
                f"{sorted(_ELIGIBLE_ACTIVATION_CLASSES)} may be used (permissive / "
                "unconfigured production-style profiles are refused)"
            )
        return v


def validate_toolchain_profile(profile: dict | None) -> ToolchainProfileSpec:
    """Strictly validate a toolchain profile spec. Raise on any problem."""
    if not isinstance(profile, dict):
        raise ValidationFailedError("toolchain profile is missing or not an object")
    try:
        return ToolchainProfileSpec.model_validate(profile)
    except ValidationError as exc:
        raise ValidationFailedError(
            "invalid toolchain profile",
            errors=[f"{'/'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()],
        ) from exc


def toolchain_profile_hash(profile: dict) -> str:
    """Deterministic SHA-256 of a validated, canonicalized toolchain profile spec.

    Binds a plan / manifest / change-set approval / apply / destroy to the exact
    toolchain in effect (ADR-013). Validation is applied first so the hash always
    covers a well-formed, secret-free profile.
    """
    from secp_scenario_schema import content_hash

    spec = validate_toolchain_profile(profile)
    return content_hash(spec.model_dump(mode="json"))
