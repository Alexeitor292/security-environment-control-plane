"""Versioned NONSECRET commissioning descriptor (SECP-PR5C, ADR-023, deliverable 2).

The descriptor is the ONLY externally-supplied input to the commissioning engine. It carries the
non-secret parameters of one deployment — exact source revision, image identity, queue names,
runtime UID/GID, root-controlled filesystem locations, resource limits, and opaque deployment
identity bindings — split into three sections: ``control_plane``, ``ordinary_worker`` and
``operator_preparation``.

It is secret-free BY CONTRACT and BY SCANNER. Every model forbids unknown fields (pydantic
``extra="forbid"``); every string field is bounded and rejects blank / wildcard / placeholder /
sentinel values; and an EXPLICIT :func:`scan_forbidden` pass rejects secret-like FIELD NAMES at any
depth and secret-material / credential VALUE patterns (PEM keys, ``vault:`` / ``openbao:`` refs,
bearer tokens, cloud keys, JWTs) before the schema is even constructed. A descriptor NEVER contains
a
credential, token, password, private key, secret reference, OpenBao path, state key, or provider
credential — those are supplied out of band to a SEPARATELY REVIEWED deployment package, never here.

The validated descriptor serializes canonically and produces a deterministic ``sha256:`` digest that
binds it into the commissioning plan and the evidence record. Repository fixtures MUST use only
RFC-reserved names (``example.com``, ``example.test``) and documentation address ranges
(``192.0.2.0/24``, ``2001:db8::/32``) — never a real deployment value.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from secp_commissioning.canonical import is_sha256_digest, sha256_digest
from secp_commissioning.errors import CommissioningError

# The descriptor CONTRACT version (distinct from the tool version). A descriptor whose
# ``contract_version`` is not EXACTLY this literal is refused — there is no best-effort upgrade.
CONTRACT_VERSION = "secp.commissioning.descriptor/v1alpha1"

# --- bounds (a real descriptor is tiny; anything larger fails closed) -----------------------------
MAX_DESCRIPTOR_BYTES = 64 * 1024
_MAX_TOKEN = 200
_MAX_LABEL = 128
_MAX_HEALTH_ARGS = 16
_MAX_UID = 65533  # never 0 (root) and never the 65534 "nobody"/overflow id


class DescriptorError(CommissioningError):
    """The descriptor is out of contract. Carries a bounded reason code; never echoes a value."""


# --------------------------------------------------------------------------- forbidden scanner

# Secret-like FIELD-NAME fragments forbidden at ANY nesting depth. A descriptor is non-secret by
# contract; a field whose NAME implies credential material is refused even if the value looks
# benign.
_FORBIDDEN_FIELD_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "credential",
    "private_key",
    "privatekey",
    "priv_key",
    "api_key",
    "apikey",
    "access_key",
    "secret_key",
    "signing_key",
    "ssh_key",
    "host_key",
    "tls_key",
    "ca_key",
    "vault",
    "openbao",
    "state_key",
    "statekey",
    "bearer",
    "cookie",
    "session_token",
    "client_secret",
    "auth_token",
    "provider_credential",
)

# Secret-material / credential VALUE patterns forbidden in ANY string value at ANY depth. These
# detect committed CREDENTIALS, not documentation host names (an image reference legitimately names
# a
# documentation registry such as ``registry.example.test``).
_FORBIDDEN_VALUE_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bssh-(rsa|ed25519|dss)\s+AAAA"),
    re.compile(r"(?i)\bvault:"),
    re.compile(r"(?i)\bopenbao:"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{8,}"),
    re.compile(r"(?i)\bauthorization\s*:"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."),  # JWT
    re.compile(r"(?i)\bx-vault-token\b"),
)

# Placeholder / sentinel VALUE tokens (substring, case-insensitive) — an un-filled template value.
# ``example`` is deliberately NOT here: ``example.com`` / ``example.test`` are valid RFC-reserved
# documentation names used by fixtures.
_SENTINEL_SUBSTRINGS: tuple[str, ...] = (
    "changeme",
    "change_me",
    "change-me",
    "replaceme",
    "replace_me",
    "replace-me",
    "placeholder",
    "fill_me",
    "fillme",
    "your-",
    "your_",
    "todo",
    "fixme",
    "tbd",
    "xxxx",
    "<",
    ">",
    "${",
    "{{",
    "%(",
)

# Exact wildcard/blank tokens (whole-value, case-insensitive) refused for every string field.
_WILDCARD_TOKENS: frozenset[str] = frozenset({"*", "any", "all", "none", "null", "na", "n/a", "-"})


def scan_forbidden(obj: Any) -> None:
    """Recursively reject secret-like field NAMES, secret-SHAPED keys, and secret-material VALUE
    patterns.

    Raises :class:`DescriptorError` with a FIXED, attacker-independent reason code — a matched
    fragment from the fixed forbidden list, ``forbidden_secret_key``, or ``forbidden_secret_value``.
    A reason code never echoes a raw key, a value, or a caller-controlled field path (any of which
    could smuggle a token into a log). Runs on the RAW parsed object BEFORE schema construction, so
    a
    secret is refused even before the typed model exists.
    """
    if isinstance(obj, dict):
        if len(obj) > 256:
            raise DescriptorError("descriptor_too_many_fields")
        for key, value in obj.items():
            key_s = str(key)
            key_l = key_s.lower()
            for frag in _FORBIDDEN_FIELD_FRAGMENTS:
                # Reason carries the MATCHED fragment (a member of our fixed list) — never the raw
                # key, which an attacker controls and could shape to smuggle a token into a log.
                if frag in key_l:
                    raise DescriptorError("forbidden_secret_field:" + frag)
            # A secret-SHAPED KEY (credential material used AS the field name) is refused with a
            # FIXED reason that never echoes the key.
            for rx in _FORBIDDEN_VALUE_RES:
                if rx.search(key_s):
                    raise DescriptorError("forbidden_secret_key")
            scan_forbidden(value)
    elif isinstance(obj, list):
        if len(obj) > 512:
            raise DescriptorError("descriptor_list_too_long")
        for value in obj:
            scan_forbidden(value)
    elif isinstance(obj, str):
        if len(obj) > _MAX_TOKEN * 8:
            raise DescriptorError("descriptor_value_too_long")
        for rx in _FORBIDDEN_VALUE_RES:
            # FIXED reason — the offending value (and its enclosing key path, which may itself be
            # attacker-controlled) never appears in the reason code.
            if rx.search(obj):
                raise DescriptorError("forbidden_secret_value")


def _safe_path(path: str) -> str:
    """Bound + sanitize a JSON field path for a reason code (field names only; never a value)."""
    return re.sub(r"[^A-Za-z0-9_.$\[\]-]", "", path)[:80]


# --------------------------------------------------------------------------- reusable field checks


def _check_token(value: str, *, field: str) -> str:
    """A bounded, non-blank token that is not a wildcard / placeholder / sentinel."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if not value.strip():
        raise ValueError(f"{field} must not be blank")
    if len(value) > _MAX_TOKEN:
        raise ValueError(f"{field} exceeds the maximum length")
    if value.strip().lower() in _WILDCARD_TOKENS:
        raise ValueError(f"{field} must not be a wildcard")
    low = value.lower()
    if any(s in low for s in _SENTINEL_SUBSTRINGS):
        raise ValueError(f"{field} must not be a placeholder or sentinel value")
    return value


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


_HEX_RE = re.compile(r"^[0-9a-f]+$")
_QUEUE_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_IMAGE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{2,199}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _git_sha(value: str, field: str) -> str:
    _check_token(value, field=field)
    v = value.lower()
    if len(v) not in (40, 64) or not _HEX_RE.match(v):
        raise ValueError(f"{field} must be a 40- or 64-char lowercase hex git object id")
    return v


# --------------------------------------------------------------------------- descriptor sub-models


class SourceRevision(_Strict):
    """The EXACT source identity a section's image was built from (pins reproducibility)."""

    source_sha: str
    source_tree_sha: str
    parent_sha: str | None = None

    @field_validator("source_sha", "source_tree_sha")
    @classmethod
    def _v_required_sha(cls, v: str, info: Any) -> str:
        return _git_sha(v, info.field_name)

    @field_validator("parent_sha")
    @classmethod
    def _v_parent(cls, v: str | None) -> str | None:
        return None if v is None else _git_sha(v, "parent_sha")


class ImageIdentity(_Strict):
    """A pinned container image: its reference AND its content-addressed digest.

    The reference is a documentation registry path in fixtures; the digest is what the installer
    verifies present via the injected local container-runtime adapter (never pulled here).
    """

    reference: str
    digest: str

    @field_validator("reference")
    @classmethod
    def _v_reference(cls, v: str) -> str:
        _check_token(v, field="image.reference")
        if not _IMAGE_REF_RE.match(v):
            raise ValueError("image.reference has invalid characters")
        return v

    @field_validator("digest")
    @classmethod
    def _v_digest(cls, v: str) -> str:
        if not is_sha256_digest(v):
            raise ValueError("image.digest must be a sha256:<64-hex> content digest")
        return v


class RuntimeIdentity(_Strict):
    """The non-root runtime user + hardening flags a service runs as."""

    uid: int = Field(ge=1, le=_MAX_UID)
    gid: int = Field(ge=1, le=_MAX_UID)
    read_only_root_fs: bool

    @field_validator("uid", "gid")
    @classmethod
    def _v_nonroot(cls, v: int, info: Any) -> int:
        if isinstance(v, bool):
            raise ValueError(f"{info.field_name} must be an integer, not a bool")
        if v == 0:
            raise ValueError(f"{info.field_name} must not be root (0)")
        return v


class ResourceLimits(_Strict):
    """Bounded resource limits for a service (never unbounded)."""

    memory_limit_mb: int = Field(ge=64, le=1024 * 1024)
    cpu_limit_millicores: int = Field(ge=100, le=256_000)
    pids_limit: int = Field(ge=16, le=100_000)


class DeploymentIdentity(_Strict):
    """Opaque, non-secret deployment identity bindings — safe labels + a UUID, never a hostname."""

    deployment_id: str
    site_label: str
    environment_label: str

    @field_validator("deployment_id")
    @classmethod
    def _v_uuid(cls, v: str) -> str:
        _check_token(v, field="deployment_id")
        if not _UUID_RE.match(v.lower()):
            raise ValueError("deployment_id must be a UUID")
        return v.lower()

    @field_validator("site_label", "environment_label")
    @classmethod
    def _v_label(cls, v: str, info: Any) -> str:
        _check_token(v, field=info.field_name)
        if not _LABEL_RE.match(v):
            raise ValueError(f"{info.field_name} has invalid characters")
        return v


def _health_command(v: list[str], field: str) -> list[str]:
    if not isinstance(v, list) or not v:
        raise ValueError(f"{field} must be a non-empty argv list")
    if len(v) > _MAX_HEALTH_ARGS:
        raise ValueError(f"{field} has too many arguments")
    for arg in v:
        _check_token(arg, field=field)
    return list(v)


class ControlPlaneSection(_Strict):
    """The control-plane (API) deployment parameters."""

    source: SourceRevision
    image: ImageIdentity
    runtime: RuntimeIdentity
    resources: ResourceLimits
    health_command: list[str]

    @field_validator("health_command")
    @classmethod
    def _v_health(cls, v: list[str]) -> list[str]:
        return _health_command(v, "control_plane.health_command")


class OrdinaryWorkerSection(_Strict):
    """The shipped, sealed ordinary-worker deployment parameters.

    ``task_queue`` is the ONLY queue the ordinary worker polls. ``db_role`` is a non-secret database
    ROLE NAME (never a password/URI). This section describes the ALREADY-RUNNING worker;
    commissioning
    NEVER stops or modifies it (the installer's rollback ownership set excludes these paths).
    """

    source: SourceRevision
    image: ImageIdentity
    runtime: RuntimeIdentity
    resources: ResourceLimits
    task_queue: str
    db_role: str
    health_command: list[str]

    @field_validator("task_queue")
    @classmethod
    def _v_queue(cls, v: str) -> str:
        _check_token(v, field="ordinary_worker.task_queue")
        if not _QUEUE_RE.match(v):
            raise ValueError("ordinary_worker.task_queue has invalid characters")
        return v

    @field_validator("db_role")
    @classmethod
    def _v_role(cls, v: str) -> str:
        _check_token(v, field="ordinary_worker.db_role")
        if not _LABEL_RE.match(v):
            raise ValueError("ordinary_worker.db_role has invalid characters")
        return v

    @field_validator("health_command")
    @classmethod
    def _v_health(cls, v: list[str]) -> list[str]:
        return _health_command(v, "ordinary_worker.health_command")


class OperatorPreparationSection(_Strict):
    """The operator-worker PREPARATION parameters — PREPARED, NEVER ACTIVATED.

    ``enabled`` MUST be ``False`` in this milestone (the service is rendered disabled and never
    started). ``task_queue`` MUST be distinct from the ordinary queue (validated at the descriptor
    level). The descriptor supplies NO install path — the executable-owned
    :class:`~secp_commissioning.locations.CommissioningLocations` fixes the operator root and every
    file basename. No composition, credential, endpoint, or secret reference appears here — the
    operator entrypoint fails closed with ``controlled_live_composition_not_installed`` until a
    later, separately-reviewed deployment package supplies the typed controlled-live compositions.
    """

    image: ImageIdentity
    runtime: RuntimeIdentity
    resources: ResourceLimits
    task_queue: str
    enabled: bool = False

    @field_validator("task_queue")
    @classmethod
    def _v_queue(cls, v: str) -> str:
        _check_token(v, field="operator_preparation.task_queue")
        if not _QUEUE_RE.match(v):
            raise ValueError("operator_preparation.task_queue has invalid characters")
        return v

    @field_validator("enabled")
    @classmethod
    def _v_enabled(cls, v: bool) -> bool:
        if v is not False:
            raise ValueError("operator_preparation.enabled must be false in this milestone")
        return v


class CommissioningDescriptor(_Strict):
    """The complete, versioned, secret-free commissioning descriptor."""

    contract_version: Literal["secp.commissioning.descriptor/v1alpha1"]
    deployment: DeploymentIdentity
    control_plane: ControlPlaneSection
    ordinary_worker: OrdinaryWorkerSection
    operator_preparation: OperatorPreparationSection

    @model_validator(mode="after")
    def _v_queue_separation(self) -> CommissioningDescriptor:
        # The operator queue MUST be distinct from the ordinary queue — a shared queue would let the
        # sealed worker pick up controlled-live work non-deterministically (ADR-022 §12).
        if self.operator_preparation.task_queue == self.ordinary_worker.task_queue:
            raise ValueError("operator_preparation.task_queue must differ from the ordinary queue")
        return self


def parse_descriptor(raw: Any) -> CommissioningDescriptor:
    """Validate a raw parsed object into a :class:`CommissioningDescriptor`.

    Runs the explicit forbidden-secret scanner FIRST, then strict schema validation. Every failure
    is a :class:`DescriptorError` with a bounded reason code that never echoes a value or a raw
    pydantic message.
    """
    if not isinstance(raw, dict):
        raise DescriptorError("descriptor_not_object")
    scan_forbidden(raw)
    try:
        return CommissioningDescriptor.model_validate(raw)
    except ValidationError as exc:
        errors = exc.errors()
        loc: tuple = tuple(errors[0].get("loc", ())) if errors else ()
        etype = errors[0].get("type") if errors else None
        # For an UNKNOWN field the leaf key is attacker-controlled (and could be secret-shaped), so
        # the reason names only the KNOWN parent path — never the offending key. For any other error
        # the whole loc is schema-defined field names, which are safe to echo.
        if etype == "extra_forbidden":
            parent = ".".join(str(p) for p in loc[:-1]) or "descriptor"
            raise DescriptorError("descriptor_unknown_field:" + _safe_path(parent)) from None
        field = ".".join(str(p) for p in loc) or "descriptor"
        raise DescriptorError("descriptor_invalid:" + _safe_path(field)) from None


def descriptor_canonical(descriptor: CommissioningDescriptor) -> dict:
    """The canonical, secret-free dict of a descriptor (stable across processes)."""
    return descriptor.model_dump(mode="json")


def descriptor_digest(descriptor: CommissioningDescriptor) -> str:
    """The deterministic ``sha256:`` content address of a validated descriptor."""
    return sha256_digest(descriptor_canonical(descriptor))
