"""The strict, secret-free, versioned deployment-local PROFILE (SECP-PR5D).

The profile carries ONLY the nonsecret IDENTITIES needed to construct + validate the deployment
package: exact source revision, package version + implementation identity, the three image content
digests, runtime UID/GIDs, the distinct ordinary/operator queues, the ordinary health command, the
local service/container identities, and the exact controlled-live composition implementation
identities. It carries NO credential, token, private key, secret reference, OpenBao path, state key,
Proxmox endpoint, password, or bearer material — enforced by strict schema (``extra="forbid"`` +
``strict``) AND the reused commissioning forbidden-secret scanner.

It is read through the HARDENED root-controlled filesystem backend (``RealFilesystem.safe_read``:
O_NOFOLLOW, root-owned + non-world-writable, exact bounded read, symlink-safe ancestors) at a FIXED
path — there is no arbitrary ``--profile`` flag. Tests inject an alternate ``fs`` / ``path`` through
typed DI. The reader NEVER contacts the network and reads no secret.
"""

from __future__ import annotations

import json
import re

from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from secp_commissioning.descriptor import scan_forbidden

from secp_operator_deployment import (
    PACKAGE_CONTRACT_VERSION,
    PACKAGE_IMPLEMENTATION_ID,
    PACKAGE_VERSION,
    DeploymentPackageError,
)

# The FIXED, root-controlled profile path. Created out of band by the bootstrap operator (ADR-024),
# never by this package. Not an arbitrary caller-selected path.
FIXED_PROFILE_PATH = "/etc/secp/operator-deployment/profile.json"
MAX_PROFILE_BYTES = 64 * 1024
_ROOT_UID = 0

_SHA_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_SHA = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_QUEUE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,199}$")
_ABS_POSIX = re.compile(r"^/[^\x00\\]{1,255}$")
_REGISTRATION = re.compile(r"^[a-z0-9][a-z0-9./-]{2,199}$")
_QUALNAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]{2,199}$")
_MAX_UID = 65533


class ProfileError(DeploymentPackageError):
    """The deployment profile is out of contract (bounded reason code; never a value)."""


class _StrictProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class DeploymentProfile(_StrictProfile):
    """The strict, secret-free, versioned deployment-local identity profile."""

    contract_version: str
    package_version: str
    package_implementation_id: str
    package_implementation_digest: str

    release_source_sha: str
    source_tree_sha: str
    parent_sha: str | None = None

    control_plane_image_digest: str
    ordinary_worker_image_digest: str
    operator_image_digest: str

    ordinary_runtime_uid: int
    ordinary_runtime_gid: int
    operator_runtime_uid: int
    operator_runtime_gid: int

    ordinary_task_queue: str
    operator_task_queue: str
    ordinary_health_command: tuple[str, ...]

    # topology: operator = prepared/disabled systemd unit; ordinary worker = existing Docker
    # container
    operator_service_name: str
    ordinary_container_name: str

    # host-invoked executables: absolute path + independently reviewed object digest (blocker #3)
    container_runtime_executable: str
    container_runtime_executable_digest: str
    service_inspector_executable: str
    service_inspector_executable_digest: str

    controlled_live_renderer_registration: str
    controlled_live_renderer_digest: str
    controlled_live_process_registration: str
    controlled_live_process_digest: str
    controlled_live_provider_source: str

    # the reviewed controlled-live PROVIDER implementation identities (module.qualname), one of the
    # three independent agreement points for each composition branch (blocker #6)
    plan_provider_identity: str
    readiness_provider_identity: str
    eligibility_provider_identity: str

    @field_validator("contract_version")
    @classmethod
    def _v_contract(cls, v: str) -> str:
        if v != PACKAGE_CONTRACT_VERSION:
            raise ValueError("unexpected profile contract version")
        return v

    @field_validator("package_version")
    @classmethod
    def _v_package_version(cls, v: str) -> str:
        if v != PACKAGE_VERSION:
            raise ValueError("unexpected package version")
        return v

    @field_validator("package_implementation_id")
    @classmethod
    def _v_package_id(cls, v: str) -> str:
        if v != PACKAGE_IMPLEMENTATION_ID:
            raise ValueError("unexpected package implementation id")
        return v

    @field_validator(
        "package_implementation_digest",
        "control_plane_image_digest",
        "ordinary_worker_image_digest",
        "operator_image_digest",
        "container_runtime_executable_digest",
        "service_inspector_executable_digest",
        "controlled_live_renderer_digest",
        "controlled_live_process_digest",
    )
    @classmethod
    def _v_digest(cls, v: str) -> str:
        if not _SHA_DIGEST.match(v):
            raise ValueError("expected a sha256:<64-hex> content digest")
        return v

    @field_validator("release_source_sha", "source_tree_sha")
    @classmethod
    def _v_sha(cls, v: str) -> str:
        if not _HEX_SHA.match(v):
            raise ValueError("expected a 40/64-char lowercase hex git object id")
        return v

    @field_validator("parent_sha")
    @classmethod
    def _v_parent(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not _HEX_SHA.match(v):
            raise ValueError("expected a 40/64-char lowercase hex git object id")
        return v

    @field_validator("ordinary_task_queue", "operator_task_queue")
    @classmethod
    def _v_queue(cls, v: str) -> str:
        if not _QUEUE.match(v):
            raise ValueError("task queue has an invalid shape")
        return v

    @field_validator("ordinary_runtime_uid", "operator_runtime_uid")
    @classmethod
    def _v_uid(cls, v: int) -> int:
        if isinstance(v, bool) or not (1 <= v <= _MAX_UID):
            raise ValueError("runtime uid must be a non-root, bounded integer")
        return v

    @field_validator("ordinary_runtime_gid", "operator_runtime_gid")
    @classmethod
    def _v_gid(cls, v: int) -> int:
        if isinstance(v, bool) or not (1 <= v <= _MAX_UID):
            raise ValueError("runtime gid must be a non-root, bounded integer")
        return v

    @field_validator("ordinary_health_command", mode="before")
    @classmethod
    def _coerce_health(cls, v: object) -> object:
        # JSON arrays parse to lists; accept a list under strict mode and canonicalise to a tuple.
        if isinstance(v, list):
            return tuple(v)
        return v

    @field_validator("ordinary_health_command")
    @classmethod
    def _v_health(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v or len(v) > 16:
            raise ValueError("health command must be a bounded non-empty argv")
        if not (isinstance(v[0], str) and v[0].startswith("/")):
            raise ValueError("health command executable must be an absolute POSIX path")
        for arg in v:
            if not (isinstance(arg, str) and arg.strip() and len(arg) <= 200):
                raise ValueError("health command argument invalid")
        return v

    @field_validator("operator_service_name", "ordinary_container_name")
    @classmethod
    def _v_service(cls, v: str) -> str:
        if not _TOKEN.match(v):
            raise ValueError("service/container identity has an invalid shape")
        return v

    @field_validator("container_runtime_executable", "service_inspector_executable")
    @classmethod
    def _v_executable(cls, v: str) -> str:
        if not _ABS_POSIX.match(v):
            raise ValueError("host executable must be an absolute POSIX path")
        return v

    @field_validator(
        "controlled_live_renderer_registration",
        "controlled_live_process_registration",
        "controlled_live_provider_source",
    )
    @classmethod
    def _v_registration(cls, v: str) -> str:
        if not _REGISTRATION.match(v):
            raise ValueError("registration identity has an invalid shape")
        return v

    @field_validator(
        "plan_provider_identity",
        "readiness_provider_identity",
        "eligibility_provider_identity",
    )
    @classmethod
    def _v_qualname(cls, v: str) -> str:
        if not _QUALNAME.match(v):
            raise ValueError("provider identity must be a module.qualname")
        return v

    @model_validator(mode="after")
    def _v_queue_separation(self) -> DeploymentProfile:
        # The operator queue MUST be distinct from the ordinary queue (ADR-022 §12): a shared queue
        # would let the sealed worker pick up controlled-live work.
        if self.ordinary_task_queue == self.operator_task_queue:
            raise ValueError("operator task queue must differ from the ordinary queue")
        return self

    def canonical(self) -> dict:
        return self.model_dump(mode="json")


def parse_deployment_profile(raw: object) -> DeploymentProfile:
    """Validate a raw parsed object into a :class:`DeploymentProfile`.

    Runs the forbidden-secret scanner FIRST (so a secret-shaped field/value is refused before the
    typed model exists), then strict schema validation. Every failure is a :class:`ProfileError`
    with a bounded reason code that never echoes a value or a raw pydantic message.
    """
    if not isinstance(raw, dict):
        raise ProfileError("profile_not_object")
    try:
        scan_forbidden(raw)  # reuse the commissioning forbidden-secret scanner
    except Exception:
        # A secret-shaped field NAME or secret-material VALUE — re-raise as a bounded package error
        # (never echo the offending key/value).
        raise ProfileError("profile_forbidden_secret") from None
    from pydantic import ValidationError

    try:
        return DeploymentProfile.model_validate(raw)
    except ValidationError as exc:
        errors = exc.errors()
        etype = errors[0].get("type") if errors else None
        loc = errors[0].get("loc", ()) if errors else ()
        if etype == "extra_forbidden":
            parent = ".".join(str(p) for p in loc[:-1] if isinstance(p, str)) or "profile"
            raise ProfileError("profile_unknown_field:" + _safe(parent)) from None
        field = ".".join(str(p) for p in loc if isinstance(p, str)) or "profile"
        raise ProfileError("profile_invalid:" + _safe(field)) from None


def _safe(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.]", "", text)[:60]


class _DuplicateKey(ValueError):
    """Raised by the duplicate-key hook (never carries the offending key/value)."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    # Fires per JSON object at EVERY nesting level; a repeated key at any depth fails closed.
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise _DuplicateKey()
        seen.add(key)
    return dict(pairs)


def parse_profile_bytes(raw_bytes: bytes) -> DeploymentProfile:
    """Strict UTF-8 decode + duplicate-key-rejecting JSON parse + validation (blocker #8)."""
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ProfileError("profile_not_utf8") from None
    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKey:
        raise ProfileError("profile_duplicate_key") from None
    except ValueError:
        raise ProfileError("profile_not_json") from None
    return parse_deployment_profile(parsed)


def read_deployment_profile(*, fs: object | None = None, path: str = FIXED_PROFILE_PATH):  # noqa: ANN201
    """Read + strictly validate the root-controlled deployment profile through the HARDENED backend.

    ``fs`` defaults to the production :class:`~secp_commissioning.runtime.RealFilesystem` (POSIX +
    root). A missing profile, an unreadable/oversized file, or a non-POSIX host fails closed with a
    bounded reason. Tests inject an in-memory backend + alternate path.
    """
    backend = fs
    if backend is None:
        try:
            from secp_commissioning.runtime import RealFilesystem

            backend = RealFilesystem()
        except Exception:  # non-POSIX dev host / backend unavailable → fail closed
            raise ProfileError("profile_reader_unavailable") from None
    try:
        st = backend.lstat(path)  # type: ignore[attr-defined]
    except Exception:
        raise ProfileError("profile_unreadable") from None
    if st is None:
        raise ProfileError("profile_not_installed")
    try:
        raw_bytes = backend.safe_read(path, max_bytes=MAX_PROFILE_BYTES, expected_uid=_ROOT_UID)  # type: ignore[attr-defined]
    except Exception:
        raise ProfileError("profile_unreadable") from None
    return parse_profile_bytes(raw_bytes)
