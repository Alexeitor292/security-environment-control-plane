"""The strict, versioned, signed offline release-bundle CONTRACT (SECP-PR5E).

A release bundle is a directory carrying a canonical-JSON ``release-manifest.json``, a detached
``release-manifest.sig.json`` signature envelope, and a CLOSED inventory of reviewed artifacts
(compose templates, image archives, wheels, SBOMs). The manifest binds every artifact's exact
SHA-256, so signing the canonical manifest signs the whole release; the aggregate release digest is
the manifest's own canonical digest.

The manifest is parsed fail-closed: canonical JSON, duplicate-key rejection, unknown-field rejection
(``extra='forbid'``), strict typing, bounded values, forbidden-secret scanning, and RELATIVE safe
artifact names only (no absolute path, traversal, ``.``/``..`` segment, backslash, or NUL). Symlink
/
hardlink / non-regular refusal and the exact per-artifact digest are enforced at verification time
against the hardened filesystem (:mod:`secp_management.release_verify`). No floating image tag is
ever
trusted — an image is identified only by its exact content digest and loaded only from its verified
archive; no registry is contacted.
"""

from __future__ import annotations

import json
import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from secp_commissioning.canonical import canonical_json, is_sha256_digest, sha256_bytes
from secp_commissioning.descriptor import scan_forbidden

from secp_management import BOOTSTRAP_CONTRACT_VERSION, PLANE_MANAGEMENT, ManagementError
from secp_management.topology import EXPECTED_CONTROLLER_COMPONENTS

MANIFEST_NAME = "release-manifest.json"
SIGNATURE_NAME = "release-manifest.sig.json"

# Closed artifact kinds. A scenario-plane / Proxmox / unknown kind is refused (extra/enum).
ARTIFACT_KINDS = frozenset(
    {
        "controller_compose_template",
        "worker_compose_template",
        "image_archive",
        "python_wheel",
        "sbom",
    }
)
# Which role each kind belongs to; "shared" artifacts are valid in either role's bundle.
_KIND_ROLE = {
    "controller_compose_template": "controller",
    "worker_compose_template": "worker",
    "image_archive": "shared",
    "python_wheel": "shared",
    "sbom": "shared",
}
_ROLES = frozenset({"controller", "worker"})
_ARTIFACT_ROLES = frozenset({"controller", "worker", "shared"})

# Closed artifact-PURPOSE taxonomy (SECP-PR5E round 4). Every image and security-sensitive wheel is
# bound to exactly one reviewed purpose in the SIGNED manifest, so the controller component->image
# mapping and the worker ordinary/operator images are derived from this signed mapping — never from
# set membership or the observed host mapping. Purposes are role-scoped: a controller/* purpose may
# appear ONLY in a controller bundle and a worker/* purpose ONLY in a worker bundle.
_CONTROLLER_IMAGE_PURPOSES = frozenset(f"controller/{c}" for c in EXPECTED_CONTROLLER_COMPONENTS)
_WORKER_IMAGE_PURPOSES = frozenset({"worker/ordinary", "worker/operator"})
_WORKER_WHEEL_PURPOSES = frozenset({"worker/deployment-package"})
_IMAGE_PURPOSES = _CONTROLLER_IMAGE_PURPOSES | _WORKER_IMAGE_PURPOSES
_WHEEL_PURPOSES = _WORKER_WHEEL_PURPOSES
_ALL_PURPOSES = _IMAGE_PURPOSES | _WHEEL_PURPOSES
# The exact purpose set each role's bundle MUST contain (missing → refused).
_REQUIRED_PURPOSES = {
    "controller": frozenset(_CONTROLLER_IMAGE_PURPOSES),
    "worker": frozenset(_WORKER_IMAGE_PURPOSES | _WORKER_WHEEL_PURPOSES),
}
# Kinds that MUST carry a purpose (images + security-sensitive wheels); others must NOT.
_PURPOSE_REQUIRED_KINDS = frozenset({"image_archive", "python_wheel"})
WORKER_ORDINARY_PURPOSE = "worker/ordinary"
WORKER_OPERATOR_PURPOSE = "worker/operator"
WORKER_DEPLOYMENT_PACKAGE_PURPOSE = "worker/deployment-package"


def _purpose_role(purpose: str) -> str:
    return purpose.split("/", 1)[0]


_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024 * 1024  # 8 GiB hard cap on a declared artifact size
_MAX_ARTIFACTS = 512
# A safe RELATIVE artifact name: dot/dash/underscore segments joined by single slashes. No leading
# slash, no `..`/`.` segment, no backslash, no empty segment, bounded length.
_SAFE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*(?:/[A-Za-z0-9_][A-Za-z0-9._-]*)*")

_Str = Annotated[str, Field(min_length=1, max_length=256, strict=True)]
_Sha = Annotated[str, Field(min_length=71, max_length=71, strict=True)]  # "sha256:" + 64 hex


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ArtifactRecord(_Strict):
    """One reviewed artifact in the closed release inventory."""

    name: _Str
    kind: _Str
    role: _Str
    sha256: _Sha
    size: Annotated[int, Field(ge=1, le=_MAX_ARTIFACT_BYTES, strict=True)]
    image_digest: _Sha | None = None
    purpose: _Str | None = None  # required for image_archive + python_wheel (closed taxonomy)


class ReleaseManifest(_Strict):
    """The strict, canonical release manifest binding every artifact digest."""

    bootstrap_contract_version: _Str
    plane: _Str
    role: _Str
    release_version: _Str
    source_sha: _Str
    source_tree_sha: _Str
    parent_sha: _Str | None = None
    migration_identity: _Str
    implementation_aggregate: _Sha
    bootstrap_package_identity: _Str
    signing_anchor_id: _Str
    artifacts: tuple[ArtifactRecord, ...]

    @field_validator("artifacts", mode="before")
    @classmethod
    def _coerce_artifacts(cls, v: object) -> object:
        return tuple(v) if isinstance(v, list) else v

    def canonical(self) -> str:
        return canonical_json(self.model_dump(mode="json"))


class ReleaseSignature(_Strict):
    """The detached signature envelope over the canonical manifest bytes."""

    algorithm: _Str
    key_id: _Str
    signature: Annotated[str, Field(min_length=128, max_length=128, strict=True)]  # 64-byte hex


def _safe_name(value: str) -> bool:
    return bool(_SAFE_NAME.fullmatch(value)) and ".." not in value.split("/") and len(value) <= 256


def parse_manifest_bytes(raw: bytes) -> ReleaseManifest:
    """Strict UTF-8 + duplicate-key-rejecting JSON parse + forbidden-secret scan + strict schema +
    semantic well-formedness (role/kind consistency, safe names, aggregate integrity). Every failure
    is a bounded :class:`ManagementError` that never echoes a value."""
    obj = _load_object(raw, "release_manifest")
    try:
        manifest = ReleaseManifest.model_validate(obj)
    except ValidationError as exc:
        raise ManagementError("release_manifest_invalid:" + _safe_field(exc)) from None
    assert_manifest_wellformed(manifest)
    return manifest


def parse_signature_bytes(raw: bytes) -> ReleaseSignature:
    obj = _load_object(raw, "release_signature")
    try:
        sig = ReleaseSignature.model_validate(obj)
    except ValidationError as exc:
        raise ManagementError("release_signature_invalid:" + _safe_field(exc)) from None
    if sig.algorithm != "ed25519":
        raise ManagementError("release_signature_algorithm_unsupported")
    try:
        bytes.fromhex(sig.signature)
    except ValueError:
        raise ManagementError("release_signature_not_hex") from None
    return sig


def assert_manifest_wellformed(manifest: ReleaseManifest) -> None:
    """Fail closed on any semantic defect the schema alone cannot express (bounded reasons)."""
    if manifest.bootstrap_contract_version != BOOTSTRAP_CONTRACT_VERSION:
        raise ManagementError("release_contract_version_invalid")
    if manifest.plane != PLANE_MANAGEMENT:
        raise ManagementError("release_plane_invalid")
    if manifest.role not in _ROLES:
        raise ManagementError("release_role_invalid")
    if not is_sha256_digest(manifest.implementation_aggregate):
        raise ManagementError("release_implementation_aggregate_invalid")
    if not manifest.artifacts or len(manifest.artifacts) > _MAX_ARTIFACTS:
        raise ManagementError("release_inventory_size_invalid")
    seen: set[str] = set()
    seen_purposes: set[str] = set()
    for art in manifest.artifacts:
        if art.kind not in ARTIFACT_KINDS:
            raise ManagementError("release_artifact_kind_unknown")
        if art.role not in _ARTIFACT_ROLES:
            raise ManagementError("release_artifact_role_invalid")
        # role/kind consistency: a kind's owning role must be the artifact role (or shared).
        if _KIND_ROLE[art.kind] != art.role:
            raise ManagementError("release_artifact_role_kind_mismatch")
        # mixed-role inventory: every artifact must belong to the bundle role (or be shared).
        if art.role not in ("shared", manifest.role):
            raise ManagementError("mixed_role_inventory")
        if not _safe_name(art.name):
            raise ManagementError("release_artifact_name_unsafe")
        if art.name in seen:
            raise ManagementError("release_artifact_duplicate_name")
        seen.add(art.name)
        if not is_sha256_digest(art.sha256):
            raise ManagementError("release_artifact_digest_invalid")
        # an image archive MUST pin an exact content digest; other kinds MUST NOT.
        if art.kind == "image_archive":
            if art.image_digest is None or not is_sha256_digest(art.image_digest):
                raise ManagementError("release_image_digest_invalid")
        elif art.image_digest is not None:
            raise ManagementError("release_image_digest_unexpected")
        _assert_artifact_purpose(manifest.role, art, seen_purposes)
    # every REQUIRED purpose for this role must be present (missing → refused).
    if not _REQUIRED_PURPOSES[manifest.role].issubset(seen_purposes):
        raise ManagementError("release_purpose_set_incomplete")


def _assert_artifact_purpose(role: str, art: ArtifactRecord, seen_purposes: set[str]) -> None:
    """Bind every image + security-sensitive wheel to exactly one closed, role-compatible purpose;
    refuse a missing/unexpected/unknown/kind-mismatched/role-incompatible/duplicate purpose."""
    if art.kind not in _PURPOSE_REQUIRED_KINDS:
        if art.purpose is not None:
            raise ManagementError("release_artifact_purpose_unexpected")
        return
    if art.purpose is None:
        raise ManagementError("release_artifact_purpose_missing")
    if art.purpose not in _ALL_PURPOSES:
        raise ManagementError("release_artifact_purpose_unknown")
    if art.kind == "image_archive" and art.purpose not in _IMAGE_PURPOSES:
        raise ManagementError("release_artifact_purpose_kind_mismatch")
    if art.kind == "python_wheel" and art.purpose not in _WHEEL_PURPOSES:
        raise ManagementError("release_artifact_purpose_kind_mismatch")
    if _purpose_role(art.purpose) != role:
        raise ManagementError("release_artifact_purpose_role_incompatible")
    if art.purpose in seen_purposes:
        raise ManagementError("release_artifact_purpose_duplicate")
    seen_purposes.add(art.purpose)


def signed_controller_image_map(manifest: ReleaseManifest) -> dict[str, str]:
    """The SIGNED controller component -> exact image digest mapping, derived ONLY from the manifest
    purposes (never from set membership or the observed host). One entry per expected component."""
    out: dict[str, str] = {}
    for art in manifest.artifacts:
        if art.kind == "image_archive" and art.purpose in _CONTROLLER_IMAGE_PURPOSES:
            component = art.purpose.split("/", 1)[1]  # type: ignore[union-attr]
            out[component] = art.image_digest  # type: ignore[assignment]
    return out


def signed_worker_image(manifest: ReleaseManifest, purpose: str) -> str:
    """The SIGNED image digest for a worker image purpose (worker/ordinary | worker/operator)."""
    for art in manifest.artifacts:
        if art.kind == "image_archive" and art.purpose == purpose:
            return art.image_digest  # type: ignore[return-value]
    raise ManagementError("release_worker_image_purpose_absent")


def signed_deployment_package(manifest: ReleaseManifest) -> ArtifactRecord:
    """The SIGNED PR5D deployment-package wheel artifact (purpose worker/deployment-package)."""
    for art in manifest.artifacts:
        if art.kind == "python_wheel" and art.purpose == WORKER_DEPLOYMENT_PACKAGE_PURPOSE:
            return art
    raise ManagementError("release_deployment_package_absent")


def manifest_aggregate_digest(manifest: ReleaseManifest) -> str:
    """The one aggregate release digest: the canonical manifest's own SHA-256 content address (it
    binds every artifact digest, so it is the whole release's content identity)."""
    return sha256_bytes(manifest.canonical().encode("utf-8"))


def manifest_signing_message(manifest: ReleaseManifest) -> bytes:
    """The exact bytes the release signature covers: the canonical manifest encoding."""
    return manifest.canonical().encode("utf-8")


# --------------------------------------------------------------------------- strict JSON parse


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise _DuplicateKey()
        seen.add(key)
    return dict(pairs)


def _load_object(raw: bytes, what: str) -> dict:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ManagementError(f"{what}_not_utf8") from None
    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKey:
        raise ManagementError(f"{what}_duplicate_key") from None
    except ValueError:
        raise ManagementError(f"{what}_not_json") from None
    if not isinstance(parsed, dict):
        raise ManagementError(f"{what}_not_object")
    try:
        scan_forbidden(parsed)
    except Exception:
        raise ManagementError(f"{what}_forbidden_secret") from None
    return parsed


def _safe_field(exc: ValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "manifest"
    err = errors[0]
    if err.get("type") == "extra_forbidden":
        loc = err.get("loc", ())
        parent = ".".join(str(p) for p in loc[:-1] if isinstance(p, str)) or "manifest"
        return "unknown_field." + re.sub(r"[^A-Za-z0-9_.]", "", parent)[:48]
    loc = err.get("loc", ())
    field = ".".join(str(p) for p in loc if isinstance(p, str)) or "manifest"
    return re.sub(r"[^A-Za-z0-9_.]", "", field)[:48]
