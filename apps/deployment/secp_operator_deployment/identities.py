"""Independent trusted deployment identity pins (SECP-PR5D, blocker #4).

The root-controlled profile must MATCH these pins — it is NEVER the sole source of truth for a
security-sensitive value. :class:`ExpectedDeploymentIdentities` is an immutable, independently
constructed trusted-pins object: the reviewed package identity + manifest digest, the release
source/tree/parent SHAs, the three image digests, runtime UID/GIDs, the distinct queues, the exact
ordinary health argv, the operator systemd unit + ordinary Docker container identities, the
host-invoked executable path+digest pins (container runtime + service inspector), and the reviewed
controlled-live plan/readiness/eligibility provider implementation identities. The shipped default
is
absent/sealed; tests inject trusted pins through typed DI. ``require_profile_agreement`` fails
closed
on any disagreement with a bounded reason that never echoes a value.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, field_validator

from secp_operator_deployment import (
    PACKAGE_CONTRACT_VERSION,
    PACKAGE_VERSION,
    DeploymentPackageError,
)

# The independent trusted-pins file is a SEPARATE root-controlled JSON at a fixed executable-owned
# path (a sibling of the profile), so the profile can NEVER be the sole authority. Absent in the
# shipped repo → the production loader fails closed.
FIXED_EXPECTED_IDENTITIES_PATH = "/etc/secp/operator-deployment/expected-identities.json"
_MAX_EXPECTED_BYTES = 64 * 1024
_ROOT_UID = 0

# The reviewed controlled-live PROVIDER implementation identities as module.qualname STRINGS. These
# are a PROFILE-declared agreement point (the profile + the independent expected pins must both
# carry them, and they are cross-checked against the code) — NOT the mechanism that binds a
# constructed provider. The constructed provider is bound to its EXACT authoritative TYPE OBJECT
# via ``assert_reviewed_provider`` (``type(x) is <ExactProviderType>``), which a
# __module__/__qualname__ spoof cannot defeat. Three separate agreement points: the profile string,
# the expected pin, the type.
PLAN_PROVIDER_IDENTITY = (
    "secp_worker.plan_gen.composition_provider.ControlledLivePlanExecutionCompositionProvider"
)
READINESS_PROVIDER_IDENTITY = (
    "secp_worker.readiness.composition_provider.ControlledLiveReadinessCompositionProvider"
)
ELIGIBILITY_PROVIDER_IDENTITY = (
    "secp_worker.onboarding.eligibility_provider.ControlledLiveEligibilityCompositionProvider"
)


class IdentityError(DeploymentPackageError):
    """A profile value disagreed with an independent trusted pin (bounded reason code)."""


@dataclass(frozen=True)
class ExpectedDeploymentIdentities:
    """The immutable, independently constructed trusted pins the profile must MATCH exactly."""

    # package identity
    package_contract_version: str
    package_version: str
    package_implementation_digest: str
    # release provenance
    release_source_sha: str
    source_tree_sha: str
    parent_sha: str | None
    # image digests
    control_plane_image_digest: str
    ordinary_worker_image_digest: str
    operator_image_digest: str
    # runtime uid/gid
    ordinary_runtime_uid: int
    ordinary_runtime_gid: int
    operator_runtime_uid: int
    operator_runtime_gid: int
    # queues + health
    ordinary_task_queue: str
    operator_task_queue: str
    ordinary_health_command: tuple[str, ...]
    # topology identities
    operator_service_name: str
    ordinary_container_name: str
    # host-invoked executable object pins (path + digest)
    container_runtime_executable: str
    container_runtime_executable_digest: str
    service_inspector_executable: str
    service_inspector_executable_digest: str
    # controlled-live composition implementation identities
    controlled_live_renderer_registration: str
    controlled_live_renderer_digest: str
    controlled_live_process_registration: str
    controlled_live_process_digest: str
    controlled_live_provider_source: str
    plan_provider_identity: str = PLAN_PROVIDER_IDENTITY
    readiness_provider_identity: str = READINESS_PROVIDER_IDENTITY
    eligibility_provider_identity: str = ELIGIBILITY_PROVIDER_IDENTITY


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise IdentityError(reason)


# (profile_attr, expected_attr, reason). Every security-sensitive profile value is matched against
# its
# independent trusted pin. ``parent_sha`` is handled separately (optional).
_AGREEMENT_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("contract_version", "package_contract_version", "contract_version_mismatch"),
    ("package_version", "package_version", "package_version_mismatch"),
    (
        "package_implementation_digest",
        "package_implementation_digest",
        "package_manifest_digest_mismatch",
    ),
    ("release_source_sha", "release_source_sha", "release_source_sha_mismatch"),
    ("source_tree_sha", "source_tree_sha", "source_tree_sha_mismatch"),
    ("control_plane_image_digest", "control_plane_image_digest", "control_plane_image_mismatch"),
    ("ordinary_worker_image_digest", "ordinary_worker_image_digest", "ordinary_image_mismatch"),
    ("operator_image_digest", "operator_image_digest", "operator_image_mismatch"),
    ("ordinary_runtime_uid", "ordinary_runtime_uid", "ordinary_runtime_uid_mismatch"),
    ("ordinary_runtime_gid", "ordinary_runtime_gid", "ordinary_runtime_gid_mismatch"),
    ("operator_runtime_uid", "operator_runtime_uid", "operator_runtime_uid_mismatch"),
    ("operator_runtime_gid", "operator_runtime_gid", "operator_runtime_gid_mismatch"),
    ("ordinary_task_queue", "ordinary_task_queue", "ordinary_queue_mismatch"),
    ("operator_task_queue", "operator_task_queue", "operator_queue_mismatch"),
    ("ordinary_health_command", "ordinary_health_command", "ordinary_health_mismatch"),
    ("operator_service_name", "operator_service_name", "operator_service_mismatch"),
    ("ordinary_container_name", "ordinary_container_name", "ordinary_container_mismatch"),
    (
        "container_runtime_executable",
        "container_runtime_executable",
        "container_runtime_executable_mismatch",
    ),
    (
        "container_runtime_executable_digest",
        "container_runtime_executable_digest",
        "container_runtime_digest_mismatch",
    ),
    (
        "service_inspector_executable",
        "service_inspector_executable",
        "service_inspector_executable_mismatch",
    ),
    (
        "service_inspector_executable_digest",
        "service_inspector_executable_digest",
        "service_inspector_digest_mismatch",
    ),
    (
        "controlled_live_renderer_registration",
        "controlled_live_renderer_registration",
        "renderer_registration_mismatch",
    ),
    (
        "controlled_live_renderer_digest",
        "controlled_live_renderer_digest",
        "renderer_digest_mismatch",
    ),
    (
        "controlled_live_process_registration",
        "controlled_live_process_registration",
        "process_registration_mismatch",
    ),
    ("controlled_live_process_digest", "controlled_live_process_digest", "process_digest_mismatch"),
    (
        "controlled_live_provider_source",
        "controlled_live_provider_source",
        "provider_source_mismatch",
    ),
    ("plan_provider_identity", "plan_provider_identity", "plan_provider_identity_mismatch"),
    (
        "readiness_provider_identity",
        "readiness_provider_identity",
        "readiness_provider_identity_mismatch",
    ),
    (
        "eligibility_provider_identity",
        "eligibility_provider_identity",
        "eligibility_provider_identity_mismatch",
    ),
)


def require_profile_agreement(profile: object, expected: ExpectedDeploymentIdentities) -> None:
    """Fail closed unless every security-sensitive profile value MATCHES its independent trusted
    pin.
    The profile is never the sole authority. ``profile`` is a validated ``DeploymentProfile``."""
    for p_attr, e_attr, reason in _AGREEMENT_FIELDS:
        p_val = getattr(profile, p_attr)
        e_val = getattr(expected, e_attr)
        if p_attr == "ordinary_health_command":
            p_val, e_val = tuple(p_val), tuple(e_val)
        _require(p_val == e_val, reason)
    if expected.parent_sha is not None:
        _require(getattr(profile, "parent_sha", None) == expected.parent_sha, "parent_sha_mismatch")


def assert_reviewed_provider(provider: object, expected_type: type, *, reason: str) -> None:
    """Bind a constructed controlled-live provider to its EXACT authoritative TYPE OBJECT via
    ``type(provider) is expected_type`` — NOT a forgeable ``module``/``qualname`` string. A foreign
    class that spoofs both ``__module__`` and ``__qualname__`` and copies ``classification`` is
    refused because it is a different type object."""
    if type(provider) is not expected_type:
        raise IdentityError(reason)
    if getattr(provider, "classification", None) != "controlled_live":
        raise IdentityError(reason)


def assert_expected_package_identity(expected: ExpectedDeploymentIdentities) -> None:
    """Cross-check the INJECTED trusted pins' package/composition identities against the values the
    CODE independently owns (the package + secp_worker) — so even the trusted-pins object cannot
    lie about the package manifest digest or the reviewed composition identities."""
    from secp_worker.plan_gen.composition import CONTROLLED_LIVE_PROVIDER_SOURCE
    from secp_worker.plan_gen.controlled_live import (
        CONTROLLED_LIVE_RENDERER_VERSION,
        controlled_live_renderer_implementation_digest,
    )
    from secp_worker.plan_gen.process_boundary import (
        PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        plan_only_executor_implementation_digest,
    )

    from secp_operator_deployment import package_implementation_digest

    _require(
        expected.package_contract_version == PACKAGE_CONTRACT_VERSION,
        "expected_contract_version_invalid",
    )  # noqa: E501
    _require(expected.package_version == PACKAGE_VERSION, "expected_package_version_invalid")
    _require(
        expected.package_implementation_digest == package_implementation_digest(),
        "expected_manifest_digest_invalid",
    )  # noqa: E501
    _require(
        expected.controlled_live_provider_source == CONTROLLED_LIVE_PROVIDER_SOURCE,
        "expected_provider_source_invalid",
    )  # noqa: E501
    _require(
        expected.controlled_live_renderer_registration == CONTROLLED_LIVE_RENDERER_VERSION,
        "expected_renderer_registration_invalid",
    )  # noqa: E501
    _require(
        expected.controlled_live_renderer_digest
        == controlled_live_renderer_implementation_digest(),
        "expected_renderer_digest_invalid",
    )  # noqa: E501
    _require(
        expected.controlled_live_process_registration == PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        "expected_process_registration_invalid",
    )  # noqa: E501
    _require(
        expected.controlled_live_process_digest == plan_only_executor_implementation_digest(),
        "expected_process_digest_invalid",
    )  # noqa: E501
    _require(
        expected.plan_provider_identity == PLAN_PROVIDER_IDENTITY, "expected_plan_provider_invalid"
    )  # noqa: E501
    _require(
        expected.readiness_provider_identity == READINESS_PROVIDER_IDENTITY,
        "expected_readiness_provider_invalid",
    )  # noqa: E501
    _require(
        expected.eligibility_provider_identity == ELIGIBILITY_PROVIDER_IDENTITY,
        "expected_eligibility_provider_invalid",
    )  # noqa: E501


# --------------------------------------------------------------------------- independent loader
# (production reads the trusted pins from a fixed root-controlled file, mirroring the profile
# reader)


class _ExpectedIdentitiesFile(BaseModel):
    """Strict schema for the independent trusted-pins file. Mirrors
    :class:`ExpectedDeploymentIdentities` exactly; ``extra='forbid'`` + ``strict`` reject any
    unknown/mistyped field."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    package_contract_version: str
    package_version: str
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
    operator_service_name: str
    ordinary_container_name: str
    container_runtime_executable: str
    container_runtime_executable_digest: str
    service_inspector_executable: str
    service_inspector_executable_digest: str
    controlled_live_renderer_registration: str
    controlled_live_renderer_digest: str
    controlled_live_process_registration: str
    controlled_live_process_digest: str
    controlled_live_provider_source: str
    plan_provider_identity: str
    readiness_provider_identity: str
    eligibility_provider_identity: str

    @field_validator("ordinary_health_command", mode="before")
    @classmethod
    def _coerce_health(cls, v: object) -> object:
        return tuple(v) if isinstance(v, list) else v

    def to_expected(self) -> ExpectedDeploymentIdentities:
        return ExpectedDeploymentIdentities(**self.model_dump())


def parse_expected_identities_bytes(raw_bytes: bytes) -> ExpectedDeploymentIdentities:
    """Strict UTF-8 decode + duplicate-key-rejecting JSON parse + forbidden-secret scan + strict
    schema validation, into an :class:`ExpectedDeploymentIdentities`. Every failure is a bounded
    :class:`IdentityError` that never echoes a value."""
    from pydantic import ValidationError
    from secp_commissioning.descriptor import scan_forbidden

    from secp_operator_deployment.profile import _DuplicateKey, _reject_duplicate_keys

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise IdentityError("expected_identities_not_utf8") from None
    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKey:
        raise IdentityError("expected_identities_duplicate_key") from None
    except ValueError:
        raise IdentityError("expected_identities_not_json") from None
    if not isinstance(parsed, dict):
        raise IdentityError("expected_identities_not_object")
    try:
        scan_forbidden(parsed)
    except Exception:
        raise IdentityError("expected_identities_forbidden_secret") from None
    try:
        return _ExpectedIdentitiesFile.model_validate(parsed).to_expected()
    except ValidationError:
        raise IdentityError("expected_identities_invalid") from None


def read_expected_identities(
    *, fs: object | None = None, path: str = FIXED_EXPECTED_IDENTITIES_PATH
) -> ExpectedDeploymentIdentities:
    """Read + strictly validate the INDEPENDENT trusted-pins file through the HARDENED
    root-controlled
    backend (the same idiom as ``read_deployment_profile``). ``fs`` defaults to the production
    :class:`~secp_commissioning.runtime.RealFilesystem`; a missing/unreadable file or non-POSIX
    host fails closed with a bounded reason. Tests inject an in-memory backend + alternate path."""
    backend = fs
    if backend is None:
        try:
            from secp_commissioning.runtime import RealFilesystem

            backend = RealFilesystem()
        except Exception:  # non-POSIX dev host / backend unavailable → fail closed
            raise IdentityError("expected_identities_reader_unavailable") from None
    try:
        st = backend.lstat(path)  # type: ignore[attr-defined]
    except Exception:
        raise IdentityError("expected_identities_unreadable") from None
    if st is None:
        raise IdentityError("expected_identities_not_installed")
    try:
        raw_bytes = backend.safe_read(  # type: ignore[attr-defined]
            path, max_bytes=_MAX_EXPECTED_BYTES, expected_uid=_ROOT_UID
        )
    except Exception:
        raise IdentityError("expected_identities_unreadable") from None
    return parse_expected_identities_bytes(raw_bytes)
