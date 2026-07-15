"""The worker-only, non-serializable plan-only capability (B1B-PR5A/PR5B, ADR-022 §4).

A ``PlanOnlyCapability`` is the token a fully-gated real-plan-generation operation carries into the
plan-only executor. It is:

* worker-only and **non-serializable** (cannot be pickled, ``repr``-ed with content, placed in a
  Temporal argument, persisted, or constructed by API code);
* bound to EVERY authoritative fact of the operation — organization, environment/plan/manifest/
  target/onboarding identities and hashes, eligibility, toolchain profile + durable attestation +
  the FRESH execution-time attestation evidence hash, provider source/version/lockfile/mirror/
  module/renderer provenance, the approved dossier, the plan-generation authorization, both
  credential bindings, remote-state + plan-secret readiness, the worker identity, the execution
  lease + attempt, and the EXACT reviewed process/renderer implementation digests — plus a
  capability contract version, operation fingerprint, and expiry;
* impossible to use for apply/destroy (the plan-only executor's grammar admits no such tokens);
* classified ``controlled_live`` or ``test_only`` — a ``test_only`` capability (the inert-fixture
  path) can never produce a controlled-live durable result or a real pending approval.

A self-declared contract version is NOT sufficient provenance: :func:`issue_plan_only_capability`
additionally refuses unless the activation's declared process + renderer implementation digests
equal the EXACT reviewed digests supplied by the worker-only composition. In the shipped worker the
plan-only process seal refuses executor construction first, so no capability is ever exercised on a
shipped path; the class exists so PR5B is a small reviewed change and its properties are testable.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, fields
from datetime import datetime
from typing import NoReturn, SupportsIndex

# Module-private construction token. A capability cannot be built without it.
_PLAN_ONLY_CAPABILITY_TOKEN = object()

# The two capability classifications. Only ``controlled_live`` may back a controlled-live durable
# result / real pending approval; ``test_only`` (the inert-fixture path) never can.
CONTROLLED_LIVE_CLASSIFICATION = "controlled_live"
TEST_ONLY_CLASSIFICATION = "test_only"
_CLASSIFICATIONS = frozenset({CONTROLLED_LIVE_CLASSIFICATION, TEST_ONLY_CLASSIFICATION})


class PlanOnlyCapabilityRefused(Exception):
    """The authoritative gate does not authorize a plan-only capability for this operation."""


@dataclass(frozen=True)
class PlanOnlyActivation:
    """The reviewed, authoritative binding a plan-only capability pins (opaque ids + hashes only).

    Every field is derived server-side from authoritative records by the worker; none is ever
    accepted from a caller, request body, Temporal argument, or adapter. It carries NO secret,
    reference, endpoint, backend address, or path.
    """

    # --- core identity ---------------------------------------------------------------------------
    organization_id: uuid.UUID
    plan_generation_authorization_id: uuid.UUID
    authorization_version: int
    authorization_expiry: datetime
    operation_fingerprint: str
    plan_only_capability_contract_version: str
    classification: str  # controlled_live | test_only
    expires_at: datetime

    # --- environment / plan / manifest / target / onboarding -------------------------------------
    environment_version_id: uuid.UUID
    environment_version_content_hash: str
    deployment_plan_id: uuid.UUID
    deployment_plan_content_hash: str
    provisioning_manifest_id: uuid.UUID
    provisioning_manifest_content_hash: str
    execution_target_id: uuid.UUID
    target_config_hash: str
    target_onboarding_id: uuid.UUID
    onboarding_boundary_hash: str

    # --- eligibility / toolchain / attestation ---------------------------------------------------
    eligibility_preflight_id: uuid.UUID
    eligibility_evidence_hash: str
    toolchain_profile_id: uuid.UUID
    toolchain_profile_hash: str
    toolchain_attestation_id: uuid.UUID
    toolchain_attestation_hash: str
    # The FRESH execution-time re-attestation evidence hash (distinct from the durable record hash).
    fresh_attestation_evidence_hash: str

    # --- provider provenance (identities/hashes only; never a mirror path/URL/endpoint) ----------
    provider_source: str
    provider_version: str
    provider_lockfile_hash: str
    provider_mirror_identity: str
    module_bundle_hash: str
    renderer_version: str

    # --- dossier ---------------------------------------------------------------------------------
    activation_dossier_id: uuid.UUID
    activation_dossier_hash: str
    activation_dossier_revision: int
    activation_dossier_expiry: datetime

    # --- credentials / readiness -----------------------------------------------------------------
    provider_credential_binding_id: uuid.UUID
    provider_credential_binding_version: int
    state_credential_binding_id: uuid.UUID
    state_credential_binding_version: int
    remote_state_readiness_id: uuid.UUID
    remote_state_evidence_hash: str
    plan_secret_readiness_id: uuid.UUID
    plan_secret_evidence_hash: str

    # --- worker identity -------------------------------------------------------------------------
    worker_identity_registration_id: uuid.UUID
    worker_identity_version: int

    # --- execution lease / attempt ---------------------------------------------------------------
    execution_lease_id: uuid.UUID
    attempt_id: uuid.UUID
    attempt_number: int

    # --- exact reviewed implementation digests (self-declared contract is not enough) ------------
    process_implementation_id: str
    process_implementation_digest: str
    renderer_module_id: str
    renderer_module_digest: str

    @property
    def is_controlled_live(self) -> bool:
        return self.classification == CONTROLLED_LIVE_CLASSIFICATION

    @property
    def is_test_only(self) -> bool:
        return self.classification == TEST_ONLY_CLASSIFICATION


class PlanOnlyCapability:
    """A worker-only, non-serializable proof that a plan-only operation was fully authorized."""

    __slots__ = ("__data",)

    def __init__(self, token: object, activation: PlanOnlyActivation) -> None:
        if token is not _PLAN_ONLY_CAPABILITY_TOKEN:
            raise TypeError(
                "PlanOnlyCapability cannot be constructed directly; it is issued only after "
                "authoritative gate verification inside the worker"
            )
        object.__setattr__(self, "_PlanOnlyCapability__data", activation)

    @property
    def activation(self) -> PlanOnlyActivation:
        return object.__getattribute__(self, "_PlanOnlyCapability__data")  # type: ignore[no-any-return]

    @property
    def is_controlled_live(self) -> bool:
        return self.activation.is_controlled_live

    def __repr__(self) -> str:
        return "PlanOnlyCapability(<redacted>)"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return self.__repr__()

    def __getstate__(self) -> NoReturn:
        raise TypeError("PlanOnlyCapability cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("PlanOnlyCapability cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("PlanOnlyCapability cannot be pickled")


def _require_complete(activation: PlanOnlyActivation) -> None:
    """Every string/hash binding must be present; no empty authoritative fact is permitted."""
    for f in fields(activation):
        value = getattr(activation, f.name)
        if isinstance(value, str) and not value:
            raise PlanOnlyCapabilityRefused(f"plan-only activation field {f.name} is empty")


def issue_plan_only_capability(
    activation: PlanOnlyActivation,
    *,
    now: datetime,
    expected_process_digest: str,
    expected_renderer_digest: str,
) -> PlanOnlyCapability:
    """Issue a plan-only capability after the authoritative gate (used only by a reviewed path).

    A fake/injected executor can never satisfy this: the capability is minted only here, from an
    authoritative activation, and the plan-only executor requires it. It refuses an expired
    activation or dossier, a contract-version drift, an unknown classification, an incomplete
    binding, or a process/renderer implementation digest that does not equal the EXACT reviewed
    digest supplied by the worker-only composition (a self-declared contract version is never
    enough).
    """
    from secp_api.plan_activation_contract import PLAN_ONLY_CAPABILITY_CONTRACT_VERSION
    from secp_api.readiness_contract import as_utc

    if activation.classification not in _CLASSIFICATIONS:
        raise PlanOnlyCapabilityRefused("plan-only capability classification is unknown")
    _require_complete(activation)
    if as_utc(activation.expires_at) <= now:
        raise PlanOnlyCapabilityRefused("plan-only activation expired")
    if as_utc(activation.authorization_expiry) <= now:
        raise PlanOnlyCapabilityRefused("plan-only authorization expired")
    if as_utc(activation.activation_dossier_expiry) <= now:
        raise PlanOnlyCapabilityRefused("plan-only activation dossier expired")
    if activation.plan_only_capability_contract_version != PLAN_ONLY_CAPABILITY_CONTRACT_VERSION:
        raise PlanOnlyCapabilityRefused("plan-only capability contract mismatch")
    if not expected_process_digest or not expected_renderer_digest:
        raise PlanOnlyCapabilityRefused("plan-only implementation digest unavailable")
    if activation.process_implementation_digest != expected_process_digest:
        raise PlanOnlyCapabilityRefused("plan-only process implementation digest mismatch")
    if activation.renderer_module_digest != expected_renderer_digest:
        raise PlanOnlyCapabilityRefused("plan-only renderer implementation digest mismatch")
    return PlanOnlyCapability(_PLAN_ONLY_CAPABILITY_TOKEN, activation)
