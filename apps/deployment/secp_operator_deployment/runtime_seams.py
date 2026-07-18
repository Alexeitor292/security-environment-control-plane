"""The controlled-live RUNTIME provisioning seam + its bound attestation (SECP-PR5D).

The secret-free deployment profile carries IDENTITIES only. The controlled-live plan-execution
composition additionally needs deployment-local RUNTIME pieces that are NOT identities and NOT
secret-free — the concrete OpenBao plan-secret resolvers, their activations, the nonsecret runtime
input sources (provider endpoint + state addresses), the on-disk toolchain layout, and the process
resource limits. Those are provisioned OUT OF BAND by the reviewed deployment onto the site worker;
they never live in Git and never enter the profile.

This module defines the injectable seam that supplies them (:class:`ControlledLiveRuntime`) and the
BOUND, versioned, immutable, nonsecret :class:`RuntimeProvisioningAttestation` a caller derives from
it. The attestation is bound to THIS deployment (canonical profile + expected-identities digests,
release/source shas, dossier hash, worker-identity registration id, toolchain identity) and to the
reviewed runtime-provider implementation identity+digest; a bare ``provisioned`` boolean is not
constructible, and a caller-fabricated or cross-deployment attestation is refused by
:func:`validate_runtime_attestation`. No reviewed controlled-live runtime provider is installed in
PR5D, so :data:`REVIEWED_RUNTIME_PROVIDERS` is empty and every provisioned attestation refuses
until a provider id is added there by a separately-reviewed code change.

The SHIPPED default, :class:`SealedControlledLiveRuntime`, fails closed
(``controlled_live_runtime_not_provisioned``) — so
:func:`secp_operator_deployment.compositions.build_controlled_live_compositions` refuses in the
shipped state, and :func:`attest_runtime` yields an UNPROVISIONED attestation. Constructing this
module contacts nothing; the seams it carries are OPAQUE (never inspected/called here), and neither
:func:`attest_runtime` nor :func:`validate_runtime_attestation` calls ``plan_execution_seams()`` or
constructs a secret resolver.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from secp_operator_deployment import DeploymentPackageError

if TYPE_CHECKING:  # precise annotations only — no runtime dependency on secp_worker
    from secp_worker.plan_gen.composition import (
        ProviderRuntimeInputSource,
        StateRuntimeInputSource,
    )
    from secp_worker.plan_gen.plan_secret_resolution import WorkerPlanSecretResolver
    from secp_worker.provisioning.toolchain_verify import ToolchainFilesystemLayout

    from secp_operator_deployment.identities import ExpectedDeploymentIdentities
    from secp_operator_deployment.profile import DeploymentProfile

# The attestation contract version (folded into the bound hash; a self-declared other version
# refuses).
RUNTIME_ATTESTATION_CONTRACT_VERSION = "secp-pr5d/runtime-provisioning-attestation/v1"
# The runtime-provider implementation identity carried by an UNPROVISIONED attestation. It is NOT a
# reviewed provider (see REVIEWED_RUNTIME_PROVIDERS), so it can never reach provisioned readiness.
UNPROVISIONED_RUNTIME_PROVIDER_ID = "secp-pr5d/controlled-live-runtime-provider/unprovisioned-v0"
# The code-owned set of reviewed controlled-live runtime-provider implementation identities. EMPTY
# in PR5D: no reviewed runtime provider is installed, so every provisioned attestation refuses. A
# future, separately-reviewed milestone adds the real provider id here.
REVIEWED_RUNTIME_PROVIDERS: frozenset[str] = frozenset()


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def runtime_provider_implementation_digest(implementation_id: str) -> str:
    """The deterministic digest of a runtime-provider implementation identity (same two-line idiom
    as
    the reviewed renderer/process implementation digests)."""
    return _sha256(implementation_id)


@dataclass(frozen=True)
class PlanExecutionRuntimeSeams:
    """The deployment-local RUNTIME pieces (never identities, never secret-free) required to build a
    controlled-live plan-execution composition. Supplied out of band; opaque to this package."""

    toolchain_layout: ToolchainFilesystemLayout
    trusted_workspace_root: str
    provider_version: str
    provider_runtime_input_source: ProviderRuntimeInputSource
    state_runtime_input_source: StateRuntimeInputSource
    provider_resolver: WorkerPlanSecretResolver
    state_resolver: WorkerPlanSecretResolver
    provider_resolver_activation: object
    state_resolver_activation: object
    process_timeout_seconds: int
    max_output_bytes: int
    deployment_activation_dossier_hash: str
    worker_identity_registration_id: str


@dataclass(frozen=True)
class RuntimeProvisioningAttestation:
    """A BOUND, versioned, immutable, nonsecret attestation of runtime provisioning. Every field is
    an
    identity/digest/boolean — NO resolver, factory, endpoint, credential, or callable — so a
    consumer (e.g. read-only ``verify``) reports provisioning WITHOUT calling any runtime method.
    It is bound to THIS deployment and to the reviewed runtime-provider implementation; a bare
    ``provisioned=True`` is not constructible, and a fabricated / cross-deployment / stale
    attestation is refused by :func:`validate_runtime_attestation`."""

    attestation_contract_version: str
    runtime_provider_implementation_id: str
    runtime_provider_implementation_digest: str
    deployment_profile_digest: str
    expected_identities_digest: str
    release_source_sha: str
    source_tree_sha: str
    deployment_activation_dossier_hash: str
    worker_identity_registration_id: str
    toolchain_layout_identity: str
    provisioned: bool
    attestation_hash: str


class ControlledLiveRuntime(Protocol):
    """The reviewed runtime-provisioning seam. ``provisioned`` gates whether the out-of-band
    prerequisites are present; ``plan_execution_seams`` yields them (or fails closed);
    ``provisioning_attestation`` issues a bound attestation (or fails closed)."""

    def provisioned(self) -> bool: ...
    def plan_execution_seams(self) -> PlanExecutionRuntimeSeams: ...
    def provisioning_attestation(
        self, *, deployment_profile_digest: str, expected_identities_digest: str
    ) -> RuntimeProvisioningAttestation: ...


def _attestation_binding_payload(
    *,
    runtime_provider_implementation_id: str,
    runtime_provider_implementation_digest: str,
    deployment_profile_digest: str,
    expected_identities_digest: str,
    release_source_sha: str,
    source_tree_sha: str,
    deployment_activation_dossier_hash: str,
    worker_identity_registration_id: str,
    toolchain_layout_identity: str,
    provisioned: bool,
) -> str:
    return "|".join(
        [
            RUNTIME_ATTESTATION_CONTRACT_VERSION,
            runtime_provider_implementation_id,
            runtime_provider_implementation_digest,
            deployment_profile_digest,
            expected_identities_digest,
            release_source_sha,
            source_tree_sha,
            deployment_activation_dossier_hash,
            worker_identity_registration_id,
            toolchain_layout_identity,
            "provisioned" if provisioned else "unprovisioned",
        ]
    )


def issue_runtime_attestation(
    *,
    runtime_provider_implementation_id: str,
    deployment_profile_digest: str,
    expected_identities_digest: str,
    release_source_sha: str,
    source_tree_sha: str,
    deployment_activation_dossier_hash: str,
    worker_identity_registration_id: str,
    toolchain_layout_identity: str,
    provisioned: bool,
) -> RuntimeProvisioningAttestation:
    """Construct a fully-bound attestation with a correct self-hash. The reviewed runtime provider
    (or
    the unprovisioned default) is the only caller; a fabricated attestation that names a
    non-reviewed provider is refused by :func:`validate_runtime_attestation` regardless."""
    provider_digest = runtime_provider_implementation_digest(runtime_provider_implementation_id)
    payload = _attestation_binding_payload(
        runtime_provider_implementation_id=runtime_provider_implementation_id,
        runtime_provider_implementation_digest=provider_digest,
        deployment_profile_digest=deployment_profile_digest,
        expected_identities_digest=expected_identities_digest,
        release_source_sha=release_source_sha,
        source_tree_sha=source_tree_sha,
        deployment_activation_dossier_hash=deployment_activation_dossier_hash,
        worker_identity_registration_id=worker_identity_registration_id,
        toolchain_layout_identity=toolchain_layout_identity,
        provisioned=provisioned,
    )
    return RuntimeProvisioningAttestation(
        attestation_contract_version=RUNTIME_ATTESTATION_CONTRACT_VERSION,
        runtime_provider_implementation_id=runtime_provider_implementation_id,
        runtime_provider_implementation_digest=provider_digest,
        deployment_profile_digest=deployment_profile_digest,
        expected_identities_digest=expected_identities_digest,
        release_source_sha=release_source_sha,
        source_tree_sha=source_tree_sha,
        deployment_activation_dossier_hash=deployment_activation_dossier_hash,
        worker_identity_registration_id=worker_identity_registration_id,
        toolchain_layout_identity=toolchain_layout_identity,
        provisioned=provisioned,
        attestation_hash=_sha256(payload),
    )


def deployment_profile_digest(profile: DeploymentProfile) -> str:
    """Canonical ``sha256:`` digest over the WHOLE deployment profile (its validated fields), used
    to
    bind an attestation to the exact deployment. Refuses a foreign/duck-typed profile by exact
    type."""
    from secp_operator_deployment.profile import DeploymentProfile as _Profile

    if type(profile) is not _Profile:
        raise DeploymentPackageError("profile_type_invalid")
    data = profile.model_dump()
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return _sha256(payload)


def expected_identities_digest(expected: ExpectedDeploymentIdentities) -> str:
    """Canonical ``sha256:`` digest over the WHOLE independent expected-identities pins, used to
    bind
    an attestation to the exact trusted pins. Refuses a foreign/duck-typed object by exact type."""
    from secp_operator_deployment.identities import ExpectedDeploymentIdentities as _Expected

    if type(expected) is not _Expected:
        raise DeploymentPackageError("expected_identities_type_invalid")
    data = dataclasses.asdict(expected)
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return _sha256(payload)


def unprovisioned_attestation(
    *, deployment_profile_digest: str, expected_identities_digest: str
) -> RuntimeProvisioningAttestation:
    """A bound but UNPROVISIONED attestation for the shipped/sealed state: it names the non-reviewed
    unprovisioned provider and ``provisioned=False``, so it can never contribute to readiness."""
    return issue_runtime_attestation(
        runtime_provider_implementation_id=UNPROVISIONED_RUNTIME_PROVIDER_ID,
        deployment_profile_digest=deployment_profile_digest,
        expected_identities_digest=expected_identities_digest,
        release_source_sha="",
        source_tree_sha="",
        deployment_activation_dossier_hash="",
        worker_identity_registration_id="",
        toolchain_layout_identity="",
        provisioned=False,
    )


def attest_runtime(
    runtime: ControlledLiveRuntime,
    *,
    profile: DeploymentProfile,
    expected: ExpectedDeploymentIdentities,
) -> RuntimeProvisioningAttestation:
    """Produce a bound attestation for the deployment. This is the CALLER's issuance step: it
    computes
    the profile/expected canonical digests and asks the runtime to ISSUE its attestation
    (``provisioning_attestation``); a sealed/unprovisioned runtime yields an UNPROVISIONED bound
    attestation. It never calls ``plan_execution_seams()`` / a resolver / a factory. Verification
    consumes the returned pure value and calls no runtime method itself."""
    pd = deployment_profile_digest(profile)
    ed = expected_identities_digest(expected)
    try:
        return runtime.provisioning_attestation(
            deployment_profile_digest=pd, expected_identities_digest=ed
        )
    except DeploymentPackageError:
        return unprovisioned_attestation(
            deployment_profile_digest=pd, expected_identities_digest=ed
        )


def validate_runtime_attestation(
    attestation: object,
    *,
    profile: DeploymentProfile,
    expected: ExpectedDeploymentIdentities,
) -> tuple[bool, str | None]:
    """Return ``(provisioned_ready, reason_code)`` for a runtime attestation WITHOUT calling any
    runtime method. Fail closed unless: exact type; contract version matches; the profile and
    expected-identities canonical digests bind to THIS deployment; the provider digest is
    internally consistent; the self-hash recomputes; ``provisioned`` is true; AND the
    runtime-provider identity is in the code-owned reviewed set (empty in PR5D → always refuses)."""
    from secp_operator_deployment.identities import ExpectedDeploymentIdentities as _Expected
    from secp_operator_deployment.profile import DeploymentProfile as _Profile

    if type(attestation) is not RuntimeProvisioningAttestation:
        return False, "attestation_type_invalid"
    if type(profile) is not _Profile or type(expected) is not _Expected:
        return False, "attestation_inputs_invalid"
    a = attestation
    if a.attestation_contract_version != RUNTIME_ATTESTATION_CONTRACT_VERSION:
        return False, "attestation_contract_version_invalid"
    if a.deployment_profile_digest != deployment_profile_digest(profile):
        return False, "attestation_profile_binding_invalid"
    if a.expected_identities_digest != expected_identities_digest(expected):
        return False, "attestation_expected_binding_invalid"
    if a.runtime_provider_implementation_digest != runtime_provider_implementation_digest(
        a.runtime_provider_implementation_id
    ):
        return False, "attestation_provider_digest_invalid"
    recomputed = _sha256(
        _attestation_binding_payload(
            runtime_provider_implementation_id=a.runtime_provider_implementation_id,
            runtime_provider_implementation_digest=a.runtime_provider_implementation_digest,
            deployment_profile_digest=a.deployment_profile_digest,
            expected_identities_digest=a.expected_identities_digest,
            release_source_sha=a.release_source_sha,
            source_tree_sha=a.source_tree_sha,
            deployment_activation_dossier_hash=a.deployment_activation_dossier_hash,
            worker_identity_registration_id=a.worker_identity_registration_id,
            toolchain_layout_identity=a.toolchain_layout_identity,
            provisioned=a.provisioned,
        )
    )
    if recomputed != a.attestation_hash:
        return False, "attestation_hash_invalid"
    if not a.provisioned:
        return False, "attestation_not_provisioned"
    if a.runtime_provider_implementation_id not in REVIEWED_RUNTIME_PROVIDERS:
        return False, "attestation_provider_not_reviewed"
    return True, None


class SealedControlledLiveRuntime:
    """Shipped default: NO controlled-live runtime is provisioned. Every accessor fails closed, so
    the
    package refuses to build compositions until a reviewed deployment injects a real seam, and an
    attestation derived from it is UNPROVISIONED."""

    def provisioned(self) -> bool:
        return False

    def plan_execution_seams(self) -> PlanExecutionRuntimeSeams:
        raise DeploymentPackageError("controlled_live_runtime_not_provisioned")

    def provisioning_attestation(
        self, *, deployment_profile_digest: str, expected_identities_digest: str
    ) -> RuntimeProvisioningAttestation:
        raise DeploymentPackageError("controlled_live_runtime_not_provisioned")
