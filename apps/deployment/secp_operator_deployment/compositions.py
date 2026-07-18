"""Typed controlled-live compositions (SECP-PR5D, blockers #4 + #9).

:func:`build_controlled_live_compositions` is the exact public hook the PR5C operator entrypoint
imports. It returns ONE immutable, provenance-bound :class:`ControlledLiveCompositions` aggregate
carrying EXACTLY the three AUTHORITATIVE composition types — never a raw dict, never a
parallel/weaker
type — constructed with the EXACT reviewed implementation digests and verified through the existing
``ControlledLive*CompositionProvider`` gates + ``verify_plan_execution_composition``. All three
controlled-live branches are independently identity-bound: the plan renderer/process/provider
digests, and — for every provider — the EXACT authoritative provider TYPE OBJECT (``type(provider)
is <ExactProviderType>``, never a forgeable ``module.qualname`` string), so a foreign
implementation copying a classification string or gate value, or spoofing
``__module__``/``__qualname__``, refuses.

It is fail-closed by construction: it refuses unless (a) a complete, secret-free, root-controlled
deployment PROFILE is present, (b) an INDEPENDENT :class:`ExpectedDeploymentIdentities` trusted-pins
object (never the profile itself) is injected and the profile AGREES with it, and (c) the
sealed-by-default controlled-live RUNTIME provisioning seam has been replaced out of band. The
shipped
package has none of these, so the shipped ``build_controlled_live_compositions()`` refuses. Building
the aggregate NEVER selects a task queue (queue resolution stays inside the registration factory,
called only by the entrypoint), constructs no ``Worker``, contacts nothing, and resolves no secret.

Heavy ``secp_worker`` imports are LAZY (inside the functions, after the fail-closed gates), so
importing this module drags in no Temporal/worker machinery and the fail-closed path is cheap.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from secp_operator_deployment import (
    PACKAGE_CONTRACT_VERSION,
    PACKAGE_IMPLEMENTATION_ID,
    PACKAGE_VERSION,
    DeploymentPackageError,
    package_implementation_digest,
)
from secp_operator_deployment.identities import (
    ExpectedDeploymentIdentities,
    assert_expected_package_identity,
    assert_reviewed_provider,
    require_profile_agreement,
)
from secp_operator_deployment.profile import DeploymentProfile, read_deployment_profile
from secp_operator_deployment.runtime_seams import (
    ControlledLiveRuntime,
    SealedControlledLiveRuntime,
)

if TYPE_CHECKING:  # string annotations only — no runtime import of secp_worker at module load
    from secp_worker.onboarding.eligibility_preflight import EligibilityPreflightComposition
    from secp_worker.plan_gen.composition import PlanExecutionComposition
    from secp_worker.readiness.composition import ReadinessComposition


@dataclass(frozen=True)
class DeploymentProvenance:
    """The reviewed package identity every controlled-live composition aggregate is bound to."""

    package_contract_version: str
    package_version: str
    package_implementation_id: str
    package_implementation_digest: str


@dataclass(frozen=True)
class ControlledLiveCompositions:
    """The ONE immutable aggregate the operator entrypoint consumes: exactly the three authoritative
    controlled-live composition types + the reviewed package provenance. Frozen; never a raw
    dict."""

    plan_execution: PlanExecutionComposition
    readiness: ReadinessComposition
    eligibility: EligibilityPreflightComposition
    provenance: DeploymentProvenance


def reviewed_composition_pins() -> dict[str, str]:
    """The CURRENT reviewed controlled-live plan renderer/process/provider identities (from
    secp_worker) — the code-owned pins the trusted-pins object is cross-checked against."""
    from secp_worker.plan_gen.composition import CONTROLLED_LIVE_PROVIDER_SOURCE
    from secp_worker.plan_gen.controlled_live import (
        CONTROLLED_LIVE_RENDERER_VERSION,
        controlled_live_renderer_implementation_digest,
    )
    from secp_worker.plan_gen.process_boundary import (
        PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        plan_only_executor_implementation_digest,
    )

    return {
        "provider_source": CONTROLLED_LIVE_PROVIDER_SOURCE,
        "renderer_registration": CONTROLLED_LIVE_RENDERER_VERSION,
        "renderer_digest": controlled_live_renderer_implementation_digest(),
        "process_registration": PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        "process_digest": plan_only_executor_implementation_digest(),
    }


def _provenance() -> DeploymentProvenance:
    return DeploymentProvenance(
        package_contract_version=PACKAGE_CONTRACT_VERSION,
        package_version=PACKAGE_VERSION,
        package_implementation_id=PACKAGE_IMPLEMENTATION_ID,
        package_implementation_digest=package_implementation_digest(),
    )


def _build_plan_execution(  # noqa: ANN202
    profile: DeploymentProfile,
    runtime: ControlledLiveRuntime,
):
    """Construct the controlled-live plan-execution composition from the reviewed digests + the
    out-of-band runtime seams, then VERIFY it (defence in depth) via the authoritative
    ``verify_plan_execution_composition`` + ``ControlledLivePlanExecutionCompositionProvider``."""
    from secp_worker.plan_gen.composition import (
        CONTROLLED_LIVE_CLASSIFICATION,
        CONTROLLED_LIVE_PROVIDER_SOURCE,
        PlanExecutionComposition,
        PlanExecutionGate,
        verify_plan_execution_composition,
    )
    from secp_worker.plan_gen.composition_provider import (
        ControlledLivePlanExecutionCompositionProvider,
    )
    from secp_worker.plan_gen.controlled_live import (
        CONTROLLED_LIVE_RENDERER_VERSION,
        controlled_live_renderer_implementation_digest,
    )
    from secp_worker.plan_gen.process_boundary import (
        PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        issue_plan_only_executor,
        plan_only_executor_implementation_digest,
    )

    seams = runtime.plan_execution_seams()  # fails closed if sealed
    composition = PlanExecutionComposition(
        gate=PlanExecutionGate(enabled=True),
        classification=CONTROLLED_LIVE_CLASSIFICATION,
        executor_factory=issue_plan_only_executor,  # bound by identity to the sealed prod issuer
        renderer_registration=CONTROLLED_LIVE_RENDERER_VERSION,
        renderer_module_digest=controlled_live_renderer_implementation_digest(),
        process_implementation_registration=PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        process_implementation_digest=plan_only_executor_implementation_digest(),
        provider_source=CONTROLLED_LIVE_PROVIDER_SOURCE,
        provider_version=seams.provider_version,
        toolchain_layout=seams.toolchain_layout,
        trusted_workspace_root=seams.trusted_workspace_root,
        provider_runtime_input_source=seams.provider_runtime_input_source,
        state_runtime_input_source=seams.state_runtime_input_source,
        provider_resolver=seams.provider_resolver,
        state_resolver=seams.state_resolver,
        provider_resolver_activation=seams.provider_resolver_activation,
        state_resolver_activation=seams.state_resolver_activation,
        process_timeout_seconds=seams.process_timeout_seconds,
        max_output_bytes=seams.max_output_bytes,
        deployment_activation_dossier_hash=seams.deployment_activation_dossier_hash,
        worker_identity_registration_id=seams.worker_identity_registration_id,
    )
    verify_plan_execution_composition(
        composition
    )  # every seam-missing / wrong-digest refusal fires
    provider = ControlledLivePlanExecutionCompositionProvider(composition)
    # Third agreement point: the EXACT authoritative TYPE OBJECT (not a forgeable module/qualname).
    assert_reviewed_provider(
        provider,
        ControlledLivePlanExecutionCompositionProvider,
        reason="plan_provider_identity_invalid",
    )
    return composition


def _build_readiness():  # noqa: ANN202
    """The controlled-live readiness composition (enabled gate), bound to its EXACT authoritative
    provider TYPE — a foreign provider copying the classification/qualname refuses. Its
    per-operation
    seams are validated at request time; the runner is sealed, so PR5D never reaches that path."""
    from secp_worker.readiness.composition import ReadinessComposition, ReadinessGate
    from secp_worker.readiness.composition_provider import (
        ControlledLiveReadinessCompositionProvider,
    )

    composition = ReadinessComposition(gate=ReadinessGate(enabled=True))
    provider = ControlledLiveReadinessCompositionProvider(composition)  # refuses sealed/test-only
    assert_reviewed_provider(
        provider,
        ControlledLiveReadinessCompositionProvider,
        reason="readiness_provider_identity_invalid",
    )
    return composition


def _build_eligibility():  # noqa: ANN202
    from secp_worker.onboarding.eligibility_preflight import (
        EligibilityPreflightComposition,
        EligibilityPreflightGate,
    )
    from secp_worker.onboarding.eligibility_provider import (
        ControlledLiveEligibilityCompositionProvider,
    )

    composition = EligibilityPreflightComposition(gate=EligibilityPreflightGate(enabled=True))
    provider = ControlledLiveEligibilityCompositionProvider(composition)  # refuses sealed default
    assert_reviewed_provider(
        provider,
        ControlledLiveEligibilityCompositionProvider,
        reason="eligibility_provider_identity_invalid",
    )
    return composition


def build_controlled_live_compositions(
    *,
    profile: DeploymentProfile | None = None,
    runtime: ControlledLiveRuntime | None = None,
    expected: ExpectedDeploymentIdentities | None = None,
) -> ControlledLiveCompositions:
    """Build the immutable, provenance-bound controlled-live composition aggregate — or FAIL CLOSED.

    The NO-ARGUMENT production hook the PR5C entrypoint calls (all three params ``None``) resolves
    the fixed root-controlled bindings through :func:`production_context.load_production_bindings`
    — the profile, the INDEPENDENT trusted pins (a SEPARATE root-controlled file, never the profile
    itself), and the installed runtime (sealed in PR5D). The shipped repo has none of these, so the
    no-argument build fails closed. Any EXPLICIT (test) argument opts out of production loading and
    keeps the strict per-input requirements below. This constructs no queue, no ``Worker``,
    contacts nothing, and resolves no secret.
    """
    if profile is None and runtime is None and expected is None:
        # Production no-argument hook: resolve the fixed root-controlled bindings (fail-closed if
        # absent). Test injection passes explicit args and never reaches this loader.
        from secp_operator_deployment.production_context import load_production_bindings

        bindings = load_production_bindings()
        profile = bindings.profile  # type: ignore[assignment]
        expected = bindings.expected  # type: ignore[assignment]
        runtime = bindings.runtime  # type: ignore[assignment]

    resolved_profile = profile if profile is not None else read_deployment_profile()
    if not isinstance(resolved_profile, DeploymentProfile):  # never accept a raw/foreign profile
        raise DeploymentPackageError("profile_type_invalid")

    if (
        expected is None
    ):  # the profile can NEVER be the sole authority for security-sensitive values
        raise DeploymentPackageError("expected_identities_not_provisioned")
    if not isinstance(expected, ExpectedDeploymentIdentities):
        raise DeploymentPackageError("expected_identities_type_invalid")
    assert_expected_package_identity(
        expected
    )  # cross-check injected pins vs the code (independent)
    # Independently verify the profile's claimed package manifest digest equals the ACTUAL manifest
    # (so a profile cannot self-attest a stale/foreign package), then require full profile
    # agreement.
    if resolved_profile.package_implementation_digest != package_implementation_digest():
        raise DeploymentPackageError("profile_manifest_digest_mismatch")
    require_profile_agreement(resolved_profile, expected)

    resolved_runtime: ControlledLiveRuntime = (
        runtime if runtime is not None else SealedControlledLiveRuntime()
    )
    if not resolved_runtime.provisioned():
        raise DeploymentPackageError("controlled_live_runtime_not_provisioned")

    plan_execution = _build_plan_execution(resolved_profile, resolved_runtime)
    readiness = _build_readiness()
    eligibility = _build_eligibility()

    # Final type assertions — the aggregate holds EXACTLY the authoritative types, never a raw
    # dict.
    from secp_worker.onboarding.eligibility_preflight import EligibilityPreflightComposition
    from secp_worker.plan_gen.composition import PlanExecutionComposition
    from secp_worker.readiness.composition import ReadinessComposition

    if type(plan_execution) is not PlanExecutionComposition:
        raise DeploymentPackageError("plan_execution_composition_type_invalid")
    if type(readiness) is not ReadinessComposition:
        raise DeploymentPackageError("readiness_composition_type_invalid")
    if type(eligibility) is not EligibilityPreflightComposition:
        raise DeploymentPackageError("eligibility_composition_type_invalid")

    return ControlledLiveCompositions(
        plan_execution=plan_execution,
        readiness=readiness,
        eligibility=eligibility,
        provenance=_provenance(),
    )
