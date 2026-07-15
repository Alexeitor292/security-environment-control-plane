"""Default-sealed plan-execution composition (B1B-PR5B, ADR-022 §5) — worker-only.

The SHIPPED composition is fully **sealed**: the gate is disabled and it carries NO toolchain
filesystem layout, NO trusted workspace root, NO controlled-live renderer/process registration, NO
runtime-input source, NO plan-execution resolver, and NO resolver activation. The durable plan-only
orchestration therefore refuses at the composition gate **before any filesystem access, secret
contact, state-backend contact, rendering, executor construction, or process execution**.

**The seal is the out-of-band reviewed composition, never an environment flag.** No environment
variable, URL, backend kind, target row, ``PATH`` entry, installed binary, caller boolean, or API
field can activate it. A separately reviewed deployment-local composition must supply the explicit
``ToolchainFilesystemLayout``, the explicit POSIX trusted workspace root, the controlled-live
renderer + process registrations bound to their EXACT reviewed implementation digests, the provider
and state runtime-input sources, the SEPARATE provider and state resolver activations, the process
resource limits, the deployment activation-dossier hash, the worker identity, and an explicit
``controlled_live`` vs ``test_only`` classification.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass

from secp_worker.plan_gen.controlled_live import (
    CONTROLLED_LIVE_PROVIDER_SOURCE,
    CONTROLLED_LIVE_RENDERER_VERSION,
    controlled_live_renderer_implementation_digest,
)
from secp_worker.plan_gen.plan_secret_resolution import WorkerPlanSecretResolver
from secp_worker.plan_gen.process_boundary import (
    PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
    PlanOnlyProcessExecutor,
    issue_plan_only_executor,
    plan_only_executor_implementation_digest,
)
from secp_worker.provisioning.toolchain_verify import ToolchainFilesystemLayout

# The executor factory the orchestration uses. The shipped default is the production issuer
# (``issue_plan_only_executor``); with ``_PLAN_ONLY_PROCESS_SEALED`` now False it constructs a real
# executor for a valid controlled-live context, but the shipped composition below is DISABLED so it
# is never reached on an ordinary path. A reviewed composition injects its own factory here; the
# orchestration NEVER names the test-only path itself.
ExecutorFactory = Callable[..., PlanOnlyProcessExecutor]

CONTROLLED_LIVE_CLASSIFICATION = "controlled_live"
TEST_ONLY_CLASSIFICATION = "test_only"
_CLASSIFICATIONS = frozenset({CONTROLLED_LIVE_CLASSIFICATION, TEST_ONLY_CLASSIFICATION})


class PlanExecutionCompositionError(Exception):
    """The plan-execution composition is sealed or incompletely bound (bounded reason code)."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True)
class ProviderRuntimeInputSource:
    """The composition-bound provider HTTPS endpoint (nonsecret; validated before use)."""

    endpoint: str


@dataclass(frozen=True)
class StateRuntimeInputSource:
    """The composition-bound remote-state HTTPS address + lock/unlock endpoints + nonsecret user."""

    address: str
    lock_address: str
    unlock_address: str
    username: str


@dataclass(frozen=True)
class PlanExecutionGate:
    """Default-**disabled** activation gate. A disabled gate refuses before any external contact."""

    enabled: bool = False


@dataclass(frozen=True)
class PlanExecutionComposition:
    """The reviewed set of injected plan-execution seams. The shipped default is fully sealed."""

    gate: PlanExecutionGate = PlanExecutionGate()

    # --- fresh on-disk re-attestation (worker filesystem only, no execution) ---------------------
    toolchain_layout: ToolchainFilesystemLayout | None = None
    # --- the explicit POSIX trusted root the ephemeral workspace is created under ----------------
    trusted_workspace_root: str | None = None
    # An OPTIONAL pre-staged offline provider mirror directory for ``init -plugin-dir=``.
    provider_plugin_source: str | None = None

    # --- reviewed renderer + process implementation registrations (bound to exact digests) -------
    renderer_registration: str = ""
    renderer_module_digest: str = ""
    process_implementation_registration: str = ""
    process_implementation_digest: str = ""
    # The reviewed executor factory (shipped default = the SEALED production issuer).
    executor_factory: ExecutorFactory = issue_plan_only_executor

    # --- the exact reviewed provider pin (deployment-local; bound into the capability + result) ---
    provider_source: str = CONTROLLED_LIVE_PROVIDER_SOURCE
    provider_version: str = ""

    # --- runtime-input sources (nonsecret, validated) --------------------------------------------
    provider_runtime_input_source: ProviderRuntimeInputSource | None = None
    state_runtime_input_source: StateRuntimeInputSource | None = None

    # --- the SEPARATE provider + state plan-execution resolvers + their reviewed activations ------
    provider_resolver: WorkerPlanSecretResolver | None = None
    state_resolver: WorkerPlanSecretResolver | None = None
    provider_resolver_activation: object | None = None
    state_resolver_activation: object | None = None

    # --- process resource limits -----------------------------------------------------------------
    process_timeout_seconds: int = 0
    max_output_bytes: int = 0

    # --- deployment binding + classification -----------------------------------------------------
    deployment_activation_dossier_hash: str = ""
    worker_identity_registration_id: str = ""
    classification: str = ""

    @property
    def is_test_only(self) -> bool:
        return self.classification == TEST_ONLY_CLASSIFICATION


def sealed_plan_execution_composition() -> PlanExecutionComposition:
    """Shipped sealed composition: gate off; no layout, root, registration, resolver, or limit."""
    return PlanExecutionComposition()


def build_plan_execution_composition(settings=None) -> PlanExecutionComposition:  # noqa: ANN001
    """Deployment-local composition factory used by the durable orchestration.

    SHIPPED DEFAULT: fully **sealed**. The orchestration refuses at the composition gate before any
    filesystem access, secret-manager contact, rendering, executor construction, or process
    execution. A future, separately reviewed activation injects the real, gated composition HERE —
    behind out-of-band reviewed material — so no single configuration flag can enable it.
    """
    return sealed_plan_execution_composition()


def verify_plan_execution_composition(  # noqa: C901, PLR0912 - one explicit refusal per binding
    composition: PlanExecutionComposition,
) -> None:
    """Refuse (bounded reason) unless ``composition`` is an enabled, fully-bound reviewed
    composition.

    The shipped default (gate disabled) always raises ``composition_sealed`` — before any filesystem
    or secret contact. When enabled, every seam must be present and each registration must equal its
    EXACT reviewed implementation digest (a self-declared registration is never sufficient).
    """
    if not composition.gate.enabled:
        raise PlanExecutionCompositionError("composition_sealed")
    if composition.classification not in _CLASSIFICATIONS:
        raise PlanExecutionCompositionError("composition_classification_invalid")
    # Bind the classification to the ACTUAL executor factory (adversarial-review §1 hardening): a
    # controlled_live composition MUST use the sealed production issuer — so it can never inertly
    # produce a controlled-live durable result — and a test_only composition may NOT use it. This
    # forbids a reviewed composition from contradicting its own contract.
    if composition.classification == CONTROLLED_LIVE_CLASSIFICATION:
        if composition.executor_factory is not issue_plan_only_executor:
            raise PlanExecutionCompositionError(
                "composition_controlled_live_requires_sealed_issuer"
            )
    elif composition.executor_factory is issue_plan_only_executor:
        raise PlanExecutionCompositionError("composition_test_only_forbids_production_issuer")
    if composition.toolchain_layout is None:
        raise PlanExecutionCompositionError("composition_layout_missing")
    root = composition.trusted_workspace_root
    if not isinstance(root, str) or not root or not os.path.isabs(root) or "\\" in root:
        raise PlanExecutionCompositionError("composition_trusted_root_invalid")
    if composition.renderer_registration != CONTROLLED_LIVE_RENDERER_VERSION:
        raise PlanExecutionCompositionError("composition_renderer_registration_invalid")
    if composition.renderer_module_digest != controlled_live_renderer_implementation_digest():
        raise PlanExecutionCompositionError("composition_renderer_digest_invalid")
    if composition.process_implementation_registration != PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID:
        raise PlanExecutionCompositionError("composition_process_registration_invalid")
    if composition.process_implementation_digest != plan_only_executor_implementation_digest():
        raise PlanExecutionCompositionError("composition_process_digest_invalid")
    if (
        composition.provider_source != CONTROLLED_LIVE_PROVIDER_SOURCE
        or not composition.provider_version
    ):
        raise PlanExecutionCompositionError("composition_provider_pin_invalid")
    if composition.provider_runtime_input_source is None:
        raise PlanExecutionCompositionError("composition_provider_runtime_input_missing")
    if composition.state_runtime_input_source is None:
        raise PlanExecutionCompositionError("composition_state_runtime_input_missing")
    if composition.provider_resolver is None or composition.state_resolver is None:
        raise PlanExecutionCompositionError("composition_resolver_missing")
    if (
        composition.provider_resolver_activation is None
        or composition.state_resolver_activation is None
    ):
        raise PlanExecutionCompositionError("composition_resolver_activation_missing")
    # A CONTROLLED-LIVE composition must carry the EXACT reviewed concrete OpenBao resolver for BOTH
    # purposes, each production-bound to the concrete client over the concrete OpenBao HTTPS
    # transport.
    # A duck-typed/foreign/sealed resolver, or one over a sealed/fake transport, is refused here —
    # the
    # activation's self-declared identity is never the only anchor (§10). A ``test_only``
    # composition
    # keeps the sealed resolver and is intentionally exempt (it can never produce controlled-live
    # evidence).
    if composition.classification == CONTROLLED_LIVE_CLASSIFICATION:
        from secp_worker.plan_gen.openbao_plan_resolver import (
            assert_concrete_openbao_plan_resolver,
        )
        from secp_worker.reviewed_identity import ReviewedIdentityError

        for resolver in (composition.provider_resolver, composition.state_resolver):
            try:
                assert_concrete_openbao_plan_resolver(resolver)
            except ReviewedIdentityError as exc:
                raise PlanExecutionCompositionError(exc.reason_code) from exc
    if composition.process_timeout_seconds <= 0 or composition.max_output_bytes <= 0:
        raise PlanExecutionCompositionError("composition_limits_invalid")
    if not composition.deployment_activation_dossier_hash:
        raise PlanExecutionCompositionError("composition_dossier_binding_missing")
    if not composition.worker_identity_registration_id:
        raise PlanExecutionCompositionError("composition_worker_identity_missing")
