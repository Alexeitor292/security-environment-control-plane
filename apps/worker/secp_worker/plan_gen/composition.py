"""The plan-execution composition (B1B-PR5B, ADR-022 §5, ADR-030) — worker-only.

This module describes **what trusted machinery is installed on this worker**. It does not, and
after ADR-030 cannot, describe what may execute.

The shipped composition is structurally incomplete: no classification, no toolchain filesystem
layout, no trusted workspace root, no controlled-live renderer/process registration, no
runtime-input source, no plan-execution resolver and no resolver activation. The durable plan-only
orchestration therefore refuses **before any filesystem access, secret contact, state-backend
contact, rendering, executor construction, or process execution** — and the refusal names the first
missing seam.

WHY THERE IS NO LONGER A GATE
------------------------------
``PlanExecutionGate`` — a single ``enabled: bool`` on this composition — was retired. ADR-030 §2
forbids any constructor or configuration field whose value widens what may execute, and this was
one: it made a fully-configured worker an authorized worker. Both halves of that are wrong. A
worker with the reviewed toolchain installed has not thereby been authorized to touch a cluster,
and an authorized operation does not become executable on a worker whose machinery is unverified.

Nothing replaces it, because the thing it was standing in for already exists. Permission belongs to
:class:`~secp_worker.plan_gen.capability.PlanOnlyCapability`, which is bound to the exact operation,
worker, target, fresh toolchain attestation, provider pin, credential binding, execution lease and
implementation digests, carries an expiry, cannot be constructed by a caller and raises on any
attempt to serialize or pickle it — so it cannot be forged, and cannot be smuggled in through a
Temporal history or an API field.

    complete composition + no capability   -> no execution
    valid capability + wrong composition   -> no execution
    complete composition + valid capability -> plan-only execution

The two are checked independently and neither substitutes for the other. Plan generation keeps its
own authority domain: it happens *before* a reviewed apply change-set exists, so it is never routed
through the apply-side ``AuthorizedExecution``.

A separately reviewed deployment-local composition must still supply the explicit
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
class PlanExecutionComposition:
    """The trusted machinery installed on THIS worker. It is capability-neutral.

    ADR-030 retired ``PlanExecutionGate`` from this record, and the deletion is the point rather
    than a tidy-up. This type answers ONE question — *what reviewed machinery is installed on this
    worker?* — and a boolean field on it was answering a different one: *may this operation
    execute?* A composition carrying its own permission means a fully-configured worker is an
    authorized worker, which is precisely the ambient authorization §2 forbids.

    So a complete composition is now necessary and **not sufficient**. Permission for a specific
    operation comes from :class:`~secp_worker.plan_gen.capability.PlanOnlyCapability`, which is
    bound to the exact operation, worker, target, toolchain attestation, credential binding,
    execution lease and implementation digests, carries an expiry, cannot be constructed by a
    caller and cannot be serialized — so it can neither be forged nor smuggled through Temporal or
    an API field. The two are checked independently and neither substitutes for the other.
    """

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


def unconfigured_plan_execution_composition() -> PlanExecutionComposition:
    """The shipped composition: NO classification, layout, root, registration, resolver or limit.

    Renamed from ``sealed_plan_execution_composition``. The old name asserted a property that is no
    longer how this refuses and, more importantly, was never how it *should* have refused: "sealed"
    described a boolean being off, and a boolean that can be off can be turned on. What makes this
    value unusable is that it names none of the machinery required to run anything — a state no
    configuration change can flip, because there is nothing to flip.
    """
    return PlanExecutionComposition()


def build_plan_execution_composition(settings=None) -> PlanExecutionComposition:  # noqa: ANN001
    """Deployment-local composition factory used by the durable orchestration.

    SHIPPED DEFAULT: structurally incomplete, and therefore unusable. The orchestration refuses
    before any filesystem access, secret-manager contact, rendering, executor construction or
    process execution — naming the first missing seam rather than reporting one opaque flag.

    A separately reviewed deployment injects the real composition HERE, out of band. Note what that
    injection buys and what it does not: a complete composition describes trusted machinery, and
    machinery is not permission. Executing a specific operation still requires a valid
    ``PlanOnlyCapability`` issued against durable rows for that exact operation.
    """
    return unconfigured_plan_execution_composition()


def verify_plan_execution_composition(  # noqa: C901, PLR0912 - one explicit refusal per binding
    composition: PlanExecutionComposition,
) -> None:
    """Refuse (bounded reason) unless ``composition`` is a fully-bound reviewed composition.

    Every seam must be present and each registration must equal its EXACT reviewed implementation
    digest (a self-declared registration is never sufficient).

    WHAT THIS FUNCTION NO LONGER DOES. It used to begin ``if not composition.gate.enabled: raise
    composition_sealed`` — one boolean standing in front of every structural check. ADR-030 retired
    it, and no boolean replaces it: this function now answers only *is the installed machinery the
    reviewed machinery*, and says nothing about whether anything may execute.

    The shipped default still refuses, and refuses FIRST, because it is structurally incomplete — it
    carries no classification, no layout, no trusted root and no registrations. That refusal names
    the missing seam an operator must supply, which the old ``composition_sealed`` could not: a
    single ambient flag reports the same thing whether one field is missing or fourteen are.

    Passing here is NOT permission to execute. The caller must additionally hold a valid
    ``PlanOnlyCapability`` for the exact operation.
    """
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
