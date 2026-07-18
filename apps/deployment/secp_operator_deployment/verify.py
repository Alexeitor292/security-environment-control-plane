"""Read-only package verification (SECP-PR5D Round 4) — truthful, sectioned, deterministic, PURE.

Distinct FACTS are reported in distinct sections and are NEVER conflated across six dimensions:
(A) package installation TRUST (the trusted directory-fd walk over the installed modules); (B) the
profile ↔ independent-expected-identities agreement; (C) the prepared HOST state (a coherent,
generation-checked observation); (D) runtime PROVISIONING (a bound attestation); (E) controlled-live
COMPOSITION readiness (semantic + provenance validation of an already-built aggregate); and (F) the
operator-activation SEAL. The PR5D prepared-deployment SUCCESS (``sealed_prepared``) requires
A/B/C/F but NOT D/E — the controlled-live runtime and composition may remain truthfully
unprovisioned until the separate activation milestone; D and E are reported separately and never
gate the prepared result.

Structurally PURE + exact-typed: verification does NO I/O and consumes ALREADY-RESOLVED, EXACT-typed
inputs (a :class:`DeploymentProfile`, an :class:`ExpectedDeploymentIdentities`, a
:class:`HostObservationEvidence`, a :class:`RuntimeProvisioningAttestation`, a
:class:`ControlledLiveCompositions` + its :class:`DeploymentProvenance`, and a precomputed
installed-trust result). A foreign / subclassed / duck-typed input is refused WITHOUT accessing an
arbitrary attribute or calling a method. Verification builds no aggregate, calls no runtime method
(``provisioned()`` / ``plan_execution_seams()``), constructs no secret resolver, invokes no resolver
method, constructs no ``Worker``, calls ``run_plan_generation`` never, and contacts no Temporal /
PostgreSQL / Proxmox / OpenBao / remote state / registry. It never emits a raw profile value.
"""

from __future__ import annotations

from typing import Any

from secp_operator_deployment import (
    PACKAGE_CONTRACT_VERSION,
    PACKAGE_IMPLEMENTATION_ID,
    PACKAGE_VERSION,
    package_implementation_digest,
)

# Honest status classes → stable exit codes.
STATUS_EXIT_CODES = {
    "sealed_prepared": 0,  # the PR5D prepared-deployment success (A/B/C/F satisfied; D/E separate)
    "sealed_but_unprovisioned": 10,  # seals ok but profile/expected bindings absent
    "profile_invalid": 11,
    "identity_mismatch": 12,
    "host_unavailable": 13,
    "host_not_ready": 14,
    "install_untrusted": 15,  # the installed package failed the trusted directory-fd verification
    "seals_unsafe": 20,
}

_COMPOSITION_TYPES = {
    "plan_execution": "secp_worker.plan_gen.composition.PlanExecutionComposition",
    "readiness": "secp_worker.readiness.composition.ReadinessComposition",
    "eligibility": "secp_worker.onboarding.eligibility_preflight.EligibilityPreflightComposition",
}


def _read_seals() -> dict:
    from secp_worker.plan_gen import process_boundary as pb
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    from secp_operator_deployment.runner import _OPERATOR_ACTIVATION_SEALED

    activation_sealed = bool(_OPERATOR_ACTIVATION_SEALED)
    plan_only = bool(pb._PLAN_ONLY_PROCESS_SEALED)
    b1a_act = bool(act._B1A_SUBPROCESS_SEALED)
    b1a_exe = bool(pe._B1A_SUBPROCESS_SEALED)
    correct = activation_sealed and plan_only is False and b1a_act is True and b1a_exe is True
    return {
        "operator_activation_sealed": activation_sealed,
        "plan_only_process_sealed": plan_only,
        "b1a_subprocess_sealed_activation": b1a_act,
        "b1a_subprocess_sealed_executor": b1a_exe,
        "apply_destroy_available": False,
        "seals_correct": correct,
    }


def _manifest_section() -> dict:
    try:
        return {
            "implementation_manifest_digest": package_implementation_digest(),
            "manifest_ok": True,
        }
    except Exception as exc:
        return {
            "implementation_manifest_digest": None,
            "manifest_ok": False,
            "reason_code": getattr(exc, "reason_code", "manifest_unavailable"),
        }


def build_verification(
    *,
    profile: object | None = None,
    profile_load_reason: str | None = None,
    expected: object | None = None,
    installed_trust_ok: bool = False,
    installed_trust_reason: str | None = None,
    attestation: object | None = None,
    compositions: object | None = None,
    host_observation: object | None = None,
) -> dict:
    """Build the deterministic, sectioned verification report + resolve the honest status. PURE +
    exact-typed: every input is a pre-resolved exact type (or ``None``); a foreign object is refused
    without attribute access. See the module docstring for the six reported dimensions and the
    ``sealed_prepared`` prepared-deployment success contract."""
    from secp_operator_deployment.identities import ExpectedDeploymentIdentities
    from secp_operator_deployment.profile import DeploymentProfile

    seals = _read_seals()
    manifest = _manifest_section()

    # --- (B) profile presence + schema validity (EXACT type; a foreign object never getattr'd) ---
    if profile is not None and type(profile) is not DeploymentProfile:
        profile = None
        profile_load_reason = "profile_type_invalid"
    profile_parsed = profile is not None  # exact DeploymentProfile guaranteed
    present_but_invalid = not profile_parsed and _is_present_but_invalid(profile_load_reason)
    profile_present = profile_parsed or present_but_invalid
    profile_section = {
        "present": profile_present,
        "schema_valid": profile_parsed,
        "reason_code": None if profile_parsed else (profile_load_reason or "profile_not_installed"),
    }

    # --- (B) identity agreement (independent trusted pins; the profile is never the sole
    # authority) ---
    expected_provided = type(expected) is ExpectedDeploymentIdentities
    identity_agrees = False
    identity_reason: str | None = None
    if profile_parsed and expected_provided:
        try:
            from secp_operator_deployment.identities import (
                assert_expected_package_identity,
                require_profile_agreement,
            )

            assert_expected_package_identity(expected)  # type: ignore[arg-type]
            require_profile_agreement(profile, expected)  # type: ignore[arg-type]
            identity_agrees = True
        except Exception as exc:
            identity_reason = getattr(exc, "reason_code", "identity_mismatch")
    identity_section = {
        "expected_provided": expected_provided,
        "agrees": identity_agrees,
        "reason_code": identity_reason,
    }

    queue_separation_ok = bool(
        profile_parsed and profile.ordinary_task_queue != profile.operator_task_queue  # type: ignore[union-attr]
    )

    # --- (D) runtime provisioning: validate the BOUND attestation; NEVER call a runtime method ---
    from secp_operator_deployment.runtime_seams import (
        RuntimeProvisioningAttestation,
        validate_runtime_attestation,
    )

    attestation_provided = type(attestation) is RuntimeProvisioningAttestation
    runtime_provisioned = False
    runtime_reason: str | None = None
    if attestation_provided and profile_parsed and expected_provided:
        runtime_provisioned, runtime_reason = validate_runtime_attestation(
            attestation,
            profile=profile,  # type: ignore[arg-type]
            expected=expected,  # type: ignore[arg-type]
        )

    # --- (E) composition readiness: SEMANTIC + provenance validation of an already-built aggregate
    # ---
    compositions_supplied = compositions is not None
    compositions_verified, compositions_reason, provenance = _verify_composition_aggregate(
        compositions,
        profile=profile,
        expected=expected,
        installed_trust_ok=installed_trust_ok,
    )

    # --- (C) host observation (EXACT HostObservationEvidence; a foreign object never getattr'd)
    # ---
    host_section = _host_section(host_observation)

    status = _resolve_status(
        seals=seals,
        installed_trust_ok=installed_trust_ok,
        profile_present=profile_present,
        profile_schema_valid=profile_parsed,
        expected_provided=expected_provided,
        identity_agrees=identity_agrees,
        host=host_section,
    )

    return {
        "phase": "verify",
        "status": status,
        "exit_code": STATUS_EXIT_CODES[status],
        "code_seals": seals,
        "package_artifact": {
            "package_contract_version": PACKAGE_CONTRACT_VERSION,
            "package_version": PACKAGE_VERSION,
            **manifest,
        },
        "package_trust": {
            "installed_trust_ok": bool(installed_trust_ok),
            "reason_code": installed_trust_reason,
        },
        "profile": profile_section,
        "identity_agreement": identity_section,
        "queue_separation": {"ok": queue_separation_ok},
        "runtime_provisioning": {
            "attested": attestation_provided,
            "provisioned": runtime_provisioned,
            "reason_code": runtime_reason,
        },
        "compositions": {
            "supplied": compositions_supplied,
            "verified": compositions_verified,
            "authoritative_types": dict(sorted(_COMPOSITION_TYPES.items())),
            "reason_code": compositions_reason,
        },
        "composition_provenance": provenance,
        "host_observation": host_section,
        "deployment_readiness": {
            "prepared": status == "sealed_prepared",
            "runtime_provisioned": runtime_provisioned,
            "compositions_verified": compositions_verified,
        },
        "effects_of_this_verification": {
            "worker_constructed": False,
            "workflow_submitted": False,
            "run_plan_generation_called": False,
            "secret_resolver_constructed": False,
            "external_contact_performed": False,
        },
    }


def _host_section(host_observation: object | None) -> dict:
    from secp_operator_deployment.host_adapters import HostObservationEvidence

    if host_observation is None:
        return {"attempted": False, "inspected": False, "coherent": False}
    if type(host_observation) is not HostObservationEvidence:
        return {
            "attempted": True,
            "inspected": False,
            "coherent": False,
            "reason_code": "host_observation_type_invalid",
        }
    ev = host_observation
    prepared = (
        ev.inspected
        and ev.coherent
        and ev.operator_present
        and not ev.operator_enabled
        and not ev.operator_running
    )
    return {
        "attempted": True,
        "inspected": ev.inspected,
        "coherent": ev.coherent,
        "operator_present": ev.operator_present,
        "operator_enabled": ev.operator_enabled,
        "operator_running": ev.operator_running,
        "operator_prepared_and_disabled": prepared,
        "ordinary_running_and_healthy": ev.ordinary_running,
    }


def _is_present_but_invalid(reason: str | None) -> bool:
    """True when the reason indicates the profile FILE physically exists but failed to parse/check
    (distinct from a cleanly absent or unreadable file)."""
    if not reason:
        return False
    if reason.startswith(("profile_invalid", "profile_unknown_field")):
        return True
    return reason in {
        "profile_duplicate_key",
        "profile_forbidden_secret",
        "profile_not_json",
        "profile_not_utf8",
        "profile_type_invalid",
    }


def _resolve_status(
    *,
    seals: dict,
    installed_trust_ok: bool,
    profile_present: bool,
    profile_schema_valid: bool,
    expected_provided: bool,
    identity_agrees: bool,
    host: dict,
) -> str:
    if not seals["seals_correct"]:
        return "seals_unsafe"
    if not profile_present:
        return "sealed_but_unprovisioned"
    if not profile_schema_valid:
        return "profile_invalid"  # a present-but-corrupt/out-of-contract profile is distinct
    if not expected_provided:
        return "sealed_but_unprovisioned"
    if not identity_agrees:
        return "identity_mismatch"
    if not installed_trust_ok:
        return "install_untrusted"  # the trusted directory-fd verification failed
    if not host["attempted"]:
        return "sealed_but_unprovisioned"
    if not (host["inspected"] and host.get("coherent", False)):
        return "host_unavailable"
    if not (host["operator_prepared_and_disabled"] and host["ordinary_running_and_healthy"]):
        return "host_not_ready"
    # A/B/C/F satisfied. Runtime provisioning (D) + composition readiness (E) are reported
    # separately and do NOT gate the PR5D prepared-deployment success.
    return "sealed_prepared"


def _aggregate_types_ok(result: object) -> bool:
    from secp_worker.onboarding.eligibility_preflight import EligibilityPreflightComposition
    from secp_worker.plan_gen.composition import PlanExecutionComposition
    from secp_worker.readiness.composition import ReadinessComposition

    return (
        type(getattr(result, "plan_execution", None)) is PlanExecutionComposition
        and type(getattr(result, "readiness", None)) is ReadinessComposition
        and type(getattr(result, "eligibility", None)) is EligibilityPreflightComposition
    )


def _verify_composition_aggregate(
    compositions: object | None,
    *,
    profile: object | None,
    expected: object | None,
    installed_trust_ok: bool,
) -> tuple[bool, str | None, dict | None]:
    """SEMANTICALLY verify an already-built controlled-live aggregate (exact types + provenance +
    classification/factory/digests/gates + exact provider identities), binding its provenance to the
    installed-package trust result and to the profile/expected. Returns
    ``(verified, reason_code, provenance_section)``. Constructs no secret resolver, invokes no
    resolver method, calls no runtime method, and contacts nothing."""
    if compositions is None:
        return False, None, None
    from secp_operator_deployment.compositions import (
        ControlledLiveCompositions,
        DeploymentProvenance,
    )

    if type(compositions) is not ControlledLiveCompositions:
        return False, "compositions_object_invalid", None  # foreign object; never method-called
    agg: Any = compositions  # exact type validated above; attributes safe to read
    if type(agg.provenance) is not DeploymentProvenance:
        return False, "provenance_type_invalid", None
    prov = agg.provenance
    if prov.package_contract_version != PACKAGE_CONTRACT_VERSION:
        return False, "provenance_contract_version_invalid", None
    if prov.package_version != PACKAGE_VERSION:
        return False, "provenance_package_version_invalid", None
    if prov.package_implementation_id != PACKAGE_IMPLEMENTATION_ID:
        return False, "provenance_implementation_id_invalid", None
    if prov.package_implementation_digest != package_implementation_digest():
        return False, "provenance_manifest_digest_invalid", None
    # Bind the provenance to the installed-package TRUST result + the profile/expected identities.
    if not installed_trust_ok:
        return False, "provenance_untrusted_install", None
    exp: Any = expected
    pf: Any = profile
    if type(expected) is not _expected_type() or (
        exp.package_implementation_digest != prov.package_implementation_digest
    ):
        return False, "provenance_expected_binding_invalid", None
    if type(profile) is not _profile_type() or (
        pf.package_implementation_digest != prov.package_implementation_digest
    ):
        return False, "provenance_profile_binding_invalid", None
    if not _aggregate_types_ok(agg):
        return False, "composition_type_invalid", None

    reason = _verify_plan_execution_semantics(agg.plan_execution)
    if reason is not None:
        return False, reason, None
    if agg.readiness.gate.enabled is not True:
        return False, "readiness_gate_disabled", None
    if agg.eligibility.gate.enabled is not True:
        return False, "eligibility_gate_disabled", None
    reason = _verify_provider_identities(agg)
    if reason is not None:
        return False, reason, None

    provenance_section = {
        "package_contract_version": prov.package_contract_version,
        "package_version": prov.package_version,
        "package_implementation_id": prov.package_implementation_id,
        "package_implementation_digest": prov.package_implementation_digest,
    }
    return True, None, provenance_section


def _verify_plan_execution_semantics(pe: Any) -> str | None:
    from secp_worker.plan_gen.composition import (
        CONTROLLED_LIVE_CLASSIFICATION,
        CONTROLLED_LIVE_PROVIDER_SOURCE,
        verify_plan_execution_composition,
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

    try:
        verify_plan_execution_composition(pe)  # authoritative PURE validator
    except Exception as exc:
        return getattr(exc, "reason_code", "plan_execution_composition_invalid")
    if pe.gate.enabled is not True:
        return "plan_gate_disabled"
    if pe.classification != CONTROLLED_LIVE_CLASSIFICATION:
        return "classification_invalid"
    if pe.executor_factory is not issue_plan_only_executor:
        return "executor_factory_invalid"
    if pe.renderer_registration != CONTROLLED_LIVE_RENDERER_VERSION:
        return "renderer_registration_invalid"
    if pe.renderer_module_digest != controlled_live_renderer_implementation_digest():
        return "renderer_digest_invalid"
    if pe.process_implementation_registration != PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID:
        return "process_registration_invalid"
    if pe.process_implementation_digest != plan_only_executor_implementation_digest():
        return "process_digest_invalid"
    if pe.provider_source != CONTROLLED_LIVE_PROVIDER_SOURCE:
        return "provider_source_invalid"
    return None


def _verify_provider_identities(agg: Any) -> str | None:
    # Construct the authoritative provider VALIDATORS (which refuse a foreign/sealed composition)
    # and bind each to its EXACT authoritative type OBJECT. This invokes NO runtime method and
    # constructs NO secret resolver — the resolvers already live in the aggregate and are only
    # referenced.
    from secp_worker.onboarding.eligibility_provider import (
        ControlledLiveEligibilityCompositionProvider,
    )
    from secp_worker.plan_gen.composition_provider import (
        ControlledLivePlanExecutionCompositionProvider,
    )
    from secp_worker.readiness.composition_provider import (
        ControlledLiveReadinessCompositionProvider,
    )

    from secp_operator_deployment.identities import assert_reviewed_provider

    try:
        assert_reviewed_provider(
            ControlledLivePlanExecutionCompositionProvider(agg.plan_execution),
            ControlledLivePlanExecutionCompositionProvider,
            reason="plan_provider_identity_invalid",
        )
        assert_reviewed_provider(
            ControlledLiveReadinessCompositionProvider(agg.readiness),
            ControlledLiveReadinessCompositionProvider,
            reason="readiness_provider_identity_invalid",
        )
        assert_reviewed_provider(
            ControlledLiveEligibilityCompositionProvider(agg.eligibility),
            ControlledLiveEligibilityCompositionProvider,
            reason="eligibility_provider_identity_invalid",
        )
    except Exception as exc:
        return getattr(exc, "reason_code", "provider_identity_invalid")
    return None


def _profile_type() -> type:
    from secp_operator_deployment.profile import DeploymentProfile

    return DeploymentProfile


def _expected_type() -> type:
    from secp_operator_deployment.identities import ExpectedDeploymentIdentities

    return ExpectedDeploymentIdentities
