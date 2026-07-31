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

On top of the six dimensions this module answers the OPERATOR's question, which a single status
enum cannot: *what stands between this host and a controlled-live plan, and in what order?* The
:data:`PREREQUISITE_LADDER` enumerates every rung in the SAME priority order
:func:`_resolve_status` evaluates, so the first unmet blocking rung is exactly the one that
determines the reported status; :data:`REFUSAL_CATALOGUE` classifies every bounded reason code by
dimension and by REMEDIATION CLASS, separating a gap an operator can close on the host from one
that only a separately reviewed code change could — this module performs neither, and reporting
that a gap is not operator-closable is precisely what stops an operator hunting for a flag that
does not exist. :func:`build_provenance_report` answers the remaining question — which
implementation aggregate is installed here — so it can be compared against a signed release.

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

from dataclasses import dataclass
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

# Provenance-report status classes → stable exit codes (the read-only provenance command).
PROVENANCE_EXIT_CODES = {
    "provenance_ok": 0,  # the installed package recomputed to its reviewed aggregate
    "provenance_untrusted": 15,  # the trusted directory-fd verification refused
    "provenance_unavailable": 20,  # the aggregate could not be computed at all
}

_COMPOSITION_TYPES = {
    "plan_execution": "secp_worker.plan_gen.composition.PlanExecutionComposition",
    "readiness": "secp_worker.readiness.composition.ReadinessComposition",
    "eligibility": "secp_worker.onboarding.eligibility_preflight.EligibilityPreflightComposition",
}

# =================================================================================================
# REMEDIATION CLASSES — what it would TAKE to satisfy a gap.
#
# These are CLASSES, never instructions and never an action this package performs. In particular
# ``REMEDIATION_REVIEWED_CODE`` marks a gap that only a separately reviewed change to a reviewed
# code constant can close (the operator-activation seal, the plan-execution gate, the reviewed
# runtime-provider set) — this module neither performs nor recommends such a change; it reports
# that the gap is not operator-closable so an operator stops rather than searching for a flag.
# =================================================================================================
REMEDIATION_REVIEWED_CODE = "reviewed_code_change"
REMEDIATION_REVIEWED_DEPLOYMENT = "reviewed_deployment_material"
REMEDIATION_OPERATOR = "operator_host_action"

REMEDIATION_CLASSES = frozenset(
    {REMEDIATION_REVIEWED_CODE, REMEDIATION_REVIEWED_DEPLOYMENT, REMEDIATION_OPERATOR}
)

# The six reported dimensions (see the module docstring).
DIMENSIONS = frozenset({"A", "B", "C", "D", "E", "F"})


@dataclass(frozen=True)
class Prerequisite:
    """One rung of the operator prerequisite ladder.

    Pure metadata: an identity, the dimension it belongs to, whether it blocks the prepared
    result, its remediation class, and — for a blocking rung — the EXACT status
    :func:`_resolve_status` returns when it is the first unmet rung. It carries no host value,
    no path, and no profile value.
    """

    id: str
    dimension: str
    blocking: bool
    remediation: str
    status_when_unmet: str | None


# The ladder, in the SAME priority order ``_resolve_status`` evaluates. The first unmet BLOCKING
# rung is therefore the one that determines the reported status — an invariant the tests assert
# against ``_resolve_status`` directly, so the two can never silently diverge.
PREREQUISITE_LADDER: tuple[Prerequisite, ...] = (
    Prerequisite("seals_correct", "F", True, REMEDIATION_REVIEWED_CODE, "seals_unsafe"),
    Prerequisite(
        "profile_installed", "B", True, REMEDIATION_REVIEWED_DEPLOYMENT, "sealed_but_unprovisioned"
    ),
    Prerequisite(
        "profile_schema_valid", "B", True, REMEDIATION_REVIEWED_DEPLOYMENT, "profile_invalid"
    ),
    Prerequisite(
        "expected_identities_installed",
        "B",
        True,
        REMEDIATION_REVIEWED_DEPLOYMENT,
        "sealed_but_unprovisioned",
    ),
    Prerequisite(
        "identity_agreement", "B", True, REMEDIATION_REVIEWED_DEPLOYMENT, "identity_mismatch"
    ),
    Prerequisite("installed_package_trusted", "A", True, REMEDIATION_OPERATOR, "install_untrusted"),
    Prerequisite("host_observed", "C", True, REMEDIATION_OPERATOR, "sealed_but_unprovisioned"),
    Prerequisite("host_observation_coherent", "C", True, REMEDIATION_OPERATOR, "host_unavailable"),
    Prerequisite(
        "operator_prepared_and_disabled", "C", True, REMEDIATION_OPERATOR, "host_not_ready"
    ),
    Prerequisite("ordinary_worker_running", "C", True, REMEDIATION_OPERATOR, "host_not_ready"),
    # D and E are reported but NEVER gate the prepared result (see the module docstring).
    Prerequisite("runtime_provisioned", "D", False, REMEDIATION_REVIEWED_DEPLOYMENT, None),
    Prerequisite("compositions_verified", "E", False, REMEDIATION_REVIEWED_DEPLOYMENT, None),
)

# =================================================================================================
# THE REFUSAL CATALOGUE — every bounded reason code an operator can meet, classified.
#
# Each entry maps a BOUNDED reason code to the dimension it belongs to and what would close it.
#
# A scan in ``test_operator_refusal_catalogue.py`` fails when a code appears in one of five
# recognised syntactic shapes without being catalogued. State its reach accurately, because
# over-trusting it is how a code reaches an operator unexplained: it MATCHES ONLY THOSE SHAPES —
# measured at 27 of the 84 codes here. A bare positional literal passed to ``rung()``, a code
# reached through a variable, and a conditional dict-literal value are NOT seen, and 22 codes in
# this module sit in exactly those shapes. The scan is a partial net, not a guarantee; the
# behavioural guard (an all-unmet ladder whose every reason code must classify) and the visible
# ``reason_catalogued: False`` at the point of use are what cover the rest. That test's docstring
# carries the full measured breakdown, re-measured on every run.
# =================================================================================================
_C = REMEDIATION_REVIEWED_CODE
_D = REMEDIATION_REVIEWED_DEPLOYMENT
_O = REMEDIATION_OPERATOR

REFUSAL_CATALOGUE: dict[str, dict[str, str]] = {
    # --- (F) seals ------------------------------------------------------------------------------
    "seal_drift_detected": {"dimension": "F", "remediation": _C},
    # The operator-activation seal: the bounded code the run hook refuses with, and the codes the
    # queue check reports when a reviewed submission stop is open or cannot be read at all. None is
    # operator-closable — there is no flag that opens or repairs a reviewed constant.
    "operator_activation_sealed": {"dimension": "F", "remediation": _C},
    "submission_stop_open": {"dimension": "F", "remediation": _C},
    "submission_stop_unobservable": {"dimension": "F", "remediation": _C},
    # --- (A) installed-package trust (the trusted directory-fd walk) -----------------------------
    "install_untrusted": {"dimension": "A", "remediation": _O},
    "install_trust_not_evaluated": {"dimension": "A", "remediation": _O},
    "manifest_unavailable": {"dimension": "A", "remediation": _O},
    "manifest_inventory_mismatch": {"dimension": "A", "remediation": _O},
    "manifest_dir_unreadable": {"dimension": "A", "remediation": _O},
    "manifest_module_unreadable": {"dimension": "A", "remediation": _O},
    "manifest_module_not_regular": {"dimension": "A", "remediation": _O},
    "manifest_module_hardlinked": {"dimension": "A", "remediation": _O},
    "manifest_module_not_root_owned": {"dimension": "A", "remediation": _O},
    "manifest_module_untrusted_mode": {"dimension": "A", "remediation": _O},
    "manifest_module_too_large": {"dimension": "A", "remediation": _O},
    "manifest_ancestor_not_directory": {"dimension": "A", "remediation": _O},
    "manifest_ancestor_not_root_owned": {"dimension": "A", "remediation": _O},
    "manifest_ancestor_world_writable": {"dimension": "A", "remediation": _O},
    "manifest_ancestor_open_failed": {"dimension": "A", "remediation": _O},
    "manifest_package_path_not_absolute": {"dimension": "A", "remediation": _O},
    "manifest_package_path_not_normalized": {"dimension": "A", "remediation": _O},
    "manifest_trust_non_posix": {"dimension": "A", "remediation": _O},
    # The hardened filesystem / command backends are POSIX + root only, and the CLI's bounded
    # top-level guard turns any refusal that escapes a per-dimension handler into one of these
    # rather than a traceback.
    "filesystem_backend_non_posix": {"dimension": "A", "remediation": _O},
    "production_filesystem_unavailable": {"dimension": "A", "remediation": _O},
    "command_backend_non_posix": {"dimension": "A", "remediation": _O},
    "unhandled_command_failure": {"dimension": "A", "remediation": _O},
    "manifest_installed_aggregate_mismatch": {"dimension": "A", "remediation": _O},
    # --- (B) profile + independent expected identities -------------------------------------------
    "profile_not_installed": {"dimension": "B", "remediation": _D},
    "profile_type_invalid": {"dimension": "B", "remediation": _D},
    "profile_schema_invalid": {"dimension": "B", "remediation": _D},
    "profile_unreadable": {"dimension": "B", "remediation": _D},
    "profile_reader_unavailable": {"dimension": "B", "remediation": _D},
    "profile_not_json": {"dimension": "B", "remediation": _D},
    "profile_not_utf8": {"dimension": "B", "remediation": _D},
    "profile_not_object": {"dimension": "B", "remediation": _D},
    "profile_duplicate_key": {"dimension": "B", "remediation": _D},
    "profile_forbidden_secret": {"dimension": "B", "remediation": _D},
    "profile_manifest_digest_mismatch": {"dimension": "B", "remediation": _D},
    "expected_identities_not_provisioned": {"dimension": "B", "remediation": _D},
    "expected_identities_type_invalid": {"dimension": "B", "remediation": _D},
    # The codes ``read_expected_identities`` ACTUALLY raises. Every one is reachable from the
    # ``provenance`` pins read, and all were uncatalogued — so the precise production codes
    # classified as unknown while the synthetic ones the tests used classified fine.
    #
    # ``expected_identities_not_installed`` names the SAME fact as
    # ``expected_identities_not_provisioned`` above; they differ only in which layer produced it —
    # the reader raises the specific one, ``build_verification`` synthesises the generic one for an
    # absent rung. Both are catalogued so an operator can look up whichever they meet.
    "expected_identities_not_installed": {"dimension": "B", "remediation": _D},
    "expected_identities_unreadable": {"dimension": "B", "remediation": _D},
    "expected_identities_reader_unavailable": {"dimension": "B", "remediation": _D},
    "expected_identities_not_json": {"dimension": "B", "remediation": _D},
    "expected_identities_not_utf8": {"dimension": "B", "remediation": _D},
    "expected_identities_not_object": {"dimension": "B", "remediation": _D},
    "expected_identities_duplicate_key": {"dimension": "B", "remediation": _D},
    "expected_identities_forbidden_secret": {"dimension": "B", "remediation": _D},
    "expected_identities_invalid": {"dimension": "B", "remediation": _D},
    "identity_mismatch": {"dimension": "B", "remediation": _D},
    "verify_context_type_invalid": {"dimension": "B", "remediation": _D},
    "queue_not_distinct": {"dimension": "B", "remediation": _D},
    "queue_separation_unavailable": {"dimension": "B", "remediation": _D},
    # --- (C) the controlled-live queue CONSUMER (queue_check) -------------------------------------
    "operator_consumer_unobservable": {"dimension": "C", "remediation": _O},
    "operator_consumer_active": {"dimension": "C", "remediation": _O},
    # --- (C) prepared host ------------------------------------------------------------------------
    "host_observation_type_invalid": {"dimension": "C", "remediation": _O},
    "host_not_observed": {"dimension": "C", "remediation": _O},
    "host_observation_incoherent": {"dimension": "C", "remediation": _O},
    "operator_not_prepared_and_disabled": {"dimension": "C", "remediation": _O},
    "ordinary_worker_not_running": {"dimension": "C", "remediation": _O},
    # --- (D) runtime provisioning attestation -----------------------------------------------------
    "attestation_type_invalid": {"dimension": "D", "remediation": _D},
    "attestation_inputs_invalid": {"dimension": "D", "remediation": _D},
    "attestation_contract_version_invalid": {"dimension": "D", "remediation": _D},
    "attestation_profile_binding_invalid": {"dimension": "D", "remediation": _D},
    "attestation_expected_binding_invalid": {"dimension": "D", "remediation": _D},
    "attestation_provider_digest_invalid": {"dimension": "D", "remediation": _D},
    "attestation_hash_invalid": {"dimension": "D", "remediation": _D},
    "attestation_not_provisioned": {"dimension": "D", "remediation": _D},
    # The reviewed runtime-provider set is a CODE constant and is empty in this milestone, so this
    # gap is deliberately NOT operator-closable.
    "attestation_provider_not_reviewed": {"dimension": "D", "remediation": _C},
    "controlled_live_runtime_not_provisioned": {"dimension": "D", "remediation": _D},
    # --- (E) controlled-live composition readiness ------------------------------------------------
    "compositions_not_supplied": {"dimension": "E", "remediation": _D},
    "compositions_object_invalid": {"dimension": "E", "remediation": _D},
    "provenance_type_invalid": {"dimension": "E", "remediation": _D},
    "provenance_contract_version_invalid": {"dimension": "E", "remediation": _D},
    "provenance_package_version_invalid": {"dimension": "E", "remediation": _D},
    "provenance_implementation_id_invalid": {"dimension": "E", "remediation": _D},
    "provenance_manifest_digest_invalid": {"dimension": "E", "remediation": _D},
    "provenance_untrusted_install": {"dimension": "E", "remediation": _O},
    "provenance_expected_binding_invalid": {"dimension": "E", "remediation": _D},
    "provenance_profile_binding_invalid": {"dimension": "E", "remediation": _D},
    "composition_type_invalid": {"dimension": "E", "remediation": _D},
    "plan_execution_composition_invalid": {"dimension": "E", "remediation": _D},
    # The shipped plan-execution gate is a reviewed code default; a disabled gate is not something
    # an operator can turn on.
    "plan_gate_disabled": {"dimension": "E", "remediation": _C},
    "composition_sealed": {"dimension": "E", "remediation": _C},
    "readiness_gate_disabled": {"dimension": "E", "remediation": _C},
    "eligibility_gate_disabled": {"dimension": "E", "remediation": _C},
    "classification_invalid": {"dimension": "E", "remediation": _D},
    "executor_factory_invalid": {"dimension": "E", "remediation": _D},
    "renderer_registration_invalid": {"dimension": "E", "remediation": _D},
    "renderer_digest_invalid": {"dimension": "E", "remediation": _D},
    "process_registration_invalid": {"dimension": "E", "remediation": _D},
    "process_digest_invalid": {"dimension": "E", "remediation": _D},
    "provider_source_invalid": {"dimension": "E", "remediation": _D},
    "provider_identity_invalid": {"dimension": "E", "remediation": _D},
    "plan_provider_identity_invalid": {"dimension": "E", "remediation": _D},
    "readiness_provider_identity_invalid": {"dimension": "E", "remediation": _D},
    "eligibility_provider_identity_invalid": {"dimension": "E", "remediation": _D},
}

# Reason codes that carry a bounded, sanitised suffix (``profile_invalid:<field>``). The prefix is
# catalogued; the suffix is the already-sanitised field name produced by the profile parser.
CATALOGUE_PREFIXES: tuple[str, ...] = ("profile_invalid:", "profile_unknown_field:")


def classify_reason_code(code: str | None) -> dict[str, str] | None:
    """Classify a bounded reason code into ``{dimension, remediation}``; ``None`` when uncatalogued.

    Pure and total: it accepts ``None``, an unknown code, and a prefixed code
    (``profile_invalid:<field>``) without raising, so a report can always be built.
    """
    if not code or not isinstance(code, str):
        return None
    entry = REFUSAL_CATALOGUE.get(code)
    if entry is not None:
        return dict(entry)
    for prefix in CATALOGUE_PREFIXES:
        if code.startswith(prefix):
            base = REFUSAL_CATALOGUE.get(prefix.rstrip(":"))
            if base is not None:
                return dict(base)
            return {"dimension": "B", "remediation": REMEDIATION_REVIEWED_DEPLOYMENT}
    return None


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


def build_prerequisite_ladder(
    *,
    seals: dict,
    profile: dict,
    identity: dict,
    installed_trust_ok: bool,
    installed_trust_reason: str | None,
    host: dict,
    runtime_provisioned: bool,
    runtime_reason: str | None,
    compositions_supplied: bool,
    compositions_verified: bool,
    compositions_reason: str | None,
) -> list[dict]:
    """Build the ORDERED operator prerequisite ladder from already-derived section facts.

    PURE: it consumes the same section dicts :func:`build_verification` has already computed and
    performs no I/O, no type resolution, and no host access. Every rung is reported honestly —
    including rungs below the first unmet one — so an operator sees the whole remaining path
    rather than one gap at a time. Each rung carries its bounded reason code, the dimension it
    belongs to, and its remediation class.
    """
    by_id = {p.id: p for p in PREREQUISITE_LADDER}

    def rung(spec_id: str, satisfied: object, reason: str | None) -> dict:
        spec = by_id[spec_id]
        ok = bool(satisfied)
        code = None if ok else (reason or "unspecified_refusal")
        row = {
            "id": spec.id,
            "dimension": spec.dimension,
            "satisfied": ok,
            "blocking": spec.blocking,
            "remediation": spec.remediation,
            "reason_code": code,
        }
        # NULL when there is no reason code at all — a SATISFIED rung. ``False`` here would read as
        # "this rung's reason is uncatalogued", a negative claim about a code that does not exist.
        # ``False`` is reserved for its one real meaning: there IS a code and it is uncatalogued.
        row["reason_catalogued"] = (
            None if code is None else (classify_reason_code(code) is not None)
        )
        return row

    attempted = bool(host.get("attempted"))
    coherent = attempted and bool(host.get("inspected")) and bool(host.get("coherent"))
    host_reason = host.get("reason_code")
    profile_reason = profile.get("reason_code")

    return [
        rung("seals_correct", seals["seals_correct"], "seal_drift_detected"),
        rung("profile_installed", profile["present"], profile_reason or "profile_not_installed"),
        rung(
            "profile_schema_valid",
            profile["schema_valid"],
            profile_reason or "profile_schema_invalid",
        ),
        rung(
            "expected_identities_installed",
            identity["expected_provided"],
            "expected_identities_not_provisioned",
        ),
        rung(
            "identity_agreement",
            identity["agrees"],
            identity.get("reason_code") or "identity_mismatch",
        ),
        rung(
            "installed_package_trusted",
            installed_trust_ok,
            installed_trust_reason or "install_untrusted",
        ),
        rung("host_observed", attempted, host_reason or "host_not_observed"),
        rung("host_observation_coherent", coherent, host_reason or "host_observation_incoherent"),
        rung(
            "operator_prepared_and_disabled",
            host.get("operator_prepared_and_disabled"),
            "operator_not_prepared_and_disabled",
        ),
        rung(
            "ordinary_worker_running",
            host.get("ordinary_running_and_healthy"),
            "ordinary_worker_not_running",
        ),
        rung(
            "runtime_provisioned",
            runtime_provisioned,
            runtime_reason or "attestation_not_provisioned",
        ),
        rung(
            "compositions_verified",
            compositions_verified,
            compositions_reason or (None if compositions_supplied else "compositions_not_supplied"),
        ),
    ]


def next_blocking_prerequisite(ladder: list[dict]) -> dict | None:
    """The first unmet BLOCKING rung — the single thing standing in the way — or ``None``."""
    for row in ladder:
        if row["blocking"] and not row["satisfied"]:
            return row
    return None


def _queue_section(profile_parsed: bool, profile: object | None) -> dict:
    """Report queue separation as BOOLEANS only.

    The queue NAMES are profile values and are deliberately never emitted (this module never
    emits a raw profile value). What an operator needs is the answer, not the value: are both
    queues configured, and are they distinct? A shared queue would let the shipped sealed worker
    pick up controlled-live work, which the profile validator already refuses at parse time.
    """
    if not profile_parsed:
        return {
            "ok": False,
            "ordinary_configured": False,
            "operator_configured": False,
            "distinct": False,
            "reason_code": "queue_separation_unavailable",
        }
    pf: Any = profile
    ordinary = bool(pf.ordinary_task_queue)
    operator = bool(pf.operator_task_queue)
    distinct = pf.ordinary_task_queue != pf.operator_task_queue
    ok = ordinary and operator and distinct
    return {
        "ok": ok,
        "ordinary_configured": ordinary,
        "operator_configured": operator,
        "distinct": distinct,
        "reason_code": None if ok else "queue_not_distinct",
    }


def _release_identity_section(expected: object | None, expected_reason: str | None) -> dict:
    """The RELEASE this deployment claims to be, taken from the INDEPENDENT trusted pins.

    Sourced from :class:`ExpectedDeploymentIdentities` — the separate root-controlled file — and
    never from the profile, so a profile cannot name its own release. A foreign object is refused
    by EXACT type without attribute access.

    These TWO values are release IDENTIFIERS, not secrets and not profile configuration: they are
    exactly what an operator has to read off the deployment and compare against the signed release.
    Emitting them is the point of the command. ``release_signature_checked`` is always ``False`` —
    this package performs no signature verification, and says so rather than letting
    ``provenance_ok`` be read as one.

    Emission is bounded STRUCTURALLY, not by convention: ``ExpectedDeploymentIdentities`` carries
    thirty fields and exactly two are read, by named attribute — never ``asdict()``, ``__dict__``
    or iteration — so adding a field to the dataclass cannot auto-leak it. The suppressed fields
    are the sensitive class: both queue names, both host executable paths, service and container
    names, uid/gids and image digests. The distinction is principled: what is emitted identifies an
    IMMUTABLE ARTEFACT that already exists; what is suppressed is the ADDRESS OF A LIVE RESOURCE —
    a queue that could be published to, an executable that could be targeted.

    ``parent_sha`` was emitted here and has been REMOVED. It could not carry its own weight: a
    signed release names its own commit and tree, not its parent, so the compare-against-the-release
    justification never reached it — and it was the only one of the three carrying commit-graph
    shape. A field that cannot be justified individually does not belong in a section whose entire
    defence is that every value in it is one an operator must compare.
    """
    from secp_operator_deployment.identities import ExpectedDeploymentIdentities

    if type(expected) is not ExpectedDeploymentIdentities:
        return {
            "available": False,
            "release_source_sha": None,
            "source_tree_sha": None,
            "authority": "independent_expected_identities",
            "release_signature_checked": False,
            "reason_code": expected_reason
            or (
                "expected_identities_type_invalid"
                if expected is not None
                else "expected_identities_not_provisioned"
            ),
        }
    return {
        "available": True,
        "release_source_sha": expected.release_source_sha,
        "source_tree_sha": expected.source_tree_sha,
        "authority": "independent_expected_identities",
        "release_signature_checked": False,
        "reason_code": None,
    }


def build_provenance_report(
    *,
    source_aggregate: str | None = None,
    source_reason: str | None = None,
    installed_aggregate: str | None = None,
    installed_trust_ok: bool = False,
    installed_trust_reason: str | None = None,
    covered_module_count: int = 0,
    expected: object | None = None,
    expected_reason: str | None = None,
) -> dict:
    """Build the deterministic read-only PROVENANCE report from already-resolved inputs.

    PURE, like :func:`build_verification`: the caller (the CLI) performs the filesystem reads and
    passes the results in. It answers the two questions the verification report cannot — *what
    implementation aggregate is actually installed here, and does it recompute cleanly under the
    trusted directory-fd walk*, and *which RELEASE do the independent trusted pins say this is* —
    so an operator can compare both against a signed release before trusting the deployment. It
    contacts nothing and mutates nothing.

    Scope, stated rather than implied. ``provenance_ok`` means the installed content recomputed to
    its reviewed aggregate. It does NOT mean a release signature was checked (this package checks
    none — see :func:`_release_identity_section`), and it does NOT mean the deployment-local
    profile agrees with the trusted pins: that is dimension B, resolved by ``verify``, and is
    deliberately not re-derived here rather than half-derived in two places.
    """
    agreement: bool | None = None
    if source_aggregate and installed_aggregate:
        agreement = source_aggregate == installed_aggregate

    if source_aggregate is None:
        status = "provenance_unavailable"
    elif not installed_trust_ok or agreement is False:
        status = "provenance_untrusted"
    else:
        status = "provenance_ok"

    return {
        "phase": "provenance",
        "status": status,
        "exit_code": PROVENANCE_EXIT_CODES[status],
        "package_artifact": {
            "package_contract_version": PACKAGE_CONTRACT_VERSION,
            "package_version": PACKAGE_VERSION,
            "package_implementation_id": PACKAGE_IMPLEMENTATION_ID,
            "covered_module_count": int(covered_module_count),
        },
        "source_aggregate": {
            "implementation_manifest_digest": source_aggregate,
            "reason_code": source_reason,
        },
        "installed_aggregate": {
            "implementation_manifest_digest": installed_aggregate,
            "trusted": bool(installed_trust_ok),
            "reason_code": installed_trust_reason,
        },
        "agreement": {
            "source_equals_installed": agreement,
            "reason_code": None
            if agreement is not False
            else "manifest_installed_aggregate_mismatch",
        },
        "release_identity": _release_identity_section(expected, expected_reason),
        "effects_of_this_provenance_check": {
            "worker_constructed": False,
            "workflow_submitted": False,
            "run_plan_generation_called": False,
            "secret_resolver_constructed": False,
            "external_contact_performed": False,
            "host_mutated": False,
        },
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
    host_commands_executed: int = 0,
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

    queue_section = _queue_section(profile_parsed, profile)

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

    ladder = build_prerequisite_ladder(
        seals=seals,
        profile=profile_section,
        identity=identity_section,
        installed_trust_ok=installed_trust_ok,
        installed_trust_reason=installed_trust_reason,
        host=host_section,
        runtime_provisioned=runtime_provisioned,
        runtime_reason=runtime_reason,
        compositions_supplied=compositions_supplied,
        compositions_verified=compositions_verified,
        compositions_reason=compositions_reason,
    )
    blocking = next_blocking_prerequisite(ladder)

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
        "queue_separation": queue_section,
        "prerequisites": {
            "ladder": ladder,
            "next_blocking": blocking["id"] if blocking else None,
            "next_blocking_reason_code": blocking["reason_code"] if blocking else None,
            "next_blocking_remediation": blocking["remediation"] if blocking else None,
            "blocking_unmet_count": sum(1 for r in ladder if r["blocking"] and not r["satisfied"]),
            "unmet_count": sum(1 for r in ladder if not r["satisfied"]),
        },
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
        # Same split, and for the same reason, as the queue report: ``verify`` resolves the SAME
        # context and therefore runs the SAME host commands, so an unconditional
        # ``external_contact_performed: False`` was wrong here too — not just in queue_check.
        "effects_of_this_verification": {
            "measured_this_invocation": {
                "host_commands_executed": int(host_commands_executed),
                "local_host_contact_performed": int(host_commands_executed) > 0,
            },
            "structural_invariants": {
                "worker_constructed": False,
                "workflow_submitted": False,
                "run_plan_generation_called": False,
                "secret_resolver_constructed": False,
            },
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
