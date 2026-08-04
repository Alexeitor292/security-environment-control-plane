"""The closed vocabularies of the acceptance harness (stages, checks, reason codes).

Three separate closed sets, kept apart on purpose:

``HARNESS_REASONS``
    Codes the HARNESS emits about itself — infrastructure it could not build, a proof it could not
    make. A harness reason never describes product behaviour.

``PRODUCT_REASONS``
    Bounded refusal codes the PRODUCT emits that a scenario asserts on. These are quoted from the
    product, not invented here; ``apps/acceptance/tests/test_acceptance_reason_provenance.py``
    proves every one of them still appears in the product source, so a renamed product code fails
    the harness build instead of silently turning an assertion into an unreachable branch.

``CHECKS`` / ``STAGES``
    The closed identities every :class:`~secp_acceptance.evidence.CheckRecord` is drawn from. A
    check that is not on this list cannot be recorded, so the evidence document can never grow an
    unreviewed claim.

Everything here is a plain ASCII identifier. No path, endpoint, credential, container id, or host
name is ever a member of any of these sets, and the evidence loader re-checks membership.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- stages

STAGE_FLEET = "fleet"
STAGE_PACKAGES = "packages"
STAGE_CONTROLLER = "controller"
STAGE_WORKER_INSTALL = "worker_install"
STAGE_ENROLLMENT = "enrollment"
STAGE_IDENTITY = "identity"
STAGE_QUEUES = "queues"
STAGE_LIFECYCLE = "lifecycle"
STAGE_FAILURE_INJECTION = "failure_injection"

STAGES: frozenset[str] = frozenset(
    {
        STAGE_FLEET,
        STAGE_PACKAGES,
        STAGE_CONTROLLER,
        STAGE_WORKER_INSTALL,
        STAGE_ENROLLMENT,
        STAGE_IDENTITY,
        STAGE_QUEUES,
        STAGE_LIFECYCLE,
        STAGE_FAILURE_INJECTION,
    }
)

# --------------------------------------------------------------------------- check identities

#: Every check the harness may record, grouped by the stage that owns it. The mapping is the
#: authority: a check id is valid ONLY under its own stage, so a queue proof can never be filed
#: under the enrollment stage and read later as if enrollment had proven it.
CHECKS_BY_STAGE: dict[str, tuple[str, ...]] = {
    STAGE_FLEET: (
        "controller_host_systemd_running",
        "controller_host_dockerd_active",
        "worker_host_systemd_running",
        "worker_host_dockerd_active",
        "hosts_are_distinct",
        "fleet_destroyed",
    ),
    STAGE_PACKAGES: (
        "controller_packages_installed",
        "worker_packages_installed",
        "secpctl_entrypoint_present",
        "worker_package_import_closure",
    ),
    STAGE_CONTROLLER: (
        "controller_database_migrated",
        "controller_api_serving_tls",
        "controller_temporal_reachable",
        "controller_signer_broker_active",
        "controller_locator_recorded",
    ),
    STAGE_WORKER_INSTALL: (
        "worker_bootstrap_plan_is_dry_run",
        "worker_bootstrap_written",
        "worker_bootstrap_reobserved_healthy",
        "worker_status_ok",
        "worker_operator_unit_present_disabled_stopped",
        "worker_evidence_attested",
        # The ordinary health command starts with an ABSOLUTE interpreter path and is exec'd INSIDE
        # the worker container, so whether that path exists is a fact about the worker IMAGE, not
        # about this repo, and it can only be settled by looking. It once named a path the image
        # does not have, which both blocked the install and manufactured a false operator-queue
        # containment breach; the constant was corrected, and this check is what keeps the
        # correction tied to an observation rather than to agreement between two constants.
        "worker_health_command_resolves_in_the_worker_image",
    ),
    STAGE_ENROLLMENT: (
        "invitation_created",
        "invitation_is_one_shot",
        "worker_enroll_dry_run_shows_fingerprint",
        "worker_enroll_reached_healthy",
        "controller_reports_healthy",
        "enrollment_inventory_lists_enrollment",
    ),
    STAGE_IDENTITY: (
        "worker_enrollment_key_protected",
        "worker_key_fingerprint_matches_controller",
        "worker_installation_id_matches_controller",
        "worker_private_key_never_left_worker",
        "enrolled_release_equals_installed_release",
    ),
    STAGE_QUEUES: (
        "ordinary_queue_has_live_poller",
        "ordinary_queue_workflow_executed",
        "operator_queue_has_zero_pollers",
        "operator_queue_workflow_never_started",
        "worker_self_reported_queues_exclude_operator",
        "operator_unit_never_activated",
    ),
    STAGE_LIFECYCLE: (
        "restart_worker_still_healthy",
        "restart_enrollment_state_survived",
        "upgrade_classified_managed_upgrade",
        "upgrade_written_and_reobserved",
        "upgrade_operator_still_disabled",
        "rollback_plan_lists_documents",
        "rollback_removed_documents",
        "recovery_required_on_demand",
        "recovery_required_terminal",
    ),
    STAGE_FAILURE_INJECTION: (
        "wrong_role_bundle_refused",
        "tampered_artifact_refused",
        "non_linear_upgrade_refused",
        "revoked_invitation_refused",
        "drifted_config_refuses_status",
        "unenrolled_worker_health_refused",
        "enroll_without_write_confirm_is_dry_run",
    ),
}

CHECKS: frozenset[str] = frozenset(check for checks in CHECKS_BY_STAGE.values() for check in checks)

# --------------------------------------------------------------------------- outcomes

OUTCOME_OBSERVED = "observed"
OUTCOME_REFUSED = "refused"
OUTCOME_UNPROVEN = "unproven"
OUTCOME_VIOLATED = "violated"

#: ``observed`` — the harness made the positive observation the check names.
#: ``refused`` — the product refused, and the refusal IS the expected result of the check
#:   (every failure-injection check that behaves correctly ends here).
#: ``unproven`` — the harness could not make the observation. This is never a pass. It is recorded
#:   rather than skipped silently, because a check that quietly disappears reads as a check that
#:   passed.
#: ``violated`` — the harness POSITIVELY OBSERVED the condition the check exists to rule out.
#:
#: WHY ``violated`` IS NOT FOLDED INTO ``unproven``
#: -----------------------------------------------
#: ``unproven`` and ``violated`` are opposites: maximal ignorance versus maximal knowledge. Folding
#: them together makes the single most serious finding this harness can produce — a worker actually
#: polling the controlled-live operator queue, a product accepting a tampered artifact — read
#: exactly like a transport error.
#:
#: The management plane already learned this and paid for the fix. ``real_adapters
#: ._observe_queue_containment`` is three-valued for the same reason, and says so in its own
#: docstring: folding ``unprovable`` into ``breached`` "is fail-closed and therefore SAFE, but it is
#: not honest". A two-valued evidence outcome would re-collapse, one level up, a distinction that
#: plane already spent a fix separating.
#:
#: The checks this matters for are disproportionately the SECURITY ones: operator-queue containment,
#: key confinement, the never-activated operator unit, and every failure-injection check (where "the
#: product did not refuse at all" is a proven defect, not a failure to look).
OUTCOMES: frozenset[str] = frozenset(
    {OUTCOME_OBSERVED, OUTCOME_REFUSED, OUTCOME_UNPROVEN, OUTCOME_VIOLATED}
)

#: The outcomes a PASSING run may contain — stated as an ALLOWLIST, which is the whole point.
#:
#: This was a denylist ("pass unless something is ``unproven``") and that shape is a false-green
#: generator: every outcome added to :data:`OUTCOMES` becomes a passing outcome by default. Adding
#: ``violated`` as a one-line vocabulary edit was measured to seal and load a document containing a
#: PROVEN VIOLATION while still reporting ``passed``. The closed vocabulary was the only thing
#: holding that shut, and it stops holding in the same commit that widens it.
#:
#: Written this way round, a future fifth outcome fails CLOSED — it is not in this set, so it cannot
#: pass — and whoever adds it is told by a test rather than by an escaped green.
PASSING_OUTCOMES: frozenset[str] = frozenset({OUTCOME_OBSERVED, OUTCOME_REFUSED})

RUN_PASSED = "passed"
RUN_FAILED = "failed"
RUN_OUTCOMES: frozenset[str] = frozenset({RUN_PASSED, RUN_FAILED})

# --------------------------------------------------------------------------- harness reasons

HARNESS_REASONS: frozenset[str] = frozenset(
    {
        # --- tier gating (see secp_acceptance.tier) ---
        # A declared container tier that left no witness is the one failure a passing test report
        # cannot express on its own, so it gets its own code rather than being folded into an
        # infrastructure error.
        "acceptance_tier_undeclared",
        "acceptance_tier_unknown_witness",
        "acceptance_container_tier_not_executed",
        # --- fleet ---
        "acceptance_container_runtime_unavailable",
        "acceptance_host_image_build_failed",
        "acceptance_host_create_failed",
        "acceptance_host_systemd_not_running",
        "acceptance_host_dockerd_not_active",
        "acceptance_host_command_failed",
        "acceptance_host_command_timeout",
        "acceptance_host_output_too_large",
        "acceptance_fleet_teardown_incomplete",
        # The residue sweep reached a LIVE daemon that is not the one the fleet was built on. Kept
        # distinct from `acceptance_container_runtime_unavailable` because the runtime is perfectly
        # available — it is the wrong computer, which needs a different fix and would otherwise be
        # indistinguishable from an outage in the one report a reader has.
        "acceptance_residue_daemon_mismatch",
        # --- provisioning ---
        "acceptance_package_install_failed",
        "acceptance_entrypoint_absent",
        "acceptance_import_closure_failed",
        # --- controller ---
        "acceptance_controller_bringup_failed",
        "acceptance_controller_migration_failed",
        "acceptance_controller_api_unreachable",
        "acceptance_controller_temporal_unreachable",
        "acceptance_controller_signer_unavailable",
        # --- release bundle ---
        "acceptance_release_build_failed",
        "acceptance_release_not_signed",
        # --- proofs ---
        "acceptance_observation_unavailable",
        "acceptance_observation_malformed",
        # The harness looked and the product did NOT refuse something it must reject. Paired with
        # OUTCOME_VIOLATED, never with OUTCOME_UNPROVEN: this is a proven product defect, not a
        # failure to observe. (`acceptance_unexpected_reason_code` below is the opposite case — the
        # product DID refuse, just not for the reason that makes the check meaningful — and that
        # stays `unproven`, because the property was not proven and nothing bad was observed.)
        "acceptance_expected_refusal_absent",
        "acceptance_unexpected_reason_code",
        "acceptance_proof_would_be_vacuous",
        # The harness positively observed the state a check exists to rule out: an operator queue
        # with a live poller, a private key that left its host, an operator unit that was activated.
        # Deliberately ONE code for all of them rather than one per check — the check id already
        # says which property was violated, and a per-check code set would grow past review.
        "acceptance_prohibited_state_observed",
        # --- the run ---
        # The recorder accumulates in memory, so a parallelised session would seal one PARTIAL
        # document per worker and every one of them would look like a complete run.
        "acceptance_run_not_single_process",
        # Sealing without a fleet record: every stage's claims are claims about a fleet, so a
        # document whose fleet was invented rather than observed misdescribes its own premise.
        "acceptance_run_fleet_not_recorded",
        # --- evidence ---
        "acceptance_evidence_invalid",
        "acceptance_evidence_forbidden_value",
        "acceptance_evidence_unknown_check",
        "acceptance_evidence_unknown_stage",
        "acceptance_evidence_unknown_reason",
        "acceptance_evidence_duplicate_check",
        "acceptance_evidence_incomplete",
    }
)

# --------------------------------------------------------------------------- product reasons

#: Bounded PRODUCT refusal codes the scenarios assert on. Quoted from the product; a provenance
#: test proves each still exists in the product source. Grouped only for readability — membership
#: is what the evidence loader checks.
PRODUCT_REASONS: frozenset[str] = frozenset(
    {
        # management engine / installer
        "release_role_mismatch",
        "release_artifact_digest_mismatch",
        "write_requires_confirm",
        "confirm_requires_write",
        "root_required_for_write",
        "preexisting_partial_install",
        "worker_upgrade_not_linear_successor",
        "worker_ordinary_config_mismatch",
        "worker_operator_not_disabled_stopped",
        "worker_ordinary_polls_operator_queue",
        # The two CAUSES behind a three-valued containment verdict of ``unprovable``. They are here
        # rather than in HARNESS_REASONS because they are the product's own codes, emitted by
        # ``real_adapters._observe_queue_containment``, and they must stay distinguishable: a probe
        # that RAN and exited non-zero (the container is gone, the interpreter path does not resolve
        # inside the image, the health module errored) has a different remediation from a container
        # runtime that could not be invoked at all. Collapsing them would leave the queues stage
        # reporting "could not prove containment" with no way to say why.
        "queue_probe_command_failed",
        "queue_probe_runtime_unavailable",
        # enrollment
        "enrollment_invitation_revoked",
        "enrollment_invitation_consumed",
        "enrollment_invitation_expired",
        "enrollment_health_incomplete",
        "secpctl_controller_ca_unavailable",
    }
)

#: The union the evidence document accepts in ``reason_code``. Kept as one frozenset so a caller
#: cannot smuggle an arbitrary string past the loader, and so the two vocabularies stay disjointly
#: reviewable above.
ALL_REASONS: frozenset[str] = HARNESS_REASONS | PRODUCT_REASONS


def assert_disjoint() -> None:
    """The two vocabularies must not overlap.

    A code that is in both sets makes ``reason_code`` ambiguous about WHO refused — the harness or
    the product — which is the single fact a reader of the evidence most needs.
    """
    overlap = HARNESS_REASONS & PRODUCT_REASONS
    if overlap:
        raise ValueError(f"reason vocabularies overlap: {sorted(overlap)}")


assert_disjoint()


__all__ = [
    "ALL_REASONS",
    "CHECKS",
    "CHECKS_BY_STAGE",
    "HARNESS_REASONS",
    "OUTCOMES",
    "OUTCOME_OBSERVED",
    "OUTCOME_REFUSED",
    "OUTCOME_UNPROVEN",
    "OUTCOME_VIOLATED",
    "PASSING_OUTCOMES",
    "PRODUCT_REASONS",
    "RUN_FAILED",
    "RUN_OUTCOMES",
    "RUN_PASSED",
    "STAGES",
    "STAGE_CONTROLLER",
    "STAGE_ENROLLMENT",
    "STAGE_FAILURE_INJECTION",
    "STAGE_FLEET",
    "STAGE_IDENTITY",
    "STAGE_LIFECYCLE",
    "STAGE_PACKAGES",
    "STAGE_QUEUES",
    "STAGE_WORKER_INSTALL",
    "assert_disjoint",
]
