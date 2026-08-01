"""Classification, planning, refusal boundaries, reset intent and evidence (secp_reconciliation.v1).

The behaviour these pin, in one sentence each: an observation that is silent about a facet is never
read as agreement; the planner refuses rather than guessing; an element the planner declines to
touch is visible in the plan rather than absent from it; and every document is bound to the exact
inputs it was derived from.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from reconciliation_support import (
    COLLECTOR_DIGEST,
    NOW,
    desired,
    edge,
    network,
    node,
    observed,
    scope,
)
from secp_reconciliation.v1 import (
    ActionKind,
    DriftKind,
    DriftReason,
    ElementKind,
    FacetName,
    ObservationFidelity,
    PlanDisposition,
    ReconciliationRefused,
    RefusalCode,
    ResetScope,
    StateElement,
    build_reconciliation_evidence,
    build_refusal_evidence,
    build_reset_intent,
    classify_drift,
    plan_from_states,
    plan_reconciliation,
    require_plan_integrity,
    require_planned_under,
    verify_inputs,
)


def _run(desired_state, observed_state, reconciliation_scope=None, now=NOW):
    return plan_from_states(
        scope=reconciliation_scope or scope(),
        desired=desired_state,
        observed=observed_state,
        now=now,
    )


def _refusal(desired_state, observed_state, reconciliation_scope=None, now=NOW) -> RefusalCode:
    with pytest.raises(ReconciliationRefused) as raised:
        _run(desired_state, observed_state, reconciliation_scope, now)
    return raised.value.code


# --- Classification -------------------------------------------------------------------------------


def test_identical_state_classifies_as_converged_with_no_findings() -> None:
    state = (network(), node(), edge())
    _, report, plan = _run(desired(*state), observed(*state))
    assert report.findings == ()
    assert report.leading_kind() is None
    assert plan.disposition is PlanDisposition.converged
    assert plan.actions == ()
    assert plan.deferred == ()


def test_a_desired_element_absent_from_the_observation_is_missing_and_plans_a_create() -> None:
    _, report, plan = _run(desired(network(), node()), observed(network()))
    assert [(f.kind, f.reason, f.element_ref) for f in report.findings] == [
        (DriftKind.missing, DriftReason.element_absent, "attacker-1")
    ]
    assert [(a.kind, a.element_kind, a.element_ref) for a in plan.actions] == [
        (ActionKind.create, ElementKind.node, "attacker-1")
    ]
    assert plan.disposition is PlanDisposition.actionable


def test_a_diverged_facet_is_reported_by_its_bounded_reason_and_plans_an_update() -> None:
    _, report, plan = _run(
        desired(network(), node()), observed(network(), node(image="kali:2025.4"))
    )
    assert [(f.kind, f.reason) for f in report.findings] == [
        (DriftKind.divergent, DriftReason.facet_image_mismatch)
    ]
    assert [(a.kind, a.element_ref, a.reasons) for a in plan.actions] == [
        (ActionKind.update, "attacker-1", (DriftReason.facet_image_mismatch,))
    ]


def test_several_diverged_facets_on_one_element_become_one_action_with_ordered_reasons() -> None:
    _, report, plan = _run(
        desired(network(), node()),
        observed(network(), node(image="kali:2025.4", role="ubuntu", address="10.20.0.99")),
    )
    assert len(report.findings) == 3
    assert len(plan.actions) == 1
    assert plan.actions[0].reasons == (
        DriftReason.facet_role_mismatch,
        DriftReason.facet_image_mismatch,
        DriftReason.facet_address_mismatch,
    )


def test_actions_are_emitted_in_dependency_order_within_an_action_kind() -> None:
    _, _, plan = _run(desired(network(), node(), edge()), observed())
    assert [a.element_kind for a in plan.actions] == [
        ElementKind.network,
        ElementKind.node,
        ElementKind.edge,
    ]


def test_finding_order_is_independent_of_the_order_the_caller_declared_elements() -> None:
    elements = (network(), node(), node("sensor-1", node_class="sensor", address="10.20.0.11"))
    drifted = (network(address_space="10.30.0.0/24"), node(image="old"))
    _, forward, _ = _run(desired(*elements), observed(*drifted), scope())
    _, reversed_report, _ = _run(
        desired(*reversed(elements)), observed(*reversed(drifted)), scope()
    )
    assert forward.findings == reversed_report.findings


# --- The silence boundary -------------------------------------------------------------------------


def test_an_observation_silent_about_a_facet_is_indeterminate_not_agreement() -> None:
    pair = verify_inputs(
        scope=scope(),
        desired=desired(network()),
        observed=observed(network(omit=(FacetName.address_space,))),
        now=NOW,
    )
    report = classify_drift(pair)
    # The crucial negative: this must NOT be an empty (converged) report.
    assert report.findings != ()
    assert [(f.kind, f.reason) for f in report.findings] == [
        (DriftKind.indeterminate, DriftReason.facet_evidence_absent)
    ]
    with pytest.raises(ReconciliationRefused) as raised:
        plan_reconciliation(pair, report)
    assert raised.value.code is RefusalCode.drift_indeterminate


def test_a_facet_the_desired_state_does_not_declare_is_simply_not_reconciled() -> None:
    _, report, plan = _run(
        desired(network(omit=(FacetName.team_binding,))),
        observed(network(team="someone-elses-team")),
    )
    assert report.findings == ()
    assert plan.disposition is PlanDisposition.converged


# --- Planner refusal boundaries -------------------------------------------------------------------


def test_the_same_ref_denoting_a_different_kind_refuses_as_an_identity_conflict() -> None:
    conflicting = node("team-network", network_attachment="team-network")
    pair = verify_inputs(
        scope=scope(), desired=desired(network()), observed=observed(conflicting), now=NOW
    )
    report = classify_drift(pair)
    assert [(f.kind, f.reason) for f in report.findings] == [
        (DriftKind.identity_conflict, DriftReason.element_kind_conflict)
    ]
    with pytest.raises(ReconciliationRefused) as raised:
        plan_reconciliation(pair, report)
    assert raised.value.code is RefusalCode.identity_conflict_unresolvable


def test_identity_conflict_is_checked_before_indeterminate_drift() -> None:
    pair = verify_inputs(
        scope=scope(),
        desired=desired(network(), node("sensor-1")),
        observed=observed(
            node("team-network", network_attachment="team-network"),
            node("sensor-1", omit=(FacetName.image,)),
        ),
        now=NOW,
    )
    report = classify_drift(pair)
    assert {f.kind for f in report.findings} == {
        DriftKind.identity_conflict,
        DriftKind.indeterminate,
    }
    with pytest.raises(ReconciliationRefused) as raised:
        plan_reconciliation(pair, report)
    assert raised.value.code is RefusalCode.identity_conflict_unresolvable


def test_a_plan_exceeding_the_declared_change_budget_refuses() -> None:
    wanted = desired(network(), node(), edge())
    assert _refusal(wanted, observed(), scope(max_actions=2)) is RefusalCode.change_budget_exceeded
    _, _, plan = _run(wanted, observed(), scope(max_actions=3))
    assert len(plan.actions) == 3


def test_a_report_from_a_different_pair_cannot_be_planned() -> None:
    pair_a = verify_inputs(scope=scope(), desired=desired(network()), observed=observed(), now=NOW)
    pair_b = verify_inputs(scope=scope(), desired=desired(node()), observed=observed(), now=NOW)
    with pytest.raises(ReconciliationRefused) as raised:
        plan_reconciliation(pair_a, classify_drift(pair_b))
    assert raised.value.code is RefusalCode.verification_token_invalid


def test_a_verified_pair_whose_contents_were_swapped_after_verification_refuses() -> None:
    from dataclasses import replace

    pair = verify_inputs(scope=scope(), desired=desired(network()), observed=observed(), now=NOW)
    tampered = replace(pair, desired=desired(node()))
    for call in (classify_drift, lambda p: plan_reconciliation(p, classify_drift(pair))):
        with pytest.raises(ReconciliationRefused) as raised:
            call(tampered)
        assert raised.value.code is RefusalCode.verification_token_invalid


# --- Unmanaged elements are deferred, never removed -----------------------------------------------


def test_an_unmanaged_observed_element_is_deferred_and_forces_an_operator_decision() -> None:
    _, report, plan = _run(desired(network()), observed(network(), node("someone-elses-vm")))
    unmanaged = [f for f in report.findings if f.kind is DriftKind.unmanaged]
    assert len(unmanaged) == 1
    assert unmanaged[0].reason is DriftReason.element_unmanaged
    assert unmanaged[0].element_ref == ""
    assert plan.actions == ()
    assert [(d.element_kind, d.reason) for d in plan.deferred] == [
        (ElementKind.node, DriftReason.element_unmanaged)
    ]
    assert plan.disposition is PlanDisposition.operator_decision_required


def test_no_plan_over_any_input_combination_can_contain_a_removal() -> None:
    # ActionKind has no removal member, so this scans what the planner actually emitted rather
    # than trusting the enum: every emitted action is a create or an update.
    cases = [
        (desired(network(), node()), observed()),
        (desired(network()), observed(network(), node("foreign-1"), node("foreign-2"))),
        (desired(network(), node()), observed(network(address_space="10.9.0.0/24"), node())),
        (desired(), observed(node("foreign-1"))),
    ]
    emitted = set()
    for wanted, seen in cases:
        _, _, plan = _run(wanted, seen)
        emitted.update(action.kind for action in plan.actions)
    assert emitted <= {ActionKind.create, ActionKind.update}
    assert emitted == {ActionKind.create, ActionKind.update}


# --- Input verification gate ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("bad_contract_version", RefusalCode.contract_version_unsupported),
        ("empty_instance", RefusalCode.scope_invalid),
        ("empty_provider", RefusalCode.scope_invalid),
        ("negative_budget", RefusalCode.scope_invalid),
        ("zero_max_age", RefusalCode.scope_invalid),
        ("real_execution_surface", RefusalCode.execution_surface_sealed),
        ("no_definition_digest", RefusalCode.desired_unverified),
        ("malformed_definition_digest", RefusalCode.desired_unverified),
        ("duplicate_desired_ref", RefusalCode.desired_state_inconsistent),
        ("desired_facet_for_wrong_kind", RefusalCode.desired_state_inconsistent),
        ("dangling_desired_edge", RefusalCode.desired_state_inconsistent),
        ("desired_instance_mismatch", RefusalCode.instance_mismatch),
        ("observed_instance_mismatch", RefusalCode.instance_mismatch),
        ("provider_mismatch", RefusalCode.provider_mismatch),
        ("malformed_collector_digest", RefusalCode.observation_unverified),
        ("unverified_fidelity", RefusalCode.observation_unverified),
        ("future_dated_observation", RefusalCode.observation_unverified),
        ("partial_fidelity", RefusalCode.observation_incomplete),
        ("stale_observation", RefusalCode.observation_stale),
        ("duplicate_observed_ref", RefusalCode.observed_state_inconsistent),
        ("dangling_observed_edge", RefusalCode.observed_state_inconsistent),
    ],
)
def test_the_verification_gate_refuses_with_the_expected_bounded_code(case, expected) -> None:
    kwargs = {"reconciliation_scope": scope(), "now": NOW}
    wanted = desired(network())
    seen = observed(network())

    if case == "bad_contract_version":
        kwargs["reconciliation_scope"] = scope(contract_version="secp-recon/v2")
    elif case == "empty_instance":
        kwargs["reconciliation_scope"] = scope(instance_id="")
    elif case == "empty_provider":
        kwargs["reconciliation_scope"] = scope(provider="")
    elif case == "negative_budget":
        kwargs["reconciliation_scope"] = scope(max_actions=-1)
    elif case == "zero_max_age":
        kwargs["reconciliation_scope"] = scope(observation_max_age_seconds=0)
    elif case == "real_execution_surface":
        kwargs["reconciliation_scope"] = scope(execution_surface="proxmox")
    elif case == "no_definition_digest":
        wanted = desired(network(), definition_digest="")
    elif case == "malformed_definition_digest":
        wanted = desired(network(), definition_digest="sha256:not-hex")
    elif case == "duplicate_desired_ref":
        wanted = desired(network(), network())
    elif case == "desired_facet_for_wrong_kind":
        # ``role`` is a node facet; a network that declares it cannot be compared.
        wanted = desired(
            StateElement(kind=ElementKind.network, ref="n1", facets=((FacetName.role, "kali"),))
        )
    elif case == "dangling_desired_edge":
        wanted = desired(network(), edge("ghost-node", "team-network"))
    elif case == "desired_instance_mismatch":
        wanted = desired(network(), instance_id="other-instance")
    elif case == "observed_instance_mismatch":
        seen = observed(network(), instance_id="other-instance")
    elif case == "provider_mismatch":
        seen = observed(network(), provider="proxmox")
    elif case == "malformed_collector_digest":
        seen = observed(network(), collector_digest="unverified")
    elif case == "unverified_fidelity":
        seen = observed(network(), fidelity=ObservationFidelity.unverified)
    elif case == "future_dated_observation":
        seen = observed(network(), observed_at=NOW + timedelta(minutes=10))
    elif case == "partial_fidelity":
        seen = observed(network(), fidelity=ObservationFidelity.partial)
    elif case == "stale_observation":
        seen = observed(network(), observed_at=NOW - timedelta(minutes=10))
    elif case == "duplicate_observed_ref":
        seen = observed(network(), network())
    elif case == "dangling_observed_edge":
        seen = observed(network(), edge("ghost-node", "team-network"))
    else:  # pragma: no cover - the parametrization is closed
        raise AssertionError(case)

    assert _refusal(wanted, seen, **kwargs) is expected


def _raised_code(call) -> RefusalCode:
    with pytest.raises(ReconciliationRefused) as raised:
        call()
    return raised.value.code


def test_every_refusal_code_is_actually_reachable() -> None:
    """Each code is *produced by running the contract*, not merely named in a list. A declared but
    unreachable refusal is dead vocabulary, and a new code fails here until it is triggerable."""
    from dataclasses import replace

    ok_pair = verify_inputs(
        scope=scope(), desired=desired(network()), observed=observed(network()), now=NOW
    )
    other_pair = verify_inputs(
        scope=scope(), desired=desired(node()), observed=observed(node()), now=NOW
    )
    conflict_pair = verify_inputs(
        scope=scope(),
        desired=desired(network()),
        observed=observed(node("team-network", network_attachment="team-network")),
        now=NOW,
    )
    silent_pair = verify_inputs(
        scope=scope(),
        desired=desired(network()),
        observed=observed(network(omit=(FacetName.address_space,))),
        now=NOW,
    )
    creating_plan = _actionable_plan()
    converged_plan = _run(desired(network()), observed(network()))[2]
    window = {"issued_at": NOW, "expires_at": NOW + timedelta(hours=1)}

    triggered = {
        _raised_code(lambda: _run(desired(network()), observed(), scope(contract_version="v9"))),
        _raised_code(lambda: _run(desired(network()), observed(), scope(instance_id=""))),
        _raised_code(
            lambda: _run(desired(network()), observed(), scope(execution_surface="proxmox"))
        ),
        _raised_code(lambda: _run(desired(network(), definition_digest="x"), observed())),
        _raised_code(lambda: _run(desired(network(), network()), observed())),
        _raised_code(
            lambda: _run(desired(network(), instance_id="elsewhere"), observed(network()))
        ),
        _raised_code(lambda: _run(desired(network()), observed(network(), provider="proxmox"))),
        _raised_code(
            lambda: _run(desired(network()), observed(network(), collector_digest="nope"))
        ),
        _raised_code(
            lambda: _run(
                desired(network()),
                observed(network(), fidelity=ObservationFidelity.partial),
            )
        ),
        _raised_code(
            lambda: _run(
                desired(network()), observed(network(), observed_at=NOW - timedelta(hours=1))
            )
        ),
        _raised_code(lambda: _run(desired(network()), observed(network(), network()))),
        _raised_code(lambda: classify_drift(replace(ok_pair, desired=desired(node())))),
        _raised_code(lambda: plan_reconciliation(conflict_pair, classify_drift(conflict_pair))),
        _raised_code(lambda: plan_reconciliation(silent_pair, classify_drift(silent_pair))),
        _raised_code(lambda: _run(desired(network(), node()), observed(), scope(max_actions=1))),
        _raised_code(
            lambda: build_reset_intent(
                plan=converged_plan, reset_scope=ResetScope.element_set, **window
            )
        ),
        _raised_code(
            lambda: build_reset_intent(
                plan=creating_plan,
                reset_scope=ResetScope.element_set,
                issued_at=NOW,
                expires_at=NOW,
            )
        ),
        _raised_code(lambda: plan_reconciliation(ok_pair, classify_drift(other_pair))),
        # A plan edited after planning no longer matches its own digest.
        _raised_code(
            lambda: require_plan_integrity(
                replace(creating_plan, actions=creating_plan.actions * 2)
            )
        ),
        # A plan presented under a scope other than the one that authorized it.
        _raised_code(lambda: require_planned_under(creating_plan, scope(max_actions=49))),
    }
    assert triggered == set(RefusalCode)


def test_a_slightly_early_observation_is_tolerated_but_a_wildly_early_one_is_not() -> None:
    from secp_reconciliation.v1 import MAX_CLOCK_SKEW_SECONDS

    tolerated = observed(network(), observed_at=NOW + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS))
    _, report, _ = _run(desired(network()), tolerated)
    assert report.findings == ()
    rejected = observed(network(), observed_at=NOW + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS + 1))
    assert _refusal(desired(network()), rejected) is RefusalCode.observation_unverified


# --- Determinism and binding ----------------------------------------------------------------------


def test_the_same_inputs_produce_byte_identical_digests() -> None:
    args = (desired(network(), node()), observed(network()))
    _, first_report, first_plan = _run(*args)
    _, second_report, second_plan = _run(*args)
    assert first_report.report_digest == second_report.report_digest
    assert first_plan.plan_digest == second_plan.plan_digest


def test_a_different_observation_moves_the_report_and_plan_digests() -> None:
    _, base_report, base_plan = _run(desired(network(), node()), observed(network()))
    _, other_report, other_plan = _run(desired(network(), node()), observed())
    assert base_report.report_digest != other_report.report_digest
    assert base_plan.plan_digest != other_plan.plan_digest


def test_the_plan_binds_the_exact_desired_observation_and_report_it_came_from() -> None:
    _, report, plan = _run(desired(network(), node()), observed(network()))
    assert plan.desired_digest == report.desired_digest
    assert plan.observed_digest == report.observed_digest
    assert plan.report_digest == report.report_digest


# --- Reset intent ---------------------------------------------------------------------------------


def _actionable_plan():
    _, _, plan = _run(desired(network(), node()), observed(network()))
    return plan


def test_a_reset_intent_binds_the_plan_and_carries_only_counts_and_digests() -> None:
    plan = _actionable_plan()
    intent = build_reset_intent(
        plan=plan,
        reset_scope=ResetScope.element_set,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    document = intent.document()
    assert document["plan_digest"] == plan.plan_digest
    assert document["action_counts"] == {"create": 1, "update": 0}
    assert document["element_kind_counts"] == {"network": 0, "node": 1, "edge": 0}
    assert document["deferred_count"] == 0
    assert document["execution_surface"] == "simulator"
    assert "elements" not in document and "actions" not in document


def test_an_instance_wide_reset_over_a_plan_with_deferred_elements_refuses() -> None:
    _, _, plan = _run(desired(network()), observed(network(), node("foreign-1")))
    with pytest.raises(ReconciliationRefused) as raised:
        build_reset_intent(
            plan=plan,
            reset_scope=ResetScope.instance,
            issued_at=NOW,
            expires_at=NOW + timedelta(hours=1),
        )
    assert raised.value.code is RefusalCode.reset_scope_unsafe


def test_a_reset_intent_that_would_authorize_nothing_refuses() -> None:
    _, _, plan = _run(desired(network()), observed(network()))
    with pytest.raises(ReconciliationRefused) as raised:
        build_reset_intent(
            plan=plan,
            reset_scope=ResetScope.element_set,
            issued_at=NOW,
            expires_at=NOW + timedelta(hours=1),
        )
    assert raised.value.code is RefusalCode.reset_scope_unsafe


@pytest.mark.parametrize("delta", [timedelta(0), timedelta(seconds=-1)])
def test_an_empty_or_inverted_validity_window_refuses(delta) -> None:
    with pytest.raises(ReconciliationRefused) as raised:
        build_reset_intent(
            plan=_actionable_plan(),
            reset_scope=ResetScope.element_set,
            issued_at=NOW,
            expires_at=NOW + delta,
        )
    assert raised.value.code is RefusalCode.reset_window_invalid


def test_the_reset_intent_digest_changes_with_the_scope_it_authorizes() -> None:
    _, _, plan = _run(desired(network(), node()), observed())
    common = {"plan": plan, "issued_at": NOW, "expires_at": NOW + timedelta(hours=1)}
    element_set = build_reset_intent(reset_scope=ResetScope.element_set, **common)
    instance = build_reset_intent(reset_scope=ResetScope.instance, **common)
    assert element_set.intent_digest != instance.intent_digest


# --- Evidence -------------------------------------------------------------------------------------


def test_reconciliation_evidence_counts_match_the_report_exactly() -> None:
    _, report, plan = _run(
        desired(network(), node()),
        observed(network(address_space="10.9.0.0/24"), node(), node("foreign-1")),
    )
    document = build_reconciliation_evidence(
        scope=scope(), report=report, plan=plan, evaluated_at=NOW
    )
    assert sum(document["drift_counts_by_kind"].values()) == len(report.findings)
    assert sum(document["drift_counts_by_reason"].values()) == len(report.findings)
    assert document["drift_counts_by_kind"]["unmanaged"] == 1
    assert document["deferred_count"] == len(plan.deferred)
    assert document["outcome"] == "planned"
    assert document["plan_digest"] == plan.plan_digest


def test_evidence_enumerates_every_kind_and_reason_including_the_zeroes() -> None:
    _, report, plan = _run(desired(network()), observed(network()))
    document = build_reconciliation_evidence(
        scope=scope(), report=report, plan=plan, evaluated_at=NOW
    )
    assert len(document["drift_counts_by_kind"]) == len(DriftKind)
    assert len(document["drift_counts_by_reason"]) == len(DriftReason)
    assert set(document["drift_counts_by_kind"].values()) == {0}


def test_refusal_evidence_records_the_bounded_code_and_whether_a_retry_could_help() -> None:
    stale = build_refusal_evidence(
        scope=scope(), code=RefusalCode.observation_stale, evaluated_at=NOW
    )
    assert stale["outcome"] == "refused"
    assert stale["refusal_code"] == "reconciliation_observation_stale"
    assert stale["retryable_with_fresh_observation"] is True
    sealed = build_refusal_evidence(
        scope=scope(), code=RefusalCode.execution_surface_sealed, evaluated_at=NOW
    )
    assert sealed["retryable_with_fresh_observation"] is False


def test_evidence_digests_are_stable_and_move_with_the_evaluation_instant() -> None:
    _, report, plan = _run(desired(network(), node()), observed(network()))
    first = build_reconciliation_evidence(scope=scope(), report=report, plan=plan, evaluated_at=NOW)
    same = build_reconciliation_evidence(scope=scope(), report=report, plan=plan, evaluated_at=NOW)
    later = build_reconciliation_evidence(
        scope=scope(), report=report, plan=plan, evaluated_at=NOW + timedelta(seconds=1)
    )
    assert first["evidence_digest"] == same["evidence_digest"]
    assert first["evidence_digest"] != later["evidence_digest"]


def test_a_naive_timestamp_is_read_as_utc_rather_than_as_a_local_time() -> None:
    naive = observed(network(), observed_at=datetime(2026, 7, 31, 12, 0, 0))
    aware = observed(network(), observed_at=datetime(2026, 7, 31, 12, 0, 0, tzinfo=UTC))
    _, naive_report, _ = _run(desired(network()), naive)
    _, aware_report, _ = _run(desired(network()), aware)
    assert naive_report.observed_digest == aware_report.observed_digest


# --- Document shape -------------------------------------------------------------------------------
# ADR-029 claims every value in these documents is a version, a closed code, a count, a digest, a
# canonical timestamp, a boolean derived from a closed code, or the control plane's own instance
# identifier. The leak scan proves no *provider* value appears; these pin the key sets exactly, so a
# field added to any of the three fails here instead of quietly widening that claim.

RESET_INTENT_KEYS = {
    "schema_version",
    "contract_version",
    "instance_id",
    "reset_scope",
    "execution_surface",
    "disposition",
    "desired_digest",
    "observed_digest",
    "report_digest",
    "plan_digest",
    "action_counts",
    "element_kind_counts",
    "deferred_count",
    "issued_at",
    "expires_at",
    "intent_digest",
}

RECONCILIATION_EVIDENCE_KEYS = {
    "schema_version",
    "contract_version",
    "classifier_version",
    "planner_version",
    "outcome",
    "instance_id",
    "scope_digest",
    "execution_surface",
    "desired_digest",
    "observed_digest",
    "report_digest",
    "plan_digest",
    "disposition",
    "drift_counts_by_kind",
    "drift_counts_by_reason",
    "action_counts",
    "action_element_counts",
    "deferred_count",
    "evaluated_at",
    "evidence_digest",
}

REFUSAL_EVIDENCE_KEYS = {
    "schema_version",
    "contract_version",
    "classifier_version",
    "planner_version",
    "outcome",
    "instance_id",
    "scope_digest",
    "refusal_code",
    "retryable_with_fresh_observation",
    "evaluated_at",
    "evidence_digest",
}


def test_every_document_carries_exactly_the_reviewed_key_set() -> None:
    _, report, plan = _run(desired(network(), node()), observed(network(), node("foreign-1")))
    intent = build_reset_intent(
        plan=plan,
        reset_scope=ResetScope.element_set,
        issued_at=NOW,
        expires_at=NOW + timedelta(hours=1),
    )
    assert set(intent.document()) == RESET_INTENT_KEYS
    assert (
        set(
            build_reconciliation_evidence(scope=scope(), report=report, plan=plan, evaluated_at=NOW)
        )
        == RECONCILIATION_EVIDENCE_KEYS
    )
    assert (
        set(
            build_refusal_evidence(
                scope=scope(), code=RefusalCode.observation_stale, evaluated_at=NOW
            )
        )
        == REFUSAL_EVIDENCE_KEYS
    )


def test_no_document_value_is_a_free_form_string_outside_the_reviewed_categories() -> None:
    """The key pin says *which* fields; this says *what may be in them*. Every scalar is an int, a
    bool, a schema/contract version, a closed code, a `sha256:` digest, a canonical timestamp, or
    the instance id the caller declared in the scope. Nested values are count maps, so their values
    are ints. A provider value landing in any field fails here even if the key set was updated.
    """
    _, report, plan = _run(desired(network(), node()), observed(network(), node("foreign-1")))
    documents = [
        build_reset_intent(
            plan=plan,
            reset_scope=ResetScope.element_set,
            issued_at=NOW,
            expires_at=NOW + timedelta(hours=1),
        ).document(),
        build_reconciliation_evidence(scope=scope(), report=report, plan=plan, evaluated_at=NOW),
        build_refusal_evidence(scope=scope(), code=RefusalCode.observation_stale, evaluated_at=NOW),
    ]
    closed_codes = {
        member.value
        for enum in (
            DriftKind,
            DriftReason,
            ElementKind,
            ActionKind,
            PlanDisposition,
            RefusalCode,
            ResetScope,
        )
        for member in enum
    }
    allowed_scalars = closed_codes | {
        "simulator",
        "planned",
        "refused",
        scope().instance_id,
        NOW.isoformat(),
        (NOW + timedelta(hours=1)).isoformat(),
    }
    versions = {"secp-recon/", "secp-recon/v1"}

    for document in documents:
        for key, value in document.items():
            if isinstance(value, dict):
                assert all(isinstance(count, int) for count in value.values()), key
                continue
            if isinstance(value, bool) or isinstance(value, int):
                continue
            assert isinstance(value, str), (key, value)
            if value.startswith("sha256:"):
                assert len(value) == len("sha256:") + 64, key
                continue
            if any(value.startswith(prefix) for prefix in versions):
                continue
            assert value in allowed_scalars, (key, value)


def test_the_collector_digest_is_part_of_what_the_observation_digest_covers() -> None:
    _, base, _ = _run(desired(network()), observed(network()))
    _, other, _ = _run(
        desired(network()), observed(network(), collector_digest="sha256:" + "33" * 32)
    )
    assert COLLECTOR_DIGEST != "sha256:" + "33" * 32
    assert base.observed_digest != other.observed_digest
