"""The closed vocabularies of the reconciliation contract (secp_reconciliation.v1).

Every assertion here pins an **exact** set or count rather than a floor, because a floor absorbs
the next silent removal: an ordering tuple that lost a member, a partition that stopped covering a
code, or an enum that quietly grew a destructive action would all still satisfy ``>=``.
"""

from __future__ import annotations

from secp_reconciliation.v1 import (
    ACTION_FOR_DRIFT_KIND,
    ACTION_KIND_ORDER,
    CONTRACT_VERSION,
    DIVERGENCE_REASON_BY_FACET,
    DRIFT_KIND_ORDER,
    DRIFT_REASON_ORDER,
    DRIFT_REASONS_BY_KIND,
    ELEMENT_KIND_ORDER,
    FACETS_BY_ELEMENT_KIND,
    RETRYABLE_WITH_FRESH_OBSERVATION,
    ActionKind,
    ConvergenceState,
    DriftKind,
    DriftReason,
    ElementKind,
    ExecutionOutcome,
    ExecutionSurface,
    FacetName,
    ObservationFidelity,
    OperatorNextStep,
    PlanDisposition,
    RefusalCode,
    ResetScope,
    StepFailureReason,
    StepStatus,
    canonical_json,
    document_digest,
    is_content_digest,
    sha256_digest,
)

# The reviewed sizes of every closed vocabulary. Each is exact: adding or removing a member forces
# a conscious edit here and, with it, a decision about what the new member means everywhere it is
# ordered, partitioned or mapped.
EXPECTED_SIZES = {
    "DriftKind": 5,
    "DriftReason": 14,
    "ElementKind": 3,
    "FacetName": 10,
    "ActionKind": 2,
    "PlanDisposition": 3,
    "ObservationFidelity": 3,
    "ExecutionSurface": 1,
    "ResetScope": 2,
    "RefusalCode": 23,
    "ExecutionOutcome": 3,
    "StepStatus": 3,
    "StepFailureReason": 2,
    "OperatorNextStep": 4,
    "ConvergenceState": 3,
}

_ENUMS = {
    "DriftKind": DriftKind,
    "DriftReason": DriftReason,
    "ElementKind": ElementKind,
    "FacetName": FacetName,
    "ActionKind": ActionKind,
    "PlanDisposition": PlanDisposition,
    "ObservationFidelity": ObservationFidelity,
    "ExecutionSurface": ExecutionSurface,
    "ResetScope": ResetScope,
    "RefusalCode": RefusalCode,
    "ExecutionOutcome": ExecutionOutcome,
    "StepStatus": StepStatus,
    "StepFailureReason": StepFailureReason,
    "OperatorNextStep": OperatorNextStep,
    "ConvergenceState": ConvergenceState,
}


def test_every_closed_vocabulary_has_its_reviewed_exact_size() -> None:
    assert {name: len(enum) for name, enum in _ENUMS.items()} == EXPECTED_SIZES


def test_every_vocabulary_covered_by_the_size_pin_is_the_complete_set_of_exported_enums() -> None:
    # keyed on what the members *are* (enum classes exported by the contract), not on a hand-kept
    # list of names, so a newly exported enum that nobody pinned fails here.
    import enum as enum_module

    import secp_reconciliation.v1 as contract

    exported = {
        name
        for name in contract.__all__
        if isinstance(getattr(contract, name), type)
        and issubclass(getattr(contract, name), enum_module.Enum)
    }
    assert exported == set(_ENUMS)


def test_no_enum_has_a_duplicate_value() -> None:
    for name, enum in _ENUMS.items():
        values = [member.value for member in enum]
        assert len(values) == len(set(values)), name


# --- Orderings ----------------------------------------------------------------------------------


def test_orderings_are_exact_permutations_of_their_enums() -> None:
    for ordering, enum in (
        (DRIFT_KIND_ORDER, DriftKind),
        (DRIFT_REASON_ORDER, DriftReason),
        (ELEMENT_KIND_ORDER, ElementKind),
        (ACTION_KIND_ORDER, ActionKind),
    ):
        assert len(ordering) == len(enum)
        assert set(ordering) == set(enum)
        assert len(set(ordering)) == len(ordering)


def test_drift_kind_order_leads_with_the_two_kinds_the_planner_refuses_on() -> None:
    assert DRIFT_KIND_ORDER[:2] == (DriftKind.identity_conflict, DriftKind.indeterminate)


def test_element_kind_order_is_dependency_order() -> None:
    assert ELEMENT_KIND_ORDER == (ElementKind.network, ElementKind.node, ElementKind.edge)


# --- Partitions and total maps ------------------------------------------------------------------


def test_drift_reasons_by_kind_partitions_every_reason_exactly_once() -> None:
    assert set(DRIFT_REASONS_BY_KIND) == set(DriftKind)
    flattened = [reason for reasons in DRIFT_REASONS_BY_KIND.values() for reason in reasons]
    assert len(flattened) == len(DriftReason)
    assert set(flattened) == set(DriftReason)


def test_facets_by_element_kind_covers_every_facet_and_edges_compare_none() -> None:
    assert set(FACETS_BY_ELEMENT_KIND) == set(ElementKind)
    covered = {facet for facets in FACETS_BY_ELEMENT_KIND.values() for facet in facets}
    assert covered == set(FacetName)
    assert FACETS_BY_ELEMENT_KIND[ElementKind.edge] == ()
    for kind, facets in FACETS_BY_ELEMENT_KIND.items():
        assert len(set(facets)) == len(facets), kind


def test_divergence_reason_by_facet_is_total_and_injective_into_the_divergent_reasons() -> None:
    assert set(DIVERGENCE_REASON_BY_FACET) == set(FacetName)
    reasons = list(DIVERGENCE_REASON_BY_FACET.values())
    assert len(set(reasons)) == len(reasons)
    assert set(reasons) == set(DRIFT_REASONS_BY_KIND[DriftKind.divergent])


def test_action_for_drift_kind_covers_exactly_the_actionable_kinds() -> None:
    assert set(ACTION_FOR_DRIFT_KIND) == {DriftKind.missing, DriftKind.divergent}
    assert ACTION_FOR_DRIFT_KIND[DriftKind.missing] is ActionKind.create
    assert ACTION_FOR_DRIFT_KIND[DriftKind.divergent] is ActionKind.update


# --- Structural seals -----------------------------------------------------------------------------


def test_action_kind_cannot_express_a_removal() -> None:
    # Not "removal is disabled" but "removal is unrepresentable": there is no member to emit.
    assert {member.value for member in ActionKind} == {"create", "update"}


def test_execution_surface_has_exactly_one_member_and_it_is_the_simulator() -> None:
    assert [member.value for member in ExecutionSurface] == ["simulator"]


def test_every_refusal_code_is_namespaced_and_carries_no_provider_vocabulary() -> None:
    for code in RefusalCode:
        assert code.value.startswith("reconciliation_")
        assert code.value == code.value.lower()
        assert " " not in code.value


def test_retryable_refusals_are_exactly_the_observation_provenance_refusals() -> None:
    assert RETRYABLE_WITH_FRESH_OBSERVATION == frozenset(
        {
            RefusalCode.observation_unverified,
            RefusalCode.observation_incomplete,
            RefusalCode.observation_stale,
            RefusalCode.observed_state_inconsistent,
        }
    )
    assert RETRYABLE_WITH_FRESH_OBSERVATION < set(RefusalCode)


def test_contract_version_is_pinned() -> None:
    assert CONTRACT_VERSION == "secp-recon/v1"


# --- Canonical encoding ---------------------------------------------------------------------------


def test_canonical_json_is_key_order_independent_and_whitespace_free() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})
    assert canonical_json({"a": 1, "b": 2}) == '{"a":1,"b":2}'


def test_document_digest_separates_identical_bodies_under_different_versions() -> None:
    body = {"a": 1}
    assert document_digest("v1", body) != document_digest("v2", body)


def test_sha256_digest_shape() -> None:
    digest = sha256_digest("x")
    assert digest.startswith("sha256:")
    assert len(digest) == len("sha256:") + 64
    assert is_content_digest(digest)


def test_is_content_digest_rejects_everything_that_is_not_one() -> None:
    good = "sha256:" + "ab" * 32
    assert is_content_digest(good)
    for bad in (
        "",
        "sha256:",
        "sha1:" + "ab" * 32,
        "sha256:" + "ab" * 31,
        "sha256:" + "ab" * 33,
        "sha256:" + "AB" * 32,  # uppercase hex is not the canonical form
        "sha256:" + "zz" * 32,
        good + " ",
        None,
        b"sha256:" + b"ab" * 32,
        123,
    ):
        assert not is_content_digest(bad), bad


# --- ADR-029 truthfulness -----------------------------------------------------------------------
# ADR-029 states specific, checkable facts about these vocabularies. Each assertion below protects
# exactly one sentence of that document; a vocabulary change that leaves the ADR behind fails here.

from pathlib import Path  # noqa: E402

ADR = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "adr"
    / "ADR-029-reconciliation-and-drift-foundation.md"
)


def _adr_text() -> str:
    return " ".join(ADR.read_text(encoding="utf-8").replace("`", "").split())


def test_the_adr_exists_and_names_the_paths_it_describes() -> None:
    body = _adr_text()
    repo = ADR.parents[2]
    for path in (
        "contracts/reconciliation/secp_reconciliation",
        "plugins/simulator/secp_plugin_simulator/reconciliation.py",
        "v1/topology_adapter.py",
    ):
        assert path in body, path
    assert (repo / "contracts/reconciliation/secp_reconciliation").is_dir()
    assert (repo / "plugins/simulator/secp_plugin_simulator/reconciliation.py").is_file()
    assert (repo / "contracts/reconciliation/secp_reconciliation/v1/topology_adapter.py").is_file()


def test_the_adrs_drift_kind_sentence_matches_the_ordering_in_code() -> None:
    named = ", ".join(kind.value for kind in DRIFT_KIND_ORDER)
    assert f"Five kinds, totally ordered by how much they block: {named}." in _adr_text()


def test_the_adrs_action_kind_sentence_matches_the_enum() -> None:
    members = " and ".join(member.value for member in ActionKind)
    assert f"ActionKind has two members, {members}." in _adr_text()
    assert len(ActionKind) == 2


def test_the_adrs_execution_surface_sentence_matches_the_enum() -> None:
    assert len(ExecutionSurface) == 1
    only = next(iter(ExecutionSurface)).value
    assert f"ExecutionSurface has exactly one member, {only};" in _adr_text()


def test_the_adrs_element_and_facet_names_are_real_members() -> None:
    body = _adr_text()
    assert "(" + " / ".join(kind.value for kind in ELEMENT_KIND_ORDER) + " —" in body
    for facet in ("address_space", "address", "node_class"):
        assert FacetName(facet)
        assert facet in body


def test_the_adrs_refusal_prefix_claim_holds() -> None:
    assert "bounded reconciliation_* code" in _adr_text()
    assert all(code.value.startswith("reconciliation_") for code in RefusalCode)
