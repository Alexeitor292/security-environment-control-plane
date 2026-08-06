"""Many operations, one canonical manifest.

Two properties decide whether a multi-operation run is honest:

* **one manifest.** A manifest per operation family would mean the signature covers several
  documents that could each be swapped independently, and "which of the four manifests was this
  fact in" is a question no operator should have to answer.
* **a failing operation does not abort the run.** A discovery that stops at the first refusal
  reports a target as far less observable than it is, and the required-fact evaluator needs to know
  *which* facts are missing rather than merely that something went wrong.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from secp_api.discovery_observation import Observation
from secp_api.discovery_operation_evidence import (
    FIRST_MVP_TRANSPORTS,
    TransportKind,
    active_transport_set,
    first_mvp_manifest_refusals,
)
from secp_api.enums import DiscoveryObservationState as S
from secp_worker.proxmox_discovery_composition import run_operation_sequence
from secp_worker.proxmox_discovery_operations import (
    GetClusterStatusOperation,
    GetNodesOperation,
    GetNodeStatusOperation,
    GetNodeVersionOperation,
    GetVersionOperation,
)
from secp_worker.proxmox_sdn_operations import (
    GetNodeSdnZonesOperation,
    GetSdnRootOperation,
    GetSdnZonesOperation,
)

START = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
END = START + timedelta(seconds=1)
AUTHORITY = "pve.example.test:8006"
SRC = "prior:/nodes"


class _Fake:
    """Returns a canned payload per path, or raises a canned error. Opens no socket."""

    def __init__(self, payloads: dict, errors: dict | None = None) -> None:
        self.payloads = payloads
        self.errors = errors or {}
        self.calls: list[str] = []

    def get(self, path: str, params: dict | None = None):
        self.calls.append(path)
        if path in self.errors:
            raise self.errors[path]
        return self.payloads[path]


def _parse(operation, payload) -> dict[str, Observation]:
    """A minimal parser: marks every field of an operation observed with its payload."""
    return {code: Observation.observed(payload) for code in operation.observation_field_codes}


def _run(transport, operations):
    return run_operation_sequence(
        transport=transport,
        operations=operations,
        target_authority_identity=AUTHORITY,
        parse=_parse,
        started_at=START,
        completed_at=END,
    )


# --- one manifest ---------------------------------------------------------------------------------


def test_every_operation_appends_to_one_manifest():
    ops = [GetVersionOperation(), GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake({"/version": {"v": 1}, "/cluster/status": [], "/nodes": []})
    result = _run(transport, ops)

    assert transport.calls == ["/version", "/cluster/status", "/nodes"]
    assert len(result.manifest.operations) == 3
    codes = [op.operation_code for op in result.manifest.operations]
    assert codes == ["api_version", "cluster_status", "node_index"]


def test_sdn_operations_share_the_same_manifest_and_engine():
    """No second engine for SDN — the whole point of the shared seam."""
    ops = [GetVersionOperation(), GetSdnRootOperation(), GetSdnZonesOperation()]
    transport = _Fake({"/version": {"v": 1}, "/cluster/sdn": [], "/cluster/sdn/zones": []})
    result = _run(transport, ops)
    assert len(result.manifest.operations) == 3
    assert active_transport_set(result.manifest) == FIRST_MVP_TRANSPORTS
    assert first_mvp_manifest_refusals(result.manifest) == ()


def test_query_parameters_reach_the_transport_for_pending_reads():
    transport = _Fake({"/cluster/sdn/zones": []})
    result = _run(transport, [GetSdnZonesOperation()])
    (record,) = result.manifest.operations
    assert record.canonical_query_parameters == (("pending", "1"),)


def test_the_manifest_records_the_template_as_well_as_the_instance():
    """A reviewer sees the SHAPE that was permitted, not only the one call that ran."""
    transport = _Fake({"/nodes/pve-a/status": {}})
    result = _run(transport, [GetNodeStatusOperation("pve-a", SRC)])
    (record,) = result.manifest.operations
    assert record.canonical_path_template == "/nodes/{node}/status"
    assert record.canonical_rendered_path == "/nodes/pve-a/status"


# --- a failure does not abort the run -------------------------------------------------------------


def test_a_failing_operation_does_not_stop_the_sequence():
    class _Denied(Exception):
        pass

    ops = [GetVersionOperation(), GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake(
        {"/version": {"v": 1}, "/nodes": []},
        errors={"/cluster/status": _Denied("proxmox_discovery_permission_denied")},
    )
    result = _run(transport, ops)

    assert transport.calls == ["/version", "/cluster/status", "/nodes"]
    assert len(result.manifest.operations) == 3
    assert result.failed is True
    assert result.failure_reason == "proxmox_discovery_permission_denied"
    # The successful operations still produced usable observations.
    assert result.observations["pve_version_full"].is_usable is True
    assert result.observations["cluster_identity"].state is S.probe_failed


def test_the_refused_operation_is_still_recorded_as_evidence():
    """A run that refused is evidence too — the record says which request was refused."""

    class _Denied(Exception):
        pass

    transport = _Fake({}, errors={"/version": _Denied("proxmox_discovery_permission_denied")})
    result = _run(transport, [GetVersionOperation()])
    (record,) = result.manifest.operations
    assert record.response_status_classification == "refused"
    assert record.canonical_rendered_path == "/version"
    assert record.transport_kind is TransportKind.proxmox_https_api


def test_a_success_does_not_erase_a_refusal_from_another_source():
    """THE FAIL-CLOSED RULE, in the order success-then-denial.

    ``node_names`` is fed by both /cluster/status and /nodes. The old rule was "a usable answer
    replaces an unusable one", so this fact read ``observed`` after one of its sources had been
    DENIED — with that source's contribution silently missing from the value and nothing anywhere
    for an operator to grant. The refusal now wins, and the good answer is kept in provenance so
    nothing is lost.
    """

    class _Denied(Exception):
        pass

    ops = [GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake(
        {"/cluster/status": ["cluster-data"]},
        errors={"/nodes": _Denied("proxmox_discovery_request_refused")},
    )
    result = _run(transport, ops)

    fact = result.observations["node_names"]
    assert fact.is_usable is False
    assert fact.reason_code == "proxmox_discovery_request_refused"

    # Nothing is lost: both contributions survive, including the one that succeeded.
    states = {c.operation_code: c.state for c in result.contributions["node_names"]}
    assert states == {"cluster_status": "observed", "node_index": "probe_failed"}


def test_a_success_does_not_erase_a_refusal_in_the_other_order_either():
    """Denial-then-success. The join is commutative or it is not a join."""

    class _Denied(Exception):
        pass

    ops = [GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake(
        {"/nodes": ["node-data"]},
        errors={"/cluster/status": _Denied("proxmox_discovery_request_refused")},
    )
    result = _run(transport, ops)

    assert result.observations["node_names"].is_usable is False
    assert result.observations["node_names"].reason_code == "proxmox_discovery_request_refused"
    states = {c.operation_code: c.state for c in result.contributions["node_names"]}
    assert states == {"cluster_status": "probe_failed", "node_index": "observed"}
    # And the fact only /cluster/status supplies stays failed.
    assert result.observations["cluster_identity"].state is S.probe_failed


def test_complementary_sources_that_both_succeed_still_merge():
    """The rule must not be "any second source ruins the fact" — that would make redundancy
    useless. Two usable contributions covering different keys combine as before."""
    ops = [GetNodeStatusOperation("pve-a", SRC), GetNodeStatusOperation("pve-b", SRC)]
    transport = _Fake({"/nodes/pve-a/status": {}, "/nodes/pve-b/status": {}})
    seen = iter(
        [
            {"node_capacity": Observation.observed({"pve-a": {"cpus": 8}})},
            {"node_capacity": Observation.observed({"pve-b": {"cpus": 16}})},
        ]
    )
    result = _run_with(transport, ops, lambda operation, payload: next(seen))
    assert result.observations["node_capacity"].is_usable is True
    assert set(result.observations["node_capacity"].value) == {"pve-a", "pve-b"}


def test_the_more_actionable_refusal_is_the_one_reported():
    """Which of two failures an operator is shown decides whether they grant a privilege or go
    hunting for a bug, so it is chosen rather than left to arrival order."""
    ops = [GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake({"/cluster/status": [], "/nodes": []})
    seen = iter(
        [
            {"node_names": Observation.probe_failed("transport_broke")},
            {
                "node_names": Observation.permission_denied(
                    missing_privilege="Sys.Audit", reason_code="denied"
                )
            },
        ]
    )
    result = _run_with(transport, ops, lambda operation, payload: next(seen))

    fact = result.observations["node_names"]
    assert fact.state is S.permission_denied
    assert fact.missing_privilege == "Sys.Audit"


def test_an_unsupported_answer_is_an_answer_and_does_not_degrade_the_fact():
    """``observed_unsupported`` means the TARGET replied that it does not have this. Treating it as
    a gap would make every PVE 8.x cluster permanently ineligible over an endpoint that did not
    exist yet."""
    ops = [GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake({"/cluster/status": [], "/nodes": []})
    seen = iter(
        [
            {"node_names": Observation.unsupported("endpoint_absent_on_this_version")},
            {"node_names": Observation.observed(("pve-a",))},
        ]
    )
    result = _run_with(transport, ops, lambda operation, payload: next(seen))
    assert result.observations["node_names"].is_usable is True
    assert result.observations["node_names"].value == ("pve-a",)


def test_a_conflict_between_two_successes_degrades_the_fact():
    """success + conflict. A target answering inconsistently is a finding, not a choice."""
    ops = [GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake({"/cluster/status": [], "/nodes": []})
    seen = iter(
        [
            {"node_names": Observation.observed(("pve-a", "pve-b"))},
            {"node_names": Observation.observed(("pve-a",))},
        ]
    )
    result = _run_with(transport, ops, lambda operation, payload: next(seen))
    fact = result.observations["node_names"]
    assert fact.is_usable is False
    assert fact.state is S.observed_malformed
    assert fact.reason_code == "source_disagreement:node_names"


def test_a_conflict_survives_a_later_success_from_a_third_source():
    """The lattice is associative: once degraded, a subsequent good answer cannot lift it."""
    ops = [GetClusterStatusOperation(), GetNodesOperation(), GetNodeStatusOperation("pve-a", SRC)]
    transport = _Fake({"/cluster/status": [], "/nodes": [], "/nodes/pve-a/status": {}})
    seen = iter(
        [
            {"node_names": Observation.observed(("pve-a", "pve-b"))},
            {"node_names": Observation.observed(("pve-a",))},
            {"node_names": Observation.observed(("pve-a", "pve-b"))},
        ]
    )
    result = _run_with(transport, ops, lambda operation, payload: next(seen))
    assert result.observations["node_names"].is_usable is False


def test_an_all_failing_run_still_produces_a_manifest():
    class _Down(Exception):
        pass

    ops = [GetVersionOperation(), GetNodesOperation()]
    transport = _Fake(
        {}, errors={"/version": _Down("proxmox_discovery_transport_failed"), "/nodes": _Down("x")}
    )
    result = _run(transport, ops)
    assert len(result.manifest.operations) == 2
    assert all(not o.is_usable for o in result.observations.values())
    assert first_mvp_manifest_refusals(result.manifest) == ()  # still an HTTPS-only manifest


def test_an_empty_operation_list_produces_an_empty_manifest_which_is_refused():
    """An empty manifest is not a clean run — it is indistinguishable from one that ran nothing."""
    result = _run(_Fake({}), [])
    assert result.manifest.operations == ()
    assert "discovery_manifest_empty" in first_mvp_manifest_refusals(result.manifest)


# --- no mutation is reachable from the sequencer --------------------------------------------------


def test_the_sequencer_exposes_no_path_or_method_parameter():
    import inspect

    params = set(inspect.signature(run_operation_sequence).parameters)
    for banned in ("path", "url", "method", "body"):
        assert banned not in params
    assert params == {
        "transport",
        "operations",
        "target_authority_identity",
        "parse",
        "started_at",
        "completed_at",
    }


# --- two sources, one fact ------------------------------------------------------------------------


def _keyed(mapping):
    """A parser that returns exactly the observations it is handed, per operation code."""

    def _parse(operation, payload):
        return mapping[operation.operation_code]

    return _parse


def _run_with(transport, operations, parse):
    return run_operation_sequence(
        transport=transport,
        operations=operations,
        target_authority_identity=AUTHORITY,
        parse=parse,
        started_at=START,
        completed_at=END,
    )


def test_per_node_mappings_merge_instead_of_the_first_node_winning():
    """The defect this rule exists for: ``node_capacity`` carries one field code and many nodes.

    Keeping the first would report a three-node cluster's first node as the whole cluster — a fact
    that looks complete and describes one node, which is worse than no fact at all.
    """
    ops = [GetNodeStatusOperation("pve-a", SRC), GetNodeStatusOperation("pve-b", SRC)]
    transport = _Fake({"/nodes/pve-a/status": {}, "/nodes/pve-b/status": {}})
    seen = iter(
        [
            {"node_capacity": Observation.observed({"pve-a": {"cpus": 8}})},
            {"node_capacity": Observation.observed({"pve-b": {"cpus": 16}})},
        ]
    )
    result = _run_with(transport, ops, lambda operation, payload: next(seen))

    assert result.observations["node_capacity"].is_usable is True
    assert result.observations["node_capacity"].value == {
        "pve-a": {"cpus": 8},
        "pve-b": {"cpus": 16},
    }


def test_two_sources_that_disagree_make_the_fact_malformed():
    """Silently preferring either source would hide a target answering inconsistently."""
    ops = [GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake({"/cluster/status": [], "/nodes": []})
    seen = iter(
        [
            {"node_names": Observation.observed(("pve-a", "pve-b"))},
            {"node_names": Observation.observed(("pve-a",))},
        ]
    )
    result = _run_with(transport, ops, lambda operation, payload: next(seen))

    obs = result.observations["node_names"]
    assert obs.is_usable is False
    assert obs.state is S.observed_malformed
    assert obs.reason_code == "source_disagreement:node_names"


def test_two_sources_that_agree_leave_the_fact_observed():
    ops = [GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake({"/cluster/status": [], "/nodes": []})
    seen = iter(
        [
            {"node_names": Observation.observed(("pve-a", "pve-b"))},
            {"node_names": Observation.observed(("pve-a", "pve-b"))},
        ]
    )
    result = _run_with(transport, ops, lambda operation, payload: next(seen))
    assert result.observations["node_names"].value == ("pve-a", "pve-b")


def test_mappings_that_collide_on_one_key_with_different_values_are_malformed():
    """A merge is not a licence to disagree: the same node reported twice, differently, is a
    disagreement even though the two mappings would otherwise combine cleanly."""
    ops = [GetNodeStatusOperation("pve-a", SRC), GetNodeVersionOperation("pve-a", SRC)]
    transport = _Fake({"/nodes/pve-a/status": {}, "/nodes/pve-a/version": {}})
    seen = iter(
        [
            {"node_versions": Observation.observed({"pve-a": "9.1.1"})},
            {"node_versions": Observation.observed({"pve-a": "8.4.0"})},
        ]
    )
    result = _run_with(transport, ops, lambda operation, payload: next(seen))

    obs = result.observations["node_versions"]
    assert obs.state is S.observed_malformed
    assert obs.reason_code == "source_disagreement:node_versions.pve-a"


def test_complementary_nested_views_of_one_object_merge_rather_than_contradict():
    """The cluster SDN index and the per-node runtime view both describe zone ``z1``, each with its
    own sub-keys. A shallow merge would compare the two sub-objects whole and call a complementary
    pair a contradiction, destroying the partial-visibility differential that reading both is for.
    """
    ops = [GetSdnZonesOperation(), GetNodeSdnZonesOperation("pve-a", SRC)]
    transport = _Fake({"/cluster/sdn/zones": [], "/nodes/pve-a/sdn/zones": []})
    seen = iter(
        [
            {
                "existing_sdn_zones": Observation.observed(
                    {"z1": {"cluster_index": {"type": "vlan"}}}
                )
            },
            {"existing_sdn_zones": Observation.observed({"z1": {"node_runtime": {"pve-a": "ok"}}})},
        ]
    )
    result = _run_with(transport, ops, lambda operation, payload: next(seen))

    obs = result.observations["existing_sdn_zones"]
    assert obs.is_usable is True
    assert obs.value == {"z1": {"cluster_index": {"type": "vlan"}, "node_runtime": {"pve-a": "ok"}}}


def test_a_disagreement_deep_inside_one_object_names_the_exact_path():
    ops = [GetSdnZonesOperation(), GetNodeSdnZonesOperation("pve-a", SRC)]
    transport = _Fake({"/cluster/sdn/zones": [], "/nodes/pve-a/sdn/zones": []})
    seen = iter(
        [
            {"existing_sdn_zones": Observation.observed({"z1": {"shared": {"tag": 100}}})},
            {"existing_sdn_zones": Observation.observed({"z1": {"shared": {"tag": 200}}})},
        ]
    )
    result = _run_with(transport, ops, lambda operation, payload: next(seen))

    obs = result.observations["existing_sdn_zones"]
    assert obs.state is S.observed_malformed
    assert obs.reason_code == "source_disagreement:existing_sdn_zones.z1.shared.tag"


def test_a_second_failure_does_not_relabel_the_first_reason():
    """Two failures of EQUAL severity resolve to the first, so a later one cannot silently relabel
    what an operator is being told to act on. (Unequal severities resolve by actionability — see
    the more-actionable test above.)"""

    class _Denied(Exception):
        pass

    ops = [GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake(
        {},
        errors={
            "/cluster/status": _Denied("proxmox_discovery_permission_denied"),
            "/nodes": _Denied("proxmox_discovery_transport_failed"),
        },
    )
    result = _run_with(transport, ops, _keyed({}))
    assert result.observations["node_names"].reason_code == "proxmox_discovery_permission_denied"
    assert result.failure_reason == "proxmox_discovery_permission_denied"


# --- every operation names the code that interpreted ITS payload ----------------------------------


def test_each_operation_records_its_own_parser_identity():
    """One shared parser id across every operation would be a false statement in signed evidence."""
    ops = [GetVersionOperation(), GetNodesOperation(), GetSdnZonesOperation()]
    transport = _Fake({"/version": {}, "/nodes": [], "/cluster/sdn/zones": []})
    result = _run(transport, ops)

    parsers = [r.parser_implementation_id for r in result.manifest.operations]
    normalizers = [r.normalizer_implementation_id for r in result.manifest.operations]
    assert len(set(parsers)) == 3, f"operations share a parser identity: {parsers}"
    assert len(set(normalizers)) == 3
    assert all(p for p in parsers)
    # And the recorded id is the operation's own, not a constant the composition chose.
    for record, operation in zip(result.manifest.operations, ops, strict=True):
        assert record.parser_implementation_id == operation.parser_implementation_id


def test_a_refused_operation_still_records_its_own_parser_identity():
    class _Denied(Exception):
        pass

    transport = _Fake({}, errors={"/cluster/sdn/zones": _Denied("x")})
    result = _run(transport, [GetSdnZonesOperation()])
    (record,) = result.manifest.operations
    assert record.parser_implementation_id == GetSdnZonesOperation.parser_implementation_id


def test_an_operation_that_names_no_parser_is_refused_before_the_request():
    """Fail closed, and BEFORE contacting the target: an operation that cannot say which code
    interprets its payload must not produce evidence at all, and a getattr default would let a newly
    added operation silently inherit somebody else's identity."""
    import pytest
    from secp_worker.proxmox_discovery_composition import DiscoveryCompositionError

    class _Unidentified:
        operation_code = "unidentified"
        path_template = "/version"
        observation_field_codes = ("pve_version_full",)

        def rendered_path(self):
            return "/version"

        def query_parameters(self):
            return ()

    transport = _Fake({"/version": {}})
    with pytest.raises(DiscoveryCompositionError, match="operation_parser_unidentified"):
        _run(transport, [_Unidentified()])
    assert transport.calls == [], "an unidentified operation reached the target"


def test_every_first_mvp_and_sdn_operation_declares_a_distinct_parser_identity():
    from secp_worker.proxmox_discovery_operations import FIRST_MVP_OPERATIONS
    from secp_worker.proxmox_sdn_operations import SDN_OPERATIONS

    all_ops = FIRST_MVP_OPERATIONS + SDN_OPERATIONS
    parsers = [op.parser_implementation_id for op in all_ops]
    normalizers = [op.normalizer_implementation_id for op in all_ops]
    assert len(set(parsers)) == len(all_ops), "two operations share a parser identity"
    assert len(set(normalizers)) == len(all_ops)


def test_every_recorded_operation_is_a_get_with_no_body():
    ops = [GetVersionOperation(), GetSdnZonesOperation(), GetNodeStatusOperation("pve-a", SRC)]
    transport = _Fake({"/version": {}, "/cluster/sdn/zones": [], "/nodes/pve-a/status": {}})
    result = _run(transport, ops)
    for record in result.manifest.operations:
        assert record.request_method == "GET"
        assert record.request_body_present is False
        assert record.rendered_argv == ()
