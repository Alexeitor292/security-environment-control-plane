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
    GetVersionOperation,
)
from secp_worker.proxmox_sdn_operations import GetSdnRootOperation, GetSdnZonesOperation

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


def test_a_failing_source_does_not_erase_a_good_answer_from_another():
    """Several operations contribute to the same fact.

    ``node_names`` comes from both /cluster/status and /nodes. If /nodes fails after
    /cluster/status succeeded, the fact must keep the observed value rather than being overwritten
    with a failure — otherwise adding a redundant source makes discovery worse.
    """

    class _Denied(Exception):
        pass

    ops = [GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake(
        {"/cluster/status": ["cluster-data"]},
        errors={"/nodes": _Denied("proxmox_discovery_request_refused")},
    )
    result = _run(transport, ops)
    assert result.observations["node_names"].is_usable is True
    assert result.observations["node_names"].value == ["cluster-data"]


def test_a_later_usable_observation_replaces_an_earlier_unusable_one():
    """The complement: a fact that failed from one source and succeeded from another is observed."""

    class _Denied(Exception):
        pass

    ops = [GetClusterStatusOperation(), GetNodesOperation()]
    transport = _Fake(
        {"/nodes": ["node-data"]},
        errors={"/cluster/status": _Denied("proxmox_discovery_request_refused")},
    )
    result = _run(transport, ops)
    assert result.observations["node_names"].is_usable is True
    assert result.observations["node_names"].value == ["node-data"]
    # And the fact only /cluster/status supplies stays failed.
    assert result.observations["cluster_identity"].state is S.probe_failed


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


def test_every_recorded_operation_is_a_get_with_no_body():
    ops = [GetVersionOperation(), GetSdnZonesOperation(), GetNodeStatusOperation("pve-a", SRC)]
    transport = _Fake({"/version": {}, "/cluster/sdn/zones": [], "/nodes/pve-a/status": {}})
    result = _run(transport, ops)
    for record in result.manifest.operations:
        assert record.request_method == "GET"
        assert record.request_body_present is False
        assert record.rendered_argv == ()
