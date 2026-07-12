"""Pure publication composition contract tests (ADR-016 / SECP-B10, PR A).

Framework-free and database-free: they exercise reconstruct/consistency/compose,
the determinism matrix, and every closed refusal code. No DB fixtures are used.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import json
from pathlib import Path

import pytest
from secp_api.environment_publication_contract import (
    ComposedPublication,
    PublicationContractError,
    compose_published_definition,
    reconstruct_canonical_topology,
)
from secp_scenario_schema import content_hash, validate_definition
from secp_scenario_schema.v1alpha1.models import API_VERSION as V1ALPHA1
from secp_scenario_schema.v1alpha2.models import (
    API_VERSION as V1ALPHA2,
)
from secp_scenario_schema.v1alpha2.models import (
    PUBLICATION_CONTRACT_VERSION,
)
from secp_scenario_schema.validator import SchemaValidationError

REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "apps" / "api" / "secp_api" / "environment_publication_contract.py"

TEMPLATE_ID = "44444444-4444-4444-8444-444444444444"


def base_definition() -> dict:
    return {
        "apiVersion": V1ALPHA2,
        "kind": "Environment",
        "metadata": {"name": "example-env"},
        "spec": {
            "teams": {"count": 1, "isolationPolicy": "strict"},
            "networks": [{"name": "net-a", "cidrStrategy": "per-team", "isolated": True}],
            "roles": [
                {"name": "attacker-1", "kind": "attacker", "image": "img-a", "network": "net-a"},
                {"name": "target-1", "kind": "target", "image": "img-t", "network": "net-a"},
            ],
            "requiredPlugins": ["simulator"],
        },
    }


def base_topology() -> dict:
    return {
        "schema_version": "secp.topology/v1",
        "nodes": [
            {"id": "attacker-1", "kind": "attacker", "network": "net-a", "x": 1, "y": 2},
            {"id": "target-1", "kind": "target", "network": "net-a", "x": 3, "y": 4},
            {"id": "net-a", "kind": "network"},
        ],
        "edges": [
            {"id": "e-att", "source": "attacker-1", "target": "net-a", "kind": "network"},
            {"id": "e-tgt", "source": "target-1", "target": "net-a", "kind": "network"},
        ],
        "networks": [{"id": "net-a", "isolated": True}],
        "zones": [{"id": "z1", "member_ids": ["attacker-1", "target-1"]}],
    }


def base_provenance() -> dict:
    return {
        "topology_document_id": "11111111-1111-4111-8111-111111111111",
        "topology_revision_id": "22222222-2222-4222-8222-222222222222",
        "topology_validation_result_id": "33333333-3333-4333-8333-333333333333",
        "topology_validation_result_hash": "sha256:" + "ab" * 32,
        "base_environment_version_id": None,
    }


def compose(
    *,
    definition: dict | None = None,
    topology: dict | None = None,
    provenance: dict | None = None,
    template_id: str = TEMPLATE_ID,
    expected_hash: str | None = None,
) -> ComposedPublication:
    definition = base_definition() if definition is None else definition
    topology = base_topology() if topology is None else topology
    provenance = base_provenance() if provenance is None else provenance
    if expected_hash is None:
        _, expected_hash = reconstruct_canonical_topology(topology)
    return compose_published_definition(
        definition=definition,
        topology_document_content=topology,
        expected_topology_content_hash=expected_hash,
        provenance=provenance,
        destination_template_id=template_id,
    )


# --- happy path + structure --------------------------------------------------------------------


def test_compose_produces_valid_v1alpha2_definition_with_both_blocks():
    result = compose()
    final = result.final_definition
    assert final["apiVersion"] == V1ALPHA2
    assert final["spec"]["topology"]["schema_version"] == "secp.topology/v1"
    prov = final["spec"]["publicationProvenance"]
    assert prov["publication_contract_version"] == PUBLICATION_CONTRACT_VERSION
    assert prov["topology_content_hash"] == result.topology_content_hash
    # the final definition re-validates under the v1alpha2 schema
    validate_definition(final)
    # environment hash is over the whole composed object
    assert result.environment_content_hash == content_hash(final)
    # result is frozen
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.environment_content_hash = "x"  # type: ignore[misc]


def test_provenance_block_excludes_event_metadata():
    prov = compose().final_definition["spec"]["publicationProvenance"]
    for forbidden in (
        "id",
        "created_by",
        "created_at",
        "audit_event_id",
        "version_number",
        "publication_fingerprint",
        "correlation_id",
        "idempotency_key",
    ):
        assert forbidden not in prov


# --- determinism matrix ------------------------------------------------------------------------


def test_reconstruction_is_order_independent():
    topo = base_topology()
    _, h1 = reconstruct_canonical_topology(topo)
    shuffled = copy.deepcopy(topo)
    shuffled["nodes"] = list(reversed(shuffled["nodes"]))
    shuffled["edges"] = list(reversed(shuffled["edges"]))
    shuffled["zones"][0]["member_ids"] = list(reversed(shuffled["zones"][0]["member_ids"]))
    canon2, h2 = reconstruct_canonical_topology(shuffled)
    assert h1 == h2
    assert [n["id"] for n in canon2["nodes"]] == sorted(n["id"] for n in canon2["nodes"])


def test_same_inputs_yield_byte_equivalent_outputs():
    a, b = compose(), compose()
    assert json.dumps(a.final_definition, sort_keys=True) == json.dumps(
        b.final_definition, sort_keys=True
    )
    assert a.environment_content_hash == b.environment_content_hash
    assert a.publication_fingerprint == b.publication_fingerprint


def test_changing_coordinates_changes_all_hashes():
    base = compose()
    topo = base_topology()
    topo["nodes"][0]["x"] = 999
    changed = compose(topology=topo)
    assert changed.topology_content_hash != base.topology_content_hash
    assert changed.environment_content_hash != base.environment_content_hash
    assert changed.publication_fingerprint != base.publication_fingerprint


def test_changing_edge_or_zone_membership_changes_hashes():
    base = compose()
    topo_edge = base_topology()
    topo_edge["edges"][0]["id"] = "e-renamed"
    assert compose(topology=topo_edge).environment_content_hash != base.environment_content_hash
    topo_zone = base_topology()
    topo_zone["zones"][0]["member_ids"] = ["attacker-1"]
    assert compose(topology=topo_zone).environment_content_hash != base.environment_content_hash


def test_changing_revision_id_changes_env_hash_and_fingerprint():
    base = compose()
    prov = base_provenance()
    prov["topology_revision_id"] = "99999999-9999-4999-8999-999999999999"
    other = compose(provenance=prov)
    assert other.environment_content_hash != base.environment_content_hash
    assert other.publication_fingerprint != base.publication_fingerprint


def test_changing_validation_result_id_changes_env_hash_and_fingerprint():
    base = compose()
    prov = base_provenance()
    prov["topology_validation_result_id"] = "88888888-8888-4888-8888-888888888888"
    other = compose(provenance=prov)
    assert other.environment_content_hash != base.environment_content_hash
    assert other.publication_fingerprint != base.publication_fingerprint


def test_changing_validation_result_hash_changes_env_hash_and_fingerprint():
    base = compose()
    prov = base_provenance()
    prov["topology_validation_result_hash"] = "sha256:" + "ef" * 32
    other = compose(provenance=prov)
    assert other.environment_content_hash != base.environment_content_hash
    assert other.publication_fingerprint != base.publication_fingerprint


def test_changing_template_changes_fingerprint_only():
    base = compose()
    other = compose(template_id="55555555-5555-4555-8555-555555555555")
    assert other.environment_content_hash == base.environment_content_hash
    assert other.publication_fingerprint != base.publication_fingerprint


def test_caller_input_dicts_are_not_mutated():
    definition, topology, provenance = base_definition(), base_topology(), base_provenance()
    def_before = copy.deepcopy(definition)
    topo_before = copy.deepcopy(topology)
    prov_before = copy.deepcopy(provenance)
    compose(definition=definition, topology=topology, provenance=provenance)
    assert definition == def_before
    assert topology == topo_before
    assert provenance == prov_before
    assert "topology" not in definition["spec"]


# --- refusals (closed codes) -------------------------------------------------------------------


def _assert_code(code: str, **kwargs):
    with pytest.raises(PublicationContractError) as exc:
        compose(**kwargs)
    assert exc.value.code == code
    return exc.value


def test_refuse_v1alpha1_definition():
    d = base_definition()
    d["apiVersion"] = V1ALPHA1
    _assert_code("version_publish_definition_invalid", definition=d)


def test_refuse_caller_supplied_topology():
    d = base_definition()
    d["spec"]["topology"] = base_topology()
    _assert_code("version_publish_topology_in_payload_forbidden", definition=d)


def test_refuse_caller_supplied_provenance():
    d = base_definition()
    d["spec"]["publicationProvenance"] = {"x": 1}
    _assert_code("version_publish_provenance_in_payload_forbidden", definition=d)


def test_refuse_unknown_definition_field():
    d = base_definition()
    d["spec"]["surprise"] = True
    _assert_code("version_publish_definition_invalid", definition=d)


def test_refuse_invalid_topology_schema():
    topo = base_topology()
    topo["nodes"][0]["kind"] = "not-a-kind"
    _assert_code("version_publish_topology_invalid", topology=topo)


def test_refuse_expected_topology_hash_mismatch():
    _assert_code("version_publish_topology_hash_mismatch", expected_hash="sha256:" + "00" * 32)


def test_refuse_definition_role_missing_from_topology():
    topo = base_topology()
    topo["nodes"] = [n for n in topo["nodes"] if n["id"] != "target-1"]
    topo["edges"] = [e for e in topo["edges"] if e["source"] != "target-1"]
    topo["zones"][0]["member_ids"] = ["attacker-1"]
    _assert_code("version_publish_role_topology_mismatch", topology=topo)


def test_refuse_topology_role_missing_from_definition():
    d = base_definition()
    d["spec"]["roles"] = [r for r in d["spec"]["roles"] if r["name"] != "target-1"]
    _assert_code("version_publish_role_topology_mismatch", definition=d)


def test_refuse_duplicate_logical_role():
    d = base_definition()
    d["spec"]["roles"][1]["name"] = "attacker-1"  # duplicate role name
    _assert_code("version_publish_role_topology_mismatch", definition=d)


def test_refuse_node_kind_mismatch():
    topo = base_topology()
    topo["nodes"][0]["kind"] = "sensor"  # role attacker-1 is 'attacker'
    _assert_code("version_publish_role_topology_mismatch", topology=topo)


def test_refuse_node_network_mismatch():
    topo = base_topology()
    topo["nodes"][0]["network"] = "net-a"  # keep valid
    d = base_definition()
    d["spec"]["networks"].append({"name": "net-b", "cidrStrategy": "per-team", "isolated": True})
    d["spec"]["roles"][0]["network"] = "net-b"  # role says net-b, node says net-a
    # net-b needs topology presence to avoid a network-set failure first; but the
    # role-node network check runs before network checks, so this yields the role code.
    _assert_code("version_publish_role_topology_mismatch", definition=d, topology=topo)


@pytest.mark.parametrize("kind", ["service", "gateway"])
def test_refuse_unsupported_role_kind(kind):
    d = base_definition()
    d["spec"]["roles"][0]["kind"] = kind
    topo = base_topology()
    # give the node a topology-valid kind; the role-kind guard fires first anyway
    topo["nodes"][0]["kind"] = "sensor"
    _assert_code("version_publish_unsupported_role_kind", definition=d, topology=topo)


def test_refuse_definition_network_missing_from_topology():
    d = base_definition()
    d["spec"]["networks"].append({"name": "net-b", "cidrStrategy": "per-team", "isolated": True})
    _assert_code("version_publish_network_topology_mismatch", definition=d)


def test_refuse_topology_network_absent_from_definition():
    topo = base_topology()
    topo["networks"].append({"id": "net-b", "isolated": True})
    topo["nodes"].append({"id": "net-b", "kind": "network"})
    _assert_code("version_publish_network_topology_mismatch", topology=topo)


def test_refuse_topology_network_id_mismatch():
    topo = base_topology()
    topo["networks"][0]["id"] = "net-x"
    _assert_code("version_publish_network_topology_mismatch", topology=topo)


def test_refuse_network_node_id_mismatch():
    topo = base_topology()
    for n in topo["nodes"]:
        if n["kind"] == "network":
            n["id"] = "net-x"
    _assert_code("version_publish_network_topology_mismatch", topology=topo)


def test_refuse_cidr_mismatch():
    d = base_definition()
    d["spec"]["networks"][0]["baseCidr"] = "10.0.0.0/24"
    topo = base_topology()
    topo["networks"][0]["cidr"] = "10.0.1.0/24"
    _assert_code("version_publish_network_topology_mismatch", definition=d, topology=topo)


def test_refuse_isolation_mismatch():
    d = base_definition()
    d["spec"]["networks"][0]["isolated"] = False
    topo = base_topology()
    topo["networks"][0]["isolated"] = True
    _assert_code("version_publish_network_topology_mismatch", definition=d, topology=topo)


def test_refuse_missing_attachment():
    topo = base_topology()
    topo["edges"] = [e for e in topo["edges"] if e["source"] != "target-1"]
    _assert_code("version_publish_network_topology_mismatch", topology=topo)


def test_refuse_ambiguous_attachment():
    topo = base_topology()
    topo["edges"].append(
        {"id": "e-dup", "source": "attacker-1", "target": "net-a", "kind": "network"}
    )
    _assert_code("version_publish_network_topology_mismatch", topology=topo)


def test_refuse_incorrect_network_edge_target_host():
    topo = base_topology()
    topo["edges"][0]["target"] = "target-1"  # a host node, not the network node
    _assert_code("version_publish_network_topology_mismatch", topology=topo)


def test_refuse_incorrect_network_edge_target_wrong_network():
    # two networks; attacker-1 (net-a) is attached to net-b instead.
    d = base_definition()
    d["spec"]["networks"].append({"name": "net-b", "cidrStrategy": "per-team", "isolated": True})
    topo = base_topology()
    topo["networks"].append({"id": "net-b", "isolated": True})
    topo["nodes"].append({"id": "net-b", "kind": "network"})
    topo["edges"][0]["target"] = "net-b"
    _assert_code("version_publish_network_topology_mismatch", definition=d, topology=topo)


def test_refuse_malformed_provenance_uuid():
    prov = base_provenance()
    prov["topology_revision_id"] = "not-a-uuid"
    _assert_code("version_publish_provenance_invalid", provenance=prov)


def test_refuse_malformed_provenance_hash():
    prov = base_provenance()
    prov["topology_validation_result_hash"] = "deadbeef"
    _assert_code("version_publish_provenance_invalid", provenance=prov)


def test_refuse_malformed_template_id():
    _assert_code("version_publish_provenance_invalid", template_id="not-a-uuid")


def test_unsupported_publication_contract_version_is_schema_rejected():
    # The composition always sets the locked constant; a hand-built definition
    # with a wrong version fails schema validation (closed structured error).
    result = compose()
    tampered = copy.deepcopy(result.final_definition)
    tampered["spec"]["publicationProvenance"]["publication_contract_version"] = (
        "secp.publication/v9"
    )
    with pytest.raises(SchemaValidationError):
        validate_definition(tampered)


# --- boundary: the pure contract imports no forbidden runtime/database modules -----------------


def test_publication_contract_imports_no_forbidden_modules():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    roots: set[str] = set()
    secp_api_modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
            if node.module.split(".")[0] == "secp_api":
                secp_api_modules.add(node.module)

    forbidden = {
        "sqlalchemy",
        "fastapi",
        "starlette",
        "httpx",
        "requests",
        "aiohttp",
        "subprocess",
        "socket",
        "ssl",
        "paramiko",
        "asyncssh",
        "boto3",
        "proxmoxer",
        "kubernetes",
        "docker",
        "secp_worker",
        "secp_plugin_proxmox",
        "secp_plugin_simulator",
    }
    assert not (roots & forbidden), f"forbidden imports: {roots & forbidden}"
    # The only permitted secp_api import is the pure topology contract.
    assert secp_api_modules <= {"secp_api.topology_authoring_contract"}, secp_api_modules


# --- fail-closed hardening: exception normalization at the public boundary ---------------------


def test_refuse_unsupported_publication_contract_version():
    prov = base_provenance()
    prov["publication_contract_version"] = "secp.publication/v9"
    _assert_code("version_publish_provenance_invalid", provenance=prov)


def test_refuse_provenance_missing_field():
    prov = base_provenance()
    del prov["topology_document_id"]
    _assert_code("version_publish_provenance_invalid", provenance=prov)


def test_refuse_provenance_unknown_field():
    prov = base_provenance()
    prov["surprise"] = "x"
    _assert_code("version_publish_provenance_invalid", provenance=prov)


def test_refuse_invalid_v1alpha2_definition():
    d = base_definition()
    d["spec"]["teams"]["count"] = 0  # violates minimum
    _assert_code("version_publish_definition_invalid", definition=d)


def test_typed_topology_envelope_validation_failure_maps_to_topology_invalid():
    topo = base_topology()
    topo["nodes"][0]["kind"] = "bad-kind"  # fails typed topology validation
    _assert_code("version_publish_topology_invalid", topology=topo)


def test_no_raw_validation_exception_escapes_the_public_boundary():
    # Each malformed input must surface ONLY as PublicationContractError — never a
    # raw pydantic ValidationError, jsonschema exception, SchemaValidationError,
    # KeyError, TypeError, or ValueError. pytest.raises(PublicationContractError)
    # fails the test if any other exception type propagates.
    malformed_cases = [
        {"definition": {"apiVersion": V1ALPHA2, "kind": "Environment"}},  # missing metadata/spec
        {"definition": "not-a-dict"},
        {"provenance": {**base_provenance(), "topology_revision_id": "not-a-uuid"}},
        {"provenance": {**base_provenance(), "topology_validation_result_hash": "nope"}},
        {"provenance": "not-a-mapping"},
        {"template_id": 12345},
        {"topology": {**base_topology(), "nodes": [{"id": "x", "kind": "bad", "x": 0, "y": 0}]}},
        {"topology": "not-a-mapping"},
    ]
    for case in malformed_cases:
        with pytest.raises(PublicationContractError):
            compose(**case)  # type: ignore[arg-type]


# --- fail-closed hardening: deep immutability of ComposedPublication ---------------------------


def test_final_definition_is_a_fresh_deep_copy_each_access():
    result = compose()
    first = result.final_definition
    first["metadata"]["name"] = "hacked"
    first["spec"]["roles"].append({"name": "injected"})
    second = result.final_definition
    assert second["metadata"]["name"] == "example-env"
    assert all(r.get("name") != "injected" for r in second["spec"]["roles"])
    assert second != first


def test_stored_env_hash_equals_content_hash_of_materialized_definition():
    result = compose()
    assert content_hash(result.final_definition) == result.environment_content_hash
    # ... and stays true even after mutating an earlier returned copy
    mutated = result.final_definition
    mutated["spec"]["teams"]["count"] = 999
    assert content_hash(result.final_definition) == result.environment_content_hash


def test_no_mutable_authoritative_snapshot_is_publicly_stored():
    result = compose()
    for field in dataclasses.fields(result):
        value = getattr(result, field.name)
        assert not isinstance(value, (dict, list)), (
            f"{field.name} is a mutable {type(value).__name__} snapshot"
        )


def test_fingerprint_stays_bound_to_the_immutable_snapshot():
    result = compose()
    # The fingerprint is derived from the snapshot's environment content hash and
    # the destination template; it cannot be separated from the canonical snapshot.
    assert result.publication_fingerprint == content_hash(
        {
            "template_id": TEMPLATE_ID,
            "environment_content_hash": content_hash(result.final_definition),
        }
    )
