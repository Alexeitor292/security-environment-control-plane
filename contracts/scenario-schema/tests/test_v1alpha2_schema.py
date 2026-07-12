"""Pure scenario-schema tests for controlplane.security/v1alpha2 (ADR-016, PR A).

These import ONLY secp_scenario_schema (no secp_api / DB): validator dispatch,
v1alpha1 compatibility, the additive typed topology + publicationProvenance
blocks, and whole-definition content hashing.
"""

from __future__ import annotations

import copy

import pytest
from secp_scenario_schema import canonicalize, content_hash, validate_definition
from secp_scenario_schema.v1alpha1.models import API_VERSION as V1ALPHA1
from secp_scenario_schema.v1alpha2.models import (
    API_VERSION as V1ALPHA2,
)
from secp_scenario_schema.v1alpha2.models import (
    PUBLICATION_CONTRACT_VERSION,
    TOPOLOGY_SCHEMA_VERSION,
)
from secp_scenario_schema.v1alpha2.models import (
    EnvironmentDefinition as EnvironmentDefinitionV2,
)
from secp_scenario_schema.validator import SUPPORTED_API_VERSIONS, SchemaValidationError


def _v1alpha1_definition() -> dict:
    return {
        "apiVersion": V1ALPHA1,
        "kind": "Environment",
        "metadata": {"name": "example-env"},
        "spec": {
            "teams": {"count": 1, "isolationPolicy": "strict"},
            "networks": [{"name": "net-a", "cidrStrategy": "per-team"}],
            "roles": [{"name": "r1", "kind": "target", "image": "img", "network": "net-a"}],
            "requiredPlugins": ["simulator"],
        },
    }


def _v1alpha2_topology() -> dict:
    return {
        "schema_version": TOPOLOGY_SCHEMA_VERSION,
        "nodes": [
            {
                "id": "net-a",
                "kind": "network",
                "label": "net-a",
                "role": None,
                "ip": None,
                "network": None,
                "x": 0,
                "y": 0,
            },
            {
                "id": "r1",
                "kind": "target",
                "label": "r1",
                "role": None,
                "ip": None,
                "network": "net-a",
                "x": 1,
                "y": 2,
            },
        ],
        "edges": [{"id": "e1", "source": "r1", "target": "net-a", "kind": "network"}],
        "networks": [{"id": "net-a", "label": "net-a", "cidr": None, "isolated": True}],
        "zones": [],
    }


def _v1alpha2_provenance() -> dict:
    return {
        "topology_document_id": "11111111-1111-4111-8111-111111111111",
        "topology_revision_id": "22222222-2222-4222-8222-222222222222",
        "topology_content_hash": "sha256:" + "ab" * 32,
        "topology_validation_result_id": "33333333-3333-4333-8333-333333333333",
        "topology_validation_result_hash": "sha256:" + "cd" * 32,
        "base_environment_version_id": None,
        "publication_contract_version": PUBLICATION_CONTRACT_VERSION,
    }


def _v1alpha2_full() -> dict:
    d = _v1alpha1_definition()
    d["apiVersion"] = V1ALPHA2
    d["spec"]["topology"] = _v1alpha2_topology()
    d["spec"]["publicationProvenance"] = _v1alpha2_provenance()
    return d


# --- v1alpha1 unchanged ------------------------------------------------------------------------


def test_both_versions_supported_and_distinct():
    assert V1ALPHA1 != V1ALPHA2
    assert set(SUPPORTED_API_VERSIONS) == {V1ALPHA1, V1ALPHA2}


def test_v1alpha1_still_validates():
    m = validate_definition(_v1alpha1_definition())
    assert m.apiVersion == V1ALPHA1
    assert m.spec.teams.count == 1


def test_v1alpha1_hash_is_stable_and_order_independent():
    d = _v1alpha1_definition()
    reordered = {k: d[k] for k in reversed(list(d.keys()))}
    assert content_hash(d) == content_hash(reordered)
    assert canonicalize(d) == canonicalize(reordered)


def test_v1alpha1_rejects_topology_and_provenance_fields():
    # v1alpha1 is unchanged: it does NOT accept the new blocks.
    d = _v1alpha1_definition()
    d["spec"]["topology"] = _v1alpha2_topology()
    with pytest.raises(SchemaValidationError):
        validate_definition(d)


def test_unsupported_api_version_rejected():
    d = _v1alpha1_definition()
    d["apiVersion"] = "controlplane.security/v2"
    with pytest.raises(SchemaValidationError):
        validate_definition(d)


# --- v1alpha2 additive blocks ------------------------------------------------------------------


def test_v1alpha2_non_topology_validates():
    d = _v1alpha1_definition()
    d["apiVersion"] = V1ALPHA2
    m = validate_definition(d)
    assert isinstance(m, EnvironmentDefinitionV2)
    assert m.apiVersion == V1ALPHA2
    assert m.spec.topology is None and m.spec.publicationProvenance is None


def test_v1alpha2_full_with_topology_and_provenance_validates():
    m = validate_definition(_v1alpha2_full())
    assert isinstance(m, EnvironmentDefinitionV2)
    assert m.spec.topology is not None
    assert m.spec.topology.schema_version == TOPOLOGY_SCHEMA_VERSION
    assert m.spec.publicationProvenance is not None
    assert m.spec.publicationProvenance.publication_contract_version == PUBLICATION_CONTRACT_VERSION


def test_v1alpha2_unknown_top_field_rejected():
    d = _v1alpha2_full()
    d["spec"]["unexpectedField"] = True
    with pytest.raises(SchemaValidationError):
        validate_definition(d)


def test_v1alpha2_unknown_topology_field_rejected():
    d = _v1alpha2_full()
    d["spec"]["topology"]["nodes"][0]["surprise"] = 1
    with pytest.raises(SchemaValidationError):
        validate_definition(d)


def test_v1alpha2_unsupported_publication_contract_version_rejected():
    d = _v1alpha2_full()
    d["spec"]["publicationProvenance"]["publication_contract_version"] = "secp.publication/v99"
    with pytest.raises(SchemaValidationError):
        validate_definition(d)


def test_v1alpha2_malformed_provenance_uuid_rejected():
    d = _v1alpha2_full()
    d["spec"]["publicationProvenance"]["topology_revision_id"] = "not-a-uuid"
    with pytest.raises(SchemaValidationError):
        validate_definition(d)


def test_v1alpha2_malformed_provenance_hash_rejected():
    d = _v1alpha2_full()
    d["spec"]["publicationProvenance"]["topology_content_hash"] = "deadbeef"
    with pytest.raises(SchemaValidationError):
        validate_definition(d)


def test_v1alpha2_wrong_topology_schema_version_rejected():
    d = _v1alpha2_full()
    d["spec"]["topology"]["schema_version"] = "secp.topology/v2"
    with pytest.raises(SchemaValidationError):
        validate_definition(d)


# --- whole-definition hashing ------------------------------------------------------------------


def test_content_hash_covers_the_whole_definition_object():
    d = _v1alpha2_full()
    base = content_hash(d)
    for mutate in (
        lambda x: x["metadata"].__setitem__("name", "renamed-env"),
        lambda x: x["spec"]["topology"]["nodes"][1].__setitem__("x", 999),
        lambda x: x["spec"]["publicationProvenance"].__setitem__(
            "topology_revision_id", "99999999-9999-4999-8999-999999999999"
        ),
    ):
        mutated = copy.deepcopy(d)
        mutate(mutated)
        assert content_hash(mutated) != base
