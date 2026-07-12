"""Shared validation-result hashing compatibility (SECP-B10 / ADR-016 PR B, deliverable 6).

The authoritative ``TopologyValidationResult.result_hash`` algorithm was extracted into the
pure ``topology_validation_result_hash`` helper so publication can re-verify byte-for-byte
what authoring recorded. These tests pin the canonical byte format (so a refactor can't
silently change historical hashes) and prove the authoring service delegates to the helper.
"""

from __future__ import annotations

import hashlib
import json

from secp_api.topology_authoring_contract import topology_validation_result_hash


def _legacy_result_hash(content_hash, status, findings):
    """The pre-extraction inline algorithm, reproduced independently as the compat oracle."""
    payload = json.dumps(
        {"content_hash": content_hash, "status": status, "findings": findings},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


CASES = [
    ("sha256:" + "0" * 64, "valid", []),
    (
        "sha256:" + "a" * 64,
        "valid_with_warnings",
        [{"code": "idle_sensor", "severity": "warning", "node_id": "s1"}],
    ),
    (
        "sha256:deadbeef",
        "invalid",
        [
            {"code": "unattached_host", "severity": "error", "node_id": "h2"},
            {"code": "empty_network", "severity": "warning", "node_id": "n9"},
        ],
    ),
    # non-ASCII must round-trip identically (ensure_ascii=False is part of the contract)
    ("sha256:unicode", "valid", [{"code": "note", "message": "café–naïve"}]),
]


def test_helper_matches_legacy_byte_format():
    for content_hash, status, findings in CASES:
        assert topology_validation_result_hash(
            content_hash, status, findings
        ) == _legacy_result_hash(content_hash, status, findings)


def test_helper_is_deterministic_and_prefixed():
    for content_hash, status, findings in CASES:
        h1 = topology_validation_result_hash(content_hash, status, findings)
        h2 = topology_validation_result_hash(content_hash, status, findings)
        assert h1 == h2
        assert h1.startswith("sha256:")


def test_helper_is_sensitive_to_each_field():
    base = topology_validation_result_hash("sha256:x", "valid", [])
    assert base != topology_validation_result_hash("sha256:y", "valid", [])
    assert base != topology_validation_result_hash("sha256:x", "valid_with_warnings", [])
    assert base != topology_validation_result_hash("sha256:x", "valid", [{"code": "a"}])


def test_authoring_service_stored_hash_equals_helper(session, principal):
    """A validation result produced by the service carries exactly the helper's hash."""
    from secp_api.services import topology_authoring as topo
    from secp_api.topology_authoring_models import TopologyRevision

    topology = {
        "schema_version": "secp.topology/v1",
        "nodes": [
            {"id": "attacker-1", "kind": "attacker", "network": "net-a", "x": 1, "y": 1},
            {"id": "net-a", "kind": "network"},
        ],
        "edges": [{"id": "e", "source": "attacker-1", "target": "net-a", "kind": "network"}],
        "networks": [{"id": "net-a", "isolated": True}],
        "zones": [],
    }
    doc = topo.create_draft(session, principal, display_name="d", document=topology)
    revision = session.get(TopologyRevision, doc.current_revision_id)
    result = topo.validate_revision(
        session, principal, doc.id, revision.id, expected_content_hash=revision.content_hash
    )
    session.flush()

    expected = topology_validation_result_hash(
        result.content_hash, result.status.value, result.findings
    )
    assert result.result_hash == expected
