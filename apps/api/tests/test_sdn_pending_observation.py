"""Stage 2, where two caller-assignable booleans become conclusions.

``PendingSdnDocument.signature_verified`` and ``.visibility_complete`` decide whether an activation
may be authorised at all, and on the dataclass they are fields — things a caller assigns. This file
pins that the production builder derives both, that no other module in the live tree constructs a
document, and that nothing observed is dropped on the way.
"""

from __future__ import annotations

import ast
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from secp_api.discovery_fact_projection import REQUIRED_FACT_PROJECTION_ID
from secp_api.discovery_observation import Observation
from secp_api.discovery_verification import (
    DISCOVERY_CONTRACT_VERSION,
    DISCOVERY_SNAPSHOT_DOMAIN,
    DISCOVERY_SNAPSHOT_KIND,
    DiscoverySnapshotBinding,
    ExpectedWorkerRegistration,
    verify_discovery_snapshot,
)
from secp_api.sdn_activation_stages import (
    PendingSdnDocument,
    PendingSdnOwnershipProofSet,
    SdnActivationRefused,
    issue_activation_authorization,
)
from secp_api.sdn_pending_observation import (
    PENDING_FAMILIES,
    UNIDENTIFIED,
    PendingObservationError,
    build_pending_sdn_document,
)
from secp_commissioning.canonical import sha256_digest
from secp_commissioning.enrollment_attestation import key_id_for, sign_detached
from secp_management.signing import generate_keypair

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
ORG = str(uuid.uuid4())
TARGET = str(uuid.uuid4())
WORKER = "wk-1"
OPERATION = "op-1"
GENERATION = 3
ROLE = "proxmox_privileged"
RELEASE = "sha256:" + "r" * 64
CLUSTER = "sha256:" + "c" * 64


def _pending_value() -> dict:
    return {
        "zones": (
            {
                "family": "zones",
                "object_id": "secpz1",
                "state": "new",
                "observed": {"zone": "secpz1", "type": "vlan", "bridge": "vmbr1"},
                "active": {},
            },
        ),
        "vnets": (),
        "controllers": (),
        "subnets@secpv1": (),
    }


def _raw(**overrides) -> dict[str, Observation]:
    base = {"pending_sdn_state": Observation.observed(_pending_value())}
    base.update(overrides)
    return base


def _facts(usable: bool = True) -> dict[str, Observation]:
    return {
        "pending_sdn_state": (
            Observation.observed(_pending_value())
            if usable
            else Observation.permission_denied(
                missing_privilege="SDN.Audit", reason_code="sdn_read_authority_not_established"
            )
        )
    }


def _authority():
    priv, pub = generate_keypair()
    binding = DiscoverySnapshotBinding(
        discovery_contract_version=DISCOVERY_CONTRACT_VERSION,
        operation_identity=OPERATION,
        operation_generation=GENERATION,
        organization_identity=ORG,
        target_identity=TARGET,
        requested_target_authority="pve.example.test:8006",
        worker_installation_id=WORKER,
        worker_role=ROLE,
        worker_release_fingerprint=RELEASE,
        signer_fingerprint=key_id_for(pub),
        observation_started_at=(NOW - timedelta(seconds=30)).isoformat(),
        observation_completed_at=(NOW - timedelta(seconds=10)).isoformat(),
        freshness_bound_seconds=1800,
        facts_hash=sha256_digest({"observations": []}),
        operation_manifest_hash=sha256_digest({"manifest": {}}),
        projection_implementation_id=REQUIRED_FACT_PROJECTION_ID,
        required_fact_observation_states=(),
    )
    attestation = sign_detached(
        priv,
        domain=DISCOVERY_SNAPSHOT_DOMAIN,
        kind=DISCOVERY_SNAPSHOT_KIND,
        digest=binding.digest(),
    )
    _projection, authority = verify_discovery_snapshot(
        binding=binding,
        attestation=attestation,
        registration=ExpectedWorkerRegistration(
            worker_installation_id=WORKER,
            worker_role=ROLE,
            worker_release_fingerprint=RELEASE,
            verification_anchor_fingerprint=key_id_for(pub),
            target_identity=TARGET,
            organization_identity=ORG,
        ),
        expected_operation_identity=OPERATION,
        expected_operation_generation=GENERATION,
        expected_target_identity=TARGET,
        expected_organization_identity=ORG,
        facts_hash=binding.facts_hash,
        operation_manifest_hash=binding.operation_manifest_hash,
        compilation_required_facts=(),
        apply_required_facts=(),
        now=NOW,
    )
    assert authority is not None
    return authority


def _build(**overrides):
    kwargs = dict(
        authority=_authority(),
        required_facts=_facts(),
        raw_observations=_raw(),
        cluster_fingerprint=CLUSTER,
        observed_at=NOW,
    )
    kwargs.update(overrides)
    return build_pending_sdn_document(**kwargs)


# === the booleans are conclusions =================================================================


def test_the_builder_requires_the_verifiers_authority_not_a_claim():
    """A caller cannot assert that a snapshot verified; it can only hand over what the verifier
    issued, and that object cannot be constructed, pickled or forged."""
    with pytest.raises(PendingObservationError, match="requires_a_verified_snapshot"):
        _build(authority=object())
    with pytest.raises(PendingObservationError):
        _build(authority=None)


def test_the_builder_takes_no_signature_or_visibility_parameter():
    import inspect

    params = set(inspect.signature(build_pending_sdn_document).parameters)
    for banned in ("signature_verified", "visibility_complete", "objects", "target_identity"):
        assert banned not in params, banned


def test_identity_is_read_off_the_signed_binding_not_supplied():
    """A document cannot claim a target the signature did not cover."""
    document = _build()
    assert document.target_identity == TARGET
    assert document.observation_identity == OPERATION
    assert document.worker_installation_id == WORKER
    assert document.worker_release_fingerprint == RELEASE
    assert document.signature_verified is True


def test_visibility_is_the_same_completeness_compilation_is_gated_on():
    assert _build().visibility_complete is True
    refused = _build(required_facts=_facts(usable=False))
    assert refused.visibility_complete is False


def test_an_incomplete_enumeration_names_the_families_an_operator_must_grant_for():
    """The refusal reason alone says only that something was missing."""
    partial = {"zones": (), "vnets": ()}
    document = _build(
        raw_observations={"pending_sdn_state": Observation.observed(partial)},
        required_facts=_facts(usable=False),
    )
    missing = {family for family, _state in document.unreadable_families}
    assert missing == {"subnets", "controllers"}
    for _family, state in document.unreadable_families:
        assert state == "permission_denied"


def test_subnets_count_as_covered_only_via_a_per_vnet_scope():
    document = _build()
    assert document.unreadable_families == ()
    assert set(PENDING_FAMILIES) == {"zones", "vnets", "subnets", "controllers"}


def test_the_control_plane_family_list_matches_the_workers():
    """The list is restated because the plane boundary forbids the control plane importing worker
    internals, and a restatement is a second copy that can drift.

    This is the only place both copies are read at once. Two tests each comparing its own copy to
    the same literal would both keep passing while the two lists said different things — which is
    exactly how a family would stop being enumerated on one side and stay required on the other.
    """
    from secp_worker.proxmox_sdn_operations import SDN_PENDING_FAMILIES

    assert PENDING_FAMILIES == SDN_PENDING_FAMILIES


def test_a_cluster_with_no_vnets_has_no_subnets_to_walk():
    """The document must not contradict itself: reporting subnets unreadable while the required-fact
    projection computes visibility as complete from the same facts is output an operator is right
    not to trust. With zero vnets there is nothing to walk, and that is coverage."""
    value = {"zones": (), "vnets": (), "controllers": ()}
    document = _build(
        raw_observations={
            "pending_sdn_state": Observation.observed(value),
            "existing_vnets": Observation.observed({}),
        }
    )
    assert document.visibility_complete is True
    assert document.unreadable_families == ()


def test_an_unwalked_vnet_still_makes_subnets_unreadable():
    """The complement, and the reason the rule above is about ZERO vnets specifically."""
    value = {"zones": (), "vnets": (), "controllers": ()}
    document = _build(
        raw_observations={
            "pending_sdn_state": Observation.observed(value),
            "existing_vnets": Observation.observed({"v1": {}}),
        }
    )
    assert ("subnets", "observed") in document.unreadable_families


def test_subnets_are_unreadable_when_the_vnet_index_itself_was_not_observed():
    value = {"zones": (), "vnets": (), "controllers": ()}
    document = _build(
        raw_observations={
            "pending_sdn_state": Observation.observed(value),
            "existing_vnets": Observation.probe_failed("x"),
        }
    )
    assert ("subnets", "observed") in document.unreadable_families


# === nothing observed is dropped ==================================================================


def test_every_observed_pending_object_becomes_a_document_object():
    document = _build()
    assert [(o.family, o.object_id, o.action) for o in document.objects] == [
        ("zones", "secpz1", "new")
    ]
    (obj,) = document.objects
    assert obj.source_endpoint == "/cluster/sdn/zones"
    assert obj.normalized_pending_representation
    assert obj.raw_result_digest


def test_an_unidentifiable_object_is_kept_and_marked_rather_than_dropped():
    """It still occupies the cluster. Dropping it would shrink the pending set that exclusivity is
    judged on, turning a contaminated cluster into a clean-looking one."""
    value = {
        "zones": (
            {"family": "zones", "object_id": "", "state": "new", "observed": {"type": "vlan"}},
        ),
        "vnets": (),
        "controllers": (),
        "subnets@v1": (),
    }
    document = _build(raw_observations={"pending_sdn_state": Observation.observed(value)})
    (obj,) = document.objects
    assert obj.object_id == ""
    assert obj.observation_state == UNIDENTIFIED


def test_a_subnet_scope_records_the_vnet_it_came_from():
    value = {
        "zones": (),
        "vnets": (),
        "controllers": (),
        "subnets@secpv1": (
            {"family": "subnets", "object_id": "s1", "state": "new", "observed": {"cidr": "x"}},
        ),
    }
    document = _build(raw_observations={"pending_sdn_state": Observation.observed(value)})
    (obj,) = document.objects
    assert obj.family == "subnets"
    assert obj.source_endpoint == "/cluster/sdn/vnets/secpv1/subnets"


def test_the_running_and_post_activation_views_are_hashed_separately():
    """A changed object's two views must not collapse into one digest, or the manifest could not
    say what activation would replace."""
    value = {
        "zones": (
            {
                "family": "zones",
                "object_id": "z1",
                "state": "changed",
                "observed": {"mtu": 9000},
                "active": {"mtu": 1500},
            },
        ),
        "vnets": (),
        "controllers": (),
        "subnets@v1": (),
    }
    document = _build(raw_observations={"pending_sdn_state": Observation.observed(value)})
    (obj,) = document.objects
    assert obj.normalized_active_representation
    assert obj.normalized_pending_representation
    assert obj.normalized_active_representation != obj.normalized_pending_representation


def test_an_unusable_pending_observation_produces_an_empty_but_honest_document():
    """Empty objects plus visibility_complete False. The activation constructor refuses on both,
    so an unreadable cluster cannot be mistaken for one with nothing pending."""
    document = _build(
        raw_observations={"pending_sdn_state": Observation.probe_failed("x")},
        required_facts=_facts(usable=False),
    )
    assert document.objects == ()
    assert document.visibility_complete is False
    with pytest.raises(SdnActivationRefused, match="visibility_incomplete"):
        issue_activation_authorization(
            document=document,
            proofs=PendingSdnOwnershipProofSet(),
            operation=_operation(),
            authorized_at=NOW,
            authorized_by="operator",
        )


def _operation():
    from secp_api.sdn_activation_stages import OperationBinding

    return OperationBinding(
        target_identity=TARGET,
        cluster_fingerprint=CLUSTER,
        range_identity="range-1",
        operation_identity=OPERATION,
        operation_generation=GENERATION,
        stage1_workspace_hash="sha256:" + "w" * 64,
        stage1_plan_hash="sha256:" + "p" * 64,
        stage1_authorization_id="auth-1",
        stage1_execution_receipt="receipt-1",
    )


# === no second construction site ==================================================================


_ALLOWED_CONSTRUCTION_SITES = frozenset(
    {
        "sdn_activation_stages.py",  # the definition itself
        "sdn_pending_observation.py",  # the derivation
    }
)


def test_no_other_module_in_the_live_tree_constructs_a_pending_document():
    """Inverted on purpose. Listing the modules allowed to build one is a closed set that a new
    module silently joins; scanning every module for the construction and allowing two is a check a
    new module has to be deliberately added to.
    """
    root = Path(__file__).resolve().parents[3]
    offenders = []
    for path in root.rglob("*.py"):
        parts = set(path.parts)
        if "tests" in parts or "__pycache__" in parts or ".venv" in parts:
            continue
        if path.name in _ALLOWED_CONSTRUCTION_SITES:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "PendingSdnDocument":
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == [], offenders


def test_the_definition_still_carries_the_two_fields_this_module_derives():
    """Renaming or removing either field would make the derivation silently stop applying."""
    import dataclasses

    names = {f.name for f in dataclasses.fields(PendingSdnDocument)}
    assert {"signature_verified", "visibility_complete", "unreadable_families"} <= names
