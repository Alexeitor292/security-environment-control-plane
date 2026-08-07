"""Stage 2, where two stampable booleans became conclusions drawn from a signature.

The defect, stated as the attack a verifier reproduced end to end: a caller holding a GENUINE
``VerifiedDiscoverySnapshot`` — whose signed binding stated ``pending_sdn_state`` was
``permission_denied``, the worker's attestation that it could not see the pending state — handed
``build_pending_sdn_document`` contradicting raw mappings and received a document reporting
``signature_verified=True``, ``visibility_complete=True``, ``unreadable_families=()``.
``issue_activation_authorization`` gates on exactly those two booleans, so the worker's signed
refusal became "nothing is pending" and the cluster-wide ``PUT /cluster/sdn`` blast radius was
judged against a pending set nobody observed.

Both booleans are now read-only properties backed by an ``AuthenticatedPendingContent`` that only
content whose recomputed commitment equals the signed ``facts_hash`` can produce, and the visibility
claim is read from inside the signature rather than from the caller's own projection.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from _sdn_authentication import (
    DEFAULT_CLUSTER_IDENTITY,
    DEFAULT_OPERATION,
    DEFAULT_RELEASE,
    DEFAULT_TARGET,
    DEFAULT_WORKER,
    NOW,
    cluster_fingerprint,
    signed_snapshot,
)
from secp_api.discovery_observation import Observation
from secp_api.sdn_activation_stages import (
    AuthenticatedPendingContent,
    OperationBinding,
    PendingSdnDocument,
    PendingSdnOwnershipProofSet,
    SdnActivationRefused,
    issue_activation_authorization,
)
from secp_api.sdn_pending_observation import (
    PENDING_FAMILIES,
    UNIDENTIFIED,
    PendingObservationError,
    authenticate_pending_content,
    build_pending_sdn_document,
)


def _pending_value(**overrides) -> dict:
    base = {
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
        "fabrics": (),
        "subnets@secpv1": (),
    }
    base.update(overrides)
    return base


def _observations(pending=None, **overrides) -> dict[str, Observation]:
    base = {
        "cluster_identity": Observation.observed(dict(DEFAULT_CLUSTER_IDENTITY)),
        "pending_sdn_state": Observation.observed(_pending_value() if pending is None else pending),
    }
    base.update(overrides)
    return base


def _build(*, pending_sdn_state="observed", observations=None, **snapshot_kwargs):
    """Sign the content, verify it, then build the document from it. The whole real path."""
    observations = observations if observations is not None else _observations()
    authority, obs, required, contributions = signed_snapshot(
        observations=observations, pending_sdn_state=pending_sdn_state, **snapshot_kwargs
    )
    return build_pending_sdn_document(
        authority=authority,
        observations=obs,
        required_facts=required,
        contributions=contributions,
    )


# === the booleans are not data ====================================================================


def test_the_document_exposes_no_way_to_stamp_either_boolean():
    """Not a field, not a keyword, not an assignable attribute."""
    import dataclasses

    fields = {f.name for f in dataclasses.fields(PendingSdnDocument)}
    assert "signature_verified" not in fields
    assert "visibility_complete" not in fields

    with pytest.raises(TypeError):
        PendingSdnDocument(
            observed_at=NOW,
            target_identity=DEFAULT_TARGET,
            cluster_fingerprint="x",
            observation_identity="o",
            worker_installation_id="w",
            worker_release_fingerprint="r",
            signature_verified=True,  # type: ignore[call-arg]
        )

    document = _build()
    with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
        document.signature_verified = True  # type: ignore[misc]


def test_an_unauthenticated_document_is_not_verified_and_not_visible():
    """The default is refusal, so a document nobody authenticated cannot pass the gate."""
    document = PendingSdnDocument(
        observed_at=NOW,
        target_identity=DEFAULT_TARGET,
        cluster_fingerprint="x",
        observation_identity="o",
        worker_installation_id="w",
        worker_release_fingerprint="r",
    )
    assert document.signature_verified is False
    assert document.visibility_complete is False


def test_the_authenticated_type_cannot_be_constructed_or_mutated():
    """Every escape the review demonstrated on the authority type, closed here too."""
    with pytest.raises(SdnActivationRefused):
        AuthenticatedPendingContent(object(), facts_hash="x", pending_sdn_state="observed")
    with pytest.raises(SdnActivationRefused):

        class _Forged(AuthenticatedPendingContent):  # type: ignore[misc]
            pass

    real = _build().authentication
    with pytest.raises(SdnActivationRefused):
        real.__setattr__("_AuthenticatedPendingContent__pending_sdn_state", "observed")
    with pytest.raises(SdnActivationRefused):
        real.__reduce__()


def test_an_object_new_allocation_passes_isinstance_and_still_authenticates_nothing():
    """Python offers no way to forbid ``object.__new__(cls)``, so the guard must not be isinstance.

    The allocation is a real instance of the type — every ``isinstance`` check accepts it — and its
    slots are unset, so the document reads it as unauthenticated. This is the same lesson as the
    closed-set guards: check the property, not the label.
    """
    forged = object.__new__(AuthenticatedPendingContent)
    assert isinstance(forged, AuthenticatedPendingContent)

    document = PendingSdnDocument(
        observed_at=NOW,
        target_identity=DEFAULT_TARGET,
        cluster_fingerprint="x",
        observation_identity="o",
        worker_installation_id="w",
        worker_release_fingerprint="r",
        authentication=forged,
    )
    assert document.signature_verified is False
    assert document.visibility_complete is False

    with pytest.raises(SdnActivationRefused, match="unsigned"):
        issue_activation_authorization(
            document=document,
            proofs=PendingSdnOwnershipProofSet(),
            operation=_operation(),
            authorized_at=NOW,
            authorized_by="operator",
        )


# === THE ATTACK: a signed refusal cannot become a visibility claim ================================


def test_a_binding_declaring_permission_denied_cannot_authenticate_complete_visibility():
    """The exact reproduction, now refused.

    The worker signs ``pending_sdn_state = permission_denied``. The content it signed is offered
    honestly, so it authenticates — and the resulting document still reports visibility as
    INCOMPLETE, because the claim is read out of the signature rather than recomputed beside it.
    """
    document = _build(pending_sdn_state="permission_denied")

    assert document.signature_verified is True  # the signature really is valid ...
    assert document.visibility_complete is False  # ... and it says the read was denied
    assert set(document.unreadable_families) == {
        (family, "permission_denied") for family in PENDING_FAMILIES
    }

    with pytest.raises(SdnActivationRefused, match="visibility_incomplete"):
        issue_activation_authorization(
            document=document,
            proofs=PendingSdnOwnershipProofSet(),
            operation=_operation(),
            authorized_at=NOW,
            authorized_by="operator",
        )


def test_contradicting_the_signed_content_refuses_rather_than_authenticating():
    """The other half: content that was never signed does not authenticate, however it is labelled.

    A caller holding a genuine authority swaps in a pending set of its own invention. The recomputed
    commitment no longer equals the signed facts_hash, so no authenticated content is produced at
    all — there is nothing to stamp a document with.
    """
    authority, obs, required, contributions = signed_snapshot(observations=_observations())
    invented = dict(obs)
    invented["pending_sdn_state"] = Observation.observed(_pending_value(zones=()))

    with pytest.raises(PendingObservationError, match="does_not_match_the_signed_facts"):
        authenticate_pending_content(
            authority=authority,
            observations=invented,
            required_facts=required,
            contributions=contributions,
        )
    with pytest.raises(PendingObservationError, match="does_not_match_the_signed_facts"):
        build_pending_sdn_document(
            authority=authority,
            observations=invented,
            required_facts=required,
            contributions=contributions,
        )


def test_a_signature_over_a_different_target_does_not_authenticate_this_content():
    """The binding is inside the commitment, so a snapshot of another target cannot be reused."""
    authority, obs, required, contributions = signed_snapshot(
        observations=_observations(), target_identity="target-elsewhere", facts_hash="sha256:wrong"
    )
    with pytest.raises(PendingObservationError, match="does_not_match_the_signed_facts"):
        build_pending_sdn_document(
            authority=authority,
            observations=obs,
            required_facts=required,
            contributions=contributions,
        )


def test_the_builder_requires_the_verifiers_authority_not_a_claim():
    with pytest.raises(PendingObservationError, match="requires_a_verified_snapshot"):
        build_pending_sdn_document(
            authority=object(),  # type: ignore[arg-type]
            observations={},
            required_facts={},
            contributions={},
        )


def test_the_builder_takes_no_stampable_parameter():
    import inspect

    params = set(inspect.signature(build_pending_sdn_document).parameters)
    for banned in (
        "signature_verified",
        "visibility_complete",
        "objects",
        "target_identity",
        "cluster_fingerprint",
        "observed_at",
        "unreadable_families",
    ):
        assert banned not in params, banned
    assert params == {"authority", "observations", "required_facts", "contributions"}


# === identity and freshness come off the binding ==================================================


def test_identity_is_read_off_the_signed_binding():
    document = _build()
    assert document.target_identity == DEFAULT_TARGET
    assert document.observation_identity == DEFAULT_OPERATION
    assert document.worker_installation_id == DEFAULT_WORKER
    assert document.worker_release_fingerprint == DEFAULT_RELEASE


def test_the_observation_time_is_the_signed_one_not_a_parameter():
    """Freshness is enforced on observed_at, so a caller who set it could revive a stale read."""
    document = _build()
    authority, _o, _r, _c = signed_snapshot(observations=_observations())
    assert document.observed_at.isoformat() == authority.binding.observation_completed_at


def test_the_cluster_fingerprint_matches_the_workers_derivation():
    """Two implementations of the same derivation, pinned against each other. If they drift, no
    content ever authenticates again — which is loud, but this test says why."""
    observations = _observations()
    document = _build(observations=observations)
    assert document.cluster_fingerprint == cluster_fingerprint(observations)
    assert document.cluster_fingerprint.startswith("sha256:")


# === nothing observed is dropped ==================================================================


def test_every_observed_pending_object_becomes_a_document_object():
    document = _build()
    # The action is DERIVED from the two views, not copied from the target's own annotation: the
    # row is labelled "new" and the pair (pending present, active absent) makes it a create.
    assert [(o.family, o.object_id, o.action) for o in document.objects] == [
        ("zones", "secpz1", "create")
    ]
    (obj,) = document.objects
    assert obj.target_state == "new"
    assert obj.source_endpoint == "/cluster/sdn/zones"
    assert obj.normalized_pending_representation
    assert obj.raw_result_digest


def test_an_unidentifiable_object_is_kept_and_marked_rather_than_dropped():
    """It still occupies the cluster. Dropping it would shrink the pending set that exclusivity is
    judged on, turning a contaminated cluster into a clean-looking one."""
    nameless = {"family": "zones", "object_id": "", "state": "new", "observed": {"type": "vlan"}}
    document = _build(observations=_observations(pending=_pending_value(zones=(nameless,))))
    (obj,) = document.objects
    assert obj.object_id == ""
    assert obj.observation_state == UNIDENTIFIED


def test_a_subnet_scope_records_the_vnet_it_came_from():
    rows = {"family": "subnets", "object_id": "s1", "state": "new", "observed": {"cidr": "x"}}
    pending = _pending_value(zones=())
    pending["subnets@secpv1"] = (rows,)
    document = _build(observations=_observations(pending=pending))
    (obj,) = document.objects
    assert obj.family == "subnets"
    assert obj.source_endpoint == "/cluster/sdn/vnets/secpv1/subnets"


def test_the_running_and_post_activation_views_are_hashed_separately():
    changed = {
        "family": "zones",
        "object_id": "z1",
        "state": "changed",
        "observed": {"mtu": 9000},
        "active": {"mtu": 1500},
    }
    document = _build(observations=_observations(pending=_pending_value(zones=(changed,))))
    (obj,) = document.objects
    assert obj.normalized_active_representation
    assert obj.normalized_pending_representation
    assert obj.normalized_active_representation != obj.normalized_pending_representation


# === unreadable families ==========================================================================


def test_a_complete_enumeration_names_no_unreadable_family():
    assert _build().unreadable_families == ()


def test_an_incomplete_enumeration_names_the_families_an_operator_must_grant_for():
    partial = {"zones": (), "vnets": ()}
    document = _build(observations=_observations(pending=partial))
    missing = {family for family, _state in document.unreadable_families}
    assert missing == {"subnets", "controllers"}


def test_a_cluster_with_no_vnets_has_no_subnets_to_walk():
    """The document must not contradict itself: reporting subnets unreadable while the signed state
    says the pending read was observed is output an operator is right not to trust."""
    observations = _observations(pending={"zones": (), "vnets": (), "controllers": ()})
    observations["existing_vnets"] = Observation.observed({})
    document = _build(observations=observations)
    assert document.visibility_complete is True
    assert document.unreadable_families == ()


def test_an_unwalked_vnet_still_makes_subnets_unreadable():
    observations = _observations(pending={"zones": (), "vnets": (), "controllers": ()})
    observations["existing_vnets"] = Observation.observed({"v1": {}})
    document = _build(observations=observations)
    assert ("subnets", "observed") in document.unreadable_families


def test_subnets_are_unreadable_when_the_vnet_index_itself_was_not_observed():
    observations = _observations(pending={"zones": (), "vnets": (), "controllers": ()})
    observations["existing_vnets"] = Observation.probe_failed("x")
    document = _build(observations=observations)
    assert ("subnets", "observed") in document.unreadable_families


def test_the_control_plane_family_list_matches_the_workers():
    """The list is restated because the plane boundary forbids the control plane importing worker
    internals, and a restatement is a second copy that can drift. This is the only place both
    copies are read at once."""
    from secp_worker.proxmox_sdn_operations import SDN_PENDING_FAMILIES

    assert PENDING_FAMILIES == SDN_PENDING_FAMILIES


def _operation() -> OperationBinding:
    return OperationBinding(
        target_identity=DEFAULT_TARGET,
        cluster_fingerprint="sha256:cluster",
        range_identity="range-1",
        operation_identity=DEFAULT_OPERATION,
        operation_generation=3,
        stage1_workspace_hash="sha256:ws",
        stage1_plan_hash="sha256:plan",
        stage1_authorization_id="auth-1",
        stage1_execution_receipt="receipt-1",
    )


# === no second construction site ==================================================================


_ALLOWED_CONSTRUCTION_SITES = frozenset({"sdn_activation_stages.py", "sdn_pending_observation.py"})


def test_no_other_module_in_the_live_tree_constructs_a_pending_document():
    """Inverted on purpose, and it now also catches ``dataclasses.replace``: a frozen dataclass can
    be copied with fields overridden without ever naming the class, which the earlier bare-name
    scan missed entirely."""
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
            if not isinstance(node, ast.Call):
                continue
            named = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if named == "PendingSdnDocument":
                offenders.append(f"{path.name}:{node.lineno}:construction")
            if named == "replace" and any(
                isinstance(k, ast.keyword) and k.arg in ("authentication",) for k in node.keywords
            ):
                offenders.append(f"{path.name}:{node.lineno}:dataclasses.replace")
    assert offenders == [], offenders


def test_the_document_still_exposes_the_properties_the_activation_gate_reads():
    """If either property were renamed, issue_activation_authorization would read a missing
    attribute and this module's derivation would silently stop applying."""
    document = _build()
    assert isinstance(document.signature_verified, bool)
    assert isinstance(document.visibility_complete, bool)
    assert not isinstance(type(document).__dict__.get("signature_verified"), (bool, type(None))), (
        "signature_verified must be a property, not a class attribute"
    )
