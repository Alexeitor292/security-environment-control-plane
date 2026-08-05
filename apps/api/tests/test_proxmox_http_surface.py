"""The Proxmox range lifecycle over HTTP.

Everything the Proxmox stream built was unreachable by any client: the compiled topology, the
deterministic allocations, the plan and its hash, the approvals, the verification report and the
residue proof had no route. These tests are about the surface that exposes them, and specifically
about the four properties that surface must not lose:

* apply and destroy authorization stay STRUCTURALLY distinct — no body satisfies both;
* an approval never starts anything;
* unknown stays unknown on the wire (``undetermined``/``unproven``/``blocked``, never a default);
* no secret has a path into a response.

No test here contacts Proxmox. The observation is a recorded fixture — which is exactly what the
worker would record — and every compile is a pure function of it.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient
from secp_api.range_catalog import PROXMOX_WEB_BREACH_LAB, WEB_BREACH_LAB, get_template
from secp_api.range_enums import RangeOperationKind
from secp_api.range_providers.proxmox_ipam import AllocationKind
from secp_api.range_providers.proxmox_model import BlockedPlan
from secp_api.services import proxmox_lifecycle, ranges

DIGEST = "sha256:" + "ab" * 32
MANAGEMENT_CIDR = "10.0.0.0/24"


def observation_payload() -> dict:
    """The JSON the worker records once discovery has PROVED these facts about the cluster.

    Every field the compiler blocks on is present. Individual tests remove them to prove the
    surface reports ``blocked`` rather than guessing.
    """
    storage = {
        "storage_id": "local-lvm",
        "content_types": ["images", "rootdir"],
        "available_bytes": 2_000_000_000_000,
    }
    node = {
        "online": True,
        "cpu_cores_total": 64,
        "memory_bytes_total": 512_000_000_000,
        "storages": [storage],
        "bridges": ["vmbr0", "vmbr1"],
    }
    return {
        "identity": {
            "target_id": "tgt-lab-01",
            "cluster_name": "pve-lab",
            "cluster_fingerprint": "sha256:aa11bb22",
            "management_cidrs": [MANAGEMENT_CIDR],
            "management_bridges": ["vmbr0"],
        },
        "nodes": [{"node_name": "pve1", **node}, {"node_name": "pve2", **node}],
        "templates": [
            {"template_ref": "kali-2026", "vmid": 8000, "node_name": "pve1", "guest_kind": "qemu"},
            {"template_ref": "dvwa-1.9", "vmid": 8001, "node_name": "pve1", "guest_kind": "qemu"},
            {"template_ref": "juice-v17", "vmid": 8002, "node_name": "pve1", "guest_kind": "qemu"},
        ],
        "sdn_supported": True,
        "firewall_supported": True,
        "vlan_tags_in_use": [100],
        "vmids_in_use": [100, 8000, 8001, 8002],
        "macs_in_use": ["BC:24:11:00:00:01"],
        "subnets_in_use": [MANAGEMENT_CIDR],
        "sdn_names_in_use": ["legacy"],
        "firewall_names_in_use": ["existing"],
    }


def binding_payload(**overrides) -> dict:
    payload = {
        "observation": observation_payload(),
        "teams": [
            {"team_ref": "red", "label": "Red"},
            {"team_ref": "blue", "label": "Blue"},
        ],
        "images": [
            {
                "workload_key": "attacker",
                "role": "attacker",
                "template_ref": "kali-2026",
                "workload_version": "2026.1",
                "image_digest": DIGEST,
                "approval_reference": "CAB-2026-11",
                "service_port": 22,
            },
            {
                "workload_key": "dvwa",
                "role": "target",
                "template_ref": "dvwa-1.9",
                "workload_version": "1.9",
                "image_digest": DIGEST,
                "approval_reference": "CAB-2026-12",
                "service_port": 80,
            },
            {
                "workload_key": "juice-shop",
                "role": "target",
                "template_ref": "juice-v17",
                "workload_version": "v17.1.0",
                "image_digest": DIGEST,
                "approval_reference": "CAB-2026-13",
                "service_port": 3000,
            },
        ],
        "profiles": {
            "attacker": {"cpu_cores": 4, "memory_mb": 8192, "disk_gb": 60},
            "target": {"cpu_cores": 2, "memory_mb": 4096, "disk_gb": 20},
        },
        "snapshot_id": "snap-0001",
        "evidence_hash": "sha256:evidence",
        "observed_at": "2026-08-05T10:00:00+00:00",
        "scoring_port": 443,
        "generation": 1,
    }
    payload.update(overrides)
    return payload


def make_range(session, principal, *, record_observation=True, **binding_overrides):
    instance = ranges.create_range(session, principal, template_slug=PROXMOX_WEB_BREACH_LAB.slug)
    if record_observation:
        ranges.record_event(
            session,
            instance,
            kind=proxmox_lifecycle.EVENT_OBSERVATION,
            message="discovery observation recorded",
            data=binding_payload(**binding_overrides),
        )
    session.flush()
    return instance


# --- the catalog --------------------------------------------------------------


def test_catalog_ships_a_proxmox_template_with_the_same_content_as_the_docker_lab():
    template = get_template("proxmox-web-breach-lab")
    assert template is not None
    assert template.provider == "proxmox"
    # The SHARED objects, not copies — the substrate changes, the content must not.
    assert template.components == WEB_BREACH_LAB.components
    assert template.challenges == WEB_BREACH_LAB.challenges
    assert [c.key for c in template.components] == ["dvwa", "juice-shop"]


def test_the_proxmox_template_is_synced_and_listable(session, principal):
    rows = {row.slug: row for row in ranges.list_templates(session)}
    assert "proxmox-web-breach-lab" in rows
    assert rows["proxmox-web-breach-lab"].provider == "proxmox"
    # The persisted spec never carries a flag value, only the count.
    spec = rows["proxmox-web-breach-lab"].spec
    assert all("flag_count" in c for c in spec["challenges"])
    assert not any("flags" in c for c in spec["challenges"])


# --- unknown stays unknown ----------------------------------------------------


def test_without_an_observation_the_plan_is_blocked_and_says_exactly_why(session, principal):
    instance = make_range(session, principal, record_observation=False)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    assert isinstance(compiled, BlockedPlan)
    assert compiled.reason_ids == ("proxmox.no_observation_of_record",)

    from secp_api.proxmox_projection import observation_out

    out = observation_out(None)
    # ABSENT, not "an empty cluster" and not an error.
    assert out.freshness is proxmox_lifecycle.ObservationFreshness.absent
    assert out.cluster_fingerprint is None
    assert "sdn_supported" in out.unobserved_fields


def test_an_unobserved_fact_blocks_rather_than_being_guessed(session, principal):
    payload = observation_payload()
    payload["sdn_supported"] = None  # never observed
    instance = make_range(session, principal, observation=payload)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    assert isinstance(compiled, BlockedPlan)
    assert "proxmox.sdn_support_unknown" in compiled.reason_ids


def test_a_missing_list_is_not_read_as_an_empty_cluster(session, principal):
    """``None`` (never observed) must not decay into ``()`` (observed, and there are none)."""
    payload = observation_payload()
    payload["vmids_in_use"] = None
    instance = make_range(session, principal, observation=payload)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    assert isinstance(compiled, BlockedPlan)
    assert any("vmid" in rid for rid in compiled.reason_ids)


def test_recorded_stages_are_undetermined_before_anything_observed(session, principal):
    from secp_api.proxmox_projection import (
        reset_dispositions_out,
        residue_out,
        verification_out,
    )

    instance = make_range(session, principal)
    for kind, project in (
        (proxmox_lifecycle.EVENT_VERIFICATION, verification_out),
        (proxmox_lifecycle.EVENT_RESET_DISPOSITIONS, reset_dispositions_out),
        (proxmox_lifecycle.EVENT_RESIDUE, residue_out),
    ):
        out = project(proxmox_lifecycle.recorded_stage(session, instance, kind))
        assert out.state is proxmox_lifecycle.RecordedStageState.undetermined


def test_an_unproven_residue_verdict_survives_to_the_wire(session, principal):
    """``unproven`` is a verdict of its own and is never folded into ``clean``."""
    from secp_api.proxmox_projection import residue_out

    instance = make_range(session, principal)
    ranges.record_event(
        session,
        instance,
        kind=proxmox_lifecycle.EVENT_RESIDUE,
        message="teardown observed",
        data={
            "verdict": "unproven",
            "probe_reachable": False,
            "expected_count": 8,
            "removed_confirmed": 6,
            "still_present": 0,
            "unproven_count": 2,
            "uncovered_classes": ["remote_state"],
            "reason": "the existence probe could not run",
        },
    )
    out = residue_out(
        proxmox_lifecycle.recorded_stage(session, instance, proxmox_lifecycle.EVENT_RESIDUE)
    )
    assert out.state is proxmox_lifecycle.RecordedStageState.recorded
    assert out.verdict == "unproven"
    assert out.unproven_count == 2
    assert out.uncovered_classes == ["remote_state"]


def test_verification_reports_infrastructure_and_isolation_separately(session, principal):
    """A passing infrastructure check must never be able to mask an isolation violation."""
    from secp_api.proxmox_projection import verification_out

    instance = make_range(session, principal)
    ranges.record_event(
        session,
        instance,
        kind=proxmox_lifecycle.EVENT_VERIFICATION,
        message="apply verified",
        data={
            "infrastructure_outcome": "passed",
            "isolation_outcome": "violated",
            "infrastructure_checks": [{"check": "guests_present", "outcome": "passed"}],
            "isolation_checks": [{"check": "cross_team", "outcome": "violated"}],
        },
    )
    out = verification_out(
        proxmox_lifecycle.recorded_stage(session, instance, proxmox_lifecycle.EVENT_VERIFICATION)
    )
    assert out.infrastructure_outcome == "passed"
    assert out.isolation_outcome == "violated"
    # There is no combined field that could have hidden the violation.
    assert not hasattr(out, "outcome")


# --- the compiled plan --------------------------------------------------------


def test_a_recorded_observation_compiles_a_full_plan(session, principal):
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    assert not isinstance(compiled, BlockedPlan), compiled.describe()
    # Two teams, each with an attacker and both targets.
    assert len(compiled.workload.topology.guests) == 6
    assert compiled.plan_hash.startswith("sha256:")
    assert all(finding.holds for finding in compiled.isolation)
    from secp_api.range_providers.proxmox_workload import readiness_is_satisfied

    assert readiness_is_satisfied(compiled.readiness)


def test_allocations_cover_every_identifier_class(session, principal):
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    rows = proxmox_lifecycle.allocation_rows(compiled.ledger)
    kinds = {row["kind"] for row in rows}
    for required in (
        AllocationKind.vmid,
        AllocationKind.mac,
        AllocationKind.subnet,
        AllocationKind.guest_address,
        AllocationKind.gateway_address,
        AllocationKind.vlan_tag,
        AllocationKind.vnet_name,
        AllocationKind.zone_name,
        AllocationKind.firewall_object_name,
    ):
        assert required.value in kinds, f"{required.value} missing from the allocation surface"
    # Every row is renderable: a kind, a human label, what it is for, and the value itself.
    assert all(row["label"] and row["purpose"] and row["value"] for row in rows)
    # Team-scoped allocations name their team; range-wide ones report null rather than "".
    assert {row["team_ref"] for row in rows} >= {"red", "blue", None}


def test_the_allocation_surface_carries_a_remote_state_key_when_one_is_allocated(
    session, principal
):
    """The remote-state KEY is publishable; the credential that opens it is not in this process.

    No remote-state key is allocated at compile time — it is allocated when a plan is generated,
    which happens in the worker. The surface projects whatever the ledger holds, so the key appears
    without an API change once that stage records one.
    """
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    ledger = compiled.ledger
    ledger.allocate_remote_state_key(
        ownership=compiled.workload.topology.ownership, purpose="workspace"
    )
    rows = proxmox_lifecycle.allocation_rows(ledger)
    keys = [row for row in rows if row["kind"] == AllocationKind.remote_state_key.value]
    assert keys, "an allocated remote-state key must reach the allocation surface"
    assert keys[0]["label"] == "remote state key"


def test_the_plan_is_deterministic(session, principal):
    """Approving a hash is only meaningful if the same inputs always produce the same hash."""
    instance = make_range(session, principal)
    first = proxmox_lifecycle.compile_plan(session, instance)
    second = proxmox_lifecycle.compile_plan(session, instance)
    assert first.plan_hash == second.plan_hash
    assert first.destroy_hash == second.destroy_hash


def test_plan_hash_and_destroy_hash_are_different_domains(session, principal):
    """An approved plan hash must not be a valid destroy hash for the same range."""
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    assert compiled.plan_hash != compiled.destroy_hash
    # Even over identical content the domains diverge.
    from secp_api.services.proxmox_lifecycle import (
        _DESTROY_HASH_DOMAIN,
        _PLAN_HASH_DOMAIN,
        _hash,
    )

    same = {"identical": "document"}
    assert _hash(_PLAN_HASH_DOMAIN, same) != _hash(_DESTROY_HASH_DOMAIN, same)


def test_no_flag_value_reaches_the_compiled_plan(session, principal):
    """The desired state becomes OpenTofu state; a challenge solution must never travel in it."""
    import json

    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    body = json.dumps(compiled.manifest)
    guardable = [
        flag.value
        for challenge in PROXMOX_WEB_BREACH_LAB.challenges
        for flag in challenge.flags
        if flag.value not in proxmox_lifecycle.unguardable_flag_values(PROXMOX_WEB_BREACH_LAB)
    ]
    assert guardable, "the guard would be vacuous if every flag were unguardable"
    for value in guardable:
        assert value not in body


# --- the four authorization acts ----------------------------------------------


def test_approving_the_wrong_hash_is_refused(session, principal):
    instance = make_range(session, principal)
    with pytest.raises(proxmox_lifecycle.ProxmoxHashMismatchError):
        proxmox_lifecycle.approve_plan(
            session, principal, instance.id, plan_hash="sha256:not-the-plan"
        )


def test_apply_cannot_be_authorized_before_the_plan_is_approved(session, principal):
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    with pytest.raises(proxmox_lifecycle.ProxmoxApprovalMissingError):
        proxmox_lifecycle.authorize_apply(
            session, principal, instance.id, plan_hash=compiled.plan_hash
        )


def test_approval_then_authorization_reaches_authorized(session, principal):
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_lifecycle.approve_plan(session, principal, instance.id, plan_hash=compiled.plan_hash)
    proxmox_lifecycle.authorize_apply(session, principal, instance.id, plan_hash=compiled.plan_hash)
    state = proxmox_lifecycle.authorization_state(
        compiled,
        proxmox_lifecycle.apply_authorization(session, instance),
        expected_hash=compiled.plan_hash,
    )
    assert state is proxmox_lifecycle.AuthorizationState.authorized


def test_an_apply_authorization_never_authorizes_a_destroy(session, principal):
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_lifecycle.approve_plan(session, principal, instance.id, plan_hash=compiled.plan_hash)
    proxmox_lifecycle.authorize_apply(session, principal, instance.id, plan_hash=compiled.plan_hash)

    # The destroy side is untouched by everything above.
    assert proxmox_lifecycle.destroy_plan_approval(session, instance) is None
    assert proxmox_lifecycle.destroy_authorization(session, instance) is None
    with pytest.raises(proxmox_lifecycle.ProxmoxApprovalMissingError):
        proxmox_lifecycle.require_operation_authorized(session, instance, "destroy")


def test_a_destroy_authorization_never_authorizes_an_apply(session, principal):
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_lifecycle.approve_destroy_plan(
        session, principal, instance.id, destroy_hash=compiled.destroy_hash
    )
    proxmox_lifecycle.authorize_destroy(
        session, principal, instance.id, destroy_hash=compiled.destroy_hash
    )
    assert proxmox_lifecycle.apply_authorization(session, instance) is None
    with pytest.raises(proxmox_lifecycle.ProxmoxApprovalMissingError):
        proxmox_lifecycle.require_operation_authorized(session, instance, "deploy")


def test_the_plan_hash_is_not_accepted_as_a_destroy_hash(session, principal):
    """Domain separation, exercised through the authorization path rather than asserted."""
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    with pytest.raises(proxmox_lifecycle.ProxmoxHashMismatchError):
        proxmox_lifecycle.approve_destroy_plan(
            session, principal, instance.id, destroy_hash=compiled.plan_hash
        )


def test_an_approval_is_superseded_when_the_plan_moves(session, principal):
    """The approval stays true; it stops being CURRENT. It is never silently transferred."""
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_lifecycle.approve_plan(session, principal, instance.id, plan_hash=compiled.plan_hash)

    # The worker records a fresh observation with one more VMID already taken; the plan moves.
    payload = observation_payload()
    payload["vmids_in_use"] = [*payload["vmids_in_use"], 200, 201, 202, 203, 204, 205]
    ranges.record_event(
        session,
        instance,
        kind=proxmox_lifecycle.EVENT_OBSERVATION,
        message="re-observed",
        data=binding_payload(observation=payload),
    )
    session.flush()

    recompiled = proxmox_lifecycle.compile_plan(session, instance)
    approval = proxmox_lifecycle.plan_approval(session, instance)
    assert approval is not None
    assert approval.approved_hash == compiled.plan_hash
    if recompiled.plan_hash != compiled.plan_hash:
        assert (
            proxmox_lifecycle.plan_state(recompiled, approval)
            is proxmox_lifecycle.PlanState.superseded
        )


# --- an approval starts nothing -----------------------------------------------


def test_approving_and_authorizing_create_no_operation(session, principal):
    """The whole point: authorization is a decision, not an execution."""
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_lifecycle.approve_plan(session, principal, instance.id, plan_hash=compiled.plan_hash)
    proxmox_lifecycle.authorize_apply(session, principal, instance.id, plan_hash=compiled.plan_hash)
    proxmox_lifecycle.approve_destroy_plan(
        session, principal, instance.id, destroy_hash=compiled.destroy_hash
    )
    proxmox_lifecycle.authorize_destroy(
        session, principal, instance.id, destroy_hash=compiled.destroy_hash
    )
    assert ranges.list_operations(session, principal, instance.id) == []
    assert instance.state.value == "draft"


# --- the enqueue gate ---------------------------------------------------------


def test_deploy_is_refused_without_an_apply_authorization(session, principal):
    instance = make_range(session, principal)
    with pytest.raises(proxmox_lifecycle.ProxmoxApprovalMissingError):
        proxmox_lifecycle.require_operation_authorized(session, instance, "deploy")


def test_deploy_is_permitted_once_apply_is_authorized(session, principal):
    instance = make_range(session, principal)
    compiled = proxmox_lifecycle.compile_plan(session, instance)
    proxmox_lifecycle.approve_plan(session, principal, instance.id, plan_hash=compiled.plan_hash)
    proxmox_lifecycle.authorize_apply(session, principal, instance.id, plan_hash=compiled.plan_hash)
    proxmox_lifecycle.require_operation_authorized(session, instance, "deploy")  # no raise


def test_a_blocked_plan_cannot_enqueue_anything(session, principal):
    instance = make_range(session, principal, record_observation=False)
    with pytest.raises(proxmox_lifecycle.ProxmoxPlanBlockedError):
        proxmox_lifecycle.require_operation_authorized(session, instance, "deploy")


def test_the_docker_lifecycle_is_untouched(session, principal):
    """The gate applies to Proxmox ranges only; the local Docker lifecycle keeps its behaviour."""
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    proxmox_lifecycle.require_operation_authorized(session, instance, "deploy")  # no raise
    _, operation = ranges.start_operation(
        session, principal, instance.id, RangeOperationKind.deploy
    )
    assert operation.kind is RangeOperationKind.deploy


def test_a_docker_range_has_no_proxmox_lifecycle(session, principal):
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    with pytest.raises(proxmox_lifecycle.ProxmoxNotApplicableError):
        proxmox_lifecycle.require_proxmox(instance)


# --- over the wire ------------------------------------------------------------


@pytest.fixture
def client(engine, principal):
    from secp_api.db import get_sessionmaker
    from secp_api.deps import current_principal
    from secp_api.main import create_app

    app = create_app()
    app.router.on_startup.clear()
    _ = get_sessionmaker()
    app.dependency_overrides[current_principal] = lambda: principal
    return TestClient(app)


def test_openapi_publishes_every_lifecycle_stage(client):
    """The generated OpenAPI is the contract a client transcribes."""
    spec = client.get("/openapi.json").json()
    for path in (
        "/api/v1/ranges/{range_id}/proxmox/topology",
        "/api/v1/ranges/{range_id}/proxmox/allocations",
        "/api/v1/ranges/{range_id}/proxmox/observation",
        "/api/v1/ranges/{range_id}/proxmox/plan",
        "/api/v1/ranges/{range_id}/proxmox/apply-authorization",
        "/api/v1/ranges/{range_id}/proxmox/verification",
        "/api/v1/ranges/{range_id}/proxmox/readiness",
        "/api/v1/ranges/{range_id}/proxmox/reset-dispositions",
        "/api/v1/ranges/{range_id}/proxmox/destroy-plan",
        "/api/v1/ranges/{range_id}/proxmox/destroy-authorization",
        "/api/v1/ranges/{range_id}/proxmox/ownership",
        "/api/v1/ranges/{range_id}/proxmox/residue",
    ):
        assert path in spec["paths"], f"{path} is not published"
    assert "post" in spec["paths"]["/api/v1/ranges/{range_id}/proxmox/plan-approval"]
    assert "post" in spec["paths"]["/api/v1/ranges/{range_id}/proxmox/destroy-plan-approval"]


def test_apply_and_destroy_authorization_schemas_cannot_be_confused(client):
    """No body validates as both. The required field names differ and both forbid extras."""
    spec = client.get("/openapi.json").json()
    schemas = spec["components"]["schemas"]
    apply_schema = schemas["ProxmoxApplyAuthorizationRequest"]
    destroy_schema = schemas["ProxmoxDestroyAuthorizationRequest"]
    assert apply_schema["required"] == ["plan_hash"]
    assert destroy_schema["required"] == ["destroy_hash"]
    assert apply_schema.get("additionalProperties") is False
    assert destroy_schema.get("additionalProperties") is False


def test_unknown_values_are_published_as_enum_members(client):
    """A client can switch on them because they are in the schema, not implied by absence."""
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    assert set(schemas["RecordedStageState"]["enum"]) == {"recorded", "undetermined"}
    assert "blocked" in schemas["PlanState"]["enum"]
    assert "undetermined" in schemas["AuthorizationState"]["enum"]
    assert "absent" in schemas["ObservationFreshness"]["enum"]


def test_posting_an_apply_body_to_the_destroy_endpoint_is_rejected(client):
    """Not a 200, not a destroyed range — a validation failure."""
    response = client.post(
        f"/api/v1/ranges/{uuid.uuid4()}/proxmox/destroy-authorization",
        json={"plan_hash": "sha256:" + "0" * 64},
    )
    assert response.status_code == 422


@pytest.fixture
def http_range(client):
    """A committed Proxmox range with a recorded observation, reachable by the ASGI app.

    Committed rather than flushed: the app resolves its own session, so anything left uncommitted
    in the test's session is invisible to the request handler.
    """
    from secp_api.db import session_scope
    from secp_api.seed import bootstrap_dev

    with session_scope() as s:
        p = bootstrap_dev(s)
        instance = ranges.create_range(s, p, template_slug=PROXMOX_WEB_BREACH_LAB.slug)
        ranges.record_event(
            s,
            instance,
            kind=proxmox_lifecycle.EVENT_OBSERVATION,
            message="discovery observation recorded",
            data=binding_payload(),
        )
        range_id = str(instance.id)
    return client, range_id


def test_the_whole_lifecycle_over_http(http_range):
    """Read the plan, approve it, authorize apply — and only then may a deploy be enqueued."""
    client, range_id = http_range
    base = f"/api/v1/ranges/{range_id}/proxmox"

    plan = client.get(f"{base}/plan")
    assert plan.status_code == 200, plan.text
    body = plan.json()
    assert body["state"] == "compiled"
    assert body["document_version"] == "secp-proxmox/desired-state-document/v1"
    assert body["isolation_holds"] is True
    plan_hash = body["plan_hash"]

    # The observation is identified and dated.
    observation = client.get(f"{base}/observation").json()
    assert observation["snapshot_id"] == "snap-0001"
    assert observation["cluster_fingerprint"] == "sha256:aa11bb22"
    assert observation["freshness"] in {"fresh", "stale"}

    # Topology and allocations are readable before anything is approved.
    assert client.get(f"{base}/topology").json()["guest_count"] == 6
    assert len(client.get(f"{base}/allocations").json()["allocations"]) > 0
    assert client.get(f"{base}/readiness").json()["satisfied"] is True
    assert client.get(f"{base}/ownership").json()["ownership"]["tags"]

    # Nothing has been observed yet, and the surface says so rather than implying success.
    assert client.get(f"{base}/verification").json()["state"] == "undetermined"
    assert client.get(f"{base}/residue").json()["state"] == "undetermined"
    assert client.get(f"{base}/reset-dispositions").json()["state"] == "undetermined"

    # Apply is not authorized, and deploy is refused.
    assert client.get(f"{base}/apply-authorization").json()["state"] == "absent"
    refused = client.post(f"/api/v1/ranges/{range_id}/deploy")
    assert refused.status_code == 409, refused.text

    # Authorizing apply before approving the plan is refused.
    assert (
        client.post(f"{base}/apply-authorization", json={"plan_hash": plan_hash}).status_code == 409
    )

    # Approve, then authorize.
    approved = client.post(f"{base}/plan-approval", json={"plan_hash": plan_hash})
    assert approved.status_code == 201, approved.text
    assert approved.json()["approved_hash_is_current"] is True

    authorized = client.post(f"{base}/apply-authorization", json={"plan_hash": plan_hash})
    assert authorized.status_code == 201, authorized.text
    assert authorized.json()["state"] == "authorized"

    # The destroy side is still untouched by all of that.
    destroy = client.get(f"{base}/destroy-authorization").json()
    assert destroy["state"] == "absent"
    destroy_hash = client.get(f"{base}/destroy-plan").json()["destroy_hash"]
    assert destroy_hash != plan_hash

    # The plan hash is not accepted as a destroy approval.
    assert (
        client.post(f"{base}/destroy-plan-approval", json={"destroy_hash": plan_hash}).status_code
        == 409
    )

    # The approval chain no longer blocks the deploy — the refusal that remains is the PRE-EXISTING
    # dispatch seal, which forbids range execution on the inline dispatcher entirely. Two
    # independent gates, and this asserts the authorization one was satisfied while the seal held:
    # the code moved from `proxmox_approval_missing` to `inline_execution_forbidden`.
    deployed = client.post(f"/api/v1/ranges/{range_id}/deploy")
    assert deployed.status_code == 403, deployed.text
    assert deployed.json()["error"]["code"] == "inline_execution_forbidden"


def test_no_response_carries_a_secret(http_range):
    """Sweep every read surface for the values that must never travel."""
    client, range_id = http_range
    base = f"/api/v1/ranges/{range_id}/proxmox"
    forbidden = [
        flag.value
        for challenge in PROXMOX_WEB_BREACH_LAB.challenges
        for flag in challenge.flags
        if flag.value not in proxmox_lifecycle.unguardable_flag_values(PROXMOX_WEB_BREACH_LAB)
    ]
    markers = ["PRIVATE KEY-----", "secret_ref", "SECP_PROVIDER_SECRET", "password="]
    for suffix in (
        "",
        "/observation",
        "/topology",
        "/allocations",
        "/plan",
        "/apply-authorization",
        "/verification",
        "/readiness",
        "/reset-dispositions",
        "/destroy-plan",
        "/destroy-authorization",
        "/ownership",
        "/residue",
    ):
        response = client.get(f"{base}{suffix}")
        assert response.status_code == 200, f"{suffix}: {response.text}"
        text = response.text
        for value in forbidden:
            assert value not in text, f"a flag value reached {suffix}"
        for marker in markers:
            assert marker not in text, f"{marker!r} reached {suffix}"


def test_a_docker_range_is_refused_by_the_proxmox_surface(client):
    from secp_api.db import session_scope
    from secp_api.seed import bootstrap_dev

    with session_scope() as s:
        p = bootstrap_dev(s)
        instance = ranges.create_range(s, p, template_slug="web-breach-lab")
        range_id = str(instance.id)
    response = client.get(f"/api/v1/ranges/{range_id}/proxmox/plan")
    assert response.status_code == 409
    assert "proxmox" in response.text.lower()
