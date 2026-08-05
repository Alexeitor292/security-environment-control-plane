"""The five Proxmox reads that had no route.

Worker, workload/bootstrap, reset plan, reconciliation, evidence references — plus the audit that
proves the OTHER required reads were already published and were not duplicated to satisfy a
checklist.

Two properties carry the weight here:

* **the worker's own addresses are on the wire.** The bootstrap contract's ``probe_address`` and
  ``report_address`` had no route at all; the topology's ``published_address`` and ``probe_address``
  already did. They are four separate facts and none may be substituted for another — the defect
  that motivated the split was a worker probing an address that had been *published* rather than
  being reachable.
* **unknown and empty never serialize to the same shape.** "no reset has been observed" is not "a
  reset ran and touched nothing"; "no residue proof exists" is not "the probe found no residue";
  "reconciliation was requested" is not "a worker looked".
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from secp_api.services import proxmox_commands, proxmox_lifecycle, ranges
from secp_api.services.proxmox_commands import CommandKind, RefusalCode
from test_proxmox_http_surface import make_range, observation_payload
from test_proxmox_operator_commands import (
    RELEASE_DIGEST,
    WORKER_INSTALLATION,
    enroll_worker,
    envelope,
    proxmox_range,
)


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


# --- the read audit -------------------------------------------------------------


def test_every_required_operator_read_has_exactly_one_route(client):
    """The brief's read list, mapped to routes, with nothing duplicated to pad the count.

    The mapping is asserted rather than described: several of these were ALREADY published, and the
    wrong response to a checklist is a second endpoint answering a question that already had one.
    Where an existing surface answers, that surface is named here and no new route exists beside it.
    """
    paths = set(client.get("/openapi.json").json()["paths"])
    required = {
        # already published before this slice — reused, not duplicated
        "discovery freshness and provenance": "/api/v1/ranges/{range_id}/proxmox/observation",
        "apply-authorization state": "/api/v1/ranges/{range_id}/proxmox/apply-authorization",
        "competition readiness": "/api/v1/ranges/{range_id}/proxmox/readiness",
        "reset dispositions": "/api/v1/ranges/{range_id}/proxmox/reset-dispositions",
        "deployment operation state": "/api/v1/range-operations/{operation_id}",
        "activity events": "/api/v1/ranges/{range_id}/events",
        "evidence (teardown)": "/api/v1/ranges/{range_id}/teardown-evidence",
        # added by this slice
        "target eligibility": "/api/v1/ranges/{range_id}/scenario",
        "worker installation/enrollment/identity/release": (
            "/api/v1/ranges/{range_id}/proxmox/worker"
        ),
        "workload and bootstrap state": "/api/v1/ranges/{range_id}/proxmox/workload",
        "reset plan": "/api/v1/ranges/{range_id}/proxmox/reset-plan",
        "reconciliation state": "/api/v1/ranges/{range_id}/proxmox/reconciliation",
        "evidence references": "/api/v1/ranges/{range_id}/proxmox/evidence",
        "audit records": "/api/v1/ranges/{range_id}/proxmox/commands",
    }
    missing = {name: path for name, path in required.items() if path not in paths}
    assert not missing, missing
    # One route per question: no two entries above may name the same path.
    assert len(set(required.values())) == len(required)


# --- the worker -----------------------------------------------------------------


def test_no_enrolled_worker_is_an_answer_not_a_404(client, session, principal):
    instance = proxmox_range(session, principal)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/worker").json()
    assert body["enrolled"] is False
    assert body["eligible_for_execution"] is False
    assert body["blockers"] == [RefusalCode.worker_mismatch.value]
    # Nobody is enrolled — which is not the same as an enrolled worker with no identity.
    assert body["state"] is None
    assert body["worker_installation_id"] is None


def test_a_healthy_worker_is_eligible_and_publishes_its_public_identity(client, session, principal):
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/worker").json()
    assert body["enrolled"] is True
    assert body["state"] == "healthy"
    assert body["eligible_for_execution"] is True
    assert body["blockers"] == []
    assert body["worker_installation_id"] == WORKER_INSTALLATION
    assert body["release_digest"] == RELEASE_DIGEST
    assert body["contract_version"]


def test_an_unhealthy_worker_is_reported_ineligible_with_the_command_refusal_code(
    client, session, principal
):
    """The same stable code a command refusal carries, so one client rendering serves both."""
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal, state="worker_bound")
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/worker").json()
    assert body["enrolled"] is True
    assert body["state"] == "worker_bound"
    assert body["eligible_for_execution"] is False
    assert body["blockers"] == [RefusalCode.worker_not_healthy.value]


def test_the_worker_read_publishes_no_compare_and_swap_material(client, session, principal):
    """The controller's CAS chain is not a fact about the worker and has no field."""
    instance = proxmox_range(session, principal)
    enroll_worker(session, principal)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/worker").json()
    for forbidden in ("transaction_id", "state_digest", "offer_digest", "result_digest"):
        assert forbidden not in body


def test_the_worker_read_is_organization_scoped(client, session, principal, other_org_principal):
    """An enrollment in another organization must not appear on this range's worker read."""
    instance = proxmox_range(session, principal)
    from datetime import UTC, datetime, timedelta

    from secp_api.worker_enrollment_models import WorkerEnrollmentState

    digest = "sha256:" + "22" * 32
    moment = datetime.now(UTC)
    session.add(
        WorkerEnrollmentState(
            enrollment_id="sha256:" + "33" * 32,
            organization_id=other_org_principal.organization_id,
            deployment_site_label="other-site",
            contract_version="secp-enrollment/v1",
            state="healthy",
            revision=1,
            sequence=1,
            controller_installation_id="controller-installation-99",
            controller_key_id=digest,
            worker_installation_id="worker-installation-9999",
            worker_key_id=digest,
            release_digest=digest,
            transaction_id="txn-9999",
            expires_at=(moment + timedelta(days=1)).isoformat(),
            updated_at=moment.isoformat(),
            state_digest=digest,
            expires_at_ts=moment + timedelta(days=1),
        )
    )
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/worker").json()
    assert body["enrolled"] is False, "another organization's worker must not leak into this read"


# --- workload and bootstrap: the addresses that had no route ---------------------


def test_the_bootstrap_contract_addresses_reach_the_wire(client, session, principal):
    """The worker's probe and report addresses were published nowhere before this."""
    instance = proxmox_range(session, principal)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/workload").json()
    assert body["guests"], "a compiled plan has guests"
    guest = body["guests"][0]
    for field in ("report_address", "report_port", "probe_address", "probe_port"):
        assert field in guest, f"{field} must survive to the wire"
    assert guest["report_address"]
    assert guest["deadline_seconds"] > 0


def test_the_worker_addresses_are_not_the_topology_addresses(client, session, principal):
    """Four concepts, four fields, and no fallback between any of them."""
    instance = proxmox_range(session, principal)
    session.commit()
    workload = client.get(f"/api/v1/ranges/{instance.id}/proxmox/workload").json()
    topology = client.get(f"/api/v1/ranges/{instance.id}/proxmox/topology").json()

    by_vmid = {guest["vmid"]: guest for guest in topology["guests"]}
    for guest in workload["guests"]:
        planned = by_vmid[guest["vmid"]]
        # The topology's published address is its own field on its own endpoint...
        assert planned["address"]["published_address"]
        # ...and nothing on the workload read silently reuses it as a probe target.
        if guest["probe_address"] is not None:
            assert guest["probe_address"] != planned["address"]["published_address"], (
                "the worker's probe address must never be the published address — probing what was "
                "published proves the address was published, not that the guest is reachable"
            )


def test_an_unobserved_guest_is_not_a_failed_one(client, session, principal):
    instance = proxmox_range(session, principal)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/workload").json()
    assert body["verification"] == "undetermined"
    for guest in body["guests"]:
        assert guest["observed"] is False
        assert guest["observed_address"] is None


def test_bootstrap_material_is_published_as_a_reference_and_never_as_material(
    client, session, principal
):
    instance = proxmox_range(session, principal)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/workload").json()
    for guest in body["guests"]:
        ref = guest["attestation_ref"]
        assert set(ref) == {"ref", "scope", "purpose", "channel"}
    assert body["materials"] is not None


def test_a_blocked_plan_gives_null_guests_not_an_empty_list(client, session, principal):
    """An empty list would read as "a lab with no guests", which the compiler never produces."""
    instance = make_range(session, principal, record_observation=False)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/workload").json()
    assert body["state"] == "blocked"
    assert body["guests"] is None
    assert body["blocked_reasons"]


# --- the reset plan is not the reset dispositions --------------------------------


def test_the_reset_plan_says_what_would_happen_and_the_dispositions_say_what_did(
    client, session, principal
):
    instance = proxmox_range(session, principal)
    session.commit()
    plan = client.get(f"/api/v1/ranges/{instance.id}/proxmox/reset-plan").json()
    observed = client.get(f"/api/v1/ranges/{instance.id}/proxmox/reset-dispositions").json()

    assert plan["guests"], "the plan names every guest a reset would recreate"
    assert all(guest["intended_action"] == "recreate" for guest in plan["guests"])
    # Nothing has been observed, and the two surfaces say so in their own vocabularies.
    assert plan["last_observed"] == "undetermined"
    assert observed["state"] == "undetermined"
    assert observed["dispositions"] is None, (
        "an empty list would say a reset ran and touched no guest, which is a real and very "
        "different observation from no reset having run"
    )


def test_the_reset_plan_resolves_the_deploys_identifiers(client, session, principal):
    """Determinism is what lets a reset restore this range instead of building a second one."""
    instance = proxmox_range(session, principal)
    session.commit()
    plan = client.get(f"/api/v1/ranges/{instance.id}/proxmox/reset-plan").json()
    topology = client.get(f"/api/v1/ranges/{instance.id}/proxmox/topology").json()
    assert {guest["vmid"] for guest in plan["guests"]} == {
        guest["vmid"] for guest in topology["guests"]
    }


# --- reconciliation: two independent facts ---------------------------------------


def test_reconciliation_starts_unrequested_and_unobserved(client, session, principal):
    instance = proxmox_range(session, principal)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/reconciliation").json()
    assert body["requested"] is False
    assert body["state"] == "undetermined"
    assert body["findings"] is None
    assert body["not_enqueued_reason"] is None


def test_a_request_does_not_make_reconciliation_observed(client, session, principal):
    """An operator asking and a worker looking are different facts and must not be conflated."""
    from secp_api.range_enums import RangeState

    instance = proxmox_range(session, principal)
    instance.state = RangeState.ready
    session.flush()
    proxmox_commands.request_reconciliation(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/reconciliation").json()
    assert body["requested"] is True
    assert body["requested_by"]
    # Still nothing has looked.
    assert body["state"] == "undetermined"
    assert body["findings"] is None
    # And the surface says out loud that nothing took the request.
    assert body["enqueued"] is False
    assert body["not_enqueued_reason"] == RefusalCode.reconciliation_consumer_unavailable.value


def test_a_recorded_reconciliation_is_reported_verbatim(client, session, principal):
    """When a worker does record one, the findings are the worker's words."""
    instance = proxmox_range(session, principal)
    ranges.record_event(
        session,
        instance,
        kind=proxmox_lifecycle.EVENT_RECONCILIATION,
        message="reconciliation observed",
        data={
            "findings": [{"guest_ref": "red-dvwa", "action": "halt", "reason": "ownership_absent"}],
            "observed_at": "2026-08-05T12:00:00+00:00",
            "detail": "one guest is not stamped for this range",
        },
    )
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/reconciliation").json()
    assert body["state"] == "recorded"
    assert body["findings"] == [
        {"guest_ref": "red-dvwa", "action": "halt", "reason": "ownership_absent"}
    ]
    assert body["detail"] == "one guest is not stamped for this range"


# --- evidence references ----------------------------------------------------------


def test_every_evidence_class_is_listed_present_or_not(client, session, principal):
    """Omitting the absent ones makes "no residue proof" look like "nobody asked"."""
    instance = proxmox_range(session, principal)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/evidence").json()
    kinds = {item["kind"]: item for item in body["references"]}
    assert set(kinds) == {
        "discovery_snapshot",
        "desired_state_plan",
        "destroy_plan",
        "verification_report",
        "reset_dispositions",
        "residue_proof",
    }
    assert kinds["discovery_snapshot"]["present"] is True
    assert kinds["desired_state_plan"]["present"] is True
    # Nothing has been observed yet, and each says so rather than being dropped.
    assert kinds["verification_report"]["present"] is False
    assert kinds["residue_proof"]["present"] is False
    assert kinds["residue_proof"]["observed_at"] is None
    assert body["teardown_evidence_ids"] == []


def test_an_unproven_residue_verdict_is_carried_into_the_evidence_reference(
    client, session, principal
):
    """``unproven`` is a verdict of its own and is never folded into ``clean``."""
    instance = proxmox_range(session, principal)
    ranges.record_event(
        session,
        instance,
        kind=proxmox_lifecycle.EVENT_RESIDUE,
        message="teardown observed",
        data={"verdict": "unproven", "observed_at": "2026-08-05T12:00:00+00:00"},
    )
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/evidence").json()
    residue = next(item for item in body["references"] if item["kind"] == "residue_proof")
    assert residue["present"] is True
    assert residue["detail"] == "unproven"


def test_evidence_references_carry_no_payload(client, session, principal):
    """References and timestamps. The reports themselves have their own endpoints."""
    instance = proxmox_range(session, principal)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/evidence").json()
    for item in body["references"]:
        assert set(item) == {"kind", "present", "reference", "observed_at", "detail"}


def test_a_blocked_plan_still_answers_the_evidence_read(client, session, principal):
    instance = make_range(session, principal, record_observation=False)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/evidence").json()
    kinds = {item["kind"]: item for item in body["references"]}
    assert kinds["discovery_snapshot"]["present"] is False
    assert kinds["desired_state_plan"]["present"] is False
    assert kinds["desired_state_plan"]["reference"] is None


# --- the secret sweep, enumerated from the live app --------------------------------


def test_no_proxmox_read_carries_a_secret(client, session, principal):
    """Every GET under ``/proxmox/``, DISCOVERED FROM THE LIVE ROUTER, swept for forbidden values.

    ``test_proxmox_http_surface`` has a sweep like this over a hand-written list of thirteen
    suffixes. That list was correct when it was written and cannot notice a route added afterwards —
    the five reads in this slice were invisible to it, and so would be the next one. A closed set
    maintained by hand is not an exhaustive guard; it is a guard over whatever its author
    remembered.

    So this one inverts it: it enumerates the served paths from the OpenAPI, requires that it found
    MORE than the old list covered (otherwise the enumeration silently degraded to nothing), and
    sweeps every one.
    """
    instance = proxmox_range(session, principal)
    # Give every surface something real to render, so the sweep is not passing over empty bodies.
    ranges.record_event(
        session,
        instance,
        kind=proxmox_lifecycle.EVENT_VERIFICATION,
        message="verification observed",
        data={
            "infrastructure_outcome": "verified",
            "isolation_outcome": "verified",
            "guests": [{"vmid": 100, "address": "10.60.0.11"}],
            "observed_at": "2026-08-05T12:00:00+00:00",
        },
    )
    proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    session.commit()

    paths = client.get("/openapi.json").json()["paths"]
    reads = sorted(
        path
        for path, methods in paths.items()
        if "/proxmox" in path and "get" in methods and "{range_id}" in path
    )
    assert len(reads) >= 18, (
        f"the enumeration found only {len(reads)} Proxmox read routes, fewer than the surface is "
        "known to have — it has degraded and would sweep almost nothing"
    )

    from secp_api.range_catalog import PROXMOX_WEB_BREACH_LAB

    forbidden = [
        flag.value
        for challenge in PROXMOX_WEB_BREACH_LAB.challenges
        for flag in challenge.flags
        if flag.value not in proxmox_lifecycle.unguardable_flag_values(PROXMOX_WEB_BREACH_LAB)
    ]
    assert forbidden, "the guard would be vacuous if every flag were unguardable"
    # Markers for the material that must never travel. Public SSH keys ARE published (cloud-init
    # carries them and CloudInitSpec refuses private material), so the marker is the PRIVATE one.
    markers = [
        "PRIVATE KEY-----",
        "SECP_PROVIDER_SECRET",
        "password=",
        "transaction_id",
        "state_digest",
    ]

    swept = 0
    for path in reads:
        url = path.replace("{range_id}", str(instance.id))
        response = client.get(url)
        assert response.status_code == 200, f"{path}: {response.status_code} {response.text[:200]}"
        text = response.text
        for value in forbidden:
            assert value not in text, f"a flag value reached {path}"
        for marker in markers:
            assert marker not in text, f"{marker!r} reached {path}"
        swept += 1
    assert swept == len(reads)


# --- the (observed, ok) pair, end to end over JSON ---------------------------------


def test_the_observed_ok_pair_keeps_all_three_states_over_the_wire(client, session, principal):
    """``ok: null`` must survive JSON serialization. Unknown is not false.

    ``test_proxmox_http_surface`` already proves the pair is not FLATTENED, but it does so with
    ``observed=false, ok=false`` — which is itself the substitution this invariant forbids, so it
    cannot show that the unknown state has a representation. The canonical triple is:

        observed=false, ok=null   the check could not be made
        observed=true,  ok=false  the check was made and failed
        observed=true,  ok=true   the check was made and passed

    Asserted through the real HTTP layer rather than on the projection, because that is where a
    ``null`` is most easily lost: a response model that defaulted ``ok`` to ``False``, or a client
    reading a missing key as falsey, turns "nobody could look" into "this failed" — and, in the
    other direction, an operator who sees a definite failure where there was only silence stops
    looking for the prober that is down.
    """
    instance = proxmox_range(session, principal)
    ranges.record_event(
        session,
        instance,
        kind=proxmox_lifecycle.EVENT_VERIFICATION,
        message="verification observed",
        data={
            "infrastructure_outcome": "verified",
            "isolation_outcome": "state_disagreement",
            "isolation_checks": [
                {"check": "cross_team", "observed": False, "ok": None, "detail": "no prober"},
                {"check": "management_plane", "observed": True, "ok": False, "detail": "reached"},
                {"check": "scoring_path", "observed": True, "ok": True, "detail": "permitted"},
            ],
        },
    )
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/verification").json()
    checks = {item["check"]: item for item in body["isolation_checks"]}

    unknown = checks["cross_team"]
    assert unknown["observed"] is False
    assert unknown["ok"] is None, (
        "an unobserved check must serialize ok=null. Coercing it to false makes 'nobody could "
        "look' indistinguishable from 'this failed', which is the substitution that has already "
        "cost this program twice."
    )
    assert "ok" in unknown, "the key must be PRESENT and null, not dropped"

    assert checks["management_plane"] == {
        "check": "management_plane",
        "observed": True,
        "ok": False,
        "detail": "reached",
    }
    assert checks["scoring_path"]["observed"] is True
    assert checks["scoring_path"]["ok"] is True
    # Three distinct states, and none collapses onto another.
    assert len({(c["observed"], c["ok"]) for c in checks.values()}) == 3
    # The lifecycle outcome is likewise not reduced to success-or-failure.
    assert body["isolation_outcome"] == "state_disagreement"
    assert body["infrastructure_outcome"] == "verified"


# --- the reset gate is explicit, not a fall-through -------------------------------


def test_a_proxmox_reset_refusal_names_the_reset_not_an_apply(session, principal):
    """The provider-neutral gate used to answer "apply is not authorized" for a reset.

    The gate is unchanged in what it REQUIRES — a reset re-materialises the approved desired state,
    so the apply authorization is the right one — but it now reaches that conclusion by an explicit
    branch and says which act it refused, so an operator is not sent to investigate an apply they
    never requested.
    """
    instance = proxmox_range(session, principal)
    with pytest.raises(proxmox_lifecycle.ProxmoxApprovalMissingError) as excinfo:
        proxmox_lifecycle.require_operation_authorized(session, instance, "reset")
    message = str(excinfo.value)
    assert message.startswith("reset is not authorized")
    assert "recreates the guests" in message

    with pytest.raises(proxmox_lifecycle.ProxmoxApprovalMissingError) as excinfo:
        proxmox_lifecycle.require_operation_authorized(session, instance, "deploy")
    assert str(excinfo.value).startswith("apply is not authorized")


def test_an_unrecognised_operation_kind_still_requires_an_apply_authorization(session, principal):
    """Fail closed: an unknown kind is refused, never waved through."""
    instance = proxmox_range(session, principal)
    with pytest.raises(proxmox_lifecycle.ProxmoxApprovalMissingError):
        proxmox_lifecycle.require_operation_authorized(session, instance, "something_new")


# --- non-Proxmox ranges -----------------------------------------------------------


def test_the_new_reads_refuse_a_non_proxmox_range(client, session, principal):
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    session.commit()
    for suffix in ("worker", "workload", "reset-plan", "reconciliation", "evidence"):
        response = client.get(f"/api/v1/ranges/{instance.id}/proxmox/{suffix}")
        assert response.status_code == 409, suffix
        assert response.json()["error"]["code"] == "range_not_proxmox"


def test_an_unobserved_fact_blocks_the_reset_plan_with_named_reasons(client, session, principal):
    payload = observation_payload()
    payload["sdn_supported"] = None
    instance = proxmox_range(session, principal, observation=payload)
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/reset-plan").json()
    assert body["state"] == "blocked"
    assert body["guests"] is None
    assert body["blocked_reasons"]
    assert all(item["reason_id"] for item in body["blocked_reasons"])


def test_the_commands_audit_read_refuses_a_non_proxmox_range(client, session, principal):
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    session.commit()
    response = client.get(f"/api/v1/ranges/{instance.id}/proxmox/commands")
    assert response.status_code == 409


def test_the_command_kinds_all_appear_in_the_audit_read_after_being_issued(
    client, session, principal
):
    instance = proxmox_range(session, principal)
    proxmox_commands.compile_topology(
        session, principal, instance.id, envelope=envelope(session, instance)
    )
    session.commit()
    body = client.get(f"/api/v1/ranges/{instance.id}/proxmox/commands").json()
    assert [item["operation_kind"] for item in body] == [CommandKind.compile_topology.value]
