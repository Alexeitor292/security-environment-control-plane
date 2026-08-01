"""The write path must never accept a deployment-site label the projection cannot render.

THE DEFECT THIS CLOSES
----------------------
``deployment_site_label`` is deliberately NON-canonical (ADR-027): it is absent from
``EnrollmentState.canonical()``, so it never enters ``state_digest``, the CAS chain or the history
snapshot. That property is correct and is pinned elsewhere. Its consequence was not:

* creation scans ``scan_forbidden(invitation.canonical())`` — which, by construction, cannot see a
  non-canonical field, so the label was never content-scanned on the way IN;
* the projection scans ``scan_forbidden(view)`` — and the view DOES carry the label.

So the admitting validator was strictly weaker than the rendering one. A label like
``AKIAIOSFODNN7EXAMPLE`` (or a JWT-shaped ``eyJ...``) matches the write-path grammar
``^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$`` and is refused by the projection scan. Measured against the
real app before the fix, ONE ordinary ``POST /api/v1/enrollment/invitations`` returning **201**
left the organization's default enrollment inventory permanently unreadable:

* ``GET /api/v1/enrollment`` -> 409 ``enrollment_state_corrupt``, with NO ``recovery_cursor`` and
  no audit row naming the offending enrollment (unlike the ``page_integrity`` path);
* ``GET /api/v1/enrollment/{id}`` -> 409, so the row could not even be inspected;
* ``POST /{id}/revoke`` with the CORRECT ``expected_revision`` -> an unhandled ``DescriptorError``
  escaping the router, while a WRONG revision returned a clean 409. The operator who did the right
  thing got the crash.

No corruption was required. The fix reconciles the two validators in the one helper both the write
path and the load path already call, so they cannot disagree.
"""

from __future__ import annotations

import secrets

import pytest
from fastapi.testclient import TestClient
from secp_api.deps import current_principal
from secp_commissioning.descriptor import DescriptorError, scan_forbidden

GOOD_SITE = "rack-01.eu_a"

#: Labels that match the write-path grammar but are refused by the projection scan. These are the
#: exact shapes the defect turned into a persistent denial of service, so they are named rather
#: than generated — a generated corpus that stopped producing them would go quietly green.
PROJECTION_HOSTILE_LABELS = (
    "AKIAIOSFODNN7EXAMPLE",  # AWS access key id shape
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefgh",  # JWT shape
)

#: Labels that must KEEP working. A fix that over-rejects is its own outage, so every guard below
#: is paired against these.
LEGITIMATE_LABELS = (
    "rack-01.eu_a",
    "eu-west-1",
    "dc1",
    "site.a-b_c",
    "A" * 120,  # the grammar's exact ceiling
)


@pytest.fixture
def client(engine, principal):
    from secp_api.main import create_app
    from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD

    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num varchar(32) primary key)"
        )
        conn.exec_driver_sql("DELETE FROM alembic_version")
        conn.exec_driver_sql(
            f"INSERT INTO alembic_version VALUES ('{RUNTIME_REQUIRED_MIGRATION_HEAD}')"
        )
    app = create_app()
    app.router.on_startup.clear()
    app.dependency_overrides[current_principal] = lambda: principal
    return TestClient(app)


def _create(client: TestClient, label: str = GOOD_SITE, ttl: int = 3600):
    return client.post(
        "/api/v1/enrollment/invitations",
        json={
            "idempotency_key": secrets.token_urlsafe(24),
            "deployment_site_label": label,
            "ttl_seconds": ttl,
        },
    )


def _renders(view: dict) -> bool:
    try:
        scan_forbidden(view)
    except DescriptorError:
        return False
    return True


# --- the guard that prevents recurrence ----------------------------------------------------------


@pytest.mark.parametrize("label", PROJECTION_HOSTILE_LABELS + LEGITIMATE_LABELS)
def test_anything_the_api_accepts_can_be_rendered_by_every_read_surface(client, label):
    """THE drift guard, and the reason this slice exists.

    Stated as a property over BEHAVIOUR, end to end through the real app, rather than by comparing
    the write-path regex to the scan by inspection. Comparing two validators' source would be the
    same defect one level up: it would agree with itself while the runtime disagreed.

    The property: if creation returns 201, then BOTH read surfaces must render the row. An API that
    accepts what it cannot show is the defect, whatever the two validators happen to say.
    """
    created = _create(client, label=label)

    if created.status_code != 201:
        # Refusing is a legitimate outcome — but it must be a bounded refusal, not a crash.
        assert created.status_code in (400, 409, 422), created.text
        assert "Traceback" not in created.text
        return

    enrollment_id = created.json()["enrollment_id"]

    status = client.get(f"/api/v1/enrollment/{enrollment_id}")
    assert status.status_code == 200, (
        f"created {label!r} but its status read refuses: {status.status_code} {status.text[:200]}"
    )

    listing = client.get("/api/v1/enrollment")
    assert listing.status_code == 200, (
        f"created {label!r} but the inventory refuses: {listing.status_code} {listing.text[:200]}"
    )
    assert any(item["enrollment_id"] == enrollment_id for item in listing.json()["items"])


@pytest.mark.parametrize("label", PROJECTION_HOSTILE_LABELS)
def test_the_write_path_refuses_a_label_the_projection_would_reject(client, label):
    """The specific direction the drift guard's property does not pin on its own.

    ``test_anything_the_api_accepts_can_be_rendered`` is satisfied either by refusing at creation OR
    by rendering successfully. For these shapes the projection genuinely cannot render them, so
    refusing at creation is the only correct outcome — pinned separately so a change that started
    accepting them again fails HERE with a clear cause, rather than as a rendering failure.
    """
    assert not _renders({"deployment_site_label": label}), (
        f"{label!r} is no longer projection-hostile; this guard is now measuring nothing"
    )
    r = _create(client, label=label)
    assert r.status_code != 201, (
        f"the API accepted {label!r}, which it cannot render — the original defect is back"
    )
    assert r.status_code in (400, 409, 422), r.text


@pytest.mark.parametrize("label", LEGITIMATE_LABELS)
def test_the_fix_does_not_over_reject_ordinary_labels(client, label):
    """A fix that refuses legitimate labels is its own outage. Both directions, always."""
    r = _create(client, label=label)
    assert r.status_code == 201, (
        f"legitimate label {label!r} refused: {r.status_code} {r.text[:200]}"
    )


# --- the operator-visible outcome the defect produced --------------------------------------------


def test_one_hostile_create_no_longer_bricks_the_organizations_inventory(client):
    """The end-to-end reproduction, as measured before the fix: 4 healthy rows, one 201 with a
    grammatically legal but unrenderable label, and every subsequent unfiltered list is 409 with no
    recovery cursor. The inventory must survive the attempt."""
    for i in range(4):
        assert _create(client, ttl=3600 + i).status_code == 201

    before = client.get("/api/v1/enrollment")
    assert before.status_code == 200
    assert len(before.json()["items"]) == 4

    assert _create(client, label="AKIAIOSFODNN7EXAMPLE", ttl=60).status_code != 201

    after = client.get("/api/v1/enrollment")
    assert after.status_code == 200, (
        f"the inventory is unreadable after a refused create: {after.text[:200]}"
    )
    assert len(after.json()["items"]) == 4, "the refused create must not have been persisted"


# --- the projection refusal is bounded (an INDEPENDENT fix, pinned where it is reachable) --------
#
# Note on why these are unit-level. An end-to-end revoke against a planted row does NOT exercise
# this: with the write-path fix in place, `_validate_rehydrated` re-checks the label and refuses
# BEFORE the projection runs, so the request never reaches `public_view` at all. A test driving the
# route would pass whether or not this fix existed — verified by mutation, which is how the first
# version of this test was caught being vacuous. Both halves are therefore pinned directly.


def _hostile_state():
    """A state carrying a label the projection scan refuses.

    Built by mutating a VALID state, so the only thing wrong with it is the label — the same
    attribution discipline the realm-pair proof uses elsewhere in this repo.
    """
    import dataclasses

    from secp_api.worker_enrollment_contract import (
        create_invitation,
        open_enrollment,
        sha256_digest_of_hex,
    )

    anchor_hex = (b"\x11" * 32).hex()
    invitation = create_invitation(
        controller_installation_id="ctrl-installation-01",
        controller_key_id=sha256_digest_of_hex(anchor_hex),  # must be derived FROM the anchor
        controller_trust_anchor_hex=anchor_hex,
        controller_origin="https://ctrl.example.com",
        release_digest="sha256:" + "a" * 64,
        transaction_id="tx-0000000000000001",
        nonce="sha256:" + "2" * 64,
        created_at="2026-01-01T00:00:00+00:00",
        expires_at="2026-01-01T01:00:00+00:00",
    )
    state = open_enrollment(
        invitation, now="2026-01-01T00:00:00+00:00", deployment_site_label=GOOD_SITE
    )
    assert state.public_view()["deployment_site_label"] == GOOD_SITE  # baseline renders
    return dataclasses.replace(state, deployment_site_label="AKIAIOSFODNN7EXAMPLE")


def test_the_projection_refuses_with_a_bounded_contract_error_not_a_raw_descriptor_error():
    """``scan_forbidden`` raises ``DescriptorError``, which is NOT a domain error. Seven routes
    project a state, so a raw one escapes as an unhandled 500 carrying an unbounded reason rather
    than the closed, redacted refusal every other failure on this path produces."""
    from secp_api.worker_enrollment_contract import WorkerEnrollmentContractError

    state = _hostile_state()
    with pytest.raises(WorkerEnrollmentContractError) as caught:
        state.public_view()
    assert caught.value.reason_code == "enrollment_state_corrupt"
    assert not isinstance(caught.value, DescriptorError)


def test_the_router_maps_a_bounded_contract_refusal_onto_the_redacted_domain_error():
    """The second half. ``WorkerEnrollmentContractError`` is a plain ``Exception``, so bounding the
    projection alone still 500s at the route — the mapping has to happen here too."""
    from secp_api.enums import WorkerEnrollmentErrorCode as EC
    from secp_api.errors import WorkerEnrollmentError
    from secp_api.routers.enrollment import _status_out

    with pytest.raises(WorkerEnrollmentError) as caught:
        _status_out(_hostile_state())
    assert caught.value.code == EC.state_corrupt.value


def test_an_unknown_contract_reason_code_fails_closed_rather_than_leaking_it():
    """A code outside the closed vocabulary must not reach the wire as a raw string."""
    from secp_api.enums import WorkerEnrollmentErrorCode as EC
    from secp_api.errors import WorkerEnrollmentError
    from secp_api.routers.enrollment import _status_out
    from secp_api.worker_enrollment_contract import WorkerEnrollmentContractError

    class _Rogue:
        def public_view(self):
            raise WorkerEnrollmentContractError("something_not_in_the_vocabulary")

    with pytest.raises(WorkerEnrollmentError) as caught:
        _status_out(_Rogue())
    assert caught.value.code == EC.internal_failure.value
    assert "something_not_in_the_vocabulary" not in str(caught.value.code)


def test_revoking_a_planted_row_is_a_bounded_refusal_end_to_end(client, session):
    """The operator-visible outcome of the original crash, kept as a regression.

    This does NOT pin the projection fix (see the note above — the repository refuses first). What
    it pins is that the ROUTE answers with a closed, redacted code instead of an unhandled
    exception, whichever layer refuses.
    """
    created = _create(client)
    assert created.status_code == 201
    enrollment_id = created.json()["enrollment_id"]
    _plant_unrenderable_label(session, enrollment_id, "AKIAIOSFODNN7EXAMPLE")

    revoked = client.post(
        f"/api/v1/enrollment/{enrollment_id}/revoke", json={"expected_revision": 0}
    )

    assert revoked.status_code == 409, revoked.text
    body = revoked.json()
    assert body["error"]["code"].startswith("enrollment_"), body
    assert "DescriptorError" not in revoked.text
    assert "forbidden_secret_value" not in revoked.text


def _plant_unrenderable_label(session, enrollment_id: str, value: str) -> None:
    """Persist a label the projection cannot render, on BOTH authoritative rows.

    Both, because ``_cross_check_invitation`` compares the state row's label against the invitation
    row's and refuses a disagreement — planting only one would exercise that check instead of the
    projection, which is a different thing entirely.
    """
    from secp_api.worker_enrollment_models import WorkerEnrollmentInvitation as InvRow
    from secp_api.worker_enrollment_models import WorkerEnrollmentState as StateRow

    state_row = session.get(StateRow, enrollment_id)
    assert state_row is not None
    state_row.deployment_site_label = value
    invitation_row = (
        session.query(InvRow).filter(InvRow.enrollment_id == enrollment_id).one_or_none()
    )
    assert invitation_row is not None
    invitation_row.deployment_site_label = value
    session.commit()


def test_a_row_persisted_before_the_fix_stays_pageable_past(client, session):
    """Defence in depth, and the reason no NEW recovery mechanism was added.

    A label planted below the API routes through the SAME ``page_integrity`` keyset recovery that
    already exists: ``_validate_rehydrated`` re-checks the label on every load, ``load_page`` wraps
    the refusal with the failing row's keyset position, and the caller pages past it. No parallel
    recovery path was invented, because that would be surface area for a state the write-path fix
    makes unreachable.
    """
    ids = [_create(client, ttl=3600 + i).json()["enrollment_id"] for i in range(5)]
    ordered = [item["enrollment_id"] for item in client.get("/api/v1/enrollment").json()["items"]]
    assert len(ordered) == 5
    victim = ordered[2]

    _plant_unrenderable_label(session, victim, "AKIAIOSFODNN7EXAMPLE")

    refused = client.get("/api/v1/enrollment")
    assert refused.status_code == 409, refused.text
    error = refused.json()["error"]
    assert error["code"] == "enrollment_page_integrity", error
    recovery = error.get("recovery_cursor")
    assert isinstance(recovery, str) and recovery, (
        "the refusal carries no recovery cursor, so the rest of the inventory is unreachable"
    )

    rest = client.get("/api/v1/enrollment", params={"after": recovery})
    assert rest.status_code == 200, rest.text
    reachable = [item["enrollment_id"] for item in rest.json()["items"]]
    assert victim not in reachable
    assert set(ordered[3:]) <= set(reachable), "rows after the poison row must be reachable"
    assert set(reachable) <= set(ids)
