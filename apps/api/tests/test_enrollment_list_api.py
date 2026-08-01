"""Org-scoped worker-enrollment inventory listing (SECP WS-B R1) + the site-label projection (R2).

Drives ``GET /api/v1/enrollment`` through the real ASGI app: keyset paging over
``(expires_at, enrollment_id)``, the closed state-filter vocabulary, the hard page ceiling, the
organization boundary, the strict ``enrollment:read`` / ``enrollment:manage`` separation, and the
invariant that NO invitation material is reachable from a list response.

The list deliberately reaches WIDER than the expiry sweep's candidate query: it includes revoked,
terminal and healthy enrollments, because that is exactly the inventory an operator needs.
"""

from __future__ import annotations

import secrets
import uuid

import pytest
from fastapi.testclient import TestClient
from secp_api.auth import Principal
from secp_api.deps import current_principal
from secp_api.enums import Permission, WorkerEnrollmentStateName
from secp_api.worker_enrollment_contract import ALL_STATES, create_invitation, sha256_digest_of_hex

CTRL_HEX = (b"\x11" * 32).hex()
CTRL_KEY = sha256_digest_of_hex(CTRL_HEX)
RELEASE = "sha256:" + "a" * 64
ORIGIN = "https://ctrl.example.com"
SITE = "rack-01.eu_a"
OTHER_SITE = "rack-02.eu_b"


def _principal(org_id: uuid.UUID, perms) -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        organization_id=org_id,
        email="rbac@test",
        permissions=frozenset(perms),
    )


def _as(client: TestClient, principal: Principal) -> TestClient:
    client.app.dependency_overrides[current_principal] = lambda: principal
    return client


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
    return TestClient(app)


def _create_body(**over: object) -> dict:
    body: dict = dict(
        idempotency_key=secrets.token_urlsafe(24),
        deployment_site_label=SITE,
        ttl_seconds=3600,
    )
    body.update(over)
    return body


def _create(client: TestClient, **over: object) -> dict:
    r = client.post("/api/v1/enrollment/invitations", json=_create_body(**over))
    assert r.status_code == 201, r.text
    return r.json()


def _list(client: TestClient, **params: object):
    r = client.get("/api/v1/enrollment", params=params)
    return r


# --- R2: the deployment-site label rides the status projection ----------------------------------


def test_status_projection_carries_the_deployment_site_label(client):
    created = _create(client, deployment_site_label=OTHER_SITE)
    status = client.get(f"/api/v1/enrollment/{created['enrollment_id']}")
    assert status.status_code == 200, status.text
    assert status.json()["deployment_site_label"] == OTHER_SITE


def test_site_label_is_not_part_of_the_canonical_contract(client, session, principal):
    """R2's whole safety argument: the label must never reach a digest or the CAS chain.

    ``client`` is requested for its schema-head stamp, which the durable service requires.
    """
    from secp_api.services import worker_enrollment as svc

    invitation = create_invitation(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        transaction_id="txn-site",
        nonce="sha256:" + "c" * 64,
        created_at="2026-07-21T00:00:00Z",
        expires_at="2026-07-21T01:00:00Z",
    )
    loaded = svc.create_invitation_and_open(
        session,
        principal,
        invitation=invitation,
        deployment_site_label=SITE,
        now="2026-07-21T00:10:00Z",
    )
    session.commit()
    state = loaded.state
    assert state.deployment_site_label == SITE
    assert "deployment_site_label" not in state.canonical()
    # the digest is identical with and without the label — proof it cannot move the CAS chain
    from dataclasses import replace

    assert replace(state, deployment_site_label="totally-different").digest() == state.digest()
    # ...and the projection still surfaces it
    assert state.public_view()["deployment_site_label"] == SITE


def test_site_label_survives_a_reload_from_persistence(client):
    """The authoritative value comes from the row, not from process memory."""
    created = _create(client, deployment_site_label=OTHER_SITE)
    first = client.get(f"/api/v1/enrollment/{created['enrollment_id']}").json()
    second = client.get(f"/api/v1/enrollment/{created['enrollment_id']}").json()
    assert first["deployment_site_label"] == second["deployment_site_label"] == OTHER_SITE


# --- R1: the org-scoped list --------------------------------------------------------------------


def test_list_returns_created_enrollments_with_status_shape(client):
    created = _create(client)
    r = _list(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"items", "next_cursor"}
    ids = [item["enrollment_id"] for item in body["items"]]
    assert created["enrollment_id"] in ids
    item = next(i for i in body["items"] if i["enrollment_id"] == created["enrollment_id"])
    assert item["state"] == "invited"
    assert item["revision"] == 0
    assert item["deployment_site_label"] == SITE


def test_list_carries_no_invitation_material(client):
    """The one-shot decision: an invitation is returned by create and nowhere else."""
    _create(client)
    body = _list(client).json()
    assert body["items"], "expected at least one enrollment"
    forbidden = {
        "invitation_id",
        "controller_trust_anchor_hex",
        "controller_origin",
        "controller_key_id",
        "release_digest",
        "transaction_id",
    }
    for item in body["items"]:
        assert forbidden.isdisjoint(item), f"invitation material leaked into the list: {item}"


def test_list_is_ordered_by_expiry_then_enrollment_id(client):
    # distinct TTLs give a deterministic expiry order that is NOT creation order
    _create(client, ttl_seconds=3600)
    _create(client, ttl_seconds=60)
    _create(client, ttl_seconds=1800)
    items = _list(client).json()["items"]
    keys = [(item["expires_at"], item["enrollment_id"]) for item in items]
    assert keys == sorted(keys), "the page must be in ascending (expires_at, enrollment_id) order"


def test_list_is_scoped_to_the_callers_organization(client, session, other_org_principal):
    """Organization is the ONLY authorization boundary — another org's rows are simply absent."""
    from secp_api.services import worker_enrollment as svc

    invitation = create_invitation(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        transaction_id="txn-cross",
        nonce="sha256:" + "b" * 64,
        created_at="2026-07-21T00:00:00Z",
        expires_at="2026-07-21T01:00:00Z",
    )
    foreign = svc.create_invitation_and_open(
        session,
        other_org_principal,
        invitation=invitation,
        deployment_site_label=SITE,
        now="2026-07-21T00:10:00Z",
    )
    session.commit()
    mine = _create(client)

    ids = [item["enrollment_id"] for item in _list(client).json()["items"]]
    assert mine["enrollment_id"] in ids
    assert foreign.state.enrollment_id not in ids, (
        "cross-organization enrollment leaked into a list"
    )


def test_list_requires_enrollment_read_and_manage_does_not_imply_it(client, principal):
    """PINNED: manage does NOT imply read (strict separation) — the list follows the same rule."""
    _create(client)
    org = principal.organization_id

    _as(client, _principal(org, [Permission.enrollment_read]))
    assert _list(client).status_code == 200

    _as(client, _principal(org, [Permission.enrollment_manage]))
    assert _list(client).status_code == 403

    _as(client, _principal(org, []))
    assert _list(client).status_code == 403


def test_unauthenticated_list_is_401(client):
    from secp_api.errors import AuthenticationError

    def _raise() -> Principal:
        raise AuthenticationError("no credential")

    client.app.dependency_overrides[current_principal] = _raise
    assert _list(client).status_code == 401


# --- state filtering ----------------------------------------------------------------------------


def test_state_filter_selects_only_the_requested_states(client, session, principal):
    from secp_api.services import worker_enrollment as svc

    live = _create(client)
    revoked = _create(client)
    svc.revoke_enrollment(
        session, principal, enrollment_id=revoked["enrollment_id"], expected_revision=0
    )
    session.commit()

    invited = [i["enrollment_id"] for i in _list(client, state="invited").json()["items"]]
    assert live["enrollment_id"] in invited
    assert revoked["enrollment_id"] not in invited

    refused = [i["enrollment_id"] for i in _list(client, state="refused").json()["items"]]
    assert revoked["enrollment_id"] in refused
    assert live["enrollment_id"] not in refused


def test_state_filter_is_repeatable(client, session, principal):
    from secp_api.services import worker_enrollment as svc

    live = _create(client)
    revoked = _create(client)
    svc.revoke_enrollment(
        session, principal, enrollment_id=revoked["enrollment_id"], expected_revision=0
    )
    session.commit()

    r = client.get("/api/v1/enrollment", params=[("state", "invited"), ("state", "refused")])
    assert r.status_code == 200, r.text
    ids = [item["enrollment_id"] for item in r.json()["items"]]
    assert live["enrollment_id"] in ids and revoked["enrollment_id"] in ids


def test_list_includes_revoked_and_terminal_states_unlike_the_sweep(client, session, principal):
    """The sweep excludes revoked/terminal rows for forward progress; the inventory must not."""
    from secp_api.services import worker_enrollment as svc

    revoked = _create(client)
    svc.revoke_enrollment(
        session, principal, enrollment_id=revoked["enrollment_id"], expected_revision=0
    )
    session.commit()

    unfiltered = [item["enrollment_id"] for item in _list(client).json()["items"]]
    assert revoked["enrollment_id"] in unfiltered


def test_unknown_state_filter_is_422(client):
    assert _list(client, state="not-a-state").status_code == 422


def test_state_filter_vocabulary_matches_the_contract_exactly(client):
    """Fails closed if a state is added to the contract without the request vocabulary."""
    assert tuple(entry.value for entry in WorkerEnrollmentStateName) == ALL_STATES
    for state in ALL_STATES:
        assert _list(client, state=state).status_code == 200, state


# --- paging -------------------------------------------------------------------------------------


def test_keyset_paging_walks_every_row_exactly_once(client):
    created = {_create(client, ttl_seconds=60 + index)["enrollment_id"] for index in range(5)}

    seen: list[str] = []
    cursor = None
    for _ in range(10):  # bounded walk; 5 rows at limit 2 needs 3 pages
        params: dict = {"limit": 2}
        if cursor is not None:
            params["after"] = cursor
        body = _list(client, **params).json()
        assert len(body["items"]) <= 2
        seen.extend(item["enrollment_id"] for item in body["items"])
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert cursor is None, "paging did not terminate"
    assert len(seen) == len(set(seen)), "keyset paging repeated a row"
    assert created <= set(seen), "keyset paging skipped a row"


def test_next_cursor_is_null_on_a_partial_final_page(client):
    _create(client)
    body = _list(client, limit=200).json()
    assert body["next_cursor"] is None


def test_next_cursor_is_present_when_the_page_is_full(client):
    _create(client)
    _create(client)
    body = _list(client, limit=1).json()
    assert len(body["items"]) == 1
    assert isinstance(body["next_cursor"], str) and body["next_cursor"]


def test_limit_is_bounded_server_side(client):
    assert _list(client, limit=201).status_code == 422
    assert _list(client, limit=0).status_code == 422
    assert _list(client, limit=200).status_code == 200


def test_default_limit_is_fifty(client):
    from secp_api.services.worker_enrollment import DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT

    assert DEFAULT_LIST_LIMIT == 50
    assert MAX_LIST_LIMIT == 200


def test_service_layer_clamps_a_limit_a_router_bypass_would_allow(client, session, principal):
    """A direct service call cannot exceed the ceiling either."""
    from secp_api.services import worker_enrollment as svc

    items, _ = svc.list_public_views(session, principal, limit=10_000)
    assert len(items) <= svc.MAX_LIST_LIMIT


@pytest.mark.parametrize(
    "bad",
    [
        "not-base64-!!",
        "",
        "x" * 300,
        "YWJj",  # valid base64, but not a cursor payload
    ],
)
def test_malformed_cursor_is_a_bounded_refusal(client, bad):
    """A bad cursor refuses; it must never silently degrade into an unpositioned scan."""
    _create(client)
    r = _list(client, after=bad)
    assert r.status_code == 422
    assert "items" not in r.json(), "a refused cursor must not return a page"


def test_cursor_from_another_page_cannot_reach_another_organization(
    client, session, other_org_principal, principal
):
    """A cursor is only ever a keyset POSITION inside the caller's own org-filtered query."""
    from secp_api.services import worker_enrollment as svc

    invitation = create_invitation(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        transaction_id="txn-cursor",
        nonce="sha256:" + "d" * 64,
        created_at="2026-07-21T00:00:00Z",
        expires_at="2026-07-21T01:00:00Z",
    )
    foreign = svc.create_invitation_and_open(
        session,
        other_org_principal,
        invitation=invitation,
        deployment_site_label=SITE,
        now="2026-07-21T00:10:00Z",
    )
    session.commit()

    # forge a cursor positioned just before the foreign row and present it as our own
    forged = svc._encode_cursor("2026-07-21T00:00:00+00:00", "sha256:" + "0" * 64, None)
    ids = [item["enrollment_id"] for item in _list(client, after=forged).json()["items"]]
    assert foreign.state.enrollment_id not in ids


# --- R3: the operator-triggered recovery route ---------------------------------------------------


def test_operator_can_mark_an_enrollment_recovery_required(client):
    created = _create(client)
    r = client.post(
        f"/api/v1/enrollment/{created['enrollment_id']}/recover",
        json={"expected_revision": 0},
    )
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "recovery_required"
    assert r.json()["refusal_reason"] == "operator_recovery_required"


def test_operator_recovery_is_idempotent_on_a_terminal_enrollment(client):
    created = _create(client)
    body = {"expected_revision": 0}
    first = client.post(f"/api/v1/enrollment/{created['enrollment_id']}/recover", json=body)
    second = client.post(f"/api/v1/enrollment/{created['enrollment_id']}/recover", json=body)
    assert first.status_code == second.status_code == 200
    assert second.json()["revision"] == first.json()["revision"], "no second write"


def test_operator_recovery_refuses_a_stale_revision(client):
    created = _create(client)
    r = client.post(
        f"/api/v1/enrollment/{created['enrollment_id']}/recover",
        json={"expected_revision": 7},
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "enrollment_revision_conflict"


def test_operator_recovery_requires_manage(client, principal):
    created = _create(client)
    org = principal.organization_id
    body = {"expected_revision": 0}

    _as(client, _principal(org, [Permission.enrollment_read]))
    assert (
        client.post(f"/api/v1/enrollment/{created['enrollment_id']}/recover", json=body).status_code
        == 403
    )

    _as(client, _principal(org, [Permission.enrollment_manage]))
    assert (
        client.post(f"/api/v1/enrollment/{created['enrollment_id']}/recover", json=body).status_code
        == 200
    )


def test_operator_recovery_rejects_a_caller_supplied_reason(client):
    """The reason code is server-owned — never caller free-text that could carry a path/secret."""
    created = _create(client)
    r = client.post(
        f"/api/v1/enrollment/{created['enrollment_id']}/recover",
        json={"expected_revision": 0, "reason": "anything"},
    )
    assert r.status_code == 422


def test_cross_org_recovery_is_forbidden(client, session, other_org_principal):
    from secp_api.services import worker_enrollment as svc

    invitation = create_invitation(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        transaction_id="txn-recover",
        nonce="sha256:" + "e" * 64,
        created_at="2026-07-21T00:00:00Z",
        expires_at="2026-07-21T01:00:00Z",
    )
    foreign = svc.create_invitation_and_open(
        session,
        other_org_principal,
        invitation=invitation,
        deployment_site_label=SITE,
        now="2026-07-21T00:10:00Z",
    )
    session.commit()

    r = client.post(
        f"/api/v1/enrollment/{foreign.state.enrollment_id}/recover",
        json={"expected_revision": 0},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "enrollment_forbidden"


def test_the_lifecycle_service_now_requires_an_explicit_permission(client, session, principal):
    """refuse/recover were authorized by the ORGANIZATION BOUNDARY ALONE; that gap is closed."""
    from secp_api.errors import AuthorizationError
    from secp_api.services import worker_enrollment as svc

    created = _create(client)
    org = principal.organization_id
    # same organization, but no enrollment:manage — the org boundary alone must not authorize it
    read_only = _principal(org, [Permission.enrollment_read])
    loaded = svc.load_public_view(session, read_only, enrollment_id=created["enrollment_id"])
    expected = svc.ExpectedRevision(
        revision=loaded["revision"], state_digest="", sequence=0, predecessor_digest=""
    )
    with pytest.raises(AuthorizationError):
        svc.recover_enrollment(
            session,
            read_only,
            enrollment_id=created["enrollment_id"],
            reason="operator_recovery_required",
            expected=expected,
        )
    with pytest.raises(AuthorizationError):
        svc.refuse_enrollment(
            session,
            read_only,
            enrollment_id=created["enrollment_id"],
            reason="operator_recovery_required",
            expected=expected,
        )


# --- page integrity: distinct code + recourse past the unrenderable row --------------------------


def _corrupt_head_row(session, enrollment_id: str) -> None:
    """Break a head row's canonical digest so it can no longer be projected."""
    from secp_api.worker_enrollment_models import WorkerEnrollmentState as StateRow

    row = session.get(StateRow, enrollment_id)
    row.state_digest = "sha256:" + "0" * 64
    session.commit()


def _break_history(session, enrollment_id: str) -> None:
    """Delete a revision-history row: the head/history disagree, which a status read refuses."""
    from secp_api.worker_enrollment_models import WorkerEnrollmentRevision as RevisionRow

    session.query(RevisionRow).filter(RevisionRow.enrollment_id == enrollment_id).delete()
    session.commit()


def test_a_page_integrity_failure_uses_a_code_distinct_from_state_corrupt(client, session):
    """A UI must tell 'this page has an unrenderable row' from 'this one enrollment is corrupt'."""
    created = _create(client)
    _corrupt_head_row(session, created["enrollment_id"])

    r = _list(client)

    assert r.status_code == 409
    assert r.json()["error"]["code"] == "enrollment_page_integrity"
    assert r.json()["error"]["code"] != "enrollment_state_corrupt"


def test_the_page_integrity_error_carries_a_cursor_that_pages_past_the_bad_row(client, session):
    """The recourse: without it, every enrollment ordered after a poison row is unreachable."""
    ids = [_create(client, ttl_seconds=60 + i)["enrollment_id"] for i in range(5)]
    order = [i["enrollment_id"] for i in _list(client).json()["items"]]
    victim = order[2]
    _corrupt_head_row(session, victim)

    failed = _list(client)
    assert failed.status_code == 409
    recovery = failed.json()["error"]["recovery_cursor"]
    assert isinstance(recovery, str) and recovery

    # paging past the bad row reaches the rest of the inventory
    rest = _list(client, after=recovery)
    assert rest.status_code == 200, rest.text
    reachable = [item["enrollment_id"] for item in rest.json()["items"]]
    assert victim not in reachable
    assert set(order[3:]) <= set(reachable), "rows after the poison row must become reachable"
    assert set(ids) - {victim} >= set(reachable)


def test_the_page_integrity_error_body_carries_no_id_label_or_reason(client, session):
    created = _create(client, deployment_site_label=OTHER_SITE)
    _corrupt_head_row(session, created["enrollment_id"])

    body = _list(client).json()

    assert set(body["error"]) == {"code", "recovery_cursor"}
    assert created["enrollment_id"] not in body["error"]["code"]
    assert OTHER_SITE not in str(body)
    assert "corrupt" not in body["error"]["code"]


def test_a_page_integrity_failure_is_audited_with_the_failing_enrollment_id(client, session):
    """The id appears server-side ONLY — that is what makes the condition diagnosable at all."""
    from secp_api.models import AuditEvent

    created = _create(client)
    _corrupt_head_row(session, created["enrollment_id"])

    assert _list(client).status_code == 409

    session.expire_all()
    rows = (
        session.query(AuditEvent).filter(AuditEvent.resource_id == created["enrollment_id"]).all()
    )
    actions = {getattr(r.action, "value", r.action) for r in rows}
    assert "enrollment.page_integrity_failed" in actions, actions


def test_a_history_inconsistent_row_fails_the_list_exactly_as_it_fails_the_detail(client, session):
    """The documented invariant: a list must not surface a row whose own detail view refuses."""
    created = _create(client)
    _break_history(session, created["enrollment_id"])

    detail = client.get(f"/api/v1/enrollment/{created['enrollment_id']}")
    listing = _list(client)

    assert detail.status_code == 409
    assert detail.json()["error"]["code"] == "enrollment_history_inconsistent"
    # the list must NOT return 200 with the row a detail read refuses
    assert listing.status_code == 409
    assert listing.json()["error"]["code"] == "enrollment_page_integrity"


# --- the cursor binds the state filter it was minted under ---------------------------------------


def test_a_cursor_minted_under_one_filter_is_refused_under_another(client):
    """Replaying a cursor across filters would silently omit matching rows — refuse instead."""
    for index in range(3):
        _create(client, ttl_seconds=60 + index)

    page = _list(client, state="invited", limit=1).json()
    cursor = page["next_cursor"]
    assert cursor

    same = client.get("/api/v1/enrollment", params={"state": "invited", "after": cursor})
    assert same.status_code == 200, "the cursor still works under the filter that minted it"

    other = client.get("/api/v1/enrollment", params={"state": "refused", "after": cursor})
    assert other.status_code == 422
    assert other.json()["error"]["code"] == "enrollment_cursor_invalid"

    unfiltered = client.get("/api/v1/enrollment", params={"after": cursor})
    assert unfiltered.status_code == 422, "no filter is a DIFFERENT filter, not a superset"


def test_the_filter_binding_is_order_and_duplicate_insensitive(client):
    """The filter is a set; reordering or repeating ?state= must not invalidate a live cursor."""
    for index in range(3):
        _create(client, ttl_seconds=60 + index)

    minted = client.get(
        "/api/v1/enrollment",
        params=[("state", "invited"), ("state", "refused"), ("limit", 1)],
    ).json()["next_cursor"]
    assert minted

    reordered = client.get(
        "/api/v1/enrollment",
        params=[
            ("state", "refused"),
            ("state", "invited"),
            ("state", "invited"),
            ("after", minted),
        ],
    )
    assert reordered.status_code == 200, reordered.text


def test_an_unfiltered_cursor_round_trips_unfiltered(client):
    for index in range(3):
        _create(client, ttl_seconds=60 + index)

    cursor = _list(client, limit=1).json()["next_cursor"]
    assert cursor
    assert _list(client, after=cursor).status_code == 200


def test_the_recovery_cursor_carries_the_same_filter_binding(client, session):
    """Otherwise the recourse hands back a cursor that 422s under the filter already in use."""
    for index in range(4):
        _create(client, ttl_seconds=60 + index)
    order = [i["enrollment_id"] for i in _list(client, state="invited").json()["items"]]
    _corrupt_head_row(session, order[1])

    failed = client.get("/api/v1/enrollment", params={"state": "invited"})
    assert failed.status_code == 409
    recovery = failed.json()["error"]["recovery_cursor"]

    # usable with the SAME filter that produced it...
    resumed = client.get("/api/v1/enrollment", params={"state": "invited", "after": recovery})
    assert resumed.status_code == 200, resumed.text
    # ...and still refused under a different one
    crossed = client.get("/api/v1/enrollment", params={"state": "healthy", "after": recovery})
    assert crossed.status_code == 422
