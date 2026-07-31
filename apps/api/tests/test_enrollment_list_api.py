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
    forged = svc._encode_cursor("2026-07-21T00:00:00+00:00", "sha256:" + "0" * 64)
    ids = [item["enrollment_id"] for item in _list(client, after=forged).json()["items"]]
    assert foreign.state.enrollment_id not in ids
