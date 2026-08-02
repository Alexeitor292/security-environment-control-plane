"""The browser client's declared enrollment types vs. what the API actually serves.

PR #72 ("runtime contract verification") established that ``apps/web/src/api/types.ts`` and the
controller's enrollment responses agree. That verification was real and it was correct — and it
lived entirely in a reviewer's session. Nothing in this repository re-checked any of it, so the
next drift would have landed silently. This module is that verification made durable.

How the two sides are derived, and why it has to be this way
-----------------------------------------------------------
The **API side is read off a live HTTP response over a real TCP socket** — uvicorn serving the real
application, an ordinary HTTP client, real routing, real ``response_model`` serialization, a real
database. It is emphatically *not* derived by importing ``secp_api.schemas_enrollment``. An
instrument that imports the module the API is built from would agree with the API by construction:
it would stay green through any change made in that module, which is precisely the drift worth
catching. Deriving from the served bytes means the comparison has two genuinely independent sides.

The **client side is parsed out of ``types.ts`` as text** (``ts_type_reader``), never imported,
transpiled or type-checked against anything. Same reason, from the other direction.

What is compared, and one row that cannot be live
-------------------------------------------------
Live, against served response bodies:

* ``EnrollmentStatus`` against the single-read body *and* against a list item — the list is a
  separate serialization path and has to be measured separately, not assumed to match;
* ``EnrollmentInvitation`` against the create body;
* ``EnrollmentInvitationCreate`` by *sending* exactly the fields the client declares — the server's
  ``extra="forbid"`` turns a client-only request field into a 422, so this is checked by being
  accepted rather than by inspection;
* ``EnrollmentListPage`` including ``next_cursor`` nullability, observed as *both* a cursor string
  and a null across two real pages;
* the invitation-only fields, confirmed unreachable from a status read and from a list item.

One row is **static and is labelled as such** rather than presented as live:
``EnrollmentLifecycleState`` against ``worker_enrollment_contract.ALL_STATES`` is a TS-file to
Python-module comparison. It cannot be live because a controller only ever exhibits the states its
records happen to hold — one, ``invited``, on a freshly created enrollment — and
:func:`test_the_live_surface_cannot_cover_the_lifecycle_vocabulary` measures that rather than
asserting it. The static row is still not vacuous: the two sides are independently authored, so it
does catch a state added on one side only. It is simply weaker evidence than the live rows, and
saying so is the point.

Note for future readers: ``recovery_required`` is a *lifecycle state value*, never a field. It
reads like a field name and has been mistaken for one before.

Provenance
----------
Authored on ``feature/secp-web-api-contract-guard`` at ``d90daad8``, transferred here because this
is the branch that owns ``apps/web/src/api/types.ts`` — the file the client side of this comparison
is parsed out of. The guard and the types it guards belong in one place.

One change was made in the move. That branch also carried its own copy of the live-server harness,
``apps/api/tests/live_api_server.py``, with a note saying to delete it and import
``socket_gate_tests.live_api_server`` once the socket gate landed. It landed on ``main`` in #77, so
the copy was not transferred and this imports the canonical module instead. That copy annotated the
ASGI app ``Any`` rather than ``object``; the canonical keeps ``object`` and is not changed here,
because the stated reason for the deviation — that ``apps/api/tests`` is on the checked mypy path —
does not hold as CI stands: CI's mypy step names eight explicit paths and that is not one of them.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from secp_api.worker_enrollment_contract import ALL_STATES
from socket_gate_tests.live_api_server import live_api_server
from ts_type_reader import (
    interface_field_is_nullable,
    interface_fields,
    read_source,
    strip_comments,
    type_union_members,
)

#: Repository-relative so a failure message names a path a reader can open.
TYPES_TS_RELATIVE = "apps/web/src/api/types.ts"
_REPO_ROOT = Path(__file__).resolve().parents[3]
TYPES_TS = _REPO_ROOT / "apps" / "web" / "src" / "api" / "types.ts"

SITE_LABEL = "rack-01.eu_a"
TTL_SECONDS = 3600

#: Bounded walk over the paged list. Two enrollments at limit=1 terminate well inside this; the
#: bound exists so a list that never stops paging fails as a harness error instead of hanging.
_MAX_PAGE_WALK = 10

#: Sample values for the fields ``EnrollmentInvitationCreate`` declares. Keyed by name so that a
#: field added to the client's request type has no value here and fails loudly, rather than being
#: quietly dropped from the request and leaving the new field unchecked.
_CREATE_SAMPLES: dict[str, Any] = {
    "idempotency_key": None,  # filled per call: must be unique and single-use
    "deployment_site_label": SITE_LABEL,
    "ttl_seconds": TTL_SECONDS,
}

#: Sample values for the fields ``EnrollmentListQuery`` declares, same contract as above: a query
#: parameter the client grows and this guard does not know about fails rather than going unsent.
#: ``after`` is replaced with a real cursor at call time — a fabricated one is not a valid probe.
_LIST_QUERY_SAMPLES: dict[str, Any] = {
    "state": ["invited"],
    "limit": 1,
    "after": None,
}


# --- the live surface ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LiveContract:
    """Response bodies as a client received them over a socket."""

    invitation: dict
    status: dict
    first_page: dict
    last_page: dict
    full_page: dict
    #: (status_code, body) of a list call sending every field ``EnrollmentListQuery`` declares.
    query_probe: tuple[int, dict]

    @property
    def list_item(self) -> dict:
        return self.full_page["items"][0]

    @property
    def observed_states(self) -> frozenset[str]:
        return frozenset(item["state"] for item in self.full_page["items"])


def _create_body(ts_source: str) -> dict:
    """Build the create request from the field names the *client* declares."""
    declared = interface_fields(ts_source, "EnrollmentInvitationCreate")
    unknown = sorted(declared - set(_CREATE_SAMPLES))
    assert not unknown, (
        f"contract drift between {TYPES_TS_RELATIVE} and this guard.\n"
        f"  `export interface EnrollmentInvitationCreate` declares {unknown}, for which this "
        f"guard has no sample value. Add one to _CREATE_SAMPLES so the new request field is "
        f"actually exercised against the server, rather than silently omitted from the request."
    )
    body = {name: _CREATE_SAMPLES[name] for name in declared}
    if "idempotency_key" in body:
        body["idempotency_key"] = secrets.token_urlsafe(24)
    return body


@pytest.fixture(scope="module")
def live(tmp_path_factory) -> LiveContract:
    """Serve the real app over a real socket and collect the bodies a client receives.

    Module-scoped: one server, one set of bodies, shared read-only by every comparison below. The
    database is a fresh file-backed SQLite per module, rebound through the same
    ``reset_engine_for_tests`` seam the rest of the suite uses.
    """
    import secp_api.immutability  # noqa: F401  (registers ORM immutability guards)
    from secp_api.db import get_sessionmaker, reset_engine_for_tests
    from secp_api.deps import current_principal
    from secp_api.main import create_app
    from secp_api.models import Base
    from secp_api.seed import bootstrap_dev
    from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD

    database = tmp_path_factory.mktemp("web-contract-guard") / "contract.db"
    engine = reset_engine_for_tests(f"sqlite+pysqlite:///{database.as_posix()}")
    Base.metadata.create_all(engine)

    session = get_sessionmaker()()
    principal = bootstrap_dev(session)
    session.commit()
    session.close()

    # The durable enrollment service refuses unless the runtime schema head is stamped.
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
    # Authentication only. Every route, schema, service and serialization step below is the shipped
    # one; nothing about the response *shape* is overridden.
    app.dependency_overrides[current_principal] = lambda: principal

    ts_source = read_source(TYPES_TS)

    with live_api_server(app) as server:
        with httpx.Client(base_url=server.base_url, timeout=30.0) as client:
            created = []
            for _ in range(2):
                response = client.post(
                    "/api/v1/enrollment/invitations", json=_create_body(ts_source)
                )
                assert response.status_code == 201, (
                    "the live API refused a create request built from the fields "
                    f"`export interface EnrollmentInvitationCreate` declares in "
                    f"{TYPES_TS_RELATIVE} (HTTP {response.status_code}): {response.text}"
                )
                created.append(response.json())

            status = client.get(f"/api/v1/enrollment/{created[0]['enrollment_id']}")
            assert status.status_code == 200, status.text

            # Page through at limit=1 so both a cursor string and a terminating null are observed
            # live. The walk is followed to exhaustion rather than assuming page 2 is the last:
            # a full page carries a cursor whether or not more records exist behind it.
            first = client.get("/api/v1/enrollment", params={"limit": 1})
            # A 404 here is a SEQUENCING fact, not a contract failure: the org-scoped list route
            # (and `next_cursor` with it) arrives with Stream B's backend work. Named explicitly so
            # a red run on a branch that predates it is self-explanatory and is not mistaken for
            # drift the guard was built to catch. Deliberately an assertion, never a skip — a
            # skipped live row renders as a pass and would hide the day the route regresses.
            assert first.status_code == 200, (
                f"GET /api/v1/enrollment returned {first.status_code}. If 404, this branch "
                f"predates the org-scoped enrollment list endpoint and every live row below is "
                f"unrunnable rather than failing; re-run once that contract is on main. "
                f"Body: {first.text}"
            )
            cursor = first.json()["next_cursor"]
            assert isinstance(cursor, str) and cursor, (
                "expected a continuation cursor on a limit=1 page over 2 enrollments; "
                f"got {cursor!r}. Without it the nullability check below would be vacuous."
            )
            last = first
            for _ in range(_MAX_PAGE_WALK):
                if last.json()["next_cursor"] is None:
                    break
                last = client.get(
                    "/api/v1/enrollment",
                    params={"limit": 1, "after": last.json()["next_cursor"]},
                )
                assert last.status_code == 200, last.text
            else:
                raise AssertionError(
                    f"the enrollment list did not terminate within {_MAX_PAGE_WALK} pages of "
                    "limit=1 over 2 enrollments; `next_cursor` may never become null."
                )

            full = client.get("/api/v1/enrollment")
            assert full.status_code == 200, full.text

            # Every field `EnrollmentListQuery` declares, sent at once. The client type has no
            # response body to compare against, so it is verified by being accepted.
            query_declared = interface_fields(ts_source, "EnrollmentListQuery")
            unknown_query = sorted(query_declared - set(_LIST_QUERY_SAMPLES))
            assert not unknown_query, (
                f"contract drift between {TYPES_TS_RELATIVE} and this guard.\n"
                f"  `export interface EnrollmentListQuery` declares {unknown_query}, for which "
                "this guard has no sample value. Add one to _LIST_QUERY_SAMPLES so the new query "
                "parameter is actually exercised against GET /api/v1/enrollment."
            )
            params: dict[str, Any] = {name: _LIST_QUERY_SAMPLES[name] for name in query_declared}
            if "after" in params:
                # A cursor is bound to the filter that produced it (the server refuses a cursor
                # carried across a different `state` filter, correctly). So the probe's cursor is
                # taken from a page requested with these very parameters.
                seed = client.get(
                    "/api/v1/enrollment",
                    params={key: value for key, value in params.items() if key != "after"},
                )
                assert seed.status_code == 200, seed.text
                params["after"] = seed.json()["next_cursor"]
            probe = client.get("/api/v1/enrollment", params=params)

            return LiveContract(
                invitation=created[0],
                status=status.json(),
                first_page=first.json(),
                last_page=last.json(),
                full_page=full.json(),
                query_probe=(probe.status_code, probe.json()),
            )


@pytest.fixture(scope="module")
def ts_source() -> str:
    return read_source(TYPES_TS)


# --- the reader is an instrument, so it is checked before anything relies on it ------------------


def test_the_declaration_file_is_present_and_non_empty(ts_source: str) -> None:
    """Positive control for every comparison below. An unreadable or empty ``types.ts`` yields
    empty field sets, which compare as "nothing missing" against literally any API."""
    assert len(ts_source) > 1000
    assert "export interface EnrollmentStatus" in ts_source


def test_the_reader_finds_fields_and_ignores_prose_that_names_fields(ts_source: str) -> None:
    """``EnrollmentStatus``'s doc comment names fields it deliberately does NOT carry ("no
    invitation id, no trust anchor, no transaction id"). A reader that did not strip comments
    would find them and the guard would fail for the wrong reason — or, worse, pass for one."""
    body_with_comments = ts_source[ts_source.index("export interface EnrollmentStatus") :]
    assert "no invitation id" in ts_source
    assert "invitation_id" not in strip_comments(body_with_comments).split("}")[0]

    fields = interface_fields(ts_source, "EnrollmentStatus")
    assert "enrollment_id" in fields
    assert "invitation_id" not in fields


def test_the_reader_raises_rather_than_returning_nothing() -> None:
    """Absence-of-match and absence-of-input look identical from the outside; only one is a
    finding. The reader must never hand a silent empty set to a comparison."""
    from ts_type_reader import TypeScriptReadError

    with pytest.raises(TypeScriptReadError):
        interface_fields("// nothing here\n", "EnrollmentStatus")
    with pytest.raises(TypeScriptReadError):
        type_union_members("// nothing here\n", "EnrollmentLifecycleState")


# --- LIVE: the client's declared shapes vs. bodies served over a socket --------------------------


def _drift_message(interface: str, served_by: str, ts_fields, live_fields) -> str:
    only_live = sorted(set(live_fields) - set(ts_fields))
    only_ts = sorted(set(ts_fields) - set(live_fields))
    lines = [f"enrollment contract drift ({TYPES_TS_RELATIVE} vs. the live API)."]
    if only_live:
        lines.append(
            f"  BACKEND ADDED : {served_by} returns {only_live}, which "
            f"`export interface {interface}` does not declare. The browser client will drop "
            f"{'these fields' if len(only_live) > 1 else 'this field'} on the floor."
        )
    if only_ts:
        lines.append(
            f"  CLIENT ORPHAN : `export interface {interface}` declares {only_ts}, which "
            f"{served_by} does not return. The client will read `undefined` at runtime."
        )
    return "\n".join(lines)


def test_enrollment_status_matches_the_live_single_read_body(live: LiveContract, ts_source) -> None:
    declared = interface_fields(ts_source, "EnrollmentStatus")
    served = frozenset(live.status)
    assert served, "the live status read returned an empty body"
    assert declared == served, _drift_message(
        "EnrollmentStatus", "GET /api/v1/enrollment/{enrollment_id}", declared, served
    )


def test_enrollment_status_matches_the_live_list_item_body(live: LiveContract, ts_source) -> None:
    """Measured separately from the single read: a list item is serialized by a different route,
    and "the list returns the same projection" is a claim, not a given."""
    declared = interface_fields(ts_source, "EnrollmentStatus")
    served = frozenset(live.list_item)
    assert served, "the live list returned an item with an empty body"
    assert declared == served, _drift_message(
        "EnrollmentStatus", "GET /api/v1/enrollment items[]", declared, served
    )


def test_enrollment_invitation_matches_the_live_create_body(live: LiveContract, ts_source) -> None:
    declared = interface_fields(ts_source, "EnrollmentInvitation")
    served = frozenset(live.invitation)
    assert served, "the live create returned an empty body"
    assert declared == served, _drift_message(
        "EnrollmentInvitation", "POST /api/v1/enrollment/invitations", declared, served
    )


def test_enrollment_list_page_matches_the_live_page_body(live: LiveContract, ts_source) -> None:
    declared = interface_fields(ts_source, "EnrollmentListPage")
    served = frozenset(live.full_page)
    assert served, "the live list returned an empty page body"
    assert declared == served, _drift_message(
        "EnrollmentListPage", "GET /api/v1/enrollment", declared, served
    )


def test_next_cursor_is_declared_nullable_and_is_observed_both_ways(
    live: LiveContract, ts_source
) -> None:
    """The client types ``next_cursor`` as ``string | null``. Both halves are observed live — a
    cursor on a page that has a successor, ``null`` on the last one — so neither the declaration
    nor the paging behaviour is taken on trust."""
    assert interface_field_is_nullable(ts_source, "EnrollmentListPage", "next_cursor"), (
        f"enrollment contract drift: `EnrollmentListPage.next_cursor` in {TYPES_TS_RELATIVE} no "
        "longer admits null, but GET /api/v1/enrollment returns null on the last page."
    )
    assert isinstance(live.first_page["next_cursor"], str)
    assert live.last_page["next_cursor"] is None, (
        "enrollment contract drift: GET /api/v1/enrollment returned "
        f"{live.last_page['next_cursor']!r} as `next_cursor` on the last page, but "
        f"`EnrollmentListPage.next_cursor` in {TYPES_TS_RELATIVE} declares null there."
    )


def test_no_invitation_only_field_is_reachable_from_a_status_read_or_a_list(
    live: LiveContract,
) -> None:
    """The invitation is bearer-grade and one-shot: only the create response may carry it. Derived
    from the live bodies rather than from a hardcoded list, so a field added to the invitation is
    covered the day it appears."""
    invitation_only = frozenset(live.invitation) - frozenset(live.status)
    assert invitation_only, (
        "the live create and status bodies have identical field sets, so this test would pass "
        "vacuously. Either the invitation stopped carrying its own material or the status "
        "projection started carrying it."
    )

    leaked_to_status = sorted(invitation_only & frozenset(live.status))
    leaked_to_list = sorted(invitation_only & frozenset(live.list_item))
    assert not leaked_to_status, (
        f"invitation material leaked: GET /api/v1/enrollment/{{id}} returned {leaked_to_status}, "
        "which only POST /api/v1/enrollment/invitations may return. The invitation is a "
        "single-use bearer capability (see the one-shot decision in secp_api.schemas_enrollment)."
    )
    assert not leaked_to_list, (
        f"invitation material leaked: GET /api/v1/enrollment items[] returned {leaked_to_list}, "
        "which only POST /api/v1/enrollment/invitations may return."
    )


def test_the_client_declares_every_invitation_only_field_it_is_handed(
    live: LiveContract, ts_source
) -> None:
    """The one-shot fields are the ones a client can never re-fetch, so a client that fails to
    declare one loses it permanently rather than re-reading it later."""
    invitation_only = frozenset(live.invitation) - frozenset(live.status)
    declared = interface_fields(ts_source, "EnrollmentInvitation")
    missing = sorted(invitation_only - declared)
    assert not missing, (
        f"enrollment contract drift: POST /api/v1/enrollment/invitations returns {missing}, "
        f"which `export interface EnrollmentInvitation` in {TYPES_TS_RELATIVE} does not declare. "
        "No route re-serves the invitation, so a field the client does not read is lost for good."
    )


# --- STATIC: a TS file compared against a Python module, and labelled as such --------------------


def test_the_live_surface_cannot_cover_the_lifecycle_vocabulary(live: LiveContract) -> None:
    """The measured justification for the static row below, rather than a claim about it.

    A live controller exhibits only the states its records happen to hold. Reaching the rest would
    mean driving worker proof-of-possession exchanges, an expiry sweep and an operator revoke —
    a different and much larger instrument than a contract guard. This measures the gap so the
    next reader can see why the comparison that follows is static.
    """
    observed = live.observed_states
    assert observed, "no enrollment states were observed at all"
    assert observed < frozenset(ALL_STATES), (
        "the live surface now exhibits every lifecycle state, so the static comparison below "
        "could be made live. Observed: " + repr(sorted(observed))
    )
    assert observed == {"invited"}, (
        "a freshly created enrollment is expected to sit at `invited`; observed "
        f"{sorted(observed)}. If this changed deliberately, the paragraph above needs updating."
    )


def test_enrollment_lifecycle_state_matches_the_contract_module(ts_source: str) -> None:
    """STATIC comparison — ``types.ts`` text vs. ``worker_enrollment_contract.ALL_STATES``.

    Not derived from a live response, and deliberately not captioned as though it were: see
    :func:`test_the_live_surface_cannot_cover_the_lifecycle_vocabulary` for the measurement of why.
    It is still real evidence — the two sides are authored independently, so a state added to one
    and not the other fails here — it is simply weaker than the live rows above.

    Order is compared as well as membership: both sides declare the lifecycle in its contract
    order, and a client that reorders it is drifting from the contract even though the set matches.
    """
    declared = type_union_members(ts_source, "EnrollmentLifecycleState")
    assert declared == ALL_STATES, (
        "enrollment lifecycle drift (STATIC comparison: "
        f"{TYPES_TS_RELATIVE} vs. secp_api.worker_enrollment_contract.ALL_STATES).\n"
        f"  CLIENT declares : {list(declared)}\n"
        f"  CONTRACT holds  : {list(ALL_STATES)}\n"
        f"  client-only     : {sorted(set(declared) - set(ALL_STATES))}\n"
        f"  contract-only   : {sorted(set(ALL_STATES) - set(declared))}\n"
        "  (`recovery_required` is a state value, never a field.)"
    )


def test_the_lifecycle_union_is_not_confused_with_a_field_name(ts_source: str) -> None:
    """``recovery_required`` reads like a field and has been mistaken for one. It is a member of
    the lifecycle union and appears in no interface's field set."""
    assert "recovery_required" in type_union_members(ts_source, "EnrollmentLifecycleState")
    for interface in ("EnrollmentStatus", "EnrollmentInvitation", "EnrollmentListPage"):
        assert "recovery_required" not in interface_fields(ts_source, interface), interface


# --- the org-scoped list query is a client-authored shape, checked against the live route --------


def test_the_list_query_fields_are_accepted_by_the_live_route(live: LiveContract) -> None:
    """``EnrollmentListQuery`` is the one client type with no response body to compare against, so
    it is verified by *use*: every field it declares was sent to the live route in one call (see
    the fixture) and must be accepted. A query parameter the client declares and the server does
    not understand shows up here as a 422 rather than as a silent no-op at runtime."""
    status_code, body = live.query_probe
    assert status_code == 200, (
        "enrollment contract drift: GET /api/v1/enrollment refused a query built from the fields "
        f"`export interface EnrollmentListQuery` declares in {TYPES_TS_RELATIVE} "
        f"(HTTP {status_code}): {body}"
    )
    assert "items" in body
