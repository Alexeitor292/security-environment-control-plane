"""The scheduled driver for the worker-enrollment expiry sweep (SECP WS-B R3).

``recovery_required`` had no producer outside tests: ``recover_expired`` / ``drain_expired`` were
correct but uncalled, so the state was unreachable in a running deployment. These tests cover the
driver that gives them a caller — that it actually reaches ``recovery_required`` end to end, that it
keeps organizations isolated, that one organization's failure cannot starve the rest, and that its
report can never carry an identifier into a log line.
"""

from __future__ import annotations

import uuid

import pytest
from secp_api import worker_enrollment_contract as contract
from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.models import Base, Organization
from secp_api.services import worker_enrollment as svc
from secp_api.services import worker_enrollment_recovery_schedule as sched
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

CTRL_HEX = (b"\x11" * 32).hex()
CTRL_KEY = contract.sha256_digest_of_hex(CTRL_HEX)
RELEASE = "sha256:" + "a" * 64
TXN = "txn-0001"
CREATED = "2026-07-21T00:00:00Z"
EXPIRES = "2026-07-21T01:00:00Z"
NOW = "2026-07-21T00:10:00Z"
AFTER = "2026-07-21T02:00:00Z"  # strictly after EXPIRES -> due
SITE = "rack-01.eu_a"


@pytest.fixture
def factory(tmp_path):
    """A real on-disk SQLite database + a sessionmaker.

    A ``sessionmaker`` (not a ``Session``) is exactly what the sweep requires: it reads its
    candidate batch in one session and recovers each candidate in its own transaction.
    """
    engine = create_engine(f"sqlite:///{tmp_path / 'sched.db'}")
    Base.metadata.create_all(engine)
    from secp_api.worker_enrollment_schema import RUNTIME_REQUIRED_MIGRATION_HEAD

    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE IF NOT EXISTS alembic_version (version_num varchar(32) primary key)"
        )
        conn.exec_driver_sql("DELETE FROM alembic_version")
        conn.exec_driver_sql(
            f"INSERT INTO alembic_version VALUES ('{RUNTIME_REQUIRED_MIGRATION_HEAD}')"
        )
    return sessionmaker(bind=engine)


def _organization(factory, slug: str) -> uuid.UUID:
    with factory() as session:
        org = Organization(name=slug, slug=slug)
        session.add(org)
        session.commit()
        return org.id


def _actor(organization_id: uuid.UUID) -> Principal:
    return Principal(
        user_id=uuid.uuid4(),
        organization_id=organization_id,
        email="sweep@test",
        permissions=frozenset({Permission.enrollment_read, Permission.enrollment_manage}),
    )


def _seed_expiring_enrollment(factory, organization_id: uuid.UUID, nonce_byte: str) -> str:
    invitation = contract.create_invitation(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=CTRL_KEY,
        controller_trust_anchor_hex=CTRL_HEX,
        controller_origin="https://ctrl.example.com",
        release_digest=RELEASE,
        transaction_id=TXN,
        nonce="sha256:" + nonce_byte * 64,
        created_at=CREATED,
        expires_at=EXPIRES,
    )
    with factory() as session:
        loaded = svc.create_invitation_and_open(
            session,
            _actor(organization_id),
            invitation=invitation,
            deployment_site_label=SITE,
            now=NOW,
        )
        session.commit()
        return loaded.state.enrollment_id


def _state_of(factory, organization_id: uuid.UUID, enrollment_id: str) -> str:
    with factory() as session:
        return svc.load_public_view(session, _actor(organization_id), enrollment_id=enrollment_id)[
            "state"
        ]


# --- the lifecycle actually reaches recovery_required -------------------------------------------


def test_scheduled_sweep_drives_a_due_enrollment_to_recovery_required(factory):
    org = _organization(factory, "org-a")
    enrollment_id = _seed_expiring_enrollment(factory, org, "b")
    assert _state_of(factory, org, enrollment_id) == "invited"

    report = sched.sweep_all_organizations(factory, now=AFTER)

    assert report.recovered == 1
    assert report.examined == 1
    assert _state_of(factory, org, enrollment_id) == "recovery_required"


def test_a_not_yet_due_enrollment_is_untouched(factory):
    org = _organization(factory, "org-a")
    enrollment_id = _seed_expiring_enrollment(factory, org, "b")

    report = sched.sweep_all_organizations(factory, now=NOW)  # before EXPIRES

    assert report.recovered == 0
    assert _state_of(factory, org, enrollment_id) == "invited"


def test_the_sweep_is_idempotent_across_runs(factory):
    org = _organization(factory, "org-a")
    enrollment_id = _seed_expiring_enrollment(factory, org, "b")

    first = sched.sweep_all_organizations(factory, now=AFTER)
    second = sched.sweep_all_organizations(factory, now=AFTER)

    assert first.recovered == 1
    assert second.recovered == 0, "a terminal row must not be recovered twice"
    assert _state_of(factory, org, enrollment_id) == "recovery_required"


# --- organization isolation ---------------------------------------------------------------------


def test_every_organization_is_swept_and_they_stay_isolated(factory):
    org_a = _organization(factory, "org-a")
    org_b = _organization(factory, "org-b")
    a_enrollment = _seed_expiring_enrollment(factory, org_a, "b")
    b_enrollment = _seed_expiring_enrollment(factory, org_b, "c")

    report = sched.sweep_all_organizations(factory, now=AFTER)

    assert report.organizations == 2
    assert report.recovered == 2
    assert _state_of(factory, org_a, a_enrollment) == "recovery_required"
    assert _state_of(factory, org_b, b_enrollment) == "recovery_required"


def test_one_organizations_failure_does_not_starve_the_others(factory, monkeypatch):
    """A persistent failure in one org must not permanently block every other org's recovery."""
    org_a = _organization(factory, "org-a")
    org_b = _organization(factory, "org-b")
    _seed_expiring_enrollment(factory, org_a, "b")
    b_enrollment = _seed_expiring_enrollment(factory, org_b, "c")

    real_drain = sched.drain_expired
    failed_for: list[uuid.UUID] = []

    def _drain(session_factory, *, organization_id, **kw):
        if organization_id == org_a:
            failed_for.append(organization_id)
            raise RuntimeError("simulated per-organization failure")
        return real_drain(session_factory, organization_id=organization_id, **kw)

    monkeypatch.setattr(sched, "drain_expired", _drain)
    report = sched.sweep_all_organizations(factory, now=AFTER)

    assert failed_for == [org_a]
    assert report.failed >= 1
    assert report.organizations == 2, "the run must continue past the failing organization"
    # ...and the healthy organization was still recovered
    assert _state_of(factory, org_b, b_enrollment) == "recovery_required"


def test_a_failing_organization_is_not_reported_as_corruption(factory, monkeypatch):
    """An unexpected error is not evidence a row is corrupt; mislabelling it would be untruthful."""
    _organization(factory, "org-a")

    def _boom(*_a, **_kw):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(sched, "drain_expired", _boom)
    report = sched.sweep_all_organizations(factory, now=AFTER)

    assert report.failed == 1
    assert report.corrupt == 0


# --- bounded + identifier-free ------------------------------------------------------------------


def test_a_run_with_no_organizations_is_a_clean_no_op(factory):
    report = sched.sweep_all_organizations(factory, now=AFTER)
    assert report.organizations == 0
    assert report.examined == 0
    assert report.organizations_truncated is False


def test_the_organization_bound_is_reported_rather_than_hidden(factory):
    for index in range(3):
        _organization(factory, f"org-{index}")

    report = sched.sweep_all_organizations(factory, now=AFTER, max_organizations=2)

    assert report.organizations == 2
    assert report.organizations_truncated is True, "hitting the bound must be visible"


def test_the_report_can_never_carry_an_identifier_into_a_log(factory):
    org = _organization(factory, "org-a")
    enrollment_id = _seed_expiring_enrollment(factory, org, "b")

    report = sched.sweep_all_organizations(factory, now=AFTER)

    rendered = repr(report) + str(report.as_log_fields())
    assert enrollment_id not in rendered
    assert str(org) not in rendered
    assert all(isinstance(value, (int, bool)) for value in report.as_log_fields().values())


def test_a_malformed_now_refuses_rather_than_sweeping(factory):
    """The sweep decides due-ness from a caller-supplied ``now``; a malformed one must not sweep."""
    org = _organization(factory, "org-a")
    enrollment_id = _seed_expiring_enrollment(factory, org, "b")

    report = sched.sweep_all_organizations(factory, now="not-a-timestamp")

    assert report.recovered == 0
    assert _state_of(factory, org, enrollment_id) == "invited"
