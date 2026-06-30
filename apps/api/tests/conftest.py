"""Shared pytest fixtures.

Tests are hermetic: a fresh file-backed SQLite database per test, the inline
dispatcher, and the bootstrapped dev admin principal. No external services.
"""

from __future__ import annotations

import os

os.environ.setdefault("SECP_APP_ENV", "test")
os.environ.setdefault("SECP_WORKFLOW_DISPATCH_MODE", "inline")

import uuid  # noqa: E402

import pytest  # noqa: E402
import secp_api.immutability  # noqa: E402,F401  (registers ORM immutability guards)
from secp_api.auth import Principal  # noqa: E402
from secp_api.db import (  # noqa: E402
    get_sessionmaker,
    reset_engine_for_tests,
)
from secp_api.models import Base  # noqa: E402
from secp_api.seed import bootstrap_dev  # noqa: E402

VALID_DEFINITION: dict = {
    "apiVersion": "controlplane.security/v1alpha1",
    "kind": "Environment",
    "metadata": {"name": "test-env", "displayName": "Test Env"},
    "spec": {
        "teams": {"count": 2, "isolationPolicy": "strict"},
        "networks": [
            {"name": "team-network", "cidrStrategy": "per-team", "baseCidr": "10.20.0.0/16"}
        ],
        "roles": [
            {
                "name": "attacker",
                "kind": "attacker",
                "image": "kali-linux",
                "network": "team-network",
            },
            {
                "name": "web-server",
                "kind": "target",
                "image": "ubuntu-server-22.04",
                "network": "team-network",
            },
            {
                "name": "wazuh-sensor",
                "kind": "sensor",
                "image": "wazuh-agent",
                "network": "team-network",
            },
        ],
        "telemetry": {"providers": ["wazuh"]},
        "validation": {
            "provider": "ctfd",
            "objectives": [
                {"id": "gain-initial-access", "description": "Get a shell", "points": 100}
            ],
        },
        "requiredPlugins": ["simulator"],
    },
}


@pytest.fixture
def engine(tmp_path):
    url = f"sqlite+pysqlite:///{(tmp_path / 'test.db').as_posix()}"
    eng = reset_engine_for_tests(url)
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)


@pytest.fixture
def session(engine):
    factory = get_sessionmaker()
    s = factory()
    try:
        yield s
    finally:
        s.rollback()
        s.close()


@pytest.fixture
def principal(session) -> Principal:
    p = bootstrap_dev(session)
    session.commit()
    return p


@pytest.fixture
def other_org_principal(session, principal) -> Principal:
    """A principal in a *different* organization (for org-scoping tests)."""
    from secp_api.enums import Permission
    from secp_api.models import (
        Organization,
        Role,
        User,
        UserRoleAssignment,
    )

    org = Organization(name="Other Org", slug="other-org")
    session.add(org)
    session.flush()
    role = session.query(Role).filter_by(name="platform-admin").one()
    user = User(
        organization_id=org.id,
        email="other-admin@local.test",
        display_name="Other Admin",
        subject="other-admin",
    )
    session.add(user)
    session.flush()
    session.add(UserRoleAssignment(organization_id=org.id, user_id=user.id, role_id=role.id))
    session.commit()
    return Principal(
        user_id=user.id,
        organization_id=org.id,
        email=user.email,
        permissions=frozenset(Permission),
    )


@pytest.fixture
def valid_definition() -> dict:
    import copy

    return copy.deepcopy(VALID_DEFINITION)


@pytest.fixture
def template_and_version(session, principal):
    """Create a template + immutable version from the valid definition."""
    from secp_api.services import catalog

    template = catalog.create_template(
        session, principal, name="Test Template", slug="test-template"
    )
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=VALID_DEFINITION
    )
    session.commit()
    return template, version


def _make_running_exercise(session, principal, *, name: str = "ex"):
    """Drive an exercise to 'running' through the full approval-gated flow."""
    from secp_api.services import catalog, exercises, planning

    template = catalog.create_template(
        session, principal, name=name, slug=f"{name}-{uuid.uuid4().hex[:8]}"
    )
    version = catalog.create_version(
        session, principal, template_id=template.id, definition=VALID_DEFINITION
    )
    exercise = exercises.create_exercise(
        session, principal, template_id=template.id, version_id=version.id, name=name
    )
    exercises.validate_exercise(session, principal, exercise.id)
    plan = planning.generate_plan(session, principal, exercise.id)
    planning.submit_plan(session, principal, plan.id)
    planning.approve_plan(session, principal, plan.id, "approved for test")
    exercises.start_exercise(session, principal, exercise.id)
    session.commit()
    return exercise


@pytest.fixture
def running_exercise(session, principal):
    """A factory fixture: call to create a fresh exercise driven to 'running'."""

    def _factory(name: str = "ex"):
        return _make_running_exercise(session, principal, name=name)

    return _factory
