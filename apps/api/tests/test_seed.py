"""The dev seed keeps the platform-admin role's permissions current."""

from __future__ import annotations

from secp_api.enums import Permission
from secp_api.models import Role
from secp_api.seed import PLATFORM_ADMIN_ROLE, bootstrap_dev


def test_bootstrap_refreshes_stale_permissions(session):
    # Simulate a persisted dev DB whose role predates newer permissions.
    session.add(Role(name=PLATFORM_ADMIN_ROLE, description="stale", permissions=["audit:read"]))
    session.commit()

    principal = bootstrap_dev(session)
    session.commit()

    role = session.query(Role).filter_by(name=PLATFORM_ADMIN_ROLE).one()
    assert set(role.permissions) == {p.value for p in Permission}
    assert Permission.target_manage in principal.permissions
    assert Permission.inventory_discover in principal.permissions
