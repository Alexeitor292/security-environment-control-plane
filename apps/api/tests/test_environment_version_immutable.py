"""AC2.1 — EnvironmentVersion is immutable after creation (Charter Invariant 2)."""

from __future__ import annotations

import pytest
from secp_api.errors import ImmutableResourceError


def test_version_spec_cannot_be_mutated(session, template_and_version):
    _, version = template_and_version
    version.spec = {**version.spec, "tampered": True}
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_version_hash_cannot_be_mutated(session, template_and_version):
    _, version = template_and_version
    version.content_hash = "sha256:deadbeef"
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_version_number_cannot_be_mutated(session, template_and_version):
    _, version = template_and_version
    version.version_number = 999
    with pytest.raises(ImmutableResourceError):
        session.flush()


def test_versions_get_monotonic_numbers_and_stable_hash(session, principal, valid_definition):
    from secp_api.services import catalog

    template = catalog.create_template(session, principal, name="T", slug="t-mono")
    v1 = catalog.create_version(
        session, principal, template_id=template.id, definition=valid_definition
    )
    v2 = catalog.create_version(
        session, principal, template_id=template.id, definition=valid_definition
    )
    session.commit()
    assert v1.version_number == 1
    assert v2.version_number == 2
    # Identical definitions produce an identical, stable content hash.
    assert v1.content_hash == v2.content_hash
    assert v1.content_hash.startswith("sha256:")
