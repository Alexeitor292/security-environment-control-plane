"""PR5F controller-image rollback compatibility stays fail closed and secret free."""

from __future__ import annotations

from secp_api.discovery_activation_rollback_probe import controller_rollback_compatible
from secp_api.enums import WorkerIdentityMechanism
from secp_api.seed import bootstrap_dev
from secp_api.services import worker_identity


def test_rollback_probe_allows_pre_adoption_database(engine) -> None:  # noqa: ARG001
    from secp_api.db import session_scope

    with session_scope() as session:
        bootstrap_dev(session)
        assert controller_rollback_compatible(session) is True


def test_rollback_probe_refuses_after_ed25519_identity_is_persisted(engine) -> None:  # noqa: ARG001
    from secp_api.db import session_scope

    with session_scope() as session:
        principal = bootstrap_dev(session)
        worker_identity.register_worker_identity(
            session,
            principal,
            mechanism=WorkerIdentityMechanism.ed25519_signed_nonce,
            identity_label="rollback-bound-worker",
            deployment_binding="production-worker",
            verification_anchor_fingerprint="sha256:" + "a" * 64,
        )
        assert controller_rollback_compatible(session) is False
