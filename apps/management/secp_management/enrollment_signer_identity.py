"""Production ACTIVE controller-identity provider for the root-gated enrollment signer broker
(SECP-PR5H-B1, Phase 3).

The root broker signs a controller offer ONLY under the authoritative ACTIVE controller identity,
serialized against controller-identity rotation for the exact duration of one signing operation
(S2). This adapter is the production :class:`ActiveControllerSigningIdentityProvider`: per sign it
opens a bounded transaction on a DEDICATED LEAST-PRIVILEGE database role, takes the fixed
transaction-level ADVISORY lock (``pg_advisory_xact_lock`` — executable by PUBLIC, so it needs NO
write privilege), then plain-``SELECT``s the single verified ACTIVE
``controller_enrollment_identity`` row, binds the immutable row id + a per-activation token into a
strict :class:`SigningIdentityLease`, and HOLDS the advisory lock until the ``with`` block (i.e.
signing + self-verification) completes. Controller-identity activation/rotation takes the SAME
advisory lock, so a rotation blocks until an in-flight signing lease exits and vice versa — the
lock, not a row-level ``FOR UPDATE`` (which PostgreSQL would refuse to a SELECT-only role), is the
serialization mechanism. A missing / ambiguous / unverified / malformed identity refuses closed.

It lives in the MANAGEMENT plane (the broker's privileged composition) and reaches the durable
identity history through RAW SQL over the known table — it never imports the ``secp_api`` ORM (the
management plane may not import the API plane) and it never touches the enrollment private key (that
is the signer's hardened filesystem reader). Every failure is a bounded
:class:`ControllerEnrollmentSignerError` reason code — never a row value, endpoint, or raw DBAPI
exception.
"""

from __future__ import annotations

import pathlib
from collections.abc import Iterator
from contextlib import contextmanager

from secp_commissioning.controller_enrollment_signer import (
    ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY,
    ControllerEnrollmentSignerError,
    SigningIdentityLease,
)

# The dedicated least-privilege database ROLE the broker authenticates as (a plain LOGIN role owning
# nothing, granted ONLY schema USAGE + SELECT on the single identity table; it takes the
# transaction-level advisory lock instead of a FOR UPDATE row lock, so SELECT-only is correct) and
# its reviewed grants are the plane-neutral code-owned constants, re-exported here for
# compatibility.
from secp_commissioning.enrollment_signer_role import (
    ENROLLMENT_SIGNER_DB_GRANT_SQL,
    ENROLLMENT_SIGNER_DB_GRANTS,
    ENROLLMENT_SIGNER_DB_ROLE,
)
from sqlalchemy import Engine, text

# The identity columns the lease needs — all PUBLIC identity material (ids, digests, anchor hex,
# https origin); the private enrollment key is NEVER in this table.
_SELECT_ACTIVE = (
    "SELECT id, controller_installation_id, controller_key_id, controller_trust_anchor_hex, "
    "controller_origin, release_digest, management_identity_digest, bootstrap_evidence_digest, "
    "enrollment_key_proof_id, verified, activated_at "
    "FROM controller_enrollment_identity WHERE status = 'active'"
)


class DbActiveControllerSigningIdentityProvider:
    """Production :class:`ActiveControllerSigningIdentityProvider`. Backed by a dedicated
    least-privilege engine; each :meth:`lease` opens ONE bounded transaction, locks the single
    verified ACTIVE identity row, and holds the lock through signing."""

    __slots__ = ("_engine",)

    def __init__(self, engine: Engine) -> None:
        self._engine = engine

    def __repr__(self) -> str:  # never the engine URL / credentials
        return "DbActiveControllerSigningIdentityProvider(<redacted>)"

    @contextmanager
    def lease(self) -> Iterator[SigningIdentityLease]:
        # On PostgreSQL (the shipped engine) take the fixed transaction-level advisory lock FIRST,
        # then a plain SELECT — this serializes against identity rotation (which takes the same
        # lock) and needs NO write privilege, so the SELECT-only role is correct. On SQLite the
        # advisory function does not exist and is unnecessary (SQLite serializes writers), so it is
        # omitted.
        is_pg = self._engine.dialect.name == "postgresql"
        try:
            begin = self._engine.begin()
        except Exception as exc:  # a connection failure is a bounded closed refusal
            raise ControllerEnrollmentSignerError(
                "controller_enrollment_identity_unavailable"
            ) from exc
        with begin as conn:
            try:
                if is_pg:
                    conn.execute(
                        text("SELECT pg_advisory_xact_lock(:k)"),
                        {"k": ENROLLMENT_IDENTITY_ADVISORY_LOCK_KEY},
                    )
                rows = conn.execute(text(_SELECT_ACTIVE)).mappings().all()
            except Exception as exc:  # a query/lock failure never leaks the DBAPI exception
                raise ControllerEnrollmentSignerError(
                    "controller_enrollment_identity_unavailable"
                ) from exc
            if not rows:
                raise ControllerEnrollmentSignerError("controller_enrollment_identity_unavailable")
            if len(rows) > 1:  # active_marker UNIQUE should make this impossible; refuse if not
                raise ControllerEnrollmentSignerError("controller_enrollment_identity_ambiguous")
            row = rows[0]
            if not bool(row["verified"]):
                raise ControllerEnrollmentSignerError("controller_enrollment_identity_unverified")
            # a malformed identity row can never yield a usable lease — SigningIdentityLease
            # construction proves every field's grammar and raises a bounded refusal otherwise.
            # The TLS trust set this controller ACTUALLY serves with, read from its own root-owned
            # bundle under the held lock — so what gets signed is what is live at sign time, not a
            # cached snapshot. It is a FILESYSTEM fact, not a row, which is why it is read here
            # rather than added to the identity table: the certificate a controller presents can be
            # replaced without any database write.
            lease = SigningIdentityLease(
                controller_tls_trust_anchor_id=_observe_tls_trust_anchor_id(),
                row_id=str(row["id"]),
                activation_token=f"{row['id']}|{row['activated_at']}",
                controller_installation_id=str(row["controller_installation_id"]),
                controller_key_id=str(row["controller_key_id"]),
                controller_trust_anchor_hex=str(row["controller_trust_anchor_hex"]),
                controller_origin=str(row["controller_origin"]),
                release_digest=str(row["release_digest"]),
                management_identity_digest=str(row["management_identity_digest"]),
                bootstrap_evidence_digest=str(row["bootstrap_evidence_digest"]),
                enrollment_key_proof_id=str(row["enrollment_key_proof_id"]),
            )
            # the lock is held for the duration of the caller's `with` block — i.e. through signing
            # and the broker's self-verification — then the transaction closes deterministically.
            yield lease


def _observe_tls_trust_anchor_id() -> str:
    """The identity of the controller's live TLS trust set, or a bounded refusal.

    Read at every lease acquisition rather than cached: a controller whose certificate bundle was
    replaced must sign the NEW identity, or the worker would pin an anchor the controller no longer
    serves and refuse every subsequent connection for a reason nobody could see.

    An unreadable or malformed bundle refuses rather than yielding a placeholder. Signing a
    fabricated anchor would be worse than not signing one: the worker would pin it and then compare
    every future connection against something that was never real.
    """
    from secp_commissioning.trust_anchor import TrustAnchorError, trust_anchor_id_for

    from secp_management.controller_tls import CONTROLLER_CA_BUNDLE_PATH

    try:
        pem = pathlib.Path(CONTROLLER_CA_BUNDLE_PATH).read_bytes()
    except OSError:
        raise ControllerEnrollmentSignerError(
            "controller_enrollment_tls_trust_anchor_unavailable"
        ) from None
    try:
        return trust_anchor_id_for(pem)
    except TrustAnchorError:
        raise ControllerEnrollmentSignerError(
            "controller_enrollment_tls_trust_anchor_invalid"
        ) from None


__all__ = [
    "ENROLLMENT_SIGNER_DB_GRANTS",
    "ENROLLMENT_SIGNER_DB_GRANT_SQL",
    "ENROLLMENT_SIGNER_DB_ROLE",
    "DbActiveControllerSigningIdentityProvider",
]
