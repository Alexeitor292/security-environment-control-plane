"""Production ACTIVE controller-identity provider for the root-gated enrollment signer broker
(SECP-PR5H-B1, Phase 3).

The root broker signs a controller offer ONLY under the authoritative ACTIVE controller identity,
proven under a HELD row lock for the exact duration of one signing operation (S2). This adapter is
the production :class:`ActiveControllerSigningIdentityProvider`: per sign it opens a bounded
transaction on a DEDICATED LEAST-PRIVILEGE database role, ``SELECT ... FOR UPDATE`` the single
verified ACTIVE ``controller_enrollment_identity`` row, binds the immutable row id + a
per-activation token into a strict :class:`SigningIdentityLease`, and holds the lock until the
``with`` block (i.e.
signing + self-verification) completes. A missing / ambiguous / unverified / malformed identity
refuses closed.

It lives in the MANAGEMENT plane (the broker's privileged composition) and reaches the durable
identity history through RAW, PARAMETER-FREE SQL over the known table — it never imports the
``secp_api`` ORM (the management plane may not import the API plane) and it never touches the
enrollment private key (that is the signer's hardened filesystem reader). Every failure is a bounded
:class:`ControllerEnrollmentSignerError` reason code — never a row value, endpoint, or raw DBAPI
exception.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from secp_commissioning.controller_enrollment_signer import (
    ControllerEnrollmentSignerError,
    SigningIdentityLease,
)
from sqlalchemy import Engine, text

#: The dedicated least-privilege database ROLE the broker authenticates as. It is granted ONLY
#: ``SELECT`` (which is sufficient to take the ``FOR UPDATE`` row lock) on the single identity table
#: — never INSERT/UPDATE/DELETE, never any enrollment/worker/audit table, never a superuser. The
#: bootstrap provisions it out of band with the reviewed grant below.
ENROLLMENT_SIGNER_DB_ROLE = "secp_enrollment_signer"

#: The reviewed, code-owned least-privilege grant (applied out of band by the DBA / bootstrap, never
#: from an HTTP request). SELECT-only on the identity history — nothing else is reachable.
ENROLLMENT_SIGNER_DB_GRANT_SQL = (
    "GRANT SELECT ON controller_enrollment_identity TO secp_enrollment_signer;"
)

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
        # FOR UPDATE bites on PostgreSQL (the shipped engine); on SQLite it is unsupported syntax
        # but unnecessary — SQLite serializes writers — so it is omitted there.
        suffix = " FOR UPDATE" if self._engine.dialect.name == "postgresql" else ""
        try:
            begin = self._engine.begin()
        except Exception as exc:  # a connection failure is a bounded closed refusal
            raise ControllerEnrollmentSignerError(
                "controller_enrollment_identity_unavailable"
            ) from exc
        with begin as conn:
            try:
                rows = conn.execute(text(_SELECT_ACTIVE + suffix)).mappings().all()
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
            lease = SigningIdentityLease(
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


__all__ = [
    "ENROLLMENT_SIGNER_DB_GRANT_SQL",
    "ENROLLMENT_SIGNER_DB_ROLE",
    "DbActiveControllerSigningIdentityProvider",
]
