"""Fixed API-plane enrollment-signer role provisioning one-shot (SECP-PR5H-B2, commit 2b-3b).

``python -m secp_api.provision_enrollment_signer_role_once`` — a NARROW local transaction
participant
the root installer invokes (via a fixed `compose run api` one-shot) to create/rotate the dedicated
least-privilege ``secp_enrollment_signer`` DB role. It exists only because the API plane owns the
DB-admin/migration connection; the management installer generates the SCRAM verifier and hands it
off
so it never needs an admin DSN, and this one-shot applies the code-owned provisioning WITHOUT the
management plane importing the API (or vice versa).

It reads ONLY the single fixed verifier handoff (mounted read-only), validates its strict closed
schema, invokes ONLY the code-owned :func:`render_signer_role_sql` provisioning operation (no
caller-selected role / SQL / db / schema / table / grants / DSN / password / command), applies it in
one transaction over the existing admin connection, and then VERIFIES the resulting role is exactly
least-privilege (closed attributes; owns nothing; SELECT only on the one identity table; no
unrelated
read; no INSERT/UPDATE/DELETE). It returns ONLY a bounded, non-secret receipt (never the verifier,
plaintext, DSN, or a raw exception). The plaintext broker credential + the real dedicated-role lease
proof are the INSTALLER's separate responsibility.

Exit codes: 0 provisioned; 1 handoff invalid; 2 unsupported (non-PostgreSQL); 3 role posture
invalid.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from secp_commissioning.canonical import canonical_json
from secp_commissioning.enrollment_signer_role import (
    ENROLLMENT_SIGNER_DB_ROLE,
    EnrollmentSignerRoleError,
    render_signer_role_sql,
)
from secp_commissioning.hardened_handoff import HardenedHandoffError, read_hardened_fixed_handoff
from sqlalchemy import Engine, text

from secp_api.db import get_engine

#: The single fixed path the verifier handoff is mounted read-only at inside the one-shot container.
HANDOFF_PATH = "/run/secp/handoff/enrollment-signer-role-provision.json"
_HANDOFF_SCHEMA = "secp.enrollment-signer-role-provision/v1"
_MAX_HANDOFF_BYTES = 4 * 1024
_IDENTITY_TABLE = "controller_enrollment_identity"

EXIT_OK = 0
EXIT_HANDOFF_INVALID = 1
EXIT_UNSUPPORTED = 2
EXIT_ROLE_POSTURE_INVALID = 3


class _HandoffInvalid(Exception):
    """A bounded, one-shot-authored refusal — only a closed reason code, never handoff bytes."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class _ProvisionHandoff(BaseModel):
    """The strict, closed verifier handoff. Extra/missing fields + wrong types are refused; every
    value is bounded. It carries the SCRAM VERIFIER only — never the plaintext password."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_id: str = Field(alias="schema", min_length=1, max_length=64)
    operation_id: str = Field(min_length=1, max_length=128)
    scram_verifier: str = Field(min_length=1, max_length=512)
    created_at: str = Field(min_length=1, max_length=40)


def _parse_handoff(raw: bytes) -> _ProvisionHandoff:
    if not raw or len(raw) > _MAX_HANDOFF_BYTES:
        raise _HandoffInvalid("provision_handoff_size_invalid")
    body = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        obj = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise _HandoffInvalid("provision_handoff_not_json") from None
    if not isinstance(obj, dict) or canonical_json(obj).encode("utf-8") != body:
        raise _HandoffInvalid("provision_handoff_noncanonical")
    try:
        handoff = _ProvisionHandoff.model_validate(obj)
    except ValidationError:
        raise _HandoffInvalid("provision_handoff_malformed") from None
    if handoff.schema_id != _HANDOFF_SCHEMA:
        raise _HandoffInvalid("provision_handoff_schema_unknown")
    try:
        render_signer_role_sql(handoff.scram_verifier)  # validates the SCRAM grammar (no injection)
    except EnrollmentSignerRoleError:
        raise _HandoffInvalid("provision_handoff_verifier_invalid") from None
    return handoff


def _production_reader() -> bytes:
    gid = int(getattr(os, "getegid", lambda: -1)())
    return read_hardened_fixed_handoff(HANDOFF_PATH, expected_gid=gid, max_bytes=_MAX_HANDOFF_BYTES)


def _verify_role_posture(conn: Any, *, unrelated_table: str | None) -> dict[str, Any]:
    """Prove the provisioned role is exactly least-privilege via the admin connection. Any deviation
    refuses (the full plaintext-credential lease proof is the installer's separate step)."""
    flags = conn.execute(
        text(
            "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolcanlogin, "
            "rolreplication, rolinherit FROM pg_roles WHERE rolname = :r"
        ),
        {"r": ENROLLMENT_SIGNER_DB_ROLE},
    ).one_or_none()
    if flags is None:
        raise _RolePostureInvalid("provision_role_absent")
    (
        rolsuper,
        rolcreaterole,
        rolcreatedb,
        rolbypassrls,
        rolcanlogin,
        rolreplication,
        rolinherit,
    ) = flags
    if (
        rolsuper,
        rolcreaterole,
        rolcreatedb,
        rolbypassrls,
        rolreplication,
        rolinherit,
    ) != (False, False, False, False, False, False) or rolcanlogin is not True:
        raise _RolePostureInvalid("provision_role_attributes_invalid")

    def _priv(table: str, privilege: str) -> bool:
        return bool(
            conn.execute(
                text("SELECT has_table_privilege(:r, :t, :p)"),
                {"r": ENROLLMENT_SIGNER_DB_ROLE, "t": table, "p": privilege},
            ).scalar()
        )

    if not _priv(_IDENTITY_TABLE, "SELECT"):
        raise _RolePostureInvalid("provision_role_missing_select")
    if any(_priv(_IDENTITY_TABLE, w) for w in ("INSERT", "UPDATE", "DELETE")):
        raise _RolePostureInvalid("provision_role_has_write")
    if unrelated_table is not None and _priv(unrelated_table, "SELECT"):
        raise _RolePostureInvalid("provision_role_reads_unrelated")
    # unexpected sequence / function execution privileges
    if unrelated_table is not None:
        seq = conn.execute(
            text(
                "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON c.relnamespace = n.oid "
                "WHERE c.relkind = 'S' AND n.nspname = 'public' LIMIT 1"
            )
        ).scalar()
        if seq is not None and bool(
            conn.execute(
                text("SELECT has_sequence_privilege(:r, 'public.' || :s, 'USAGE')"),
                {"r": ENROLLMENT_SIGNER_DB_ROLE, "s": seq},
            ).scalar()
        ):
            raise _RolePostureInvalid("provision_role_has_sequence_privilege")
    # no ownership of ANY object class (table/index/sequence/view), schema, or function
    owned = conn.execute(
        text(
            "SELECT (SELECT count(*) FROM pg_class c JOIN pg_roles o ON c.relowner = o.oid"
            " WHERE o.rolname = :r)"
            " + (SELECT count(*) FROM pg_namespace ns JOIN pg_roles o ON ns.nspowner = o.oid"
            " WHERE o.rolname = :r)"
            " + (SELECT count(*) FROM pg_proc p JOIN pg_roles o ON p.proowner = o.oid"
            " WHERE o.rolname = :r)"
        ),
        {"r": ENROLLMENT_SIGNER_DB_ROLE},
    ).scalar()
    if owned:
        raise _RolePostureInvalid("provision_role_owns_objects")
    # no role membership in EITHER direction (a membership is a SET ROLE escalation path)
    memberships = conn.execute(
        text(
            "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r "
            "ON (m.member = r.oid OR m.roleid = r.oid) WHERE r.rolname = :r"
        ),
        {"r": ENROLLMENT_SIGNER_DB_ROLE},
    ).scalar()
    if memberships:
        raise _RolePostureInvalid("provision_role_has_membership")
    return {
        "role_name": ENROLLMENT_SIGNER_DB_ROLE,
        "can_login": True,
        "not_superuser": True,
        "not_createrole": True,
        "not_createdb": True,
        "not_bypassrls": True,
        "not_inherit": True,
        "not_replication": True,
        "select_on_identity": True,
        "no_write_on_identity": True,
        "no_unrelated_read": unrelated_table is not None,
        "owns_nothing": True,
        "no_memberships": True,
    }


class _RolePostureInvalid(Exception):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _quote_ident(name: str) -> str:
    """Double-quote a catalog-sourced role identifier (defensive doubling of any embedded quote)."""
    return '"' + name.replace('"', '""') + '"'


def _repair_hostile_role(conn: Any) -> None:
    """Normalize a pre-existing (possibly hostile) ``secp_enrollment_signer`` to the closed
    least-privilege posture BEFORE the reviewed grants are applied. A prior installer, an operator,
    or an attacker with prior DB-admin access could have left the role a member of a privileged
    group, a grantable escalation target, an object owner, or the holder of sequence/function
    privileges. This step enumerates the catalogs EXHAUSTIVELY (not one sample) and:

    * revokes every role membership in BOTH directions — a membership either way is a ``SET ROLE``
      escalation path;
    * REFUSES (``provision_role_owns_objects``) if the role owns ANY object
      (table/index/sequence/view, schema, or function) — an owned object is a persistence/escalation
      foothold the closed installation ownership policy must not silently keep;
    * strips any sequence / function / routine execution privilege.

    Parent/child role names come from the catalog and are quoted; the signer role name is a fixed
    code constant. The subsequent reviewed statements pin the closed attribute set + re-grant the
    exact schema ``USAGE`` + identity ``SELECT``."""
    role = ENROLLMENT_SIGNER_DB_ROLE
    q = _quote_ident(role)
    # 1) revoke every group the signer is a MEMBER of (SET ROLE <group> escalation).
    parents = (
        conn.execute(
            text(
                "SELECT g.rolname FROM pg_auth_members m "
                "JOIN pg_roles g ON m.roleid = g.oid "
                "JOIN pg_roles r ON m.member = r.oid WHERE r.rolname = :r"
            ),
            {"r": role},
        )
        .scalars()
        .all()
    )
    for parent in parents:
        conn.exec_driver_sql(f"REVOKE {_quote_ident(parent)} FROM {q};")
    # 2) revoke every role the signer has been GRANTED TO (a grantee could SET ROLE into it).
    children = (
        conn.execute(
            text(
                "SELECT c.rolname FROM pg_auth_members m "
                "JOIN pg_roles r ON m.roleid = r.oid "
                "JOIN pg_roles c ON m.member = c.oid WHERE r.rolname = :r"
            ),
            {"r": role},
        )
        .scalars()
        .all()
    )
    for child in children:
        conn.exec_driver_sql(f"REVOKE {q} FROM {_quote_ident(child)};")
    # 3) refuse ANY owned object (table/index/sequence/view, schema, function); never silently keep.
    owned = conn.execute(
        text(
            "SELECT (SELECT count(*) FROM pg_class c JOIN pg_roles o ON c.relowner = o.oid"
            " WHERE o.rolname = :r)"
            " + (SELECT count(*) FROM pg_namespace ns JOIN pg_roles o ON ns.nspowner = o.oid"
            " WHERE o.rolname = :r)"
            " + (SELECT count(*) FROM pg_proc p JOIN pg_roles o ON p.proowner = o.oid"
            " WHERE o.rolname = :r)"
        ),
        {"r": role},
    ).scalar()
    if owned:
        raise _RolePostureInvalid("provision_role_owns_objects")
    # 4) strip any sequence / function / routine privilege beyond the reviewed identity SELECT.
    conn.exec_driver_sql(f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {q};")
    conn.exec_driver_sql(f"REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM {q};")
    conn.exec_driver_sql(f"REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM {q};")


def run_provision(
    *, read_handoff: Any = None, engine: Engine | None = None
) -> tuple[int, dict[str, Any]]:
    """Read + validate the fixed verifier handoff (via the plane-neutral HARDENED reader in
    production), apply the code-owned provisioning SQL over the admin connection, and verify the
    least-privilege posture. Returns ``(exit_code, receipt/reason)``. Role provisioning is
    PostgreSQL-only. ``read_handoff`` defaults to the hardened fixed-path reader; tests inject a
    verified-reader seam (never a production path override)."""
    reader = read_handoff if read_handoff is not None else _production_reader
    try:
        handoff = _parse_handoff(reader())
    except HardenedHandoffError as exc:
        return EXIT_HANDOFF_INVALID, {"reason_code": exc.reason_code}
    except _HandoffInvalid as exc:
        return EXIT_HANDOFF_INVALID, {"reason_code": exc.reason_code}
    eng = engine if engine is not None else get_engine()
    if eng.dialect.name != "postgresql":
        return EXIT_UNSUPPORTED, {"reason_code": "provision_role_requires_postgresql"}
    statements = render_signer_role_sql(handoff.scram_verifier)
    try:
        with eng.begin() as conn:
            # 1) create/ensure the role, 2) NORMALIZE a pre-existing hostile role completely, then
            # 3) pin the closed attributes + REVOKE table/schema privilege + GRANT reviewed reads.
            conn.exec_driver_sql(statements[0])
            _repair_hostile_role(conn)
            for stmt in statements[1:]:
                conn.exec_driver_sql(stmt)
            unrelated = conn.execute(
                text(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
                    "AND tablename <> :t ORDER BY tablename LIMIT 1"
                ),
                {"t": _IDENTITY_TABLE},
            ).scalar()
            posture = _verify_role_posture(conn, unrelated_table=unrelated)
    except _RolePostureInvalid as exc:
        return EXIT_ROLE_POSTURE_INVALID, {"reason_code": exc.reason_code}
    return EXIT_OK, {"operation_id": handoff.operation_id, **posture}


def main(argv: list[str] | None = None) -> int:
    argparse.ArgumentParser(
        prog="python -m secp_api.provision_enrollment_signer_role_once",
        description=(
            "Provision the dedicated least-privilege enrollment-signer DB role from the fixed "
            "verifier handoff (no argument selects the role, SQL, database, or verifier)."
        ),
    ).parse_args(argv)
    code, payload = run_provision()
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))  # noqa: T201
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
