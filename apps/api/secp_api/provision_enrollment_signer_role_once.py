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
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from secp_commissioning.canonical import canonical_json
from secp_commissioning.enrollment_signer_role import (
    ENROLLMENT_SIGNER_DB_ROLE,
    EnrollmentSignerRoleError,
    render_signer_role_sql,
)
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


def _read_handoff(handoff_path: str) -> bytes:
    try:
        with open(handoff_path, "rb") as fh:
            return fh.read(_MAX_HANDOFF_BYTES + 1)
    except OSError:
        raise _HandoffInvalid("provision_handoff_unreadable") from None


def _verify_role_posture(conn: Any, *, unrelated_table: str | None) -> dict[str, Any]:
    """Prove the provisioned role is exactly least-privilege via the admin connection. Any deviation
    refuses (the full plaintext-credential lease proof is the installer's separate step)."""
    flags = conn.execute(
        text(
            "SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolcanlogin, "
            "rolreplication FROM pg_roles WHERE rolname = :r"
        ),
        {"r": ENROLLMENT_SIGNER_DB_ROLE},
    ).one_or_none()
    if flags is None:
        raise _RolePostureInvalid("provision_role_absent")
    rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolcanlogin, rolreplication = flags
    if (rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication) != (
        False,
        False,
        False,
        False,
        False,
    ) or rolcanlogin is not True:
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
    owned = conn.execute(
        text(
            "SELECT count(*) FROM pg_class c JOIN pg_roles o ON c.relowner = o.oid "
            "WHERE o.rolname = :r"
        ),
        {"r": ENROLLMENT_SIGNER_DB_ROLE},
    ).scalar()
    if owned:
        raise _RolePostureInvalid("provision_role_owns_objects")
    return {
        "role_name": ENROLLMENT_SIGNER_DB_ROLE,
        "can_login": True,
        "not_superuser": True,
        "not_createrole": True,
        "not_createdb": True,
        "not_bypassrls": True,
        "select_on_identity": True,
        "no_write_on_identity": True,
        "no_unrelated_read": unrelated_table is not None,
        "owns_nothing": True,
    }


class _RolePostureInvalid(Exception):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def run_provision(
    *, handoff_path: str = HANDOFF_PATH, engine: Engine | None = None
) -> tuple[int, dict[str, Any]]:
    """Read + validate the fixed verifier handoff, apply the code-owned provisioning SQL over the
    admin connection, and verify the least-privilege posture. Returns ``(exit_code,
    receipt/reason)``.
    Role provisioning is PostgreSQL-only (the role attributes/grants are PostgreSQL semantics)."""
    try:
        handoff = _parse_handoff(_read_handoff(handoff_path))
    except _HandoffInvalid as exc:
        return EXIT_HANDOFF_INVALID, {"reason_code": exc.reason_code}
    eng = engine if engine is not None else get_engine()
    if eng.dialect.name != "postgresql":
        return EXIT_UNSUPPORTED, {"reason_code": "provision_role_requires_postgresql"}
    statements = render_signer_role_sql(handoff.scram_verifier)
    try:
        with eng.begin() as conn:
            for stmt in statements:
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
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))  # noqa: T201 - one-shot receipt
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
