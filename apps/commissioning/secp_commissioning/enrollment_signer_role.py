"""Plane-neutral dedicated enrollment-signer DB role primitives (SECP-PR5H-B2, commit 2b-3).

The pure SCRAM-SHA-256 verifier computation, the reviewed least-privilege role-provisioning SQL, and
the fixed role name + grants — shared by the MANAGEMENT installer (which generates the verifier and
writes the broker credential) and the API provisioning one-shot (which renders + applies the SQL
inside the API container's DB-admin connection), so NEITHER plane imports the other. This module is
PURE + offline: it opens no network connection, runs no subprocess, and never returns/logs the
plaintext or verifier bytes on error.

The role is a plain LOGIN role owning nothing, granted ONLY schema ``USAGE`` + ``SELECT`` on the one
identity table (CONNECT comes from PUBLIC's default; on PostgreSQL 15+ PUBLIC has no CREATE on the
public schema). Its password is stored in the database ONLY as a SCRAM-SHA-256 verifier (RFC 5802) —
the plaintext never appears in a ``CREATE``/``ALTER ROLE`` value, and the role name is a code
constant + the verifier is grammar-validated before it is embedded, so there is no injection
surface.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from typing import NoReturn

from secp_commissioning.errors import CommissioningError

#: The dedicated least-privilege role + its reviewed code-owned grants (never caller-supplied).
ENROLLMENT_SIGNER_DB_ROLE = "secp_enrollment_signer"
ENROLLMENT_SIGNER_DB_GRANTS = (
    "GRANT USAGE ON SCHEMA public TO secp_enrollment_signer;",
    "GRANT SELECT ON controller_enrollment_identity TO secp_enrollment_signer;",
)
#: Back-compat alias: the single SELECT grant that is the security-critical one.
ENROLLMENT_SIGNER_DB_GRANT_SQL = ENROLLMENT_SIGNER_DB_GRANTS[-1]

_SCRAM_ITERATIONS = 4096
_SALT_BYTES = 16
_PASSWORD_BYTES = 32  # 256 bits of entropy, rendered as 64 lowercase hex (ASCII, DSN/SASL-safe)
# a SCRAM-SHA-256 verifier: SCRAM-SHA-256$<iters>:<b64salt>$<b64storedkey>:<b64serverkey>
_VERIFIER_GRAMMAR = re.compile(
    r"SCRAM-SHA-256\$[1-9][0-9]{0,6}:[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}"
)
_PASSWORD_GRAMMAR = re.compile(r"[0-9a-f]{32,128}")  # the generated ASCII-hex secret


class EnrollmentSignerRoleError(CommissioningError):
    """A bounded, closed refusal — only a reason code, never the password, verifier, or DSN."""


def _reject(reason_code: str) -> NoReturn:
    raise EnrollmentSignerRoleError(reason_code)


def generate_signer_db_password() -> str:
    """A fresh high-entropy ASCII-hex secret for the dedicated signer role (256 bits). Hex keeps it
    SASLprep-identity + DSN-safe, so no normalization or escaping is ever needed."""
    return secrets.token_hex(_PASSWORD_BYTES)


def scram_sha256_verifier(
    password: str, *, salt: bytes | None = None, iterations: int = _SCRAM_ITERATIONS
) -> str:
    """Compute the RFC 5802 SCRAM-SHA-256 verifier PostgreSQL stores for ``password``. The plaintext
    is required only here (and to authenticate); the database stores ONLY this verifier. ``salt`` is
    a parameter for deterministic tests; production always uses a fresh random salt."""
    if not isinstance(password, str) or not _PASSWORD_GRAMMAR.fullmatch(password):
        _reject("enrollment_signer_password_invalid")
    if not isinstance(iterations, int) or not (4096 <= iterations <= 1_000_000):
        _reject("enrollment_signer_scram_iterations_invalid")
    real_salt = secrets.token_bytes(_SALT_BYTES) if salt is None else salt
    if not isinstance(real_salt, bytes) or not (8 <= len(real_salt) <= 64):
        _reject("enrollment_signer_scram_salt_invalid")
    salted = hashlib.pbkdf2_hmac(
        "sha256", password.encode("ascii"), real_salt, iterations, dklen=32
    )
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    verifier = (
        f"SCRAM-SHA-256${iterations}:{base64.b64encode(real_salt).decode('ascii')}"
        f"${base64.b64encode(stored_key).decode('ascii')}"
        f":{base64.b64encode(server_key).decode('ascii')}"
    )
    if not _VERIFIER_GRAMMAR.fullmatch(
        verifier
    ):  # defensive: the emitted verifier must be well-formed
        _reject("enrollment_signer_scram_verifier_invalid")
    return verifier


def render_signer_role_sql(verifier: str) -> tuple[str, ...]:
    """Render the reviewed, idempotent least-privilege provisioning statements. The role name is a
    CODE constant and the verifier is grammar-validated before it is embedded (a malformed verifier
    refuses), so there is no injection surface. Order: create/ensure the role, set its SCRAM
    password
    + closed attributes, REVOKE schema/table privilege, then GRANT exactly USAGE + SELECT."""
    if not isinstance(verifier, str) or not _VERIFIER_GRAMMAR.fullmatch(verifier):
        _reject("enrollment_signer_scram_verifier_invalid")
    role = ENROLLMENT_SIGNER_DB_ROLE  # a fixed literal, never caller-supplied
    attrs = "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS"
    return (
        # 1) create the role if absent (no bare CREATE ROLE — re-install must be idempotent)
        f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') "
        f"THEN CREATE ROLE {role} WITH {attrs}; END IF; END $$;",
        # 2) pin the closed attribute set + the SCRAM verifier (never the plaintext) every time
        f"ALTER ROLE {role} WITH {attrs} PASSWORD '{verifier}';",
        # 3) strip any pre-existing schema/table privilege (the role owns nothing and needs none),
        #    then grant EXACTLY the least-privilege reads.
        f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {role};",
        f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {role};",
        *ENROLLMENT_SIGNER_DB_GRANTS,
    )


__all__ = [
    "ENROLLMENT_SIGNER_DB_GRANTS",
    "ENROLLMENT_SIGNER_DB_GRANT_SQL",
    "ENROLLMENT_SIGNER_DB_ROLE",
    "EnrollmentSignerRoleError",
    "generate_signer_db_password",
    "render_signer_role_sql",
    "scram_sha256_verifier",
]
