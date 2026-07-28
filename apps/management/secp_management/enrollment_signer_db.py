"""Dedicated least-privilege enrollment-signer DB role + SCRAM credential (SECP-PR5H-B2, 2b-2).

The root-gated enrollment-signer broker authenticates to PostgreSQL as a DEDICATED LOGIN role
(:data:`~secp_management.enrollment_signer_identity.ENROLLMENT_SIGNER_DB_ROLE`) that owns nothing
and
is granted ONLY ``CONNECT`` + schema ``USAGE`` + ``SELECT`` on the single identity table — never
INSERT/UPDATE/DELETE, never any other table (rejecting the earlier NOLOGIN + ``SET ROLE`` design,
where the admin connection retains admin capability). Its password is a high-entropy secret that:

* is stored in the database ONLY as a SCRAM-SHA-256 verifier (RFC 5802) — the plaintext is never in
  a ``CREATE ROLE`` statement value that would reach the SQL log, and PostgreSQL never sees
  plaintext;
* is delivered to the broker process ONLY through a fixed root-owned systemd credential
  (``LoadCredential``), read from ``$CREDENTIALS_DIRECTORY`` at start — never an environment
  variable,
  a command line, a world-readable file, or a value in the connection string on disk.

This module is PURE + offline: it computes the verifier, renders the reviewed provisioning SQL (role
name is a code constant; the verifier is grammar-validated before it is ever embedded, so there is
no
injection surface), and reads the credential from the systemd-provided directory. It opens no
network
connection and runs no subprocess; the admin-side ``psql`` apply is a distinct root install step.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
from typing import NoReturn

from secp_management import ManagementError
from secp_management.enrollment_signer_identity import (
    ENROLLMENT_SIGNER_DB_GRANTS,
    ENROLLMENT_SIGNER_DB_ROLE,
)
from secp_management.layout import ManagementLocations

#: The systemd credential id + fixed root-owned source path the installer writes the plaintext to.
#: systemd ``LoadCredential=<id>:<path>`` copies it into ``$CREDENTIALS_DIRECTORY/<id>`` (tmpfs,
#: 0400)
#: for the broker unit; the broker reads it there, never from this source path directly. The source
#: path is the authoritative code-owned location (a writable controller-config-rooted path).
ENROLLMENT_SIGNER_CREDENTIAL_ID = "secp-enrollment-signer-db"
ENROLLMENT_SIGNER_CREDENTIAL_SOURCE_PATH = ManagementLocations().enrollment_signer_credential_path()

_SCRAM_ITERATIONS = 4096
_SALT_BYTES = 16
_PASSWORD_BYTES = 32  # 256 bits of entropy, rendered as 64 lowercase hex (ASCII, DSN/SASL-safe)
_MAX_CREDENTIAL_BYTES = 4096
# a SCRAM-SHA-256 verifier: SCRAM-SHA-256$<iters>:<b64salt>$<b64storedkey>:<b64serverkey>
_VERIFIER_GRAMMAR = re.compile(
    r"SCRAM-SHA-256\$[1-9][0-9]{0,6}:[A-Za-z0-9+/]+={0,2}\$[A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}"
)
_PASSWORD_GRAMMAR = re.compile(r"[0-9a-f]{32,128}")  # the generated ASCII-hex secret


class EnrollmentSignerDbError(ManagementError):
    """A bounded, closed refusal — only a reason code, never the password, verifier, or DSN."""


def _reject(reason_code: str) -> NoReturn:
    raise EnrollmentSignerDbError(reason_code)


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
        f"${base64.b64encode(stored_key).decode('ascii')}:{base64.b64encode(server_key).decode('ascii')}"
    )
    if not _VERIFIER_GRAMMAR.fullmatch(
        verifier
    ):  # defensive: the emitted verifier must be well-formed
        _reject("enrollment_signer_scram_verifier_invalid")
    return verifier


def render_signer_role_sql(verifier: str) -> tuple[str, ...]:
    """Render the reviewed, idempotent least-privilege provisioning statements an admin applies out
    of band at install. The role name is a CODE constant and the verifier is grammar-validated
    before it is embedded (a malformed verifier refuses), so there is no injection surface. Order:
    create/ensure the role, set its SCRAM password + closed attributes, REVOKE everything, then
    GRANT
    exactly CONNECT/USAGE/SELECT."""
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
        #    then grant EXACTLY the least-privilege reads. CONNECT comes from PUBLIC's default; on
        #    PostgreSQL 15+ PUBLIC no longer has CREATE on the public schema, so a SELECT-only role
        #    cannot create objects there either.
        f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {role};",
        f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {role};",
        *ENROLLMENT_SIGNER_DB_GRANTS,
    )


def signer_db_credential_dir() -> str | None:
    """The systemd-provided credentials directory for the broker unit, or ``None`` off systemd. Only
    an absolute path systemd set is honored — never a caller-chosen directory."""
    value = os.environ.get("CREDENTIALS_DIRECTORY")
    if not value or not value.startswith("/") or "\x00" in value:
        return None
    return value


def load_signer_db_password(*, credentials_dir: str | None = None) -> str:
    """Read the signer role's plaintext password from the systemd credential
    (``$CREDENTIALS_DIRECTORY/<id>``) — the ONLY sanctioned source. Fails closed (bounded reason)
    when
    systemd did not provide the credential, or the file is missing/oversized/malformed. Never
    returns
    the raw file bytes on error and never logs the value."""
    base = credentials_dir if credentials_dir is not None else signer_db_credential_dir()
    if not base:
        _reject("enrollment_signer_credential_unavailable")
    path = os.path.join(base, ENROLLMENT_SIGNER_CREDENTIAL_ID)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, os.O_RDONLY | nofollow)
    except OSError:
        _reject("enrollment_signer_credential_unavailable")
    try:
        raw = os.read(fd, _MAX_CREDENTIAL_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > _MAX_CREDENTIAL_BYTES:
        _reject("enrollment_signer_credential_malformed")
    text = raw.decode("ascii", errors="ignore").strip()
    if not _PASSWORD_GRAMMAR.fullmatch(text):
        _reject("enrollment_signer_credential_malformed")
    return text


__all__ = [
    "ENROLLMENT_SIGNER_CREDENTIAL_ID",
    "ENROLLMENT_SIGNER_CREDENTIAL_SOURCE_PATH",
    "EnrollmentSignerDbError",
    "generate_signer_db_password",
    "load_signer_db_password",
    "render_signer_role_sql",
    "scram_sha256_verifier",
    "signer_db_credential_dir",
]
