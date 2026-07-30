"""Management-side enrollment-signer credential loader + re-export of the plane-neutral role
primitives (SECP-PR5H-B2).

The pure SCRAM verifier + provisioning-SQL + fixed role/grants live in the plane-neutral
:mod:`secp_commissioning.enrollment_signer_role` (so the API provisioning one-shot can render +
apply
them WITHOUT importing the management plane, and the installer can generate the verifier without the
API plane). This management module re-exports them and adds the MANAGEMENT-only systemd-credential
loader: the broker reads the dedicated role's plaintext password ONLY from the fixed root-owned
systemd credential (``LoadCredential``), never an env var / command line / world-readable file / DSN
on disk.
"""

from __future__ import annotations

import os
import re
from typing import NoReturn

from secp_commissioning.enrollment_signer_role import (
    ENROLLMENT_SIGNER_DB_GRANT_SQL,
    ENROLLMENT_SIGNER_DB_GRANTS,
    ENROLLMENT_SIGNER_DB_ROLE,
    EnrollmentSignerRoleError,
    generate_signer_db_password,
    render_signer_role_sql,
    scram_sha256_verifier,
)

from secp_management.layout import ManagementLocations

#: Back-compat alias for the management-facing error name (now the plane-neutral role error).
EnrollmentSignerDbError = EnrollmentSignerRoleError

#: The systemd credential id + fixed root-owned source path the installer writes the plaintext to.
#: systemd ``LoadCredential=<id>:<path>`` copies it into ``$CREDENTIALS_DIRECTORY/<id>`` (tmpfs,
#: 0400) for the broker unit; the broker reads it there, never from this source path directly.
ENROLLMENT_SIGNER_CREDENTIAL_ID = "secp-enrollment-signer-db"
ENROLLMENT_SIGNER_CREDENTIAL_SOURCE_PATH = ManagementLocations().enrollment_signer_credential_path()

_MAX_CREDENTIAL_BYTES = 4096
_PASSWORD_GRAMMAR = re.compile(r"[0-9a-f]{32,128}")  # the generated ASCII-hex secret

# The reviewed FIXED controller PostgreSQL coordinates the dedicated least-privilege role connects
# to. Host/port/dbname are code-owned constants (a single-host controller install maps postgres to
# loopback); the driver is psycopg. Production connects here with the role name + plaintext ONLY —
# never a caller/env-selected DSN. ``base_url`` is a TEST-ONLY seam (the real-PostgreSQL fences
# point
# it at the ephemeral CI database); production ``main()`` never passes it.
_SIGNER_DB_HOST = "127.0.0.1"
_SIGNER_DB_PORT = 5432
_SIGNER_DB_NAME = "secp"


def _reject(reason_code: str) -> NoReturn:
    raise EnrollmentSignerRoleError(reason_code)


def build_signer_role_engine(password: str, *, base_url: str | None = None):
    """Build a SQLAlchemy ``Engine`` authenticated as the dedicated least-privilege
    ``secp_enrollment_signer`` role with ``password``. The DSN is code-owned: only the role name +
    plaintext vary; host/port/dbname are fixed constants. The session ``TimeZone`` is pinned to UTC
    so the derived ``activation_token`` (``str(activated_at)``) renders identically to the API's
    runtime binding across planes. The plaintext lives ONLY inside the returned engine's connection
    config — it is never printed, logged, or persisted. ``base_url`` is a test-only coordinate seam;
    production passes none."""
    if not _PASSWORD_GRAMMAR.fullmatch(password):
        _reject("enrollment_signer_credential_malformed")
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url

    base = (
        make_url(base_url)
        if base_url
        else make_url(
            f"postgresql+psycopg://x@{_SIGNER_DB_HOST}:{_SIGNER_DB_PORT}/{_SIGNER_DB_NAME}"
        )
    )
    url = base.set(username=ENROLLMENT_SIGNER_DB_ROLE, password=password)
    return create_engine(
        url, future=True, pool_pre_ping=True, connect_args={"options": "-c timezone=UTC"}
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
    when systemd did not provide the credential, or the file is missing/oversized/malformed. Never
    returns the raw file bytes on error and never logs the value."""
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
    "ENROLLMENT_SIGNER_DB_GRANTS",
    "ENROLLMENT_SIGNER_DB_GRANT_SQL",
    "ENROLLMENT_SIGNER_DB_ROLE",
    "EnrollmentSignerDbError",
    "EnrollmentSignerRoleError",
    "generate_signer_db_password",
    "load_signer_db_password",
    "render_signer_role_sql",
    "scram_sha256_verifier",
    "signer_db_credential_dir",
]
