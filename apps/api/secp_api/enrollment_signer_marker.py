"""Root-owned enrollment-signer enablement MARKER reader (SECP-PR5H-B2, commit 2b-3b).

The API signer client is enabled in PRODUCTION by exactly ONE authority: a fixed, root-owned marker
file the root installer writes LAST (after TLS/locator/role/key/broker/activation all verify) and
bind-mounts read-only into the API container. NO environment variable, Compose value, database
field,
or HTTP request can enable the signer in production; the ordinary non-root API cannot create,
replace,
chmod, unlink, or rewrite the marker. Marker absence, corruption, an unsafe filesystem posture, or a
malformed binding all mean SEALED.

This module only READS + validates the marker (bounded, canonical, strict closed schema, and — on a
POSIX host — a root-owned, single-link, non-symlink, non-group/other-writable regular file). It
never
writes the marker (that is the management installer's finalization step) and never returns secret
content — the marker binds only public installation facts.
"""

from __future__ import annotations

import json
import os
import stat
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from secp_commissioning.canonical import canonical_json

#: The single fixed, code-owned marker path (also named by the management ``ApiSignerMarker`` /
#: ``ManagementLocations`` contract). Bind-mounted read-only into the API container at this path.
MARKER_PATH = "/etc/secp/controller/enrollment-signer.enabled"
_MARKER_SCHEMA = "secp.enrollment-signer-enablement/v1"
_MAX_MARKER_BYTES = 8 * 1024


class EnrollmentSignerMarker(BaseModel):
    """The strict, closed enablement-marker binding. Extra/missing fields + wrong types are refused;
    every value is bounded. It binds the marker to the exact installation/release/active-identity/
    broker/UDS/API-peer — a mismatch on any is one the caller can seal on. No secret content."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_id: str = Field(alias="schema", min_length=1, max_length=64)
    installation_id: str = Field(min_length=1, max_length=64)
    release_digest: str = Field(min_length=71, max_length=71)
    active_identity_row_id: str = Field(min_length=1, max_length=64)
    activation_token: str = Field(min_length=1, max_length=128)
    controller_key_id: str = Field(min_length=71, max_length=71)
    broker_unit_identity: str = Field(min_length=71, max_length=71)
    uds_contract_identity: str = Field(min_length=1, max_length=128)
    api_uid: int = Field(ge=0, le=2**31 - 1)
    api_gid: int = Field(ge=0, le=2**31 - 1)
    signer_role_name: str = Field(min_length=1, max_length=64)
    locator_ca_digest: str = Field(min_length=71, max_length=71)
    management_identity_digest: str = Field(min_length=71, max_length=71)
    bootstrap_evidence_digest: str = Field(min_length=71, max_length=71)
    recorded_at: str = Field(min_length=1, max_length=40)


def _fs_safe(path: str) -> bool:
    """On POSIX, the marker must be a root-owned, single-link, non-symlink, non-group/other-writable
    regular file (so the non-root API can never forge it). Off POSIX (a dev host) this check is not
    meaningful and is skipped — production runs on POSIX."""
    if os.name != "posix":
        return True
    try:
        st = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISREG(st.st_mode)
        and not stat.S_ISLNK(st.st_mode)
        and st.st_uid == 0
        and st.st_nlink == 1
        and (st.st_mode & 0o022) == 0
    )


def load_valid_marker(*, path: str = MARKER_PATH) -> EnrollmentSignerMarker | None:
    """Return the validated marker, or ``None`` (→ SEALED) when it is absent, filesystem-unsafe,
    oversized, non-canonical, or malformed. Never raises on a bad marker and never logs bytes."""
    if not _fs_safe(path):
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read(_MAX_MARKER_BYTES + 1)
    except OSError:
        return None
    if not raw or len(raw) > _MAX_MARKER_BYTES:
        return None
    body = raw[:-1] if raw.endswith(b"\n") else raw
    try:
        obj = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict) or canonical_json(obj).encode("utf-8") != body:
        return None  # a non-canonical marker is treated as corrupt → sealed
    try:
        marker = EnrollmentSignerMarker.model_validate(obj)
    except ValidationError:
        return None
    if marker.schema_id != _MARKER_SCHEMA:
        return None
    return marker


def marker_binding_matches(marker: EnrollmentSignerMarker, *, expected: dict[str, Any]) -> bool:
    """Whether the marker's binding matches the running install's expected public facts (id, release,
    active identity, key, broker, UDS, API uid/gid, role, locator/CA + mgmt/evidence digests). Any
    mismatch → the caller seals. Only the keys present in ``expected`` are checked (each must equal
    the marker field)."""
    for key, value in expected.items():
        if getattr(marker, key, object()) != value:
            return False
    return True


__all__ = [
    "MARKER_PATH",
    "EnrollmentSignerMarker",
    "load_valid_marker",
    "marker_binding_matches",
]
