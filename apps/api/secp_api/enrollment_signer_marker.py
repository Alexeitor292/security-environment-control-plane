"""Root-owned enrollment-signer enablement MARKER reader (SECP-PR5H-B2, commit 2b-3b / 2b-3c-c).

The API signer client is enabled in PRODUCTION by exactly ONE authority: a fixed, root-owned marker
file the root installer writes LAST (after TLS/locator/role/key/broker/activation all verify) and
bind-mounts read-only into the API container. NO environment variable, Compose value, database
field,
or HTTP request can enable the signer in production; the ordinary non-root API cannot create,
replace,
chmod, unlink, or rewrite the marker. Marker absence, corruption, an unsafe filesystem posture, or a
malformed binding all mean SEALED.

The marker SCHEMA + BYTES CONTRACT are NOT defined here: they live in the plane-neutral
``secp_commissioning.enrollment_signer_marker`` module that the management writer, the management
engine replay/status, the management runtime observer and this reader all import, so the two planes
accept and reject exactly the same marker bytes (R7). What stays here is the API-plane-specific part
only: the POSIX root-owned filesystem-posture gate and the bounded, fail-closed file read.

This module only READS + validates the marker (bounded, canonical, strict closed schema, and — on a
POSIX host — a root-owned, single-link, non-symlink, non-group/other-writable regular file). It
never
writes the marker (that is the management installer's finalization step) and never returns secret
content — the marker binds only public installation facts.
"""

from __future__ import annotations

import os
import stat
from typing import Any

from secp_commissioning.enrollment_signer_marker import (
    ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS,
    ENROLLMENT_SIGNER_MARKER_FIELDS,
    ENROLLMENT_SIGNER_MARKER_MAX_BYTES,
    ENROLLMENT_SIGNER_MARKER_PATH,
    ENROLLMENT_SIGNER_MARKER_SCHEMA,
    EnrollmentSignerMarker,
    EnrollmentSignerMarkerError,
    parse_marker_bytes,
    parse_marker_bytes_or_none,
    render_marker_bytes,
)

#: The single fixed, code-owned marker path (also named by the management ``ApiSignerMarker`` /
#: ``ManagementLocations`` contract). Bind-mounted read-only into the API container at this path.
#: Re-exported from the plane-neutral contract so both planes name the same constant.
MARKER_PATH = ENROLLMENT_SIGNER_MARKER_PATH
_MAX_MARKER_BYTES = ENROLLMENT_SIGNER_MARKER_MAX_BYTES


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
    oversized, non-canonical, or malformed. Never raises on a bad marker and never logs bytes.

    The content decision is delegated verbatim to the shared plane-neutral parser: the management
    plane refuses exactly the bytes this refuses, and accepts exactly the bytes this accepts."""
    if not _fs_safe(path):
        return None
    try:
        with open(path, "rb") as fh:
            # one byte past the bound so an oversized marker is detected, not silently truncated
            raw = fh.read(_MAX_MARKER_BYTES + 1)
    except OSError:
        return None
    return parse_marker_bytes_or_none(raw)


def marker_binding_matches(marker: EnrollmentSignerMarker, *, expected: dict[str, Any]) -> bool:
    """Whether the marker's binding matches the running install's expected public facts. Any
    mismatch → the caller seals. Only the keys present in ``expected`` are checked (each must
    equal the marker field)."""
    for key, value in expected.items():
        if getattr(marker, key, object()) != value:
            return False
    return True


__all__ = [
    "ENROLLMENT_SIGNER_MARKER_BINDING_FIELDS",
    "ENROLLMENT_SIGNER_MARKER_FIELDS",
    "ENROLLMENT_SIGNER_MARKER_SCHEMA",
    "MARKER_PATH",
    "EnrollmentSignerMarker",
    "EnrollmentSignerMarkerError",
    "load_valid_marker",
    "marker_binding_matches",
    "parse_marker_bytes",
    "parse_marker_bytes_or_none",
    "render_marker_bytes",
]
