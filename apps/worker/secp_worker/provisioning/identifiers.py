"""Safe identifier validation for toolchain provenance (SECP-002B-1A, ADR-013).

Worker-only. Before any pinned value is interpolated into a process ``argv``, a
filesystem path, or a generated workspace file, it is validated as a safe opaque
identifier (or an approved absolute worker-managed executable path). This prevents shell
metacharacters, whitespace, path traversal, relative paths, and arbitrary executable
names from ever reaching a would-be process invocation or rendered artifact.

No process is run and no filesystem/binary is inspected here — this is pure string
validation.
"""

from __future__ import annotations

import re

# Characters that must never appear in a pinned identifier that will be interpolated.
_SHELL_METACHARS = set(";|&$`<>(){}[]*?!~'\"\\ \t\n\r")
# Opaque identifiers may use alnum plus a small safe punctuation set (for refs/mirrors).
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:@/-]+$")
# A bare executable name: no path separators, no metacharacters.
_BARE_EXEC_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
# An approved absolute, worker-managed executable path.
_ABS_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
_APPROVED_EXEC_PREFIXES = ("/opt/secp/toolchain/", "/opt/secp/bin/")


class IdentifierError(ValueError):
    """A pinned identifier failed safety validation (redacted)."""


def validate_identifier(value: object, field: str) -> str:
    """Validate a safe opaque identifier. Raise ``IdentifierError`` on any problem."""
    if not isinstance(value, str) or not value:
        raise IdentifierError(f"{field} must be a non-empty string")
    if any(ch in _SHELL_METACHARS for ch in value):
        raise IdentifierError(f"{field} contains unsafe characters")
    if ".." in value:
        raise IdentifierError(f"{field} must not contain path traversal")
    if not _SAFE_ID_RE.match(value):
        raise IdentifierError(f"{field} contains characters outside the safe identifier set")
    return value


def validate_executable(value: object) -> str:
    """Validate an executable identity: a bare safe name or an approved absolute path."""
    if not isinstance(value, str) or not value:
        raise IdentifierError("executable must be a non-empty string")
    if any(ch in _SHELL_METACHARS for ch in value) or ".." in value:
        raise IdentifierError("executable contains unsafe characters or path traversal")
    if value.startswith("/"):
        if not value.startswith(_APPROVED_EXEC_PREFIXES) or not _ABS_PATH_RE.match(value):
            raise IdentifierError(
                "absolute executable must be an approved worker-managed path under "
                f"{_APPROVED_EXEC_PREFIXES}"
            )
        return value
    if "/" in value or "\\" in value or not _BARE_EXEC_RE.match(value):
        raise IdentifierError(
            "executable must be a bare safe identifier (no path separators) or an "
            "approved absolute worker-managed path"
        )
    return value


def validate_toolchain_identifiers(profile: dict) -> None:
    """Validate every pinned identifier that could be interpolated. Raise on any problem."""
    validate_executable(profile.get("executable"))
    validate_identifier(profile.get("module_bundle_id"), "module_bundle_id")
    mirror = profile.get("provider_mirror") or {}
    validate_identifier(mirror.get("identity"), "provider_mirror.identity")
    backend = profile.get("state_backend") or {}
    validate_identifier(backend.get("kind"), "state_backend.kind")
    validate_identifier(backend.get("reference"), "state_backend.reference")
