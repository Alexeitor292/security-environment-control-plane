"""Trusted commissioning locations + path-safety contract (SECP-PR5C, ADR-023, defect #1).

The commissioning EXECUTABLE — not the untrusted descriptor — owns where things are read and
written.
:class:`CommissioningLocations` fixes the descriptor read path, the evidence path, and the SINGLE
operator-preparation root beneath which every installed artifact must live. The install layout
(directory + file basenames) is entirely executable-owned; the descriptor supplies NO absolute path.

Every managed write target is validated to be strictly beneath the fixed operator root and to fall
under NO protected root (ordinary-worker, control-plane, release, database, Docker, systemd-global,
SSH, ``/etc``, ``/root``, ``/boot``, system bin dirs, …). Path validation rejects ``..``, empty
components, duplicate separators, NUL, backslash, and alternate-root forms. The defaults are generic
repository-convention paths and contain no deployment-specific value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from secp_commissioning.errors import CommissioningError

# --- fixed, executable-owned install layout (basenames only; never descriptor-supplied) ----------
ROLE_OPERATOR_ROOT = "operator_preparation_root"
ROLE_OPERATOR_ENTRYPOINT = "operator_entrypoint_template"
ROLE_OPERATOR_PREPARATION_BUNDLE = "operator_preparation_bundle"
ROLE_DIRECTORY_MANIFEST = "root_directory_manifest"
ROLE_OPERATOR_SERVICE_DISABLED = "operator_service_definition_disabled"

# The fixed file roles installed under the operator root, mapped to their FIXED basenames + mode.
OPERATOR_FILE_LAYOUT: tuple[tuple[str, str, int], ...] = (
    (ROLE_DIRECTORY_MANIFEST, "directory-manifest.json", 0o640),
    (ROLE_OPERATOR_PREPARATION_BUNDLE, "preparation.json", 0o640),
    (ROLE_OPERATOR_ENTRYPOINT, "entrypoint.py", 0o750),
    (ROLE_OPERATOR_SERVICE_DISABLED, "operator.service.disabled", 0o640),
)
OPERATOR_ROOT_MODE = 0o750
_RESERVED_BASENAMES = frozenset(b for _r, b, _m in OPERATOR_FILE_LAYOUT)

# Roots that installed/rollback-owned material must NEVER touch (prefix match on a clean abs path).
PROTECTED_ROOTS: tuple[str, ...] = (
    "/opt/secp/worker",
    "/opt/secp/api",
    "/opt/secp/control-plane",
    "/opt/secp/release",
    "/etc",
    "/root",
    "/home",
    "/boot",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib/systemd",
    "/etc/systemd",
    "/var/lib/postgresql",
    "/var/lib/docker",
    "/var/run/docker.sock",
    "/run/systemd",
)

_CLEAN_ABS = re.compile(r"^/[A-Za-z0-9._/-]{1,511}$")
_SAFE_BASENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class LocationError(CommissioningError):
    """A path/location violated the trusted-locations contract (bounded reason code; no path)."""


def _is_clean_absolute(path: str) -> bool:
    if not isinstance(path, str) or not _CLEAN_ABS.match(path):
        return False
    if "\x00" in path or "\\" in path or "//" in path:
        return False
    parts = path.split("/")[1:]
    return bool(parts) and all(p not in ("", ".", "..") for p in parts)


def _under(path: str, root: str) -> bool:
    """True if ``path`` equals ``root`` or is strictly beneath it (component-wise; no prefix trick)."""  # noqa: E501
    return path == root or path.startswith(root.rstrip("/") + "/")


@dataclass(frozen=True)
class CommissioningLocations:
    """The executable-owned, fixed locations. Defaults are generic repository-convention paths."""

    descriptor_path: str = "/etc/secp/commissioning/descriptor.json"
    evidence_path: str = "/var/lib/secp/commissioning/evidence.json"
    operator_root: str = "/opt/secp/operator"
    # Additional protected roots the deployment can supply (never overlapping the operator root).
    extra_protected_roots: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for path in (self.descriptor_path, self.evidence_path, self.operator_root):
            if not _is_clean_absolute(path):
                raise LocationError("location_path_malformed")
        # The operator root (the only WRITE root for installed material) must not itself be a
        # protected root, and the evidence path must not live under the operator root (they have
        # distinct ownership sets so a rollback of installed material never removes the evidence).
        for protected in self.protected_roots():
            if _under(self.operator_root, protected):
                raise LocationError("operator_root_under_protected_root")
        if _under(self.evidence_path, self.operator_root):
            raise LocationError("evidence_path_under_operator_root")

    def protected_roots(self) -> tuple[str, ...]:
        return PROTECTED_ROOTS + tuple(self.extra_protected_roots)

    def resolve_operator_file(self, basename: str) -> str:
        """Resolve a FIXED operator file basename to its absolute path strictly beneath the operator
        root, refusing any traversal / unsafe basename / protected-root overlap."""
        if not (isinstance(basename, str) and _SAFE_BASENAME.match(basename)):
            raise LocationError("operator_file_basename_invalid")
        if "/" in basename or basename in (".", ".."):
            raise LocationError("operator_file_basename_invalid")
        candidate = self.operator_root.rstrip("/") + "/" + basename
        self.assert_writable_target(candidate)
        return candidate

    def assert_writable_target(self, path: str) -> None:
        """Fail closed unless ``path`` is a clean absolute path strictly beneath the operator root
        and beneath NO protected root. The single 'may commissioning write here?' authority."""
        if not _is_clean_absolute(path):
            raise LocationError("write_target_malformed")
        if not _under(path, self.operator_root):
            raise LocationError("write_target_outside_operator_root")
        # The operator root itself is a managed DIRECTORY target, not a file target; a file target
        # must be strictly beneath it.
        for protected in self.protected_roots():
            if _under(path, protected):
                raise LocationError("write_target_under_protected_root")

    def reserved_basenames(self) -> frozenset[str]:
        return _RESERVED_BASENAMES
