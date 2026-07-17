"""Safe staging-bundle renderer (SECP-PR5C, ADR-023, deliverable 5 + defect #8).

Renders the deployment-local material into a CALLER-SUPPLIED temporary directory using FIXED,
executable-owned basenames resolved strictly beneath the operator root (the descriptor supplies no
path). The staging root is validated (must be a real, non-symlink directory); every file is written
with ``O_EXCL | O_NOFOLLOW`` and ALL bytes are written (a short write is refused). The rendered
target set is checked for uniqueness + basename/role collisions and asserted to equal the plan's
file
set. The operator entrypoint bytes are pinned to the plan's entrypoint-template digest.

Rendering is DETERMINISTIC (no timestamp, no randomness), secret-free (the renderer re-scans its own
JSON through the descriptor forbidden-secret scanner), and contacts nothing.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from typing import Protocol

from secp_commissioning import TOOL_VERSION
from secp_commissioning.canonical import canonical_json, sha256_bytes
from secp_commissioning.descriptor import (
    CONTRACT_VERSION,
    CommissioningDescriptor,
    OperatorPreparationSection,
    scan_forbidden,
)
from secp_commissioning.errors import reject
from secp_commissioning.locations import (
    OPERATOR_FILE_LAYOUT,
    ROLE_DIRECTORY_MANIFEST,
    ROLE_OPERATOR_ENTRYPOINT,
    ROLE_OPERATOR_PREPARATION_BUNDLE,
    ROLE_OPERATOR_SERVICE_DISABLED,
    CommissioningLocations,
)
from secp_commissioning.operator_template import (
    ENTRYPOINT_TEMPLATE_BYTES,
    OPERATOR_ENTRYPOINT_TEMPLATE,
)
from secp_commissioning.plan import CommissioningPlan

__all__ = [
    "render_bundle",
    "RenderResult",
    "RenderedFile",
    "OPERATOR_ENTRYPOINT_TEMPLATE",
    "StagingSeam",
    "StagingStat",
    "RealStagingSeam",
    "InMemoryStagingSeam",
]

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_STAGING_WRITE_MASK = 0o022  # no group/other write on the staging root


@dataclass(frozen=True)
class StagingStat:
    is_dir: bool
    is_symlink: bool
    uid: int
    gid: int
    mode: int


class StagingSeam(Protocol):
    """The injectable staging boundary (defect #8). The renderer validates the root's type + trusted
    ownership + restrictive mode through this seam and writes each fixed-basename file through it,
    so the ownership/mode policy is exercised deterministically on any platform (in-memory seam) &
    enforced for real on POSIX (the real seam)."""

    root: str

    def trusted_uid(self) -> int: ...
    def inspect_root(self) -> StagingStat | None: ...
    def write_new(self, relname: str, data: bytes, *, mode: int) -> None: ...


class RealStagingSeam:
    """Production staging seam: real ``os`` operations under ``root`` (POSIX). Writes are
    O_EXCL|O_NOFOLLOW with a full-bytes loop, and a partially-written file is unlinked on any
    short-write/error."""

    def __init__(self, root: str) -> None:
        self.root = root

    def trusted_uid(self) -> int:
        geteuid = getattr(os, "geteuid", None)
        return geteuid() if geteuid is not None else 0

    def inspect_root(self) -> StagingStat | None:
        try:
            st = os.lstat(self.root)
        except OSError:
            return None
        m = st.st_mode
        return StagingStat(
            is_dir=stat.S_ISDIR(m),
            is_symlink=stat.S_ISLNK(m),
            uid=st.st_uid,
            gid=st.st_gid,
            mode=stat.S_IMODE(m),
        )

    def write_new(self, relname: str, data: bytes, *, mode: int) -> None:
        dest = os.path.join(self.root, relname)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC
        fd = os.open(dest, flags, mode)
        wrote = False
        try:
            view = memoryview(data)
            total = 0
            while total < len(data):
                written = os.write(fd, view[total:])
                if written <= 0:
                    reject("render_short_write")
                total += written
            wrote = True
        finally:
            os.close(fd)
            if not wrote:  # unlink the partially-written staging file
                try:
                    os.unlink(dest)
                except OSError:
                    pass


class InMemoryStagingSeam:
    """Deterministic staging seam for tests (cross-platform). Models a staging root with explicit
    ownership/type/mode and records written files in memory. ``fail_on`` models a short-write: the
    named file is refused and NOT recorded (the real seam unlinks the partial)."""

    def __init__(
        self,
        root: str = "/staging",
        *,
        uid: int = 0,
        gid: int = 0,
        mode: int = 0o700,
        is_dir: bool = True,
        is_symlink: bool = False,
        exists: bool = True,
        trusted_uid: int = 0,
        fail_on: str | None = None,
    ) -> None:
        self.root = root
        self._uid = uid
        self._gid = gid
        self._mode = mode
        self._is_dir = is_dir
        self._is_symlink = is_symlink
        self._exists = exists
        self._trusted_uid = trusted_uid
        self._fail_on = fail_on
        self.written: dict[str, bytes] = {}

    def trusted_uid(self) -> int:
        return self._trusted_uid

    def inspect_root(self) -> StagingStat | None:
        if not self._exists:
            return None
        return StagingStat(
            is_dir=self._is_dir,
            is_symlink=self._is_symlink,
            uid=self._uid,
            gid=self._gid,
            mode=self._mode,
        )

    def write_new(self, relname: str, data: bytes, *, mode: int) -> None:
        if relname in self.written:
            reject("render_staging_exists")
        if relname == self._fail_on:
            reject("render_short_write")  # partial write; nothing recorded (real seam unlinks)
        self.written[relname] = data


@dataclass(frozen=True)
class RenderedFile:
    role: str
    relative_path: str
    target_path: str
    sha256: str
    owner_uid: int
    owner_gid: int
    mode: int
    content: bytes

    def __repr__(self) -> str:
        return f"RenderedFile(role={self.role}, target={self.target_path}, sha256={self.sha256})"


@dataclass(frozen=True)
class RenderResult:
    staging_dir: str
    descriptor_digest: str
    plan_digest: str
    files: tuple[RenderedFile, ...]

    def manifest(self) -> dict:
        return {
            "contract_version": CONTRACT_VERSION,
            "tool_version": TOOL_VERSION,
            "descriptor_digest": self.descriptor_digest,
            "plan_digest": self.plan_digest,
            "files": [
                {
                    "role": f.role,
                    "sha256": f.sha256,
                    "owner_uid": f.owner_uid,
                    "owner_gid": f.owner_gid,
                    "mode": f.mode,
                }
                for f in sorted(self.files, key=lambda x: x.role)
            ],
        }

    def manifest_digest(self) -> str:
        return sha256_bytes(canonical_json(self.manifest()).encode("utf-8"))


def _validate_staging(seam: StagingSeam) -> None:
    st = seam.inspect_root()
    if st is None:
        reject("render_staging_dir_missing")
    if st.is_symlink:
        reject("render_staging_dir_symlink")
    if not st.is_dir:
        reject("render_staging_dir_not_directory")
    if st.uid != seam.trusted_uid():
        reject("render_staging_dir_untrusted_owner")
    if st.mode & _STAGING_WRITE_MASK:
        reject("render_staging_dir_world_writable")


def _content_for(
    role: str, descriptor: CommissioningDescriptor, locations: CommissioningLocations
) -> bytes:
    op = descriptor.operator_preparation
    if role == ROLE_DIRECTORY_MANIFEST:
        payload = {
            "contract_version": CONTRACT_VERSION,
            "operator_root": locations.operator_root,
            "mode": 0o750,
        }
        scan_forbidden(payload)
        return canonical_json(payload).encode("utf-8")
    if role == ROLE_OPERATOR_PREPARATION_BUNDLE:
        payload = {
            "contract_version": CONTRACT_VERSION,
            "activation_status": "prepared",
            "enabled": False,
            "task_queue": op.task_queue,
            "image_digest": op.image.digest,
            "runtime": {"uid": op.runtime.uid, "gid": op.runtime.gid},
            "controlled_live_composition_installed": False,
        }
        scan_forbidden(payload)
        return canonical_json(payload).encode("utf-8")
    if role == ROLE_OPERATOR_ENTRYPOINT:
        return ENTRYPOINT_TEMPLATE_BYTES
    if role == ROLE_OPERATOR_SERVICE_DISABLED:
        return _service_unit(op, locations).encode("utf-8")
    reject("render_unknown_role")


def _service_unit(op: OperatorPreparationSection, locations: CommissioningLocations) -> str:
    uid = op.runtime.uid
    gid = op.runtime.gid
    entrypoint = locations.resolve_operator_file("entrypoint.py")
    return (
        "# RENDERED disabled operator unit (secp_commissioning, SECP-PR5C). PREPARED, NOT RUN.\n"
        "# No install/wanted-by section, so it is inert until a separately reviewed deployment\n"
        "# package installs the controlled-live compositions AND an operator then activates it.\n"
        "# Commissioning never enables or starts it.\n"
        "[Unit]\n"
        "Description=SECP controlled-live operator worker (prepared, disabled)\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"User={uid}\n"
        f"Group={gid}\n"
        "NoNewPrivileges=true\n"
        "ProtectSystem=strict\n"
        "ReadOnlyPaths=/\n"
        f"ExecStart=/usr/bin/env python3 {entrypoint}\n"
    )


def render_bundle(
    *,
    descriptor: CommissioningDescriptor,
    plan: CommissioningPlan,
    locations: CommissioningLocations,
    staging_dir: str | None = None,
    staging_seam: StagingSeam | None = None,
) -> RenderResult:
    """Render the staging bundle through ``staging_seam`` (defaulting to a real seam over
    ``staging_dir``). Deterministic + secret-free; contacts none. The staging root must be a real,
    non-symlink directory OWNED by the trusted commissioning identity and NOT group/other-writable;
    each file is written with fixed basenames and a partial write is unlinked."""
    if staging_seam is None:
        if not (isinstance(staging_dir, str) and staging_dir):
            reject("render_staging_dir_unset")
        staging_seam = RealStagingSeam(staging_dir)
    _validate_staging(staging_seam)
    files: list[RenderedFile] = []
    for role, basename, mode in OPERATOR_FILE_LAYOUT:
        target = locations.resolve_operator_file(basename)
        data = _content_for(role, descriptor, locations)
        staging_seam.write_new(basename, data, mode=0o600)
        files.append(
            RenderedFile(
                role=role,
                relative_path=basename,
                target_path=target,
                sha256=sha256_bytes(data),
                owner_uid=0,
                owner_gid=0,
                mode=mode,
                content=data,
            )
        )

    # Collision + set invariants: unique targets + basenames + roles; entrypoint pinned; manifest
    # set
    # equals the plan's file set exactly.
    targets = [f.target_path for f in files]
    if len(set(targets)) != len(targets):
        reject("render_duplicate_target")
    if len({f.relative_path for f in files}) != len(files):
        reject("render_duplicate_basename")
    if len({f.role for f in files}) != len(files):
        reject("render_duplicate_role")
    entrypoint = next(f for f in files if f.role == ROLE_OPERATOR_ENTRYPOINT)
    if entrypoint.sha256 != plan.entrypoint_template_digest:
        reject("render_entrypoint_template_mismatch")
    if {f.role for f in files} != {f.role for f in plan.files}:
        reject("render_file_set_mismatch")
    if {f.target_path for f in files} != {f.target_path for f in plan.files}:
        reject("render_target_set_mismatch")

    return RenderResult(
        staging_dir=staging_seam.root,
        descriptor_digest=plan.descriptor_digest,
        plan_digest=plan.digest(),
        files=tuple(files),
    )
