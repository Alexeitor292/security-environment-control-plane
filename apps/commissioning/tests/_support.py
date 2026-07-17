"""Shared test support for the commissioning suite (SECP-PR5C, second iteration).

Documentation-only fixtures (never a real deployment value); a fake OS seam for the descriptor
reader
(with per-fd offset so exact-read + growth checks are exercised); and helpers to assemble the
in-memory engine with the trusted locations + expected-identity pins. Nothing here contacts the
network, Temporal, a database, or any external infrastructure.
"""

from __future__ import annotations

import stat
from dataclasses import dataclass

# Documentation-only constants (RFC 5737 / RFC 2606 style). NEVER a real value.
SOURCE_SHA = "a" * 40
SOURCE_TREE_SHA = "b" * 40
DIGEST_CP = "sha256:" + "1" * 64
DIGEST_OW = "sha256:" + "2" * 64
DIGEST_OP = "sha256:" + "3" * 64
ORDINARY_QUEUE = "secp-orchestration"
OPERATOR_QUEUE = "secp-controlled-live-v1"
ORDINARY_HEALTH = ("python", "-m", "secp_worker.health", "check")

DESCRIPTOR_PATH = "/etc/secp/commissioning/descriptor.json"
EVIDENCE_PATH = "/var/lib/secp/commissioning/evidence.json"
OPERATOR_ROOT = "/opt/secp/operator"
ENTRYPOINT_PATH = OPERATOR_ROOT + "/entrypoint.py"


def valid_descriptor_raw(**overrides: object) -> dict:
    def _rt() -> dict:
        return {"uid": 10001, "gid": 10001, "read_only_root_fs": True}

    def _res() -> dict:
        return {"memory_limit_mb": 512, "cpu_limit_millicores": 1000, "pids_limit": 256}

    raw: dict = {
        "contract_version": "secp.commissioning.descriptor/v1alpha1",
        "deployment": {
            "deployment_id": "12345678-1234-1234-1234-1234567890ab",
            "site_label": "lab-01",
            "environment_label": "staging",
        },
        "control_plane": {
            "source": {"source_sha": SOURCE_SHA, "source_tree_sha": SOURCE_TREE_SHA},
            "image": {"reference": "registry.example.test/secp/api:pr5c", "digest": DIGEST_CP},
            "runtime": {"uid": 1000, "gid": 1000, "read_only_root_fs": True},
            "resources": _res(),
            "health_command": ["python", "-m", "secp_api.health"],
        },
        "ordinary_worker": {
            "source": {"source_sha": SOURCE_SHA, "source_tree_sha": SOURCE_TREE_SHA},
            "image": {"reference": "registry.example.test/secp/worker:pr5c", "digest": DIGEST_OW},
            "runtime": _rt(),
            "resources": _res(),
            "task_queue": ORDINARY_QUEUE,
            "db_role": "secp_worker",
            "health_command": list(ORDINARY_HEALTH),
        },
        "operator_preparation": {
            "image": {"reference": "registry.example.test/secp/operator:pr5c", "digest": DIGEST_OP},
            "runtime": _rt(),
            "resources": _res(),
            "task_queue": OPERATOR_QUEUE,
            "enabled": False,
        },
    }
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(raw.get(key), dict):
            raw[key] = {**raw[key], **value}
        else:
            raw[key] = value
    return raw


def locations():  # noqa: ANN201
    from secp_commissioning.locations import CommissioningLocations

    return CommissioningLocations()


def expected(**over):  # noqa: ANN001, ANN201
    from secp_commissioning.plan import ExpectedIdentities

    base = dict(
        release_source_sha=SOURCE_SHA,
        source_tree_sha=SOURCE_TREE_SHA,
        control_plane_image_digest=DIGEST_CP,
        ordinary_worker_image_digest=DIGEST_OW,
        operator_image_digest=DIGEST_OP,
        ordinary_task_queue=ORDINARY_QUEUE,
        operator_task_queue=OPERATOR_QUEUE,
        ordinary_health_command=ORDINARY_HEALTH,
    )
    base.update(over)
    return ExpectedIdentities(**base)


# --------------------------------------------------------------------------- descriptor reader seam

S_DIR = stat.S_IFDIR | 0o755
S_REG = stat.S_IFREG | 0o644
S_LNK = stat.S_IFLNK | 0o777


@dataclass
class FakeStat:
    st_mode: int
    st_uid: int = 0
    st_size: int = 10
    st_nlink: int = 1
    st_ino: int = 1


class FakeOsSeam:
    """Injectable OS seam for the descriptor reader. Tracks a per-fd offset so exact-read + growth
    checks run; ``fstat`` may disagree with ``lstat`` to model a replacement race."""

    def __init__(self, lstats, fstat, content, *, is_posix=True):  # noqa: ANN001
        self.is_posix = is_posix
        self._lstats = lstats
        self._fstat = fstat
        self._content = content
        self._fd = 0
        self._offsets: dict[int, int] = {}

    def lstat(self, path: str):  # noqa: ANN201
        if path not in self._lstats:
            raise OSError("missing")
        return self._lstats[path]

    def open_nofollow(self, path: str) -> int:
        self._fd += 1
        self._offsets[self._fd] = 0
        return self._fd

    def fstat(self, fd: int):  # noqa: ANN201
        return self._fstat

    def read(self, fd: int, size: int) -> bytes:
        off = self._offsets.get(fd, 0)
        chunk = self._content[off : off + size]
        self._offsets[fd] = off + len(chunk)
        return chunk

    def close(self, fd: int) -> None:
        return None


def good_lstats(content: bytes) -> dict:
    return {
        "/etc": FakeStat(S_DIR),
        "/etc/secp": FakeStat(S_DIR),
        "/etc/secp/commissioning": FakeStat(S_DIR),
        DESCRIPTOR_PATH: FakeStat(S_REG, st_size=len(content)),
    }


# --------------------------------------------------------------------------- in-memory engine


@dataclass
class Engine:
    descriptor: object
    plan: object
    render: object
    fs: object
    container_runtime: object
    service_state: object
    locations: object
    expected: object


def build_engine(
    staging_dir: str, *, images_present: bool = True, service_state=None, overrides=None
):  # noqa: ANN001, ANN201
    from secp_commissioning.descriptor import parse_descriptor
    from secp_commissioning.plan import build_plan
    from secp_commissioning.render import InMemoryStagingSeam, render_bundle
    from secp_commissioning.runtime import InMemoryContainerRuntime, InMemoryFilesystem
    from secp_commissioning.status import StaticServiceState, inspect_host

    descriptor = parse_descriptor(valid_descriptor_raw(**(overrides or {})))
    loc = locations()
    fs = InMemoryFilesystem()
    present = (DIGEST_CP, DIGEST_OW, DIGEST_OP) if images_present else ()
    cr = InMemoryContainerRuntime(present=present)
    ss = service_state if service_state is not None else StaticServiceState()
    exp = expected()
    facts = inspect_host(
        descriptor=descriptor, locations=loc, fs=fs, container_runtime=cr, service_state=ss
    )
    plan = build_plan(descriptor=descriptor, locations=loc, facts=facts, expected=exp)
    # Deterministic, cross-platform staging: a trusted (root-owned, restrictive) in-memory staging
    # root, so the ownership/mode policy runs identically on any dev box (the real seam is exercised
    # by the POSIX-only staging tests).
    seam = InMemoryStagingSeam(root=staging_dir, uid=0, gid=0, mode=0o700, trusted_uid=0)
    render = render_bundle(descriptor=descriptor, plan=plan, locations=loc, staging_seam=seam)
    return Engine(descriptor, plan, render, fs, cr, ss, loc, exp)


def do_install(
    engine: Engine, now: str = "2026-07-17T00:00:00+00:00", *, write: bool, confirm: bool
):  # noqa: ANN201
    from secp_commissioning.install import install_prepared

    return install_prepared(
        descriptor=engine.descriptor,
        plan=engine.plan,
        render=engine.render,
        locations=engine.locations,
        fs=engine.fs,
        container_runtime=engine.container_runtime,
        service_state=engine.service_state,
        now=now,
        write=write,
        confirm=confirm,
    )
