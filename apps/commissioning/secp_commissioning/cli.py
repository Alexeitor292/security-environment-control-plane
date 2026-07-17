"""Commissioning CLI (SECP-PR5C, ADR-023, deliverable 7 + defects #1B, #5D).

``python -m secp_commissioning <phase>`` exposes the engine to an administrator; the SAME engine +
deterministic ``--json`` are what the future web wizard will call. Phases:

    inspect | plan | render | verify | install-prepared | status | rollback-prepared | evidence

There is NO ``activate`` phase. ``install-prepared`` / ``rollback-prepared`` default to DRY-RUN; a
write needs ``--write --confirm``. The CLI exposes NO arbitrary root write location: the descriptor,
evidence, operator root, and every install path are FIXED by the executable-owned
:class:`~secp_commissioning.locations.CommissioningLocations`; the staging bundle is an internal
temp
directory. The only descriptor inputs are the trusted expected-identity PINS (reviewed release SHAs
+
image digests + operator queue), which the descriptor must MATCH. Tests inject alternate locations +
fakes through :class:`CommissioningDeps`. The CLI imports no subprocess/Temporal/HTTP client and
contacts nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC

from secp_commissioning import TOOL_VERSION
from secp_commissioning.errors import CommissioningError
from secp_commissioning.locations import CommissioningLocations
from secp_commissioning.plan import ExpectedIdentities
from secp_commissioning.runtime import (
    ContainerRuntime,
    FilesystemBackend,
    SealedContainerRuntime,
)
from secp_commissioning.status import ServiceStateAdapter, UnavailableServiceState

DEFAULT_ORDINARY_QUEUE = "secp-orchestration"
DEFAULT_ORDINARY_HEALTH = ("python", "-m", "secp_worker.health", "check")


def _utc_now() -> str:
    from datetime import datetime

    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _default_fs() -> FilesystemBackend:
    from secp_commissioning.runtime import RealFilesystem

    return RealFilesystem()


def _default_staging_seam(root: str):  # noqa: ANN202
    from secp_commissioning.render import RealStagingSeam

    return RealStagingSeam(root)


@dataclass
class CommissioningDeps:
    """Injected effects + trusted locations. Production defaults fail closed; tests inject fakes."""

    locations: CommissioningLocations = field(default_factory=CommissioningLocations)
    fs: FilesystemBackend | None = None
    container_runtime: ContainerRuntime = field(default_factory=SealedContainerRuntime)
    service_state: ServiceStateAdapter = field(default_factory=UnavailableServiceState)
    clock: Callable[[], str] = _utc_now
    descriptor_os_seam: object | None = None
    staging_dir_factory: Callable[[], str] = tempfile.mkdtemp
    staging_seam_factory: Callable[[str], object] = _default_staging_seam

    def filesystem(self) -> FilesystemBackend:
        return self.fs if self.fs is not None else _default_fs()


def _read_descriptor(deps: CommissioningDeps):  # noqa: ANN202
    from secp_commissioning.reader import RootControlledDescriptorReader

    reader = RootControlledDescriptorReader(
        deps.locations.descriptor_path,
        os_seam=deps.descriptor_os_seam,  # type: ignore[arg-type]
    )
    return reader.read()


def _expected(args: argparse.Namespace) -> ExpectedIdentities:
    return ExpectedIdentities(
        release_source_sha=args.expected_source_sha,
        source_tree_sha=args.expected_source_tree_sha,
        parent_sha=getattr(args, "expected_parent_sha", None),
        control_plane_image_digest=args.expected_control_plane_image,
        ordinary_worker_image_digest=args.expected_ordinary_image,
        operator_image_digest=args.expected_operator_image,
        ordinary_task_queue=args.expected_ordinary_queue,
        operator_task_queue=args.expected_operator_queue,
        ordinary_health_command=DEFAULT_ORDINARY_HEALTH,
    )


def _build_plan(args: argparse.Namespace, deps: CommissioningDeps):  # noqa: ANN202
    from secp_commissioning.plan import build_plan
    from secp_commissioning.status import inspect_host

    read = _read_descriptor(deps)
    facts = inspect_host(
        descriptor=read.descriptor,
        locations=deps.locations,
        fs=deps.filesystem(),
        container_runtime=deps.container_runtime,
        service_state=deps.service_state,
    )
    plan = build_plan(
        descriptor=read.descriptor, locations=deps.locations, facts=facts, expected=_expected(args)
    )
    return read, plan


def _render(args: argparse.Namespace, deps: CommissioningDeps):  # noqa: ANN202
    from secp_commissioning.render import render_bundle

    read, plan = _build_plan(args, deps)
    seam = deps.staging_seam_factory(deps.staging_dir_factory())
    result = render_bundle(
        descriptor=read.descriptor,
        plan=plan,
        locations=deps.locations,
        staging_seam=seam,  # type: ignore[arg-type]
    )
    return read, plan, result


# --------------------------------------------------------------------------- phase handlers


def cmd_inspect(args: argparse.Namespace, deps: CommissioningDeps) -> tuple[int, dict]:
    from secp_commissioning.status import inspect_host

    read = _read_descriptor(deps)
    facts = inspect_host(
        descriptor=read.descriptor,
        locations=deps.locations,
        fs=deps.filesystem(),
        container_runtime=deps.container_runtime,
        service_state=deps.service_state,
    )
    return 0, {
        "phase": "inspect",
        "descriptor_digest": read.descriptor_digest,
        "operator_root_present": facts.directories[deps.locations.operator_root].exists,
        "images_present": list(facts.image_digests_present),
        "service_state_inspected": facts.service_state_inspected,
        "operator_service_enabled": facts.operator_service_enabled,
        "operator_service_running": facts.operator_service_running,
    }


def cmd_plan(args: argparse.Namespace, deps: CommissioningDeps) -> tuple[int, dict]:
    _read, plan = _build_plan(args, deps)
    return 0, {"phase": "plan", "plan_digest": plan.digest(), "plan": plan.canonical()}


def cmd_render(args: argparse.Namespace, deps: CommissioningDeps) -> tuple[int, dict]:
    _read, plan, result = _render(args, deps)
    return 0, {
        "phase": "render",
        "plan_digest": plan.digest(),
        "render_manifest_digest": result.manifest_digest(),
        "manifest": result.manifest(),
    }


def cmd_verify(args: argparse.Namespace, deps: CommissioningDeps) -> tuple[int, dict]:
    read, plan = _build_plan(args, deps)
    return 0, {
        "phase": "verify",
        "ok": True,
        "descriptor_digest": read.descriptor_digest,
        "plan_digest": plan.digest(),
        "ordinary_task_queue": plan.ordinary_task_queue,
        "operator_task_queue": plan.operator_task_queue,
        "operator_service_enabled": False,
    }


def cmd_install_prepared(args: argparse.Namespace, deps: CommissioningDeps) -> tuple[int, dict]:
    from secp_commissioning.install import MODE_REFUSED, install_prepared

    read, plan, result = _render(args, deps)
    report = install_prepared(
        descriptor=read.descriptor,
        plan=plan,
        render=result,
        locations=deps.locations,
        fs=deps.filesystem(),
        container_runtime=deps.container_runtime,
        service_state=deps.service_state,
        now=deps.clock(),
        write=bool(args.write),
        confirm=bool(args.confirm),
    )
    payload = {
        "phase": "install-prepared",
        "mode": report.mode,
        "plan_digest": report.plan_digest,
        "changed": report.changed,
        "evidence_digest": report.evidence_digest,
        "reason_code": report.reason_code,
        "operations": [
            {"kind": o.kind, "target": o.target, "detail": o.detail} for o in report.operations
        ],
    }
    return (2 if report.mode == MODE_REFUSED else 0), payload


def cmd_status(args: argparse.Namespace, deps: CommissioningDeps) -> tuple[int, dict]:
    from secp_commissioning.status import STATUS_PREPARED_OK, commissioning_status

    report = commissioning_status(
        locations=deps.locations,
        fs=deps.filesystem(),
        container_runtime=deps.container_runtime,
        service_state=deps.service_state,
    )
    code = 0 if report.state == STATUS_PREPARED_OK else 1
    return code, {"phase": "status", **report.canonical()}


def cmd_rollback_prepared(args: argparse.Namespace, deps: CommissioningDeps) -> tuple[int, dict]:
    from secp_commissioning.install import MODE_REFUSED, rollback_prepared
    from secp_commissioning.reader import evidence_exists, read_evidence

    fs = deps.filesystem()
    if not evidence_exists(fs, deps.locations.evidence_path):
        return 1, {
            "phase": "rollback-prepared",
            "mode": "refused",
            "reason_code": "evidence_absent",
        }
    evidence = read_evidence(fs, deps.locations.evidence_path)
    report = rollback_prepared(
        evidence=evidence,
        locations=deps.locations,
        fs=fs,
        write=bool(args.write),
        confirm=bool(args.confirm),
    )
    return (2 if report.mode == MODE_REFUSED else 0), {
        "phase": "rollback-prepared",
        "mode": report.mode,
        "changed": report.changed,
        "reason_code": report.reason_code,
        "operations": [
            {"kind": o.kind, "target": o.target, "detail": o.detail} for o in report.operations
        ],
    }


def cmd_evidence(args: argparse.Namespace, deps: CommissioningDeps) -> tuple[int, dict]:
    from secp_commissioning.reader import evidence_exists, read_evidence

    fs = deps.filesystem()
    if not evidence_exists(fs, deps.locations.evidence_path):
        return 1, {"phase": "evidence", "present": False, "reason_code": "evidence_absent"}
    evidence = read_evidence(fs, deps.locations.evidence_path)
    return 0, {"phase": "evidence", "present": True, "evidence": evidence.canonical()}


_HANDLERS: dict[str, Callable[[argparse.Namespace, CommissioningDeps], tuple[int, dict]]] = {
    "inspect": cmd_inspect,
    "plan": cmd_plan,
    "render": cmd_render,
    "verify": cmd_verify,
    "install-prepared": cmd_install_prepared,
    "status": cmd_status,
    "rollback-prepared": cmd_rollback_prepared,
    "evidence": cmd_evidence,
}


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="deterministic machine-readable output")
    parser = argparse.ArgumentParser(
        prog="python -m secp_commissioning",
        parents=[common],
        description=(
            "SECP commissioning automation foundation (SECP-PR5C). Prepares — never activates. "
            "There is no activate command and no arbitrary write-location flag."
        ),
    )
    parser.add_argument("--version", action="version", version=f"secp_commissioning {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="phase", required=True)

    def _sub(
        name: str, help: str, *, pins: bool = True, wc: bool = False
    ) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help, parents=[common])
        if pins:
            p.add_argument("--expected-source-sha", required=True)
            p.add_argument("--expected-source-tree-sha", required=True)
            p.add_argument("--expected-parent-sha", default=None)
            p.add_argument("--expected-control-plane-image", required=True)
            p.add_argument("--expected-ordinary-image", required=True)
            p.add_argument("--expected-operator-image", required=True)
            p.add_argument("--expected-operator-queue", required=True)
            p.add_argument("--expected-ordinary-queue", default=DEFAULT_ORDINARY_QUEUE)
        if wc:
            p.add_argument("--write", action="store_true", help="perform writes (default: dry-run)")
            p.add_argument("--confirm", action="store_true", help="confirm the write")
        return p

    _sub("inspect", "observe host facts (read-only)")
    _sub("plan", "build the immutable commissioning plan")
    _sub("render", "render the staging bundle")
    _sub("verify", "validate descriptor + plan preconditions")
    _sub("install-prepared", "install the prepared (disabled) state", wc=True)
    _sub("status", "independently re-verify the prepared state", pins=False)
    _sub("rollback-prepared", "remove only objects this install created", pins=False, wc=True)
    _sub("evidence", "print the prepared-state evidence record", pins=False)
    return parser


def run(argv: list[str], deps: CommissioningDeps | None = None) -> tuple[int, dict]:
    args = build_parser().parse_args(argv)
    resolved = deps if deps is not None else CommissioningDeps()
    handler = _HANDLERS[args.phase]
    try:
        return handler(args, resolved)
    except CommissioningError as exc:
        return 2, {"phase": args.phase, "ok": False, "reason_code": exc.reason_code}


def _render_human(exit_code: int, payload: dict) -> str:
    head = f"[{payload.get('phase', '?')}] exit={exit_code}"
    for key in ("mode", "state", "ok", "reason_code", "plan_digest", "evidence_digest", "changed"):
        if payload.get(key) is not None:
            head += f" {key}={payload[key]}"
    return head


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    exit_code, payload = run(args_list)
    if "--json" in args_list:
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(_render_human(exit_code, payload) + "\n")
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
