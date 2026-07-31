"""``secpctl`` — the customer-facing management-plane installer CLI (SECP-PR5E).

Command surface (there is deliberately NO ``activate``/``apply``/``destroy``/``proxmox``/``ssh``/
``exec``/``shell``)::

    secpctl release verify --bundle DIR
    secpctl host inspect
    secpctl bootstrap controller|worker --bundle DIR   [--write --confirm]
    secpctl adopt     controller|worker --bundle DIR    [--write --confirm]
    secpctl status    controller|worker
    secpctl evidence  controller|worker
    secpctl rollback  controller|worker                 [--write --confirm]

Every mutation defaults to DRY-RUN; a real write requires BOTH ``--write`` and ``--confirm``.
``--json``
prints deterministic JSON. Human-readable and JSON output execute the SAME engine — the CLI only
chooses formatting. There is NO arbitrary Python dependency injection through CLI arguments; the
only
path argument is the read-only offline release-bundle source.
"""

from __future__ import annotations

import argparse
import json
import sys

from secp_management import ManagementError
from secp_management.engine import (
    EngineDeps,
    adopt,
    bootstrap,
    controller_install,
    host_inspect,
    read_evidence,
    release_verify,
    status,
)
from secp_management.engine import rollback as engine_rollback
from secp_management.enrollment_cli import (
    EnrollmentCliDeps,
    enrollment_revoke,
    enrollment_status,
    invite_create,
    worker_enroll,
    worker_retry,
    worker_status,
)
from secp_management.transaction import EXIT_REFUSED, WriteGate

_ROLES = ("controller", "worker")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secpctl",
        description=(
            "SECP management-plane installer (SECP-PR5E). Local-first, human-supervised. No "
            "activate/apply/destroy/proxmox/ssh/exec/shell command; mutations default to dry-run "
            "and require --write --confirm."
        ),
    )
    parser.add_argument("--json", action="store_true", help="deterministic machine-readable output")
    groups = parser.add_subparsers(dest="group", required=True)

    rel = groups.add_parser("release", help="release bundle operations").add_subparsers(
        dest="action", required=True
    )
    rv = rel.add_parser("verify", help="verify a signed offline release bundle (read-only)")
    rv.add_argument("--bundle", required=True, help="path to the offline release bundle directory")

    host = groups.add_parser("host", help="host operations").add_subparsers(
        dest="action", required=True
    )
    host.add_parser("inspect", help="read-only local host inspection")

    for verb, helptext, wc, bundle in (
        ("bootstrap", "local bootstrap of a role", True, True),
        ("adopt", "safe adoption of an existing installation", True, True),
        ("status", "revalidating status of a role", False, False),
        ("evidence", "read + revalidate stored evidence", False, False),
        ("rollback", "remove only objects created by the bootstrap transaction", True, False),
    ):
        sub = groups.add_parser(verb, help=helptext)
        sub.add_argument("role", choices=_ROLES)
        if bundle:
            sub.add_argument("--bundle", required=True, help="offline release bundle directory")
        if wc:
            sub.add_argument(
                "--write", action="store_true", help="perform writes (default: dry-run)"
            )
            sub.add_argument("--confirm", action="store_true", help="confirm a real write")

    _add_controller_parser(groups)
    _add_enrollment_parser(groups)
    _add_worker_parser(groups)
    return parser


def _add_controller_parser(groups) -> None:
    """``secpctl controller install`` — the supported root-only controller-enrollment installation
    (SECP-PR5H-B2 2b-3c). It takes ONLY the two reviewed operator facts (``--public-origin``,
    ``--tls-mode``) plus the hardened ``--bundle``; there is NO ``--url``/``--ca``/``--key``/
    ``--credential``/``--dsn``/``--path``/``--command``. ``--write --confirm`` are mandatory for a
    real install; the default is a dry-run plan. Its deps resolve through the root-gated install
    composition; every steady-state command keeps finalization sealed."""
    controller = groups.add_parser("controller", help="controller installation operations")
    actions = controller.add_subparsers(dest="action", required=True)
    install = actions.add_parser(
        "install", help="install controller enrollment finalization (POSIX root only)"
    )
    install.add_argument("--bundle", required=True, help="offline release bundle directory")
    install.add_argument(
        "--public-origin", required=True, help="controller canonical public HTTPS origin"
    )
    install.add_argument("--tls-mode", required=True, help="policy-permitted controller TLS mode")
    _add_write_confirm(install)


def _add_write_confirm(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--write", action="store_true", help="perform writes (default: dry-run)")
    parser.add_argument("--confirm", action="store_true", help="confirm a real write")


def _add_enrollment_parser(groups) -> None:
    """``secpctl enrollment invite create|status|revoke`` — the supported controller enrollment
    commands, operated ONLY over the controller HTTPS API. No ``--url``/``--ca``/``--token`` and no
    internal CAS coordinate (state_digest/sequence/predecessor_digest) is ever accepted."""
    enr = groups.add_parser("enrollment", help="worker-enrollment controller operations")
    actions = enr.add_subparsers(dest="action", required=True)

    invite = actions.add_parser("invite", help="invitation operations").add_subparsers(
        dest="invite_action", required=True
    )
    create = invite.add_parser("create", help="create a single-use worker-enrollment invitation")
    create.add_argument("--site", required=True, help="opaque deployment-site label")
    create.add_argument(
        "--ttl-seconds", type=int, default=3600, help="invitation lifetime in seconds"
    )
    _add_write_confirm(create)

    st = actions.add_parser("status", help="read the bounded public enrollment status")
    st.add_argument("--enrollment-id", required=True, help="the enrollment id from the invitation")

    revoke = actions.add_parser("revoke", help="revoke an enrollment")
    revoke.add_argument("--enrollment-id", required=True, help="the enrollment id to revoke")
    revoke.add_argument(
        "--expected-revision", type=int, required=True, help="the last observed public revision"
    )
    _add_write_confirm(revoke)


def _add_worker_parser(groups) -> None:
    """``secpctl worker enroll|enrollment status|retry`` — the worker side of the exchange, driven
    from the non-secret invitation FILE and authenticated by worker proof-of-possession + the signed
    controller offer (NEVER the operator OIDC token)."""
    worker = groups.add_parser("worker", help="worker-side enrollment operations")
    actions = worker.add_subparsers(dest="action", required=True)

    enroll = actions.add_parser("enroll", help="drive this worker's enrollment to healthy")
    enroll.add_argument(
        "--invitation", required=True, help="path to the non-secret invitation file"
    )
    _add_write_confirm(enroll)

    enrollment = actions.add_parser(
        "enrollment", help="worker enrollment status/retry"
    ).add_subparsers(dest="worker_action", required=True)
    wst = enrollment.add_parser("status", help="read-only local reconciliation")
    wst.add_argument("--invitation", required=True, help="path to the non-secret invitation file")
    wretry = enrollment.add_parser("retry", help="resume-safe re-drive")
    wretry.add_argument(
        "--invitation", required=True, help="path to the non-secret invitation file"
    )
    _add_write_confirm(wretry)


def _gate(args: argparse.Namespace) -> WriteGate:
    return WriteGate(
        write=bool(getattr(args, "write", False)), confirm=bool(getattr(args, "confirm", False))
    )


_ENROLLMENT_GROUPS = ("enrollment", "worker")


def _is_enrollment_group(argv: list[str]) -> bool:
    for token in argv:
        if token.startswith("-"):
            continue
        return token in _ENROLLMENT_GROUPS
    return False


def run(
    argv: list[str],
    deps: EngineDeps | None = None,
    *,
    enrollment_deps: EnrollmentCliDeps | None = None,
) -> tuple[int, dict]:
    """Parse ``argv`` and execute the engine. Returns ``(exit_code, report_dict)``.

    ``deps=None`` builds a SEALED :class:`EngineDeps` (every adapter fails closed) — it is NOT the
    production path. The supported production composition lives in :func:`main`, which passes an
    explicitly-composed ``deps`` (steady-state :func:`_production_engine_deps`, or — Phase 2b — the
    clean-host root installation composition), falling back to this sealed default on any error.
    Tests inject their own ``deps`` directly. The enrollment/worker commands take a separate
    :class:`EnrollmentCliDeps` (SEALED default; tests inject fakes; ``main`` composes the real)."""
    args = build_parser().parse_args(argv)
    resolved = deps if deps is not None else EngineDeps()
    enr = enrollment_deps if enrollment_deps is not None else EnrollmentCliDeps()
    try:
        return _dispatch(args, resolved, enr)
    except ManagementError as exc:  # any uncaught engine refusal → bounded reason, exit 2
        return EXIT_REFUSED, {"command": args.group, "reason_code": exc.reason_code}


def _dispatch(
    args: argparse.Namespace, deps: EngineDeps, enr: EnrollmentCliDeps
) -> tuple[int, dict]:
    group = args.group
    if group == "release":
        return release_verify(args.bundle, deps)
    if group == "host":
        return host_inspect(deps)
    if group == "bootstrap":
        return bootstrap(args.role, args.bundle, _gate(args), deps)
    if group == "adopt":
        return adopt(args.role, args.bundle, _gate(args), deps)
    if group == "status":
        return status(args.role, deps)
    if group == "evidence":
        return read_evidence(args.role, deps)
    if group == "rollback":
        return engine_rollback(args.role, _gate(args), deps)
    if group == "controller":
        if args.action == "install":
            return controller_install(
                args.public_origin, args.tls_mode, args.bundle, _gate(args), deps
            )
        return EXIT_REFUSED, {"command": "controller", "reason_code": "unknown_command"}
    if group == "enrollment":
        return _dispatch_enrollment(args, enr)
    if group == "worker":
        return _dispatch_worker(args, enr)
    return EXIT_REFUSED, {"command": group, "reason_code": "unknown_command"}


def _dispatch_worker(args: argparse.Namespace, enr: EnrollmentCliDeps) -> tuple[int, dict]:
    if args.action == "enroll":
        return worker_enroll(enr, invitation_file=args.invitation, gate=_gate(args))
    if args.action == "enrollment" and args.worker_action == "status":
        return worker_status(enr, invitation_file=args.invitation)
    if args.action == "enrollment" and args.worker_action == "retry":
        return worker_retry(enr, invitation_file=args.invitation, gate=_gate(args))
    return EXIT_REFUSED, {"command": "worker", "reason_code": "unknown_command"}


def _dispatch_enrollment(args: argparse.Namespace, enr: EnrollmentCliDeps) -> tuple[int, dict]:
    if args.action == "invite" and args.invite_action == "create":
        return invite_create(
            enr, deployment_site_label=args.site, ttl_seconds=args.ttl_seconds, gate=_gate(args)
        )
    if args.action == "status":
        return enrollment_status(enr, enrollment_id=args.enrollment_id)
    if args.action == "revoke":
        return enrollment_revoke(
            enr,
            enrollment_id=args.enrollment_id,
            expected_revision=args.expected_revision,
            gate=_gate(args),
        )
    return EXIT_REFUSED, {"command": "enrollment", "reason_code": "unknown_command"}


def _production_enrollment_deps() -> EnrollmentCliDeps:
    """Compose the real controller client from the bootstrap-recorded locator + the protected
    operator token (POSIX/production). Any construction failure falls back to the SEALED default, so
    an unconfigured or non-POSIX host fails closed with a bounded code rather than crashing."""
    try:
        import os

        from secp_commissioning.runtime import RealFilesystem

        from secp_management.controller_api_locator import FileControllerApiLocatorProvider
        from secp_management.enrollment_controller_client import HttpsEnrollmentControllerClient
        from secp_management.operator_auth import (
            OPERATOR_TOKEN_FILE_ENV,
            ProtectedTokenFileProvider,
            SealedOperatorAccessTokenProvider,
        )

        fs = RealFilesystem()
        token_path = os.environ.get(OPERATOR_TOKEN_FILE_ENV, "")
        token_provider = (
            ProtectedTokenFileProvider(token_path)
            if token_path
            else SealedOperatorAccessTokenProvider()
        )
        # ONE locator instance, shared by the client and the CA provider on purpose: the client
        # pins its TLS to the recorded CA path and the invitation carries that same CA to the
        # worker. Two instances could resolve two different locators and hand the worker a chain
        # the operator's own client never trusted.
        locator_provider = FileControllerApiLocatorProvider(fs)
        client = HttpsEnrollmentControllerClient(
            locator_provider=locator_provider,
            token_provider=token_provider,
        )
        from secp_management.enrollment_cli import LocatorControllerCaBundleProvider
        from secp_management.worker_enroller import build_worker_enroller

        return EnrollmentCliDeps(
            controller_client=client,
            worker_enroller=build_worker_enroller(),
            # Without this the field falls to SealedControllerCaBundleProvider and EVERY
            # `enrollment invite create` refuses `secpctl_controller_ca_unavailable` — the CA
            # feature shipped inert. Same failure class as the sealed worker-enroller composition.
            ca_bundle=LocatorControllerCaBundleProvider(fs, locator_provider),
        )
    except Exception:  # noqa: BLE001 - fail closed to the sealed default; commands refuse, bounded
        return EnrollmentCliDeps()


def _controller_install_engine_deps() -> EngineDeps | None:
    """Compose the ROOT-ONLY controller-install deps (the ONLY composition that reaches the real
    finalization factory). It is gated POSIX-root up front (``assert_posix_root`` inside
    ``controller_install_engine_deps``) and falls back to the SEALED default on any error, so a
    non-root/non-POSIX/unprovisioned host fails closed with a bounded reason. No adapter/factory is
    ever selected by a flag, environment variable, or import."""
    try:
        from secp_management.production import controller_install_engine_deps

        return controller_install_engine_deps()
    except Exception:  # noqa: BLE001 - fail closed to the sealed default; the command refuses
        return None


def _is_controller_install_group(argv: list[str]) -> bool:
    positionals = [a for a in argv if not a.startswith("-")]
    return len(positionals) >= 2 and positionals[0] == "controller" and positionals[1] == "install"


def _production_engine_deps() -> EngineDeps | None:
    """Compose the production management-engine deps from the fixed root-controlled bootstrap inputs
    (SECP-PR5H-B2). This is the supported production CLI entrypoint's composition: it wires the real
    hardened adapters so ``secpctl bootstrap/adopt/status/evidence/rollback`` act on a real host.

    Any missing / unsafe / mismatched / non-production input (e.g. an unprovisioned or non-POSIX
    host) falls back to the SEALED default (``None`` → ``run`` builds a sealed ``EngineDeps()``), so
    the command fails closed with a bounded reason code rather than crashing or acting on an
    unverified adapter. No adapter is ever selected by a CLI flag, environment variable, or import —
    ``production_engine_deps`` reads only the fixed code-owned inputs."""
    try:
        from secp_management.production import production_engine_deps

        return production_engine_deps()
    except Exception:  # noqa: BLE001 - fail closed to the sealed default; the command refuses, bounded
        return None


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    # the enrollment/worker groups get the production controller-client composition; every OTHER
    # (engine) group gets the production management-engine deps. BOTH fall back to their SEALED
    # default on any error, so an unprovisioned/non-POSIX host still fails closed with a bounded
    # reason (unchanged) while a properly provisioned production host drives the real adapters.
    is_enrollment = _is_enrollment_group(args_list)
    enr = _production_enrollment_deps() if is_enrollment else None
    if is_enrollment:
        deps = None
    elif _is_controller_install_group(args_list):
        # the ONLY path that reaches the real finalization factory (root-gated); steady-state groups
        # stay on the finalization-SEALED steady-state composition.
        deps = _controller_install_engine_deps()
    else:
        deps = _production_engine_deps()
    exit_code, payload = run(args_list, deps=deps, enrollment_deps=enr)
    if "--json" in args_list:
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(_render_human(exit_code, payload))
    return exit_code


def _render_human(exit_code: int, payload: dict) -> str:
    command = payload.get("command", "?")
    parts = [f"[{command}] exit={exit_code}"]
    for key in ("role", "mode", "status", "ok", "trusted", "reason_code"):
        if key in payload:
            parts.append(f"{key}={payload[key]}")
    return " ".join(str(p) for p in parts) + "\n"
