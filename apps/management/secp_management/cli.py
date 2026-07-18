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
    host_inspect,
    read_evidence,
    release_verify,
    status,
)
from secp_management.engine import rollback as engine_rollback
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
    return parser


def _gate(args: argparse.Namespace) -> WriteGate:
    return WriteGate(
        write=bool(getattr(args, "write", False)), confirm=bool(getattr(args, "confirm", False))
    )


def run(argv: list[str], deps: EngineDeps | None = None) -> tuple[int, dict]:
    """Parse ``argv`` and execute the engine. Returns ``(exit_code, report_dict)``. Production
    passes
    ``deps=None`` → a real :class:`EngineDeps`; tests inject a fake one."""
    args = build_parser().parse_args(argv)
    resolved = deps if deps is not None else EngineDeps()
    try:
        return _dispatch(args, resolved)
    except ManagementError as exc:  # any uncaught engine refusal → bounded reason, exit 2
        return EXIT_REFUSED, {"command": args.group, "reason_code": exc.reason_code}


def _dispatch(args: argparse.Namespace, deps: EngineDeps) -> tuple[int, dict]:
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
    return EXIT_REFUSED, {"command": group, "reason_code": "unknown_command"}


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    exit_code, payload = run(args_list)
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
