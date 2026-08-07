"""The ``secp-worker`` console entry point — the executable the installed systemd unit runs.

The installer has always rendered ``ExecStart=/opt/secp/worker/bin/secp-worker --role <r>
--task-queue <q>`` (`worker_service_adapters.py:277,321`) and then refused to install unless that
file existed. **Nothing produced it.** ``pyproject.toml`` declared three console scripts and none
was ``secp-worker``, and ``secp_worker.main.main`` parsed no argv at all — so even a hand-built
wrapper would have silently ignored the role and queue the unit passes it. The installer was
validating a runtime tree an administrator had to construct by hand, which is the opposite of an
installer owning its installation.

This module is that executable.

WHY THE ARGV IS PARSED AND THEN CHECKED AGAINST SETTINGS
---------------------------------------------------------
The unit passes ``--role`` and ``--task-queue``. Both are also deployment configuration. Rather
than letting either win silently, this refuses when they disagree: a unit that says
``--task-queue secp-controlled-live-v1`` while the process is configured for the ordinary queue is
a misconfiguration whose symptom would otherwise be a worker quietly polling the wrong queue — and
on this system the operator queue is the privileged one, so "quietly polling the wrong queue" is a
privilege question, not a nuisance.

The argv is therefore an ASSERTION about what was installed, checked against what the process is
configured to be. Agreement runs; disagreement exits non-zero with a closed reason.

WHAT IT DOES NOT DO
-------------------
It does not choose a queue, construct a worker, enable a capability, or accept anything else from
argv. There is no ``--enable``, no ``--unseal``, no ``--real``. Execution authority on this system
comes from durable rows (ADR-030), and a command line is not a durable row.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

#: The roles an installed worker may declare. Closed: a role outside this set is a refusal, never
#: a default, because the role selects which queue the process is allowed to serve.
SUPPORTED_ROLES: tuple[str, ...] = ("ordinary", "operator")

#: Exit codes an operator (and a systemd ``Restart=`` policy) can act on. Distinct values because a
#: misconfigured unit needs an edit while a failed run needs a restart.
EXIT_OK = 0
EXIT_MISCONFIGURED = 2


class WorkerCliError(Exception):
    """A closed reason code. Never a path, a queue secret or a backend error."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secp-worker",
        description="Run the SECP worker for an installed role.",
        allow_abbrev=False,  # `--role` must not be satisfiable by `--ro`
    )
    parser.add_argument("--role", required=True, choices=SUPPORTED_ROLES)
    parser.add_argument("--task-queue", required=True, dest="task_queue")
    return parser


def resolve_role_and_queue(argv: Sequence[str], *, settings: object) -> tuple[str, str]:
    """Parse the installed argv and check it against the process configuration.

    Returns the agreed ``(role, task_queue)``. Raises :class:`WorkerCliError` when the unit and the
    configuration disagree — never silently prefers one.
    """
    args = build_parser().parse_args(list(argv))
    role = str(args.role)
    queue = str(args.task_queue).strip()
    if not queue:
        raise WorkerCliError("worker_task_queue_empty")

    ordinary = str(getattr(settings, "temporal_task_queue", "") or "")
    operator = str(getattr(settings, "temporal_operator_task_queue", "") or "")

    if role == "ordinary":
        if queue != ordinary:
            raise WorkerCliError("worker_queue_does_not_match_configured_ordinary_queue")
        if operator and queue == operator:
            # Belt and braces: an ordinary unit must never end up on the privileged queue even if
            # the two settings were configured to the same string.
            raise WorkerCliError("worker_ordinary_role_on_operator_queue")
        return role, queue

    # role == "operator"
    if not operator:
        raise WorkerCliError("worker_operator_queue_not_configured")
    if queue != operator:
        raise WorkerCliError("worker_queue_does_not_match_configured_operator_queue")
    return role, queue


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code; never raises past this boundary."""
    from secp_api.config import get_settings

    from secp_worker import main as worker_main

    raw = list(sys.argv[1:] if argv is None else argv)
    try:
        role, queue = resolve_role_and_queue(raw, settings=get_settings())
    except WorkerCliError as exc:
        # A closed reason on stderr, and a distinct exit code: a misconfigured unit needs an
        # operator edit, and restarting it forever would hide that.
        print(f"secp-worker refused to start: {exc}", file=sys.stderr)
        return EXIT_MISCONFIGURED
    except SystemExit as exc:  # argparse's own refusal (unknown role, missing flag)
        return int(exc.code or EXIT_MISCONFIGURED)

    if role == "operator":
        # The operator worker is a separate, deployment-local composition on a distinct queue. It
        # is not built here, and this entry point must not pretend it can start one: a process that
        # said "operator" and then served the ordinary set would be the privilege confusion the
        # queue separation exists to prevent.
        print(
            "secp-worker refused to start: worker_operator_composition_not_installed",
            file=sys.stderr,
        )
        return EXIT_MISCONFIGURED

    worker_main.main()
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - process entry
    raise SystemExit(main())
