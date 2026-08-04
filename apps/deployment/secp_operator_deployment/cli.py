"""Administrator CLI for the deployment package (SECP-PR5D Round 4).

``python -m secp_operator_deployment verify --json`` runs the read-only prepared-deployment
verification and prints a deterministic, bounded, secret-free JSON report. By DEFAULT the real
command resolves its inputs from the fixed root-controlled PRODUCTION context
(:func:`production_context.load_verify_context`) — the profile, the INDEPENDENT expected pins, the
trusted installed-package verification, a bound runtime attestation, and a coherent host
observation — with no Python-level dependency injection required and no arbitrary ``--profile``
path flag. There is deliberately NO ``activate`` command and no command that constructs a
``Worker``, calls ``run_plan_generation``, resolves a credential, or contacts any infrastructure.
Tests inject a pre-resolved context / explicit inputs through the TEST-ONLY :class:`VerifyDeps`
seam.

``python -m secp_operator_deployment provenance --json`` is the second read-only command: it
recomputes the implementation manifest over the INSTALLED package through the trusted
directory-fd walk and reports the aggregate, so an operator can compare it against the aggregate
bound into a signed release BEFORE trusting the deployment. Like ``verify`` it takes no path
argument — the directory inspected is the installed module's own, resolved in code — and it
mutates nothing.

``python -m secp_operator_deployment queue --json`` is the third: the controlled-live QUEUE
isolation check (:mod:`secp_operator_deployment.queue_check`) — does the profile-to-pins-to-worker
queue authority hold, is the packaged operator unit dormant, and what would refuse an attempted
controlled-live start.
It resolves its inputs through the SAME context loader ``verify`` uses, so it adds no contact
surface, and it takes no queue argument for the same reason the others take no path argument.

All three commands perform their filesystem reads HERE and hand already-resolved values to the
PURE builders in :mod:`secp_operator_deployment.verify` /
:mod:`secp_operator_deployment.queue_check`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass

from secp_operator_deployment import PACKAGE_VERSION


@dataclass
class VerifyDeps:
    """TEST-ONLY injection seam (never reached by the production CLI): a pre-resolved
    :class:`~secp_operator_deployment.production_context.VerifyContext` OR explicit,
    already-resolved ``build_verification`` inputs. When ``None`` is passed to :func:`run`, the
    production context
    loader is used instead."""

    context: object | None = None
    profile: object | None = None
    profile_load_reason: str | None = None
    expected: object | None = None
    installed_trust_ok: bool = False
    installed_trust_reason: str | None = None
    attestation: object | None = None
    compositions: object | None = None
    host_observation: object | None = None
    # provenance-command inputs (TEST-ONLY, same seam): already-resolved manifest aggregates.
    source_aggregate: str | None = None
    source_reason: str | None = None
    installed_aggregate: str | None = None


def _kwargs_from_context(ctx: object) -> dict:
    return dict(
        profile=ctx.profile,  # type: ignore[attr-defined]
        profile_load_reason=ctx.profile_load_reason,  # type: ignore[attr-defined]
        expected=ctx.expected,  # type: ignore[attr-defined]
        installed_trust_ok=ctx.installed_trust_ok,  # type: ignore[attr-defined]
        installed_trust_reason=ctx.installed_trust_reason,  # type: ignore[attr-defined]
        attestation=ctx.attestation,  # type: ignore[attr-defined]
        host_observation=ctx.host_observation,  # type: ignore[attr-defined]
        # Carried so the report states contact from a MEASUREMENT, not a declaration.
        host_commands_executed=ctx.host_commands_executed,  # type: ignore[attr-defined]
    )


def _verify_kwargs(deps: VerifyDeps | None) -> dict:
    from secp_operator_deployment.production_context import VerifyContext, load_verify_context

    if deps is None:
        # PRODUCTION default: resolve the fixed root-controlled verify context (no Python
        # injection).
        return _kwargs_from_context(load_verify_context())
    if deps.context is not None:
        # EXACT context type only; a foreign/duck-typed context yields fail-closed inputs (never
        # getattr'd for verification data).
        if type(deps.context) is not VerifyContext:
            return {"profile": None, "profile_load_reason": "verify_context_type_invalid"}
        return _kwargs_from_context(deps.context)
    return dict(
        profile=deps.profile,
        profile_load_reason=deps.profile_load_reason,
        expected=deps.expected,
        installed_trust_ok=bool(deps.installed_trust_ok),
        installed_trust_reason=deps.installed_trust_reason,
        attestation=deps.attestation,
        compositions=deps.compositions,
        host_observation=deps.host_observation,
    )


def cmd_verify(args: argparse.Namespace, deps: VerifyDeps | None) -> tuple[int, dict]:
    from secp_operator_deployment.verify import STATUS_EXIT_CODES, build_verification

    report = build_verification(**_verify_kwargs(deps))
    code = STATUS_EXIT_CODES.get(report.get("status", ""), 20)
    return code, report


def _provenance_kwargs(deps: VerifyDeps | None) -> dict:
    """Resolve the provenance inputs. This is where the I/O lives — :mod:`verify` stays PURE.

    There is deliberately NO ``--package-dir`` flag: the directory inspected is the INSTALLED
    module's own directory, resolved in code exactly as :mod:`production_context` resolves it. An
    operator-supplied path would let the report describe a tree that is not the one that would
    actually run, which is the same reason there is no arbitrary profile-path flag.
    """
    from secp_operator_deployment.manifest import COVERED_MODULES

    covered = len(COVERED_MODULES)
    if deps is not None:  # TEST-ONLY injection; never reached by the production CLI
        return dict(
            source_aggregate=deps.source_aggregate,
            source_reason=deps.source_reason,
            installed_aggregate=deps.installed_aggregate,
            installed_trust_ok=bool(deps.installed_trust_ok),
            installed_trust_reason=deps.installed_trust_reason,
            covered_module_count=covered,
            expected=deps.expected,
        )

    from secp_operator_deployment import package_implementation_digest
    from secp_operator_deployment.manifest import verify_installed_package_trust
    from secp_operator_deployment.production_context import _installed_package_dir

    source_aggregate: str | None = None
    source_reason: str | None = None
    try:
        source_aggregate = package_implementation_digest()
    except Exception as exc:
        source_reason = getattr(exc, "reason_code", "manifest_unavailable")

    installed_aggregate: str | None = None
    installed_trust_ok = False
    installed_trust_reason: str | None = "install_trust_not_evaluated"
    try:
        installed_aggregate = verify_installed_package_trust(_installed_package_dir())
        installed_trust_ok = True
        installed_trust_reason = None
    except Exception as exc:
        installed_trust_reason = getattr(exc, "reason_code", "install_untrusted")

    # The RELEASE identity comes from the INDEPENDENT root-controlled expected-identities file, not
    # from the profile — a profile must not be able to name its own release. Fail closed: an absent
    # or unreadable file yields a bounded reason and a report that says the identity is unavailable
    # rather than one that omits the question.
    expected: object | None = None
    expected_reason: str | None = None
    try:
        from secp_operator_deployment.identities import read_expected_identities
        from secp_operator_deployment.production_context import _production_fs

        expected = read_expected_identities(fs=_production_fs())
    except Exception as exc:
        expected = None
        expected_reason = getattr(exc, "reason_code", "expected_identities_not_provisioned")

    return dict(
        source_aggregate=source_aggregate,
        source_reason=source_reason,
        installed_aggregate=installed_aggregate,
        installed_trust_ok=installed_trust_ok,
        installed_trust_reason=installed_trust_reason,
        covered_module_count=covered,
        expected=expected,
        expected_reason=expected_reason,
    )


def cmd_provenance(args: argparse.Namespace, deps: VerifyDeps | None) -> tuple[int, dict]:
    from secp_operator_deployment.verify import PROVENANCE_EXIT_CODES, build_provenance_report

    report = build_provenance_report(**_provenance_kwargs(deps))
    code = PROVENANCE_EXIT_CODES.get(report.get("status", ""), 20)
    return code, report


def _queue_kwargs(deps: VerifyDeps | None) -> dict:
    """Resolve the queue-check inputs from the SAME fixed root-controlled context ``verify`` uses.

    The loader is called EXACTLY ONCE per invocation, which is what makes "adds no contact surface
    beyond ``verify``'s" checkable rather than claimed — a test counts the calls. There is no
    ``--queue`` argument: the queues inspected are the ones in the installed profile, never ones an
    operator names, for the same reason there is no profile-path flag.

    It also carries out the EXECUTED host-command count, so the report can state contact from a
    measurement instead of asserting it. Explicitly-injected test inputs never resolve a context
    and therefore truthfully report a count of zero.
    """
    from secp_operator_deployment.production_context import VerifyContext, load_verify_context

    ctx: object | None = None
    if deps is None:
        ctx = load_verify_context()  # PRODUCTION path — the one call
    elif deps.context is not None and type(deps.context) is VerifyContext:
        ctx = deps.context

    if ctx is not None:
        return {
            "profile": ctx.profile,  # type: ignore[attr-defined]
            "expected": ctx.expected,  # type: ignore[attr-defined]
            "host_observation": ctx.host_observation,  # type: ignore[attr-defined]
            "host_commands_executed": ctx.host_commands_executed,  # type: ignore[attr-defined]
        }
    # Explicit inputs, or a foreign context refused by exact type: no context resolution ran, so no
    # host command could have been executed through it.
    return {
        "profile": None if deps is None else deps.profile,
        "expected": None if deps is None else deps.expected,
        "host_observation": None if deps is None else deps.host_observation,
        "host_commands_executed": 0,
    }


def cmd_queue(args: argparse.Namespace, deps: VerifyDeps | None) -> tuple[int, dict]:
    from secp_operator_deployment.queue_check import QUEUE_EXIT_CODES, build_queue_report

    report = build_queue_report(**_queue_kwargs(deps))
    code = QUEUE_EXIT_CODES.get(report.get("status", ""), 20)
    return code, report


_HANDLERS = {"verify": cmd_verify, "provenance": cmd_provenance, "queue": cmd_queue}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m secp_operator_deployment",
        description=(
            "SECP controlled-live operator deployment package (SECP-PR5D). Sealed — never "
            "activates. There is no activate command and no arbitrary profile-path flag."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"secp_operator_deployment {PACKAGE_VERSION}"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify", help="read-only prepared-deployment verification (sealed)")
    verify.add_argument("--json", action="store_true", help="deterministic machine-readable output")
    prov = sub.add_parser(
        "provenance",
        help="read-only installed-package provenance (implementation aggregate + trust)",
    )
    prov.add_argument("--json", action="store_true", help="deterministic machine-readable output")
    queue = sub.add_parser(
        "queue",
        help="read-only queue authority, packaged-unit dormancy, and submission stops",
    )
    queue.add_argument("--json", action="store_true", help="deterministic machine-readable output")
    return parser


def run(argv: list[str], deps: VerifyDeps | None = None) -> tuple[int, dict]:
    args = build_parser().parse_args(argv)
    return _HANDLERS[args.command](args, deps)


# A bounded reason token: lowercase snake_case only. Anything else is replaced, so an exception
# message — which can carry absolute paths — can never reach an operator's terminal through here.
_BOUNDED_REASON = re.compile(r"^[a-z][a-z0-9_]{3,63}$")

# Exit code for a refusal that escaped the per-dimension handlers. Shares 20 with the other
# "stop and escalate" classes (``seals_unsafe``, ``queue_stops_open``, ``provenance_unavailable``)
# rather than inventing a code outside every published table.
UNAVAILABLE_EXIT_CODE = 20


def _bounded_reason(exc: BaseException) -> str:
    reason = getattr(exc, "reason_code", None)
    if isinstance(reason, str) and _BOUNDED_REASON.match(reason):
        return reason
    return "unhandled_command_failure"


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    # deps=None → the production context loader resolves the fixed root-controlled inputs.
    #
    # A package whose entire value is BOUNDED REFUSAL must not have an unbounded traceback as a
    # reachable exit. The hardened filesystem is POSIX+root only and refuses to construct
    # elsewhere; before this guard that refusal escaped every per-dimension handler and printed a
    # stack containing absolute deployment paths, exiting 1 — a code in none of the published
    # tables. Now every escaping refusal becomes a bounded report. SystemExit (argparse) and
    # KeyboardInterrupt deliberately still propagate: those are the caller's, not a refusal.
    try:
        exit_code, payload = run(args_list, deps=None)
    except Exception as exc:
        exit_code = UNAVAILABLE_EXIT_CODE
        payload = {
            "phase": args_list[0] if args_list and not args_list[0].startswith("-") else "?",
            "status": "command_unavailable",
            "exit_code": UNAVAILABLE_EXIT_CODE,
            # The bounded reason code ONLY. The exception message is never rendered.
            "reason_code": _bounded_reason(exc),
        }
    if "--json" in args_list:
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(
            f"[{payload.get('phase', '?')}] exit={exit_code} status={payload.get('status')}\n"
        )
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
