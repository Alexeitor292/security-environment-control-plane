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
"""

from __future__ import annotations

import argparse
import json
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


def _kwargs_from_context(ctx: object) -> dict:
    return dict(
        profile=ctx.profile,  # type: ignore[attr-defined]
        profile_load_reason=ctx.profile_load_reason,  # type: ignore[attr-defined]
        expected=ctx.expected,  # type: ignore[attr-defined]
        installed_trust_ok=ctx.installed_trust_ok,  # type: ignore[attr-defined]
        installed_trust_reason=ctx.installed_trust_reason,  # type: ignore[attr-defined]
        attestation=ctx.attestation,  # type: ignore[attr-defined]
        host_observation=ctx.host_observation,  # type: ignore[attr-defined]
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


_HANDLERS = {"verify": cmd_verify}


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
    return parser


def run(argv: list[str], deps: VerifyDeps | None = None) -> tuple[int, dict]:
    args = build_parser().parse_args(argv)
    return _HANDLERS[args.command](args, deps)


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    # deps=None → the production context loader resolves the fixed root-controlled inputs.
    exit_code, payload = run(args_list, deps=None)
    if "--json" in args_list:
        sys.stdout.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    else:
        sys.stdout.write(
            f"[{payload.get('phase', '?')}] exit={exit_code} status={payload.get('status')}\n"
        )
    return exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
