"""SECP two-host acceptance harness (SECP WS-B acceptance).

The automated controller-to-worker acceptance harness that must pass BEFORE any real Proxmox
acceptance is attempted. It creates two disposable hosts, installs the real product packages on
both, drives the real supported installation + enrollment path end to end, and emits a structured,
versioned acceptance evidence document.

WHAT THIS PACKAGE IS NOT
------------------------
It is **not** part of the product. It is deliberately absent from
``[tool.hatch.build.targets.wheel].packages`` and from ``infra/dev/Dockerfile.python``, so no
acceptance code ships in the controller/worker runtime image. It is importable for its own hermetic
tests through ``pythonpath``/``mypy_path`` only.

It contacts **no** Proxmox/provider, runs **no** OpenTofu/Terraform, performs no apply or destroy,
holds no production credential, and changes no trust root or safety seal. Every host it touches is
one it created itself and destroys on the way out.

WHAT "REAL" MEANS HERE
----------------------
Every stage runs product code that a customer would run: the real ``secpctl`` engine, the real
management adapters against a real Docker daemon and a real systemd, the real ``secp_api``
enrollment surface over real TLS against a real PostgreSQL, the real root-gated enrollment-signer
broker, and the real ``secp_worker`` Temporal worker against a real Temporal server. Where local
disposable infrastructure genuinely cannot reach, the harness records an explicit
:class:`~secp_acceptance.evidence.GapRecord` in the evidence document rather than leaving the
substitution implicit — see :mod:`secp_acceptance.gaps`.
"""

from __future__ import annotations

#: The acceptance harness contract version. It is bound into every evidence document and into the
#: run identity, so evidence produced by two different harness revisions is never conflated.
ACCEPTANCE_CONTRACT_VERSION = "secp.acceptance/v1"


class AcceptanceError(Exception):
    """A bounded acceptance-harness refusal.

    Carries ONLY a closed reason code from :mod:`secp_acceptance.reasons` — never a host path, a
    container id, a token, an origin, a key, or a raw exception chain. The harness drives real
    infrastructure, so an unbounded error string here would be the easiest place in the whole
    program for a credential or an endpoint to escape into an evidence document or a CI log.
    """

    __slots__ = ("reason_code",)

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code

    def __repr__(self) -> str:
        return f"AcceptanceError({self.reason_code})"


__all__ = ["ACCEPTANCE_CONTRACT_VERSION", "AcceptanceError"]
