"""Pure, deterministic plan-secret readiness evaluation (B1B-PR4 / ADR-021 §H).

Two MANDATORY facets, both required for ``ready``:

1. ``backend_authentication_readiness`` — the worker can AUTHENTICATE to the configured secret
   backend through the reviewed resolver self-test. It returns **no target provisioning secret**,
   surfaces **no secret reference**, and persists **no backend response body**. A self-test whose
   reason code is not a closed, bounded token is treated as leaking backend details and REFUSED.

2. ``jit_injection_contract`` — supplying opaque secret material to the future plan environment
   builder produces ONLY the exact allowlisted variables, inherits no ambient environment, mutates
   no ``os.environ``, creates no shell string, writes no HCL/durable artefact, and runs no process.

It performs no I/O and imports no adapter, transport, HTTP, subprocess, or backend client.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from secp_api.enums import (
    PlanSecretPurpose,
    PlanSecretReadinessFacet,
    PlanSecretReadinessOutcome,
    ReadinessFacetStatus,
    ReadinessReason,
)
from secp_api.readiness_contract import MAX_EVIDENCE_REASONS, is_opaque_proof_id

_F = PlanSecretReadinessFacet
_S = ReadinessFacetStatus
_R = ReadinessReason

# A self-test may return only a bounded, opaque reason code / proof label. Anything else (a URL, a
# vault path, a token, a stack trace, a backend response body) is REFUSED rather than persisted.
#
# ``fullmatch`` — NEVER ``match``: Python's ``$`` also matches immediately BEFORE a trailing
# newline,
# so ``re.match(r"^...$", "ok\n")`` succeeds and a newline would reach a bounded column.
#
# The reason-code shape bounds the CHARSET and LENGTH only; that charset is exactly the alphabet of
# DNS hostnames, S3/GCS bucket names, and Vault mounts, so the reason code is additionally compared
# against a CLOSED catalogue before use.
#
# The self-test PROOF ID is not shape-bounded at all — it must be a **UUID** (B1B-PR4 §5). A
# shape-bounded label could itself BE a Vault mount or a hostname, and an unsalted digest OF that
# label is an offline confirmation oracle for it. A UUID can be neither.
_SAFE_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,119}")


@dataclass(frozen=True)
class FacetResult:
    facet: str
    status: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class PlanSecretEvaluation:
    """The closed, secret-free evaluation of one plan-secret readiness attempt."""

    outcome: str
    facets: tuple[FacetResult, ...]
    reason_codes: tuple[str, ...]
    secret_purpose: str
    self_test_proof_id: uuid.UUID | None = None

    def facet_payload(self) -> list[dict]:
        return [{"facet": f.facet, "status": f.status} for f in self.facets]


def evaluate_plan_secret_readiness(
    *,
    self_test_ok: bool,
    self_test_reason_code: str,
    self_test_proof_id: object,
    jit_env_ok: bool,
    jit_reason: ReadinessReason | None,
    secret_purpose: str = PlanSecretPurpose.plan_read.value,
) -> PlanSecretEvaluation:
    """Evaluate both mandatory plan-secret facets explicitly and return one closed outcome."""
    facets: list[FacetResult] = []
    reasons: list[str] = []

    def add(facet: _F, status: _S, *facet_reasons: ReadinessReason) -> None:
        codes = tuple(r.value for r in facet_reasons)
        facets.append(FacetResult(facet=facet.value, status=status.value, reasons=codes))
        reasons.extend(codes)

    # --- 1. backend_authentication_readiness -----------------------------------------------------
    proof_id: uuid.UUID | None = None
    reason_token = str(self_test_reason_code or "")
    if reason_token and not _SAFE_TOKEN_RE.fullmatch(reason_token):
        # The self-test tried to return a free-form / structured detail (a URL, a path, a token, a
        # response body, a stack trace). Refuse rather than persist it.
        add(
            _F.backend_authentication_readiness,
            _S.failed,
            _R.resolver_self_test_leaked_details,
        )
    elif self_test_ok:
        # The self-test's proof id must be an OPAQUE UUID. A shape-bounded label could itself BE a
        # backend locator (a Vault mount, a hostname), and a digest of that label would be an
        # offline confirmation oracle for it — so neither is accepted.
        proof_id = (
            self_test_proof_id if is_opaque_proof_id(self_test_proof_id) else None  # type: ignore[assignment]
        )
        if proof_id is None:
            # A self-test that reports success but yields no opaque proof id gives nothing durable
            # to record. Fail closed rather than fabricate an unproven pass.
            add(
                _F.backend_authentication_readiness,
                _S.unverifiable,
                _R.resolver_self_test_unavailable,
            )
        else:
            add(_F.backend_authentication_readiness, _S.passed)
    else:
        add(
            _F.backend_authentication_readiness,
            _S.unverifiable,
            _R.resolver_self_test_failed,
        )

    # --- 2. jit_injection_contract ----------------------------------------------------------------
    if jit_env_ok:
        add(_F.jit_injection_contract, _S.passed)
    else:
        add(_F.jit_injection_contract, _S.failed, jit_reason or _R.jit_env_contract_violation)

    statuses = {f.status for f in facets}
    if _S.failed.value in statuses:
        outcome = PlanSecretReadinessOutcome.not_ready
    elif _S.unverifiable.value in statuses:
        outcome = PlanSecretReadinessOutcome.unavailable
    else:
        outcome = PlanSecretReadinessOutcome.ready

    return PlanSecretEvaluation(
        outcome=outcome.value,
        facets=tuple(facets),
        reason_codes=tuple(dict.fromkeys(reasons))[:MAX_EVIDENCE_REASONS],
        secret_purpose=secret_purpose,
        self_test_proof_id=proof_id,
    )
