"""The plan-secret secret-backend SELF-TEST seam (B1B-PR4 / ADR-021 §H).

The ONLY thing in the readiness path that may contact a secret manager. It proves exactly one thing:
**the worker can AUTHENTICATE to the configured secret backend.** It returns **no target
provisioning secret**, surfaces **no secret reference**, and its backend response body is **never
persisted**.

It reuses the reviewed B2-4
:class:`~secp_worker.preflight.backends.openbao_resolver.ResolverSelfTest` shape (``ok`` + a bounded
``reason_code``) and ADDS one field the reviewed shape lacks and readiness needs: an explicit,
opaque ``proof_id`` — a **UUID**.

**Why a distinct field.** ``ResolverSelfTestResult`` carries only ``ok`` and ``reason_code`` — a
*failure* category (the sealed default returns ``resolver_self_test_sealed``). Using that failure
reason as the durable *proof of success* would record the opposite of what happened, and a
conformant self-test that succeeds with an empty reason code could never reach ``ready``. A proof is
not a reason, so readiness asks for one explicitly.

The shipped default is :class:`SealedPlanSecretSelfTest`: it contacts nothing and never succeeds.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class PlanSecretSelfTestResult:
    """The bounded, secret-free result of one secret-backend authentication self-test.

    * ``ok`` — the worker authenticated.
    * ``reason_code`` — a bounded, opaque, lowercase token. It is validated against a closed shape;
      a free-form value (a URL, a vault path, a token, a stack trace, a response body) is REFUSED
      rather than persisted.
    * ``proof_id`` — an opaque proof **UUID** issued by the self-test (B1B-PR4 §5). It is
      deliberately NOT a shape-bounded label: that charset is exactly the alphabet of a Vault mount,
      a hostname, or a bucket name, so a label could BE a backend locator — and an unsalted digest
      of such a label is an offline confirmation oracle for it. A UUID can be neither. A self-test
      that reports success without one yields nothing durable, and readiness fails closed.

    There is deliberately NO field for a secret, a secret reference, a backend locator, a token, or
    a response body.
    """

    ok: bool
    reason_code: str = ""
    proof_id: uuid.UUID | None = None


@runtime_checkable
class PlanSecretSelfTest(Protocol):
    """Structurally compatible with the reviewed ``ResolverSelfTest`` (``run(*, now)``)."""

    def run(self, *, now: datetime) -> PlanSecretSelfTestResult:
        """Authenticate to the secret backend and return a bounded, secret-free result.

        It must NEVER return, log, or persist a target provisioning secret, a secret reference, a
        backend locator, a token, or a backend response body.
        """
        ...


class SealedPlanSecretSelfTest:
    """The SHIPPED DEFAULT. It contacts nothing and never succeeds.

    Unsealing is not a configuration flag: a reviewed deployment-local composition must inject a
    real self-test.
    """

    def run(self, *, now: datetime) -> PlanSecretSelfTestResult:
        return PlanSecretSelfTestResult(ok=False, reason_code="resolver_self_test_sealed")
