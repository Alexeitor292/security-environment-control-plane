"""The worker-only, non-serializable plan-only capability (B1B-PR5A, ADR-022 §4).

A ``PlanOnlyCapability`` is the token an approved, fully-gated real-plan-generation operation would
carry into PR5B's plan-only executor. It is:

* worker-only and **non-serializable** (cannot be pickled, ``repr``-ed with content, placed in a
  Temporal argument, persisted, or constructed by API code);
* operation-specific, dossier-bound, authorization-bound, manifest-bound, worker-bound, and
expiring;
* impossible to use for apply/destroy (the plan-only executor's grammar admits no such tokens, §4).

In PR5A the capability is **never issued in a shipped path**: the plan-only process seal
(``_PLAN_ONLY_PROCESS_SEALED``) refuses executor construction first, so the operation STOPS before a
capability is minted. The class exists so PR5B is a small reviewed change and so the
non-serializable
property is testable.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn, SupportsIndex

# Module-private construction token. A capability cannot be built without it.
_PLAN_ONLY_CAPABILITY_TOKEN = object()


class PlanOnlyCapabilityRefused(Exception):
    """The authoritative gate does not authorize a plan-only capability for this operation."""


@dataclass(frozen=True)
class PlanOnlyActivation:
    """The reviewed, authoritative binding a plan-only capability pins (opaque ids + hashes
    only)."""

    plan_generation_authorization_id: uuid.UUID
    authorization_version: int
    activation_dossier_id: uuid.UUID
    activation_dossier_hash: str
    provisioning_manifest_id: uuid.UUID
    provisioning_manifest_content_hash: str
    execution_target_id: uuid.UUID
    worker_identity_registration_id: uuid.UUID
    worker_identity_version: int
    plan_only_capability_contract_version: str
    operation_fingerprint: str
    expires_at: datetime


class PlanOnlyCapability:
    """A worker-only, non-serializable proof that a plan-only operation was fully authorized."""

    __slots__ = ("__data",)

    def __init__(self, token: object, activation: PlanOnlyActivation) -> None:
        if token is not _PLAN_ONLY_CAPABILITY_TOKEN:
            raise TypeError(
                "PlanOnlyCapability cannot be constructed directly; it is issued only after "
                "authoritative gate verification inside the worker"
            )
        object.__setattr__(self, "_PlanOnlyCapability__data", activation)

    @property
    def activation(self) -> PlanOnlyActivation:
        return object.__getattribute__(self, "_PlanOnlyCapability__data")  # type: ignore[no-any-return]

    def __repr__(self) -> str:
        return "PlanOnlyCapability(<redacted>)"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return self.__repr__()

    def __getstate__(self) -> NoReturn:
        raise TypeError("PlanOnlyCapability cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("PlanOnlyCapability cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("PlanOnlyCapability cannot be pickled")


def issue_plan_only_capability(
    activation: PlanOnlyActivation, *, now: datetime
) -> PlanOnlyCapability:
    """Issue a plan-only capability after the authoritative gate (used only by a reviewed PR5B
    path).

    A fake/injected generic executor can never satisfy this: the capability is minted only here,
    from
    an authoritative activation, and the plan-only executor requires it. It refuses an expired
    activation or a contract-version drift.
    """
    from secp_api.plan_activation_contract import PLAN_ONLY_CAPABILITY_CONTRACT_VERSION
    from secp_api.readiness_contract import as_utc

    if as_utc(activation.expires_at) <= now:
        raise PlanOnlyCapabilityRefused("plan-only activation expired")
    if activation.plan_only_capability_contract_version != PLAN_ONLY_CAPABILITY_CONTRACT_VERSION:
        raise PlanOnlyCapabilityRefused("plan-only capability contract mismatch")
    return PlanOnlyCapability(_PLAN_ONLY_CAPABILITY_TOKEN, activation)
