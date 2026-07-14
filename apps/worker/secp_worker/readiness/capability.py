"""Controlled-live readiness ADAPTER PROVENANCE capability (B1B-PR4 amendment §3).

A self-declared ``contract_version`` is **not** provenance: any object can claim any string. This
module is the only place a readiness adapter or a secret-backend self-test can be *authorized*, and
it authorizes them against a **reviewed deployment-local activation record** — never against
anything the adapter says about itself.

**The capability is worker-only and non-forgeable in practice.**

* Construction requires a module-private token, so no caller outside this module can build one.
* The only public factory (:func:`issue_readiness_adapter_capability`) verifies the activation
  against the AUTHORITATIVE readiness binding before issuing.
* It cannot be serialized, pickled, ``repr``-ed with content, placed in a Temporal argument,
  persisted, or constructed by API code (the architecture boundary forbids the import).
* The shipped composition carries **no activation**, so no capability exists and both seams refuse
  **before any contact**.

**Test-only escape hatch.** :func:`issue_test_only_capability` is explicitly named and produces a
capability whose ``capability_class`` is ``test_only``. Evidence produced under it is permanently
marked ``test_only`` and can **never** make combined provisioning readiness current — a fake adapter
that claims the exact expected contract version and returns all-pass evidence still cannot produce
controlled-live evidence.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import NoReturn, SupportsIndex

from secp_api.enums import ReadinessCapabilityClass, ReadinessOperationKind
from secp_api.readiness_contract import ReadinessBinding, as_utc, is_placeholder_dossier

# Module-private construction token. A capability cannot be built without it, and it never leaves
# this module.
_CAPABILITY_TOKEN = object()


class AdapterCapabilityRefused(Exception):
    """The reviewed activation does not authorize this adapter for this operation. Fail closed."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"readiness adapter capability refused: {reason_code}")
        self.reason_code = reason_code


def implementation_identity(adapter: object) -> str:
    """The reviewed IMPLEMENTATION identity of an injected adapter object.

    A stable digest of the concrete class's module + qualified name. The deployment-local activation
    record pins the exact expected value, so a *different* implementation — even one that claims the
    right ``contract_version`` and returns all-pass evidence — cannot obtain a capability.

    (This is provenance, not a proof of behaviour: see the truthful limitation in ADR-021 §E.)
    """
    klass = type(adapter)
    return (
        "sha256:" + hashlib.sha256(f"{klass.__module__}.{klass.__qualname__}".encode()).hexdigest()
    )


@dataclass(frozen=True)
class AdapterActivation:
    """The REVIEWED, deployment-local activation record for ONE readiness adapter.

    It is supplied out of band by the reviewed worker composition — never by an environment
    variable,
    a URL, the database, the API, or the adapter itself. It carries no secret, no endpoint, and no
    backend locator: only opaque registration identity, the reviewed implementation digest, the
    contract version it authorizes, the dossier hash, and the authorization/expiry envelope.
    """

    adapter_registration_id: uuid.UUID
    adapter_kind: str
    # The reviewed implementation digest — compare against :func:`implementation_identity`.
    implementation_identity: str
    adapter_contract_version: str
    operation_kind: str
    activation_dossier_hash: str
    authorization_id: uuid.UUID
    authorization_version: int
    authorization_expiry: datetime
    organization_id: uuid.UUID
    execution_target_id: uuid.UUID
    target_onboarding_id: uuid.UUID
    provisioning_manifest_id: uuid.UUID
    deployment_plan_id: uuid.UUID
    worker_identity_registration_id: uuid.UUID
    worker_identity_version: int
    expires_at: datetime


class ReadinessAdapterCapability:
    """A worker-only, non-serializable proof that an adapter was authorized by a reviewed
    activation.

    It can only be created by this module's verified factories.
    """

    __slots__ = ("__data",)

    def __init__(self, token: object, data: AdapterActivation, capability_class: str) -> None:
        if token is not _CAPABILITY_TOKEN:
            raise TypeError(
                "ReadinessAdapterCapability cannot be constructed directly; it is issued only "
                "after authoritative activation verification inside the worker"
            )
        object.__setattr__(self, "_ReadinessAdapterCapability__data", (data, capability_class))

    # --- accessors ---------------------------------------------------------------------------
    def _payload(self) -> tuple[AdapterActivation, str]:
        return object.__getattribute__(  # type: ignore[no-any-return]
            self, "_ReadinessAdapterCapability__data"
        )

    @property
    def activation(self) -> AdapterActivation:
        return self._payload()[0]

    @property
    def capability_class(self) -> str:
        return self._payload()[1]

    @property
    def controlled_live(self) -> bool:
        return self.capability_class == ReadinessCapabilityClass.controlled_live.value

    @property
    def adapter_registration_id(self) -> uuid.UUID:
        return self.activation.adapter_registration_id

    @property
    def activation_dossier_hash(self) -> str:
        return self.activation.activation_dossier_hash

    @property
    def operation_kind(self) -> str:
        return self.activation.operation_kind

    # --- non-serializable, redacted ------------------------------------------------------------
    def __repr__(self) -> str:
        return f"ReadinessAdapterCapability(class={self.capability_class!r}, <redacted>)"

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return self.__repr__()

    def __getstate__(self) -> NoReturn:
        raise TypeError("ReadinessAdapterCapability cannot be serialized")

    def __reduce__(self) -> NoReturn:
        raise TypeError("ReadinessAdapterCapability cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        raise TypeError("ReadinessAdapterCapability cannot be pickled")


def _verify(
    activation: AdapterActivation,
    binding: ReadinessBinding,
    adapter: object,
    operation_kind: ReadinessOperationKind,
    now: datetime,
) -> None:
    """Authoritative activation verification. Every failure is fail-closed and secret-free."""
    if activation.operation_kind != operation_kind.value:
        raise AdapterCapabilityRefused("adapter_capability_invalid")
    # The reviewed activation must pin a REAL dossier: the placeholder can never authorize anything.
    if is_placeholder_dossier(activation.activation_dossier_hash):
        raise AdapterCapabilityRefused("activation_dossier_placeholder")
    if as_utc(activation.expires_at) <= now:
        raise AdapterCapabilityRefused("adapter_capability_invalid")
    if as_utc(activation.authorization_expiry) <= now:
        raise AdapterCapabilityRefused("adapter_capability_invalid")
    # The reviewed IMPLEMENTATION must be the one actually injected — not merely one that claims the
    # right contract version.
    if activation.implementation_identity != implementation_identity(adapter):
        raise AdapterCapabilityRefused("adapter_capability_invalid")
    # ... and the adapter's own self-declared version must ALSO agree (defence in depth; it is never
    # sufficient on its own).
    declared = str(getattr(adapter, "contract_version", "") or "")
    if declared and declared != activation.adapter_contract_version:
        raise AdapterCapabilityRefused("adapter_contract_mismatch")
    if activation.adapter_contract_version != binding.adapter_contract_version:
        raise AdapterCapabilityRefused("adapter_contract_mismatch")
    # The activation must be bound to EXACTLY this operation's authoritative world.
    for actual, expected in (
        (str(activation.organization_id), binding.organization_id),
        (str(activation.execution_target_id), binding.execution_target_id),
        (str(activation.target_onboarding_id), binding.target_onboarding_id),
        (str(activation.provisioning_manifest_id), binding.provisioning_manifest_id),
        (str(activation.deployment_plan_id), binding.deployment_plan_id),
        (
            str(activation.worker_identity_registration_id),
            binding.worker_identity_registration_id,
        ),
    ):
        if actual != expected:
            raise AdapterCapabilityRefused("adapter_capability_invalid")
    if activation.worker_identity_version != binding.worker_identity_version:
        raise AdapterCapabilityRefused("adapter_capability_invalid")


def issue_readiness_adapter_capability(
    *,
    activation: AdapterActivation,
    binding: ReadinessBinding,
    adapter: object,
    operation_kind: ReadinessOperationKind,
    now: datetime,
) -> ReadinessAdapterCapability:
    """Issue a CONTROLLED-LIVE capability after authoritative activation verification.

    An adapter's self-reported ``contract_version`` alone can NEVER create this: the reviewed
    activation must pin the exact implementation digest, a non-placeholder dossier, and the exact
    organization / target / onboarding / manifest / plan / worker-identity of this operation.
    """
    _verify(activation, binding, adapter, operation_kind, now)
    return ReadinessAdapterCapability(
        _CAPABILITY_TOKEN, activation, ReadinessCapabilityClass.controlled_live.value
    )


def issue_test_only_capability(
    *,
    activation: AdapterActivation,
    binding: ReadinessBinding,
    adapter: object,
    operation_kind: ReadinessOperationKind,
    now: datetime,
) -> ReadinessAdapterCapability:
    """The EXPLICITLY NAMED test-only factory.

    It runs the same authoritative verification, but the capability it issues is permanently marked
    ``test_only``. Evidence recorded under it is marked ``test_only`` and can NEVER satisfy a
    controlled-live gate: ``ProvisioningReadinessStatus`` refuses it.
    """
    _verify(activation, binding, adapter, operation_kind, now)
    return ReadinessAdapterCapability(
        _CAPABILITY_TOKEN, activation, ReadinessCapabilityClass.test_only.value
    )
