"""Closed, typed controller-enrollment FINALIZATION plan + sealed adapter (SECP-PR5H-B2, 2b-3).

After the controller stack is bootstrapped, the root installation FINALIZES the enrollment surface:
it produces the controller-API TLS material, records the fixed-CA locator, provisions the dedicated
least-privilege signer database role, prepares the 0600 controller enrollment key, installs the
root-gated signer broker unit, enables the non-root API signer client, and — LAST — activates the
verified controller identity. These effects are driven through a CLOSED, typed adapter with the SAME
discipline as the bootstrap adapter: every op consumes an exact typed input (no generic
path/command/SQL verb), the adapter accumulates a :class:`ControllerFinalizationReceipt` of only the
objects it created, and a closed ``compensate(receipt)`` removes exactly those in reverse order
(returning a :class:`~secp_management.adapters.CompensationResult` whose residual forces
``recovery_required``).

Secrets are NEVER carried in the plan: the plan holds only reviewed, non-secret descriptors (the
signed TLS policy, the canonical public origin + mode, the fixed role/credential/enablement paths,
and the reviewed bootstrap-fact digests). The real adapter generates the TLS key, the SCRAM secret,
and the enrollment key at write time and writes them to their fixed root-owned paths. The verified
identity's public key material is derived from the prepared enrollment key (returned by
``prepare_enrollment_key``) and combined with the reviewed facts to build the activation LAST.

The SHIPPED default is SEALED: every finalization op fails closed with
``controller_finalization_adapter_not_provisioned``, so finalization refuses (no false success)
until
a reviewed real adapter is composed in ``production.py``. This module performs no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from secp_management import ManagementError
from secp_management.adapters import CompensationResult, ReviewedUnit

if TYPE_CHECKING:
    from secp_management.release_bundle import ControllerTlsPolicy


# --------------------------------------------------------------------- typed finalization inputs


@dataclass(frozen=True)
class EnrollmentKeyIdentity:
    """The PUBLIC identity derived from the prepared 0600 controller enrollment key: the ``sha256:``
    key id, the raw 64-hex Ed25519 public key (the trust anchor), and the ``enrkp:`` proof id. No
    private material — these are exactly the public values ``prepare_controller_enrollment_key``
    returns and the ones the activated identity binds."""

    controller_key_id: str
    controller_trust_anchor_hex: str
    enrollment_key_proof_id: str


@dataclass(frozen=True)
class ReviewedSignerRole:
    """A non-secret descriptor of the dedicated least-privilege signer DB role: the fixed role name
    and the fixed root-owned path the SCRAM secret is written to. The adapter GENERATES the secret +
    verifier at write time — the plan never carries a credential."""

    role_name: str
    credential_source_path: str


@dataclass(frozen=True)
class ReviewedApiSigner:
    """A non-secret descriptor for enabling the non-root API signer client: the fixed root-owned
    path the installer writes to flip ``enrollment_signer_enabled`` on. No socket/key override."""

    enablement_path: str


@dataclass(frozen=True)
class ControllerIdentityActivation:
    """The closed activation token — the exact eight fields of the API's
    ``VerifiedControllerIdentity``
    — built LAST from the prepared enrollment key's public identity + the reviewed bootstrap facts.
    The management adapter hands these to the API activation one-shot (never importing the API)."""

    controller_installation_id: str
    controller_key_id: str
    controller_trust_anchor_hex: str
    controller_origin: str
    release_digest: str
    management_identity_digest: str
    bootstrap_evidence_digest: str
    enrollment_key_proof_id: str


@dataclass(frozen=True)
class ControllerEnrollmentFinalizationPlan:
    """The exact typed finalization plan, derived by the engine from the verified release (signed
    TLS policy + fact digests) and validated install options (origin + mode). Non-secret only."""

    role: str
    tls_policy: ControllerTlsPolicy
    canonical_origin: str
    tls_mode: str
    signer_role: ReviewedSignerRole
    api_signer: ReviewedApiSigner
    broker_unit: ReviewedUnit
    controller_installation_id: str
    release_digest: str
    management_identity_digest: str
    bootstrap_evidence_digest: str


# --------------------------------------------------------------------- receipt + protocol


@dataclass(frozen=True)
class ControllerFinalizationReceipt:
    """A record of ONLY the finalization objects the adapter actually created/changed, so it can
    compensate exactly those and nothing else. All default empty (empty PROVES no effect)."""

    installed_tls: tuple[str, ...] = ()
    recorded_locators: tuple[str, ...] = ()
    provisioned_roles: tuple[str, ...] = ()
    prepared_keys: tuple[str, ...] = ()
    installed_broker_units: tuple[str, ...] = ()
    enabled_signers: tuple[str, ...] = ()
    activated_identities: tuple[str, ...] = ()


class ControllerEnrollmentFinalizationAdapter(Protocol):
    """The closed finalization seam. Ops run in reviewed order, ACTIVATION LAST.
    ``prepare_enrollment_key``
    returns the derived public identity the engine folds into the activation token."""

    def install_tls_material(
        self, *, policy: ControllerTlsPolicy, canonical_origin: str, tls_mode: str
    ) -> None: ...
    def record_locator(self, *, canonical_origin: str) -> None: ...
    def provision_signer_role(self, role: ReviewedSignerRole) -> None: ...
    def prepare_enrollment_key(self) -> EnrollmentKeyIdentity: ...
    def install_broker_unit(self, unit: ReviewedUnit) -> None: ...
    def enable_api_signer(self, signer: ReviewedApiSigner) -> None: ...
    def activate_controller_identity(self, activation: ControllerIdentityActivation) -> None: ...
    def receipt(self) -> ControllerFinalizationReceipt: ...
    def compensate(self, receipt: ControllerFinalizationReceipt) -> CompensationResult: ...


_SEALED = "controller_finalization_adapter_not_provisioned"


class SealedControllerEnrollmentFinalizationAdapter:
    """Shipped default: no reviewed finalization adapter is installed — every op fails closed, so a
    controller finalization refuses (no false success) until a real adapter is composed."""

    def install_tls_material(
        self, *, policy: ControllerTlsPolicy, canonical_origin: str, tls_mode: str
    ) -> None:
        raise ManagementError(_SEALED)

    def record_locator(self, *, canonical_origin: str) -> None:
        raise ManagementError(_SEALED)

    def provision_signer_role(self, role: ReviewedSignerRole) -> None:
        raise ManagementError(_SEALED)

    def prepare_enrollment_key(self) -> EnrollmentKeyIdentity:
        raise ManagementError(_SEALED)

    def install_broker_unit(self, unit: ReviewedUnit) -> None:
        raise ManagementError(_SEALED)

    def enable_api_signer(self, signer: ReviewedApiSigner) -> None:
        raise ManagementError(_SEALED)

    def activate_controller_identity(self, activation: ControllerIdentityActivation) -> None:
        raise ManagementError(_SEALED)

    def receipt(self) -> ControllerFinalizationReceipt:
        # every op raised before touching the host → an EMPTY receipt PROVES no effect occurred, so
        # the engine refuses with the original reason rather than a false recovery_required.
        return ControllerFinalizationReceipt()

    def compensate(self, receipt: ControllerFinalizationReceipt) -> CompensationResult:
        return CompensationResult(proven=True)


__all__ = [
    "ControllerEnrollmentFinalizationAdapter",
    "ControllerEnrollmentFinalizationPlan",
    "ControllerFinalizationReceipt",
    "ControllerIdentityActivation",
    "EnrollmentKeyIdentity",
    "ReviewedApiSigner",
    "ReviewedSignerRole",
    "SealedControllerEnrollmentFinalizationAdapter",
]
