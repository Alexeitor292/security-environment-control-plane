"""Closed, typed controller-enrollment FINALIZATION plan + sealed adapter (SECP-PR5H-B2, 2b-3).

After the controller stack is bootstrapped, the root installation FINALIZES the enrollment surface
through a CLOSED, typed adapter with the SAME discipline as the bootstrap adapter (exact typed
inputs;
a receipt of only what was created; a closed ``compensate(receipt)`` whose residual forces
``recovery_required``). The API plane stays SEALED throughout finalization until the enablement
marker
is written LAST.

Reviewed order (the API remains sealed for steps 1-9):

1. install + verify the controller-API TLS material;
2. record + verify the fixed-CA locator;
3. provision + verify the dedicated least-privilege signer DB role (via the API provisioning
   one-shot) and write the broker's SCRAM credential;
4. prepare + verify the 0600 controller enrollment key (returns its PUBLIC identity);
5. install + verify the fixed root-gated broker unit;
6. start the broker;
7. prove the signer path operational — dedicated-role authentication, advisory-lock lease, key/
   identity consistency, fixed UDS posture, exact API uid/gid peer policy;
8. **activate** the verified controller identity through the API activation one-shot — the FINAL
   database identity switch (PENULTIMATE runtime step);
9. write the root-owned API signer-enablement MARKER **last** — the FINAL product-runtime enablement
   switch — then restart the non-root API and prove it reads the marker and uses only the fixed UDS
   client.

Compensation runs in reverse and removes the MARKER FIRST (returning the API to sealed) before
restoring/removing the controller identity and the remaining receipt-owned artifacts.

Secrets are NEVER carried in the plan: it holds only reviewed, non-secret descriptors. The real
adapter generates the TLS key, the SCRAM secret, and the enrollment key at write time; the verified
identity's public key material is derived from the prepared enrollment key and combined with the
reviewed facts to build the activation. The management plane never imports secp_api — the API-plane
persistence invariants (activation, provisioning) run only through the fixed code-owned one-shots.

The SHIPPED default is SEALED: every finalization op fails closed with
``controller_finalization_adapter_not_provisioned``. This module performs no I/O.
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
    private material — exactly the public values ``prepare_controller_enrollment_key`` returns and
    the
    ones the activated identity binds."""

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
class ApiSignerMarker:
    """The bounded, non-secret enablement-marker binding written LAST. It is the SOLE positive
    production authority for the API signer client (no env / compose / DB / HTTP can enable it), and
    it binds the marker to the exact installation, release, active identity, broker unit, fixed UDS
    contract, and API peer pair — a mismatch on any field seals. No secret content."""

    marker_path: str
    installation_id: str
    release_digest: str
    active_identity_row_id: str
    activation_token: str
    controller_key_id: str
    broker_unit_identity: str
    uds_contract_identity: str
    api_uid: int
    api_gid: int
    signer_role_name: str
    locator_ca_digest: str
    management_identity_digest: str
    bootstrap_evidence_digest: str


@dataclass(frozen=True)
class ControllerIdentityActivation:
    """The closed activation token — the exact eight fields of the API's
    ``VerifiedControllerIdentity``
    — built from the prepared enrollment key's public identity + the reviewed bootstrap facts, plus
    the expected predecessor binding (``previous_active_row_id`` or ``None`` for a fresh install)
    and
    the operation id for idempotent replay. Handed to the API activation one-shot."""

    controller_installation_id: str
    controller_key_id: str
    controller_trust_anchor_hex: str
    controller_origin: str
    release_digest: str
    management_identity_digest: str
    bootstrap_evidence_digest: str
    enrollment_key_proof_id: str
    operation_id: str
    previous_active_row_id: str | None = None


@dataclass(frozen=True)
class ActivationReceipt:
    """The bounded, non-secret public receipt the API activation one-shot returns (never a private
    key, DSN, raw row, SQL, or exception). The installer validates it before writing the marker."""

    operation_id: str
    candidate_digest: str
    resulting_row_id: str
    activation_token: str
    previous_active_row_id: str | None
    created: bool  # True = created; False = exact-idempotent replay
    resulting_status: str
    resulting_public_state_digest: str


@dataclass(frozen=True)
class ControllerEnrollmentFinalizationPlan:
    """The exact typed finalization plan, derived by the engine from the verified release (signed
    TLS policy + fact digests) and validated install options (origin + mode). Non-secret only."""

    role: str
    tls_policy: ControllerTlsPolicy
    canonical_origin: str
    tls_mode: str
    signer_role: ReviewedSignerRole
    broker_unit: ReviewedUnit
    controller_installation_id: str
    release_digest: str
    management_identity_digest: str
    bootstrap_evidence_digest: str


# --------------------------------------------------------------------- receipt + protocol


@dataclass(frozen=True)
class ControllerFinalizationReceipt:
    """A record of ONLY the finalization objects the adapter actually created/changed, in reviewed
    order, so it can compensate exactly those in reverse (marker FIRST). All default empty (empty
    PROVES no effect)."""

    installed_tls: tuple[str, ...] = ()
    recorded_locators: tuple[str, ...] = ()
    provisioned_roles: tuple[str, ...] = ()
    written_credentials: tuple[str, ...] = ()
    prepared_keys: tuple[str, ...] = ()
    installed_broker_units: tuple[str, ...] = ()
    started_brokers: tuple[str, ...] = ()
    activated_identities: tuple[str, ...] = ()  # penultimate
    enabled_markers: tuple[str, ...] = ()  # LAST → compensated FIRST


class ControllerEnrollmentFinalizationAdapter(Protocol):
    """The closed finalization seam. Ops run in reviewed order: TLS → locator → signer role →
    enrollment key → broker unit → start broker → prove operational → ACTIVATE (penultimate) →
    enable MARKER (last). ``prepare_enrollment_key`` returns the derived public identity the engine
    folds into the activation; ``activate_controller_identity`` returns a bounded public receipt."""

    def install_tls_material(
        self, *, policy: ControllerTlsPolicy, canonical_origin: str, tls_mode: str
    ) -> None: ...
    def record_locator(self, *, canonical_origin: str) -> None: ...
    def provision_signer_role(self, role: ReviewedSignerRole) -> None: ...
    def prepare_enrollment_key(self) -> EnrollmentKeyIdentity: ...
    def install_broker_unit(self, unit: ReviewedUnit) -> None: ...
    def start_broker(self) -> None: ...
    def verify_signer_operational(self, *, key_identity: EnrollmentKeyIdentity) -> None: ...
    def activate_controller_identity(
        self, activation: ControllerIdentityActivation
    ) -> ActivationReceipt: ...
    def enable_api_signer(self, marker: ApiSignerMarker) -> None: ...  # LAST
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

    def start_broker(self) -> None:
        raise ManagementError(_SEALED)

    def verify_signer_operational(self, *, key_identity: EnrollmentKeyIdentity) -> None:
        raise ManagementError(_SEALED)

    def activate_controller_identity(
        self, activation: ControllerIdentityActivation
    ) -> ActivationReceipt:
        raise ManagementError(_SEALED)

    def enable_api_signer(self, marker: ApiSignerMarker) -> None:
        raise ManagementError(_SEALED)

    def receipt(self) -> ControllerFinalizationReceipt:
        # every op raised before touching the host → an EMPTY receipt PROVES no effect occurred, so
        # the engine refuses with the original reason rather than a false recovery_required.
        return ControllerFinalizationReceipt()

    def compensate(self, receipt: ControllerFinalizationReceipt) -> CompensationResult:
        return CompensationResult(proven=True)


__all__ = [
    "ActivationReceipt",
    "ApiSignerMarker",
    "ControllerEnrollmentFinalizationAdapter",
    "ControllerEnrollmentFinalizationPlan",
    "ControllerFinalizationReceipt",
    "ControllerIdentityActivation",
    "EnrollmentKeyIdentity",
    "ReviewedSignerRole",
    "SealedControllerEnrollmentFinalizationAdapter",
]
