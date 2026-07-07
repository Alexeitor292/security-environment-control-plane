"""Worker-side discovery admission client seam (SECP-B6 MB-1).

The worker proves possession of its deployment-local Ed25519 identity key to the CONTROL-PLANE
admission verifier before any host contact. This module holds ONLY the seam + a signing client; the
identity DECISION is made by :mod:`secp_api.services.worker_admission` (the verifier issues the
single-use nonce and checks the signature against the registered anchor — never a self-asserted
key).

The shipped default is :class:`SealedWorkerAdmissionClient`, which refuses and performs no signing.
A real client is constructed only on the isolated worker from deployment-local key material. In a
deployed topology the worker and control plane are separate processes and the client talks to the
internal admission route over mutual TLS; the in-process signing client is the co-located / test
realization of the SAME control-plane-verified handshake. This module imports no SSH/Proxmox/
mutation/transport code and holds no private key beyond the deployment-local signer.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol, runtime_checkable

from sqlalchemy.orm import Session


class WorkerAdmissionUnavailable(Exception):
    """Fail-closed: no valid control-plane admission could be obtained. Closed reason code only."""

    def __init__(self, reason_code: str = "worker_admission_unavailable") -> None:
        super().__init__(f"worker discovery admission unavailable: {reason_code}")
        self.reason_code = reason_code


@runtime_checkable
class WorkerAdmissionClient(Protocol):
    """Obtains a control-plane-verified, one-time admission id for a discovery job, or fails."""

    def admit(
        self,
        session: Session,
        *,
        discovery_job_id: uuid.UUID,
        authorization_id: uuid.UUID,
        authorization_version: int,
        endpoint_binding_hash: str,
        now: datetime,
    ) -> uuid.UUID: ...


class SealedWorkerAdmissionClient:
    """Shipped default: refuses. No key material, no signing, no admission is ever obtained."""

    def admit(
        self,
        session: Session,
        *,
        discovery_job_id: uuid.UUID,
        authorization_id: uuid.UUID,
        authorization_version: int,
        endpoint_binding_hash: str,
        now: datetime,
    ) -> uuid.UUID:
        raise WorkerAdmissionUnavailable("no worker admission client is configured")


class SignedWorkerAdmissionClient:
    """Performs the control-plane-verified handshake with a deployment-local Ed25519 signer.

    Constructed ONLY on the isolated worker from its deployment-local identity key material. It
    signs the verifier-issued nonce; the control-plane admission service verifies the signature
    against the registered anchor and marks the durable admission ``admitted``. The client never
    verifies its own proof (that would be a self-check) and never persists/logs the private key.
    """

    def __init__(self, *, private_key_hex: str, public_anchor_hex: str) -> None:
        self._private_key_hex = private_key_hex
        self._public_anchor_hex = public_anchor_hex

    def __repr__(self) -> str:  # never expose the private key
        return "SignedWorkerAdmissionClient(<redacted>)"

    def admit(
        self,
        session: Session,
        *,
        discovery_job_id: uuid.UUID,
        authorization_id: uuid.UUID,
        authorization_version: int,
        endpoint_binding_hash: str,
        now: datetime,
    ) -> uuid.UUID:
        # The verification DECISION lives in the control-plane service; the client only signs.
        from secp_api.services import worker_admission as adm
        from secp_api.worker_admission_contract import admission_signing_message, ed25519_sign

        try:
            admission = adm.issue_discovery_admission_challenge(
                session,
                discovery_job_id=discovery_job_id,
                authorization_id=authorization_id,
                authorization_version=authorization_version,
                endpoint_binding_hash=endpoint_binding_hash,
                now=now,
            )
            message = admission_signing_message(
                nonce=admission.nonce,
                organization_id=str(admission.organization_id),
                discovery_job_id=str(admission.discovery_job_id),
                worker_registration_id=str(admission.worker_registration_id),
                identity_version=admission.identity_version,
                endpoint_binding_hash=admission.endpoint_binding_hash,
                expires_at=admission.expires_at,
            )
            signature = ed25519_sign(private_key_hex=self._private_key_hex, message=message)
            adm.complete_discovery_admission(
                session,
                admission_id=admission.id,
                presented_anchor=self._public_anchor_hex,
                signature=signature,
                now=now,
            )
            return admission.id
        except adm.WorkerAdmissionRefused as exc:
            raise WorkerAdmissionUnavailable(exc.reason_code) from None
