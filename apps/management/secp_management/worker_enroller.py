"""Concrete worker enroller adapter for secpctl (SECP-PR5H-B1, Phase 4).

Bridges the secpctl ``worker`` commands to the delivered ``secp_worker`` enrollment driver: it maps
the validated non-secret invitation dict to the driver's ``EnrollmentInvitationInputs`` and drives
enroll / retry, and reports read-only local restart state for status. The worker exchange
authenticates by proof-of-possession + the signed controller offer — it uses NO operator OIDC token
and reaches no provider/operator/OpenTofu/controlled-live capability.

Shipped inert by default: the driver's transport and worker-key seam are SEALED until a reviewed
worker deployment profile wires them, so enroll/retry fail closed with a bounded driver reason code.
The ``secp_worker`` import is lazy so the management CLI need not load the worker package unless a
worker command actually runs.
"""

from __future__ import annotations


class DriverWorkerEnroller:
    """Adapts a ``secp_worker`` :class:`WorkerEnrollmentDriver` to the secpctl ``WorkerEnroller``
    protocol. Holds its own reference to the driver's restart-state store so ``status`` can report
    local progress without driving or contacting the controller."""

    __slots__ = ("_driver", "_state_store")

    def __init__(self, *, driver: object, state_store: object) -> None:
        self._driver = driver
        self._state_store = state_store

    def enroll(self, invitation: dict, *, now: str) -> dict:
        outcome = self._driver.enroll(self._inputs(invitation), now=now)  # type: ignore[attr-defined]
        return {
            "enrollment_id": outcome.enrollment_id,
            "state": outcome.state,
            "revision": outcome.revision,
            "already_healthy": outcome.already_healthy,
        }

    def retry(self, invitation: dict, *, now: str) -> dict:
        # the driver is resume-safe + idempotent; a retry is an identical re-drive
        return self.enroll(invitation, now=now)

    def status(self, invitation: dict) -> dict:
        # read-only: report the local restart-state marker; never drive or contact the controller
        enrollment_id = invitation["enrollment_id"]
        step = self._state_store.load(enrollment_id)  # type: ignore[attr-defined]
        return {"enrollment_id": enrollment_id, "state": step or "unknown"}

    @staticmethod
    def _inputs(invitation: dict):
        from secp_worker.enrollment_http_transport import EnrollmentInvitationInputs

        # NOTE the one deliberate rename: the API/invitation-file name is `transaction_id`, the
        # worker-side name is `controller_transaction_id`. This adapter is the ONLY correct place
        # for that translation — the invitation file must keep the API's own field name, and the
        # worker type must keep the name that says WHOSE transaction it is.
        return EnrollmentInvitationInputs(
            enrollment_id=invitation["enrollment_id"],
            invitation_id=invitation["invitation_id"],
            controller_installation_id=invitation["controller_installation_id"],
            controller_key_id=invitation["controller_key_id"],
            controller_origin=invitation["controller_origin"],
            controller_transaction_id=invitation["transaction_id"],
            release_digest=invitation["release_digest"],
            expires_at=invitation["expires_at"],
            controller_ca_bundle_pem=invitation["controller_ca_bundle_pem"],
        )


def build_worker_enroller() -> DriverWorkerEnroller:
    """Compose the concrete worker enroller over the delivered driver with its SEALED defaults (no
    transport, no worker key) — inert until a reviewed worker profile activates them. The
    ``secp_worker`` import is lazy."""
    from secp_worker.enrollment_driver import (
        InMemoryWorkerEnrollmentStateStore,
        WorkerEnrollmentDriver,
    )

    state_store = InMemoryWorkerEnrollmentStateStore()
    driver = WorkerEnrollmentDriver(state_store=state_store)
    return DriverWorkerEnroller(driver=driver, state_store=state_store)


__all__ = ["DriverWorkerEnroller", "build_worker_enroller"]
