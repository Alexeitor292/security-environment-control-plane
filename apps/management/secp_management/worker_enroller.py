"""Concrete worker enroller adapter for secpctl (SECP-PR5H-B1 Phase 4; production leaves in WS-B).

Bridges the secpctl ``worker`` commands to the delivered ``secp_worker`` enrollment driver: it maps
the validated non-secret invitation dict to the driver's ``EnrollmentInvitationInputs`` and drives
enroll / retry, and reports read-only local restart state for status. The worker exchange
authenticates by proof-of-possession + the signed controller offer — it uses NO operator OIDC token
and reaches no provider/operator/OpenTofu/controlled-live capability.

WHY THE DRIVER IS BUILT PER INVITATION
--------------------------------------
Two of the driver's collaborators are pinned to ONE invitation and cannot be shared across
enrollments:

* the transport carries the controller origin + CA chain, which now travel IN the invitation;
* :class:`~secp_worker.enrollment_health_probes.LocalWorkerHealthProbes` holds the invitation at
  construction ON PURPOSE, so a context describing another exchange can never satisfy a check.

A driver built once and reused would therefore either pin the FIRST invitation's origin/CA for every
later enrollment, or force the probes to read the invitation from the context they are validating —
which is precisely the property the probes exist to deny. So this adapter composes a fresh driver
per ``enroll()``. Only the durable restart-state store is long-lived, because ``status()`` must read
it without driving anything.

The ``secp_worker`` RUNTIME import stays lazy so the management CLI need not load the worker package
unless a worker command actually runs. The TYPE-ONLY imports below are guarded by ``TYPE_CHECKING``,
so they cost nothing at runtime while still giving the composition real types: passing the wrong
backend into the protected key seam, or the wrong object as the state store, is now a type error
rather than something ``object`` would wave through.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:  # type-only: never imported at runtime, so the lazy-import property is preserved
    from secp_commissioning.runtime import FilesystemBackend
    from secp_worker.enrollment_driver import (
        WorkerEnrollmentDriver,
        WorkerEnrollmentStateStore,
    )
    from secp_worker.enrollment_http_transport import EnrollmentInvitationInputs


class _DriverFactory(Protocol):
    """Builds a driver for ONE invitation. Production uses the real per-invitation composition;
    tests inject a double. Named so the injected callable is checked rather than untyped."""

    def __call__(self, inputs: EnrollmentInvitationInputs) -> WorkerEnrollmentDriver: ...


class DriverWorkerEnroller:
    """Adapts the ``secp_worker`` enrollment driver to the secpctl ``WorkerEnroller`` protocol.

    Holds the hardened filesystem seam and the durable restart-state store; builds the driver itself
    per enrollment (see the module docstring)."""

    __slots__ = ("_fs", "_state_store", "_driver_factory")

    def __init__(
        self,
        *,
        fs: FilesystemBackend,
        state_store: WorkerEnrollmentStateStore,
        driver_factory: _DriverFactory | None = None,
    ) -> None:
        self._fs = fs
        self._state_store = state_store
        # injectable purely so tests can compose a driver over doubles; production passes None and
        # gets the real per-invitation composition below
        self._driver_factory = driver_factory or self._build_driver

    def enroll(self, invitation: dict, *, now: str) -> dict:
        inputs = self._inputs(invitation)
        outcome = self._driver_factory(inputs).enroll(inputs, now=now)
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
        # read-only: report the local restart-state marker; never drive or contact the controller.
        # ``load`` is part of the WorkerEnrollmentStateStore protocol, so this no longer needs an
        # attr-defined ignore — the protocol expresses the invariant the ignore used to hide.
        enrollment_id = invitation["enrollment_id"]
        step = self._state_store.load(enrollment_id)
        return {"enrollment_id": enrollment_id, "state": step or "unknown"}

    def _build_driver(self, inputs: EnrollmentInvitationInputs) -> WorkerEnrollmentDriver:
        """Compose the production driver over the real host-local leaves, pinned to THIS invitation.

        Reaching here already means the operator passed ``--write --confirm`` (``worker_enroll``
        only calls ``enroll`` on the write path), which is the authority the key seam requires to
        CREATE a key that does not exist yet. With a key already provisioned the seam is a pure
        read."""
        from secp_worker.enrollment_driver import (
            LocalWorkerHealthObserver,
        )
        from secp_worker.enrollment_driver import (
            WorkerEnrollmentDriver as _Driver,
        )
        from secp_worker.enrollment_health_probes import LocalWorkerHealthProbes
        from secp_worker.enrollment_http_transport import build_invitation_transport
        from secp_worker.enrollment_key import LocalWorkerEnrollmentKeySeam

        return _Driver(
            key_seam=LocalWorkerEnrollmentKeySeam(self._fs, write=True, confirm=True),
            # per-invitation: the origin + CA chain are the validated invitation's own
            transport_factory=build_invitation_transport,
            state_store=self._state_store,
            health_observer=LocalWorkerHealthObserver(
                LocalWorkerHealthProbes(
                    invitation=inputs, fs=self._fs, state_store=self._state_store
                )
            ),
        )

    @staticmethod
    def _inputs(invitation: dict) -> EnrollmentInvitationInputs:
        from secp_worker.enrollment_http_transport import (
            EnrollmentInvitationInputs as _Inputs,
        )

        # NOTE the one deliberate rename: the API/invitation-file name is `transaction_id`, the
        # worker-side name is `controller_transaction_id`. This adapter is the ONLY correct place
        # for that translation — the invitation file must keep the API's own field name, and the
        # worker type must keep the name that says WHOSE transaction it is.
        return _Inputs(
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


def build_worker_enroller(fs: FilesystemBackend | None = None) -> DriverWorkerEnroller:
    """Compose the concrete worker enroller over the REAL host-local leaves.

    The three leaves delivered by WS-B (the fixed-path protected key seam, the durable restart-state
    store, and the derived health probes) are composed here with the per-invitation transport, so
    the supported worker enrollment path is functional on a correctly bootstrapped worker host
    rather than inert.

    It still fails CLOSED everywhere it should: an unbootstrapped host has no management worker
    records, so the derived health probes observe ``False`` and the driver refuses locally before
    signing anything; a host with no key and no write authority refuses
    ``enrollment_worker_key_absent``; and an unreachable controller refuses a bounded transport
    code. ``fs`` is injectable so tests compose over an in-memory hardened filesystem; production
    passes nothing and gets the real one."""
    from secp_commissioning.runtime import RealFilesystem
    from secp_worker.enrollment_state_store import DurableWorkerEnrollmentStateStore

    backend: FilesystemBackend = fs if fs is not None else RealFilesystem()
    return DriverWorkerEnroller(fs=backend, state_store=DurableWorkerEnrollmentStateStore(backend))


__all__ = ["DriverWorkerEnroller", "build_worker_enroller"]
