"""Concrete HTTP control-metadata probe for remote-state readiness (B1B-PR5B / ADR-021 §D, §E).

The concrete "HTTP" layer under :class:`~secp_worker.readiness.http_state_adapter.
HttpRemoteStateReadinessAdapter`, analogous to the OpenBao resolver/client split. All actual socket
work is INJECTED through an approved, bounded :class:`ApprovedStateBackendControlTransport`; this
probe owns the SAFETY ORCHESTRATION that makes the contact correct:

* it trusts the transport ONLY if it is an approved (nominal) transport — a loose duck-typed object
  cannot masquerade — and derives the transport-security posture from the transport's own
  attestation
  (never hardcoded);
* namespace occupancy is decided from METADATA/version identity only; the transport never reads a
  state body, and a value it cannot determine without one is reported as ``None`` (→ unverifiable);
* the ephemeral lock probe is bounded and idempotent, holds exactly ONE readiness lock, and ALWAYS
  releases it in a ``finally`` — even under cancellation or a mapping error — so it can never leak a
  readiness lock; contention is proven by a self-contained ``probe_contention`` and force-unlock
  availability is reported honestly (both are refusal conditions);
* encryption / backup / restore are immutable EXTERNAL proofs bound to THIS operation's namespace,
  obtained from an injected :class:`ExternalStateProofSource`. This probe never invents a proof and
  never performs a backup or a restore against real state.

The shipped defaults (:class:`SealedStateBackendControlTransport`, :class:`SealedExternalStateProof
Source`) refuse, so nothing here contacts a network at construction or in tests. No backend URL,
bucket / object name, state key, token, or credential is present here or anywhere in the repository.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from secp_worker.readiness.http_state_adapter import StateControlObservation
from secp_worker.readiness.state_adapter import (
    LockCapabilityProof,
    RemoteStateReadinessBinding,
    StateProof,
)

CONCRETE_HTTP_STATE_PROBE_REGISTRATION = "secp-002b-1b-pr5b/http-state-control-probe/v1"


class StateProbeError(Exception):
    """Fail-closed probe error. Carries ONLY a closed reason code (never a value or response)."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(f"remote-state probe refused: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class TransportSecurityPosture:
    """The transport's attested transport-security posture (§D.2). Booleans only — no value."""

    tls_verified: bool = False
    certificate_validation_enabled: bool = False
    trusted_identity_policy: str = ""
    proxy_inheritance_enabled: bool = True
    redirect_observed: bool = True
    destination_stable: bool = False


@dataclass(frozen=True)
class ReadinessLockHandle:
    """An opaque handle for ONE acquired readiness lock. The transport correlates release by
    identity; ``caller_supplied_owner`` (a refusal condition) is surfaced so evaluation fails
    closed."""

    caller_supplied_owner: bool = False


class ApprovedStateBackendControlTransport(ABC):
    """Nominal marker base a REAL, approved control-metadata transport must subclass.

    A foreign object that merely exposes these methods structurally is NOT approved — approval is
    nominal so a loose duck-typed implementation cannot masquerade as a hardened transport. A real
    implementation (deployment-only) enforces HTTPS/TLS verification, no redirects, ``trust_env=
    False``, and a bounded timeout, and reads NO state body. Every method is bounded and idempotent.
    """

    @property
    def control_origin(self) -> str:
        """The canonical ``https://host:port`` origin this transport is bound to (``""`` if none).

        The probe requires it to equal the origin of the AUTHORITATIVE state-backend reference
        before
        any contact, so a transport pointing at a different backend is refused. The sealed default
        returns ``""`` (matches no reference)."""
        return ""

    @abstractmethod
    def security_posture(self, *, now: datetime) -> TransportSecurityPosture: ...

    @abstractmethod
    def namespace_occupied(self, *, now: datetime) -> bool | None: ...

    @abstractmethod
    def granted_actions(self, *, now: datetime) -> tuple[str, ...] | None: ...

    @abstractmethod
    def local_fallback_reachable(self, *, now: datetime) -> bool: ...

    @abstractmethod
    def force_unlock_available(self, *, now: datetime) -> bool: ...

    @abstractmethod
    def acquire_readiness_lock(self, *, now: datetime) -> ReadinessLockHandle | None: ...

    @abstractmethod
    def probe_contention(self, *, now: datetime) -> bool: ...

    @abstractmethod
    def release_readiness_lock(self, handle: ReadinessLockHandle, *, now: datetime) -> bool: ...


class SealedStateBackendControlTransport(ApprovedStateBackendControlTransport):
    """The shipped default transport: contacts nothing; refuses / fails closed on every method."""

    def security_posture(self, *, now: datetime) -> TransportSecurityPosture:
        return TransportSecurityPosture()

    def namespace_occupied(self, *, now: datetime) -> bool | None:
        return None

    def granted_actions(self, *, now: datetime) -> tuple[str, ...] | None:
        return None

    def local_fallback_reachable(self, *, now: datetime) -> bool:
        return False

    def force_unlock_available(self, *, now: datetime) -> bool:
        # Unknown → treat as available (a refusal condition): never assume force-unlock is absent.
        return True

    def acquire_readiness_lock(self, *, now: datetime) -> ReadinessLockHandle | None:
        raise StateProbeError("state_transport_sealed")

    def probe_contention(self, *, now: datetime) -> bool:
        return False

    def release_readiness_lock(self, handle: ReadinessLockHandle, *, now: datetime) -> bool:
        return False


@dataclass(frozen=True)
class ObservedProofs:
    """Immutable EXTERNAL proofs for one namespace. Each may be ``None`` (→ that facet fails)."""

    encryption: StateProof | None = None
    backup: StateProof | None = None
    restore: StateProof | None = None


@runtime_checkable
class ExternalStateProofSource(Protocol):
    """Injected source of immutable EXTERNAL encryption/backup/restore proofs bound to the
    operation's namespace. The shipped default returns none, so those facets fail closed."""

    def external_proofs(
        self, binding: RemoteStateReadinessBinding, *, now: datetime
    ) -> ObservedProofs: ...


class SealedExternalStateProofSource:
    """The shipped default: NO external proofs. Every proof-backed facet fails closed."""

    def external_proofs(
        self, binding: RemoteStateReadinessBinding, *, now: datetime
    ) -> ObservedProofs:
        return ObservedProofs()


class ConcreteHttpStateControlProbe:
    """A concrete ``RemoteStateControlProbe`` over an injected approved control-metadata transport.

    NOT a shipped default — supplied only to a reviewed deployment-local readiness composition. With
    the sealed transport it produces a fully fail-closed observation and contacts nothing. It never
    reads a state body, always releases the ephemeral lock in a ``finally``, and maps every backend
    failure to a closed, secret-free reason code.
    """

    IMPLEMENTATION_ID = CONCRETE_HTTP_STATE_PROBE_REGISTRATION

    def __init__(
        self,
        *,
        transport: ApprovedStateBackendControlTransport,
        proof_source: ExternalStateProofSource | None = None,
        lock_issuer: uuid.UUID | None = None,
    ) -> None:
        self._transport = transport
        self._proof_source: ExternalStateProofSource = (
            proof_source or SealedExternalStateProofSource()
        )
        self._lock_issuer = lock_issuer

    def observe(
        self, binding: RemoteStateReadinessBinding, *, now: datetime
    ) -> StateControlObservation:
        reasons: list[str] = []
        # 1. Approved transport ONLY — a foreign/loose object is refused before any contact,
        # yielding
        #    a fully fail-closed observation (transport_security fails, everything unverifiable).
        if not isinstance(self._transport, ApprovedStateBackendControlTransport):
            return StateControlObservation(reason_codes=("adapter_report_invalid",))

        # 2. AUTHORITATIVE BACKEND BINDING (ADR-022 §6) — the transport's control origin MUST equal
        #    the origin of the toolchain profile's ``state_backend.reference`` this readiness op is
        #    bound to. A transport pointing at a DIFFERENT backend (or a non-HTTPS reference) is
        #    refused HERE, before any contact — readiness can never validate backend A while the
        #    transport talks to backend B.
        from secp_worker.plan_gen.destination_binding import (
            DestinationBindingError,
            canonicalize_https,
        )

        try:
            _canon, ref_origin, _path = canonicalize_https(
                binding.state_backend_reference, allow_query=False, reason="state_reference"
            )
        except DestinationBindingError:
            return StateControlObservation(reason_codes=("state_backend_reference_drift",))
        if self._transport.control_origin != ref_origin:
            return StateControlObservation(reason_codes=("state_backend_reference_drift",))

        posture = self._safe_posture(now, reasons)
        namespace_present = self._safe_namespace(now, reasons)
        allowed_actions, scope_evidence = self._safe_scope(now, reasons)
        local_fallback = self._safe_local_fallback(now, reasons)
        locking = self._lock_probe(binding, now, reasons)
        proofs = self._safe_proofs(binding, now, reasons)

        return StateControlObservation(
            tls_verified=posture.tls_verified,
            certificate_validation_enabled=posture.certificate_validation_enabled,
            trusted_identity_policy=posture.trusted_identity_policy,
            proxy_inheritance_enabled=posture.proxy_inheritance_enabled,
            redirect_observed=posture.redirect_observed,
            destination_stable=posture.destination_stable,
            namespace_present=namespace_present,
            allowed_actions=allowed_actions,
            scope_evidence_available=scope_evidence,
            local_fallback_available=local_fallback,
            encryption=proofs.encryption,
            locking=locking,
            backup=proofs.backup,
            restore=proofs.restore,
            reason_codes=tuple(dict.fromkeys(reasons)),
        )

    # --- bounded steps; each maps any failure to a fail-closed value + a closed reason ------------

    def _safe_posture(self, now: datetime, reasons: list[str]) -> TransportSecurityPosture:
        try:
            posture = self._transport.security_posture(now=now)
        except Exception:  # noqa: BLE001 - never surface a raw backend error
            reasons.append("state_tls_disabled")
            return TransportSecurityPosture()
        if not isinstance(posture, TransportSecurityPosture):
            reasons.append("state_tls_disabled")
            return TransportSecurityPosture()
        return posture

    def _safe_namespace(self, now: datetime, reasons: list[str]) -> bool | None:
        try:
            present = self._transport.namespace_occupied(now=now)
        except Exception:  # noqa: BLE001
            reasons.append("state_namespace_unknown")
            return None
        return present if isinstance(present, bool) else None

    def _safe_scope(self, now: datetime, reasons: list[str]) -> tuple[tuple[str, ...], bool]:
        try:
            actions = self._transport.granted_actions(now=now)
        except Exception:  # noqa: BLE001
            reasons.append("state_least_privilege_unproven")
            return (), False
        if not actions:
            return (), False
        return tuple(str(a).strip().lower() for a in actions), True

    def _safe_local_fallback(self, now: datetime, reasons: list[str]) -> bool:
        try:
            # Unknown/error → treat as available (a refusal condition): never assume it is absent.
            return bool(self._transport.local_fallback_reachable(now=now))
        except Exception:  # noqa: BLE001
            reasons.append("state_local_fallback_available")
            return True

    def _lock_probe(
        self, binding: RemoteStateReadinessBinding, now: datetime, reasons: list[str]
    ) -> LockCapabilityProof | None:
        """Bounded, idempotent lock probe: acquire ONE readiness lock, prove contention, ALWAYS
        release it in a ``finally``. Without a reviewed lock issuer the capability is unprovable."""
        if self._lock_issuer is None:
            reasons.append("state_lock_unavailable")
            return None

        handle: ReadinessLockHandle | None = None
        lock_capability = False
        contention_detected = False
        caller_supplied_owner = False
        probe_released = False
        try:
            handle = self._transport.acquire_readiness_lock(now=now)
            lock_capability = handle is not None
            if handle is not None:
                caller_supplied_owner = bool(handle.caller_supplied_owner)
                contention_detected = bool(self._transport.probe_contention(now=now))
        except Exception:  # noqa: BLE001 - the acquire/contention probe failed; report unprovable
            reasons.append("state_lock_unavailable")
            return None
        finally:
            if handle is not None:
                try:
                    probe_released = bool(self._transport.release_readiness_lock(handle, now=now))
                except Exception:  # noqa: BLE001 - a leaked readiness lock; report not released
                    probe_released = False

        try:
            force_unlock_available = bool(self._transport.force_unlock_available(now=now))
        except Exception:  # noqa: BLE001 - unknown → assume available (a refusal condition)
            force_unlock_available = True

        readiness = binding.binding
        return LockCapabilityProof(
            proof_id=uuid.uuid4(),
            issuer=self._lock_issuer,
            performed_at=now,
            toolchain_profile_hash=readiness.toolchain_profile_hash,
            namespace_hash=readiness.state_namespace_identity,
            lock_capability=lock_capability,
            contention_detected=contention_detected,
            force_unlock_available=force_unlock_available,
            caller_supplied_owner=caller_supplied_owner,
            probe_released=probe_released,
        )

    def _safe_proofs(
        self, binding: RemoteStateReadinessBinding, now: datetime, reasons: list[str]
    ) -> ObservedProofs:
        try:
            proofs = self._proof_source.external_proofs(binding, now=now)
        except Exception:  # noqa: BLE001 - a missing/failed proof source → every proof fails closed
            reasons.append("adapter_report_invalid")
            return ObservedProofs()
        return proofs if isinstance(proofs, ObservedProofs) else ObservedProofs()
