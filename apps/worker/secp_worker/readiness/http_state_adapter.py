"""Concrete HTTP remote-state readiness adapter (B1B-PR5B / ADR-021 §D) — DISABLED BY DEFAULT.

This is the reviewed, in-repository CONCRETE implementation of the
:class:`~secp_worker.readiness.state_adapter.RemoteStateReadinessAdapter` seam. It is the ONLY thing
that may contact a remote-state backend, and it is EXPLICITLY INJECTED by a reviewed
deployment-local
composition — never inferred from an environment variable, backend kind, URL, installed SDK, or
caller data. The shipped composition keeps :class:`SealedRemoteStateReadinessAdapter`, so ordinary
production refuses at the seal and this class is never even constructed there.

**It has no state-body surface.** Its ONLY public members are ``contract_version`` and ``evaluate``
(so :func:`~secp_worker.readiness.state_adapter.assert_no_state_body_surface` accepts it), and it
performs backend CONTROL-METADATA validation only: it never reads, writes, returns, restores,
deletes, or force-unlocks an OpenTofu state body — there is no interface through which one could.

Layering (identical discipline to the OpenBao resolver / client split):

* the ACTUAL backend contact is done by an injected :class:`RemoteStateControlProbe` — a bounded,
  idempotent control-metadata probe (TLS posture, namespace occupancy from metadata only, least-
  privilege scope, and an ephemeral lock probe released in a ``finally``). The shipped default is
  :class:`SealedRemoteStateControlProbe`, which refuses; a real hardened-HTTP probe is supplied out
  of band, and tests inject a fake — so nothing here contacts a network at construction or in tests;
* this adapter maps the typed, secret-free :class:`StateControlObservation` onto a
  :class:`~secp_worker.readiness.state_adapter.RemoteStateAdapterReport`, ALWAYS taking the backend
  kind, the immutable toolchain-profile hash, and the state-namespace identity from the
  AUTHORITATIVE
  binding (never from the probe), and NEVER self-attesting an occupied-namespace marker. The pure
  evaluation (:func:`~secp_worker.readiness.state_evaluation.evaluate_remote_state_readiness`) then
  validates every facet and fails closed on anything unprovable.

No backend URL, bucket / container / object name, state key, TLS fingerprint, token, or credential
is
present here or anywhere in the repository.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable

from secp_api.readiness_contract import (
    BACKEND_CLASS_LOCAL,
    BACKEND_CLASS_REMOTE,
    LOCAL_STATE_TOKENS,
    REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
    TLS_MODE_DISABLED,
    TLS_MODE_VERIFIED,
)

from secp_worker.readiness.state_adapter import (
    LockCapabilityProof,
    RemoteStateAdapterReport,
    RemoteStateReadinessBinding,
    RemoteStateReadinessUnavailable,
    StateProof,
)
from secp_worker.reviewed_identity import (
    ReviewedIdentityError,
    assert_reviewed_object,
    declaration_digest,
    object_identity,
)

# The reviewed concrete-implementation registration of this adapter. A controlled-live
# state-readiness
# operation is bound to it (and to this class's un-forgeable ``module.qualname``), so a duck-typed /
# foreign / sealed adapter, or one over a sealed/fake probe or transport, is refused (§10).
HTTP_STATE_ADAPTER_REGISTRATION = "secp-002b-1b-pr5b/http-state-adapter/v1"

# The exact reviewed identities the controlled-live binding walks. The probe/transport identities
# are
# STRING-PINNED (not imported) to avoid a circular import with ``http_state_probe`` and to keep this
# module free of the top-level ``httpx`` transport; ``test_concrete_transports`` cross-checks them.
_ADAPTER_IDENTITY = "secp_worker.readiness.http_state_adapter.HttpRemoteStateReadinessAdapter"
_PROBE_IDENTITY = "secp_worker.readiness.http_state_probe.ConcreteHttpStateControlProbe"
_PROBE_REGISTRATION = "secp-002b-1b-pr5b/http-state-control-probe/v1"
_STATE_TRANSPORT_IDENTITY = "secp_worker.state_control_http_transport.HttpStateControlTransport"
_STATE_TRANSPORT_REGISTRATION = "secp-002b-1b-pr5b/state-control-http-transport/v1"


def http_state_adapter_digest() -> str:
    """The stable digest of the reviewed concrete HTTP state adapter implementation identity."""
    return declaration_digest(HTTP_STATE_ADAPTER_REGISTRATION)


@dataclass(frozen=True)
class StateControlObservation:
    """The typed, secret-free result of ONE bounded backend control-metadata probe.

    It carries NO state body, backend URL, bucket/object name, token, or response payload — only the
    booleans and immutable EXTERNAL proofs the evaluation needs. Identity fields (backend kind,
    profile hash, namespace) are deliberately ABSENT: the adapter always takes those from the
    authoritative binding, so a probe can never substitute a namespace or a backend.
    """

    # Transport security (§D.2), derived from the probe transport's attested hardening posture.
    tls_verified: bool = False
    certificate_validation_enabled: bool = False
    trusted_identity_policy: str = ""
    proxy_inheritance_enabled: bool = True
    redirect_observed: bool = True
    destination_stable: bool = False
    # Namespace occupancy (§D.9), decided from METADATA/version identity only — the body is never
    # read. ``None`` means it could not be determined without reading a state body → unverifiable.
    namespace_present: bool | None = None
    # Least privilege (§D.8): the EXACT allowed backend actions + whether scope evidence was there.
    allowed_actions: tuple[str, ...] = ()
    scope_evidence_available: bool = False
    # Local fallback (§D.10): true iff a local/disk state fallback is reachable (a refusal reason).
    local_fallback_available: bool = False
    # Immutable EXTERNAL proofs for THIS operation's namespace (§D.4-§D.7). ``None`` = the probe
    # could not obtain the proof → that facet fails closed. The adapter passes them through; the
    # pure evaluation independently re-validates each proof's namespace/profile binding + freshness.
    encryption: StateProof | None = None
    locking: LockCapabilityProof | None = None
    backup: StateProof | None = None
    restore: StateProof | None = None
    # Bounded, closed reason codes the probe wants to surface (free text / oversize is dropped).
    reason_codes: tuple[str, ...] = field(default_factory=tuple)


@runtime_checkable
class RemoteStateControlProbe(Protocol):
    """The injected, worker-only backend control-metadata probe seam.

    ``observe`` performs the bounded, idempotent control-metadata validation for exactly one
    authoritative binding and returns a typed :class:`StateControlObservation`. It must never read
    or
    write an OpenTofu state body, never force-unlock, and never return state content; any lock probe
    must be idempotent, bounded, released in a ``finally``, cancellation-safe, and namespace-bound.
    """

    def observe(
        self, binding: RemoteStateReadinessBinding, *, now: datetime
    ) -> StateControlObservation: ...


class SealedRemoteStateControlProbe:
    """The shipped default probe: contacts nothing and refuses unconditionally."""

    def observe(
        self, binding: RemoteStateReadinessBinding, *, now: datetime
    ) -> StateControlObservation:
        raise RemoteStateReadinessUnavailable(
            "no remote-state control probe is configured; the shipped composition is sealed and "
            "contacts no state backend"
        )


def _backend_class(kind: str) -> str:
    """Map the AUTHORITATIVE backend kind onto a bounded class; a local/empty kind → ``local``."""
    token = str(kind or "").strip().lower()
    return BACKEND_CLASS_LOCAL if token in LOCAL_STATE_TOKENS else BACKEND_CLASS_REMOTE


class HttpRemoteStateReadinessAdapter:
    """A concrete ``RemoteStateReadinessAdapter`` over an injected control-metadata probe.

    Sealed by default: with the sealed probe (or none) every ``evaluate`` refuses before any
    contact.
    Its ONLY public members are ``contract_version`` and ``evaluate`` — it exposes no state-body
    surface, so a state payload can never be read, written, returned, or persisted through it.
    """

    IMPLEMENTATION_ID = HTTP_STATE_ADAPTER_REGISTRATION

    def __init__(self, *, probe: RemoteStateControlProbe | None = None) -> None:
        self._probe: RemoteStateControlProbe = probe or SealedRemoteStateControlProbe()
        # "Production bound" ONLY when the probe is the EXACT concrete probe over the EXACT concrete
        # HTTP state-control transport. A sealed/fake probe, or one over a sealed/fake transport, is
        # not bound (controlled-live state readiness refuses it). Private state — the adapter's
        # PUBLIC
        # surface stays exactly {contract_version, evaluate} so ``assert_no_state_body_surface``
        # holds.
        self._production_bound = _probe_is_production_bound(self._probe)

    @property
    def contract_version(self) -> str:
        return REMOTE_STATE_ADAPTER_CONTRACT_VERSION

    def evaluate(
        self, binding: RemoteStateReadinessBinding, *, now: datetime
    ) -> RemoteStateAdapterReport:
        if not isinstance(binding, RemoteStateReadinessBinding):
            raise RemoteStateReadinessUnavailable("remote-state binding is not a typed binding")

        # THE ONLY BACKEND CONTACT — bounded control-metadata validation. A sealed probe refuses
        # here.
        observation = self._probe.observe(binding, now=now)
        if not isinstance(observation, StateControlObservation):
            raise RemoteStateReadinessUnavailable("remote-state probe returned an untyped result")

        readiness = binding.binding
        # Identity fields ALWAYS come from the authoritative binding, never from the probe: the
        # probe
        # cannot substitute a namespace, a backend, or a toolchain profile. The occupied-namespace
        # marker is deliberately BLANK — this adapter never self-attests its way past an occupied
        # namespace; an occupied namespace with no server-derived marker fails closed in evaluation.
        return RemoteStateAdapterReport(
            backend_class=_backend_class(binding.state_backend_kind),
            backend_kind=binding.state_backend_kind,
            toolchain_profile_hash=readiness.toolchain_profile_hash,
            namespace_identity=readiness.state_namespace_identity,
            tls_mode=TLS_MODE_VERIFIED if observation.tls_verified else TLS_MODE_DISABLED,
            trusted_identity_policy=observation.trusted_identity_policy,
            certificate_validation_enabled=observation.certificate_validation_enabled,
            proxy_inheritance_enabled=observation.proxy_inheritance_enabled,
            redirect_observed=observation.redirect_observed,
            destination_stable=observation.destination_stable,
            namespace_state_present=observation.namespace_present,
            expected_namespace_marker="",
            allowed_actions=tuple(observation.allowed_actions),
            scope_evidence_available=observation.scope_evidence_available,
            local_fallback_available=observation.local_fallback_available,
            encryption=observation.encryption,
            locking=observation.locking,
            backup=observation.backup,
            restore=observation.restore,
            reason_codes=tuple(observation.reason_codes),
        )


# --- reviewed concrete-chain binding (controlled-live state-readiness verification) ---------------


def _probe_is_production_bound(probe: object) -> bool:
    """True only when ``probe`` is the EXACT concrete probe over the EXACT concrete state transport.

    Walks the reviewed chain by un-forgeable ``module.qualname`` identity + declared registration. A
    sealed/fake probe, or the concrete probe over a sealed/fake/foreign transport, is not bound. No
    object is echoed; this performs no I/O.
    """
    if object_identity(probe) != _PROBE_IDENTITY:
        return False
    if getattr(type(probe), "IMPLEMENTATION_ID", None) != _PROBE_REGISTRATION:
        return False
    transport = getattr(probe, "_transport", None)
    if transport is None:
        return False
    if object_identity(transport) != _STATE_TRANSPORT_IDENTITY:
        return False
    return getattr(type(transport), "IMPLEMENTATION_ID", None) == _STATE_TRANSPORT_REGISTRATION


def assert_concrete_state_adapter(adapter: object) -> None:
    """Refuse unless ``adapter`` is the reviewed concrete HTTP state adapter, production-bound.

    A duck-typed / foreign / sealed adapter, a forged registration, or the concrete adapter over a
    sealed/fake/foreign probe or transport is refused with a closed reason code
    (:class:`~secp_worker.reviewed_identity.ReviewedIdentityError`). Used by controlled-live state
    readiness — never on the shipped sealed path or the explicit test-only path.
    """
    assert_reviewed_object(
        adapter,
        expected_identity=_ADAPTER_IDENTITY,
        expected_registration=HTTP_STATE_ADAPTER_REGISTRATION,
        reason_code="state_adapter_not_concrete",
    )
    if not getattr(adapter, "_production_bound", False):
        raise ReviewedIdentityError("state_adapter_not_production_bound")
