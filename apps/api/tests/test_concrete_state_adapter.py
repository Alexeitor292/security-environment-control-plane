"""B1B-PR5B — the concrete HTTP remote-state readiness adapter + control probe (ADR-021 §D, §E).

The reviewed, in-repository CONCRETE ``RemoteStateReadinessAdapter`` is sealed by default (no probe
→ refuse), exposes ONLY ``{contract_version, evaluate}`` (no state-body surface), ALWAYS takes the
backend kind / profile hash / namespace identity from the authoritative binding, and never
self-attests an occupied-namespace marker. The concrete probe holds exactly one ephemeral lock and
ALWAYS releases it in a ``finally``. These tests inject fakes only; nothing contacts a network.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from secp_api.enums import ReadinessOperationKind, RemoteStateReadinessOutcome
from secp_api.readiness_contract import (
    PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
    READINESS_POLICY_VERSION,
    REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
    ReadinessBinding,
)
from secp_worker.readiness.http_state_adapter import (
    HttpRemoteStateReadinessAdapter,
    SealedRemoteStateControlProbe,
    StateControlObservation,
)
from secp_worker.readiness.http_state_probe import (
    ApprovedStateBackendControlTransport,
    ConcreteHttpStateControlProbe,
    ObservedProofs,
    ReadinessLockHandle,
    SealedStateBackendControlTransport,
    TransportSecurityPosture,
)
from secp_worker.readiness.state_adapter import (
    LockCapabilityProof,
    RemoteStateAdapterReport,
    RemoteStateReadinessBinding,
    RemoteStateReadinessUnavailable,
    StateProof,
    assert_no_state_body_surface,
)
from secp_worker.readiness.state_evaluation import evaluate_remote_state_readiness

NOW = datetime(2026, 7, 15, tzinfo=UTC)
_PROFILE_HASH = "sha256:" + "a" * 64
_NAMESPACE = "sha256:" + "b" * 64


def _readiness_binding(**over) -> ReadinessBinding:
    """A minimal authoritative binding — only the two identity fields the adapter reads matter."""
    base = dict(
        organization_id=str(uuid.uuid4()),
        environment_version_id=str(uuid.uuid4()),
        environment_version_content_hash="sha256:" + "1" * 64,
        deployment_plan_id=str(uuid.uuid4()),
        deployment_plan_content_hash="sha256:" + "2" * 64,
        provisioning_manifest_id=str(uuid.uuid4()),
        provisioning_manifest_content_hash="sha256:" + "3" * 64,
        execution_target_id=str(uuid.uuid4()),
        target_config_hash="sha256:" + "4" * 64,
        target_onboarding_id=str(uuid.uuid4()),
        onboarding_boundary_hash="sha256:" + "5" * 64,
        effective_boundary_hash="sha256:" + "6" * 64,
        eligibility_preflight_id=str(uuid.uuid4()),
        eligibility_evidence_hash="sha256:" + "7" * 64,
        eligibility_policy_version="pol/v1",
        eligibility_expires_at="2026-07-15T18:00:00Z",
        toolchain_profile_id=str(uuid.uuid4()),
        toolchain_profile_hash=_PROFILE_HASH,
        toolchain_attestation_policy_version="att/v1",
        toolchain_attestation_id=str(uuid.uuid4()),
        toolchain_attestation_hash="sha256:" + "8" * 64,
        state_namespace_identity=_NAMESPACE,
        credential_binding_id=str(uuid.uuid4()),
        credential_binding_version=1,
        activation_dossier_hash="sha256:" + "9" * 64,
        worker_identity_registration_id=str(uuid.uuid4()),
        worker_identity_version=1,
        operation_kind=ReadinessOperationKind.remote_state_readiness.value,
        readiness_policy_version=READINESS_POLICY_VERSION,
        adapter_contract_version=REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
    )
    base.update(over)
    return ReadinessBinding(**base)


# The authoritative HTTPS state-backend reference the readiness op is bound to; its origin must
# equal
# the concrete probe transport's control origin (the destination-binding correction, ADR-022 §6).
_STATE_REFERENCE = "https://state.example/lab"
_STATE_ORIGIN = "https://state.example:443"


def _adapter_binding(**over) -> RemoteStateReadinessBinding:
    return RemoteStateReadinessBinding(
        binding=_readiness_binding(),
        state_backend_kind=over.get("state_backend_kind", "s3"),
        state_backend_reference=over.get("state_backend_reference", _STATE_REFERENCE),
    )


def _bound_proof(**over) -> StateProof:
    base = dict(
        proof_id=uuid.uuid4(),
        issuer=uuid.uuid4(),
        performed_at=NOW,
        toolchain_profile_hash=_PROFILE_HASH,
        namespace_hash=_NAMESPACE,
    )
    base.update(over)
    return StateProof(**base)


def _passing_lock_proof(**over) -> LockCapabilityProof:
    base = dict(
        proof_id=uuid.uuid4(),
        issuer=uuid.uuid4(),
        performed_at=NOW,
        toolchain_profile_hash=_PROFILE_HASH,
        namespace_hash=_NAMESPACE,
        lock_capability=True,
        contention_detected=True,
        force_unlock_available=False,
        caller_supplied_owner=False,
        probe_released=True,
    )
    base.update(over)
    return LockCapabilityProof(**base)


def _ready_observation() -> StateControlObservation:
    return StateControlObservation(
        tls_verified=True,
        certificate_validation_enabled=True,
        trusted_identity_policy="system_trust_store",
        proxy_inheritance_enabled=False,
        redirect_observed=False,
        destination_stable=True,
        namespace_present=False,
        allowed_actions=("read", "write", "lock", "unlock_own"),
        scope_evidence_available=True,
        local_fallback_available=False,
        encryption=_bound_proof(),
        locking=_passing_lock_proof(),
        backup=_bound_proof(),
        restore=_bound_proof(restore_tested=True),
    )


class _FixedProbe:
    def __init__(self, observation: StateControlObservation) -> None:
        self._observation = observation
        self.calls = 0

    def observe(self, binding, *, now):  # noqa: ANN001, ANN201
        self.calls += 1
        return self._observation


# --- the adapter: sealed default, no-state-body surface, authoritative identity ------------------


def test_sealed_adapter_refuses_before_any_contact():
    adapter = HttpRemoteStateReadinessAdapter()  # sealed probe by default
    assert adapter.contract_version == REMOTE_STATE_ADAPTER_CONTRACT_VERSION
    with pytest.raises(RemoteStateReadinessUnavailable):
        adapter.evaluate(_adapter_binding(), now=NOW)
    # An explicit sealed probe is equivalent.
    with pytest.raises(RemoteStateReadinessUnavailable):
        HttpRemoteStateReadinessAdapter(probe=SealedRemoteStateControlProbe()).evaluate(
            _adapter_binding(), now=NOW
        )


def test_adapter_exposes_no_state_body_surface():
    # The structural guard accepts the adapter (only contract_version + evaluate are public).
    assert_no_state_body_surface(HttpRemoteStateReadinessAdapter())
    assert_no_state_body_surface(
        HttpRemoteStateReadinessAdapter(probe=_FixedProbe(_ready_observation()))
    )


def test_adapter_takes_identity_from_the_binding_never_the_probe():
    probe = _FixedProbe(_ready_observation())
    report = HttpRemoteStateReadinessAdapter(probe=probe).evaluate(_adapter_binding(), now=NOW)
    assert isinstance(report, RemoteStateAdapterReport)
    # Identity is always the authoritative binding's — never anything the probe could substitute.
    assert report.toolchain_profile_hash == _PROFILE_HASH
    assert report.namespace_identity == _NAMESPACE
    assert report.backend_kind == "s3"
    assert report.backend_class == "remote"
    # The adapter NEVER self-attests an occupied-namespace marker.
    assert report.expected_namespace_marker == ""


def test_adapter_report_yields_ready_when_everything_is_genuinely_present():
    probe = _FixedProbe(_ready_observation())
    report = HttpRemoteStateReadinessAdapter(probe=probe).evaluate(_adapter_binding(), now=NOW)
    evaluation = evaluate_remote_state_readiness(
        binding=_readiness_binding(), report=report, now=NOW
    )
    assert evaluation.outcome == RemoteStateReadinessOutcome.ready.value


def test_a_local_backend_kind_fails_closed():
    probe = _FixedProbe(_ready_observation())
    report = HttpRemoteStateReadinessAdapter(probe=probe).evaluate(
        _adapter_binding(state_backend_kind="local"), now=NOW
    )
    assert report.backend_class == "local"
    evaluation = evaluate_remote_state_readiness(
        binding=_readiness_binding(), report=report, now=NOW
    )
    assert evaluation.outcome == RemoteStateReadinessOutcome.not_ready.value


def test_untyped_probe_result_refuses():
    class _BadProbe:
        def observe(self, binding, *, now):  # noqa: ANN001, ANN201
            return {"backend_class": "remote"}

    with pytest.raises(RemoteStateReadinessUnavailable):
        HttpRemoteStateReadinessAdapter(probe=_BadProbe()).evaluate(_adapter_binding(), now=NOW)


# --- the concrete probe: fail-closed, lock ALWAYS released ----------------------------------------


class _RecordingTransport(ApprovedStateBackendControlTransport):
    """A configurable approved transport that records lock acquire/release for leak assertions."""

    def __init__(
        self,
        *,
        posture: TransportSecurityPosture,
        occupied: bool | None,
        actions: tuple[str, ...] | None,
        fallback: bool,
        force_unlock: bool,
        acquire: bool,
        contention: bool,
        contention_raises: bool = False,
        caller_owner: bool = False,
    ) -> None:
        self._posture = posture
        self._occupied = occupied
        self._actions = actions
        self._fallback = fallback
        self._force_unlock = force_unlock
        self._acquire = acquire
        self._contention = contention
        self._contention_raises = contention_raises
        self._caller_owner = caller_owner
        self.acquired = 0
        self.released = 0

    @property
    def control_origin(self):  # noqa: ANN201 - bound to the same backend the binding references
        return _STATE_ORIGIN

    def security_posture(self, *, now):  # noqa: ANN001, ANN201
        return self._posture

    def namespace_occupied(self, *, now):  # noqa: ANN001, ANN201
        return self._occupied

    def granted_actions(self, *, now):  # noqa: ANN001, ANN201
        return self._actions

    def local_fallback_reachable(self, *, now):  # noqa: ANN001, ANN201
        return self._fallback

    def force_unlock_available(self, *, now):  # noqa: ANN001, ANN201
        return self._force_unlock

    def acquire_readiness_lock(self, *, now):  # noqa: ANN001, ANN201
        if not self._acquire:
            return None
        self.acquired += 1
        return ReadinessLockHandle(caller_supplied_owner=self._caller_owner)

    def probe_contention(self, *, now):  # noqa: ANN001, ANN201
        if self._contention_raises:
            raise RuntimeError("contention probe blew up")
        return self._contention

    def release_readiness_lock(self, handle, *, now):  # noqa: ANN001, ANN201
        self.released += 1
        return True


def _healthy_transport(**over) -> _RecordingTransport:
    base = dict(
        posture=TransportSecurityPosture(
            tls_verified=True,
            certificate_validation_enabled=True,
            trusted_identity_policy="system_trust_store",
            proxy_inheritance_enabled=False,
            redirect_observed=False,
            destination_stable=True,
        ),
        occupied=False,
        actions=("read", "write", "lock", "unlock_own"),
        fallback=False,
        force_unlock=False,
        acquire=True,
        contention=True,
    )
    base.update(over)
    return _RecordingTransport(**base)


class _HealthyProofSource:
    def external_proofs(self, binding, *, now):  # noqa: ANN001, ANN201
        return ObservedProofs(
            encryption=_bound_proof(),
            backup=_bound_proof(),
            restore=_bound_proof(restore_tested=True),
        )


def test_sealed_transport_produces_a_fully_fail_closed_observation():
    probe = ConcreteHttpStateControlProbe(transport=SealedStateBackendControlTransport())
    obs = probe.observe(_adapter_binding(), now=NOW)
    # Nothing proves out: TLS unverified, namespace undeterminable, no scope, no lock proof.
    assert obs.tls_verified is False
    assert obs.namespace_present is None
    assert obs.allowed_actions == ()
    assert obs.locking is None
    # A sealed acquire raised → no handle → nothing to leak.
    # Feeding it through the adapter + evaluation is never ``ready``.
    report = HttpRemoteStateReadinessAdapter(probe=probe).evaluate(_adapter_binding(), now=NOW)
    evaluation = evaluate_remote_state_readiness(
        binding=_readiness_binding(), report=report, now=NOW
    )
    assert evaluation.outcome != RemoteStateReadinessOutcome.ready.value


def test_foreign_transport_is_refused_without_contact():
    probe = ConcreteHttpStateControlProbe(transport=object())  # not an approved transport
    obs = probe.observe(_adapter_binding(), now=NOW)
    assert obs.tls_verified is False
    assert "adapter_report_invalid" in obs.reason_codes


def test_healthy_transport_and_proofs_yield_ready_and_release_the_lock():
    transport = _healthy_transport()
    lock_issuer = uuid.uuid4()
    probe = ConcreteHttpStateControlProbe(
        transport=transport, proof_source=_HealthyProofSource(), lock_issuer=lock_issuer
    )
    report = HttpRemoteStateReadinessAdapter(probe=probe).evaluate(_adapter_binding(), now=NOW)
    evaluation = evaluate_remote_state_readiness(
        binding=_readiness_binding(), report=report, now=NOW
    )
    assert evaluation.outcome == RemoteStateReadinessOutcome.ready.value
    # The ephemeral lock was acquired once and released once (no leak).
    assert transport.acquired == 1
    assert transport.released == 1
    assert report.locking is not None and report.locking.issuer == lock_issuer


def test_lock_is_released_even_when_the_contention_probe_raises():
    transport = _healthy_transport(contention_raises=True)
    probe = ConcreteHttpStateControlProbe(
        transport=transport, proof_source=_HealthyProofSource(), lock_issuer=uuid.uuid4()
    )
    obs = probe.observe(_adapter_binding(), now=NOW)
    # The lock probe failed → reported unprovable, but the acquired lock was STILL released.
    assert obs.locking is None
    assert transport.acquired == 1
    assert transport.released == 1


def test_without_a_lock_issuer_the_lock_is_unprovable_and_no_lock_is_acquired():
    transport = _healthy_transport()
    probe = ConcreteHttpStateControlProbe(transport=transport)  # no lock issuer
    obs = probe.observe(_adapter_binding(), now=NOW)
    assert obs.locking is None
    assert transport.acquired == 0  # never even attempts to acquire without a reviewed issuer


def test_force_unlock_availability_fails_the_lock_facet():
    transport = _healthy_transport(force_unlock=True)
    probe = ConcreteHttpStateControlProbe(
        transport=transport, proof_source=_HealthyProofSource(), lock_issuer=uuid.uuid4()
    )
    report = HttpRemoteStateReadinessAdapter(probe=probe).evaluate(_adapter_binding(), now=NOW)
    assert report.locking is not None and report.locking.force_unlock_available is True
    evaluation = evaluate_remote_state_readiness(
        binding=_readiness_binding(), report=report, now=NOW
    )
    assert evaluation.outcome == RemoteStateReadinessOutcome.not_ready.value


def test_plan_secret_resolver_contract_label_is_distinct_from_the_adapter_contract():
    # Defensive: the plan-secret resolver + state adapter contracts are intentionally different
    # labels so one can never satisfy the other's gate.
    assert PLAN_SECRET_RESOLVER_CONTRACT_VERSION != REMOTE_STATE_ADAPTER_CONTRACT_VERSION
