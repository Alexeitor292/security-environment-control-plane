"""Shared, NON-COLLECTED test helpers for the B1B-PR3 eligibility-preflight suites.

This module is deliberately NOT a ``test_*`` file, so pytest never collects it and it is imported
under a single module name (``tests._eligibility_fixtures``). Importing shared helpers from here —
rather than from a sibling ``test_*`` module — keeps cross-suite imports stable across the sharded
collection (a collected test module would otherwise be imported under two names and mismatch).

Nothing here contacts anything: it builds fixture ORM records and injected fake Path B seams only.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from secp_api.enums import (
    IsolationModel,
    LiveReadAuthorizationStatus,
    OnboardingMode,
    OnboardingStatus,
    VerificationLevel,
    WorkerIdentityMechanism,
    WorkerIdentityStatus,
)
from secp_api.live_read_contract import connection_identity_hash
from secp_api.models import (
    AuditEvent,
    ExecutionTarget,
    LiveReadAuthorization,
    Organization,
    TargetOnboarding,
    TargetPreflight,
    WorkerIdentityRegistration,
)
from secp_scenario_schema import content_hash
from secp_worker.onboarding.eligibility_preflight import (
    EligibilityPreflightComposition,
    EligibilityPreflightGate,
    EligibilityPreflightRequest,
)
from secp_worker.onboarding.live_readonly import LiveReadCollectionGate
from sqlalchemy import select

NOW = datetime(2026, 7, 2, tzinfo=UTC)
STORED_CONFIG = {"base_url": "https://lab.example.test:8006/api2/json", "verify_tls": True}
SECRET_REF = "env:SECP_PROVIDER_SECRET__LAB"

# A single-node, fully-segregated first-lab boundary.
BOUNDARY: dict = {
    "nodes": ["labnode"],
    "storage": ["labstore"],
    "network_segments": ["labseg"],
    "cidrs": ["10.9.0.0/24"],
    "vmid_range": {"start": 9000, "end": 9100},
    "quotas": {
        "max_teams": 1,
        "max_vms": 4,
        "max_containers": 2,
        "max_total_vcpu": 8,
        "max_total_memory_mb": 8192,
        "max_total_disk_gb": 100,
    },
    "external_connectivity": {"policy": "deny"},
    "credential_scope": "least_privilege",
}

ELIGIBLE_OBSERVED: dict = {
    "nodes": ["labnode"],
    "storage": ["labstore"],
    "network_segments": ["labseg"],
    "cidr_reservations": ["10.9.0.0/24"],
    "vmid_range": {"start": 8000, "end": 9999, "collision": False},
    "quotas": {
        "max_teams": 2,
        "max_vms": 8,
        "max_containers": 4,
        "max_total_vcpu": 16,
        "max_total_memory_mb": 16384,
        "max_total_disk_gb": 200,
    },
    "isolation": {
        "profile": "fully_segregated",
        "external_connectivity_policy": "deny",
        "route_to_protected": False,
        "no_default_route": True,
    },
    "disposability": {"storage": True},
}


# --- Injected fake Path B seams (never contact anything) ------------------------------------------


class _Cred:
    def reveal_secret(self) -> str:
        return "transient-token"


class _Resolver:
    def resolve(self, secret_ref: str) -> _Cred:
        return _Cred()


class _DummyTransport:
    def get(self, path: str):  # pragma: no cover - the fake collector never calls it
        raise AssertionError("fake collector must not use the transport")


def _transport_factory(validated_config, token):
    return _DummyTransport()


class _AllowVerifier:
    def verify(self, binding, *, now) -> bool:
        return True


class _EligibleCollector:
    """Returns a complete observed dict (an authorized activation supplying approved dedicated
    observations). It ignores the transport — nothing is contacted."""

    def collect(self, transport, *, declared_boundary) -> dict:
        return dict(ELIGIBLE_OBSERVED)


class _RaisingSeam:
    """A spy that fails the test if any of its methods is reached before its gate."""

    def resolve(self, *a, **k):
        raise AssertionError("secret resolver reached before its gate")

    def verify(self, *a, **k):
        raise AssertionError("authorization verifier reached before its gate")

    def collect(self, *a, **k):
        raise AssertionError("collector reached before its gate")

    def __call__(self, *a, **k):
        raise AssertionError("transport factory reached before its gate")


# --- DB chain builder ----------------------------------------------------------------------------


class Chain:
    def __init__(self, org_id, target, onboarding, authorization, worker_reg):
        self.org_id = org_id
        self.target = target
        self.onboarding = onboarding
        self.authorization = authorization
        self.worker_reg = worker_reg

    def request(self, **over) -> EligibilityPreflightRequest:
        fields = dict(
            organization_id=self.org_id,
            execution_target_id=self.target.id,
            onboarding_id=self.onboarding.id,
            authorization_id=self.authorization.id,
            authorization_version=self.authorization.authorization_version,
            worker_identity_registration_id=self.worker_reg.id,
        )
        fields.update(over)
        return EligibilityPreflightRequest(**fields)


def _default_target_status():
    from secp_api.enums import TargetStatus

    return TargetStatus.active


def _build_chain(session, *, boundary=BOUNDARY, over: dict | None = None, org_id=None) -> Chain:
    """Build a fully-consistent live-read chain. ``over`` sets fields at CONSTRUCTION time (never a
    post-flush mutation) so refusal scenarios don't trip the immutability guards."""
    over = over or {}
    if org_id is None:
        org_id = session.execute(select(Organization.id)).scalars().first()
    assert org_id is not None
    boundary_hash = content_hash(boundary)

    target = ExecutionTarget(
        organization_id=org_id,
        display_name="lab-proxmox",
        plugin_name="proxmox",
        config=dict(STORED_CONFIG),
        config_hash=content_hash(STORED_CONFIG),
        secret_ref=SECRET_REF,
        status=over.get("target_status", None) or _default_target_status(),
    )
    session.add(target)
    session.flush()

    onboarding = TargetOnboarding(
        organization_id=org_id,
        execution_target_id=target.id,
        onboarding_mode=OnboardingMode.existing_environment,
        isolation_model=IsolationModel.physical,
        status=over.get("onboarding_status", OnboardingStatus.active),
        declared_boundary=dict(boundary),
        boundary_hash=over.get("boundary_hash", boundary_hash),
    )
    session.add(onboarding)
    session.flush()

    authorization = LiveReadAuthorization(
        organization_id=org_id,
        execution_target_id=target.id,
        onboarding_id=onboarding.id,
        connection_hash=over.get("connection_hash", connection_identity_hash(STORED_CONFIG)),
        boundary_hash=over.get("auth_boundary_hash", boundary_hash),
        authorization_version=1,
        authorization_expiry=over.get("auth_expiry", NOW + timedelta(days=1)),
        collector_contract_version=over.get(
            "collector_contract_version", "secp-002b-1b-4/live-readonly-proxmox-collector/v1"
        ),
        endpoint_allowlist_version=over.get(
            "endpoint_allowlist_version", "secp-002b-1b-3/proxmox-readonly-allowlist/v1"
        ),
        evidence_source=over.get("evidence_source", "live_readonly_proxmox"),
        verification_level=VerificationLevel.live_verified.value,
        status=over.get("auth_status", LiveReadAuthorizationStatus.approved),
        approved_by=None,
        approved_at=NOW,
    )
    session.add(authorization)

    worker_reg = WorkerIdentityRegistration(
        organization_id=org_id,
        mechanism=WorkerIdentityMechanism.mtls_workload_identity,
        identity_label="lab-worker",
        deployment_binding="lab-deploy",
        verification_anchor_fingerprint="sha256:" + "a" * 64,
        identity_version=1,
        expiry=over.get("worker_expiry", NOW + timedelta(days=1)),
        status=over.get("worker_status", WorkerIdentityStatus.approved),
    )
    session.add(worker_reg)
    session.flush()
    return Chain(org_id, target, onboarding, authorization, worker_reg)


def _full_composition(collector=None) -> EligibilityPreflightComposition:
    return EligibilityPreflightComposition(
        gate=EligibilityPreflightGate(enabled=True),
        live_read_gate=LiveReadCollectionGate(enabled=True),
        secret_resolver=_Resolver(),
        transport_factory=_transport_factory,
        collector=collector or _EligibleCollector(),
        authorization_verifier=_AllowVerifier(),
    )


def _preflight_rows(session):
    return session.execute(select(TargetPreflight)).scalars().all()


def _audit_actions(session, org_id):
    session.flush()
    return [
        e.action
        for e in session.execute(select(AuditEvent).where(AuditEvent.organization_id == org_id))
        .scalars()
        .all()
    ]
