"""Shared, NON-COLLECTED test helpers for the B1B-PR4 readiness suites (ADR-021).

Deliberately NOT a ``test_*`` module, so pytest never collects it and it is imported under a single
stable module name (``tests._readiness_fixtures``) across the sharded collection.

Nothing here contacts anything. It builds fixture ORM records plus INJECTED fake seams:

* an INERT temporary toolchain tree + its ``ToolchainFilesystemLayout``, so the REAL
  ``RealToolchainVerifier`` can produce a genuine durable attestation record without any binary ever
  being executed, any provider being loaded, or any network being touched;
* a fake remote-state readiness adapter (it performs no I/O and has NO state-body method);
* a fake resolver self-test (it returns a bounded reason code and no target credential);
* clearly test-only ``AdapterActivation`` records + a clearly test-only (but NON-placeholder)
  activation-dossier hash, so the controlled-live capability path can be exercised;
* trap seams that fail the test if a privileged boundary is reached before its gate;
* an INERT sentinel ``SecretMaterial`` — no real provisioning credential is ever resolved.

No real backend, secret manager, Proxmox host, OpenTofu binary, or network is used.
"""

from __future__ import annotations

import copy
import uuid
from datetime import UTC, datetime, timedelta

from secp_api.enums import (
    LiveReadAuthorizationStatus,
    PlanSecretEvidenceKind,
    PlanSecretEvidenceStatus,
    ReadinessOperationKind,
    VerificationLevel,
    WorkerIdentityMechanism,
    WorkerIdentityStatus,
)
from secp_api.live_read_contract import connection_identity_hash
from secp_api.models import (
    AuditEvent,
    LiveReadAuthorization,
    WorkerIdentityRegistration,
)
from secp_api.readiness_binding import load_readiness_binding
from secp_api.readiness_contract import (
    PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
    REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
    ReadinessBinding,
)
from secp_worker.readiness.capability import AdapterActivation, implementation_identity
from secp_worker.readiness.composition import ReadinessComposition, ReadinessGate
from secp_worker.readiness.self_test import PlanSecretSelfTestResult
from secp_worker.readiness.state_adapter import (
    LockCapabilityProof,
    RemoteStateAdapterReport,
    RemoteStateReadinessBinding,
    StateProof,
)
from sqlalchemy import select

# The worker seams take an explicit ``now``; the API authorization lifecycle uses the real clock
# (correct for production). ``NOW`` therefore tracks the real clock so both agree, and every
# expiry/TTL assertion is expressed RELATIVE to it (never against a hard-coded date).
NOW = datetime.now(UTC).replace(microsecond=0)

# An OPAQUE placeholder credential reference (never a secret, never a real vault path).
VAULT_SECRET_REF = "vault:secp-fake-lab/plan-read"

# The INERT sentinel used to prove the JIT projection. It is NOT a target credential, it never comes
# from a backend, and it must never appear in the database, an audit row, a log, a workflow arg, an
# exception, a repr, a model dump, an API response, a rendered file, or the git diff.
SENTINEL_SECRET = "SECP-INERT-SENTINEL-b1b-pr4-3f9c1a2e"  # noqa: S105 - inert test canary, not a secret

# A clearly TEST-ONLY (but non-placeholder) reviewed activation-dossier hash. Production requires a
# real, reviewed, deployment-local dossier; the fail-closed placeholder authorizes nothing, ever.
TEST_DOSSIER_HASH = "sha256:" + "d0551e5" * 9 + "d"  # 64 hex chars, obviously a fixture


# --- observed-evidence synthesis (satisfies ANY declared boundary) --------------------------------


def eligible_observed(boundary: dict) -> dict:
    """A complete observed payload that satisfies ``boundary`` on every eligibility dimension."""
    quotas = dict(boundary.get("quotas") or {})
    vmid = dict(boundary.get("vmid_range") or {})
    return {
        "nodes": list(boundary.get("nodes") or []),
        "storage": list(boundary.get("storage") or []),
        "network_segments": list(boundary.get("network_segments") or []),
        "cidr_reservations": list(boundary.get("cidrs") or []),
        "vmid_range": {
            "start": int(vmid.get("start", 9000)),
            "end": int(vmid.get("end", 9100)),
            "collision": False,
        },
        "quotas": {k: v for k, v in quotas.items() if v is not None},
        "isolation": {
            "profile": "fully_segregated",
            "external_connectivity_policy": "deny",
            "route_to_protected": False,
            "no_default_route": True,
        },
        "disposability": {"storage": True},
    }


# --- fake Path B eligibility seams (contact nothing) ----------------------------------------------


class _Cred:
    def reveal_secret(self) -> str:
        return "transient-token"  # noqa: S106 - inert fixture value


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


class _BoundaryCollector:
    """Returns observations derived from the declared boundary. It contacts nothing."""

    def collect(self, transport, *, declared_boundary) -> dict:
        return eligible_observed(declared_boundary)


# --- readiness environment ------------------------------------------------------------------------


class ReadinessEnv:
    def __init__(self, lab, authorization, worker_reg, preflight):
        self.lab = lab
        self.target = lab.target
        self.plan = lab.plan
        self.manifest = lab.manifest
        self.toolchain = lab.toolchain
        self.onboarding = lab.onboarding
        self.org_id = lab.target.organization_id
        self.live_read_authorization = authorization
        self.worker_reg = worker_reg
        self.eligibility_preflight = preflight
        # The INERT deployment-local layout the durable attestation was produced from (or None when
        # the suite deliberately runs WITHOUT an attestation).
        self.toolchain_layout = None


def single_node_scope() -> dict:
    """The MINIMUM first-lab scope (ADR-020 §P): exactly ONE allowed node.

    The B1B-PR3 eligibility policy fails ``node_boundary`` unless the declared boundary names
    exactly one node, so the readiness chain can only reach ``eligible`` on a minimal shape.
    """
    from tests.conftest import VALID_PROVISIONING_SCOPE  # type: ignore[import-not-found]

    scope = copy.deepcopy(VALID_PROVISIONING_SCOPE)
    scope["allowed_nodes"] = ["pve-node-1"]
    return scope


def toolchain_fixture(root: str):
    """An INERT temporary toolchain tree + its explicit layout + a matching secret-free profile.

    It reuses the reviewed B1B-PR2 builder verbatim, so the REAL ``RealToolchainVerifier`` verifies
    a real on-disk tree. Nothing is executed: the "binary" is inert bytes, the "provider plugin" is
    inert bytes, and the verifier only ever *reads* files.
    """
    from tests.test_toolchain_verify import build_fixture  # type: ignore[import-not-found]

    return build_fixture(root)


def attest_toolchain(session, env, *, layout, now: datetime = NOW):
    """Run the REAL worker-local toolchain attestation against the inert fixture layout.

    This is the only way a ``ToolchainAttestationRecord`` comes into existence: a matching profile
    hash is a DECLARATION, never evidence.
    """
    from secp_worker.readiness.toolchain_attestation import run_toolchain_attestation

    result = run_toolchain_attestation(
        session, toolchain_profile_id=env.toolchain.id, layout=layout, now=now
    )
    assert result.outcome == "attested", f"fixture attestation failed: {result}"
    session.flush()
    return result


def build_readiness_env(
    session,
    principal,
    *,
    now: datetime = NOW,
    toolchain_root: str | None = None,
    attest: bool = True,
    **lab_kwargs,
) -> ReadinessEnv:
    """The full authoritative chain PR4 requires, up to CURRENT ELIGIBLE live eligibility evidence.

    Uses the narrow existing test-only fixture path: the real worker seam
    ``run_real_eligibility_preflight`` with an explicitly-injected activation composition. There is
    NO production shortcut that upgrades ``unverifiable`` into ``eligible``.
    """
    from secp_worker.onboarding.eligibility_preflight import (
        EligibilityPreflightComposition,
        EligibilityPreflightGate,
        EligibilityPreflightRequest,
        run_real_eligibility_preflight,
    )
    from secp_worker.onboarding.live_readonly import LiveReadCollectionGate
    from tests.conftest import build_lab_env  # type: ignore[import-not-found]

    layout = None
    if toolchain_root is not None:
        layout, profile = toolchain_fixture(toolchain_root)
        lab_kwargs.setdefault("toolchain", profile)
    lab_kwargs.setdefault("scope", single_node_scope())
    lab_kwargs.setdefault("secret_ref", VAULT_SECRET_REF)
    lab = build_lab_env(session, principal, **lab_kwargs)
    org_id = lab.target.organization_id

    authorization = LiveReadAuthorization(
        organization_id=org_id,
        execution_target_id=lab.target.id,
        onboarding_id=lab.onboarding.id,
        connection_hash=connection_identity_hash(lab.target.config),
        boundary_hash=lab.onboarding.boundary_hash,
        authorization_version=1,
        authorization_expiry=now + timedelta(days=1),
        collector_contract_version="secp-002b-1b-4/live-readonly-proxmox-collector/v1",
        endpoint_allowlist_version="secp-002b-1b-3/proxmox-readonly-allowlist/v1",
        evidence_source="live_readonly_proxmox",
        verification_level=VerificationLevel.live_verified.value,
        status=LiveReadAuthorizationStatus.approved,
        approved_by=principal.user_id,
        approved_at=now,
    )
    session.add(authorization)
    worker_reg = WorkerIdentityRegistration(
        organization_id=org_id,
        mechanism=WorkerIdentityMechanism.mtls_workload_identity,
        identity_label="readiness-worker",
        deployment_binding="readiness-deploy",
        verification_anchor_fingerprint="sha256:" + "b" * 64,
        identity_version=1,
        expiry=now + timedelta(days=1),
        status=WorkerIdentityStatus.approved,
    )
    session.add(worker_reg)
    session.flush()

    result = run_real_eligibility_preflight(
        session,
        request=EligibilityPreflightRequest(
            organization_id=org_id,
            execution_target_id=lab.target.id,
            onboarding_id=lab.onboarding.id,
            authorization_id=authorization.id,
            authorization_version=authorization.authorization_version,
            worker_identity_registration_id=worker_reg.id,
        ),
        composition=EligibilityPreflightComposition(
            gate=EligibilityPreflightGate(enabled=True),
            live_read_gate=LiveReadCollectionGate(enabled=True),
            secret_resolver=_Resolver(),
            transport_factory=_transport_factory,
            collector=_BoundaryCollector(),
            authorization_verifier=_AllowVerifier(),
        ),
        now=now,
    )
    assert result.outcome == "eligible", f"fixture eligibility not eligible: {result}"
    from secp_api.models import TargetPreflight

    preflight = session.get(TargetPreflight, result.preflight_id)
    session.flush()
    env = ReadinessEnv(lab, authorization, worker_reg, preflight)
    env.toolchain_layout = layout
    if layout is not None and attest:
        attest_toolchain(session, env, layout=layout, now=now)
    return env


def reauthorize_eligibility(
    session, env: ReadinessEnv, *, version: int = 2, now: datetime = NOW, approved_by=None
) -> None:
    """Issue a NEW live-read authorization version and re-run the eligibility preflight.

    This is the real-world re-authorization path: a new authorization version yields a new
    eligibility operation fingerprint, hence a NEW immutable eligibility-evidence record — which in
    turn changes every downstream readiness binding.
    """
    from secp_worker.onboarding.eligibility_preflight import (
        EligibilityPreflightComposition,
        EligibilityPreflightGate,
        EligibilityPreflightRequest,
        run_real_eligibility_preflight,
    )
    from secp_worker.onboarding.live_readonly import LiveReadCollectionGate

    fresh = LiveReadAuthorization(
        organization_id=env.org_id,
        execution_target_id=env.target.id,
        onboarding_id=env.onboarding.id,
        connection_hash=connection_identity_hash(env.target.config),
        boundary_hash=env.onboarding.boundary_hash,
        authorization_version=version,
        authorization_expiry=now + timedelta(days=2),
        collector_contract_version="secp-002b-1b-4/live-readonly-proxmox-collector/v1",
        endpoint_allowlist_version="secp-002b-1b-3/proxmox-readonly-allowlist/v1",
        evidence_source="live_readonly_proxmox",
        verification_level=VerificationLevel.live_verified.value,
        status=LiveReadAuthorizationStatus.approved,
        approved_by=approved_by,
        approved_at=now,
    )
    session.add(fresh)
    session.flush()
    result = run_real_eligibility_preflight(
        session,
        request=EligibilityPreflightRequest(
            organization_id=env.org_id,
            execution_target_id=env.target.id,
            onboarding_id=env.onboarding.id,
            authorization_id=fresh.id,
            authorization_version=fresh.authorization_version,
            worker_identity_registration_id=env.worker_reg.id,
        ),
        composition=EligibilityPreflightComposition(
            gate=EligibilityPreflightGate(enabled=True),
            live_read_gate=LiveReadCollectionGate(enabled=True),
            secret_resolver=_Resolver(),
            transport_factory=_transport_factory,
            collector=_BoundaryCollector(),
            authorization_verifier=_AllowVerifier(),
        ),
        now=now,
    )
    assert result.outcome == "eligible", result
    env.live_read_authorization = fresh
    from secp_api.models import TargetPreflight

    env.eligibility_preflight = session.get(TargetPreflight, result.preflight_id)
    session.flush()


def state_binding(session, env: ReadinessEnv, *, now: datetime = NOW) -> ReadinessBinding:
    result = load_readiness_binding(
        session,
        manifest_id=env.manifest.id,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=now,
        activation_dossier_hash=TEST_DOSSIER_HASH,
    )
    assert result.binding is not None, f"binding refused: {result.reason}"
    return result.binding


def adapter_activation(
    env: ReadinessEnv,
    binding: ReadinessBinding,
    adapter: object,
    *,
    operation_kind: ReadinessOperationKind,
    now: datetime = NOW,
    **over,
) -> AdapterActivation:
    """A clearly test-only REVIEWED activation for one exact adapter implementation + operation.

    It pins the adapter's IMPLEMENTATION digest, so a different implementation that merely claims
    the right ``contract_version`` obtains no capability.
    """
    fields: dict = {
        "adapter_registration_id": uuid.uuid4(),
        "adapter_kind": "fixture",
        "implementation_identity": implementation_identity(adapter),
        "adapter_contract_version": binding.adapter_contract_version,
        "operation_kind": operation_kind.value,
        "activation_dossier_hash": TEST_DOSSIER_HASH,
        "authorization_id": uuid.uuid4(),
        "authorization_version": 1,
        "authorization_expiry": now + timedelta(days=1),
        "organization_id": env.org_id,
        "execution_target_id": env.target.id,
        "target_onboarding_id": env.onboarding.id,
        "provisioning_manifest_id": env.manifest.id,
        "deployment_plan_id": env.plan.id,
        "worker_identity_registration_id": env.worker_reg.id,
        "worker_identity_version": env.worker_reg.identity_version,
        "expires_at": now + timedelta(days=1),
    }
    fields.update(over)
    return AdapterActivation(**fields)


# --- fake remote-state adapter (no I/O, NO state-body surface)
# -------------------------------------


# Opaque fixture issuer + proof ids. They are UUIDs, never labels: a label could BE a bucket name,
# a hostname, or a Vault mount, and an unsalted digest of one is a confirmation oracle for it.
FIXTURE_ISSUER = uuid.UUID("5ec9b1b4-0000-4000-8000-00000000f00d")


def healthy_report(binding: ReadinessBinding, *, now: datetime = NOW, **over) -> dict:
    """The kwargs of a fully-passing adapter report. Override any field to build a refusal case."""
    proof_common = {
        "toolchain_profile_hash": binding.toolchain_profile_hash,
        "namespace_hash": binding.state_namespace_identity,
        "performed_at": now - timedelta(days=1),
        "expires_at": now + timedelta(days=10),
    }
    fields: dict = {
        "backend_class": "remote",
        "backend_kind": "http",
        "toolchain_profile_hash": binding.toolchain_profile_hash,
        "namespace_identity": binding.state_namespace_identity,
        "tls_mode": "verified",
        "trusted_identity_policy": "pinned_ca_bundle",
        "certificate_validation_enabled": True,
        "proxy_inheritance_enabled": False,
        "redirect_observed": False,
        "destination_stable": True,
        "namespace_state_present": False,
        "expected_namespace_marker": "",
        "allowed_actions": ("read", "write", "lock", "unlock_own"),
        "scope_evidence_available": True,
        "local_fallback_available": False,
        "encryption": StateProof(proof_id=uuid.uuid4(), issuer=FIXTURE_ISSUER, **proof_common),
        "locking": LockCapabilityProof(
            proof_id=uuid.uuid4(),
            issuer=FIXTURE_ISSUER,
            performed_at=now - timedelta(minutes=5),
            toolchain_profile_hash=binding.toolchain_profile_hash,
            namespace_hash=binding.state_namespace_identity,
            lock_capability=True,
            contention_detected=True,
            force_unlock_available=False,
            caller_supplied_owner=False,
            probe_released=True,
            expires_at=now + timedelta(days=1),
        ),
        "backup": StateProof(proof_id=uuid.uuid4(), issuer=FIXTURE_ISSUER, **proof_common),
        "restore": StateProof(
            proof_id=uuid.uuid4(),
            issuer=FIXTURE_ISSUER,
            restore_tested=True,
            **proof_common,
        ),
        "reason_codes": (),
    }
    fields.update(over)
    return fields


class FakeStateAdapter:
    """An injected remote-state adapter. It performs NO I/O and exposes NO state-body method."""

    def __init__(self, report_fields: dict, *, contract_version: str | None = None):
        self._fields = report_fields
        self._contract = contract_version or REMOTE_STATE_ADAPTER_CONTRACT_VERSION
        self.calls: list[RemoteStateReadinessBinding] = []

    @property
    def contract_version(self) -> str:
        return self._contract

    def evaluate(self, binding: RemoteStateReadinessBinding, *, now) -> RemoteStateAdapterReport:
        self.calls.append(binding)
        return RemoteStateAdapterReport(**self._fields)


class RaisingStateAdapter:
    """Fails the test if it is reached before its gate."""

    @property
    def contract_version(self) -> str:
        return REMOTE_STATE_ADAPTER_CONTRACT_VERSION

    def evaluate(self, binding, *, now):
        raise AssertionError("state adapter reached before its gate")


class StateBodyAdapter(FakeStateAdapter):
    """An adapter that (illegally) exposes a state-body surface. It must be refused BEFORE use."""

    def read_state(self, *a, **k):  # pragma: no cover - must never be called
        raise AssertionError("state body was read")

    def upload_state(self, *a, **k):  # pragma: no cover - must never be called
        raise AssertionError("state body was written")

    def force_unlock(self, *a, **k):  # pragma: no cover - must never be called
        raise AssertionError("force-unlock was attempted")


# --- fake resolver self-test (no target credential, no backend body)
# -------------------------------


class FakeSelfTest:
    """An injected secret-backend self-test. It contacts nothing and returns no credential.

    ``proof_id`` is an EXPLICIT, opaque UUID — never the reason code, and never a label (a label
    could itself BE a Vault mount or a hostname).
    """

    _SENTINEL = object()

    def __init__(
        self,
        ok: bool = True,
        reason_code: str = "self_test_ok",
        proof_id: object = _SENTINEL,
    ):
        self._ok = ok
        self._reason = reason_code
        self._proof = uuid.uuid4() if proof_id is FakeSelfTest._SENTINEL else proof_id
        self.calls = 0

    def run(self, *, now) -> PlanSecretSelfTestResult:
        self.calls += 1
        return PlanSecretSelfTestResult(
            ok=self._ok,
            reason_code=self._reason,
            proof_id=self._proof,  # type: ignore[arg-type]
        )


class RaisingSelfTest:
    def run(self, *, now):
        raise AssertionError("secret backend reached before its gate")


def full_composition(
    *,
    state_adapter=None,
    self_test=None,
    resolver_contract: str | None = None,
    state_activation: AdapterActivation | None = None,
    plan_secret_activation: AdapterActivation | None = None,
    toolchain_layout=None,
    test_only: bool = False,
) -> ReadinessComposition:
    """The ONLY thing that unseals the readiness seam in tests (an out-of-band reviewed injection).

    An adapter WITHOUT a matching reviewed ``AdapterActivation`` obtains no capability and is
    refused before any contact — a self-declared ``contract_version`` is never sufficient.
    """
    return ReadinessComposition(
        gate=ReadinessGate(enabled=True),
        toolchain_layout=toolchain_layout,
        state_adapter=state_adapter,
        state_adapter_activation=state_activation,
        resolver_self_test=self_test,
        plan_secret_adapter_activation=plan_secret_activation,
        resolver_contract_version=(
            PLAN_SECRET_RESOLVER_CONTRACT_VERSION
            if resolver_contract is None
            else resolver_contract
        ),
        test_only_capability=test_only,
    )


def bare_activation(adapter, *, operation_kind: ReadinessOperationKind, now: datetime = NOW):
    """An activation bound to NOTHING real.

    For suites that must reach a gate BEHIND the capability check (the binding itself refuses
    first), where no authoritative binding exists to build a matching activation from.
    """
    contract = (
        REMOTE_STATE_ADAPTER_CONTRACT_VERSION
        if operation_kind is ReadinessOperationKind.remote_state_readiness
        else PLAN_SECRET_RESOLVER_CONTRACT_VERSION
    )
    return AdapterActivation(
        adapter_registration_id=uuid.uuid4(),
        adapter_kind="fixture",
        implementation_identity=implementation_identity(adapter),
        adapter_contract_version=contract,
        operation_kind=operation_kind.value,
        activation_dossier_hash=TEST_DOSSIER_HASH,
        authorization_id=uuid.uuid4(),
        authorization_version=1,
        authorization_expiry=now + timedelta(days=1),
        organization_id=uuid.uuid4(),
        execution_target_id=uuid.uuid4(),
        target_onboarding_id=uuid.uuid4(),
        provisioning_manifest_id=uuid.uuid4(),
        deployment_plan_id=uuid.uuid4(),
        worker_identity_registration_id=uuid.uuid4(),
        worker_identity_version=1,
        expires_at=now + timedelta(days=1),
    )


def state_composition(
    session, env: ReadinessEnv, adapter, *, now: datetime = NOW, activation=None, **over
):
    """A composition wired for the REMOTE-STATE operation with a matching reviewed activation."""
    binding = state_binding(session, env, now=now)
    return full_composition(
        state_adapter=adapter,
        state_activation=(
            activation
            if activation is not None
            else adapter_activation(
                env,
                binding,
                adapter,
                operation_kind=ReadinessOperationKind.remote_state_readiness,
                now=now,
            )
        ),
        **over,
    )


def plan_secret_composition(
    session, env: ReadinessEnv, self_test, *, now: datetime = NOW, activation=None, **over
):
    """A composition wired for the PLAN-SECRET operation with a matching reviewed activation.

    Every bound fact is shared with the remote-state binding EXCEPT the adapter contract version,
    which must be the RESOLVER contract: a live-read resolver contract can never satisfy this gate.
    """
    binding = state_binding(session, env, now=now)
    return full_composition(
        self_test=self_test,
        plan_secret_activation=(
            activation
            if activation is not None
            else adapter_activation(
                env,
                binding,
                self_test,
                operation_kind=ReadinessOperationKind.plan_secret_readiness,
                adapter_contract_version=PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
                now=now,
            )
        ),
        **over,
    )


# --- plan-secret authorization helper
# --------------------------------------------------------------


def approve_plan_secret_authorization(session, principal, manifest_id: uuid.UUID, **kwargs):
    """Create + fully evidence + approve a plan-secret authorization (the operator's explicit
    act)."""
    from secp_api.services import plan_secret_authorization as svc

    row = svc.create_plan_secret_authorization(
        session, principal, manifest_id=manifest_id, **kwargs
    )
    for kind in PlanSecretEvidenceKind:
        svc.record_plan_secret_evidence(
            session,
            principal,
            row.id,
            kind=kind,
            status=PlanSecretEvidenceStatus.verified,
            proof_id=f"proof-{kind.value[:20]}",
            issuer="secp-fake-reviewer",
        )
    return svc.approve_plan_secret_authorization(session, principal, row.id)


# --- assertion helpers
# ------------------------------------------------------------------------------


def audit_actions(session, org_id) -> list[str]:
    session.flush()
    return [
        e.action
        for e in session.execute(select(AuditEvent).where(AuditEvent.organization_id == org_id))
        .scalars()
        .all()
    ]


def audit_blob(session) -> str:
    session.flush()
    rows = session.execute(select(AuditEvent)).scalars().all()
    return " ".join(f"{e.action} {e.resource_type} {e.resource_id} {e.data}" for e in rows)


def db_text_blob(session) -> str:
    """Every text/JSON column of every readiness row + audit row, as one string."""
    from secp_api.models import (
        CredentialBinding,
        PlanSecretReadinessAuthorization,
        PlanSecretReadinessEvidence,
        PlanSecretReadinessRecord,
        PlanSecretResolutionLease,
        RemoteStateReadinessRecord,
        ToolchainAttestationRecord,
        WorkflowDispatchOutbox,
        WorkflowRun,
    )

    session.flush()
    chunks: list[str] = [audit_blob(session)]
    for model in (
        ToolchainAttestationRecord,
        CredentialBinding,
        RemoteStateReadinessRecord,
        PlanSecretReadinessRecord,
        PlanSecretReadinessAuthorization,
        PlanSecretReadinessEvidence,
        PlanSecretResolutionLease,
        WorkflowRun,
        WorkflowDispatchOutbox,
    ):
        for row in session.execute(select(model)).scalars().all():
            chunks.append(
                " ".join(
                    f"{c.name}={getattr(row, c.name)!r}"
                    for c in model.__table__.columns  # type: ignore[attr-defined]
                )
            )
    return " ".join(chunks)


def deep_copy(value):
    return copy.deepcopy(value)
