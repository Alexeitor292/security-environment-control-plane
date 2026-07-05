"""SECP-B2-4.4 — load-bearing durable registered worker identity in the sealed preflight chain.

Proves the durable registered worker identity is MANDATORY and verified BEFORE the activation
capability and any lease: the shipped deny default ignores a valid durable registration; a valid
durable identity is verified before the activation check; a cross-org identity fails closed; and a
valid durable identity reaches the sealed resolver boundary (and nothing beyond it). Fake-only:
nothing contacts a backend, resolves a secret, or constructs a transport.
"""

from __future__ import annotations

from secp_api.enums import (
    IsolationModel,
    OnboardingMode,
    OnboardingStatus,
    ReadonlyPreflightOutcome,
    ResolverActivationEvidenceKind,
    ResolverActivationEvidenceStatus,
    TargetStatus,
    WorkerIdentityMechanism,
)
from secp_api.models import ExecutionTarget, ResolutionLease, TargetOnboarding
from secp_api.services import readonly_preflight, resolver_activation, staging_labs
from secp_worker.preflight.orchestration import run_readonly_preflight
from secp_worker.preflight.sealed_secret_resolver import SealedSecretResolver
from secp_worker.preflight.worker_identity_attestation import (
    RegisteredWorkerIdentityVerifier,
    WorkerIdentityClaim,
)

OPAQUE_REF = "env:SECP_PROVIDER_SECRET__PREFLIGHT"
UNAVAILABLE = ReadonlyPreflightOutcome.credential_unavailable


class _ApprovedGate:
    def check(self) -> None:
        return None


def _substrate(session, principal) -> ExecutionTarget:
    target = ExecutionTarget(
        organization_id=principal.organization_id,
        display_name="staging substrate",
        plugin_name="proxmox",
        config={"base_url": "placeholder", "verify_tls": True},
        config_hash="sha256:" + "ab" * 32,
        secret_ref=OPAQUE_REF,
        status=TargetStatus.active,
        scope_policy={},
        created_by=principal.user_id,
    )
    session.add(target)
    session.flush()
    session.add(
        TargetOnboarding(
            organization_id=principal.organization_id,
            execution_target_id=target.id,
            onboarding_mode=OnboardingMode.existing_environment,
            isolation_model=IsolationModel.logical,
            status=OnboardingStatus.active,
            declared_boundary={},
            boundary_hash="sha256:" + "cd" * 32,
            created_by=principal.user_id,
        )
    )
    session.flush()
    staging_labs.grant_substrate_eligibility(session, principal, execution_target_id=target.id)
    return target


def _queued(session, principal):
    target = _substrate(session, principal)
    auth = readonly_preflight.create_preflight_authorization(
        session, principal, execution_target_id=target.id
    )
    readonly_preflight.approve_preflight_authorization(session, principal, auth.id)
    return readonly_preflight.queue_preflight(
        session, principal, live_read_authorization_id=auth.id
    )


def _approved_activation(session, principal, pf):
    row = resolver_activation.create_activation_authorization(
        session, principal, preflight_id=pf.id
    )
    for kind in ResolverActivationEvidenceKind:
        resolver_activation.record_evidence(
            session,
            principal,
            row.id,
            kind=kind,
            status=ResolverActivationEvidenceStatus.verified,
            proof_id="TKT-1",
            issuer="reviewer",
        )
    resolver_activation.approve_activation_authorization(session, principal, row.id)


def _no_lease(session) -> bool:
    session.flush()
    return session.query(ResolutionLease).count() == 0


def test_shipped_deny_default_ignores_a_valid_durable_registration(
    session, principal, worker_identity_verifier
):
    # Even with a VALID approved durable registration + activation present, the SHIPPED default
    # (deny) stops the run before the activation capability and any lease — a durable registration
    # never trusted without the (unwired) registered verifier.
    worker_identity_verifier()  # create the durable approved registration
    pf = _queued(session, principal)
    _approved_activation(session, principal, pf)
    result = run_readonly_preflight(session, pf.id, secret_resolver=SealedSecretResolver())
    assert result.outcome == UNAVAILABLE
    assert _no_lease(session)


def test_durable_identity_is_verified_before_activation_capability(
    session, principal, worker_identity_verifier
):
    # Valid durable identity + approved gate, but NO activation authorization: the identity is
    # verified (passes) and the run then fails closed at the activation-capability check, BEFORE any
    # lease — proving the durable identity is verified before activation capability.
    verifier = worker_identity_verifier()
    pf = _queued(session, principal)  # no activation authorization created
    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=SealedSecretResolver(),
        identity_verifier=verifier,
        activation_gate=_ApprovedGate(),
    )
    assert result.outcome == UNAVAILABLE
    assert _no_lease(session)


def test_cross_org_identity_fails_closed_before_lease(
    session, principal, other_org_principal, worker_identity_verifier
):
    # A durable-backed verifier whose claim asserts a FOREIGN organization, run against a preflight
    # the principal's org, fails closed (cross-org) before the activation capability and any lease.
    worker_identity_verifier()  # a valid registration exists in the preflight's org

    class _ForeignOrgSource:
        def attest(self, *, preflight, now):
            return WorkerIdentityClaim(
                organization_id=other_org_principal.organization_id,  # a DIFFERENT org
                mechanism=WorkerIdentityMechanism.mtls_workload_identity.value,
                identity_label="staging-worker-a",
                deployment_binding="deploy-01",
                identity_version=1,
                public_anchor="test-public-anchor-v1",
            )

    pf = _queued(session, principal)
    _approved_activation(session, principal, pf)
    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=SealedSecretResolver(),
        identity_verifier=RegisteredWorkerIdentityVerifier(_ForeignOrgSource()),
        activation_gate=_ApprovedGate(),
    )
    assert result.outcome == UNAVAILABLE
    assert _no_lease(session)


def test_valid_durable_identity_reaches_sealed_resolver_boundary_only(
    session, principal, worker_identity_verifier
):
    # Valid durable identity + gate + activation -> reaches the lease (identity load-bearing works),
    # then the SEALED resolver still fails closed. The lease records the DURABLE identity label; no
    # secret material, transport, or contact is produced.
    verifier = worker_identity_verifier()
    pf = _queued(session, principal)
    _approved_activation(session, principal, pf)
    result = run_readonly_preflight(
        session,
        pf.id,
        secret_resolver=SealedSecretResolver(),
        identity_verifier=verifier,
        activation_gate=_ApprovedGate(),
    )
    assert result.outcome == UNAVAILABLE
    assert result.readiness_facts is None
    lease = session.query(ResolutionLease).one()
    assert lease.worker_identity_id == "staging-worker-a"  # the durable registration's label
    assert lease.attempt_count == 1
