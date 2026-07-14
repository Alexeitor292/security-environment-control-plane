"""B1B-PR4 — plan-secret readiness refusal matrix + lease semantics (ADR-021 §G, §H, §I, §J, §K).

No real secret manager is contacted, no target provisioning credential is resolved, and no process
runs. The resolver self-test is an injected fake; the JIT projection is exercised with INERT
material.
"""

from __future__ import annotations

import dataclasses
from datetime import timedelta

import pytest
from secp_api.enums import (
    AuditAction,
    Permission,
    PlanSecretAuthorizationStatus,
    PlanSecretEvidenceKind,
    PlanSecretEvidenceStatus,
    PlanSecretPurpose,
    PlanSecretReadinessFacet,
    PlanSecretReadinessOutcome,
    ReadinessOperationKind,
    ReadinessReason,
    ResolutionLeaseStatus,
)
from secp_api.errors import AuthorizationError, ReadinessError
from secp_api.models import PlanSecretReadinessRecord, PlanSecretResolutionLease
from secp_api.readiness_contract import (
    MAX_ENV_VALUE_BYTES,
    PLAN_SECRET_ENV_ALLOWLIST,
    PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
    PurposeNotPermitted,
    assert_plan_only_purpose,
)
from secp_api.services import plan_secret_authorization as auth_svc
from secp_worker.preflight.secret_resolution import SecretMaterial
from secp_worker.readiness.composition import (
    ReadinessComposition,
    ReadinessGate,
    build_readiness_composition,
)
from secp_worker.readiness.plan_env import (
    PlanSecretEnvContract,
    PlanSecretEnvViolation,
    build_plan_secret_env,
)
from secp_worker.readiness.plan_secret_lease import (
    RETRY_BUDGET,
    PlanSecretLeaseRefused,
    PlanSecretOperationKey,
    acquire_lease,
    begin_attempt,
    mark_consumed,
)
from secp_worker.readiness.plan_secret_readiness import run_plan_secret_readiness
from sqlalchemy import select
from tests._readiness_fixtures import (  # type: ignore[import-not-found]
    NOW,
    SENTINEL_SECRET,
    FakeSelfTest,
    FakeStateAdapter,
    RaisingSelfTest,
    approve_plan_secret_authorization,
    audit_actions,
    audit_blob,
    bare_activation,
    build_readiness_env,
    full_composition,
    healthy_report,
    plan_secret_composition,
    state_binding,
    state_composition,
)

_F = PlanSecretReadinessFacet


@pytest.fixture
def env(session, principal, tmp_path):
    e = build_readiness_env(session, principal, toolchain_root=str(tmp_path))
    # Remote-state readiness must already be current: a plan-secret authorization can never be
    # created against an unproven state backend.
    binding = state_binding(session, e)
    from secp_worker.readiness.state_readiness import run_remote_state_readiness

    run_remote_state_readiness(
        session,
        manifest_id=e.manifest.id,
        composition=state_composition(session, e, FakeStateAdapter(healthy_report(binding))),
        now=NOW,
    )
    return e


def _run(session, env, *, self_test=None, composition=None, now=NOW):
    self_test = self_test or FakeSelfTest()
    composition = composition or plan_secret_composition(session, env, self_test)
    result = run_plan_secret_readiness(
        session, manifest_id=env.manifest.id, composition=composition, now=now
    )
    return result, self_test


# --- authorization lifecycle
# -----------------------------------------------------------------------


def test_no_dedicated_authorization_refuses(session, env):
    result, self_test = _run(session, env)
    assert result.reason_code == ReadinessReason.secret_authorization_missing.value
    assert self_test.calls == 0
    assert session.execute(select(PlanSecretReadinessRecord)).scalars().all() == []


def test_draft_authorization_refuses(session, principal, env):
    auth_svc.create_plan_secret_authorization(session, principal, manifest_id=env.manifest.id)
    result, self_test = _run(session, env, self_test=RaisingSelfTest())
    assert result.reason_code == ReadinessReason.secret_authorization_draft.value
    assert session.execute(select(PlanSecretResolutionLease)).scalars().all() == []


def test_revoked_authorization_refuses_immediately(session, principal, env):
    row = approve_plan_secret_authorization(session, principal, env.manifest.id)
    auth_svc.revoke_plan_secret_authorization(session, principal, row.id, "operator")
    session.flush()
    result, _ = _run(session, env, self_test=RaisingSelfTest())
    # A revoked authorization is no longer ACTIVE, so it is not even selected.
    assert result.reason_code == ReadinessReason.secret_authorization_missing.value
    assert AuditAction.plan_secret_authorization_revoked.value in audit_actions(session, env.org_id)


def test_expired_authorization_refuses(session, principal, env):
    from secp_api.readiness_contract import as_utc

    row = approve_plan_secret_authorization(session, principal, env.manifest.id, ttl_seconds=1)
    # Anchor to the authorization's OWN expiry: the lifecycle service stamps it from the real clock,
    # so a module-import-time constant would drift as the suite runs.
    later = as_utc(row.authorization_expiry) + timedelta(seconds=5)
    result, _ = _run(session, env, self_test=RaisingSelfTest(), now=later)
    assert result.reason_code == ReadinessReason.secret_authorization_expired.value
    assert row.status == PlanSecretAuthorizationStatus.approved  # never mutated by the worker


def test_approval_requires_a_dedicated_permission(session, principal, env):
    """``readiness:approve`` can never be inferred from ``readiness:manage`` or any other grant."""
    row = auth_svc.create_plan_secret_authorization(session, principal, manifest_id=env.manifest.id)
    for kind in PlanSecretEvidenceKind:
        auth_svc.record_plan_secret_evidence(
            session,
            principal,
            row.id,
            kind=kind,
            status=PlanSecretEvidenceStatus.verified,
            proof_id="p1",
            issuer="reviewer",
        )
    manager_only = dataclasses.replace(
        principal,
        permissions=frozenset(p for p in Permission if p is not Permission.readiness_approve),
    )
    with pytest.raises((ReadinessError, AuthorizationError)):
        auth_svc.approve_plan_secret_authorization(session, manager_only, row.id)


def test_approval_requires_a_complete_evidence_set(session, principal, env):
    row = auth_svc.create_plan_secret_authorization(session, principal, manifest_id=env.manifest.id)
    kinds = list(PlanSecretEvidenceKind)
    for kind in kinds[:-1]:  # one short
        auth_svc.record_plan_secret_evidence(
            session,
            principal,
            row.id,
            kind=kind,
            status=PlanSecretEvidenceStatus.verified,
            proof_id="p1",
            issuer="reviewer",
        )
    with pytest.raises(ReadinessError, match="evidence_incomplete"):
        auth_svc.approve_plan_secret_authorization(session, principal, row.id)


def test_creating_an_authorization_runs_no_readiness(session, principal, env):
    auth_svc.create_plan_secret_authorization(session, principal, manifest_id=env.manifest.id)
    assert session.execute(select(PlanSecretReadinessRecord)).scalars().all() == []
    assert session.execute(select(PlanSecretResolutionLease)).scalars().all() == []


def test_approving_an_authorization_runs_no_readiness(session, principal, env):
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    assert session.execute(select(PlanSecretReadinessRecord)).scalars().all() == []
    assert session.execute(select(PlanSecretResolutionLease)).scalars().all() == []


def test_evidence_proof_metadata_is_bounded_and_opaque(session, principal, env):
    row = auth_svc.create_plan_secret_authorization(session, principal, manifest_id=env.manifest.id)
    for bad in ("vault:secret/lab", "https://backend.invalid/x", "user@host", "a b", "x" * 200):
        with pytest.raises(ReadinessError, match="evidence_invalid"):
            auth_svc.record_plan_secret_evidence(
                session,
                principal,
                row.id,
                kind=PlanSecretEvidenceKind.independent_adversarial_review,
                status=PlanSecretEvidenceStatus.verified,
                proof_id=bad,
                issuer="reviewer",
            )


# --- purpose: PLAN-ONLY
# ------------------------------------------------------------------------------


@pytest.mark.parametrize("bad_purpose", ["apply", "destroy", "all", "plan_write", "", "PLAN_READ"])
def test_apply_and_destroy_purposes_are_refused(bad_purpose):
    with pytest.raises(PurposeNotPermitted):
        assert_plan_only_purpose(bad_purpose)


def test_only_plan_read_is_representable():
    assert [p.value for p in PlanSecretPurpose] == ["plan_read"]


def test_the_api_schema_cannot_express_an_apply_or_destroy_purpose():
    """Pydantic refuses the request body BEFORE any service code runs."""
    from pydantic import ValidationError
    from secp_api.schemas_readiness import CreatePlanSecretAuthorizationIn

    for bad in ("apply", "destroy", "all"):
        with pytest.raises(ValidationError):
            CreatePlanSecretAuthorizationIn(purpose=bad)  # type: ignore[arg-type]


def test_the_service_refuses_a_non_plan_read_purpose(session, principal, env):
    with pytest.raises(PurposeNotPermitted):
        auth_svc.create_plan_secret_authorization(
            session, principal, manifest_id=env.manifest.id, purpose="apply"
        )


def test_a_row_carrying_an_apply_purpose_is_refused_by_the_worker(session, principal, env):
    """Defence in depth: even a directly-written apply-purpose row can never authorize readiness."""
    row = approve_plan_secret_authorization(session, principal, env.manifest.id)
    session.execute(
        __import__("sqlalchemy")
        .update(type(row))
        .where(type(row).id == row.id)
        .values(purpose="apply")
    )
    session.flush()
    session.expire_all()
    result, self_test = _run(session, env, self_test=RaisingSelfTest())
    assert result.reason_code == ReadinessReason.secret_authorization_purpose_invalid.value
    assert session.execute(select(PlanSecretReadinessRecord)).scalars().all() == []


# --- binding drift
# ------------------------------------------------------------------------------------


def test_state_readiness_missing_refuses(session, principal, tmp_path):
    """A plan-secret authorization cannot even be created against an unproven state backend."""
    e = build_readiness_env(session, principal, toolchain_root=str(tmp_path))
    with pytest.raises(ReadinessError, match="invalid_state"):
        auth_svc.create_plan_secret_authorization(session, principal, manifest_id=e.manifest.id)

    result = run_plan_secret_readiness(
        session,
        manifest_id=e.manifest.id,
        composition=plan_secret_composition(session, e, RaisingSelfTest()),
        now=NOW,
    )
    assert result.reason_code == ReadinessReason.secret_state_readiness_missing.value


def test_state_readiness_expired_refuses(session, principal, env):
    from secp_api.readiness_contract import REMOTE_STATE_READINESS_TTL

    approve_plan_secret_authorization(session, principal, env.manifest.id, ttl_seconds=24 * 3600)
    later = NOW + REMOTE_STATE_READINESS_TTL + timedelta(minutes=1)
    result, _ = _run(session, env, self_test=RaisingSelfTest(), now=later)
    # The eligibility TTL (6h) equals the state TTL, so the binding refuses at whichever gate is
    # evaluated first — either way NOTHING is contacted and no evidence is written.
    assert result.reason_code in {
        ReadinessReason.eligibility_expired.value,
        ReadinessReason.secret_state_readiness_missing.value,
    }
    assert session.execute(select(PlanSecretReadinessRecord)).scalars().all() == []


def test_eligibility_not_eligible_refuses(session, principal):
    from tests.conftest import build_lab_env  # type: ignore[import-not-found]

    lab = build_lab_env(session, principal, secret_ref="vault:secp-fake-lab/plan-read")
    self_test = RaisingSelfTest()
    result = run_plan_secret_readiness(
        session,
        manifest_id=lab.manifest.id,
        # The AUTHORITATIVE binding refuses long before the capability is even considered.
        composition=full_composition(
            self_test=self_test,
            plan_secret_activation=bare_activation(
                self_test, operation_kind=ReadinessOperationKind.plan_secret_readiness
            ),
        ),
        now=NOW,
    )
    assert result.reason_code in {
        ReadinessReason.eligibility_missing.value,
        ReadinessReason.worker_identity_untrusted.value,
    }


def test_worker_identity_drift_refuses(session, principal, env):
    from secp_api.enums import WorkerIdentityStatus

    approve_plan_secret_authorization(session, principal, env.manifest.id)
    # The composition (and its reviewed activation) is built while the identity is STILL trusted, so
    # the refusal below can only come from the identity gate — never from a missing capability.
    composition = plan_secret_composition(session, env, RaisingSelfTest())
    env.worker_reg.status = WorkerIdentityStatus.revoked
    env.worker_reg.revoked_by = principal.user_id
    env.worker_reg.revoked_at = NOW
    session.flush()
    result, _ = _run(session, env, composition=composition)
    assert result.reason_code in {
        ReadinessReason.worker_identity_untrusted.value,
        ReadinessReason.eligibility_drifted.value,
    }


def test_resolver_contract_mismatch_refuses(session, principal, env):
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    composition = plan_secret_composition(
        session, env, RaisingSelfTest(), resolver_contract="some-other-resolver/v9"
    )
    result = run_plan_secret_readiness(
        session, manifest_id=env.manifest.id, composition=composition, now=NOW
    )
    assert result.reason_code == ReadinessReason.resolver_contract_mismatch.value
    assert session.execute(select(PlanSecretResolutionLease)).scalars().all() == []


# --- credential-reference scheme
# ------------------------------------------------------------------------


def test_unsupported_reference_scheme_refuses(session, principal, tmp_path):
    """An ``env:`` reference is a development-only scheme and can never back a plan-read
    credential."""
    e = build_readiness_env(
        session, principal, toolchain_root=str(tmp_path), secret_ref="env:SECP_PROVIDER_SECRET__LAB"
    )
    binding = state_binding(session, e)
    from secp_worker.readiness.state_readiness import run_remote_state_readiness

    run_remote_state_readiness(
        session,
        manifest_id=e.manifest.id,
        composition=state_composition(session, e, FakeStateAdapter(healthy_report(binding))),
        now=NOW,
    )
    # The authorization itself cannot be created: the scheme is derived server-side and refused
    # only at readiness time; creation records the (env) scheme, and the worker then refuses.
    approve_plan_secret_authorization(session, principal, e.manifest.id)
    result = run_plan_secret_readiness(
        session,
        manifest_id=e.manifest.id,
        composition=plan_secret_composition(session, e, RaisingSelfTest()),
        now=NOW,
    )
    assert result.reason_code == ReadinessReason.credential_reference_scheme_unsupported.value


# --- resolver seal + self-test
# -----------------------------------------------------------------------


def test_shipped_default_composition_is_sealed(session, principal, env):
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    composition = build_readiness_composition()
    assert composition.gate.enabled is False
    assert composition.resolver_self_test is None
    assert composition.resolver_contract_version == ""

    result = run_plan_secret_readiness(
        session, manifest_id=env.manifest.id, composition=composition, now=NOW
    )
    assert result.reason_code == ReadinessReason.sealed.value
    assert session.execute(select(PlanSecretResolutionLease)).scalars().all() == []
    assert session.execute(select(PlanSecretReadinessRecord)).scalars().all() == []


def test_sealed_resolver_self_test_yields_unavailable(session, principal, env):
    from secp_worker.preflight.backends.openbao_resolver import SealedResolverSelfTest

    approve_plan_secret_authorization(session, principal, env.manifest.id)
    result, _ = _run(session, env, self_test=SealedResolverSelfTest())
    assert result.outcome == PlanSecretReadinessOutcome.unavailable.value
    row = session.get(PlanSecretReadinessRecord, result.record_id)
    facet = next(f for f in row.facets if f["facet"] == _F.backend_authentication_readiness.value)
    assert facet["status"] == "unverifiable"


def test_missing_self_test_with_an_enabled_gate_still_refuses(session, principal, env):
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    composition = ReadinessComposition(
        gate=ReadinessGate(enabled=True),
        resolver_self_test=None,
        resolver_contract_version=PLAN_SECRET_RESOLVER_CONTRACT_VERSION,
    )
    result = run_plan_secret_readiness(
        session, manifest_id=env.manifest.id, composition=composition, now=NOW
    )
    assert result.reason_code == ReadinessReason.resolver_sealed.value


def test_a_self_test_leaking_backend_details_is_refused(session, principal, env):
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    leaky = FakeSelfTest(ok=True, reason_code="https://vault.invalid/v1/secret/lab?token=abc")
    result, _ = _run(session, env, self_test=leaky)
    row = session.get(PlanSecretReadinessRecord, result.record_id)
    facet = next(f for f in row.facets if f["facet"] == _F.backend_authentication_readiness.value)
    assert facet["status"] == "fail"
    assert ReadinessReason.resolver_self_test_leaked_details.value in row.reason_codes
    assert row.self_test_proof_id is None
    blob = audit_blob(session)
    assert "vault.invalid" not in blob
    assert "token=abc" not in blob


def test_a_raising_self_test_never_leaks_the_exception(session, principal, env):
    class _Boom:
        def run(self, *, now):
            raise RuntimeError("https://vault.invalid/v1/auth?token=SUPERSECRET")

    approve_plan_secret_authorization(session, principal, env.manifest.id)
    result, _ = _run(session, env, self_test=_Boom())
    assert result.reason_code == ReadinessReason.resolver_self_test_unavailable.value
    blob = audit_blob(session)
    assert "vault.invalid" not in blob
    assert "SUPERSECRET" not in blob


def test_the_real_target_credential_is_never_resolved(session, principal, env, monkeypatch):
    """``WorkerSecretResolver.resolve()`` is NEVER called by the readiness path."""
    from secp_worker.preflight import secret_resolution

    def _trap(*a, **k):  # pragma: no cover - must never run
        raise AssertionError("a target provisioning credential was resolved")

    monkeypatch.setattr(secret_resolution.SealedUnavailableResolver, "resolve", _trap)
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    result, _ = _run(session, env)
    assert result.outcome == PlanSecretReadinessOutcome.ready.value


# --- lease semantics
# ---------------------------------------------------------------------------------


def test_no_secret_backend_contact_before_begin_attempt(session, principal, env):
    """The lease's begin_attempt is the LAST thing before the secret boundary."""
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    calls: list[str] = []

    class _Ordered:
        def run(self, *, now):
            lease = session.execute(select(PlanSecretResolutionLease)).scalars().one()
            # The attempt budget MUST already be consumed when the backend is first touched.
            assert lease.attempt_count == 1
            calls.append("self_test")
            return FakeSelfTest().run(now=now)

    result, _ = _run(session, env, self_test=_Ordered())
    assert calls == ["self_test"]
    assert result.outcome == PlanSecretReadinessOutcome.ready.value


def test_lease_replay_after_consumption_is_refused(session, principal, env):
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    first, _ = _run(session, env)
    assert first.outcome == PlanSecretReadinessOutcome.ready.value
    lease = session.execute(select(PlanSecretResolutionLease)).scalars().one()
    assert lease.status == ResolutionLeaseStatus.consumed

    with pytest.raises(PlanSecretLeaseRefused) as exc:
        begin_attempt(session, lease, now=NOW)
    assert exc.value.reason.value == "replay_refused"


def test_retry_budget_is_bounded_and_never_reset(session, principal, env):
    row = approve_plan_secret_authorization(session, principal, env.manifest.id)
    key = PlanSecretOperationKey(
        authorization_id=row.id,
        authorization_version=row.authorization_version,
        operation_fingerprint="sha256:" + "f" * 64,
    )
    lease = acquire_lease(
        session,
        organization_id=env.org_id,
        key=key,
        worker_identity_id="w1",
        authorization_expiry=row.authorization_expiry,
        now=NOW,
    )
    for i in range(RETRY_BUDGET):
        begin_attempt(session, lease, now=NOW)
        assert lease.attempt_count == i + 1
    with pytest.raises(PlanSecretLeaseRefused) as exc:
        begin_attempt(session, lease, now=NOW)
    assert exc.value.reason.value == "retry_bound_exceeded"
    assert lease.status == ResolutionLeaseStatus.exhausted

    # A NEW lease instance never resets the durable budget.
    with pytest.raises(PlanSecretLeaseRefused):
        acquire_lease(
            session,
            organization_id=env.org_id,
            key=key,
            worker_identity_id="w2",
            authorization_expiry=row.authorization_expiry,
            now=NOW,
        )


def test_a_second_worker_identity_cannot_open_a_duplicate_budget(session, principal, env):
    """Worker identity is deliberately NOT part of the lease uniqueness key."""
    row = approve_plan_secret_authorization(session, principal, env.manifest.id)
    key = PlanSecretOperationKey(
        authorization_id=row.id,
        authorization_version=row.authorization_version,
        operation_fingerprint="sha256:" + "a" * 64,
    )
    acquire_lease(
        session,
        organization_id=env.org_id,
        key=key,
        worker_identity_id="worker-a",
        authorization_expiry=row.authorization_expiry,
        now=NOW,
    )
    with pytest.raises(PlanSecretLeaseRefused) as exc:
        acquire_lease(
            session,
            organization_id=env.org_id,
            key=key,
            worker_identity_id="worker-b",
            authorization_expiry=row.authorization_expiry,
            now=NOW,
        )
    assert exc.value.reason.value == "lease_held"
    assert len(session.execute(select(PlanSecretResolutionLease)).scalars().all()) == 1


def test_an_expired_lease_is_replaced_without_resetting_the_budget(session, principal, env):
    row = approve_plan_secret_authorization(session, principal, env.manifest.id, ttl_seconds=7200)
    key = PlanSecretOperationKey(
        authorization_id=row.id,
        authorization_version=row.authorization_version,
        operation_fingerprint="sha256:" + "b" * 64,
    )
    lease = acquire_lease(
        session,
        organization_id=env.org_id,
        key=key,
        worker_identity_id="w1",
        authorization_expiry=row.authorization_expiry,
        now=NOW,
    )
    begin_attempt(session, lease, now=NOW)
    assert lease.attempt_count == 1

    later = NOW + timedelta(seconds=600)  # past the 120s lease TTL, inside the authorization
    lease2 = acquire_lease(
        session,
        organization_id=env.org_id,
        key=key,
        worker_identity_id="w2",
        authorization_expiry=row.authorization_expiry,
        now=later,
    )
    assert lease2.id == lease.id
    assert lease2.attempt_count == 1  # the durable budget is PRESERVED, never reset


def test_a_failure_never_becomes_a_consumed_success(session, principal, env):
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    result, _ = _run(session, env, self_test=FakeSelfTest(ok=False, reason_code="backend_down"))
    assert result.outcome == PlanSecretReadinessOutcome.unavailable.value
    lease = session.execute(select(PlanSecretResolutionLease)).scalars().one()
    assert lease.status == ResolutionLeaseStatus.active  # NOT consumed
    assert lease.consumed_at is None


def test_mark_consumed_refuses_on_a_non_active_lease(session, principal, env):
    row = approve_plan_secret_authorization(session, principal, env.manifest.id)
    key = PlanSecretOperationKey(
        authorization_id=row.id,
        authorization_version=row.authorization_version,
        operation_fingerprint="sha256:" + "c" * 64,
    )
    lease = acquire_lease(
        session,
        organization_id=env.org_id,
        key=key,
        worker_identity_id="w1",
        authorization_expiry=row.authorization_expiry,
        now=NOW,
    )
    begin_attempt(session, lease, now=NOW)
    mark_consumed(session, lease, now=NOW)
    before = (lease.status, lease.revision, lease.attempt_count)
    with pytest.raises(PlanSecretLeaseRefused):
        mark_consumed(session, lease, now=NOW)
    assert (lease.status, lease.revision, lease.attempt_count) == before  # no state change


# --- JIT environment projection (§K)
# --------------------------------------------------------------------


def test_the_projection_returns_only_the_allowlisted_variable():
    env_map = build_plan_secret_env(
        SecretMaterial(SENTINEL_SECRET), contract=PlanSecretEnvContract()
    )
    assert set(env_map) == set(PLAN_SECRET_ENV_ALLOWLIST)


def test_an_arbitrary_environment_key_is_refused():
    with pytest.raises(PlanSecretEnvViolation):
        build_plan_secret_env(
            SecretMaterial(SENTINEL_SECRET),
            contract=PlanSecretEnvContract(variable_names=("PATH",)),
        )
    with pytest.raises(PlanSecretEnvViolation):
        build_plan_secret_env(
            SecretMaterial(SENTINEL_SECRET),
            contract=PlanSecretEnvContract(variable_names=("TF_VAR_pm_api_token", "HOME")),
        )


def test_duplicate_and_case_colliding_keys_are_refused():
    with pytest.raises(PlanSecretEnvViolation, match="duplicate"):
        build_plan_secret_env(
            SecretMaterial(SENTINEL_SECRET),
            contract=PlanSecretEnvContract(
                variable_names=("TF_VAR_pm_api_token", "TF_VAR_pm_api_token")
            ),
        )
    with pytest.raises(PlanSecretEnvViolation):
        build_plan_secret_env(
            SecretMaterial(SENTINEL_SECRET),
            contract=PlanSecretEnvContract(
                variable_names=("TF_VAR_pm_api_token", "tf_var_pm_api_token")
            ),
        )


@pytest.mark.parametrize("bad", ["a\x00b", "a\nb", "a\rb"])
def test_nul_and_newline_values_are_refused(bad):
    with pytest.raises(PlanSecretEnvViolation, match="control character"):
        build_plan_secret_env(SecretMaterial(bad), contract=PlanSecretEnvContract())


def test_an_oversized_value_is_refused():
    with pytest.raises(PlanSecretEnvViolation, match="bounded size"):
        build_plan_secret_env(
            SecretMaterial("x" * (MAX_ENV_VALUE_BYTES + 1)), contract=PlanSecretEnvContract()
        )


def test_a_raw_string_is_refused_only_typed_opaque_material_is_accepted():
    with pytest.raises(PlanSecretEnvViolation, match="SecretMaterial"):
        build_plan_secret_env(SENTINEL_SECRET, contract=PlanSecretEnvContract())  # type: ignore[arg-type]


def test_the_projection_never_imports_os():
    """No ``os`` import means no ambient environment to inherit and no global to mutate."""
    import ast
    import pathlib

    src = pathlib.Path("apps/worker/secp_worker/readiness/plan_env.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(a.name.split(".")[0] != "os" for a in node.names)
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] != "os"


def test_secret_material_is_redacted_and_non_serializable():
    material = SecretMaterial(SENTINEL_SECRET)
    assert SENTINEL_SECRET not in repr(material)
    assert SENTINEL_SECRET not in str(material)
    assert SENTINEL_SECRET not in f"{material}"
    import pickle

    with pytest.raises(TypeError):
        pickle.dumps(material)


# --- evidence + audit safety
# ----------------------------------------------------------------------------


def test_the_sentinel_never_reaches_the_database_or_the_audit_log(session, principal, env):
    from tests._readiness_fixtures import db_text_blob

    approve_plan_secret_authorization(session, principal, env.manifest.id)
    _run(session, env)
    blob = db_text_blob(session)
    assert SENTINEL_SECRET not in blob
    assert "secp-inert-readiness-canary" not in blob
    assert "TF_VAR_pm_api_token" not in blob
    assert "vault:" not in blob
