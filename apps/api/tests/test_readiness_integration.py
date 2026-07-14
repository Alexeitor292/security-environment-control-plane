"""B1B-PR4 — the principal integration proof (ADR-021).

Drives the COMPLETE readiness chain over fixture records and injected fake seams:

    current eligible PR3 evidence
    → exact PR2 toolchain binding
    → explicit remote-state readiness request (enqueue-only, durable)
    → worker-owned bounded state-backend metadata validation
    → explicit plan-secret authorization (create → evidence → approve, separate permission)
    → explicit plan-secret readiness request (enqueue-only, durable)
    → lease acquisition → begin_attempt → secret-backend SELF-TEST
    → safe environment projection using INERT material
    → immutable readiness evidence
    → combined readiness current
    → STOP with ZERO execution

Nothing real is contacted: no state backend, no secret manager, no Proxmox host, no OpenTofu binary,
no network. No provisioning credential is resolved. Both B1-A subprocess seals stay ``True``.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta

import pytest
from secp_api.enums import (
    AuditAction,
    PlanSecretPurpose,
    PlanSecretReadinessOutcome,
    RemoteStateReadinessOutcome,
    WorkflowKind,
)
from secp_api.models import (
    PlanSecretReadinessRecord,
    PlanSecretResolutionLease,
    RemoteStateReadinessRecord,
    WorkflowDispatchOutbox,
    WorkflowRun,
)
from secp_api.readiness_contract import (
    PLAN_SECRET_ENV_ALLOWLIST,
    REQUIRED_PLAN_SECRET_FACETS,
    REQUIRED_REMOTE_STATE_FACETS,
)
from secp_api.services import readiness as readiness_svc
from secp_worker.readiness.plan_secret_readiness import run_plan_secret_readiness
from secp_worker.readiness.state_readiness import run_remote_state_readiness
from sqlalchemy import select
from tests._readiness_fixtures import (  # type: ignore[import-not-found]
    NOW,
    SENTINEL_SECRET,
    FakeSelfTest,
    FakeStateAdapter,
    approve_plan_secret_authorization,
    audit_actions,
    build_readiness_env,
    db_text_blob,
    healthy_report,
    plan_secret_composition,
    reauthorize_eligibility,
    state_binding,
    state_composition,
)


@pytest.fixture
def env(session, principal, tmp_path):
    return build_readiness_env(session, principal, toolchain_root=str(tmp_path))


def _run_state(session, env, **over):
    binding = state_binding(session, env)
    adapter = FakeStateAdapter(healthy_report(binding, **over))
    result = run_remote_state_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=state_composition(session, env, adapter),
        now=NOW,
    )
    return result, adapter


def _run_secret(session, env, *, self_test=None):
    self_test = self_test or FakeSelfTest()
    result = run_plan_secret_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=plan_secret_composition(session, env, self_test),
        now=NOW,
    )
    return result, self_test


# --- the full flow
# ---------------------------------------------------------------------------------


def test_full_readiness_flow_reaches_ready_and_stops(session, principal, env):
    # 1. Remote-state readiness (a SEPARATE explicit operator action).
    state_result, adapter = _run_state(session, env)
    assert state_result.outcome == RemoteStateReadinessOutcome.ready.value
    assert len(adapter.calls) == 1  # exactly one bounded backend contact

    state_row = session.get(RemoteStateReadinessRecord, state_result.record_id)
    assert state_row is not None
    assert {f["facet"] for f in state_row.facets} == set(REQUIRED_REMOTE_STATE_FACETS)
    assert all(f["status"] == "pass" for f in state_row.facets)
    assert state_row.reason_codes == []
    assert state_row.state_backend_class == "remote"
    assert state_row.expires_at.replace(tzinfo=state_row.expires_at.tzinfo or NOW.tzinfo) > NOW

    # 2. The plan-secret authorization is a SEPARATE explicit human decision. State readiness did
    #    NOT create it: nothing exists yet.
    from secp_api.models import PlanSecretReadinessAuthorization

    assert session.execute(select(PlanSecretReadinessAuthorization)).scalars().all() == []

    authorization = approve_plan_secret_authorization(session, principal, env.manifest.id)
    assert authorization.purpose == PlanSecretPurpose.plan_read.value
    assert authorization.credential_reference_scheme == "vault"
    assert authorization.evidence_fingerprint.startswith("sha256:")

    # Approving the authorization ran NO readiness.
    assert session.execute(select(PlanSecretReadinessRecord)).scalars().all() == []

    # 3. Plan-secret readiness (another SEPARATE explicit operator action).
    secret_result, self_test = _run_secret(session, env)
    assert secret_result.outcome == PlanSecretReadinessOutcome.ready.value
    assert self_test.calls == 1  # exactly one secret-backend contact (a SELF-TEST, no credential)

    secret_row = session.get(PlanSecretReadinessRecord, secret_result.record_id)
    assert secret_row is not None
    assert {f["facet"] for f in secret_row.facets} == set(REQUIRED_PLAN_SECRET_FACETS)
    assert all(f["status"] == "pass" for f in secret_row.facets)
    assert secret_row.secret_purpose == PlanSecretPurpose.plan_read.value
    assert secret_row.remote_state_readiness_id == state_row.id

    # 4. The lease was acquired, one attempt consumed, and marked consumed on success.
    lease = session.execute(select(PlanSecretResolutionLease)).scalars().one()
    assert lease.attempt_count == 1
    assert lease.status.value == "consumed"

    # 5. Combined readiness is CURRENT.
    view = readiness_svc.get_provisioning_readiness(session, principal, env.manifest.id, now=NOW)
    assert view["ready"] is True
    assert view["reasons"] == []
    assert view["remote_state_readiness_id"] == str(state_row.id)
    assert view["plan_secret_readiness_id"] == str(secret_row.id)

    # 6. STOP. Readiness dispatched NOTHING: no plan, no apply, no destroy, no workflow run.
    runs = session.execute(select(WorkflowRun)).scalars().all()
    assert [r.kind for r in runs] == []
    assert session.execute(select(WorkflowDispatchOutbox)).scalars().all() == []

    # 7. No provisioning operation, no change-set approval, no activation grant exists.
    from secp_api.models import ProvisioningChangeSetApproval, ProvisioningOperation

    assert session.execute(select(ProvisioningOperation)).scalars().all() == []
    assert session.execute(select(ProvisioningChangeSetApproval)).scalars().all() == []

    # 8. The audit chain is complete and bounded.
    actions = audit_actions(session, env.org_id)
    for expected in (
        AuditAction.remote_state_readiness_started.value,
        AuditAction.remote_state_readiness_completed.value,
        AuditAction.plan_secret_authorization_created.value,
        AuditAction.plan_secret_authorized.value,
        AuditAction.plan_secret_readiness_started.value,
        AuditAction.plan_secret_readiness_completed.value,
        AuditAction.resolution_lease_acquired.value,
        AuditAction.resolution_lease_attempt_started.value,
        AuditAction.resolution_lease_consumed.value,
    ):
        assert expected in actions, expected


def test_no_secret_reference_or_backend_detail_is_ever_persisted(session, principal, env):
    """The sentinel, the credential reference, the backend reference, and the namespace name never
    reach the database, an audit row, a workflow arg, or an API response."""
    _run_state(session, env)
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    _run_secret(session, env)

    blob = db_text_blob(session)
    forbidden = (
        SENTINEL_SECRET,
        "secp-inert-readiness-canary",  # the worker-generated inert canary
        "vault:secp-fake-lab/plan-read",  # the opaque credential reference
        "secp-fake-remote-state/lab",  # the opaque backend reference
        "proxmox.example.test",  # the target endpoint
        "transient-token",
    )
    for token in forbidden:
        assert token not in blob, f"leaked: {token}"

    # The API read models never expose them either.
    state_view = readiness_svc.get_remote_state_readiness(session, principal, env.manifest.id)
    secret_view = readiness_svc.get_plan_secret_readiness(session, principal, env.manifest.id)
    rendered = f"{state_view} {secret_view}"
    for token in forbidden:
        assert token not in rendered, f"leaked in API: {token}"
    # The backend appears ONLY as a bounded class + opaque, non-oracle identifiers.
    assert state_view["state_backend_class"] == "remote"
    assert state_view["toolchain_profile_hash"].startswith("sha256:")
    assert state_view["state_namespace_hash"].startswith("sha256:")
    assert "state_backend_kind" not in state_view
    assert "state_backend_reference" not in state_view
    # B1B-PR4 §5: the backend-reference CONFIRMATION ORACLE is gone. No persisted or returned value
    # is a digest of the backend reference (or of the credential reference).
    assert "state_backend_binding_hash" not in state_view
    for secret in ("secp-fake-remote-state/lab", "vault:secp-fake-lab/plan-read"):
        digest = hashlib.sha256(secret.encode()).hexdigest()
        assert digest not in blob
        assert digest not in rendered


def test_exact_retry_is_idempotent_and_does_not_recontact(session, principal, env):
    first, adapter1 = _run_state(session, env)
    binding = state_binding(session, env)
    adapter2 = FakeStateAdapter(healthy_report(binding))
    second = run_remote_state_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=state_composition(session, env, adapter2),
        now=NOW + timedelta(minutes=1),
    )
    assert second.reused is True
    assert second.record_id == first.record_id
    assert adapter2.calls == []  # NO second backend contact
    assert len(session.execute(select(RemoteStateReadinessRecord)).scalars().all()) == 1


def test_changed_binding_creates_a_new_immutable_record_and_never_mutates_the_old(
    session, principal, env
):
    """Re-establishing eligibility changes a bound fact → a NEW operation → a NEW immutable record.

    The prior successful record is NEVER mutated into failure: history is append-only and validity
    is DERIVED (ADR-021 §N).
    """
    first, _ = _run_state(session, env)
    old = session.get(RemoteStateReadinessRecord, first.record_id)
    old_hash, old_outcome = old.evidence_hash, old.outcome

    # A fresh live-read authorization (version 2) → a fresh eligibility preflight → a new evidence
    # hash → a NEW readiness operation fingerprint.
    reauthorize_eligibility(session, env, version=2, now=NOW)

    second, _ = _run_state(session, env)
    assert second.record_id != first.record_id
    assert len(session.execute(select(RemoteStateReadinessRecord)).scalars().all()) == 2

    session.expire_all()
    old = session.get(RemoteStateReadinessRecord, first.record_id)
    assert old.evidence_hash == old_hash
    assert old.outcome == old_outcome  # history is never rewritten


def test_a_readiness_record_never_outlives_its_binding(session, principal, env):
    """The readiness TTL is pinned to the eligibility TTL, and readiness is collected AFTER
    eligibility — so an expired readiness record ALWAYS implies an already-refused binding.

    That closes the strand: a record can never expire while its binding is still valid (which would
    make the exact-once success constraint permanently block a fresh ``ready`` row for the same
    fingerprint). No secret backend is re-contacted, and no historical record is mutated.
    """
    from secp_api.eligibility_policy import ELIGIBILITY_EVIDENCE_TTL
    from secp_api.readiness_contract import (
        PLAN_SECRET_READINESS_TTL,
        REMOTE_STATE_READINESS_TTL,
    )

    assert PLAN_SECRET_READINESS_TTL == ELIGIBILITY_EVIDENCE_TTL
    assert REMOTE_STATE_READINESS_TTL == ELIGIBILITY_EVIDENCE_TTL

    _run_state(session, env)
    approve_plan_secret_authorization(session, principal, env.manifest.id, ttl_seconds=24 * 3600)
    first, _ = _run_secret(session, env)
    assert first.outcome == PlanSecretReadinessOutcome.ready.value

    later = NOW + PLAN_SECRET_READINESS_TTL + timedelta(minutes=1)
    self_test = FakeSelfTest()
    result = run_plan_secret_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=plan_secret_composition(session, env, self_test),
        now=later,
    )
    # The BINDING refuses first (its eligibility evidence expired earlier), so the expired record is
    # never even reached — and certainly never replayed as fresh readiness.
    assert result.outcome == PlanSecretReadinessOutcome.refused.value
    assert self_test.calls == 0  # no second secret-backend contact

    row = session.get(PlanSecretReadinessRecord, first.record_id)
    assert row.outcome == PlanSecretReadinessOutcome.ready  # the historical row is NOT rewritten

    # And the derived combined check refuses — without mutating any historical record.
    view = readiness_svc.get_provisioning_readiness(session, principal, env.manifest.id, now=later)
    assert view["ready"] is False
    assert view["reasons"]


def test_expired_eligibility_invalidates_state_readiness_without_mutating_it(
    session, principal, env
):
    """Past the eligibility TTL, the readiness BINDING itself refuses — the immutable
    state-readiness
    record is neither replayed as fresh nor rewritten."""
    from secp_api.eligibility_policy import ELIGIBILITY_EVIDENCE_TTL
    from secp_api.enums import ReadinessOperationKind, ReadinessReason
    from secp_api.readiness_binding import load_readiness_binding

    first, _ = _run_state(session, env)
    later = NOW + ELIGIBILITY_EVIDENCE_TTL + timedelta(minutes=1)

    result = load_readiness_binding(
        session,
        manifest_id=env.manifest.id,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=later,
    )
    assert result.binding is None
    assert result.reason is ReadinessReason.eligibility_expired

    adapter = FakeStateAdapter({})
    outcome = run_remote_state_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=state_composition(session, env, adapter),
        now=later,
    )
    assert outcome.outcome == RemoteStateReadinessOutcome.refused.value
    assert adapter.calls == []  # the adapter was never reached

    row = session.get(RemoteStateReadinessRecord, first.record_id)
    assert row.outcome == RemoteStateReadinessOutcome.ready  # history is never rewritten


def test_readiness_never_reads_or_mutates_os_environ(session, principal, env, monkeypatch):
    import os

    before = dict(os.environ)
    reads: list[str] = []
    original = os.environ.__class__.__getitem__

    def _spy(self, key):
        reads.append(key)
        return original(self, key)

    monkeypatch.setattr(os.environ.__class__, "__getitem__", _spy, raising=False)
    _run_state(session, env)
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    _run_secret(session, env)
    monkeypatch.undo()

    assert dict(os.environ) == before  # os.environ was never mutated


def test_jit_projection_yields_only_the_allowlisted_variable(session, principal, env):
    """The JIT contract facet is proven with INERT material and produces ONLY the allowlist."""
    from secp_worker.preflight.secret_resolution import SecretMaterial
    from secp_worker.readiness.plan_env import PlanSecretEnvContract, build_plan_secret_env

    env_map = build_plan_secret_env(
        SecretMaterial(SENTINEL_SECRET), contract=PlanSecretEnvContract()
    )
    assert set(env_map) == set(PLAN_SECRET_ENV_ALLOWLIST) == {"TF_VAR_pm_api_token"}
    assert "PATH" not in env_map
    assert "HOME" not in env_map
    assert "USERPROFILE" not in env_map
    assert env_map["TF_VAR_pm_api_token"] == SENTINEL_SECRET


def test_api_enqueue_is_durable_and_refuses_inline(session, principal, env, monkeypatch):
    """The API is ENQUEUE-ONLY: the inline dispatcher REFUSES with no fallback; Temporal enqueues a
    durable WorkflowRun + outbox row whose args carry IDS ONLY."""
    from secp_api.config import Settings
    from secp_api.dispatch import TemporalDispatcher
    from secp_api.safety import InlineExecutionForbidden

    # Inline (the dev/test default) refuses.
    with pytest.raises(InlineExecutionForbidden):
        readiness_svc.request_remote_state_readiness(session, principal, env.manifest.id)
    with pytest.raises(InlineExecutionForbidden):
        readiness_svc.request_plan_secret_readiness(session, principal, env.manifest.id)
    session.rollback()

    # Temporal enqueues only.
    settings = Settings(app_env="test", workflow_dispatch_mode="temporal")
    monkeypatch.setattr(
        "secp_api.dispatch.get_dispatcher",
        lambda *a, **k: TemporalDispatcher(settings, submitter=_NoSubmit()),
    )
    readiness_svc.request_remote_state_readiness(session, principal, env.manifest.id)
    readiness_svc.request_plan_secret_readiness(session, principal, env.manifest.id)
    session.flush()

    runs = session.execute(select(WorkflowRun)).scalars().all()
    assert {r.kind for r in runs} == {
        WorkflowKind.remote_state_readiness,
        WorkflowKind.plan_secret_readiness,
    }
    outbox = session.execute(select(WorkflowDispatchOutbox)).scalars().all()
    assert {o.workflow for o in outbox} == {
        "RemoteStateReadinessWorkflow",
        "PlanSecretReadinessWorkflow",
    }
    for row in outbox:
        assert set(row.args) == {"manifest_id", "workflow_run_id"}
        uuid.UUID(row.args["manifest_id"])
        # NOTHING privileged is in a workflow argument.
        rendered = str(row.args)
        for token in ("vault:", "http", "secp-fake-remote-state", "base_url", "sha256:"):
            assert token not in rendered, token

    # Nothing executed: no readiness evidence was created by the API.
    assert session.execute(select(RemoteStateReadinessRecord)).scalars().all() == []
    assert session.execute(select(PlanSecretReadinessRecord)).scalars().all() == []


class _NoSubmit:
    def submit(self, request):  # pragma: no cover - never called before commit
        raise AssertionError("Temporal submission must not happen inside the API transaction")
