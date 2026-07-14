"""B1B-PR4 — regression tests for every CONFIRMED adversarial-review finding (ADR-021 §U).

Each test reproduces the exact defect the threat review found and proves it is fixed. Nothing here
contacts a real backend, secret manager, or network.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import timedelta

import pytest
from secp_api.enums import (
    PlanSecretReadinessOutcome,
    ReadinessReason,
    RemoteStateReadinessFacet,
    RemoteStateReadinessOutcome,
    ResolutionLeaseStatus,
)
from secp_api.models import (
    PlanSecretReadinessRecord,
    PlanSecretResolutionLease,
    RemoteStateReadinessRecord,
)
from secp_api.readiness_contract import (
    BACKEND_CLASS_UNKNOWN,
    PLAN_SECRET_ENV_CONTRACT_VERSION,
    REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
    state_namespace_marker,
)
from secp_api.services import readiness as readiness_svc
from secp_worker.readiness.plan_secret_readiness import run_plan_secret_readiness
from secp_worker.readiness.state_adapter import (
    RemoteStateReadinessUnavailable,
    assert_no_state_body_surface,
)
from secp_worker.readiness.state_readiness import run_remote_state_readiness
from sqlalchemy import select
from tests._readiness_fixtures import (  # type: ignore[import-not-found]
    FIXTURE_ISSUER,
    NOW,
    FakeSelfTest,
    FakeStateAdapter,
    approve_plan_secret_authorization,
    audit_blob,
    build_readiness_env,
    db_text_blob,
    healthy_report,
    plan_secret_composition,
    state_binding,
    state_composition,
)

_F = RemoteStateReadinessFacet


@pytest.fixture
def env(session, principal, tmp_path):
    return build_readiness_env(session, principal, toolchain_root=str(tmp_path))


@pytest.fixture
def state_ready_env(session, principal, tmp_path):
    e = build_readiness_env(session, principal, toolchain_root=str(tmp_path))
    binding = state_binding(session, e)
    run_remote_state_readiness(
        session,
        manifest_id=e.manifest.id,
        composition=state_composition(session, e, FakeStateAdapter(healthy_report(binding))),
        now=NOW,
    )
    return e


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


# --- FINDING 1 (HIGH): raw adapter backend_class was persisted + returned verbatim ---------


def test_an_arbitrary_backend_class_is_normalized_and_never_persisted_verbatim(session, env):
    """An adapter returning a backend LOCATOR as its ``backend_class`` must not land in evidence."""
    locator = "https://acme-prod-tfstate.s3.eu-west-1.amazonaws.com/lab.tfstate"
    result, _ = _run_state(session, env, backend_class=locator)
    row = session.get(RemoteStateReadinessRecord, result.record_id)

    assert row.state_backend_class == BACKEND_CLASS_UNKNOWN  # NORMALIZED to the closed vocabulary
    assert locator not in db_text_blob(session)
    assert "amazonaws" not in db_text_blob(session)
    assert row.outcome != RemoteStateReadinessOutcome.ready


# --- FINDING 2 (HIGH): the no-state-body guard used getattr, EXECUTING a `get_state` property -----


def test_the_guard_never_executes_a_descriptor_and_refuses_a_property_state_reader():
    """The old ``getattr`` guard would have DOWNLOADED the state body while checking for it."""
    executed: list[str] = []

    class _PropertyStateReader:
        contract_version = REMOTE_STATE_ADAPTER_CONTRACT_VERSION

        @property
        def get_state(self):  # pragma: no cover - must never be executed
            executed.append("get_state")
            raise AssertionError("the guard executed the state-body descriptor")

        def evaluate(self, binding, *, now):
            raise AssertionError("must not be reached")

    with pytest.raises(RemoteStateReadinessUnavailable):
        assert_no_state_body_surface(_PropertyStateReader())
    assert executed == []  # the descriptor was NEVER invoked


def test_the_guard_is_an_allowlist_not_a_denylist():
    """A state-body method under ANY name (not just the nine known ones) is refused."""

    class _RenamedStateReader:
        contract_version = REMOTE_STATE_ADAPTER_CONTRACT_VERSION

        def evaluate(self, binding, *, now):
            raise AssertionError("must not be reached")

        def fetch_tfstate(self):  # not in the denylist at all
            raise AssertionError("must not be reached")

    with pytest.raises(RemoteStateReadinessUnavailable):
        assert_no_state_body_surface(_RenamedStateReader())


def test_an_adapter_with_exactly_the_allowed_surface_is_accepted():
    class _Clean:
        contract_version = REMOTE_STATE_ADAPTER_CONTRACT_VERSION

        def evaluate(self, binding, *, now):
            return None

    assert_no_state_body_surface(_Clean())  # does not raise


# --- FINDING 3 (HIGH): the proof-id shape admitted a backend locator into durable evidence --------


def test_a_proof_label_that_is_a_backend_locator_is_refused_outright(session, env):
    """``acme-prod-tfstate.s3.eu-west-1.amazonaws.com`` is a SHAPE-VALID proof label AND a real
    backend locator.

    The original fix persisted only its DIGEST — but an unsalted digest of an ENUMERABLE locator is
    an offline confirmation oracle: an attacker who guesses the bucket can confirm the guess against
    the durable record. B1B-PR4 §5 removes the oracle entirely: a proof id must be an opaque UUID,
    so neither the locator nor any digest of it is ever persisted, audited, or returned.
    """
    from secp_worker.readiness.state_adapter import StateProof

    binding = state_binding(session, env)
    locator = "acme-prod-tfstate.s3.eu-west-1.amazonaws.com"
    proof = StateProof(
        proof_id=locator,  # type: ignore[arg-type]
        issuer="vault.corp.internal",  # type: ignore[arg-type]
        performed_at=NOW - timedelta(days=1),
        toolchain_profile_hash=binding.toolchain_profile_hash,
        namespace_hash=binding.state_namespace_identity,
        expires_at=NOW + timedelta(days=10),
    )
    result, _ = _run_state(session, env, encryption=proof)
    row = session.get(RemoteStateReadinessRecord, result.record_id)

    assert row.encryption_proof_id is None
    assert ReadinessReason.state_proof_id_not_opaque.value in row.reason_codes
    blob = db_text_blob(session)
    assert locator not in blob
    assert "amazonaws" not in blob
    assert "vault.corp.internal" not in blob
    # ... and NO digest of either value is persisted, audited, or returned.
    for secret in (locator, "vault.corp.internal"):
        assert hashlib.sha256(secret.encode()).hexdigest() not in blob


def test_a_trailing_newline_never_passes_the_bounded_proof_shape(session, env):
    """Python's ``$`` also matches BEFORE a trailing newline — the validators use ``fullmatch``.

    A UUID with a trailing newline is not a UUID, so it is refused and nothing is persisted.
    """
    from secp_worker.readiness.state_adapter import StateProof

    binding = state_binding(session, env)
    proof = StateProof(
        proof_id=f"{uuid.uuid4()}\n",  # type: ignore[arg-type]
        issuer=FIXTURE_ISSUER,
        performed_at=NOW - timedelta(days=1),
        toolchain_profile_hash=binding.toolchain_profile_hash,
        namespace_hash=binding.state_namespace_identity,
    )
    result, _ = _run_state(session, env, backup=proof)
    row = session.get(RemoteStateReadinessRecord, result.record_id)
    facet = next(f for f in row.facets if f["facet"] == _F.backup_proof.value)
    assert facet["status"] == "fail"
    assert ReadinessReason.state_proof_id_not_opaque.value in row.reason_codes
    assert row.backup_proof_id is None


def test_evidence_proof_metadata_rejects_a_trailing_newline(session, principal, state_ready_env):
    from secp_api.enums import PlanSecretEvidenceKind, PlanSecretEvidenceStatus
    from secp_api.errors import ReadinessError
    from secp_api.services import plan_secret_authorization as auth_svc

    row = auth_svc.create_plan_secret_authorization(
        session, principal, manifest_id=state_ready_env.manifest.id
    )
    with pytest.raises(ReadinessError, match="evidence_invalid"):
        auth_svc.record_plan_secret_evidence(
            session,
            principal,
            row.id,
            kind=PlanSecretEvidenceKind.independent_adversarial_review,
            status=PlanSecretEvidenceStatus.verified,
            proof_id="proof-1\n",
            issuer="reviewer",
        )


# --- FINDING 4 (HIGH): the expected-namespace marker was SELF-ATTESTED ----------------------------


def test_an_adapter_chosen_marker_cannot_excuse_an_occupied_namespace(session, env):
    result, _ = _run_state(
        session,
        env,
        namespace_state_present=True,
        expected_namespace_marker="anything-i-like",  # shape-valid, but NOT server-derived
    )
    row = session.get(RemoteStateReadinessRecord, result.record_id)
    facet = next(f for f in row.facets if f["facet"] == _F.empty_or_expected_namespace.value)
    assert facet["status"] == "fail"
    assert ReadinessReason.state_namespace_occupied.value in row.reason_codes


def test_only_the_server_derived_marker_excuses_an_occupied_namespace(session, env):
    binding = state_binding(session, env)
    marker = state_namespace_marker(binding.state_namespace_identity)
    result, _ = _run_state(
        session, env, namespace_state_present=True, expected_namespace_marker=marker
    )
    row = session.get(RemoteStateReadinessRecord, result.record_id)
    facet = next(f for f in row.facets if f["facet"] == _F.empty_or_expected_namespace.value)
    assert facet["status"] == "pass"
    assert row.outcome == RemoteStateReadinessOutcome.ready


# --- FINDING 5 (HIGH): a non-ready record short-circuited every retry -----------------------------


def test_a_transient_state_failure_does_not_permanently_poison_the_operation(session, env):
    """One transient blip must not make the operation un-retryable."""
    first, _ = _run_state(session, env, encryption=None)  # unverifiable
    assert first.outcome == RemoteStateReadinessOutcome.unverifiable

    second, adapter = _run_state(session, env)  # a healthy retry
    assert second.outcome == RemoteStateReadinessOutcome.ready
    assert len(adapter.calls) == 1  # the backend WAS re-contacted
    assert second.record_id != first.record_id

    # Both attempts are immutable history; the failed one is not rewritten.
    rows = session.execute(select(RemoteStateReadinessRecord)).scalars().all()
    assert len(rows) == 2
    assert {r.outcome for r in rows} == {
        RemoteStateReadinessOutcome.unverifiable,
        RemoteStateReadinessOutcome.ready,
    }


def test_a_transient_secret_backend_failure_leaves_the_retry_budget_usable(
    session, principal, state_ready_env
):
    """The bounded N=3 lease budget must actually be reachable through the seam."""
    approve_plan_secret_authorization(
        session, principal, state_ready_env.manifest.id, ttl_seconds=24 * 3600
    )

    failing = FakeSelfTest(ok=False, reason_code="backend_timeout")
    first = run_plan_secret_readiness(
        session,
        manifest_id=state_ready_env.manifest.id,
        composition=plan_secret_composition(session, state_ready_env, failing),
        now=NOW,
    )
    assert first.outcome == PlanSecretReadinessOutcome.unavailable.value
    lease = session.execute(select(PlanSecretResolutionLease)).scalars().one()
    assert lease.attempt_count == 1
    assert lease.status == ResolutionLeaseStatus.active  # NOT consumed

    # A retry WITHIN the lease instance TTL is refused (`lease_held`): at most one valid pre-success
    # lease exists at a time. The retry becomes possible once that lease instance expires — and the
    # durable attempt budget is PRESERVED across the re-issue, never reset.
    blocked = run_plan_secret_readiness(
        session,
        manifest_id=state_ready_env.manifest.id,
        composition=plan_secret_composition(session, state_ready_env, FakeSelfTest()),
        now=NOW,
    )
    assert blocked.reason_code == ReadinessReason.lease_refused.value

    from secp_worker.readiness.plan_secret_lease import DEFAULT_LEASE_TTL_SECONDS

    later = NOW + timedelta(seconds=DEFAULT_LEASE_TTL_SECONDS + 10)
    healthy = FakeSelfTest()
    second = run_plan_secret_readiness(
        session,
        manifest_id=state_ready_env.manifest.id,
        composition=plan_secret_composition(session, state_ready_env, healthy),
        now=later,
    )
    assert second.outcome == PlanSecretReadinessOutcome.ready.value
    assert healthy.calls == 1  # the secret backend WAS re-contacted (the budget was usable)
    assert second.record_id != first.record_id

    session.expire_all()
    lease = session.execute(select(PlanSecretResolutionLease)).scalars().one()
    assert lease.attempt_count == 2  # the budget advanced; it was never reset
    assert lease.status == ResolutionLeaseStatus.consumed


def test_the_terminal_ready_record_is_still_exact_once(session, env):
    first, _ = _run_state(session, env)
    assert first.outcome == RemoteStateReadinessOutcome.ready
    second, adapter = _run_state(session, env)
    assert second.reused is True
    assert second.record_id == first.record_id
    assert adapter.calls == []  # no second backend contact
    assert len(session.execute(select(RemoteStateReadinessRecord)).scalars().all()) == 1


# --- FINDING 6 (HIGH/LOW): the self-test's REASON CODE was used as its PROOF ID -------------------


def test_a_self_test_that_succeeds_without_a_proof_id_is_unverifiable(
    session, principal, state_ready_env
):
    approve_plan_secret_authorization(session, principal, state_ready_env.manifest.id)
    result = run_plan_secret_readiness(
        session,
        manifest_id=state_ready_env.manifest.id,
        composition=plan_secret_composition(
            session,
            state_ready_env,
            FakeSelfTest(ok=True, reason_code="", proof_id=None),
        ),
        now=NOW,
    )
    assert result.outcome == PlanSecretReadinessOutcome.unavailable.value
    row = session.get(PlanSecretReadinessRecord, result.record_id)
    assert ReadinessReason.resolver_self_test_unavailable.value in row.reason_codes
    assert row.self_test_proof_id is None


def test_the_self_test_proof_id_is_an_opaque_uuid_not_a_label_or_a_digest_of_one(
    session, principal, state_ready_env
):
    """B1B-PR4 §5: a shape-bounded proof LABEL is refused outright — and so is a digest of one.

    ``vault.corp.internal`` is a syntactically valid label AND a real backend locator. Persisting
    it would leak the locator; persisting an unsalted digest of it would be an offline confirmation
    oracle for it (an attacker who guesses the hostname can confirm the guess against the record).
    Only an opaque UUID is accepted, so the success is unverifiable and readiness fails closed.
    """
    approve_plan_secret_authorization(session, principal, state_ready_env.manifest.id)
    result = run_plan_secret_readiness(
        session,
        manifest_id=state_ready_env.manifest.id,
        composition=plan_secret_composition(
            session,
            state_ready_env,
            FakeSelfTest(ok=True, reason_code="self_test_ok", proof_id="vault.corp.internal"),
        ),
        now=NOW,
    )
    row = session.get(PlanSecretReadinessRecord, result.record_id)
    assert result.outcome == PlanSecretReadinessOutcome.unavailable.value
    assert row.self_test_proof_id is None  # NOT the label, and NOT a digest of it
    assert ReadinessReason.resolver_self_test_unavailable.value in row.reason_codes
    assert "vault.corp.internal" not in db_text_blob(session)
    assert "vault.corp.internal" not in audit_blob(session)
    assert hashlib.sha256(b"vault.corp.internal").hexdigest() not in db_text_blob(session)


def test_the_shipped_self_test_is_sealed_and_never_succeeds():
    from secp_worker.readiness.self_test import SealedPlanSecretSelfTest

    result = SealedPlanSecretSelfTest().run(now=NOW)
    assert result.ok is False
    assert result.proof_id is None


# --- FINDING 7 (LOW): the lock proof was not bound to the backend ---------------------------------


def test_a_lock_proof_from_another_backend_is_refused(session, env):
    from secp_worker.readiness.state_adapter import LockCapabilityProof

    binding = state_binding(session, env)
    foreign = LockCapabilityProof(
        proof_id=uuid.uuid4(),
        issuer=FIXTURE_ISSUER,
        performed_at=NOW - timedelta(minutes=1),
        toolchain_profile_hash="sha256:" + "e" * 64,  # a DIFFERENT backend
        namespace_hash=binding.state_namespace_identity,
        lock_capability=True,
        contention_detected=True,
        force_unlock_available=False,
        caller_supplied_owner=False,
        probe_released=True,
        expires_at=NOW + timedelta(days=1),
    )
    result, _ = _run_state(session, env, locking=foreign)
    row = session.get(RemoteStateReadinessRecord, result.record_id)
    facet = next(f for f in row.facets if f["facet"] == _F.locking.value)
    assert facet["status"] == "fail"
    assert ReadinessReason.state_lock_proof_unbound.value in row.reason_codes


# --- FINDING 8 (MEDIUM): evidence fingerprint bound but never RE-VERIFIED ------------------


def test_a_tampered_evidence_fingerprint_refuses_the_readiness_attempt(
    session, principal, state_ready_env
):
    """The worker RECOMPUTES the review-evidence fingerprint and compares it to the approval."""
    import sqlalchemy as sa
    from secp_api.models import PlanSecretReadinessAuthorization

    row = approve_plan_secret_authorization(session, principal, state_ready_env.manifest.id)
    session.execute(
        sa.update(PlanSecretReadinessAuthorization)
        .where(PlanSecretReadinessAuthorization.id == row.id)
        .values(evidence_fingerprint="sha256:" + "0" * 64)  # bypasses the ORM guard
    )
    session.flush()
    session.expire_all()

    self_test = FakeSelfTest()
    result = run_plan_secret_readiness(
        session,
        manifest_id=state_ready_env.manifest.id,
        composition=plan_secret_composition(session, state_ready_env, self_test),
        now=NOW,
    )
    assert result.reason_code == ReadinessReason.secret_evidence_fingerprint_mismatch.value
    assert self_test.calls == 0  # the secret backend was never reached
    assert session.execute(select(PlanSecretReadinessRecord)).scalars().all() == []


# --- FINDING 9 (MEDIUM): the JIT env contract version escaped the drift matrix -------------


def test_a_bumped_jit_env_contract_invalidates_current_plan_secret_readiness(
    session, principal, state_ready_env, monkeypatch
):
    approve_plan_secret_authorization(session, principal, state_ready_env.manifest.id)
    result = run_plan_secret_readiness(
        session,
        manifest_id=state_ready_env.manifest.id,
        composition=plan_secret_composition(session, state_ready_env, FakeSelfTest()),
        now=NOW,
    )
    assert result.outcome == PlanSecretReadinessOutcome.ready.value

    view = readiness_svc.get_provisioning_readiness(
        session, principal, state_ready_env.manifest.id, now=NOW
    )
    assert view["ready"] is True

    # Bump the JIT env-projection contract: the recorded facet was proven against a DIFFERENT
    # allowlist, so current readiness must fail closed.
    monkeypatch.setattr(
        readiness_svc, "PLAN_SECRET_ENV_CONTRACT_VERSION", PLAN_SECRET_ENV_CONTRACT_VERSION + "-x"
    )
    view = readiness_svc.get_provisioning_readiness(
        session, principal, state_ready_env.manifest.id, now=NOW
    )
    assert view["ready"] is False
    assert ReadinessReason.readiness_policy_mismatch.value in view["reasons"]


# --- FINDING 10 (MEDIUM): the read model's `current` flag ignored binding drift ------------


def test_the_read_model_current_flag_follows_the_authoritative_binding(session, principal, env):
    from secp_api.services import live_authorizations

    _run_state(session, env)
    view = readiness_svc.get_remote_state_readiness(session, principal, env.manifest.id, now=NOW)
    assert view["current"] is True

    # Revoke the bound live-read authorization → the eligibility evidence drifts → the binding
    # refuses → the record is no longer CURRENT, even though it is still ``ready`` and unexpired.
    live_authorizations.revoke_live_read_authorization(
        session, principal, env.live_read_authorization.id, "operator"
    )
    session.flush()

    view = readiness_svc.get_remote_state_readiness(session, principal, env.manifest.id, now=NOW)
    assert view["current"] is False
    assert view["expired"] is False
    assert view["outcome"] == RemoteStateReadinessOutcome.ready.value  # history is NOT rewritten


# --- FINDING 11 (MEDIUM): the 422 echoed a rejected `purpose` ------------------------------


def test_a_rejected_apply_purpose_is_never_echoed_in_the_validation_error(session, principal, env):
    from fastapi.testclient import TestClient
    from secp_api.db import session_scope
    from secp_api.main import create_app
    from secp_api.seed import bootstrap_dev

    with session_scope() as s:
        bootstrap_dev(s)
    app = create_app()
    app.router.on_startup.clear()
    client = TestClient(app)

    response = client.post(
        f"/api/v1/provisioning-manifests/{env.manifest.id}/plan-secret-authorizations",
        json={"purpose": "apply", "ttl_seconds": 3600},
    )
    assert response.status_code == 422
    body = response.text
    assert "apply" not in body  # the REJECTED VALUE is never echoed
    assert "invalid_readiness_input" in body
