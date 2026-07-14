"""B1B-PR4 — remote-state readiness refusal matrix (ADR-021 §D, §E).

Every mandatory facet is proven to fail closed. A fact that cannot be PROVEN yields ``unverifiable``
— never a fabricated pass. Nothing is contacted: the adapter is an injected fake with no I/O.
"""

from __future__ import annotations

import copy
import hashlib
import uuid
from datetime import timedelta

import pytest
from secp_api.enums import (
    AuditAction,
    ReadinessOperationKind,
    ReadinessReason,
    RemoteStateReadinessFacet,
    RemoteStateReadinessOutcome,
)
from secp_api.models import RemoteStateReadinessRecord
from secp_api.readiness_binding import load_readiness_binding
from secp_api.readiness_contract import (
    FORBIDDEN_STATE_ADAPTER_METHODS,
    REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
    ReadinessBinding,
    state_namespace_identity,
)
from secp_worker.readiness.composition import build_readiness_composition
from secp_worker.readiness.state_adapter import (
    LockCapabilityProof,
    RemoteStateReadinessAdapter,
    SealedRemoteStateReadinessAdapter,
    StateProof,
)
from secp_worker.readiness.state_readiness import run_remote_state_readiness
from sqlalchemy import select
from tests._readiness_fixtures import (  # type: ignore[import-not-found]
    FIXTURE_ISSUER,
    NOW,
    FakeStateAdapter,
    RaisingStateAdapter,
    StateBodyAdapter,
    audit_actions,
    bare_activation,
    build_readiness_env,
    db_text_blob,
    full_composition,
    healthy_report,
    state_binding,
    state_composition,
)

_F = RemoteStateReadinessFacet


@pytest.fixture
def env(session, principal, tmp_path):
    return build_readiness_env(session, principal, toolchain_root=str(tmp_path))


def _run(session, env, *, adapter=None, now=NOW, **over):
    binding = state_binding(session, env)
    adapter = adapter or FakeStateAdapter(healthy_report(binding, now=now, **over))
    result = run_remote_state_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=state_composition(session, env, adapter),
        now=now,
    )
    return result, adapter


def _record(session, result) -> RemoteStateReadinessRecord:
    row = session.get(RemoteStateReadinessRecord, result.record_id)
    assert row is not None
    return row


def _facet(row, facet: _F) -> dict:
    return next(f for f in row.facets if f["facet"] == facet.value)


def _proofs(binding: ReadinessBinding, now=NOW) -> dict:
    return {
        "toolchain_profile_hash": binding.toolchain_profile_hash,
        "namespace_hash": binding.state_namespace_identity,
        "performed_at": now - timedelta(days=1),
        "expires_at": now + timedelta(days=10),
    }


# --- backend class / local fallback ---------------------------------------------------------------


def test_local_backend_is_refused(session, env):
    result, _ = _run(session, env, backend_class="local", backend_kind="local")
    row = _record(session, result)
    assert row.outcome == RemoteStateReadinessOutcome.not_ready
    assert _facet(row, _F.backend_class)["status"] == "fail"
    assert ReadinessReason.state_backend_local.value in row.reason_codes


@pytest.mark.parametrize("kind", ["local", "local-state", "localfs", "file", "disk", ""])
def test_every_local_state_token_is_refused(session, env, kind):
    result, _ = _run(session, env, backend_kind=kind)
    row = _record(session, result)
    assert _facet(row, _F.backend_class)["status"] == "fail"


def test_missing_backend_class_is_refused(session, env):
    result, _ = _run(session, env, backend_class="unknown")
    row = _record(session, result)
    assert ReadinessReason.state_backend_missing.value in row.reason_codes


def test_backend_reference_drift_is_refused(session, env):
    """The adapter is bound to a DIFFERENT backend than the ToolchainProfile pins."""
    result, _ = _run(session, env, toolchain_profile_hash="sha256:" + "9" * 64)
    row = _record(session, result)
    assert _facet(row, _F.backend_class)["status"] == "fail"
    assert ReadinessReason.state_backend_reference_drift.value in row.reason_codes


def test_local_fallback_available_is_refused(session, env):
    result, _ = _run(session, env, local_fallback_available=True)
    row = _record(session, result)
    assert _facet(row, _F.no_local_fallback)["status"] == "fail"
    assert ReadinessReason.state_local_fallback_available.value in row.reason_codes


# --- transport security ---------------------------------------------------------------------------


def test_tls_disabled_is_refused(session, env):
    result, _ = _run(session, env, tls_mode="disabled")
    row = _record(session, result)
    assert _facet(row, _F.transport_security)["status"] == "fail"
    assert ReadinessReason.state_tls_disabled.value in row.reason_codes


def test_certificate_validation_disabled_is_refused(session, env):
    result, _ = _run(session, env, certificate_validation_enabled=False)
    assert _facet(_record(session, result), _F.transport_security)["status"] == "fail"


def test_untrusted_identity_policy_is_refused(session, env):
    result, _ = _run(session, env, trusted_identity_policy="insecure_skip_verify")
    assert _facet(_record(session, result), _F.transport_security)["status"] == "fail"


def test_trust_env_proxy_inheritance_is_refused(session, env):
    result, _ = _run(session, env, proxy_inheritance_enabled=True)
    row = _record(session, result)
    assert ReadinessReason.state_trust_env_enabled.value in row.reason_codes


def test_redirect_to_another_backend_is_refused(session, env):
    result, _ = _run(session, env, redirect_observed=True)
    row = _record(session, result)
    assert ReadinessReason.state_redirect_observed.value in row.reason_codes


def test_unstable_destination_is_refused(session, env):
    result, _ = _run(session, env, destination_stable=False)
    row = _record(session, result)
    assert ReadinessReason.state_destination_unstable.value in row.reason_codes


# --- namespace identity ---------------------------------------------------------------------------


def test_caller_selected_state_key_is_refused(session, env):
    """A namespace SECP did not derive (a caller-selected state key) fails closed."""
    result, _ = _run(session, env, namespace_identity="sha256:" + "0" * 64)
    row = _record(session, result)
    assert _facet(row, _F.namespace_identity)["status"] == "fail"
    assert ReadinessReason.state_namespace_mismatch.value in row.reason_codes


def test_cross_organization_namespace_is_refused(session, env):
    """Another organization's namespace identity is a different digest → refused."""
    binding = state_binding(session, env)
    other_org = state_namespace_identity(
        organization_id="00000000-0000-0000-0000-0000000000ff",
        execution_target_id=binding.execution_target_id,
        onboarding_id=binding.target_onboarding_id,
        manifest_id=binding.provisioning_manifest_id,
        manifest_content_hash=binding.provisioning_manifest_content_hash,
        deployment_plan_id=binding.deployment_plan_id,
    )
    assert other_org != binding.state_namespace_identity
    result, _ = _run(session, env, namespace_identity=other_org)
    row = _record(session, result)
    assert _facet(row, _F.namespace_identity)["status"] == "fail"


def test_unknown_namespace_is_unverifiable(session, env):
    result, _ = _run(session, env, namespace_identity="")
    row = _record(session, result)
    assert row.outcome == RemoteStateReadinessOutcome.unverifiable
    assert _facet(row, _F.namespace_identity)["status"] == "unverifiable"


def test_existing_unrelated_namespace_is_refused(session, env):
    """The first lab may not adopt an existing unrelated state (metadata identity only)."""
    result, _ = _run(session, env, namespace_state_present=True, expected_namespace_marker="")
    row = _record(session, result)
    assert _facet(row, _F.empty_or_expected_namespace)["status"] == "fail"
    assert ReadinessReason.state_namespace_occupied.value in row.reason_codes


def test_approved_expected_namespace_marker_is_accepted(session, env):
    """The ONE marker excusing an occupied namespace is SERVER-DERIVED (never self-attested)."""
    from secp_api.readiness_contract import state_namespace_marker

    binding = state_binding(session, env)
    result, _ = _run(
        session,
        env,
        namespace_state_present=True,
        expected_namespace_marker=state_namespace_marker(binding.state_namespace_identity),
    )
    row = _record(session, result)
    assert _facet(row, _F.empty_or_expected_namespace)["status"] == "pass"
    assert row.outcome == RemoteStateReadinessOutcome.ready


def test_undeterminable_namespace_occupancy_is_unverifiable(session, env):
    """It is decided from metadata/version identity ONLY — the state body is never read."""
    result, _ = _run(session, env, namespace_state_present=None)
    row = _record(session, result)
    assert _facet(row, _F.empty_or_expected_namespace)["status"] == "unverifiable"
    assert row.outcome == RemoteStateReadinessOutcome.unverifiable


# --- encryption at rest ---------------------------------------------------------------------------


def test_encryption_proof_absent_is_unverifiable(session, env):
    result, _ = _run(session, env, encryption=None)
    row = _record(session, result)
    assert _facet(row, _F.encryption_at_rest)["status"] == "unverifiable"
    assert ReadinessReason.state_encryption_proof_absent.value in row.reason_codes
    assert row.outcome == RemoteStateReadinessOutcome.unverifiable
    assert row.encryption_proof_id is None


def test_encryption_proof_stale_is_refused(session, env):
    binding = state_binding(session, env)
    stale = StateProof(
        proof_id=uuid.uuid4(),
        issuer=FIXTURE_ISSUER,
        toolchain_profile_hash=binding.toolchain_profile_hash,
        namespace_hash=binding.state_namespace_identity,
        performed_at=NOW - timedelta(days=400),
        expires_at=NOW - timedelta(days=1),
    )
    result, _ = _run(session, env, encryption=stale)
    row = _record(session, result)
    assert _facet(row, _F.encryption_at_rest)["status"] == "fail"
    assert ReadinessReason.state_encryption_proof_stale.value in row.reason_codes


def test_forged_encryption_proof_bound_to_another_backend_is_refused(session, env):
    binding = state_binding(session, env)
    forged = StateProof(
        proof_id=uuid.uuid4(),
        issuer=FIXTURE_ISSUER,
        toolchain_profile_hash="sha256:" + "e" * 64,
        namespace_hash=binding.state_namespace_identity,
        performed_at=NOW - timedelta(days=1),
    )
    result, _ = _run(session, env, encryption=forged)
    row = _record(session, result)
    assert ReadinessReason.state_encryption_proof_unbound.value in row.reason_codes


# --- locking
# ---------------------------------------------------------------------------------------


def test_locking_unavailable_is_unverifiable(session, env):
    result, _ = _run(session, env, locking=None)
    row = _record(session, result)
    assert _facet(row, _F.locking)["status"] == "unverifiable"
    assert ReadinessReason.state_lock_unavailable.value in row.reason_codes


def _lock(binding, **over):
    fields = {
        "proof_id": uuid.uuid4(),
        "issuer": FIXTURE_ISSUER,
        "performed_at": NOW - timedelta(minutes=1),
        "toolchain_profile_hash": binding.toolchain_profile_hash,
        "namespace_hash": binding.state_namespace_identity,
        "lock_capability": True,
        "contention_detected": True,
        "force_unlock_available": False,
        "caller_supplied_owner": False,
        "probe_released": True,
        "expires_at": NOW + timedelta(days=1),
    }
    fields.update(over)
    return LockCapabilityProof(**fields)


def test_lock_contention_not_detected_is_refused(session, env):
    binding = state_binding(session, env)
    result, _ = _run(session, env, locking=_lock(binding, contention_detected=False))
    row = _record(session, result)
    assert _facet(row, _F.locking)["status"] == "fail"
    assert ReadinessReason.state_lock_contention_undetected.value in row.reason_codes


def test_force_unlock_capability_is_refused(session, env):
    binding = state_binding(session, env)
    result, _ = _run(session, env, locking=_lock(binding, force_unlock_available=True))
    row = _record(session, result)
    assert ReadinessReason.state_lock_force_unlock_available.value in row.reason_codes


def test_caller_supplied_lock_owner_is_refused(session, env):
    binding = state_binding(session, env)
    result, _ = _run(session, env, locking=_lock(binding, caller_supplied_owner=True))
    row = _record(session, result)
    assert ReadinessReason.state_lock_owner_caller_supplied.value in row.reason_codes


def test_lock_probe_cleanup_failure_is_refused(session, env):
    """A bounded ephemeral probe that was not released in a ``finally`` leaks a lock → fail
    closed."""
    binding = state_binding(session, env)
    result, _ = _run(session, env, locking=_lock(binding, probe_released=False))
    row = _record(session, result)
    assert ReadinessReason.state_lock_probe_not_released.value in row.reason_codes


def test_lock_proof_bound_to_another_namespace_is_refused(session, env):
    binding = state_binding(session, env)
    result, _ = _run(session, env, locking=_lock(binding, namespace_hash="sha256:" + "7" * 64))
    row = _record(session, result)
    assert ReadinessReason.state_lock_proof_unbound.value in row.reason_codes


# --- backup / restore proofs
# ------------------------------------------------------------------------


def test_backup_proof_absent_is_unverifiable(session, env):
    result, _ = _run(session, env, backup=None)
    row = _record(session, result)
    assert _facet(row, _F.backup_proof)["status"] == "unverifiable"
    assert ReadinessReason.state_backup_proof_absent.value in row.reason_codes
    assert row.backup_proof_id is None


def test_backup_proof_stale_is_refused(session, env):
    binding = state_binding(session, env)
    stale = StateProof(
        proof_id=uuid.uuid4(),
        issuer=FIXTURE_ISSUER,
        performed_at=NOW - timedelta(days=90),
        toolchain_profile_hash=binding.toolchain_profile_hash,
        namespace_hash=binding.state_namespace_identity,
    )
    result, _ = _run(session, env, backup=stale)
    row = _record(session, result)
    assert ReadinessReason.state_backup_proof_stale.value in row.reason_codes


def test_restore_proof_absent_is_unverifiable(session, env):
    result, _ = _run(session, env, restore=None)
    row = _record(session, result)
    assert _facet(row, _F.restore_proof)["status"] == "unverifiable"
    assert ReadinessReason.state_restore_proof_absent.value in row.reason_codes


def test_restore_proof_without_a_tested_restore_is_refused(session, env):
    """A restore CAPABILITY is not a restore PROOF. PR4 performs no restore against real state."""
    binding = state_binding(session, env)
    untested = StateProof(
        proof_id=uuid.uuid4(),
        issuer=FIXTURE_ISSUER,
        performed_at=NOW - timedelta(days=1),
        restore_tested=False,
        **{
            k: v
            for k, v in _proofs(binding).items()
            if k in ("toolchain_profile_hash", "namespace_hash")
        },
    )
    result, _ = _run(session, env, restore=untested)
    row = _record(session, result)
    assert _facet(row, _F.restore_proof)["status"] == "fail"


def test_restore_proof_stale_is_refused(session, env):
    binding = state_binding(session, env)
    stale = StateProof(
        proof_id=uuid.uuid4(),
        issuer=FIXTURE_ISSUER,
        performed_at=NOW - timedelta(days=90),
        restore_tested=True,
        toolchain_profile_hash=binding.toolchain_profile_hash,
        namespace_hash=binding.state_namespace_identity,
    )
    result, _ = _run(session, env, restore=stale)
    row = _record(session, result)
    assert ReadinessReason.state_restore_proof_stale.value in row.reason_codes


def test_future_dated_proof_is_never_accepted(session, env):
    binding = state_binding(session, env)
    future = StateProof(
        proof_id=uuid.uuid4(),
        issuer=FIXTURE_ISSUER,
        performed_at=NOW + timedelta(days=1),
        toolchain_profile_hash=binding.toolchain_profile_hash,
        namespace_hash=binding.state_namespace_identity,
    )
    result, _ = _run(session, env, backup=future)
    row = _record(session, result)
    assert _facet(row, _F.backup_proof)["status"] == "fail"


# --- least privilege
# ---------------------------------------------------------------------------------


def test_least_privilege_scope_evidence_unavailable_is_unverifiable(session, env):
    """A successful metadata read alone is NEVER least-privilege proof."""
    result, _ = _run(session, env, scope_evidence_available=False)
    row = _record(session, result)
    assert _facet(row, _F.least_privileged_access)["status"] == "unverifiable"
    assert ReadinessReason.state_least_privilege_unproven.value in row.reason_codes


@pytest.mark.parametrize("action", ["delete", "force_unlock", "admin", "list_all", "*"])
def test_excessive_state_privilege_is_refused(session, env, action):
    result, _ = _run(session, env, allowed_actions=("read", "write", "lock", "unlock_own", action))
    row = _record(session, result)
    assert _facet(row, _F.least_privileged_access)["status"] == "fail"
    assert ReadinessReason.state_privilege_excessive.value in row.reason_codes
    # The reason code names NO action value.
    assert action not in " ".join(row.reason_codes) or action in ("read", "write")


# --- adapter integrity
# -------------------------------------------------------------------------------


def test_shipped_default_adapter_is_sealed(session, env):
    """The shipped composition injects NO adapter and refuses before any contact."""
    composition = build_readiness_composition()
    assert composition.gate.enabled is False
    assert composition.state_adapter is None

    result = run_remote_state_readiness(
        session, manifest_id=env.manifest.id, composition=composition, now=NOW
    )
    assert result.outcome == RemoteStateReadinessOutcome.refused.value
    assert result.reason_code == ReadinessReason.sealed.value
    assert session.execute(select(RemoteStateReadinessRecord)).scalars().all() == []


def test_sealed_adapter_refuses_unconditionally():
    from secp_worker.readiness.state_adapter import RemoteStateReadinessUnavailable

    with pytest.raises(RemoteStateReadinessUnavailable, match="sealed"):
        SealedRemoteStateReadinessAdapter().evaluate(None, now=NOW)  # type: ignore[arg-type]


def test_missing_adapter_with_an_enabled_gate_still_refuses(session, env):
    from secp_worker.readiness.composition import ReadinessComposition, ReadinessGate

    result = run_remote_state_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=ReadinessComposition(gate=ReadinessGate(enabled=True), state_adapter=None),
        now=NOW,
    )
    assert result.reason_code == ReadinessReason.adapter_unavailable.value
    assert session.execute(select(RemoteStateReadinessRecord)).scalars().all() == []


def test_adapter_contract_mismatch_is_refused(session, env):
    binding = state_binding(session, env)
    adapter = FakeStateAdapter(healthy_report(binding), contract_version="some-other-adapter/v9")
    result, _ = _run(session, env, adapter=adapter)
    assert result.reason_code == ReadinessReason.adapter_contract_mismatch.value
    assert adapter.calls == []  # never invoked
    assert session.execute(select(RemoteStateReadinessRecord)).scalars().all() == []


def test_an_adapter_exposing_a_state_body_surface_is_refused_before_invocation(session, env):
    binding = state_binding(session, env)
    adapter = StateBodyAdapter(healthy_report(binding))
    result, _ = _run(session, env, adapter=adapter)
    assert result.reason_code == ReadinessReason.state_body_access_attempted.value
    assert adapter.calls == []  # evaluate() was NEVER called
    assert session.execute(select(RemoteStateReadinessRecord)).scalars().all() == []


def test_the_adapter_protocol_has_no_state_body_surface():
    """There is no interface through which a state payload could be read, written, or returned."""
    for name in FORBIDDEN_STATE_ADAPTER_METHODS:
        assert not hasattr(RemoteStateReadinessAdapter, name)
        assert not hasattr(SealedRemoteStateReadinessAdapter, name)
        assert not hasattr(FakeStateAdapter, name)
    surface = {m for m in dir(RemoteStateReadinessAdapter) if not m.startswith("_")}
    assert surface == {"contract_version", "evaluate"}


def test_an_adapter_raising_is_refused_without_leaking_the_exception(session, env):
    class _Boom:
        contract_version = REMOTE_STATE_ADAPTER_CONTRACT_VERSION

        def evaluate(self, binding, *, now):
            raise RuntimeError("https://real-backend.invalid/bucket/lab.tfstate?token=abc")

    result = run_remote_state_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=state_composition(session, env, _Boom()),
        now=NOW,
    )
    assert result.reason_code == ReadinessReason.adapter_report_invalid.value
    blob = " ".join(audit_actions(session, env.org_id))
    assert "real-backend.invalid" not in blob
    from tests._readiness_fixtures import audit_blob

    assert "real-backend.invalid" not in audit_blob(session)
    assert "token=abc" not in audit_blob(session)


def test_a_non_report_return_value_is_refused(session, env):
    class _Bogus:
        contract_version = REMOTE_STATE_ADAPTER_CONTRACT_VERSION

        def evaluate(self, binding, *, now):
            return {"backend_class": "remote", "state": "<the whole tfstate body>"}

    result = run_remote_state_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=state_composition(session, env, _Bogus()),
        now=NOW,
    )
    assert result.reason_code == ReadinessReason.adapter_report_invalid.value
    assert session.execute(select(RemoteStateReadinessRecord)).scalars().all() == []


def test_free_form_adapter_reason_codes_are_never_persisted_verbatim(session, env):
    result, _ = _run(
        session,
        env,
        reason_codes=("https://bucket.invalid/lab.tfstate", "AKIAIOSFODNN7EXAMPLE"),
    )
    row = _record(session, result)
    for code in row.reason_codes:
        # Every persisted code is a member of the closed catalog.
        ReadinessReason(code)
    blob = str(row.reason_codes)
    assert "bucket.invalid" not in blob
    assert "AKIA" not in blob


@pytest.mark.parametrize(
    "bad_proof_id",
    [
        "x" * 500,  # oversized
        "acme-tfstate.s3.amazonaws.com",  # a real backend LOCATOR wearing a label's clothes
        "secp-fake-remote-state/lab",
        "enc-proof-001",  # even a harmless-looking label is refused: the SHAPE is the problem
        "",
    ],
)
def test_a_proof_id_that_is_not_an_opaque_uuid_is_refused(session, env, bad_proof_id):
    """B1B-PR4 §5: external proof ids must be UUIDs.

    A shape-bounded label is exactly the alphabet of a DNS hostname, an S3/GCS bucket, a Vault
    mount, or a state-file name — so persisting one leaks an enumerable locator, and persisting an
    unsalted digest of one is an offline confirmation oracle for it. Only a UUID is accepted, and
    nothing derived from the rejected value is persisted.
    """
    binding = state_binding(session, env)
    labelled = StateProof(
        proof_id=bad_proof_id,  # type: ignore[arg-type]
        issuer=FIXTURE_ISSUER,
        performed_at=NOW - timedelta(days=1),
        toolchain_profile_hash=binding.toolchain_profile_hash,
        namespace_hash=binding.state_namespace_identity,
    )
    result, _ = _run(session, env, encryption=labelled)
    row = _record(session, result)
    assert _facet(row, _F.encryption_at_rest)["status"] == "fail"
    assert ReadinessReason.state_proof_id_not_opaque.value in row.reason_codes
    assert row.encryption_proof_id is None
    if bad_proof_id:
        blob = db_text_blob(session)
        assert bad_proof_id not in blob
        assert hashlib.sha256(bad_proof_id.encode()).hexdigest() not in blob


# --- ordering
# ---------------------------------------------------------------------------------------


def test_no_backend_adapter_before_the_authoritative_binding(session, principal):
    """A trap adapter proves the backend is NEVER touched before the binding is authoritative."""
    from tests.conftest import build_lab_env  # type: ignore[import-not-found]

    # A lab env with NO eligibility evidence at all → the binding refuses first.
    lab = build_lab_env(session, principal, secret_ref="vault:secp-fake-lab/plan-read")
    adapter = RaisingStateAdapter()
    result = run_remote_state_readiness(
        session,
        manifest_id=lab.manifest.id,
        composition=full_composition(
            state_adapter=adapter,
            state_activation=bare_activation(
                adapter, operation_kind=ReadinessOperationKind.remote_state_readiness
            ),
        ),
        now=NOW,
    )
    assert result.outcome == RemoteStateReadinessOutcome.refused.value
    assert result.reason_code in {
        ReadinessReason.eligibility_missing.value,
        ReadinessReason.eligibility_not_eligible.value,
        ReadinessReason.worker_identity_untrusted.value,
    }
    assert session.execute(select(RemoteStateReadinessRecord)).scalars().all() == []


def test_no_state_probe_before_current_eligibility(session, principal, env):
    """Revoke the bound live-read authorization → eligibility drifts → the adapter is never
    reached."""
    from secp_api.services import live_authorizations

    result = load_readiness_binding(
        session,
        manifest_id=env.manifest.id,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=NOW,
    )
    assert result.binding is not None  # currently valid

    # The composition (and its reviewed activation) is built while the binding is STILL valid, so
    # the refusal below can only come from the eligibility gate — never from a missing capability.
    composition = state_composition(session, env, RaisingStateAdapter())

    live_authorizations.revoke_live_read_authorization(
        session, principal, env.live_read_authorization.id, "operator"
    )
    session.flush()

    outcome = run_remote_state_readiness(
        session, manifest_id=env.manifest.id, composition=composition, now=NOW
    )
    assert outcome.reason_code == ReadinessReason.eligibility_drifted.value


def test_no_evidence_persistence_before_the_typed_evaluation(session, env):
    """A refusal at any gate persists NO evidence and records a bounded refusal audit."""
    result = run_remote_state_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=build_readiness_composition(),
        now=NOW,
    )
    assert result.record_id is None
    assert session.execute(select(RemoteStateReadinessRecord)).scalars().all() == []
    assert AuditAction.remote_state_readiness_refused.value in audit_actions(session, env.org_id)
    assert AuditAction.remote_state_readiness_started.value not in audit_actions(
        session, env.org_id
    )


@pytest.mark.parametrize("kind", ["local", "local-state", "localfs", "file", "disk", ""])
def test_a_toolchain_with_a_local_state_backend_can_never_be_registered(kind):
    """Defence in depth: a local state backend is refused at the CONTROL PLANE, before readiness.

    A toolchain profile pinning local state cannot even be validated, so no manifest, plan, or
    readiness operation can ever be bound to one.
    """
    from secp_api.errors import ValidationFailedError
    from secp_api.toolchain_profile import validate_toolchain_profile
    from tests.conftest import VALID_TOOLCHAIN_PROFILE  # type: ignore[import-not-found]

    bad = copy.deepcopy(VALID_TOOLCHAIN_PROFILE)
    bad["state_backend"] = {"kind": kind, "reference": "terraform.tfstate"}
    with pytest.raises(ValidationFailedError):
        validate_toolchain_profile(bad)
