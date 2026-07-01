"""Proofs #6, #9, #10, #11, #12, #13, #15 — isolated-lab activation gate.

Exercises the REAL worker-only OpenTofu path (``run_real_provisioning``) using a
``FakeProcessExecutor`` and a ``FakeSecretResolver`` — no real binary, provider,
network, or endpoint. Covers: full approved dry-run → approve → apply → destroy;
apply refused without / on drift from an approved change set; destroy requires its own
approved change set; Temporal-only (inline refused) and mode/real-setting gates; drift
invalidation; simulator unchanged; and no secret leakage.
"""

from __future__ import annotations

import copy

import pytest
from secp_api.config import Settings
from secp_api.enums import (
    AuditAction,
    ChangeSetApprovalStatus,
    ProvisioningOperationKind,
    ProvisioningStatus,
)
from secp_api.errors import ProvisioningRefusedError
from secp_api.models import (
    ExecutionTarget,
    ProvisioningChangeSetApproval,
    ProvisioningManifest,
    ProvisioningOperation,
)
from secp_api.services import approvals
from secp_worker.provisioning import FakeProcessExecutor
from secp_worker.provisioning.execution import run_real_provisioning
from secp_worker.secrets import FakeSecretResolver

REAL_ON = Settings(
    app_env="test",
    provisioning_application_mode="isolated_lab",
    enable_real_provisioning=True,
    workflow_dispatch_mode="temporal",
)
REAL_OFF = Settings(app_env="test", provisioning_application_mode="simulator")


def _resolver():
    return FakeSecretResolver({"env:SECP_PROVIDER_SECRET__LAB": "fake-lab-token"})


def _pending(session, manifest_id, kind):
    return (
        session.query(ProvisioningChangeSetApproval)
        .filter_by(manifest_id=manifest_id, authorizes_kind=kind)
        .order_by(ProvisioningChangeSetApproval.created_at.desc())
        .first()
    )


def _actions(session):
    from secp_api.models import AuditEvent

    return {e.action for e in session.query(AuditEvent).all()}


def _dry_run(session, manifest_id, *, digest="fake-plan-deterministic"):
    return run_real_provisioning(
        session,
        manifest_id,
        ProvisioningOperationKind.dry_run,
        executor=FakeProcessExecutor(plan_digest=digest),
        settings=REAL_ON,
        dispatch_mode="temporal",
    )


# --- full approved lifecycle -------------------------------------------------


def test_full_real_lab_lifecycle_with_explicit_approval(session, principal, lab_env):
    env = lab_env()
    mid = env.manifest.id

    # 1. Dry run (apply preview) → pending change-set approval, awaiting approval.
    dry = _dry_run(session, mid)
    session.commit()
    assert dry.status == ProvisioningStatus.awaiting_change_set_approval
    approval = _pending(session, mid, ProvisioningOperationKind.apply)
    assert approval is not None and approval.status == ChangeSetApprovalStatus.pending
    assert dry.result["change_set_hash"] == approval.change_set_hash

    # 2. Explicit human approval of that exact change set.
    approvals.approve_change_set(session, principal, approval.id, "human reviewed")
    session.commit()

    # 3. Apply — regenerated dry run matches the approved hash.
    applied = run_real_provisioning(
        session,
        mid,
        ProvisioningOperationKind.apply,
        executor=FakeProcessExecutor(),
        settings=REAL_ON,
        dispatch_mode="temporal",
        secret_resolver=_resolver(),
    )
    session.commit()
    assert applied.status == ProvisioningStatus.applied
    assert session.get(ProvisioningChangeSetApproval, approval.id).status == (
        ChangeSetApprovalStatus.consumed
    )

    # 4. Destroy needs its OWN approved destroy change set.
    ddry = run_real_provisioning(
        session,
        mid,
        ProvisioningOperationKind.destroy_dry_run,
        executor=FakeProcessExecutor(),
        settings=REAL_ON,
        dispatch_mode="temporal",
    )
    session.commit()
    assert ddry.status == ProvisioningStatus.awaiting_change_set_approval
    dapproval = _pending(session, mid, ProvisioningOperationKind.destroy)
    approvals.approve_change_set(session, principal, dapproval.id, "destroy reviewed")
    session.commit()

    destroyed = run_real_provisioning(
        session,
        mid,
        ProvisioningOperationKind.destroy,
        executor=FakeProcessExecutor(),
        settings=REAL_ON,
        dispatch_mode="temporal",
        secret_resolver=_resolver(),
    )
    session.commit()
    assert destroyed.status == ProvisioningStatus.destroyed

    actions = _actions(session)
    for expected in (
        AuditAction.workspace_rendered,
        AuditAction.change_set_recorded,
        AuditAction.change_set_approved,
        AuditAction.provisioning_apply_started,
        AuditAction.provisioning_applied,
        AuditAction.provisioning_destroyed,
    ):
        assert expected.value in actions


# --- #9 apply refused without approval ---------------------------------------


def test_apply_refused_without_approval(session, principal, lab_env):
    env = lab_env()
    _dry_run(session, env.manifest.id)  # produces a PENDING (unapproved) change set
    session.commit()
    with pytest.raises(ProvisioningRefusedError, match="none is approved"):
        run_real_provisioning(
            session,
            env.manifest.id,
            ProvisioningOperationKind.apply,
            executor=FakeProcessExecutor(),
            settings=REAL_ON,
            dispatch_mode="temporal",
            secret_resolver=_resolver(),
        )


# --- #10 apply refused when regenerated dry run differs ----------------------


def test_apply_refused_on_regenerated_dry_run_mismatch(session, principal, lab_env):
    env = lab_env()
    mid = env.manifest.id
    _dry_run(session, mid, digest="ORIGINAL")
    session.commit()
    approval = _pending(session, mid, ProvisioningOperationKind.apply)
    approvals.approve_change_set(session, principal, approval.id, "approved original")
    session.commit()

    # The regenerated dry run now yields a DIFFERENT plan digest → different hash.
    with pytest.raises(ProvisioningRefusedError, match="differs from the approved"):
        run_real_provisioning(
            session,
            mid,
            ProvisioningOperationKind.apply,
            executor=FakeProcessExecutor(plan_digest="DRIFTED"),
            settings=REAL_ON,
            dispatch_mode="temporal",
            secret_resolver=_resolver(),
        )


# --- #11 destroy requires its own approved destroy change set ----------------


def test_destroy_refused_without_destroy_approval(session, principal, lab_env):
    env = lab_env()
    mid = env.manifest.id
    # Approve + apply first so an APPLY change set is approved/consumed.
    _dry_run(session, mid)
    session.commit()
    approvals.approve_change_set(
        session, principal, _pending(session, mid, ProvisioningOperationKind.apply).id, "ok"
    )
    session.commit()
    run_real_provisioning(
        session,
        mid,
        ProvisioningOperationKind.apply,
        executor=FakeProcessExecutor(),
        settings=REAL_ON,
        dispatch_mode="temporal",
        secret_resolver=_resolver(),
    )
    session.commit()
    # Destroy without a destroy change set is refused (an apply approval is not enough).
    with pytest.raises(ProvisioningRefusedError, match="none is approved"):
        run_real_provisioning(
            session,
            mid,
            ProvisioningOperationKind.destroy,
            executor=FakeProcessExecutor(),
            settings=REAL_ON,
            dispatch_mode="temporal",
            secret_resolver=_resolver(),
        )


# --- #12 Temporal required, inline refused, gates ----------------------------


def test_inline_execution_is_refused(session, principal, lab_env):
    env = lab_env()
    with pytest.raises(ProvisioningRefusedError, match="inline execution is refused"):
        run_real_provisioning(
            session,
            env.manifest.id,
            ProvisioningOperationKind.dry_run,
            executor=FakeProcessExecutor(),
            settings=REAL_ON,
            dispatch_mode="inline",
        )


def test_disabled_application_mode_is_refused(session, principal, lab_env):
    env = lab_env()
    with pytest.raises(ProvisioningRefusedError, match="isolated-lab application mode"):
        run_real_provisioning(
            session,
            env.manifest.id,
            ProvisioningOperationKind.dry_run,
            executor=FakeProcessExecutor(),
            settings=REAL_OFF,
            dispatch_mode="temporal",
        )


def test_real_provisioning_setting_required(session, principal, lab_env):
    env = lab_env()
    settings = Settings(
        app_env="test",
        provisioning_application_mode="isolated_lab",
        enable_real_provisioning=False,
        workflow_dispatch_mode="temporal",
    )
    with pytest.raises(ProvisioningRefusedError, match="real provisioning is disabled"):
        run_real_provisioning(
            session,
            env.manifest.id,
            ProvisioningOperationKind.dry_run,
            executor=FakeProcessExecutor(),
            settings=settings,
            dispatch_mode="temporal",
        )


# --- #6 drift invalidates execution ------------------------------------------


def test_toolchain_profile_disabled_after_approval_refuses(session, principal, lab_env):
    from secp_api.services import toolchain

    env = lab_env()
    mid = env.manifest.id
    _dry_run(session, mid)
    session.commit()
    approvals.approve_change_set(
        session, principal, _pending(session, mid, ProvisioningOperationKind.apply).id, "ok"
    )
    session.commit()
    # Disable the pinned toolchain profile → the activation gate fails closed.
    toolchain.disable_toolchain_profile(session, principal, env.toolchain.id)
    session.commit()
    with pytest.raises(ProvisioningRefusedError, match="not active|drift"):
        run_real_provisioning(
            session,
            mid,
            ProvisioningOperationKind.apply,
            executor=FakeProcessExecutor(),
            settings=REAL_ON,
            dispatch_mode="temporal",
            secret_resolver=_resolver(),
        )


def test_scope_policy_drift_after_manifest_refuses(session, principal, lab_env):
    env = lab_env()
    target = session.get(ExecutionTarget, env.target.id)
    drifted = copy.deepcopy(target.scope_policy)
    drifted["provisioning"]["max_vms"] = 999
    session.execute(
        ExecutionTarget.__table__.update()
        .where(ExecutionTarget.__table__.c.id == target.id)
        .values(scope_policy=drifted)
    )
    session.commit()
    session.expire_all()
    with pytest.raises(ProvisioningRefusedError, match="scope_policy has drifted"):
        _dry_run(session, env.manifest.id)


def test_non_isolated_lab_profile_cannot_reach_real_path(session, principal, lab_env):
    """A manifest with no pinned toolchain profile cannot use the real path."""
    # A B0-style provisioning env (no toolchain profile) yields a manifest with a null
    # toolchain binding; the real gate fails closed.
    from tests.conftest import build_provisioning_env  # type: ignore

    env = build_provisioning_env(session, principal)
    from secp_api.services import manifests

    manifest = manifests.generate_manifest(session, principal, env.plan.id)
    session.commit()
    with pytest.raises(ProvisioningRefusedError, match="toolchain profile"):
        _dry_run(session, manifest.id)


# --- #13 simulator unchanged, #15 no secret leakage --------------------------


def test_simulator_path_unaffected_by_real_settings(session, principal, running_exercise):
    running_exercise()
    session.commit()
    assert session.query(ProvisioningManifest).count() == 0
    assert session.query(ProvisioningOperation).count() == 0


def test_no_secret_leaks_in_records_or_audit(session, principal, lab_env):
    from secp_api.models import AuditEvent

    env = lab_env()
    mid = env.manifest.id
    _dry_run(session, mid)
    session.commit()
    approvals.approve_change_set(
        session, principal, _pending(session, mid, ProvisioningOperationKind.apply).id, "ok"
    )
    session.commit()
    applied = run_real_provisioning(
        session,
        mid,
        ProvisioningOperationKind.apply,
        executor=FakeProcessExecutor(),
        settings=REAL_ON,
        dispatch_mode="temporal",
        secret_resolver=_resolver(),
    )
    session.commit()
    blob = str(applied.result).lower()
    for needle in ("fake-lab-token", "token", "secret", "password", "credential", "api_token"):
        assert needle not in blob
    audit_blob = " ".join(str(e.data) for e in session.query(AuditEvent).all()).lower()
    assert "fake-lab-token" not in audit_blob
    # No filesystem workspace path leaks into the durable record.
    assert "secp-tofu-ws-" not in blob
