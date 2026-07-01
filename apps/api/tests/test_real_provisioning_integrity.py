"""Correction-pass proofs (SECP-002B-1A):
- Part 1: exact prepared-plan application; ephemeral workspace/plan cleanup; no raw plan.
- Part 2: idempotent/retryable operations; safe re-run while awaiting; failed re-entry.
- Part 5: strengthened profile/target/org/hash binding (direct DB-corruption tests).

All fakes; no real binary, provider, network, or endpoint.
"""

from __future__ import annotations

import copy
import json

import pytest
from secp_api.config import Settings
from secp_api.enums import ProvisioningOperationKind as K
from secp_api.enums import ProvisioningStatus
from secp_api.errors import ProvisioningRefusedError
from secp_api.models import (
    Organization,
    ProvisioningChangeSetApproval,
    ProvisioningManifest,
    ToolchainProfile,
)
from secp_api.services import approvals, toolchain
from secp_worker.provisioning import FakeProcessExecutor, build_fixture_show_json
from secp_worker.provisioning.execution import run_real_provisioning
from secp_worker.provisioning.process_executor import ProcessResult
from secp_worker.secrets import FakeSecretResolver

REAL_ON = Settings(
    app_env="test",
    provisioning_application_mode="isolated_lab",
    enable_real_provisioning=True,
    workflow_dispatch_mode="temporal",
)


def _resolver():
    return FakeSecretResolver({"env:SECP_PROVIDER_SECRET__LAB": "fake-lab-token"})


def _exec(manifest, *, actions=("create",)):
    return FakeProcessExecutor(show_json=build_fixture_show_json(manifest.content, actions=actions))


def _run(session, manifest, kind, *, executor=None, actions=("create",), resolver=None, root=None):
    return run_real_provisioning(
        session,
        manifest.id,
        kind,
        executor=executor if executor is not None else _exec(manifest, actions=actions),
        settings=REAL_ON,
        dispatch_mode="temporal",
        secret_resolver=resolver,
        workspace_root=root,
    )


def _pending(session, manifest_id, kind):
    return (
        session.query(ProvisioningChangeSetApproval)
        .filter_by(manifest_id=manifest_id, authorizes_kind=kind)
        .order_by(ProvisioningChangeSetApproval.created_at.desc())
        .first()
    )


def _approve_apply(session, principal, manifest):
    _run(session, manifest, K.dry_run)
    session.commit()
    approvals.approve_change_set(
        session, principal, _pending(session, manifest.id, K.apply).id, "ok"
    )
    session.commit()


# --- Part 1: exact prepared plan + ephemeral cleanup + no raw plan -----------


def test_apply_uses_same_prepared_plan_no_toctou(session, principal, lab_env, tmp_path):
    env = lab_env()
    m = env.manifest
    _approve_apply(session, principal, m)
    root = str(tmp_path)
    applied = _run(session, m, K.apply, resolver=_resolver(), root=root)
    session.commit()
    assert applied.status == ProvisioningStatus.applied
    # No ephemeral workspace or binary plan artifact survives.
    assert list(tmp_path.glob("secp-tofu-ws-*")) == []
    # Durable record holds only the canonical change set — no raw plan JSON.
    blob = str(applied.result).lower()
    for needle in ("before", '"after"', "root_password", "plan.tfplan", "secp-tofu-ws-"):
        assert needle not in blob


def test_ephemeral_workspace_cleaned_up_on_failure(session, principal, lab_env, tmp_path):
    env = lab_env()
    m = env.manifest
    _approve_apply(session, principal, m)
    # Script: init ok, plan ok, show (matching fixture), apply FAILS.
    show = ProcessResult(returncode=0, stdout=json.dumps(build_fixture_show_json(m.content)))
    failing = FakeProcessExecutor(
        script=[
            ProcessResult(returncode=0),
            ProcessResult(returncode=0),
            show,
            ProcessResult(returncode=1),  # apply fails
        ]
    )
    op = _run(session, m, K.apply, executor=failing, resolver=_resolver(), root=str(tmp_path))
    session.commit()
    assert op.status == ProvisioningStatus.failed
    # Cleanup still happened despite the failure.
    assert list(tmp_path.glob("secp-tofu-ws-*")) == []


def test_dry_run_persists_only_canonical_change_set(session, principal, lab_env):
    env = lab_env()
    dry = _run(session, env.manifest, K.dry_run)
    session.commit()
    assert set(dry.result) == {"kind", "summary", "change_set_hash", "workspace_hash", "resources"}
    for r in dry.result["resources"]:
        assert set(r) == {"address", "mode", "type", "name", "provider", "actions", "replace"}


# --- Part 2: idempotency / retry --------------------------------------------


def test_retry_applied_operation_is_idempotent_noop(session, principal, lab_env):
    env = lab_env()
    m = env.manifest
    _approve_apply(session, principal, m)
    _run(session, m, K.apply, resolver=_resolver())
    session.commit()
    # Retry with a fresh executor that records calls — nothing must be invoked.
    retry_exec = _exec(m)
    op = _run(session, m, K.apply, executor=retry_exec, resolver=_resolver())
    session.commit()
    assert op.status == ProvisioningStatus.applied
    assert op.result.get("idempotent_noop") is True
    assert retry_exec.calls == []  # no renderer/executor/runner invocation


def test_retry_destroyed_operation_is_idempotent_noop(session, principal, lab_env):
    env = lab_env()
    m = env.manifest
    # dry -> approve -> apply
    _approve_apply(session, principal, m)
    _run(session, m, K.apply, resolver=_resolver())
    session.commit()
    # destroy dry -> approve -> destroy
    _run(session, m, K.destroy_dry_run, actions=("delete",))
    session.commit()
    approvals.approve_change_set(session, principal, _pending(session, m.id, K.destroy).id, "ok")
    session.commit()
    _run(session, m, K.destroy, actions=("delete",), resolver=_resolver())
    session.commit()
    # Retry destroy — idempotent noop, nothing invoked.
    retry_exec = _exec(m, actions=("delete",))
    op = _run(session, m, K.destroy, executor=retry_exec, actions=("delete",), resolver=_resolver())
    session.commit()
    assert op.status == ProvisioningStatus.destroyed
    assert retry_exec.calls == []


def test_failed_apply_can_retry_after_new_valid_plan(session, principal, lab_env):
    env = lab_env()
    m = env.manifest
    _approve_apply(session, principal, m)
    show = ProcessResult(returncode=0, stdout=json.dumps(build_fixture_show_json(m.content)))
    failing = FakeProcessExecutor(
        script=[
            ProcessResult(returncode=0),
            ProcessResult(returncode=0),
            show,
            ProcessResult(returncode=1),
        ]
    )
    op1 = _run(session, m, K.apply, executor=failing, resolver=_resolver())
    session.commit()
    assert op1.status == ProvisioningStatus.failed
    # Retry with a healthy executor — the same approval still authorizes it.
    op2 = _run(session, m, K.apply, resolver=_resolver())
    session.commit()
    assert op2.id == op1.id
    assert op2.status == ProvisioningStatus.applied


def test_rerun_dry_run_while_awaiting_is_legal(session, principal, lab_env):
    env = lab_env()
    m = env.manifest
    op1 = _run(session, m, K.dry_run)
    session.commit()
    assert op1.status == ProvisioningStatus.awaiting_change_set_approval
    op2 = _run(session, m, K.dry_run)  # same hash — must not raise / illegal-transition
    session.commit()
    assert op2.id == op1.id
    assert op2.status == ProvisioningStatus.awaiting_change_set_approval
    # Same hash → one pending approval, not two.
    assert (
        session.query(ProvisioningChangeSetApproval)
        .filter_by(manifest_id=m.id, authorizes_kind=K.apply)
        .count()
        == 1
    )


def test_changed_dry_run_creates_new_pending_preserving_original(session, principal, lab_env):
    env = lab_env()
    m = env.manifest
    _run(session, m, K.dry_run, actions=("create",))
    session.commit()
    first = _pending(session, m.id, K.apply)
    _run(session, m, K.dry_run, actions=("update",))  # different canonical hash
    session.commit()
    approvals_all = (
        session.query(ProvisioningChangeSetApproval)
        .filter_by(manifest_id=m.id, authorizes_kind=K.apply)
        .all()
    )
    assert len(approvals_all) == 2  # original preserved + new pending
    assert session.get(ProvisioningChangeSetApproval, first.id) is not None


# --- Part 5: strengthened binding (direct DB corruption) ---------------------


def _corrupt_manifest(session, manifest_id, **values):
    session.execute(
        ProvisioningManifest.__table__.update()
        .where(ProvisioningManifest.__table__.c.id == manifest_id)
        .values(**values)
    )
    session.commit()
    session.expire_all()


def _corrupt_profile(session, profile_id, **values):
    session.execute(
        ToolchainProfile.__table__.update()
        .where(ToolchainProfile.__table__.c.id == profile_id)
        .values(**values)
    )
    session.commit()
    session.expire_all()


def test_profile_content_changed_without_hash_is_refused(session, principal, lab_env):
    env = lab_env()
    tampered = copy.deepcopy(env.toolchain.content)
    tampered["opentofu_version"] = "8.8.8"  # valid but different; content_hash unchanged
    _corrupt_profile(session, env.toolchain.id, content=tampered)
    with pytest.raises(ProvisioningRefusedError, match="content hash does not match"):
        _run(session, env.manifest, K.dry_run)


def test_profile_id_mismatch_same_hash_is_refused(session, principal, lab_env):
    env = lab_env()
    # A second profile with identical content → identical content_hash, different id.
    twin = toolchain.register_toolchain_profile(
        session,
        principal,
        target_id=env.target.id,
        name="twin",
        profile=copy.deepcopy(env.toolchain.content),
    )
    session.commit()
    assert twin.content_hash == env.toolchain.content_hash and twin.id != env.toolchain.id
    _corrupt_manifest(session, env.manifest.id, toolchain_profile_id=twin.id)
    with pytest.raises(ProvisioningRefusedError, match="id disagreement|id mismatch"):
        _run(session, env.manifest, K.dry_run)


def test_profile_bound_to_another_target_is_refused(session, principal, lab_env):
    from secp_api.services import targets

    env = lab_env()
    other = targets.register_target(
        session,
        principal,
        display_name="Other",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref="env:SECP_PROVIDER_SECRET__OTHER",
        scope_policy={"provisioning": {}},
    )
    session.commit()
    _corrupt_profile(session, env.toolchain.id, execution_target_id=other.id)
    with pytest.raises(ProvisioningRefusedError, match="different execution target"):
        _run(session, env.manifest, K.dry_run)


def test_profile_bound_to_another_org_is_refused(session, principal, lab_env):
    env = lab_env()
    org = Organization(name="Rogue", slug="rogue-org")
    session.add(org)
    session.commit()
    _corrupt_profile(session, env.toolchain.id, organization_id=org.id)
    with pytest.raises(ProvisioningRefusedError, match="different organization"):
        _run(session, env.manifest, K.dry_run)
