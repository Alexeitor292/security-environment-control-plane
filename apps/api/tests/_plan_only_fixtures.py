"""Shared builders for the plan-only EXECUTION tests (B1B-PR5B) — NOT a test module.

These construct the exact new-shaped inputs the hardened plan-only executor + runner require: a
typed :class:`AttestedToolchain` (real lstat'd handles for the real-subprocess path, or lightweight
stubs for the cross-platform fake-executor path), a valid ``test_only`` :class:`PlanOnlyCapability`
bound to an exact lease/attempt/fingerprint, the exact closed child environment, and a matching
:class:`PlanOnlyExecutionContext`. Tests deliberately mismatch a single field to prove the executor
re-checks it independently (it is the FINAL enforcement boundary, ADR-022 §4).
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from secp_api.plan_activation_contract import (
    PLAN_ONLY_CAPABILITY_CONTRACT_VERSION,
    PLAN_SECRET_ENV_CONTRACT_VERSION,
)
from secp_worker.plan_gen.capability import (
    CONTROLLED_LIVE_CLASSIFICATION,
    TEST_ONLY_CLASSIFICATION,
    PlanOnlyActivation,
    issue_plan_only_capability,
)
from secp_worker.plan_gen.controlled_live import (
    CONTROLLED_LIVE_PROVIDER_SOURCE,
    CONTROLLED_LIVE_RENDERER_VERSION,
    controlled_live_renderer_implementation_digest,
)
from secp_worker.plan_gen.process_boundary import (
    PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
    PlanOnlyExecutionContext,
    plan_only_executor_implementation_digest,
)
from secp_worker.plan_gen.reattest import AttestedPath, AttestedToolchain
from secp_worker.plan_gen.runtime_inputs import PLAN_ONLY_CHILD_ENV_KEYS

NOW = datetime(2026, 7, 15, tzinfo=UTC)
_EXE = "/opt/tofu/tofu"


def _h(c: str) -> str:
    return "sha256:" + c * 64


def exact_child_env() -> dict[str, str]:
    """A concrete dict whose key set is EXACTLY :data:`PLAN_ONLY_CHILD_ENV_KEYS`."""
    return {k: ("LOCK" if "METHOD" in k else f"value-for-{k}") for k in PLAN_ONLY_CHILD_ENV_KEYS}


def _stub_path(path: str, *, is_dir: bool) -> SimpleNamespace:
    return SimpleNamespace(path=path, st_ino=1, st_dev=1, st_mode=0, is_dir=is_dir)


def stub_attested(*, exe: str = _EXE, mirror: str = "/w/mirror") -> SimpleNamespace:
    """A lightweight AttestedToolchain-shaped stub for the FAKE-executor (no real spawn) path."""
    return SimpleNamespace(
        evidence_hash=_h("5"),
        executable=_stub_path(exe, is_dir=False),
        provider_mirror=_stub_path(mirror, is_dir=True),
        provider_lockfile=_stub_path("/w/lock", is_dir=False),
        cli_config=_stub_path("/w/cli", is_dir=False),
        module_bundle=_stub_path("/w/bundle", is_dir=True),
    )


def _sha256_file(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _attested_path(path: str, *, is_dir: bool) -> AttestedPath:
    st = os.lstat(path)
    return AttestedPath(
        path=path.replace("\\", "/"),
        st_ino=st.st_ino,
        st_dev=st.st_dev,
        st_mode=st.st_mode,
        is_dir=is_dir,
        # FILE handles bind their on-disk content digest, so the executor's pre-spawn re-check binds
        # execution to the exact opened object (inode-reuse-robust). Directory handles carry none.
        content_digest="" if is_dir else _sha256_file(path),
    )


def real_attested(root: str, *, exe: str) -> AttestedToolchain:
    """Build a REAL :class:`AttestedToolchain` by lstat'ing + digesting on-disk handles.

    Creates a provider-mirror dir, a lockfile, a cli-config file, and a module-bundle dir so the
    executor's pre-spawn re-checks (identity for dirs, identity+content-digest for files, and the
    no-follow descriptor pinning for the executable) all pass.
    """
    root = root.replace("\\", "/").rstrip("/")
    mirror = f"{root}/mirror"
    bundle = f"{root}/bundle"
    lockfile = f"{root}/provider.lock"
    cli = f"{root}/cli.tofurc"
    os.makedirs(mirror, exist_ok=True)
    os.makedirs(bundle, exist_ok=True)
    for f in (lockfile, cli):
        with open(f, "w", encoding="utf-8") as fh:
            fh.write("x")
    return AttestedToolchain(
        evidence_hash=_h("5"),
        executable=_attested_path(exe, is_dir=False),
        provider_mirror=_attested_path(mirror, is_dir=True),
        provider_lockfile=_attested_path(lockfile, is_dir=False),
        cli_config=_attested_path(cli, is_dir=False),
        module_bundle=_attested_path(bundle, is_dir=True),
    )


def build_test_only_capability(
    *,
    lease_id: uuid.UUID,
    attempt_id: uuid.UUID,
    attempt_number: int,
    operation_fingerprint: str,
    now: datetime = NOW,
    classification: str = TEST_ONLY_CLASSIFICATION,
    **over,
):
    """A valid capability bound to the exact lease/attempt/fingerprint (test_only by default)."""
    base = dict(
        organization_id=uuid.uuid4(),
        plan_generation_authorization_id=uuid.uuid4(),
        authorization_version=1,
        authorization_expiry=now + timedelta(hours=2),
        operation_fingerprint=operation_fingerprint,
        plan_only_capability_contract_version=PLAN_ONLY_CAPABILITY_CONTRACT_VERSION,
        classification=classification,
        expires_at=now + timedelta(minutes=10),
        environment_version_id=uuid.uuid4(),
        environment_version_content_hash=_h("d"),
        deployment_plan_id=uuid.uuid4(),
        deployment_plan_content_hash=_h("e"),
        provisioning_manifest_id=uuid.uuid4(),
        provisioning_manifest_content_hash=_h("b"),
        execution_target_id=uuid.uuid4(),
        target_config_hash=_h("f"),
        target_onboarding_id=uuid.uuid4(),
        onboarding_boundary_hash=_h("1"),
        eligibility_preflight_id=uuid.uuid4(),
        eligibility_evidence_hash=_h("2"),
        toolchain_profile_id=uuid.uuid4(),
        toolchain_profile_hash=_h("3"),
        toolchain_attestation_id=uuid.uuid4(),
        toolchain_attestation_hash=_h("4"),
        fresh_attestation_evidence_hash=_h("5"),
        provider_source=CONTROLLED_LIVE_PROVIDER_SOURCE,
        provider_version="0.80.0",
        provider_lockfile_hash=_h("6"),
        provider_mirror_identity=_h("7"),
        module_bundle_hash=_h("8"),
        renderer_version=CONTROLLED_LIVE_RENDERER_VERSION,
        activation_dossier_id=uuid.uuid4(),
        activation_dossier_hash=_h("a"),
        activation_dossier_revision=1,
        activation_dossier_expiry=now + timedelta(hours=3),
        provider_credential_binding_id=uuid.uuid4(),
        provider_credential_binding_version=1,
        state_credential_binding_id=uuid.uuid4(),
        state_credential_binding_version=1,
        remote_state_readiness_id=uuid.uuid4(),
        remote_state_evidence_hash=_h("9"),
        plan_secret_readiness_id=uuid.uuid4(),
        plan_secret_evidence_hash=_h("0"),
        worker_identity_registration_id=uuid.uuid4(),
        worker_identity_version=1,
        execution_lease_id=lease_id,
        attempt_id=attempt_id,
        attempt_number=attempt_number,
        process_implementation_id=PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        process_implementation_digest=plan_only_executor_implementation_digest(),
        renderer_module_id=CONTROLLED_LIVE_RENDERER_VERSION,
        renderer_module_digest=controlled_live_renderer_implementation_digest(),
    )
    base.update(over)
    return issue_plan_only_capability(
        PlanOnlyActivation(**base),
        now=now,
        expected_process_digest=plan_only_executor_implementation_digest(),
        expected_renderer_digest=controlled_live_renderer_implementation_digest(),
    )


def build_controlled_live_capability(
    *, lease_id, attempt_id, attempt_number, operation_fingerprint, **over
):
    """A valid ``controlled_live`` capability (for the production-mode executor check)."""
    return build_test_only_capability(
        lease_id=lease_id,
        attempt_id=attempt_id,
        attempt_number=attempt_number,
        operation_fingerprint=operation_fingerprint,
        classification=CONTROLLED_LIVE_CLASSIFICATION,
        **over,
    )


def make_context(
    *,
    attested,
    capability,
    workspace: str,
    plan_file: str,
    env: dict[str, str] | None = None,
    env_contract_version: str = PLAN_SECRET_ENV_CONTRACT_VERSION,
    timeout: int = 60,
    max_output_bytes: int = 4 * 1024 * 1024,
    now: datetime = NOW,
    **over,
) -> PlanOnlyExecutionContext:
    """Build a context whose expected_* fields agree with ``capability`` by default.

    ``over`` may override any expected_* field so a test can prove the executor refuses a capability
    minted for a DIFFERENT lease/attempt/fingerprint (a cross-lease forgery).
    """
    act = capability.activation
    fields = dict(
        executable_handle=attested.executable,
        provider_mirror_handle=attested.provider_mirror,
        cli_config_handle=attested.cli_config,
        module_bundle_handle=attested.module_bundle,
        workspace=workspace,
        plan_file=plan_file,
        env=exact_child_env() if env is None else env,
        env_contract_version=env_contract_version,
        capability=capability,
        timeout=timeout,
        max_output_bytes=max_output_bytes,
        expected_lease_id=act.execution_lease_id,
        expected_attempt_id=act.attempt_id,
        expected_attempt_number=act.attempt_number,
        expected_operation_fingerprint=act.operation_fingerprint,
        now=now,
    )
    fields.update(over)
    return PlanOnlyExecutionContext(**fields)
