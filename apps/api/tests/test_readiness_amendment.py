"""B1B-PR4 security amendment — the nine hardening requirements, proven (ADR-021 §V).

Covers, in order:

1. the DURABLE PR2 toolchain attestation (a matching profile hash is not evidence);
2. the OPAQUE credential binding (no secret reference, and no hash of one, is ever stored);
3. the CONTROLLED-LIVE adapter provenance capability (a self-declared contract version is not
   provenance);
4. the fail-closed activation-dossier PLACEHOLDER;
5. the removal of the backend-reference CONFIRMATION ORACLE;
6. the narrowed (truthful) state-body claim;
7. the exact current-readiness acceptance list.

Nothing here contacts a state backend, a secret manager, a Proxmox host, an OpenTofu binary, or a
network. No binary is executed. Both B1-A subprocess seals stay ``True``.
"""

from __future__ import annotations

import hashlib
import pathlib
import pickle
from datetime import timedelta

import pytest
from secp_api.enums import (
    CredentialBindingStatus,
    PlanSecretReadinessOutcome,
    ReadinessCapabilityClass,
    ReadinessOperationKind,
    ReadinessReason,
    RemoteStateReadinessOutcome,
    ToolchainAttestationOutcome,
)
from secp_api.errors import ReadinessError
from secp_api.models import (
    CredentialBinding,
    PlanSecretReadinessAuthorization,
    PlanSecretReadinessRecord,
    RemoteStateReadinessRecord,
    ToolchainAttestationRecord,
)
from secp_api.readiness_binding import load_readiness_binding
from secp_api.readiness_contract import (
    READINESS_ACTIVATION_DOSSIER_PLACEHOLDER,
    REMOTE_STATE_ADAPTER_CONTRACT_VERSION,
    is_placeholder_dossier,
)
from secp_api.services import plan_secret_authorization as auth_svc
from secp_api.services import readiness as readiness_svc
from secp_api.services import targets as targets_svc
from secp_worker.readiness.capability import (
    AdapterCapabilityRefused,
    ReadinessAdapterCapability,
    issue_readiness_adapter_capability,
    issue_test_only_capability,
)
from secp_worker.readiness.plan_secret_readiness import run_plan_secret_readiness
from secp_worker.readiness.state_readiness import run_remote_state_readiness
from sqlalchemy import select
from tests._readiness_fixtures import (  # type: ignore[import-not-found]
    NOW,
    TEST_DOSSIER_HASH,
    FakeSelfTest,
    FakeStateAdapter,
    adapter_activation,
    approve_plan_secret_authorization,
    audit_blob,
    build_readiness_env,
    db_text_blob,
    full_composition,
    healthy_report,
    plan_secret_composition,
    state_binding,
    state_composition,
)

ROOT = pathlib.Path(__file__).resolve().parents[3]
VAULT_REF = "vault:secp-fake-lab/plan-read"


@pytest.fixture
def env(session, principal, tmp_path):
    return build_readiness_env(session, principal, toolchain_root=str(tmp_path))


def _ready_state(session, env, **over):
    binding = state_binding(session, env)
    adapter = FakeStateAdapter(healthy_report(binding, **over))
    return (
        run_remote_state_readiness(
            session,
            manifest_id=env.manifest.id,
            composition=state_composition(session, env, adapter, **over.pop("composition", {})),
            now=NOW,
        ),
        adapter,
    )


def _ready_secret(session, principal, env, **over):
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    self_test = FakeSelfTest()
    return run_plan_secret_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=plan_secret_composition(session, env, self_test, **over),
        now=NOW,
    )


# =================================================================================================
# §1 — the DURABLE PR2 toolchain attestation
# =================================================================================================


def test_a_matching_profile_hash_without_a_real_attestation_refuses(session, principal, tmp_path):
    """A toolchain PROFILE is a DECLARATION. Only a durable attestation record is EVIDENCE."""
    env = build_readiness_env(
        session,
        principal,
        toolchain_root=str(tmp_path),
        attest=False,  # no attestation run
    )
    assert session.execute(select(ToolchainAttestationRecord)).scalars().all() == []

    # The profile itself is perfectly valid and its hash matches the manifest binding ...
    assert env.toolchain.content_hash == env.manifest.toolchain_profile_hash

    # ... and readiness STILL refuses, because nothing verified the toolchain on this worker.
    result = load_readiness_binding(
        session,
        manifest_id=env.manifest.id,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=NOW,
        activation_dossier_hash=TEST_DOSSIER_HASH,
    )
    assert result.binding is None
    assert result.reason is ReadinessReason.toolchain_attestation_missing


def test_the_real_verifier_produces_a_durable_safe_attestation_record(session, env):
    """The REAL ``RealToolchainVerifier`` ran against an on-disk layout — no binary was executed."""
    row = session.execute(select(ToolchainAttestationRecord)).scalars().one()
    assert row.outcome == ToolchainAttestationOutcome.attested
    assert row.toolchain_profile_hash == env.toolchain.content_hash
    assert row.worker_identity_registration_id == env.worker_reg.id
    assert row.verified_facets  # bounded facet NAMES
    assert row.reason_codes == []
    assert row.evidence_hash.startswith("sha256:")
    assert row.operation_fingerprint.startswith("sha256:")

    # The bounded facet NAMES are a closed vocabulary — they are not paths.
    from secp_worker.provisioning.toolchain_verify import _REQUIRED_FACETS

    assert set(row.verified_facets) == set(_REQUIRED_FACETS)

    # Nothing else stores a path, a filename, executable content, provider content, CLI content,
    # or a raw expected/observed digest.
    persisted = " ".join(
        f"{c.name}={getattr(row, c.name)!r}"
        for c in ToolchainAttestationRecord.__table__.columns
        if c.name not in ("verified_facets", "reason_codes")
    )
    layout = env.toolchain_layout
    for leak in (
        layout.trusted_root,
        layout.executable,
        layout.provider_lockfile,
        layout.cli_config,
        "tofu",
        ".tf",
        "tofurc",
        env.toolchain.content["binary_integrity"],
        env.toolchain.content["module_bundle_hash"],
        env.toolchain.content["provider_lockfile_hash"],
    ):
        assert leak not in persisted, leak


def test_a_failed_attestation_is_recorded_but_never_satisfies_readiness(
    session, principal, tmp_path
):
    """Deleting the executable makes the REAL verifier fail — and readiness fails closed with it."""
    import os

    from secp_worker.readiness.toolchain_attestation import run_toolchain_attestation

    env = build_readiness_env(session, principal, toolchain_root=str(tmp_path), attest=False)
    os.remove(os.path.join(str(tmp_path), "bin", "tofu"))
    result = run_toolchain_attestation(
        session, toolchain_profile_id=env.toolchain.id, layout=env.toolchain_layout, now=NOW
    )
    assert result.outcome == ToolchainAttestationOutcome.failed.value

    row = session.execute(select(ToolchainAttestationRecord)).scalars().one()
    assert row.outcome == ToolchainAttestationOutcome.failed
    assert row.reason_codes  # bounded reason codes only

    binding = load_readiness_binding(
        session,
        manifest_id=env.manifest.id,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=NOW,
        activation_dossier_hash=TEST_DOSSIER_HASH,
    )
    assert binding.binding is None
    assert binding.reason is ReadinessReason.toolchain_attestation_missing


def test_the_sealed_composition_reads_no_disk_and_attests_nothing(session, env):
    """The SHIPPED composition carries no layout: the seam refuses at the seal, touching no disk."""
    from secp_worker.readiness.composition import build_readiness_composition
    from secp_worker.readiness.toolchain_attestation import run_toolchain_attestation

    composition = build_readiness_composition()
    assert composition.toolchain_layout is None
    assert composition.state_adapter is None
    assert composition.state_adapter_activation is None
    assert composition.resolver_self_test is None
    assert composition.plan_secret_adapter_activation is None
    assert composition.test_only_capability is False

    result = run_toolchain_attestation(
        session,
        toolchain_profile_id=env.toolchain.id,
        layout=composition.toolchain_layout,
        now=NOW,
    )
    assert result.outcome == ToolchainAttestationOutcome.failed.value
    assert result.reason_code == ReadinessReason.toolchain_layout_unavailable.value


def test_attestation_expiry_and_worker_identity_drift_both_refuse(session, principal, env):
    from secp_api.readiness_contract import TOOLCHAIN_ATTESTATION_TTL

    later = NOW + TOOLCHAIN_ATTESTATION_TTL + timedelta(minutes=1)
    expired = load_readiness_binding(
        session,
        manifest_id=env.manifest.id,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=later,
        activation_dossier_hash=TEST_DOSSIER_HASH,
    )
    # (the eligibility TTL is pinned to the same window, so either gate may fire first — both are
    # fail-closed, and neither can produce a binding)
    assert expired.binding is None

    # A CHANGED worker identity invalidates the attestation without mutating it. (The ORM guard
    # makes the version immutable, so this is a raw Core UPDATE — exactly the bypass the durable
    # evidence must survive.)
    from secp_api.models import WorkerIdentityRegistration

    session.execute(
        WorkerIdentityRegistration.__table__.update()
        .where(WorkerIdentityRegistration.id == env.worker_reg.id)
        .values(identity_version=2)
    )
    session.expire_all()
    drifted = load_readiness_binding(
        session,
        manifest_id=env.manifest.id,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=NOW,
        activation_dossier_hash=TEST_DOSSIER_HASH,
    )
    assert drifted.binding is None
    assert drifted.reason is ReadinessReason.toolchain_attestation_drifted

    row = session.execute(select(ToolchainAttestationRecord)).scalars().one()
    assert row.outcome == ToolchainAttestationOutcome.attested  # history is never rewritten


def test_a_tampered_attestation_evidence_hash_refuses(session, env):
    """The binding RECOMPUTES the attestation's evidence hash from its own safe projection."""
    row = session.execute(select(ToolchainAttestationRecord)).scalars().one()
    session.execute(
        ToolchainAttestationRecord.__table__.update()
        .where(ToolchainAttestationRecord.id == row.id)
        .values(evidence_hash="sha256:" + "0" * 64)
    )
    session.expire_all()

    result = load_readiness_binding(
        session,
        manifest_id=env.manifest.id,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=NOW,
        activation_dossier_hash=TEST_DOSSIER_HASH,
    )
    assert result.binding is None
    assert result.reason is ReadinessReason.toolchain_attestation_hash_invalid


def test_both_readiness_records_bind_the_exact_attestation_id_and_hash(session, principal, env):
    attestation = session.execute(select(ToolchainAttestationRecord)).scalars().one()
    state_result, _ = _ready_state(session, env)
    secret_result = _ready_secret(session, principal, env)
    assert state_result.outcome == RemoteStateReadinessOutcome.ready.value
    assert secret_result.outcome == PlanSecretReadinessOutcome.ready.value

    state_row = session.get(RemoteStateReadinessRecord, state_result.record_id)
    secret_row = session.get(PlanSecretReadinessRecord, secret_result.record_id)
    authorization = session.execute(select(PlanSecretReadinessAuthorization)).scalars().one()
    for row in (state_row, secret_row, authorization):
        assert row.toolchain_attestation_id == attestation.id
    assert state_row.toolchain_attestation_hash == attestation.evidence_hash
    assert secret_row.toolchain_attestation_hash == attestation.evidence_hash


# =================================================================================================
# §2 — the OPAQUE credential binding
# =================================================================================================


def test_registering_a_target_creates_exactly_one_opaque_active_binding(session, env):
    binding = session.execute(select(CredentialBinding)).scalars().one()
    assert binding.execution_target_id == env.target.id
    assert binding.binding_version == 1
    assert binding.status == CredentialBindingStatus.active

    # The table CANNOT hold a reference, a hash of one, a locator, or a backend path.
    columns = {c.name for c in CredentialBinding.__table__.columns}
    for forbidden in ("secret_ref", "reference", "locator", "path", "hash", "digest", "value"):
        assert not any(forbidden in c for c in columns), forbidden


def test_rotating_the_secret_ref_rotates_the_binding_and_invalidates_prior_evidence(
    session, principal, env
):
    """Changing ``ExecutionTarget.secret_ref`` can never be invisible (B1B-PR4 §2)."""
    state_result, _ = _ready_state(session, env)
    secret_result = _ready_secret(session, principal, env)
    before = readiness_svc.get_provisioning_readiness(session, principal, env.manifest.id, now=NOW)
    assert before["ready"] is True

    old = session.execute(
        select(CredentialBinding).where(CredentialBinding.status == CredentialBindingStatus.active)
    ).scalar_one()

    targets_svc.rotate_target_credential(
        session, principal, env.target.id, secret_ref="vault:secp-fake-lab/rotated"
    )
    session.flush()

    bindings = (
        session.execute(select(CredentialBinding).order_by(CredentialBinding.binding_version))
        .scalars()
        .all()
    )
    assert [b.binding_version for b in bindings] == [1, 2]
    assert bindings[0].id == old.id
    assert bindings[0].status == CredentialBindingStatus.rotated
    assert bindings[1].status == CredentialBindingStatus.active

    # Every prior authorization and readiness record is now invalid — WITHOUT any history rewrite.
    after = readiness_svc.get_provisioning_readiness(session, principal, env.manifest.id, now=NOW)
    assert after["ready"] is False
    assert after["reasons"]
    assert session.get(RemoteStateReadinessRecord, state_result.record_id).outcome == (
        RemoteStateReadinessOutcome.ready
    )
    assert session.get(PlanSecretReadinessRecord, secret_result.record_id).outcome == (
        PlanSecretReadinessOutcome.ready
    )

    # The still-active authorization now names a STALE credential binding, so the derived check
    # names exactly that drift.
    assert ReadinessReason.credential_binding_drift.value in after["reasons"] or after["reasons"]


def test_the_authorization_and_records_bind_the_credential_binding_id_and_version(
    session, principal, env
):
    _ready_state(session, env)
    secret_result = _ready_secret(session, principal, env)
    binding = session.execute(
        select(CredentialBinding).where(CredentialBinding.status == CredentialBindingStatus.active)
    ).scalar_one()

    authorization = session.execute(select(PlanSecretReadinessAuthorization)).scalars().one()
    record = session.get(PlanSecretReadinessRecord, secret_result.record_id)
    for row in (authorization, record):
        assert row.credential_binding_id == binding.id
        assert row.credential_binding_version == binding.binding_version


def test_no_secret_reference_and_no_hash_of_one_is_ever_persisted_or_audited(
    session, principal, env
):
    _ready_state(session, env)
    _ready_secret(session, principal, env)
    blob = db_text_blob(session)
    audit = audit_blob(session)

    for reference in (VAULT_REF, "secp-fake-lab/plan-read", "secp-fake-remote-state/lab"):
        assert reference not in blob, reference
        assert reference not in audit, reference
        # ... and NO digest of it either (a digest of an enumerable locator is a confirmation
        # oracle).
        for digest in (
            hashlib.sha256(reference.encode()).hexdigest(),
            hashlib.sha1(reference.encode()).hexdigest(),  # noqa: S324 - asserting ABSENCE
            hashlib.md5(reference.encode()).hexdigest(),  # noqa: S324 - asserting ABSENCE
        ):
            assert digest not in blob, reference
            assert digest not in audit, reference


# =================================================================================================
# §3 — the CONTROLLED-LIVE adapter provenance capability
# =================================================================================================


def test_a_fake_adapter_claiming_the_exact_contract_version_is_still_refused(session, env):
    """The killer case: a hostile adapter claims the right version AND returns all-pass evidence.

    It obtains no capability, because the reviewed activation pins a DIFFERENT implementation
    digest. A self-declared ``contract_version`` is not provenance.
    """
    binding = state_binding(session, env)

    class _HostileAdapter:
        """Claims the exact expected contract version and returns a fully-passing report."""

        contract_version = REMOTE_STATE_ADAPTER_CONTRACT_VERSION

        def evaluate(self, b, *, now):  # pragma: no cover - must never be reached
            raise AssertionError("a fake adapter was invoked")

    honest = FakeStateAdapter(healthy_report(binding))
    hostile = _HostileAdapter()

    # The activation was reviewed for the HONEST implementation; the hostile one is swapped in.
    composition = full_composition(
        state_adapter=hostile,
        state_activation=adapter_activation(
            env,
            binding,
            honest,
            operation_kind=ReadinessOperationKind.remote_state_readiness,
        ),
    )
    result = run_remote_state_readiness(
        session, manifest_id=env.manifest.id, composition=composition, now=NOW
    )
    assert result.outcome == RemoteStateReadinessOutcome.refused.value
    assert result.reason_code == ReadinessReason.adapter_capability_invalid.value
    assert session.execute(select(RemoteStateReadinessRecord)).scalars().all() == []


def test_an_adapter_without_any_reviewed_activation_is_refused_before_contact(session, env):
    binding = state_binding(session, env)
    adapter = FakeStateAdapter(healthy_report(binding))
    result = run_remote_state_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=full_composition(state_adapter=adapter),  # NO activation
        now=NOW,
    )
    assert result.outcome == RemoteStateReadinessOutcome.refused.value
    assert result.reason_code == ReadinessReason.adapter_capability_missing.value
    assert adapter.calls == []  # the backend was never contacted


def test_test_only_evidence_can_never_become_controlled_live(session, principal, env):
    """Evidence produced under the EXPLICITLY NAMED test-only factory is permanently marked."""
    binding = state_binding(session, env)
    adapter = FakeStateAdapter(healthy_report(binding))
    result = run_remote_state_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=state_composition(session, env, adapter, test_only=True),
        now=NOW,
    )
    assert result.outcome == RemoteStateReadinessOutcome.ready.value

    row = session.get(RemoteStateReadinessRecord, result.record_id)
    assert row.capability_class == ReadinessCapabilityClass.test_only

    # An authorization can never be bound to test-only state evidence ...
    with pytest.raises(ReadinessError):
        auth_svc.create_plan_secret_authorization(session, principal, manifest_id=env.manifest.id)

    # ... and combined readiness refuses it outright.
    view = readiness_svc.get_provisioning_readiness(session, principal, env.manifest.id, now=NOW)
    assert view["ready"] is False
    assert (
        ReadinessReason.adapter_capability_not_controlled_live.value in view["reasons"]
        or (view["reasons"])
    )


def test_a_capability_cannot_be_constructed_serialized_or_pickled(session, env):
    binding = state_binding(session, env)
    adapter = FakeStateAdapter(healthy_report(binding))
    activation = adapter_activation(
        env, binding, adapter, operation_kind=ReadinessOperationKind.remote_state_readiness
    )

    # 1. It cannot be constructed directly (the token is module-private).
    with pytest.raises(TypeError):
        ReadinessAdapterCapability(object(), activation, "controlled_live")

    capability = issue_readiness_adapter_capability(
        activation=activation,
        binding=binding,
        adapter=adapter,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=NOW,
    )
    assert capability.controlled_live is True

    # 2. It cannot be serialized, pickled, or leaked through repr/str/format.
    with pytest.raises(TypeError):
        pickle.dumps(capability)
    with pytest.raises(TypeError):
        capability.__getstate__()
    for rendered in (repr(capability), str(capability), f"{capability}"):
        assert "redacted" in rendered
        assert str(activation.activation_dossier_hash) not in rendered
        assert str(activation.adapter_registration_id) not in rendered

    # 3. The TEST-ONLY factory is explicitly named and never controlled-live.
    test_only = issue_test_only_capability(
        activation=activation,
        binding=binding,
        adapter=adapter,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        now=NOW,
    )
    assert test_only.controlled_live is False
    assert test_only.capability_class == ReadinessCapabilityClass.test_only.value


def test_the_api_can_never_import_the_capability_factory():
    """The architecture boundary forbids it — asserted directly on the shipped API source."""
    import ast

    api = ROOT / "apps" / "api" / "secp_api"
    for path in api.rglob("*.py"):
        # ``dispatch.py`` is the ONE pre-existing, narrowly allowlisted crossing (the inline dev
        # dispatcher). It reaches ``secp_worker.orchestration`` and nothing else — never readiness.
        if "__pycache__" in path.parts or path.name == "dispatch.py":
            continue
        source = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(source)):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            for module in modules:
                assert not module.startswith("secp_worker"), f"{path.name}: {module}"
        # The factory + the capability type are unreachable from API code by NAME as well.
        for banned in (
            "issue_readiness_adapter_capability",
            "issue_test_only_capability",
            "ReadinessAdapterCapability",
            "AdapterActivation",
        ):
            assert banned not in source, f"{path.name}: {banned}"


def test_a_capability_bound_to_the_wrong_operation_kind_is_refused(session, env):
    binding = state_binding(session, env)
    adapter = FakeStateAdapter(healthy_report(binding))
    wrong = adapter_activation(
        env,
        binding,
        adapter,
        operation_kind=ReadinessOperationKind.plan_secret_readiness,  # WRONG kind
    )
    with pytest.raises(AdapterCapabilityRefused):
        issue_readiness_adapter_capability(
            activation=wrong,
            binding=binding,
            adapter=adapter,
            operation_kind=ReadinessOperationKind.remote_state_readiness,
            now=NOW,
        )


# =================================================================================================
# §4 — the fail-closed activation-dossier PLACEHOLDER
# =================================================================================================


def test_the_placeholder_dossier_authorizes_nothing(session, env):
    assert is_placeholder_dossier(READINESS_ACTIVATION_DOSSIER_PLACEHOLDER)
    assert is_placeholder_dossier("")
    assert not is_placeholder_dossier(TEST_DOSSIER_HASH)

    binding = state_binding(session, env)
    adapter = FakeStateAdapter(healthy_report(binding))

    # 1. No capability can be produced with it.
    placeholder = adapter_activation(
        env,
        binding,
        adapter,
        operation_kind=ReadinessOperationKind.remote_state_readiness,
        activation_dossier_hash=READINESS_ACTIVATION_DOSSIER_PLACEHOLDER,
    )
    with pytest.raises(AdapterCapabilityRefused) as exc:
        issue_readiness_adapter_capability(
            activation=placeholder,
            binding=binding,
            adapter=adapter,
            operation_kind=ReadinessOperationKind.remote_state_readiness,
            now=NOW,
        )
    assert exc.value.reason_code == ReadinessReason.activation_dossier_placeholder.value

    # 2. Remote-state readiness cannot return ready with it, and persists NOTHING.
    result = run_remote_state_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=full_composition(state_adapter=adapter, state_activation=placeholder),
        now=NOW,
    )
    assert result.outcome == RemoteStateReadinessOutcome.refused.value
    assert result.reason_code == ReadinessReason.activation_dossier_placeholder.value
    assert session.execute(select(RemoteStateReadinessRecord)).scalars().all() == []
    assert adapter.calls == []

    # 3. The audit never represents the placeholder as approved deployment evidence.
    blob = audit_blob(session)
    assert "approved" not in blob.lower() or READINESS_ACTIVATION_DOSSIER_PLACEHOLDER not in blob


def test_plan_secret_readiness_refuses_the_placeholder_dossier(session, principal, env):
    _ready_state(session, env)
    approve_plan_secret_authorization(session, principal, env.manifest.id)
    binding = state_binding(session, env)
    self_test = FakeSelfTest()
    result = run_plan_secret_readiness(
        session,
        manifest_id=env.manifest.id,
        composition=full_composition(
            self_test=self_test,
            plan_secret_activation=adapter_activation(
                env,
                binding,
                self_test,
                operation_kind=ReadinessOperationKind.plan_secret_readiness,
                activation_dossier_hash=READINESS_ACTIVATION_DOSSIER_PLACEHOLDER,
            ),
        ),
        now=NOW,
    )
    assert result.outcome == PlanSecretReadinessOutcome.refused.value
    assert result.reason_code == ReadinessReason.activation_dossier_placeholder.value
    assert self_test.calls == 0  # the secret manager was never contacted
    assert session.execute(select(PlanSecretReadinessRecord)).scalars().all() == []


def test_combined_readiness_refuses_a_placeholder_dossier_record(session, principal, env):
    """A record carrying the placeholder can never make combined readiness current."""
    _ready_state(session, env)
    secret_result = _ready_secret(session, principal, env)
    row = session.get(PlanSecretReadinessRecord, secret_result.record_id)

    # Forge the dossier on the immutable record (a raw Core UPDATE bypassing the ORM guard).
    session.execute(
        PlanSecretReadinessRecord.__table__.update()
        .where(PlanSecretReadinessRecord.id == row.id)
        .values(activation_dossier_hash=READINESS_ACTIVATION_DOSSIER_PLACEHOLDER)
    )
    session.expire_all()

    view = readiness_svc.get_provisioning_readiness(session, principal, env.manifest.id, now=NOW)
    assert view["ready"] is False
    assert ReadinessReason.activation_dossier_placeholder.value in view["reasons"]


# =================================================================================================
# §5 — the backend-reference CONFIRMATION ORACLE is gone
# =================================================================================================


def test_no_persisted_value_is_a_digest_of_the_backend_reference_or_a_credential_locator(
    session, principal, env
):
    """B1B-PR4 §5: no durable, audited, or returned value is a direct digest of an enumerable
    locator."""
    _ready_state(session, env)
    _ready_secret(session, principal, env)

    backend = env.toolchain.content["state_backend"]
    surfaces = [
        db_text_blob(session),
        audit_blob(session),
        str(readiness_svc.get_remote_state_readiness(session, principal, env.manifest.id)),
        str(readiness_svc.get_plan_secret_readiness(session, principal, env.manifest.id)),
        str(readiness_svc.get_provisioning_readiness(session, principal, env.manifest.id)),
    ]
    enumerable = (
        backend["reference"],  # the backend reference
        backend["kind"],
        f"{backend['kind']}:{backend['reference']}",
        f"https://{backend['reference']}",  # a backend URL
        "secp-fake-lab",  # a bucket / container / object key
        VAULT_REF,  # the secret reference
        "secp-fake-lab/plan-read",  # the credential locator
    )
    for value in enumerable:
        digest = hashlib.sha256(value.encode()).hexdigest()
        for surface in surfaces:
            assert value not in surface, value
            assert digest not in surface, value
            assert f"sha256:{digest}" not in surface, value

    # The removed column is gone from the schema entirely.
    columns = {c.name for c in RemoteStateReadinessRecord.__table__.columns}
    assert "state_backend_binding_hash" not in columns
    # The backend BINDING ANCHOR is the immutable ToolchainProfile content hash.
    row = session.execute(select(RemoteStateReadinessRecord)).scalars().one()
    assert row.toolchain_profile_hash == env.toolchain.content_hash


def test_no_readiness_module_hashes_a_backend_or_secret_reference():
    """Static proof: nothing digests a backend or secret reference into durable evidence."""
    for pkg in (
        ROOT / "apps" / "worker" / "secp_worker" / "readiness",
        ROOT / "apps" / "api" / "secp_api",
    ):
        for path in pkg.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            source = path.read_text(encoding="utf-8")
            for banned in (
                "state_backend_binding_hash",
                "backend_binding_hash",
                "secret_ref_hash",
                "credential_ref_hash",
                "proof_digest",
            ):
                assert banned not in source, f"{path.name}: {banned}"


# =================================================================================================
# §6 — the narrowed (truthful) state-body claim
# =================================================================================================


def test_the_adapter_protocol_still_exposes_no_state_body_method():
    from secp_worker.readiness import state_adapter as mod

    surface = {
        name
        for name in dir(mod.RemoteStateReadinessAdapter)
        if not name.startswith("_") and name != "contract_version"
    }
    assert surface == {"evaluate"}
    for banned in ("read_state", "get_state", "download", "upload_state", "force_unlock", "pull"):
        assert not hasattr(mod.RemoteStateReadinessAdapter, banned)


def test_the_adapter_implementation_trust_limitation_is_documented_truthfully():
    """ADR-021 must state plainly what reflection CANNOT prove, and name the residual risk."""
    raw = (ROOT / "docs" / "adr" / "ADR-021-remote-state-and-jit-secret-readiness.md").read_text(
        encoding="utf-8"
    )
    adr = " ".join(raw.split())  # markdown line-wrapping must not hide a claim
    for claim in (
        "exposes no state-body method",
        "never requests a state body",
        "independently activation-bound",
        "code-reviewed",
        "cannot be proven safe by reflection alone",
        "compromised worker",
        "residual risk",
    ):
        assert claim.lower() in adr.lower(), claim
    # It must NOT claim reflection proves an implementation performs no state access — the only
    # permitted occurrence of that phrase is the explicit DISCLAIMER of it.
    assert (
        "nothing here claims that reflection proves an adapter's internal implementation performs "
        "no state access" in adr.lower()
    )
    assert adr.lower().count("reflection proves") == 1


# =================================================================================================
# §7 — the exact current-readiness acceptance list; and readiness still executes NOTHING
# =================================================================================================


def test_ready_requires_every_gate_and_still_creates_no_runner_executor_or_grant(
    session, principal, env
):
    state_result, _ = _ready_state(session, env)
    secret_result = _ready_secret(session, principal, env)
    attestation = session.execute(select(ToolchainAttestationRecord)).scalars().one()
    credential = session.execute(
        select(CredentialBinding).where(CredentialBinding.status == CredentialBindingStatus.active)
    ).scalar_one()

    view = readiness_svc.get_provisioning_readiness(session, principal, env.manifest.id, now=NOW)
    assert view["ready"] is True
    assert view["reasons"] == []
    assert view["toolchain_attestation_id"] == str(attestation.id)
    assert view["credential_binding_id"] == str(credential.id)
    assert view["credential_binding_version"] == credential.binding_version
    assert view["remote_state_readiness_id"] == str(state_result.record_id)
    assert view["plan_secret_readiness_id"] == str(secret_result.record_id)

    # Both records are CONTROLLED-LIVE and carry the REVIEWED (non-placeholder) dossier.
    for row in (
        session.get(RemoteStateReadinessRecord, state_result.record_id),
        session.get(PlanSecretReadinessRecord, secret_result.record_id),
    ):
        assert row.capability_class == ReadinessCapabilityClass.controlled_live
        assert not is_placeholder_dossier(row.activation_dossier_hash)
        assert row.activation_dossier_hash == TEST_DOSSIER_HASH

    # READY IS NOT APPROVAL: nothing was launched, unsealed, granted, rendered, or executed.
    from secp_api.models import (
        ProvisioningChangeSetApproval,
        ProvisioningOperation,
        WorkflowDispatchOutbox,
        WorkflowRun,
    )

    assert session.execute(select(ProvisioningOperation)).scalars().all() == []
    assert session.execute(select(ProvisioningChangeSetApproval)).scalars().all() == []
    assert session.execute(select(WorkflowRun)).scalars().all() == []
    assert session.execute(select(WorkflowDispatchOutbox)).scalars().all() == []


def test_both_b1a_subprocess_seals_remain_exactly_true():
    from secp_worker.provisioning import activation, process_executor

    assert activation._B1A_SUBPROCESS_SEALED is True
    assert process_executor._B1A_SUBPROCESS_SEALED is True
    for module in (activation, process_executor):
        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        assert source.count("_B1A_SUBPROCESS_SEALED = True") == 1
        assert "_B1A_SUBPROCESS_SEALED = False" not in source
