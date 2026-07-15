"""B1B-PR5B — plan-only EXECUTION component units (composition, resolver, runtime inputs, reattest,
capability digests, models, seals, scanners), all with the plan-only seal held ``True``.

These prove the isolated security-critical logic without the full readiness DB stack; the DB-backed
lease/result/orchestration behaviour is proven in ``test_plan_execution_lease.py``.
"""

from __future__ import annotations

import ast
import pathlib
import sys
import uuid
from datetime import UTC, datetime  # noqa: E402 - grouped with stdlib

import pytest

NOW = datetime(2026, 7, 15, tzinfo=UTC)
ROOT = pathlib.Path(__file__).resolve().parents[3]
# Deterministic ids so a "candidate vs authoritative" contract differs ONLY in the field under test.
_FIXED_IDS = {k: uuid.UUID(int=i + 1) for i, k in enumerate("otmdcwlx")}


class _FakeAuthMaterialProvider:
    """A non-serializable, test-only worker-auth provider (yields an inert non-secret header)."""

    def __getstate__(self):  # noqa: ANN204
        raise TypeError("cannot serialize")

    def auth_headers(self, *, now):  # noqa: ANN001, ANN201
        return {"X-Vault-Token": "TEST-TOKEN-NEVER-REAL"}


def production_bound_openbao_plan_resolver():  # noqa: ANN201
    """A CONTROLLED-LIVE-bindable resolver: the concrete resolver over the concrete client over
    the concrete OpenBao HTTPS transport. Construction validates the origin string and contacts
    nothing (no CA read, no TLS, no request until ``read`` is called, which tests never do)."""
    from secp_worker.openbao_plan_http_transport import OpenBaoHttpTransport
    from secp_worker.plan_gen.openbao_plan_resolver import (
        ConcreteOpenBaoPlanSecretClient,
        OpenBaoPlanSecretResolver,
    )

    transport = OpenBaoHttpTransport(
        origin="https://vault.example",
        ca_path="/etc/ssl/certs/reviewed-ca.pem",
        auth_provider=_FakeAuthMaterialProvider(),
    )
    client = ConcreteOpenBaoPlanSecretClient(transport=transport)
    return OpenBaoPlanSecretResolver(client=client)


# --- all three seals remain True -----------------------------------------------------------------


def test_plan_only_seal_is_false_and_both_b1a_seals_remain_true():
    """After the reviewed PR5B activation the dedicated plan-only seal is False; the two independent
    generic B1-A subprocess seals stay True (apply/destroy remain impossible)."""
    from secp_worker.plan_gen import process_boundary as pb
    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    assert pb._PLAN_ONLY_PROCESS_SEALED is False
    assert pe._B1A_SUBPROCESS_SEALED is True
    assert act._B1A_SUBPROCESS_SEALED is True


# --- the sealed default composition + verification ------------------------------------------------


def test_sealed_default_composition_refuses_before_any_contact():
    from secp_worker.plan_gen.composition import (
        PlanExecutionCompositionError,
        build_plan_execution_composition,
        verify_plan_execution_composition,
    )

    comp = build_plan_execution_composition()
    assert comp.gate.enabled is False
    assert comp.toolchain_layout is None
    assert comp.provider_resolver is None
    assert comp.trusted_workspace_root is None
    with pytest.raises(PlanExecutionCompositionError, match="composition_sealed"):
        verify_plan_execution_composition(comp)


def test_no_env_flag_or_field_activates_the_composition():
    # The factory ignores any settings object; it always returns the sealed default.
    from secp_worker.plan_gen.composition import build_plan_execution_composition

    for settings in (None, {"enabled": True}, object(), {"gate": {"enabled": True}}):
        assert build_plan_execution_composition(settings).gate.enabled is False


def _activated_composition(*, classification="test_only", **over):
    """A minimal ACTIVATED composition (used only to exercise verify's per-binding refusals)."""
    from secp_worker.plan_gen.composition import (
        PlanExecutionComposition,
        PlanExecutionGate,
        ProviderRuntimeInputSource,
        StateRuntimeInputSource,
    )
    from secp_worker.plan_gen.controlled_live import (
        CONTROLLED_LIVE_RENDERER_VERSION,
        controlled_live_renderer_implementation_digest,
    )
    from secp_worker.plan_gen.plan_secret_resolution import SealedPlanSecretResolver
    from secp_worker.plan_gen.process_boundary import (
        PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        PlanOnlyProcessExecutor,
        issue_plan_only_executor,
        plan_only_executor_implementation_digest,
    )
    from secp_worker.provisioning.toolchain_verify import ToolchainFilesystemLayout

    # A controlled_live composition MUST bind the sealed production issuer; test_only may not.
    factory = (
        issue_plan_only_executor
        if classification == "controlled_live"
        else PlanOnlyProcessExecutor.for_inert_fixture_test
    )
    # A controlled_live composition MUST carry the EXACT reviewed concrete OpenBao resolver chain
    # (production bound to the concrete client over the concrete HTTPS transport); a test_only
    # composition uses the sealed resolver (which can never resolve).
    resolver = (
        production_bound_openbao_plan_resolver()
        if classification == "controlled_live"
        else SealedPlanSecretResolver()
    )
    layout = ToolchainFilesystemLayout(
        trusted_root="/trusted",
        executable="bin/tofu",
        version_metadata="meta/version.json",
        module_bundle="bundle",
        provider_lockfile="meta/provider.lock",
        provider_mirror="mirror",
        cli_config="meta/cli.tofurc",
    )
    base = dict(
        gate=PlanExecutionGate(enabled=True),
        classification=classification,
        toolchain_layout=layout,
        trusted_workspace_root="/trusted/ws",
        renderer_registration=CONTROLLED_LIVE_RENDERER_VERSION,
        renderer_module_digest=controlled_live_renderer_implementation_digest(),
        process_implementation_registration=PLAN_ONLY_EXECUTOR_IMPLEMENTATION_ID,
        process_implementation_digest=plan_only_executor_implementation_digest(),
        provider_version="0.80.0",
        provider_runtime_input_source=ProviderRuntimeInputSource(
            endpoint="https://pve.example:8006"
        ),
        state_runtime_input_source=StateRuntimeInputSource(
            address="https://state.example/lab",
            lock_address="https://state.example/lab?lock",
            unlock_address="https://state.example/lab?unlock",
            username="u",
        ),
        provider_resolver=resolver,
        state_resolver=(
            production_bound_openbao_plan_resolver()
            if classification == "controlled_live"
            else SealedPlanSecretResolver()
        ),
        provider_resolver_activation=object(),
        state_resolver_activation=object(),
        process_timeout_seconds=60,
        max_output_bytes=1024,
        deployment_activation_dossier_hash="sha256:" + "a" * 64,
        worker_identity_registration_id=str(uuid.uuid4()),
        executor_factory=factory,
    )
    base.update(over)
    return PlanExecutionComposition(**base)


def test_activated_composition_verifies_and_binds_exact_digests():
    from secp_worker.plan_gen.composition import verify_plan_execution_composition

    verify_plan_execution_composition(_activated_composition())  # no raise
    verify_plan_execution_composition(_activated_composition(classification="controlled_live"))


def test_classification_is_bound_to_the_actual_executor_factory():
    """Adversarial-review §1: a composition cannot pair a classification with a wrong factory."""
    from secp_worker.plan_gen.composition import (
        PlanExecutionCompositionError,
        verify_plan_execution_composition,
    )
    from secp_worker.plan_gen.process_boundary import (
        PlanOnlyProcessExecutor,
        issue_plan_only_executor,
    )

    # controlled_live with an inert (test-only) factory is refused.
    with pytest.raises(PlanExecutionCompositionError, match="requires_sealed_issuer"):
        verify_plan_execution_composition(
            _activated_composition(
                classification="controlled_live",
                executor_factory=PlanOnlyProcessExecutor.for_inert_fixture_test,
            )
        )
    # test_only with the sealed production issuer is refused.
    with pytest.raises(PlanExecutionCompositionError, match="forbids_production_issuer"):
        verify_plan_execution_composition(
            _activated_composition(
                classification="test_only", executor_factory=issue_plan_only_executor
            )
        )


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"renderer_module_digest": "sha256:" + "0" * 64}, "composition_renderer_digest_invalid"),
        (
            {"process_implementation_digest": "sha256:" + "0" * 64},
            "composition_process_digest_invalid",
        ),
        ({"renderer_registration": "bogus/v9"}, "composition_renderer_registration_invalid"),
        ({"trusted_workspace_root": "relative/x"}, "composition_trusted_root_invalid"),
        ({"provider_version": ""}, "composition_provider_pin_invalid"),
        ({"provider_resolver": None}, "composition_resolver_missing"),
        ({"provider_resolver_activation": None}, "composition_resolver_activation_missing"),
        ({"process_timeout_seconds": 0}, "composition_limits_invalid"),
        ({"classification": "bogus"}, "composition_classification_invalid"),
    ],
)
def test_activated_composition_refuses_incomplete_binding(over, reason):
    from secp_worker.plan_gen.composition import (
        PlanExecutionCompositionError,
        verify_plan_execution_composition,
    )

    with pytest.raises(PlanExecutionCompositionError, match=reason):
        verify_plan_execution_composition(_activated_composition(**over))


def test_activated_composition_refuses_the_old_v1_executor_identity():
    """A composition carrying the OLD sealed v1 process-implementation registration or digest is
    refused — the seal flip advanced the reviewed identity to v2, so an old binding cannot activate
    the unsealed executor."""
    import hashlib

    from secp_worker.plan_gen.composition import (
        PlanExecutionCompositionError,
        verify_plan_execution_composition,
    )

    v1_id = "secp-002b-1b-pr5b/plan-only-executor/v1"
    v1_digest = "sha256:" + hashlib.sha256(v1_id.encode()).hexdigest()
    with pytest.raises(
        PlanExecutionCompositionError, match="composition_process_registration_invalid"
    ):
        verify_plan_execution_composition(
            _activated_composition(process_implementation_registration=v1_id)
        )
    with pytest.raises(PlanExecutionCompositionError, match="composition_process_digest_invalid"):
        verify_plan_execution_composition(
            _activated_composition(process_implementation_digest=v1_digest)
        )


# --- the plan-execution resolver seam ------------------------------------------------------------


def _contract(**over):
    from secp_worker.plan_gen.plan_secret_resolution import (
        PLAN_EXECUTION_RESOLVER_CONTRACT_VERSION,
        PlanCredentialReference,
        PlanExecutionResolutionContract,
        PlanExecutionResolutionPurpose,
    )

    base = dict(
        purpose=PlanExecutionResolutionPurpose.provider_plan_read,
        organization_id=_FIXED_IDS["o"],
        execution_target_id=_FIXED_IDS["t"],
        provisioning_manifest_id=_FIXED_IDS["m"],
        provisioning_manifest_content_hash="sha256:" + "1" * 64,
        activation_dossier_id=_FIXED_IDS["d"],
        activation_dossier_hash="sha256:" + "2" * 64,
        credential_binding_id=_FIXED_IDS["c"],
        credential_binding_version=1,
        binding_source="dedicated_operation",
        worker_identity_registration_id=_FIXED_IDS["w"],
        worker_identity_version=1,
        resolver_contract_version=PLAN_EXECUTION_RESOLVER_CONTRACT_VERSION,
        operation_fingerprint="sha256:" + "3" * 64,
        authorization_expiry="2026-07-15T12:00:00Z",
        execution_lease_id=_FIXED_IDS["l"],
        attempt_number=1,
        credential_reference=PlanCredentialReference("op://x", scheme="openbao"),
    )
    base.update(over)
    return PlanExecutionResolutionContract(**base)


def _resolver_activation(**over):
    from secp_worker.plan_gen.plan_secret_resolution import (
        PLAN_EXECUTION_RESOLVER_REGISTRATION,
        PlanExecutionResolutionPurpose,
        PlanResolverActivation,
        plan_execution_resolver_digest,
    )

    base = dict(
        purpose=PlanExecutionResolutionPurpose.provider_plan_read,
        resolver_registration=PLAN_EXECUTION_RESOLVER_REGISTRATION,
        resolver_digest=plan_execution_resolver_digest(),
        worker_identity_registration_id=_FIXED_IDS["w"],
        worker_identity_version=1,
    )
    base.update(over)
    return PlanResolverActivation(**base)


def _resolver_capability(contract, activation=None):
    from secp_worker.plan_gen.plan_secret_resolution import issue_plan_resolver_capability

    return issue_plan_resolver_capability(
        contract=contract,
        activation=activation if activation is not None else _resolver_activation(),
        worker_identity_registration_id=_FIXED_IDS["w"],
        worker_identity_version=1,
    )


def test_sealed_plan_resolver_verifies_then_fails_closed():
    from secp_worker.plan_gen.plan_secret_resolution import (
        PlanSecretResolutionUnavailable,
        SealedPlanSecretResolver,
        build_trusted_plan_resolution_request,
    )

    contract = _contract()
    request = build_trusted_plan_resolution_request(contract)
    capability = _resolver_capability(contract)
    with pytest.raises(PlanSecretResolutionUnavailable):
        SealedPlanSecretResolver().resolve(
            request, expectation=contract, capability=capability, now=NOW
        )


def test_resolver_activation_is_verified_not_merely_non_null():
    """Item 6: a resolver activation must be a real, reviewed activation for the exact purpose +
    worker + digest — a bare non-null object, wrong digest, wrong purpose, or wrong worker fails."""
    from secp_worker.plan_gen.plan_secret_resolution import (
        PlanExecutionResolutionPurpose,
        PlanResolutionContractViolation,
        issue_plan_resolver_capability,
    )

    contract = _contract()
    # A bare (non-activation) object is refused — NOT merely non-null.
    with pytest.raises(PlanResolutionContractViolation, match="resolver_activation_invalid"):
        issue_plan_resolver_capability(
            contract=contract,
            activation=object(),
            worker_identity_registration_id=_FIXED_IDS["w"],
            worker_identity_version=1,
        )
    # A self-declared registration / wrong digest is refused.
    with pytest.raises(
        PlanResolutionContractViolation, match="resolver_activation_registration_invalid"
    ):
        _resolver_capability(contract, _resolver_activation(resolver_registration="bogus/v9"))
    with pytest.raises(PlanResolutionContractViolation, match="resolver_activation_digest_invalid"):
        _resolver_capability(contract, _resolver_activation(resolver_digest="sha256:" + "0" * 64))
    # A wrong purpose (state activation used for a provider contract) is refused.
    with pytest.raises(
        PlanResolutionContractViolation, match="resolver_activation_purpose_mismatch"
    ):
        _resolver_capability(
            contract,
            _resolver_activation(purpose=PlanExecutionResolutionPurpose.state_backend_plan),
        )
    # A worker-identity mismatch is refused.
    with pytest.raises(PlanResolutionContractViolation, match="worker_mismatch"):
        _resolver_capability(contract, _resolver_activation(worker_identity_version=9))


def test_plan_resolver_refuses_a_legacy_binding_source():
    from secp_worker.plan_gen.plan_secret_resolution import (
        PlanResolutionContractViolation,
        assert_plan_resolution_authorized,
    )

    bad = _contract(binding_source="legacy_generic")
    with pytest.raises(PlanResolutionContractViolation, match="binding_source_not_dedicated"):
        assert_plan_resolution_authorized(bad, bad, now=NOW)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("credential_binding_version", 2, "credential_binding_version_mismatch"),
        ("operation_fingerprint", "sha256:" + "9" * 64, "operation_fingerprint_mismatch"),
        ("worker_identity_version", 9, "worker_identity_version_mismatch"),
        ("resolver_contract_version", "wrong/v0", "resolver_contract_mismatch"),
    ],
)
def test_plan_resolver_refuses_per_fact_drift(field, value, reason):
    from secp_worker.plan_gen.plan_secret_resolution import (
        PlanResolutionContractViolation,
        assert_plan_resolution_authorized,
    )

    authoritative = _contract()
    candidate = _contract(**{field: value})
    with pytest.raises(PlanResolutionContractViolation, match=reason):
        assert_plan_resolution_authorized(candidate, authoritative, now=NOW)


def test_plan_resolver_refuses_expired_and_unsupported_scheme():
    from secp_worker.plan_gen.plan_secret_resolution import (
        PlanCredentialReference,
        PlanResolutionContractViolation,
        assert_plan_resolution_authorized,
    )

    expired = _contract(authorization_expiry="2020-01-01T00:00:00Z")
    with pytest.raises(PlanResolutionContractViolation, match="authorization_expired"):
        assert_plan_resolution_authorized(expired, expired, now=NOW)
    bad_scheme = _contract(credential_reference=PlanCredentialReference("x", scheme="http"))
    with pytest.raises(PlanResolutionContractViolation, match="reference_scheme_unsupported"):
        assert_plan_resolution_authorized(bad_scheme, bad_scheme, now=NOW)


def test_plan_credential_reference_and_material_are_non_serializable_and_redacted():
    import pickle

    from secp_worker.plan_gen.plan_secret_resolution import PlanCredentialReference

    ref = PlanCredentialReference("op://super-secret", scheme="openbao")
    assert "super-secret" not in repr(ref)
    with pytest.raises(TypeError):
        pickle.dumps(ref)


# --- runtime inputs + explicit child environment -------------------------------------------------


def test_runtime_inputs_require_https_and_refuse_dangerous_urls():
    from secp_worker.plan_gen.runtime_inputs import RuntimeInputError, build_provider_runtime_input

    build_provider_runtime_input("https://pve.example:8006")  # ok
    for bad in (
        "http://pve.example",  # not https
        "https://user:pw@pve.example",  # userinfo
        "https://pve.example/#frag",  # fragment
        "https://pve.example/?q=1",  # query
        "https://localhost:8006",  # loopback
        "https://169.254.169.254/latest",  # metadata
    ):
        with pytest.raises(RuntimeInputError):
            build_provider_runtime_input(bad)


def test_child_environment_is_exact_and_never_inherits_os_environ():
    from secp_worker.plan_gen.runtime_inputs import (
        OperationalPaths,
        build_child_environment,
        build_provider_runtime_input,
        build_state_runtime_input,
    )
    from secp_worker.preflight.secret_resolution import SecretMaterial

    env = build_child_environment(
        provider_material=SecretMaterial("PROVIDER-TOKEN-VALUE"),
        state_material=SecretMaterial("STATE-PASSWORD-VALUE"),
        provider_input=build_provider_runtime_input("https://pve.example:8006"),
        state_input=build_state_runtime_input(
            "https://state.example/lab",
            "https://state.example/lab?lock",
            "https://state.example/lab?unlock",
            "svc",
        ),
        operational=OperationalPaths(
            home="/ws/home", tmpdir="/ws/tmp", tf_data_dir="/ws/tfdata", cli_config_file="/ws/cli"
        ),
    )
    # Exactly the allowlisted variables; the two secrets in their exact vars only. Item 11: the
    # HTTP-backend lock/unlock addresses + LOCK/UNLOCK methods are always present so state LOCKING
    # can never be silently disabled.
    assert set(env) == {
        "TF_VAR_pm_api_token",
        "TF_HTTP_PASSWORD",
        "TF_VAR_pm_endpoint",
        "TF_HTTP_ADDRESS",
        "TF_HTTP_USERNAME",
        "TF_HTTP_LOCK_ADDRESS",
        "TF_HTTP_UNLOCK_ADDRESS",
        "TF_HTTP_LOCK_METHOD",
        "TF_HTTP_UNLOCK_METHOD",
        "TF_HTTP_RETRY_MAX",
        "HOME",
        "TMPDIR",
        "TF_DATA_DIR",
        "TF_CLI_CONFIG_FILE",
    }
    assert env["TF_VAR_pm_api_token"] == "PROVIDER-TOKEN-VALUE"
    assert env["TF_HTTP_PASSWORD"] == "STATE-PASSWORD-VALUE"
    # Locking is enabled with the reviewed methods and the exact lock/unlock addresses.
    assert env["TF_HTTP_LOCK_ADDRESS"] == "https://state.example/lab?lock"
    assert env["TF_HTTP_UNLOCK_ADDRESS"] == "https://state.example/lab?unlock"
    assert env["TF_HTTP_LOCK_METHOD"] == "LOCK"
    assert env["TF_HTTP_UNLOCK_METHOD"] == "UNLOCK"
    # No ambient inheritance: PATH / proxy / SSH must be absent.
    for ambient in ("PATH", "HTTP_PROXY", "SSH_AUTH_SOCK", "HTTPS_PROXY", "AWS_ACCESS_KEY_ID"):
        assert ambient not in env
    # The two secret values never cross into the other's variable.
    assert env["TF_VAR_pm_endpoint"] == "https://pve.example:8006"
    assert "PROVIDER-TOKEN-VALUE" not in env["TF_HTTP_PASSWORD"]


# --- fresh execution-time re-attestation (POSIX; reuses the real verifier fixture) ---------------


@pytest.mark.skipif(sys.platform == "win32", reason="RealToolchainVerifier POSIX guarantees")
def test_fresh_reattestation_passes_and_detects_drift(tmp_path):
    from secp_worker.plan_gen.reattest import FreshAttestationError, fresh_execution_attestation
    from secp_worker.provisioning.toolchain_verify import ATTESTATION_POLICY_VERSION
    from tests.test_toolchain_verify import build_fixture

    layout, profile = build_fixture(str(tmp_path))
    from secp_api.toolchain_profile import toolchain_profile_hash

    profile_hash = toolchain_profile_hash(profile)
    comp = _activated_composition(toolchain_layout=layout, trusted_workspace_root=str(tmp_path))
    fresh = fresh_execution_attestation(
        comp,
        profile_content=profile,
        durable_profile_hash=profile_hash,
        durable_policy_version=ATTESTATION_POLICY_VERSION,
        durable_attestation_id="att-1",
    )
    # Item 7: the fresh attestation returns a typed in-memory object with the evidence hash and the
    # exact verified absolute path handles (each with its inode/device), never a bare path string.
    assert fresh.evidence_hash.startswith("sha256:")
    assert fresh.executable.path.endswith("bin/tofu")
    assert fresh.provider_mirror.is_dir
    assert fresh.executable.st_ino and fresh.executable.st_dev
    # A durable-profile-hash drift fails closed.
    with pytest.raises(FreshAttestationError, match="reattestation_drifted"):
        fresh_execution_attestation(
            comp,
            profile_content=profile,
            durable_profile_hash="sha256:" + "0" * 64,
            durable_policy_version=ATTESTATION_POLICY_VERSION,
            durable_attestation_id="att-1",
        )


# --- durable models carry no secret-bearing column -----------------------------------------------


def test_execution_models_have_no_secret_bearing_column():
    import secp_api.models  # noqa: F401 - register metadata
    from secp_api.plan_activation_models import (
        PlanGenerationExecutionLease,
        RealPlanGenerationResult,
    )

    forbidden = (
        "secret_ref",
        "token",
        "password",
        "endpoint",
        "backend_address",
        "url",
        "bucket",
        "object_key",
        "state_key",
        "state_path",
        "namespace_name",
        "access_key",
        "argv",
        "command",
        "cwd",
        "executable_path",
        "workspace_path",
        "mirror_path",
        "stdout",
        "stderr",
        "raw_show",
        "binary_plan",
        "response_body",
        "stack",
    )
    allowed = {"plan_secret_readiness_id", "plan_secret_evidence_hash", "provider_mirror_identity"}
    for model in (PlanGenerationExecutionLease, RealPlanGenerationResult):
        for column in model.__table__.columns:
            if column.name in allowed:
                continue
            for frag in forbidden:
                assert frag not in column.name, f"{model.__tablename__}.{column.name} ~ {frag}"


# --- architecture scanner: no shipped module reaches the seal-bypassing test-only path -----------


def test_no_shipped_plan_gen_module_uses_the_test_only_construction_path():
    pkg = ROOT / "apps" / "worker" / "secp_worker" / "plan_gen"
    for path in sorted(pkg.rglob("*.py")):
        if path.name == "process_boundary.py" or "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        used |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        assert "for_inert_fixture_test" not in used, path.name
        assert "_PLAN_ONLY_TEST_CONSTRUCTION_TOKEN" not in used, path.name


def test_plan_gen_never_imports_the_fake_provisioning_adapters():
    """Adversarial-review §2: lock the controlled-live path's disjointness from the fake adapter."""
    pkg = ROOT / "apps" / "worker" / "secp_worker" / "plan_gen"
    for path in sorted(pkg.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods: list[str] = []
            if isinstance(node, ast.Import):
                mods += [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.append(node.module)
            for m in mods:
                assert "provisioning.adapters" not in m, (
                    f"{path.name} imports the fake adapter: {m}"
                )


def test_orchestration_never_names_a_fake_or_apply_symbol():
    src = (ROOT / "apps" / "worker" / "secp_worker" / "plan_gen" / "orchestration.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(src)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    for forbidden in (
        "for_inert_fixture_test",
        "ProxmoxAdapter",
        "SubprocessProcessExecutor",
        "build_fixture_show_json",
        "apply_prepared",
        "destroy_prepared",
    ):
        assert forbidden not in names, forbidden
