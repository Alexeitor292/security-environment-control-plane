"""Production-context and dispatch tests for the fixed-path PR5F activation CLI."""

from __future__ import annotations

import hashlib
import importlib
import json
from datetime import UTC, datetime
from functools import cache
from pathlib import Path

import pytest
import secp_discovery_activation.cli as cli_module
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from secp_commissioning.runtime import InMemoryFilesystem
from secp_discovery_activation import PACKAGE_CONTRACT_VERSION
from secp_discovery_activation.adapters import SealedActivationAdapter
from secp_discovery_activation.cli import (
    EXIT_OK,
    EXIT_REFUSED,
    CliDependencies,
    _load_fixed_profile,
    _load_fixed_tls,
    build_parser,
    main,
    run,
)
from secp_discovery_activation.engine import EngineDependencies, OperationResult
from secp_discovery_activation.evidence import (
    SHIPPED_EVIDENCE_TRUST_ROOT,
    SealedEvidenceAuthenticator,
)
from secp_discovery_activation.layout import PRODUCTION_LAYOUT
from secp_discovery_activation.profile import parse_deployment_profile
from secp_discovery_activation.runtime_overlay import (
    build_runtime_overlay,
    runtime_overlay_sha256,
)
from secp_discovery_activation.state import InMemoryWorkerStateFilesystem
from secp_discovery_activation.tls import generate_tls_material

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
REPOSITORY = Path(__file__).resolve().parents[3]


@cache
def _runtime_overlay() -> bytes:
    return build_runtime_overlay(REPOSITORY)


def _profile_raw(*, enabled: bool = True) -> dict[str, object]:
    return {
        "contract_version": PACKAGE_CONTRACT_VERSION,
        "activation_enabled": enabled,
        "ordinary_worker_image_digest": "sha256:" + "1" * 64,
        "worker_runtime_overlay_digest": runtime_overlay_sha256(_runtime_overlay()),
        "ordinary_runtime_uid": 1001,
        "ordinary_runtime_gid": 1001,
        "worker_node_organization": "11111111-1111-4111-8111-111111111111",
        "worker_node_label": "site-worker-01",
        "admission_endpoint": "https://admission.internal.test:8443",
        "admission_listener_bind": "10.20.30.40:8443",
        "controller_api_upstream": "http://api:8080",
        "controller_compose_project": "secp-controller",
        "worker_compose_project": "secp-worker",
        "admission_certificate_dns_name": "admission.internal.test",
        "admission_proxy_image": ("registry.internal.test/secp/admission-proxy@sha256:" + "2" * 64),
        "admission_proxy_runtime_image_digest": "sha256:" + "8" * 64,
        "controller_api_baseline_image_digest": "sha256:" + "7" * 64,
        "controller_api_runtime_image_digest": "sha256:" + "9" * 64,
        "controller_api_image": "registry.internal.test/secp/api@sha256:" + "6" * 64,
        "admission_proxy_runtime_uid": 1002,
        "admission_proxy_runtime_gid": 1002,
        "container_runtime_executable": "/usr/bin/docker",
        "container_runtime_executable_digest": "sha256:" + "3" * 64,
        "compose_executable": "/usr/libexec/docker/cli-plugins/docker-compose",
        "compose_executable_digest": "sha256:" + "4" * 64,
    }


def _fixed_filesystem(
    *, enabled: bool = True, role: str = "controller", evidence_key: bool = False
):  # noqa: ANN202
    fs = InMemoryFilesystem()
    fs.seed_dir("/etc/secp/discovery-activation", uid=0, gid=0, mode=0o700)
    fs.seed_dir("/etc/secp/discovery-activation/tls", uid=0, gid=0, mode=0o700)
    fs.seed_dir("/etc/secp/discovery-activation/import", uid=0, gid=0, mode=0o700)
    fs.seed_file(
        PRODUCTION_LAYOUT.host_role_path,
        role.encode("ascii") + b"\n",
        uid=0,
        gid=0,
        mode=0o644,
    )
    profile = _profile_raw(enabled=enabled)
    # A generated test key avoids checking a reusable private scalar into source control. Tests bind
    # only its public key id, so determinism of the private material is neither needed nor desired.
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    key_id = "sha256:" + hashlib.sha256(public).hexdigest()
    profile["controller_evidence_key_id"] = key_id
    profile["worker_evidence_key_id"] = key_id
    profile_raw = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
    fs.seed_file(PRODUCTION_LAYOUT.profile_path, profile_raw, uid=0, gid=0, mode=0o640)
    material = generate_tls_material(
        dns_identity="admission.internal.test", validity_days=30, now=NOW
    )
    fs.seed_file(
        PRODUCTION_LAYOUT.ca_certificate_path,
        material.ca_certificate_pem(),
        uid=0,
        gid=0,
        mode=0o644,
    )
    fs.seed_file(
        PRODUCTION_LAYOUT.server_certificate_path,
        material.server_certificate_pem(),
        uid=0,
        gid=0,
        mode=0o644,
    )
    fs.seed_file(
        PRODUCTION_LAYOUT.server_private_key_path,
        material.server_private_key_pem(),
        uid=0,
        gid=1002,
        mode=0o640,
    )
    fs.seed_file(
        PRODUCTION_LAYOUT.tls_import_ca_certificate_path,
        material.ca_certificate_pem(),
        uid=0,
        gid=0,
        mode=0o644,
    )
    fs.seed_file(
        PRODUCTION_LAYOUT.tls_import_server_certificate_path,
        material.server_certificate_pem(),
        uid=0,
        gid=0,
        mode=0o644,
    )
    fs.seed_file(
        PRODUCTION_LAYOUT.tls_import_server_private_key_path,
        material.server_private_key_pem(),
        uid=0,
        gid=0,
        mode=0o600,
    )
    fs.seed_file(
        PRODUCTION_LAYOUT.worker_runtime_overlay_import_path,
        _runtime_overlay(),
        uid=0,
        gid=0,
        mode=0o644,
    )
    if evidence_key:
        fs.seed_dir("/var/lib/secp/discovery-activation", uid=0, gid=0, mode=0o700)
        fs.seed_file(
            PRODUCTION_LAYOUT.evidence_signing_key_path,
            private_raw.hex().encode("ascii"),
            uid=0,
            gid=0,
            mode=0o600,
        )
        fs.seed_file(
            PRODUCTION_LAYOUT.evidence_trust_anchor_path,
            public.hex().encode("ascii"),
            uid=0,
            gid=0,
            mode=0o644,
        )
    return fs, material


def _injected_dependencies():  # noqa: ANN202
    profile = parse_deployment_profile(_profile_raw())
    material = generate_tls_material(
        dns_identity="admission.internal.test", validity_days=30, now=NOW
    )
    engine = EngineDependencies(
        adapter=SealedActivationAdapter(),
        state=InMemoryWorkerStateFilesystem(),
        evidence_authenticator=SealedEvidenceAuthenticator(),
        evidence_trust_root=SHIPPED_EVIDENCE_TRUST_ROOT,
        clock=lambda: NOW,
    )
    return CliDependencies(profile=profile, tls_material=material, engine_dependencies=engine)


def test_parser_exposes_exact_eight_operations_and_no_path_or_generic_command() -> None:
    parser = build_parser()
    operation_actions = [
        action
        for action in parser._actions
        if action.dest == "operation"  # noqa: SLF001
    ]
    assert len(operation_actions) == 1
    choices = set(operation_actions[0].choices or {})
    assert choices == {
        "inspect",
        "plan",
        "render",
        "install",
        "verify",
        "status",
        "rollback",
        "evidence",
    }

    for forbidden in ("--profile", "--tls", "--path", "--exec", "--shell", "--host"):
        with pytest.raises(SystemExit):
            parser.parse_args(["plan", forbidden, "/tmp/untrusted"])
    for invented in ("activate", "apply", "destroy", "ssh", "opentofu", "operator"):
        with pytest.raises(SystemExit):
            parser.parse_args([invented])


def test_cli_and_module_entrypoint_import_and_parser_construction_are_inert(monkeypatch) -> None:
    original_main = cli_module.main
    monkeypatch.setattr(
        cli_module,
        "main",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("import must not execute the CLI")
        ),
    )
    import secp_discovery_activation.__main__ as module_entrypoint

    importlib.reload(module_entrypoint)
    module_entrypoint.main = original_main
    assert build_parser().prog == "secp-discovery-activation"


def test_only_mutations_accept_write_confirm_and_install_requires_identity() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["inspect", "--write", "--confirm"])
    with pytest.raises(SystemExit):
        parser.parse_args(["install", "--write", "--confirm"])

    install = parser.parse_args(
        ["install", "--write", "--confirm", "--installation-identity", "operator.test"]
    )
    rollback = parser.parse_args(["rollback", "--write", "--confirm"])
    assert install.write is install.confirm is True
    assert install.installation_identity == "operator.test"
    assert rollback.write is rollback.confirm is True


@pytest.mark.parametrize(
    ("argv", "reason"),
    [
        (["install", "--installation-identity", "operator.test"], "write_authority_required"),
        (
            ["install", "--write", "--installation-identity", "operator.test"],
            "explicit_confirmation_required",
        ),
        (["rollback"], "write_authority_required"),
        (["rollback", "--write"], "explicit_confirmation_required"),
    ],
)
def test_mutation_gate_refuses_before_resolving_any_production_dependency(
    argv: list[str], reason: str, monkeypatch
) -> None:
    monkeypatch.setattr(
        cli_module,
        "_real_filesystem",
        lambda: (_ for _ in ()).throw(AssertionError("production resolution must stay inert")),
    )

    code, payload = run(argv)

    assert code == EXIT_REFUSED
    assert payload["outcome"] == "refused" and payload["reason_code"] == reason


def test_fixed_profile_and_tls_loader_accept_only_exact_root_controlled_sources() -> None:
    fs, original = _fixed_filesystem()

    profile = _load_fixed_profile(fs)
    imported = _load_fixed_tls(fs, profile)

    assert profile.activation_enabled is True
    assert imported.metadata.server_dns_identity == "admission.internal.test"
    assert imported.metadata.server_certificate_fingerprint == (
        original.metadata.server_certificate_fingerprint
    )


@pytest.mark.parametrize(
    ("target", "mutation", "reason"),
    [
        (
            "profile",
            lambda fs: fs.seed_symlink(PRODUCTION_LAYOUT.profile_path),
            "production_profile_unavailable",
        ),
        (
            "profile",
            lambda fs: fs.seed_file(
                PRODUCTION_LAYOUT.profile_path, b"{}", uid=0, gid=0, mode=0o666
            ),
            "production_profile_unavailable",
        ),
        (
            "tls",
            lambda fs: fs.seed_file(
                PRODUCTION_LAYOUT.server_private_key_path,
                b"not-a-key",
                uid=0,
                gid=0,
                mode=0o640,
            ),
            "production_tls_private_key_unavailable",
        ),
        (
            "tls",
            lambda fs: fs.seed_file(
                PRODUCTION_LAYOUT.ca_certificate_path,
                b"not-a-ca",
                uid=0,
                gid=0,
                mode=0o644,
                nlink=2,
            ),
            "production_tls_ca_unavailable",
        ),
    ],
)
def test_fixed_input_metadata_refuses_symlink_hardlink_wrong_owner_or_mode(
    target: str,
    mutation,
    reason: str,  # noqa: ANN001
) -> None:
    fs, _material = _fixed_filesystem()
    mutation(fs)

    with pytest.raises(Exception) as exc:
        profile = _load_fixed_profile(fs)
        if target == "tls":
            _load_fixed_tls(fs, profile)

    assert getattr(exc.value, "reason_code", None) == reason
    assert "not-a-key" not in repr(exc.value)


def test_production_plan_and_render_use_fixed_inputs_without_mutation_or_adapter(
    monkeypatch,
) -> None:
    fs, _material = _fixed_filesystem()
    before = fs.paths()
    monkeypatch.setattr(cli_module, "_real_filesystem", lambda: fs)

    plan_code, plan = run(["plan", "--json"])
    render_code, rendered = run(["render", "--json"])

    assert plan_code == render_code == EXIT_OK
    assert plan["outcome"] == "planned"
    assert rendered["outcome"] == "rendered"
    assert plan["details"]["host_mutations_during_plan"] is False
    assert plan["details"]["external_contacts_during_plan"] is False
    assert fs.paths() == before
    assert PRODUCTION_LAYOUT.evidence_signing_key_path not in fs.paths()


@pytest.mark.parametrize("role", ["controller", "worker"])
def test_production_fixed_role_dispatches_all_eight_operations_without_generic_host_selection(
    role: str, monkeypatch
) -> None:
    fs, _material = _fixed_filesystem(role=role, evidence_key=True)
    before = fs.paths()
    monkeypatch.setattr(cli_module, "_real_filesystem", lambda: fs)
    monkeypatch.setattr(cli_module, "RealWorkerStateFilesystem", InMemoryWorkerStateFilesystem)

    def handler(name: str):
        def invoke(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
            return OperationResult(name, "complete", None, False, {"marker": name})

        return invoke

    prefix = "controller" if role == "controller" else "worker"
    for operation in ("inspect", "install", "verify", "status", "rollback", "evidence"):
        monkeypatch.setattr(
            cli_module,
            f"{prefix}_{operation}_operation",
            handler(f"{prefix}-{operation}"),
        )

    observed: list[str] = []
    for operation in (
        "inspect",
        "plan",
        "render",
        "install",
        "verify",
        "status",
        "rollback",
        "evidence",
    ):
        argv = [operation, "--json"]
        if operation == "install":
            argv += ["--write", "--confirm", "--installation-identity", "operator.test"]
        elif operation == "rollback":
            argv += ["--write", "--confirm"]
        code, payload = run(argv)
        assert code == EXIT_OK, (operation, payload)
        assert payload["operation"] == operation
        assert payload["details"]["host_role"] == role
        observed.append(operation)

    assert observed == list(cli_module._OPERATIONS)  # noqa: SLF001
    assert fs.paths() == before


def test_disabled_install_prepares_only_local_evidence_key_and_invalid_identity_stays_inert(
    monkeypatch,
) -> None:
    disabled, _material = _fixed_filesystem(enabled=False)
    monkeypatch.setattr(cli_module, "_real_filesystem", lambda: disabled)
    code, payload = run(
        [
            "install",
            "--write",
            "--confirm",
            "--installation-identity",
            "operator.test",
        ]
    )
    assert code == EXIT_OK and payload["outcome"] == "prepared"
    assert payload["reason_code"] == "activation_disabled_key_preparation_only"
    assert payload["details"]["activation_effects_started"] is False
    assert payload["details"]["container_recreated"] is False
    assert payload["details"]["evidence_key_id"].startswith("sha256:")
    assert PRODUCTION_LAYOUT.evidence_signing_key_path in disabled.paths()
    assert PRODUCTION_LAYOUT.evidence_trust_anchor_path in disabled.paths()

    enabled, _material = _fixed_filesystem(enabled=True)
    monkeypatch.setattr(cli_module, "_real_filesystem", lambda: enabled)
    code, payload = run(
        [
            "install",
            "--write",
            "--confirm",
            "--installation-identity",
            "bad identity with spaces",
        ]
    )
    assert code == EXIT_REFUSED and payload["reason_code"] == "installation_identity_invalid"
    assert PRODUCTION_LAYOUT.evidence_signing_key_path not in enabled.paths()


@pytest.mark.parametrize("role", ["controller", "worker"])
def test_inspect_does_not_require_or_create_an_evidence_key(role: str, monkeypatch) -> None:
    fs, _material = _fixed_filesystem(role=role, evidence_key=False)
    before = fs.paths()
    monkeypatch.setattr(cli_module, "_real_filesystem", lambda: fs)
    monkeypatch.setattr(cli_module, "RealWorkerStateFilesystem", InMemoryWorkerStateFilesystem)
    operation = f"{role}_inspect_operation"
    monkeypatch.setattr(
        cli_module,
        operation,
        lambda *_args, **_kwargs: OperationResult(operation, "inspected", None, False, {}),
    )

    code, payload = run(["inspect", "--json"])

    assert code == EXIT_OK and payload["outcome"] == "inspected"
    assert fs.paths() == before
    assert PRODUCTION_LAYOUT.evidence_signing_key_path not in fs.paths()


@pytest.mark.parametrize("role", ["controller", "worker"])
def test_disabled_status_does_not_require_tls_or_an_evidence_key(role: str, monkeypatch) -> None:
    fs, _material = _fixed_filesystem(enabled=False, role=role, evidence_key=False)
    for path in (
        PRODUCTION_LAYOUT.ca_certificate_path,
        PRODUCTION_LAYOUT.server_certificate_path,
        PRODUCTION_LAYOUT.server_private_key_path,
    ):
        if fs.lstat(path) is not None:
            fs.remove_file(path)
    before = fs.paths()
    monkeypatch.setattr(cli_module, "_real_filesystem", lambda: fs)
    monkeypatch.setattr(cli_module, "RealWorkerStateFilesystem", InMemoryWorkerStateFilesystem)
    operation = f"{role}_status_operation"
    monkeypatch.setattr(
        cli_module,
        operation,
        lambda *_args, **_kwargs: OperationResult(
            operation, "disabled", "activation_false", False, {}
        ),
    )

    code, payload = run(["status", "--json"])

    assert code == EXIT_OK and payload["outcome"] == "disabled"
    assert fs.paths() == before
    assert PRODUCTION_LAYOUT.evidence_signing_key_path not in fs.paths()


def test_test_only_dependency_injection_dispatches_each_exact_engine_operation(monkeypatch) -> None:
    deps = _injected_dependencies()
    called: list[tuple[str, tuple, dict]] = []

    def handler(name: str):
        def invoke(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            called.append((name, args, kwargs))
            return OperationResult(name, "complete", None, False, {"operation_marker": name})

        return invoke

    mapping = {
        "inspect_operation": "inspect",
        "plan_operation": "plan",
        "render_operation": "render",
        "install_operation": "install",
        "verify_operation": "verify",
        "status_operation": "status",
        "rollback_operation": "rollback",
        "evidence_operation": "evidence",
    }
    for attribute, operation in mapping.items():
        monkeypatch.setattr(cli_module, attribute, handler(operation))

    for operation in (
        "inspect",
        "plan",
        "render",
        "install",
        "verify",
        "status",
        "rollback",
        "evidence",
    ):
        argv = [operation]
        if operation == "install":
            argv += ["--write", "--confirm", "--installation-identity", "operator.test"]
        elif operation == "rollback":
            argv += ["--write", "--confirm"]
        code, payload = run(argv, deps=deps)
        assert code == EXIT_OK
        assert payload["operation"] == operation
        assert payload["details"] == {"operation_marker": operation}

    assert [name for name, _args, _kwargs in called] == list(mapping.values())
    install_call = next(item for item in called if item[0] == "install")
    assert install_call[2]["installation_identity"] == "operator.test"


def test_foreign_dependency_object_is_refused_without_attribute_access() -> None:
    class Hostile:
        def __getattribute__(self, _name):
            raise AssertionError("foreign dependencies must not be inspected")

    code, payload = run(["plan"], deps=Hostile())  # type: ignore[arg-type]

    assert code == EXIT_REFUSED
    assert payload["reason_code"] == "cli_dependencies_type_invalid"


def test_json_output_is_canonical_deterministic_and_secret_free(capsys) -> None:
    deps = _injected_dependencies()
    first = main(["plan", "--json"], deps=deps)
    first_output = capsys.readouterr().out
    second = main(["plan", "--json"], deps=deps)
    second_output = capsys.readouterr().out

    assert first == second == EXIT_OK
    assert first_output == second_output
    payload = json.loads(first_output)
    assert payload["outcome"] == "planned"
    assert "PRIVATE KEY" not in first_output
    assert "BEGIN CERTIFICATE" not in first_output
    assert "database_url" not in first_output


def test_production_dependency_exception_is_bounded_and_never_echoed(monkeypatch) -> None:
    monkeypatch.setattr(
        cli_module,
        "_real_filesystem",
        lambda: (_ for _ in ()).throw(
            RuntimeError("postgresql://administrator:secret@internal.example")
        ),
    )

    code, payload = run(["plan", "--json"])
    serialized = json.dumps(payload)

    assert code == EXIT_REFUSED
    assert payload["reason_code"] == "production_dependency_unavailable"
    assert "secret" not in serialized and "internal.example" not in serialized
