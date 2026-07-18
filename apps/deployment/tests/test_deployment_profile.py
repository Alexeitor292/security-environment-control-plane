"""The strict, secret-free, hardened-read deployment profile (SECP-PR5D, blocker #8)."""

from __future__ import annotations

import json

import pytest
from _deploy_support import seeded_profile_fs, valid_profile_raw
from secp_operator_deployment import DeploymentPackageError
from secp_operator_deployment.profile import (
    ProfileError,
    parse_deployment_profile,
    parse_profile_bytes,
    read_deployment_profile,
)


def test_valid_profile_roundtrips():
    from secp_operator_deployment.identities import (
        ELIGIBILITY_PROVIDER_IDENTITY,
        PLAN_PROVIDER_IDENTITY,
        READINESS_PROVIDER_IDENTITY,
    )

    p = parse_deployment_profile(valid_profile_raw())
    assert p.contract_version == "secp.operator-deployment/v1alpha1"
    assert p.ordinary_task_queue != p.operator_task_queue
    assert p.ordinary_container_name == "secp-ordinary-worker"
    # blocker #6: the three reviewed provider identities are strict required profile fields.
    assert p.plan_provider_identity == PLAN_PROVIDER_IDENTITY
    assert p.readiness_provider_identity == READINESS_PROVIDER_IDENTITY
    assert p.eligibility_provider_identity == ELIGIBILITY_PROVIDER_IDENTITY


def test_unknown_field_refused():
    with pytest.raises(ProfileError):
        parse_deployment_profile({**valid_profile_raw(), "surprise": 1})


def test_secret_shaped_field_name_refused():
    with pytest.raises(DeploymentPackageError):
        parse_deployment_profile({**valid_profile_raw(), "openbao_token": "x"})


def test_secret_shaped_value_refused():
    with pytest.raises(DeploymentPackageError):
        parse_deployment_profile(valid_profile_raw(operator_service_name="vault:secret/data/op"))


@pytest.mark.parametrize(
    "field",
    [
        "package_implementation_digest",
        "operator_image_digest",
        "ordinary_container_name",
        "container_runtime_executable",
        "container_runtime_executable_digest",
        "service_inspector_executable",
        "service_inspector_executable_digest",
        "controlled_live_process_digest",
        "plan_provider_identity",
        "readiness_provider_identity",
        "eligibility_provider_identity",
    ],
)
def test_missing_required_field_refused(field):
    raw = valid_profile_raw()
    raw.pop(field)
    with pytest.raises(ProfileError):
        parse_deployment_profile(raw)


@pytest.mark.parametrize(
    "field",
    ["plan_provider_identity", "readiness_provider_identity", "eligibility_provider_identity"],
)
def test_malformed_provider_identity_refused(field):
    # blocker #6: a provider identity that is not a dotted module.qualname is refused by the schema.
    with pytest.raises(ProfileError):
        parse_deployment_profile(valid_profile_raw(**{field: "not a qualname!"}))


def test_queue_equality_refused():
    with pytest.raises(ProfileError):
        parse_deployment_profile(valid_profile_raw(operator_task_queue="secp-orchestration"))


def test_non_absolute_service_inspector_refused():
    with pytest.raises(ProfileError):
        parse_deployment_profile(valid_profile_raw(service_inspector_executable="systemctl"))


def test_non_sha_executable_digest_refused():
    with pytest.raises(ProfileError):
        parse_deployment_profile(valid_profile_raw(container_runtime_executable_digest="deadbeef"))


def test_relative_health_command_executable_refused():
    raw = valid_profile_raw(ordinary_health_command=["python", "-m", "secp_worker.health"])
    with pytest.raises(ProfileError):
        parse_deployment_profile(raw)


# --- blocker #8: duplicate-key rejection at every nesting level ---


def test_top_level_duplicate_key_refused():
    raw = valid_profile_raw()
    body = json.dumps(raw)
    # inject a duplicate top-level key by string surgery (json.dumps can't emit duplicates)
    injected = body[:-1] + ',"operator_task_queue":"secp-x"}'
    with pytest.raises(ProfileError) as exc:
        parse_profile_bytes(injected.encode("utf-8"))
    assert exc.value.reason_code == "profile_duplicate_key"


def test_nested_duplicate_key_refused():
    # a nested object with a repeated key at depth
    dup = b'{"a": {"k": 1, "k": 2}}'
    with pytest.raises(ProfileError) as exc:
        parse_profile_bytes(dup)
    assert exc.value.reason_code == "profile_duplicate_key"


def test_non_utf8_profile_refused():
    with pytest.raises(ProfileError) as exc:
        parse_profile_bytes(b"\xff\xfe not utf8")
    assert exc.value.reason_code == "profile_not_utf8"


def test_reason_code_never_echoes_duplicate_key():
    dup = b'{"vault_topology_secret": 1, "vault_topology_secret": 2}'
    with pytest.raises(ProfileError) as exc:
        parse_profile_bytes(dup)
    assert "vault" not in exc.value.reason_code
    assert exc.value.reason_code in ("profile_duplicate_key", "profile_forbidden_secret")


# --- hardened fixed-path read ---


def test_hardened_read_from_fixed_path():
    p = read_deployment_profile(fs=seeded_profile_fs())
    assert p.package_version == "0.1.0"


def test_absent_profile_fails_closed():
    from secp_commissioning.runtime import InMemoryFilesystem

    with pytest.raises(ProfileError) as exc:
        read_deployment_profile(fs=InMemoryFilesystem())
    assert exc.value.reason_code == "profile_not_installed"


def test_untrusted_owner_profile_fails_closed():
    from secp_commissioning.runtime import InMemoryFilesystem

    fs = InMemoryFilesystem()
    fs.seed_dir("/etc/secp/operator-deployment", uid=0, gid=0, mode=0o755)
    fs.seed_file(
        "/etc/secp/operator-deployment/profile.json",
        json.dumps(valid_profile_raw()).encode(),
        uid=1000,
        gid=0,
        mode=0o640,
    )
    with pytest.raises(ProfileError) as exc:
        read_deployment_profile(fs=fs)
    assert exc.value.reason_code == "profile_unreadable"


def test_duplicate_key_refused_through_hardened_read():
    raw = valid_profile_raw()
    body = json.dumps(raw)
    injected = (body[:-1] + ',"operator_image_digest":"sha256:' + "0" * 64 + '"}').encode("utf-8")
    with pytest.raises(ProfileError) as exc:
        read_deployment_profile(fs=seeded_profile_fs(raw_bytes=injected))
    assert exc.value.reason_code == "profile_duplicate_key"
