"""Proofs #4, #5 — toolchain profiles reject unsafe provenance and bind by hash.

#4: reject floating versions, missing hashes, local state, direct downloads, unknown
    adapters, and unconfigured/permissive activation.
#5: the toolchain-profile hash binds exactly to the plan and the manifest (and, via the
    gate test, to change-set approvals, apply, and destroy).
"""

from __future__ import annotations

import copy

import pytest
from secp_api.errors import ValidationFailedError
from secp_api.toolchain_profile import toolchain_profile_hash, validate_toolchain_profile

VALID: dict = {
    "runner_kind": "opentofu",
    "executable": "tofu",
    "opentofu_version": "9.9.9",
    "binary_integrity": "sha256:" + "de" * 32,
    "adapter_kind": "proxmox",
    "module_bundle_id": "secp-fake-lab-bundle",
    "module_bundle_hash": "sha256:" + "ab" * 32,
    "provider_lockfile_hash": "sha256:" + "cd" * 32,
    "renderer_version": "secp-002b-1a/renderer/v1",
    "state_backend": {"kind": "http", "reference": "secp-fake-remote-state/lab"},
    "provider_mirror": {
        "identity": "secp-fake-offline-mirror",
        "network_access": "offline",
        "allow_runtime_download": False,
    },
    "activation_class": "isolated_lab",
}


def _without(key: str) -> dict:
    p = copy.deepcopy(VALID)
    p.pop(key, None)
    return p


def _with(**overrides) -> dict:
    p = copy.deepcopy(VALID)
    p.update(overrides)
    return p


def test_valid_profile_accepted():
    spec = validate_toolchain_profile(VALID)
    assert spec.runner_kind == "opentofu"
    assert spec.activation_class == "isolated_lab"
    assert spec.opentofu_version == "9.9.9"


@pytest.mark.parametrize(
    "profile",
    [
        _with(opentofu_version="latest"),
        _with(opentofu_version=">=1.0.0"),
        _with(opentofu_version="~> 1.8"),
        _with(opentofu_version="1.8"),
        _with(opentofu_version="1.8.x"),
        _with(opentofu_version=""),
        _with(opentofu_version="*"),
    ],
)
def test_floating_or_unpinned_version_rejected(profile):
    with pytest.raises(ValidationFailedError):
        validate_toolchain_profile(profile)


@pytest.mark.parametrize(
    "profile",
    [
        _without("binary_integrity"),
        _with(binary_integrity="not-a-digest"),
        _with(binary_integrity=""),
        _without("module_bundle_hash"),
        _with(module_bundle_hash="deadbeef"),
        _without("provider_lockfile_hash"),
        _with(provider_lockfile_hash="sha256:xyz"),
    ],
)
def test_missing_or_malformed_hashes_rejected(profile):
    with pytest.raises(ValidationFailedError):
        validate_toolchain_profile(profile)


@pytest.mark.parametrize(
    "backend",
    [
        {"kind": "local", "reference": "state"},
        {"kind": "", "reference": "state"},
        {"kind": "file", "reference": "state"},
        {"kind": "http", "reference": ""},  # missing reference
    ],
)
def test_local_or_unconfigured_state_rejected(backend):
    with pytest.raises(ValidationFailedError):
        validate_toolchain_profile(_with(state_backend=backend))


@pytest.mark.parametrize(
    "mirror",
    [
        {"identity": "m", "network_access": "online", "allow_runtime_download": False},
        {"identity": "m", "network_access": "internet", "allow_runtime_download": False},
        {"identity": "m", "network_access": "offline", "allow_runtime_download": True},
        {"identity": "", "network_access": "offline", "allow_runtime_download": False},
    ],
)
def test_direct_download_or_online_mirror_rejected(mirror):
    with pytest.raises(ValidationFailedError):
        validate_toolchain_profile(_with(provider_mirror=mirror))


@pytest.mark.parametrize(
    "profile",
    [
        _with(adapter_kind="aws"),
        _with(adapter_kind="unknown"),
        _with(runner_kind="terraform"),
        _with(activation_class="production"),
        _with(activation_class="permissive"),
        _with(unexpected_key=True),  # extra="forbid"
    ],
)
def test_unknown_adapter_runner_or_permissive_activation_rejected(profile):
    with pytest.raises(ValidationFailedError):
        validate_toolchain_profile(profile)


def test_hash_is_stable_and_order_independent():
    reordered = {k: VALID[k] for k in reversed(list(VALID))}
    assert toolchain_profile_hash(VALID) == toolchain_profile_hash(reordered)


# --- #5: hash binding to plan + manifest -------------------------------------


def test_profile_hash_binds_to_plan_and_manifest(lab_env):
    env = lab_env()
    expected = env.toolchain.content_hash
    assert env.plan.toolchain_profile_id == env.toolchain.id
    assert env.plan.toolchain_profile_hash == expected
    assert env.manifest.toolchain_profile_id == env.toolchain.id
    assert env.manifest.toolchain_profile_hash == expected
    assert env.manifest.content["toolchain_profile_hash"] == expected
    # And the recorded hash is exactly the canonical hash of the profile content.
    assert toolchain_profile_hash(env.toolchain.content) == expected


def test_toolchain_profile_is_immutable_after_creation(session, principal, lab_env):
    """The toolchain profile provenance is immutable (ORM guard, ADR-013)."""
    from secp_api.errors import ImmutableResourceError

    env = lab_env()
    env.toolchain.content = {**env.toolchain.content, "opentofu_version": "1.2.3"}
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()


def test_change_set_approval_bindings_are_immutable(session, principal, lab_env):
    """An approval's bindings/hashes are immutable; only the decision may change."""
    from secp_api.enums import ProvisioningOperationKind
    from secp_api.errors import ImmutableResourceError
    from secp_api.models import ProvisioningChangeSetApproval
    from secp_api.services import approvals

    env = lab_env()
    approval = approvals.record_change_set(
        session,
        env.manifest,
        env.toolchain,
        authorizes_kind=ProvisioningOperationKind.apply,
        change_set_hash="sha256:" + "11" * 32,
        rendered_workspace_hash="sha256:" + "22" * 32,
        summary={"create": 8},
    )
    session.commit()
    # Mutating a binding is refused.
    approval.change_set_hash = "sha256:" + "33" * 32
    with pytest.raises(ImmutableResourceError):
        session.flush()
    session.rollback()
    # But approving (a decision field) is allowed.
    fresh = session.get(ProvisioningChangeSetApproval, approval.id)
    approvals.approve_change_set(session, principal, fresh.id, "ok")
    session.flush()


def test_registration_rejects_unknown_adapter_for_provider(session, principal, lab_env):
    """A profile whose adapter does not match the target provider is refused."""
    from secp_api.services import targets, toolchain

    target = targets.register_target(
        session,
        principal,
        display_name="Lab2",
        plugin_name="proxmox",
        config={"base_url": "https://proxmox.example.test:8006/api2/json", "verify_tls": True},
        secret_ref="env:SECP_PROVIDER_SECRET__LAB2",
        scope_policy={"provisioning": {}},
    )
    session.commit()
    bad = copy.deepcopy(VALID)
    bad["adapter_kind"] = "aws"  # not proxmox
    with pytest.raises(ValidationFailedError):
        toolchain.register_toolchain_profile(
            session, principal, target_id=target.id, name="bad", profile=bad
        )
