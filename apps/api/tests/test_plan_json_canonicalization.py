"""Part 3 + Part 4 — canonical redacted OpenTofu show-json handling, pinned executable,
safe identifiers, and the toolchain-verifier requirement (all fake, no real process)."""

from __future__ import annotations

import copy

import pytest
from secp_worker.provisioning import (
    FakeProcessExecutor,
    FakeToolchainVerifier,
    OpenTofuRunner,
    PlanCanonicalizationError,
    build_fixture_show_json,
    canonicalize_plan_json,
    change_set_hash,
)
from secp_worker.provisioning.runner import RunnerError

_PROVENANCE = {
    "renderer_version": "r",
    "module_bundle_hash": "sha256:aa",
    "opentofu_version": "9.9.9",
}


def _show(actions):
    return {
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "labfake_vm.team1_attacker",
                "mode": "managed",
                "type": "labfake_vm",
                "name": "team1_attacker",
                "provider_name": "example.test/fake/labproxmox",
                "change": {
                    "actions": list(actions),
                    "before": None,
                    "after": {"api_token": "SUPER-SECRET", "root_password": "hunter2"},
                    "after_sensitive": {"api_token": True},
                },
            }
        ],
    }


# --- #3 canonicalization -----------------------------------------------------


def test_resource_action_difference_changes_hash():
    a = canonicalize_plan_json(_show(("create",)), kind="apply", workspace_hash="w", provenance={})
    b = canonicalize_plan_json(_show(("update",)), kind="apply", workspace_hash="w", provenance={})
    assert change_set_hash(a) != change_set_hash(b)


def test_sensitive_values_do_not_survive_canonicalization():
    canonical = canonicalize_plan_json(
        _show(("create",)), kind="apply", workspace_hash="w", provenance=_PROVENANCE
    )
    blob = str(canonical).lower()
    for needle in ("super-secret", "hunter2", "api_token", "root_password", "after", "before"):
        assert needle not in blob
    # Only safe review fields survive.
    r = canonical["resources"][0]
    assert set(r) == {"address", "mode", "type", "name", "provider", "actions", "replace"}


def test_replacement_indicator_detected():
    canonical = canonicalize_plan_json(
        _show(("delete", "create")), kind="apply", workspace_hash="w", provenance={}
    )
    assert canonical["resources"][0]["replace"] is True


@pytest.mark.parametrize(
    "bad",
    [
        {},  # no resource_changes
        {"resource_changes": "nope"},
        {"resource_changes": [{"type": "t", "name": "n"}]},  # missing change/address
        {
            "resource_changes": [{"address": "a", "type": "t", "name": "n", "change": {}}]
        },  # no actions
        {
            "resource_changes": [
                {"address": "a", "type": "t", "name": "n", "change": {"actions": "x"}}
            ]
        },
        "not-a-dict",
    ],
)
def test_malformed_plan_json_fails_closed(bad):
    with pytest.raises(PlanCanonicalizationError):
        canonicalize_plan_json(bad, kind="apply", workspace_hash="w", provenance={})


def test_fixture_builder_is_realistic_and_sensitive(lab_env):
    env = lab_env()
    show = build_fixture_show_json(env.manifest.content)
    assert show["resource_changes"]
    # The fixture deliberately carries fake secrets so redaction can be proven.
    assert any("SUPER-SECRET-FAKE-TOKEN" in str(rc) for rc in show["resource_changes"])


# --- #4 pinned executable, safe identifiers, verifier requirement ------------


def test_runner_uses_pinned_absolute_executable(lab_env):
    env = lab_env()
    profile = copy.deepcopy(env.toolchain.content)
    profile["executable"] = "/opt/secp/toolchain/tofu-9.9.9"
    executor = FakeProcessExecutor(show_json=build_fixture_show_json(env.manifest.content))
    OpenTofuRunner(executor, profile=profile).dry_run(env.manifest.content, operation_id="op")
    assert all(c.argv[0] == "/opt/secp/toolchain/tofu-9.9.9" for c in executor.calls)


@pytest.mark.parametrize(
    "executable",
    ["tofu; rm -rf /", "../evil", "bin/tofu", "/etc/passwd", "to fu", "tofu$(x)"],
)
def test_unsafe_executable_is_rejected(lab_env, executable):
    env = lab_env()
    profile = copy.deepcopy(env.toolchain.content)
    profile["executable"] = executable
    with pytest.raises(RunnerError):
        OpenTofuRunner(FakeProcessExecutor(), profile=profile)


@pytest.mark.parametrize("mirror_id", ["../evil", "a b", "m;rm", "m$(x)"])
def test_unsafe_mirror_identity_is_rejected(lab_env, mirror_id):
    env = lab_env()
    profile = copy.deepcopy(env.toolchain.content)
    profile["provider_mirror"]["identity"] = mirror_id
    with pytest.raises(RunnerError):
        OpenTofuRunner(FakeProcessExecutor(), profile=profile)


def test_runner_requires_toolchain_verification(lab_env):
    env = lab_env()
    # A verifier that fails to attest the binary digest → the runner refuses to execute.
    verifier = FakeToolchainVerifier(attest={"executable", "version", "renderer"})
    runner = OpenTofuRunner(
        FakeProcessExecutor(show_json=build_fixture_show_json(env.manifest.content)),
        profile=env.toolchain.content,
        verifier=verifier,
    )
    with pytest.raises(RunnerError, match="not verified"):
        runner.dry_run(env.manifest.content, operation_id="op")


def test_state_backend_reference_not_interpolated(lab_env):
    """The (possibly operator-supplied) backend reference never reaches rendered HCL."""
    from secp_worker.provisioning import WorkspaceRenderer

    env = lab_env()
    profile = copy.deepcopy(env.toolchain.content)
    profile["state_backend"]["reference"] = "secp-fake-remote-state/lab-marker-123"
    ws = WorkspaceRenderer().render(env.manifest.content, profile)
    assert "lab-marker-123" not in "\n".join(ws.files.values())
    assert 'backend "http" {}' in ws.files["backend.tf"]
