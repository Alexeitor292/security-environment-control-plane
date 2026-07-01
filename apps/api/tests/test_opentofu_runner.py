"""Proofs #7, #8 (+ #15 leakage) — deterministic secret-free rendering, safe sealed
process invocation, and redacted errors. No real binary/provider/endpoint is used."""

from __future__ import annotations

import pytest
from secp_worker.provisioning import (
    FakeProcessExecutor,
    OpenTofuRunner,
    WorkspaceRenderer,
    build_fixture_show_json,
)
from secp_worker.provisioning.process_executor import DEFAULT_TIMEOUT_S
from secp_worker.provisioning.rendering import RENDERER_VERSION, RenderingError
from secp_worker.provisioning.runner import RunnerError

_SECRET_ENV = {
    "TF_VAR_pm_endpoint": "https://proxmox.example.test",
    "TF_VAR_pm_api_token": "FAKE-TOKEN-XYZ",
}


def _manifest_and_profile(lab_env):
    env = lab_env()
    return env.manifest.content, env.toolchain.content


# --- #7: deterministic, secret-free rendering --------------------------------


def test_render_is_deterministic(lab_env):
    manifest, profile = _manifest_and_profile(lab_env)
    a = WorkspaceRenderer().render(manifest, profile)
    b = WorkspaceRenderer().render(manifest, profile)
    assert a.content_hash == b.content_hash
    assert a.files == b.files
    assert a.renderer_version == RENDERER_VERSION


def test_rendered_workspace_is_secret_free(lab_env):
    manifest, profile = _manifest_and_profile(lab_env)
    ws = WorkspaceRenderer().render(manifest, profile)
    blob = "\n".join(ws.files.values())
    # Endpoint + token are referenced ONLY as input variables, never as literals.
    assert "var.pm_endpoint" in blob
    assert "var.pm_api_token" in blob
    for needle in ("FAKE-TOKEN", "env:SECP", "proxmox.example.test", 'api_token = "'):
        assert needle not in blob, f"rendered workspace leaked {needle!r}"
    # A remote backend is rendered; local state is never present.
    assert "backend" in ws.files["backend.tf"]
    assert 'backend "local"' not in blob


def test_render_records_all_binding_hashes(lab_env):
    manifest, profile = _manifest_and_profile(lab_env)
    ws = WorkspaceRenderer().render(manifest, profile)
    from secp_scenario_schema import content_hash

    assert ws.manifest_content_hash == content_hash(manifest)
    assert ws.scope_policy_hash == manifest["target_scope_policy_hash"]
    assert ws.module_bundle_hash == profile["module_bundle_hash"]
    assert ws.renderer_version == RENDERER_VERSION


def test_renderer_refuses_renderer_version_drift(lab_env):
    manifest, profile = _manifest_and_profile(lab_env)
    drifted = dict(profile)
    drifted["renderer_version"] = "secp-002b-1a/renderer/vOTHER"
    with pytest.raises(RenderingError, match="renderer_version"):
        WorkspaceRenderer().render(manifest, drifted)


def test_renderer_refuses_local_state(lab_env):
    manifest, profile = _manifest_and_profile(lab_env)
    local = dict(profile)
    local["state_backend"] = {"kind": "local", "reference": "x"}
    with pytest.raises((RenderingError, Exception)):
        WorkspaceRenderer().render(manifest, local)


# --- #8: sealed process executor receives safe argv/cwd/offline/env/timeout ---


def test_dry_run_uses_safe_sealed_process_calls(lab_env):
    manifest, profile = _manifest_and_profile(lab_env)
    executor = FakeProcessExecutor(show_json=build_fixture_show_json(manifest))
    runner = OpenTofuRunner(executor, profile=profile, secret_env=_SECRET_ENV)
    cs = runner.dry_run(manifest, operation_id="op-1")

    assert cs.change_set_hash and cs.workspace_hash
    assert executor.calls, "the runner must go through the process executor"

    labels = {c.label for c in executor.calls}
    assert {"init", "plan", "show"} <= labels

    for spec in executor.calls:
        # argv arrays only, never a shell string. The pinned executable is used.
        assert isinstance(spec.argv, list) and spec.argv
        assert spec.argv[0] == profile["executable"] == "tofu"
        assert not any(tok in " ".join(spec.argv) for tok in (";", "&&", "|", "`", "$("))
        # the working directory is the ephemeral restrictive-permission workspace.
        assert "secp-tofu-ws-" in spec.cwd
        # bounded timeout.
        assert 0 < spec.timeout_s <= DEFAULT_TIMEOUT_S
        # environment is allowlisted and the secret value is redacted for logging.
        assert all(k == "TF_IN_AUTOMATION" or k.startswith("TF_VAR_") for k in spec.env)
        redacted = spec.redacted_env()
        if "TF_VAR_pm_api_token" in redacted:
            assert redacted["TF_VAR_pm_api_token"] == "***REDACTED***"
            assert "FAKE-TOKEN" not in "".join(redacted.values())

    # init carries offline-only flags (no network, no module/plugin download).
    init = next(c for c in executor.calls if c.label == "init")
    joined = " ".join(init.argv)
    assert "-get=false" in init.argv
    assert "-lockfile=readonly" in init.argv
    assert any(a.startswith("-plugin-dir=") for a in init.argv)
    assert "-upgrade=false" in init.argv
    assert "-input=false" in joined

    # The ephemeral workspace is cleaned up after dry_run returns (no residue).
    import os

    assert not os.path.isdir(executor.calls[0].cwd)


def test_change_set_hash_changes_when_plan_actions_change(lab_env):
    manifest, profile = _manifest_and_profile(lab_env)
    a = OpenTofuRunner(
        FakeProcessExecutor(show_json=build_fixture_show_json(manifest, actions=("create",))),
        profile=profile,
    ).dry_run(manifest, operation_id="op")
    b = OpenTofuRunner(
        FakeProcessExecutor(show_json=build_fixture_show_json(manifest, actions=("update",))),
        profile=profile,
    ).dry_run(manifest, operation_id="op")
    assert a.change_set_hash != b.change_set_hash


# --- #15: redacted errors ----------------------------------------------------


def test_invalid_manifest_raises_redacted_error(lab_env):
    _manifest, profile = _manifest_and_profile(lab_env)
    runner = OpenTofuRunner(FakeProcessExecutor(), profile=profile)
    with pytest.raises(RunnerError) as exc:
        runner.dry_run({"manifest_version": "x"}, operation_id="op-bad")
    msg = str(exc.value).lower()
    assert "redacted" in msg
    for needle in ("token", "password", "secret"):
        assert needle not in msg
