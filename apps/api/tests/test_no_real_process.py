"""Proof #3 — no test / CI / verification path invokes a real binary, network,
provider, or endpoint. The subprocess executor is disarmed by default and never armed
in B1-A; every path uses the FakeProcessExecutor."""

from __future__ import annotations

from pathlib import Path

import pytest
from secp_api.config import Settings
from secp_worker.provisioning import FakeProcessExecutor, SubprocessProcessExecutor
from secp_worker.provisioning.activation import build_process_executor
from secp_worker.provisioning.process_executor import ProcessExecutionError, ProcessSpec

WORKER_PROV = Path(__file__).resolve().parents[2] / "worker" / "secp_worker" / "provisioning"


def test_subprocess_executor_is_sealed_and_cannot_be_constructed():
    """Proof #1 (hardened) — the real executor is SEALED: construction refused
    unconditionally in B1-A, even directly and even with armed=True."""
    with pytest.raises(ProcessExecutionError, match="SEALED|sealed"):
        SubprocessProcessExecutor()
    with pytest.raises(ProcessExecutionError, match="SEALED|sealed"):
        SubprocessProcessExecutor(armed=True)


def test_b1a_subprocess_seal_is_a_code_constant_set_true():
    from secp_worker.provisioning import process_executor as pe

    assert pe._B1A_SUBPROCESS_SEALED is True


def test_fake_executor_runs_nothing_but_records_calls():
    executor = FakeProcessExecutor()
    # A non-show step produces no parsed stdout; the fake runs nothing.
    plan = executor.run(
        ProcessSpec(argv=["tofu", "version"], cwd=".", timeout_s=1.0, label="probe")
    )
    assert plan.returncode == 0 and plan.stdout == ""
    # The show step returns only safe, canned fixture JSON — no host state is touched.
    show = executor.run(ProcessSpec(argv=["tofu", "show"], cwd=".", timeout_s=1.0, label="show"))
    assert '"resource_changes"' in show.stdout
    assert executor.calls and executor.calls[0].argv == ["tofu", "version"]


def test_default_settings_select_the_fake_executor():
    # In B1-A (no subprocess arm) the factory always returns the fake executor.
    executor = build_process_executor(Settings(app_env="test"))
    assert isinstance(executor, FakeProcessExecutor)


def test_config_flag_alone_cannot_construct_real_subprocess():
    """Proof #6 — SECP_ENABLE_OPENTOFU_SUBPROCESS=true alone yields a FakeProcessExecutor."""
    settings = Settings(app_env="dev", enable_opentofu_subprocess=True)
    assert isinstance(build_process_executor(settings, grant=None), FakeProcessExecutor)


def test_grant_requires_a_passed_gate():
    from secp_worker.provisioning.activation import grant_real_lab_activation

    with pytest.raises(RuntimeError, match="gate"):
        grant_real_lab_activation(manifest_id="m", gate_passed=False)


def test_even_a_valid_grant_stays_sealed_in_b1a():
    """A valid grant + enabled + non-prod still returns Fake due to the hard B1-A seal."""
    from secp_worker.provisioning.activation import grant_real_lab_activation

    settings = Settings(app_env="dev", enable_opentofu_subprocess=True)
    grant = grant_real_lab_activation(manifest_id="m", gate_passed=True)
    assert isinstance(build_process_executor(settings, grant=grant), FakeProcessExecutor)


def test_negative_gates_never_construct_real_subprocess():
    # Simulator mode, missing real-provisioning, and inline dispatch all keep the fake.
    for settings in (
        Settings(app_env="test", provisioning_application_mode="simulator"),
        Settings(app_env="test", enable_real_provisioning=False),
        Settings(app_env="test", enable_opentofu_subprocess=False),
    ):
        assert isinstance(build_process_executor(settings), FakeProcessExecutor)


def test_subprocess_arm_is_refused_in_production():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(
            app_env="production",
            enable_opentofu_subprocess=True,
            auth_dev_mode=False,
            workflow_dispatch_mode="temporal",
        )


def test_no_worker_module_calls_subprocess_run_outside_the_sealed_executor():
    """Only process_executor.py may *use* subprocess, and only lazily inside the
    (inert) SubprocessProcessExecutor. Prose/docstring mentions are ignored; this
    checks for actual import/call usage."""
    usage = ("import subprocess", "subprocess.run", "subprocess.Popen", "subprocess.call")
    for path in WORKER_PROV.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if path.name == "process_executor.py":
            assert "import subprocess" in text  # lazy import inside the sealed executor
            continue
        for token in (*usage, "os.system(", "os.popen("):
            assert token not in text, f"{path.name} uses {token}"


def test_opentofu_runner_never_imports_a_provider_sdk():
    text = (WORKER_PROV / "opentofu.py").read_text(encoding="utf-8")
    for forbidden in ("proxmoxer", "import httpx", "import requests", "socket", "paramiko"):
        assert forbidden not in text
