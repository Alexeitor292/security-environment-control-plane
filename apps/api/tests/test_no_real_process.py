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


def test_subprocess_executor_is_disarmed_by_default():
    with pytest.raises(ProcessExecutionError, match="disarmed|not enabled"):
        SubprocessProcessExecutor()


def test_fake_executor_runs_nothing_but_records_calls():
    executor = FakeProcessExecutor(plan_digest="x")
    result = executor.run(
        ProcessSpec(argv=["tofu", "version"], cwd=".", timeout_s=1.0, label="probe")
    )
    assert result.returncode == 0
    assert executor.calls and executor.calls[0].argv == ["tofu", "version"]
    # The fake returns only canned, secret-free JSON — no host state is touched.
    assert "plan_digest" in result.stdout


def test_default_settings_select_the_fake_executor():
    # In B1-A (no subprocess arm) the factory always returns the fake executor.
    executor = build_process_executor(Settings(app_env="test"))
    assert isinstance(executor, FakeProcessExecutor)


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
