"""Proof #3 — no test / CI / verification path invokes a real binary, network, provider or endpoint.

Every path here uses the ``FakeProcessExecutor``, and the settings-driven factory returns it for
every combination of inputs it still accepts. That second half is now the load-bearing one: ADR-030
removed the seal that made a real executor unconstructible, so what keeps these paths fake is the
factory's severance from settings and grants rather than an inability to build the alternative.
The closure on the real executor itself is proven in ``test_opentofu_command_grammar.py``."""

from __future__ import annotations

from pathlib import Path

import pytest
from secp_api.config import Settings
from secp_worker.provisioning import FakeProcessExecutor, SubprocessProcessExecutor
from secp_worker.provisioning.activation import build_process_executor
from secp_worker.provisioning.process_executor import ProcessExecutionError, ProcessSpec

WORKER_PROV = Path(__file__).resolve().parents[2] / "worker" / "secp_worker" / "provisioning"


def test_the_real_executor_refuses_every_route_that_lacks_durable_authority():
    """The property that replaced the seal, exercised at its most permissive.

    Construction with no authority, with ``None`` through the worker's issuing function, and with
    a FORGERY -- an object carrying exactly the attribute names a real ``AuthorizedExecution``
    carries. The forgery is the case that matters: an executor validating by duck-typing would
    accept it, and only an identity check on the authority type refuses it.
    """
    from secp_worker.provisioning.activation import issue_authorized_executor

    class _Forged:
        opentofu_executable = "/opt/secp/bin/tofu"
        provider_mirror_identity = "forged-mirror"
        operation_id = "00000000-0000-0000-0000-000000000000"
        worker_installation_id = "wk-forged"
        rendered_workspace_hash = "sha256:" + "0" * 64
        change_set_hash = "sha256:" + "0" * 64
        authority_version = "secp.provisioning-execution-authority/v1"

    with pytest.raises(TypeError):
        SubprocessProcessExecutor()  # authority is keyword-only and required
    for bad in (None, _Forged(), object(), {"opentofu_executable": "/opt/secp/bin/tofu"}):
        with pytest.raises(ProcessExecutionError, match="AuthorizedExecution"):
            SubprocessProcessExecutor(authority=bad)
    with pytest.raises(ProcessExecutionError):
        issue_authorized_executor(None)


def test_the_retired_seal_and_its_flag_left_no_constant_or_alias_behind():
    """ADR-030 §1: delete the constants, and leave no compatibility alias -- an alias is a name
    future code can come to depend on, and its presence would let a later edit re-acquire a global
    "may execute" switch."""
    import inspect

    from secp_worker.provisioning import activation as act
    from secp_worker.provisioning import process_executor as pe

    for module in (pe, act):
        assert not hasattr(module, "_B1A_SUBPROCESS_SEALED")
    assert "armed" not in inspect.signature(SubprocessProcessExecutor.__init__).parameters
    # The name may still appear in prose recording what was retired and why; what must not exist is
    # an assignment creating one.
    for module in (pe, act):
        source = inspect.getsource(module)
        for retired in ("_B1A_SUBPROCESS_SEALED =", "self._armed", "armed: bool"):
            assert retired not in source, (module.__name__, retired)


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


def test_the_removed_config_flag_cannot_be_resurrected_through_the_factory():
    """``SECP_ENABLE_OPENTOFU_SUBPROCESS`` is gone (ADR-030 §2), not merely defaulted off.

    Passing it anyway is accepted-and-ignored by ``Settings`` (extras are not forbidden), which is
    the safe direction: the field being absent is what makes a stale value in a deployment's
    environment inert. The factory returns the fake either way.
    """
    settings = Settings(app_env="dev", enable_opentofu_subprocess=True)
    assert not hasattr(settings, "enable_opentofu_subprocess")
    assert isinstance(build_process_executor(settings, grant=None), FakeProcessExecutor)


def test_grant_requires_a_passed_gate():
    from secp_worker.provisioning.activation import grant_real_lab_activation

    with pytest.raises(RuntimeError, match="gate"):
        grant_real_lab_activation(manifest_id="m", gate_passed=False)


def test_even_a_valid_grant_cannot_obtain_a_real_executor():
    """A caller-attested ``gate_passed=True`` is not authority and never was a substitute for it.

    The grant is minted through the real function with the strongest input it accepts. Under
    ADR-030 the factory is SEVERED from it -- the parameter is accepted for call-site compatibility
    and cannot influence the result.
    """
    from secp_worker.provisioning.activation import grant_real_lab_activation

    settings = Settings(app_env="dev")
    grant = grant_real_lab_activation(manifest_id="m", gate_passed=True)
    assert isinstance(build_process_executor(settings, grant=grant), FakeProcessExecutor)


def test_negative_gates_never_construct_real_subprocess():
    # Simulator mode, missing real-provisioning, and inline dispatch all keep the fake.
    for settings in (
        Settings(app_env="test", provisioning_application_mode="simulator"),
        Settings(app_env="test"),
        Settings(app_env="test"),
    ):
        assert isinstance(build_process_executor(settings), FakeProcessExecutor)


def test_production_settings_carry_no_execution_arming_field_at_all():
    """The production refusal for ``enable_opentofu_subprocess`` is gone because the FIELD is gone.

    Stronger than the refusal it replaces: a validator that rejects a value in production still
    leaves the value settable everywhere else, and "everywhere else" includes the reviewed
    disposable lab this was always going to be armed in.
    """
    # Asserted against the MODEL rather than an instance: the field set is the property, and it
    # holds for every environment rather than only the one a test managed to construct.
    for removed in ("enable_opentofu_subprocess", "enable_real_provisioning"):
        assert removed not in Settings.model_fields, removed


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
