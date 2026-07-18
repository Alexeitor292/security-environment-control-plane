"""The operator-activation seal + the runner's exact-type refusal (SECP-PR5D, blocker #7)."""

from __future__ import annotations

import ast
import pathlib

import pytest
from secp_operator_deployment import DeploymentPackageError
from secp_operator_deployment import runner as runner_mod
from secp_operator_deployment.runner import run_operator_worker

_RUNNER_SRC = pathlib.Path(runner_mod.__file__)


def _real_registration():
    # The authoritative frozen dataclass, constructed directly — exactly the reviewed type.
    from secp_worker.operator_bootstrap import OperatorWorkerRegistration

    return OperatorWorkerRegistration(
        task_queue="secp-controlled-live-v1",
        workflows=(),
        activities=(),
        activity_names=(),
    )


def test_activation_seal_is_true():
    assert runner_mod._OPERATOR_ACTIVATION_SEALED is True


def test_real_registration_passes_type_check_then_hits_the_seal():
    with pytest.raises(DeploymentPackageError) as exc:
        run_operator_worker(_real_registration())
    assert exc.value.reason_code == "operator_activation_sealed"


def test_forged_module_qualname_registration_is_refused():
    # A forged class spoofing __module__/__qualname__ + shaped attributes must NOT pass the exact
    # type() is check.
    class _Reg:
        pass

    _Reg.__module__ = "secp_worker.operator_bootstrap"
    _Reg.__qualname__ = "OperatorWorkerRegistration"
    reg = _Reg()
    reg.task_queue = "x"
    reg.workflows = ()
    reg.activities = ()
    reg.activity_names = ()
    with pytest.raises(DeploymentPackageError) as exc:
        run_operator_worker(reg)
    assert exc.value.reason_code == "operator_registration_invalid"


def test_foreign_object_refused():
    with pytest.raises(DeploymentPackageError) as exc:
        run_operator_worker(object())
    assert exc.value.reason_code == "operator_registration_invalid"


def test_runner_module_never_imports_temporalio_or_constructs_a_worker():
    tree = ast.parse(_RUNNER_SRC.read_text(encoding="utf-8"))
    module_level_roots: set[str] = set()
    for node in tree.body:  # MODULE-LEVEL imports only
        if isinstance(node, ast.Import):
            module_level_roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            module_level_roots.add(node.module.split(".")[0])
    assert "temporalio" not in module_level_roots
    assert "secp_worker" not in module_level_roots  # the authoritative type is imported lazily
    text = _RUNNER_SRC.read_text(encoding="utf-8")
    assert "Worker(" not in text
    assert "run_plan_generation" not in text
    assert "asyncio" not in text


def test_no_config_or_env_bypasses_the_seal():
    text = _RUNNER_SRC.read_text(encoding="utf-8")
    assert "_OPERATOR_ACTIVATION_SEALED = True" in text
    assert "os.environ" not in text
    assert "getenv" not in text
