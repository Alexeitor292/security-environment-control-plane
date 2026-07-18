"""Automation-boundary proofs (SECP-PR5C, defects #1, #10, #9) — static + behavioral + fuzzed."""

from __future__ import annotations

import ast
import pathlib

import pytest
from _support import OPERATOR_ROOT, valid_descriptor_raw

_PKG = pathlib.Path(__file__).resolve().parents[1] / "secp_commissioning"
_SOURCE_FILES = sorted(_PKG.glob("*.py"))
_ALL_FILES = _SOURCE_FILES + sorted(pathlib.Path(__file__).resolve().parent.glob("*.py"))

_FORBIDDEN_IMPORT_ROOTS = frozenset(
    {
        "temporalio",
        "subprocess",
        "httpx",
        "requests",
        "socket",
        "http",
        "secp_worker",
        "secp_api",
        "secp_operator_deployment",
        "psycopg",
        "sqlalchemy",
    }
)
_FORBIDDEN_SUBSTRINGS = (
    "docker compose up",
    "compose up",
    "systemctl start",
    "systemctl enable",
    "podman run",
    "run_plan_generation",
    "Worker(",
)


def _imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


@pytest.mark.parametrize("path", _SOURCE_FILES, ids=lambda p: p.name)
def test_no_forbidden_imports(path):
    bad = _imports(path) & _FORBIDDEN_IMPORT_ROOTS
    assert not bad, f"{path.name} imports {sorted(bad)}"


@pytest.mark.parametrize("path", _SOURCE_FILES, ids=lambda p: p.name)
def test_no_dangerous_literal(path):
    text = path.read_text(encoding="utf-8")
    present = [s for s in _FORBIDDEN_SUBSTRINGS if s in text]
    assert not present, f"{path.name} contains {present}"


def test_no_real_endpoint_in_any_file():
    import re

    ipv4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    ok = ("192.0.2.", "198.51.100.", "203.0.113.", "127.0.0.", "0.0.0.")
    for path in _ALL_FILES:
        for m in ipv4.finditer(path.read_text(encoding="utf-8")):
            assert m.group(0).startswith(ok), f"{path.name}: {m.group(0)}"


def test_no_credential_material_in_source():
    import re

    creds = (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n[A-Za-z0-9+/=]{40,}"),
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"(?i)\bvault:secret/[a-z0-9]"),
    )
    for path in _SOURCE_FILES:
        text = path.read_text(encoding="utf-8")
        for rx in creds:
            assert not rx.search(text), path.name


def test_process_seals_unchanged_and_untouched():
    from secp_worker.plan_gen import process_boundary
    from secp_worker.provisioning import activation, process_executor

    assert process_boundary._PLAN_ONLY_PROCESS_SEALED is False
    assert activation._B1A_SUBPROCESS_SEALED is True
    assert process_executor._B1A_SUBPROCESS_SEALED is True
    for path in _SOURCE_FILES:
        text = path.read_text(encoding="utf-8")
        assert "_PLAN_ONLY_PROCESS_SEALED" not in text
        assert "_B1A_SUBPROCESS_SEALED" not in text


def test_secret_descriptor_field_never_accepted():
    from secp_commissioning.descriptor import DescriptorError, parse_descriptor

    raw = valid_descriptor_raw()
    raw["ordinary_worker"] = {**raw["ordinary_worker"], "openbao_token": "x"}
    with pytest.raises(DescriptorError):
        parse_descriptor(raw)


def test_operator_queue_can_never_equal_ordinary():
    from secp_commissioning.descriptor import DescriptorError, parse_descriptor

    with pytest.raises(DescriptorError):
        parse_descriptor(
            valid_descriptor_raw(operator_preparation={"task_queue": "secp-orchestration"})
        )


def test_every_writable_target_stays_under_operator_root_under_fuzzed_layout():
    # Fuzz the operator file basenames: every resolved write target must be strictly beneath the
    # operator root or refused; none may reach a protected / worker / etc path.
    from secp_commissioning.locations import CommissioningLocations, LocationError

    loc = CommissioningLocations()
    fuzz = [
        "entrypoint.py",
        "preparation.json",
        "../../etc/passwd",
        "a/b",
        "..",
        "/opt/secp/worker/x",
        "\x00",
        "..\\..\\x",
        "....//x",
        ".",
        "-",
        "$(whoami)",
        "x" * 200,
    ]
    for name in fuzz:
        try:
            path = loc.resolve_operator_file(name)
        except LocationError:
            continue
        assert path.startswith(OPERATOR_ROOT + "/")
        assert not path.startswith("/opt/secp/worker")
        assert not path.startswith("/etc")


def test_operator_bootstrap_and_workflow_routing_still_import():
    from secp_api.workflow_routing import resolve_operator_task_queue  # noqa: F401
    from secp_worker.operator_bootstrap import build_operator_worker_registration  # noqa: F401
