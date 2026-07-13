"""Architecture/boundary lock for the read-only eligibility preflight (SECP-002B-1B, B1B-PR3).

Proves the eligibility path cannot run OpenTofu, execute a subprocess, mutate infrastructure, or
construct a real provisioning/toolchain/activation seam; that both B1-A subprocess seals remain
``True``; that the worker seam is sealed by default; and that Path B (the dormant HTTP collector)
gains no new production caller and stays disabled by default.
"""

from __future__ import annotations

import ast
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_API = _REPO / "api" / "secp_api"
_WORKER = _REPO / "worker" / "secp_worker"

# New/extended source files this PR introduces (the eligibility path).
_PR3_SOURCES = (
    _WORKER / "onboarding" / "eligibility_preflight.py",
    _WORKER / "onboarding" / "eligibility_recorder.py",
    _API / "eligibility_policy.py",
    _API / "services" / "eligibility.py",
    _API / "target_evidence.py",
)

# Import *module* substrings the eligibility path must never pull in. Prose/docstrings are ignored
# because these are matched against parsed import statements only.
_FORBIDDEN_IMPORT_SUBSTRINGS = (
    "opentofu",
    "process_executor",
    "mutation_transport",
    "provisioning.activation",
    "toolchain_verify",
    "deployment.engine",
    "deployment.runtime",
    "paramiko",
    "asyncssh",
)

# Raw-text tokens that would indicate real process / mutation capability.
_FORBIDDEN_TOKENS = (
    "import subprocess",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "os.system(",
    "os.popen(",
    "run_real_provisioning",
    "RealToolchainVerifier",
    "grant_real_lab_activation",
    "RealLabActivationGrant",
    "SubprocessProcessExecutor",
)


def _imported_modules(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    return modules


def test_eligibility_path_imports_no_opentofu_process_or_mutation():
    for path in _PR3_SOURCES:
        for module in _imported_modules(path):
            for forbidden in _FORBIDDEN_IMPORT_SUBSTRINGS:
                assert forbidden not in module, f"{path.name} imports forbidden module {module!r}"


def test_eligibility_path_has_no_process_or_mutation_tokens():
    for path in _PR3_SOURCES:
        text = path.read_text(encoding="utf-8")
        for token in _FORBIDDEN_TOKENS:
            assert token not in text, f"{path.name} contains forbidden token {token!r}"


def test_both_b1a_subprocess_seals_remain_true():
    from secp_worker.provisioning import activation, process_executor

    assert process_executor._B1A_SUBPROCESS_SEALED is True
    assert activation._B1A_SUBPROCESS_SEALED is True


def test_worker_eligibility_seam_is_sealed_by_default():
    from secp_worker.onboarding.eligibility_preflight import sealed_eligibility_composition

    comp = sealed_eligibility_composition()
    assert comp.gate.enabled is False
    assert comp.live_read_gate.enabled is False
    assert comp.secret_resolver is None
    assert comp.transport_factory is None
    assert comp.collector is None
    assert comp.authorization_verifier is None


def test_path_b_gains_no_new_production_caller():
    """The only worker source that calls ``run_live_readonly_collection`` is the sealed eligibility
    seam (and tests). No runtime loop / consumer / dispatcher gains a new caller."""
    callers = []
    for path in _WORKER.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if "run_live_readonly_collection(" in text:
            callers.append(path.name)
    assert set(callers) <= {"eligibility_preflight.py", "live_readonly.py"}, callers


def test_live_read_collection_gate_is_disabled_by_default():
    from secp_worker.onboarding.live_readonly import LiveReadCollectionGate

    assert LiveReadCollectionGate().enabled is False
