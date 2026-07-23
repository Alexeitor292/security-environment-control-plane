"""Structural guard for the API-side enrollment contract mirror (SECP-PR5H-A, ADR-027).

The mirror exists ONLY to preserve the plane boundary, so it must stay a pure contract and must not
become a second implementation of privileged management behavior.  This module proves, statically:

* the mirror does not import ``secp_management`` — the boundary is preserved, not allowlisted;
* the mirror does not import the deployment plane either;
* neither the mirror nor its first-party transitive closure imports persistence, SQLAlchemy,
  network/transport, filesystem, host-adapter, systemd, Docker/Compose, subprocess, provider/IaC,
  key-loading or signing modules;
* the mirror reads no clock, no randomness and no environment — it is deterministic by construction;
* only the TEST layer imports both planes' contracts;
* the existing management-plane boundary test still governs the mirror's directory and still refuses
  the mirror if it ever reaches across (i.e. it was not weakened to let this commit through).
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API_PKG = REPO / "apps" / "api" / "secp_api"
MIRROR = API_PKG / "worker_enrollment_contract.py"
PARITY_CORPUS = REPO / "tests" / "test_worker_enrollment_contract_parity.py"

#: Roots that first-party closure resolution may walk into.
FIRST_PARTY_ROOTS = (
    API_PKG.parent,
    REPO / "apps" / "commissioning",
)

FORBIDDEN_TOP_LEVEL = {
    # persistence
    "sqlalchemy",
    "alembic",
    "psycopg",
    "psycopg2",
    "asyncpg",
    "sqlite3",
    "redis",
    # network / transport
    "requests",
    "httpx",
    "aiohttp",
    "urllib",
    "urllib3",
    "socket",
    "ssl",
    "http",
    "httpcore",
    "fastapi",
    "starlette",
    "uvicorn",
    "websockets",
    "grpc",
    "temporalio",
    # filesystem / process / host adapters
    "subprocess",
    "shutil",
    "tempfile",
    "pathlib",
    "io",
    "os",
    "sys",
    "signal",
    "multiprocessing",
    "docker",
    "systemd",
    "pwd",
    "grp",
    "ctypes",
    "resource",
    # provider / IaC / remote
    "paramiko",
    "fabric",
    "asyncssh",
    "ansible",
    "proxmoxer",
    "boto3",
    "botocore",
    "kubernetes",
    "opentofu",
    "terraform",
    "azure",
    "google",
    # key loading / signing
    "cryptography",
    "nacl",
    "jwt",
    "jose",
    "keyring",
    # non-determinism
    "random",
    "secrets",
    "time",
    "uuid",
    "platform",
    "getpass",
    # other planes
    "secp_management",
    "secp_discovery_activation",
    "secp_worker",
    "secp_operator_deployment",
}

#: Calls that would make the mirror non-deterministic or privileged.
FORBIDDEN_CALLS = {
    "now",
    "utcnow",
    "today",
    "time",
    "monotonic",
    "open",
    "urandom",
    "getenv",
    "system",
    "run",
    "popen",
    "spawn",
    "connect",
    "read_text",
    "write_text",
    "mkdir",
    "unlink",
    "token_bytes",
    "token_hex",
    "randbytes",
    "choice",
    "shuffle",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(path: Path) -> set[str]:
    """Static AND dynamic imports (``__import__``/``importlib.import_module``), so a dynamic-import
    evasion cannot smuggle a forbidden module into the mirror."""
    names: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
        elif isinstance(node, ast.Call):
            target = node.func
            dynamic = isinstance(target, ast.Name) and target.id == "__import__"
            dynamic = dynamic or (
                isinstance(target, ast.Attribute) and target.attr == "import_module"
            )
            if dynamic and node.args and isinstance(node.args[0], ast.Constant):
                if isinstance(node.args[0].value, str):
                    names.add(node.args[0].value)
    return names


def _imports_qualified(path: Path) -> set[str]:
    """Like :func:`_imports`, but also yields ``module.name`` for ``from module import name``, so a
    submodule imported as a NAME (``from secp_api import worker_enrollment_contract``) is still
    seen — otherwise a bridge module could hide behind the from-import form."""
    names = set(_imports(path))
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.update(f"{node.module}.{alias.name}" for alias in node.names)
    return names


def _resolve(module: str) -> Path | None:
    """Locate a first-party module's file, or None if it is stdlib/third-party."""
    parts = module.split(".")
    for root in FIRST_PARTY_ROOTS:
        candidate = root.joinpath(*parts)
        if candidate.with_suffix(".py").is_file():
            return candidate.with_suffix(".py")
        if (candidate / "__init__.py").is_file():
            return candidate / "__init__.py"
    return None


def _closure(entry: Path) -> dict[Path, set[str]]:
    """Every first-party file the mirror can reach, mapped to the modules it imports."""
    seen: dict[Path, set[str]] = {}
    pending = [entry]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        imported = _imports(current)
        seen[current] = imported
        for module in imported:
            resolved = _resolve(module)
            if resolved is not None and resolved not in seen:
                pending.append(resolved)
    return seen


def test_the_mirror_exists_and_the_closure_scan_is_not_vacuous() -> None:
    assert MIRROR.is_file()
    closure = _closure(MIRROR)
    # the mirror plus the two shared pure helpers it reaches (canonical, descriptor, package inits)
    assert len(closure) >= 3, sorted(p.name for p in closure)


@pytest.mark.parametrize("path", sorted(_closure(MIRROR)), ids=lambda p: p.name)
def test_mirror_closure_imports_no_forbidden_module(path: Path) -> None:
    offending = {m for m in _imports(path) if m.split(".")[0] in FORBIDDEN_TOP_LEVEL}
    assert not offending, (
        f"{path.relative_to(REPO)} (reachable from the enrollment contract mirror) imports "
        f"{sorted(offending)}; the mirror must stay a pure contract with no persistence, network, "
        "filesystem, host-adapter, provider, signing or cross-plane capability"
    )


def test_mirror_does_not_import_the_management_or_deployment_plane() -> None:
    imported = _imports(MIRROR)
    assert not [m for m in imported if m.split(".")[0] == "secp_management"]
    assert not [m for m in imported if m.split(".")[0] == "secp_discovery_activation"]
    # it imports only pure helpers plus the stdlib it needs for parsing/hashing
    assert imported <= {
        "__future__",
        "datetime",
        "hashlib",
        "re",
        "dataclasses",
        "secp_commissioning.canonical",
        "secp_commissioning.descriptor",
    }, sorted(imported)


@pytest.mark.parametrize("path", sorted(_closure(MIRROR)), ids=lambda p: p.name)
def test_mirror_closure_reads_no_clock_randomness_or_environment(path: Path) -> None:
    offending: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Call):
            target = node.func
            name = (
                target.attr
                if isinstance(target, ast.Attribute)
                else target.id
                if isinstance(target, ast.Name)
                else None
            )
            if name in FORBIDDEN_CALLS:
                offending.add(name)
    assert not offending, (
        f"{path.relative_to(REPO)} calls {sorted(offending)}; the enrollment contract must be "
        "deterministic — timestamps and nonces are supplied by the caller, never read here"
    )


# --- participant-separation guard wiring ---------------------------------------------------------
#
# Structural backstop for the confirmed self-enrolment defect: the behavioral corpus proves the
# guard WORKS, this proves it stays WIRED.  A future transition added without the assertion is a
# silent reopening of the hole, and a behavioral corpus can only catch cases someone remembered to
# write — so the call sites are pinned here for both planes.

MGMT_CONTRACT = REPO / "apps" / "management" / "secp_management" / "enrollment.py"
SEPARATION_GUARD = "_assert_participants_separated"

#: function -> how many times the guard must be invoked inside it
GUARDED_TRANSITIONS = {
    "_advance": 1,
    "bind_worker_identity": 2,  # the PROPOSED identity and the state's own (rehydrated) pair
    "record_controller_offer": 1,
    "record_worker_result": 1,
    "mark_verified": 1,
    "mark_healthy": 1,
}
#: remediation must stay reachable for a corrupted state, so these must NOT be guarded
UNGUARDED_TERMINALS = ("refuse", "require_recovery")


#: the EXACT invocations each guarded function must make, in order.  Pinning the rendered call kills
#: a mutant that keeps the call but neuters its arguments (e.g. comparing a field against itself).
GUARD_INVOCATIONS = {
    "_advance": [f"{SEPARATION_GUARD}(state.controller_key_id, state.worker_key_id)"],
    "bind_worker_identity": [
        f"{SEPARATION_GUARD}(state.controller_key_id, worker_key_id)",
        f"{SEPARATION_GUARD}(state.controller_key_id, state.worker_key_id)",
    ],
    "record_controller_offer": [
        f"{SEPARATION_GUARD}(state.controller_key_id, state.worker_key_id)"
    ],
    "record_worker_result": [f"{SEPARATION_GUARD}(state.controller_key_id, state.worker_key_id)"],
    "mark_verified": [f"{SEPARATION_GUARD}(state.controller_key_id, state.worker_key_id)"],
    "mark_healthy": [f"{SEPARATION_GUARD}(state.controller_key_id, state.worker_key_id)"],
}


def _function(path: Path, function: str) -> ast.FunctionDef:
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.FunctionDef) and node.name == function:
            return node
    raise AssertionError(f"{path.name} has no function named {function!r}")


def _guard_calls(path: Path, function: str) -> int:
    return sum(
        1
        for inner in ast.walk(_function(path, function))
        if isinstance(inner, ast.Call)
        and isinstance(inner.func, ast.Name)
        and inner.func.id == SEPARATION_GUARD
    )


def _is_guard_stmt(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Expr)
        and isinstance(stmt.value, ast.Call)
        and isinstance(stmt.value.func, ast.Name)
        and stmt.value.func.id == SEPARATION_GUARD
    )


def _has_early_return(stmt: ast.stmt) -> bool:
    """An ``if ...: return`` branch — the idempotent-retry escape hatch that skips ``_advance``."""
    return isinstance(stmt, ast.If) and any(
        isinstance(inner, ast.Return) for inner in ast.walk(stmt)
    )


@pytest.mark.parametrize("plane", [MIRROR, MGMT_CONTRACT], ids=lambda p: p.parent.name)
@pytest.mark.parametrize(("function", "expected"), sorted(GUARDED_TRANSITIONS.items()))
def test_participant_separation_guard_is_wired(plane: Path, function: str, expected: int) -> None:
    assert _guard_calls(plane, function) == expected, (
        f"{plane.relative_to(REPO)}::{function} must invoke {SEPARATION_GUARD} {expected}x — the "
        "controller and the worker must never be the same signer, on any path"
    )


@pytest.mark.parametrize("plane", [MIRROR, MGMT_CONTRACT], ids=lambda p: p.parent.name)
@pytest.mark.parametrize(("function", "expected"), sorted(GUARD_INVOCATIONS.items()))
def test_participant_separation_guard_arguments_are_exact(
    plane: Path, function: str, expected: list[str]
) -> None:
    """Counting calls is not enough — a call that compares a field against itself would still count.
    The rendered invocations are pinned, in order."""
    rendered = [
        ast.unparse(stmt.value)
        for stmt in ast.walk(_function(plane, function))
        if isinstance(stmt, ast.Expr) and _is_guard_stmt(stmt)
    ]
    assert rendered == expected, f"{plane.relative_to(REPO)}::{function}: {rendered} != {expected}"


@pytest.mark.parametrize("plane", [MIRROR, MGMT_CONTRACT], ids=lambda p: p.parent.name)
@pytest.mark.parametrize("function", sorted(GUARDED_TRANSITIONS))
def test_participant_separation_guard_precedes_every_early_return(
    plane: Path, function: str
) -> None:
    """Placement, not just presence.

    Each of these functions has (or may gain) an ``if ...: return`` idempotent-retry branch that
    escapes before ``_advance`` is reached.  A guard sitting AFTER that branch is dead on exactly
    the path it protects: a corrupted same-key row would keep being re-affirmed as healthy while
    every call reported success.  Counting calls cannot see this — moving the call keeps the count —
    so the ordering is pinned here, and the behavioural corpus exercises the same path directly.
    """
    body = _function(plane, function).body
    guards = [i for i, stmt in enumerate(body) if _is_guard_stmt(stmt)]
    assert guards, f"{plane.relative_to(REPO)}::{function} has no top-level {SEPARATION_GUARD} call"
    returns = [i for i, stmt in enumerate(body) if _has_early_return(stmt)]
    if returns:
        assert max(guards) < min(returns), (
            f"{plane.relative_to(REPO)}::{function}: {SEPARATION_GUARD} must be invoked BEFORE the "
            f"early-return branch at statement {min(returns)} (guards at {guards}) — otherwise a "
            "same-key state is waved through on the idempotent-retry path"
        )


@pytest.mark.parametrize("plane", [MIRROR, MGMT_CONTRACT], ids=lambda p: p.parent.name)
@pytest.mark.parametrize("function", UNGUARDED_TERMINALS)
def test_remediation_paths_are_not_guarded(plane: Path, function: str) -> None:
    assert _guard_calls(plane, function) == 0, (
        f"{plane.relative_to(REPO)}::{function} must NOT be separation-guarded — a corrupted "
        "enrollment has to stay movable to a terminal so an operator can remediate it"
    )


@pytest.mark.parametrize("plane", [MIRROR, MGMT_CONTRACT], ids=lambda p: p.parent.name)
def test_participant_separation_guard_refuses_with_the_existing_bounded_code(plane: Path) -> None:
    """One helper per plane, refusing with the EXISTING code — a dedicated code would tell a prober
    exactly which of the two identity checks it tripped."""
    definitions = [
        node
        for node in ast.walk(_tree(plane))
        if isinstance(node, ast.FunctionDef) and node.name == SEPARATION_GUARD
    ]
    assert len(definitions) == 1, f"{plane.name}: expected exactly one {SEPARATION_GUARD}"
    codes = {
        arg.value
        for node in ast.walk(definitions[0])
        if isinstance(node, ast.Call)
        for arg in node.args
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
    }
    assert codes == {"enrollment_worker_mismatch"}, codes


def test_only_the_test_layer_imports_both_planes() -> None:
    """A production module importing both contracts would mean the mirror had become a bridge."""
    both: list[Path] = []
    for root in (REPO / "apps", REPO / "plugins"):
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts or "tests" in path.parts:
                continue
            imported = _imports_qualified(path)
            has_mgmt = any(m.startswith("secp_management") for m in imported)
            has_api = any("worker_enrollment_contract" in m for m in imported)
            if has_mgmt and has_api:
                both.append(path)
    assert not both, [str(p.relative_to(REPO)) for p in both]
    # ...and the parity corpus, which legitimately imports both, is a test module
    assert PARITY_CORPUS.is_file()
    corpus_imports = _imports_qualified(PARITY_CORPUS)
    assert "secp_management.enrollment" in corpus_imports
    assert any("worker_enrollment_contract" in m for m in corpus_imports)


def test_existing_management_boundary_test_still_governs_the_mirror() -> None:
    """The boundary was preserved, not weakened: the reviewed guard still covers the mirror's
    directory and still refuses a hypothetical mirror that reached across the plane."""
    sys.path.insert(0, str(REPO / "tests"))
    import test_management_plane_boundary as boundary

    assert API_PKG in boundary.LOWER_PLANE_ROOTS
    assert MIRROR in boundary._py_files(API_PKG)
    # no allowlist parameter exists on the guard — it takes a path and nothing else
    signature = boundary.test_lower_plane_cannot_import_bootstrap_write_adapters.__code__
    assert signature.co_varnames[: signature.co_argcount] == ("path",)
    # the guard passes for the mirror as written...
    boundary.test_lower_plane_cannot_import_bootstrap_write_adapters(MIRROR)
    # ...and would have FAILED had the mirror imported the management contract instead of mirroring
    assert "secp_management.enrollment" in boundary._imports(PARITY_CORPUS)
    with pytest.raises(AssertionError):
        boundary.test_lower_plane_cannot_import_bootstrap_write_adapters(PARITY_CORPUS)
