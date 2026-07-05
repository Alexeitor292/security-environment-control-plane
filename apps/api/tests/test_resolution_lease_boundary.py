"""SECP-B2-3 — static safety guardrails for the durable lease + sealed identity/activation gate.

Proves: the durable schema stores no secret/reference/endpoint; the API cannot import the
worker-only lease/identity/gate internals; production worker code selects ONLY the sealed
deny-by-default identity and disabled activation gate (no approved/static impl or SecretMaterial
construction in production); the lease/identity/gate modules add no backend/network/subprocess/env
client; and the frontend exposes no lease/activation/credential interface.
"""

from __future__ import annotations

import ast
import os
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
API_PKG = REPO_ROOT / "apps" / "api" / "secp_api"
WORKER_PKG = REPO_ROOT / "apps" / "worker" / "secp_worker"
PREFLIGHT_PKG = WORKER_PKG / "preflight"
MIGRATION = (
    REPO_ROOT / "apps" / "api" / "migrations" / "versions" / "c4e9a1f7d2b3_resolution_lease.py"
)


def _py(pkg: Path) -> list[Path]:
    return [p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts]


def test_lease_schema_has_no_secret_reference_or_endpoint_storage():
    from secp_api.models import ResolutionLease

    cols = set(ResolutionLease.__table__.columns.keys())
    forbidden = {
        "secret",
        "secret_ref",
        "secret_reference",
        "credential",
        "credential_ref",
        "credential_reference",
        "token",
        "endpoint",
        "base_url",
        "url",
        "host",
        "certificate",
        "config",
        "reference_hash",
        "secret_hash",
    }
    assert not (cols & forbidden), f"lease model exposes forbidden column(s): {cols & forbidden}"
    # The migration DDL must likewise never mention a secret/reference/endpoint value.
    ddl = MIGRATION.read_text(encoding="utf-8").lower()
    for token in ("secret", "credential", "endpoint", "base_url", "token", "certificate"):
        assert token not in ddl, f"migration references `{token}`"


def test_migration_columns_match_the_safe_model_shape():
    from secp_api.models import ResolutionLease

    ddl = MIGRATION.read_text(encoding="utf-8")
    # Every column defined in the model must appear in the migration by name (secret-free set).
    for col in ResolutionLease.__table__.columns.keys():
        assert f'"{col}"' in ddl, f"migration missing column {col!r}"


def test_migration_upgrade_downgrade_roundtrip_sqlite():
    """Derive revisions from the migration graph (no fragile relative offsets): head is the lease
    migration; one step down removes resolution_lease and keeps readonly_staging_preflight; the
    step below removes readonly_staging_preflight; upgrade restores both."""
    from alembic import command
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from secp_api.config import get_settings
    from sqlalchemy import create_engine, inspect

    api_dir = REPO_ROOT / "apps" / "api"
    db = os.path.join(tempfile.gettempdir(), f"secp_lease_mig_{os.getpid()}.db")
    if os.path.exists(db):
        os.remove(db)
    url = f"sqlite+pysqlite:///{db}"
    prev = os.environ.get("SECP_DATABASE_URL")
    os.environ["SECP_DATABASE_URL"] = url
    # alembic's env.py resolves the URL via the cached get_settings(); clear it so the migration
    # runs against THIS temp DB (not a URL cached by an earlier test in the suite).
    get_settings.cache_clear()
    try:
        cfg = Config(str(api_dir / "alembic.ini"))
        cfg.set_main_option("script_location", str(api_dir / "migrations"))
        cfg.set_main_option("sqlalchemy.url", url)
        script = ScriptDirectory.from_config(cfg)
        # Derive the revision that CREATES readonly_staging_preflight (robust to migrations added
        # above it, e.g. the lease + resolver-activation migrations). Downgrading to it removes
        # everything above (incl. resolution_lease) while keeping readonly_staging_preflight.
        import re

        preflight_rev = None
        for rev in script.walk_revisions():
            src = Path(rev.module.__file__).read_text(encoding="utf-8")
            if re.search(r'create_table\(\s*"readonly_staging_preflight"', src):
                preflight_rev = rev.revision
                break
        assert isinstance(preflight_rev, str)
        preflight_parent = script.get_revision(preflight_rev).down_revision
        assert isinstance(preflight_parent, str)

        command.upgrade(cfg, "head")
        eng = create_engine(url)

        def tables() -> set[str]:
            return set(inspect(eng).get_table_names())

        assert {"resolution_lease", "readonly_staging_preflight"} <= tables()
        command.downgrade(cfg, preflight_rev)
        assert "resolution_lease" not in tables()
        assert "readonly_staging_preflight" in tables()
        command.downgrade(cfg, preflight_parent)
        assert "readonly_staging_preflight" not in tables()
        command.upgrade(cfg, "head")
        assert {"resolution_lease", "readonly_staging_preflight"} <= tables()
        eng.dispose()
    finally:
        if prev is None:
            os.environ.pop("SECP_DATABASE_URL", None)
        else:
            os.environ["SECP_DATABASE_URL"] = prev
        get_settings.cache_clear()
        if os.path.exists(db):
            os.remove(db)


def test_api_cannot_import_worker_lease_identity_or_gate():
    forbidden_prefixes = (
        "secp_worker.preflight.lease",
        "secp_worker.preflight.identity",
        "secp_worker.preflight.activation_gate",
    )
    for path in _py(API_PKG):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                assert not mod.startswith(forbidden_prefixes), f"{path.name} imports from {mod}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(forbidden_prefixes), (
                        f"{path.name} imports {alias.name}"
                    )


def _call_name(node: ast.Call) -> str:
    fn = node.func
    return fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")


def _worker_identity_calls(tree: ast.AST) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _call_name(node) == "WorkerIdentity"
    ]


def _blessed_return_call_ids(tree: ast.AST) -> set[int]:
    """ids of ``WorkerIdentity(...)`` calls that are the value of a ``return`` inside
    ``RegisteredWorkerIdentityVerifier._verify_claim`` — the sole reviewed success path."""
    blessed: set[int] = set()
    for cls in ast.walk(tree):
        if not (isinstance(cls, ast.ClassDef) and cls.name == "RegisteredWorkerIdentityVerifier"):
            continue
        for method in ast.walk(cls):
            if not (isinstance(method, ast.FunctionDef) and method.name == "_verify_claim"):
                continue
            for node in ast.walk(method):
                if (
                    isinstance(node, ast.Return)
                    and isinstance(node.value, ast.Call)
                    and _call_name(node.value) == "WorkerIdentity"
                ):
                    blessed.add(id(node.value))
    return blessed


def _check_worker_identity_construction(filename: str, source: str) -> int:
    """Structural guard: a ``WorkerIdentity(...)`` construction is permitted ONLY in
    ``worker_identity_attestation.py`` and ONLY as the value returned from the reviewed
    ``RegisteredWorkerIdentityVerifier._verify_claim`` success path. Any construction elsewhere — in
    another worker module, or unconditional/extra/non-return construction in the attestation
    module — raises ``AssertionError``. Returns the number of (blessed) constructions in source."""
    tree = ast.parse(source, filename=filename)
    calls = _worker_identity_calls(tree)
    if not calls:
        return 0
    assert filename == "worker_identity_attestation.py", (
        f"{filename} constructs a WorkerIdentity outside the reviewed verifier module"
    )
    blessed = _blessed_return_call_ids(tree)
    for call in calls:
        assert id(call) in blessed, (
            f"{filename} constructs a WorkerIdentity outside the reviewed "
            "RegisteredWorkerIdentityVerifier._verify_claim success return path"
        )
    return len(calls)


def test_production_worker_only_constructs_identity_in_the_reviewed_verifier_return():
    # The shipped default identity verifier denies and constructs nothing. Across the whole worker
    # package there must be EXACTLY ONE ``WorkerIdentity(...)`` construction, and it must be the
    # value returned from ``RegisteredWorkerIdentityVerifier._verify_claim`` after all durable
    # checks pass (that verifier is not wired into shipped runtime — a separate guard asserts that).
    total = 0
    for path in _py(WORKER_PKG):
        total += _check_worker_identity_construction(path.name, path.read_text(encoding="utf-8"))
    assert total == 1, f"expected exactly one reviewed WorkerIdentity construction, found {total}"


def test_worker_identity_construction_guard_rejects_unsafe_additions():
    # The guard passes on the real, reviewed source...
    attest = (PREFLIGHT_PKG / "worker_identity_attestation.py").read_text(encoding="utf-8")
    assert _check_worker_identity_construction("worker_identity_attestation.py", attest) == 1
    # ...but rejects an EXTRA construction added in an unrelated function of the attestation module,
    poisoned_helper = (
        attest
        + "\n\ndef _forged_identity():\n    return WorkerIdentity(worker_identity_id='forged')\n"
    )
    with pytest.raises(AssertionError):
        _check_worker_identity_construction("worker_identity_attestation.py", poisoned_helper)
    # ...an UNCONDITIONAL module-level construction,
    poisoned_module = attest + "\n_FORGED = WorkerIdentity(worker_identity_id='forged')\n"
    with pytest.raises(AssertionError):
        _check_worker_identity_construction("worker_identity_attestation.py", poisoned_module)
    # ...and ANY construction in a different worker module.
    other_module = (
        "from secp_worker.preflight.identity import WorkerIdentity\n"
        "def sneak():\n    return WorkerIdentity(worker_identity_id='forged')\n"
    )
    with pytest.raises(AssertionError):
        _check_worker_identity_construction("consumer.py", other_module)


def test_orchestration_defaults_to_sealed_identity_and_disabled_gate():
    src = (PREFLIGHT_PKG / "orchestration.py").read_text(encoding="utf-8")
    assert "identity_verifier or DenyingWorkerIdentityVerifier()" in src
    assert "activation_gate or SealedActivationGate()" in src
    # The shipped gate always raises; there is no approving gate in the production package.
    gate_src = (PREFLIGHT_PKG / "activation_gate.py").read_text(encoding="utf-8")
    assert "raise ResolutionActivationDisabled" in gate_src
    identity_src = (PREFLIGHT_PKG / "identity.py").read_text(encoding="utf-8")
    assert "raise WorkerIdentityUnavailable" in identity_src


def test_lease_identity_gate_modules_add_no_backend_or_network_client():
    forbidden = (
        "hvac",
        "openbao",
        "import vault",
        "from vault",
        "boto3",
        "botocore",
        "azure",
        "googleapiclient",
        "keyring",
        "getpass",
        "import httpx",
        "import requests",
        "import aiohttp",
        "import socket",
        "from socket",
        "import subprocess",
        "from subprocess",
        "import ssl",
        "os.environ",
        "os.getenv",
        "pathlib",
        "open(",
    )
    for name in ("lease.py", "identity.py", "activation_gate.py"):
        src = (PREFLIGHT_PKG / name).read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{name} must not reference `{token}`"


def test_frontend_has_no_lease_or_activation_interface():
    web_src = REPO_ROOT / "apps" / "web" / "src"
    forbidden = (
        "resolution_lease",
        "resolutionLease",
        "activation-gate",
        "activationGate",
        "acquireLease",
        "beginAttempt",
        "worker_identity",
        'type="password"',
        "type='password'",
    )
    scanned = 0
    for path in list(web_src.rglob("*.ts")) + list(web_src.rglob("*.tsx")):
        if ".mypy_cache" in path.parts or "node_modules" in path.parts:
            continue
        scanned += 1
        src = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"frontend {path.name} references `{token}`"
    assert scanned >= 5
