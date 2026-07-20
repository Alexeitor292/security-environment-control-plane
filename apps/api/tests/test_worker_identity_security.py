"""SECP-B2-4.3 — static/architecture guardrails for worker-identity (secret-free, sealed).

Proves: the API/web cannot import the worker-only attestation source or the registered verifier; the
durable schema + migration store no certificate/key/CSR/CA/endpoint/secret; the shared contract
version matches across API + worker (no drift); the shipped worker runtime remains deny-by-default
(the registered verifier + attestation source are NOT wired into the consumer/orchestration);
the worker attestation module adds no network/subprocess/OpenBao/Proxmox/CA/certificate code and no
persistence; and no real infrastructure/secret value is committed in changed non-test files.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
API_PKG = REPO_ROOT / "apps" / "api" / "secp_api"
WEB_SRC = REPO_ROOT / "apps" / "web" / "src"
PREFLIGHT = REPO_ROOT / "apps" / "worker" / "secp_worker" / "preflight"
ATTESTATION = PREFLIGHT / "worker_identity_attestation.py"


def _py(pkg: Path) -> list[Path]:
    return [p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts]


# The API must never import the worker-only attestation/verifier internals.
_API_FORBIDDEN_IMPORT_PREFIXES = ("secp_plugin_proxmox", "secp_worker.preflight")
_API_FORBIDDEN_SYMBOLS = frozenset(
    {
        "RegisteredWorkerIdentityVerifier",
        "WorkerIdentityAttestationSource",
        "SealedWorkerIdentityAttestationSource",
        "WorkerIdentityClaim",
        "WorkerIdentityVerificationRefused",
        "WorkerIdentityAttestationUnavailable",
    }
)


def test_api_cannot_import_worker_identity_verifier_or_attestation():
    for path in _py(API_PKG):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert not module.startswith(_API_FORBIDDEN_IMPORT_PREFIXES), (
                    f"{path.name} imports from {module}"
                )
                for alias in node.names:
                    assert alias.name not in _API_FORBIDDEN_SYMBOLS, (
                        f"{path.name} imports {alias.name}"
                    )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(_API_FORBIDDEN_IMPORT_PREFIXES), (
                        f"{path.name} imports {alias.name}"
                    )


def test_frontend_has_no_worker_identity_verifier_or_secret_field():
    # PR5F permits exactly one non-secret boolean proving the operator reviewed the published
    # admission-anchor fingerprint. It still exposes no verifier, attestation, raw verification
    # anchor, generic identity lifecycle route, or secret-entry field. Generic words like
    # "certificate" appear in existing benign prose and are not scanned.
    forbidden = (
        'type="password"',
        "type='password'",
        "RegisteredWorkerIdentityVerifier",
        "WorkerIdentityAttestation",
        "verification_anchor",
        "workload_identity",
        "worker-identity/registrations",
    )
    scanned = 0
    for path in list(WEB_SRC.rglob("*.ts")) + list(WEB_SRC.rglob("*.tsx")):
        if ".mypy_cache" in path.parts or "node_modules" in path.parts:
            continue
        scanned += 1
        src = path.read_text(encoding="utf-8")
        # Narrow reviewed exception: a literal-true confirmation only. Removing its exact field
        # name must leave no other verification-anchor surface anywhere in frontend source.
        src = src.replace("verification_anchor_review_confirmed", "")
        for token in forbidden:
            assert token not in src, f"frontend {path.name} references `{token}`"
    assert scanned >= 5


def test_registration_schema_has_no_secret_or_backend_columns():
    from secp_api.models import WorkerIdentityEvidence, WorkerIdentityRegistration

    cols = set(WorkerIdentityRegistration.__table__.columns.keys()) | set(
        WorkerIdentityEvidence.__table__.columns.keys()
    )
    forbidden = {
        "certificate",
        "cert",
        "cert_pem",
        "private_key",
        "key",
        "public_key",
        "csr",
        "ca",
        "ca_name",
        "secret",
        "secret_ref",
        "credential",
        "token",
        "endpoint",
        "base_url",
        "url",
        "host",
        "hostname",
        "port",
        "anchor",
        "anchor_material",
        "policy",
    }
    assert not (cols & forbidden), (
        f"worker-identity schema exposes forbidden column(s): {cols & forbidden}"
    )


def test_migration_ddl_is_secret_free():
    migration = (
        REPO_ROOT / "apps/api/migrations/versions/e7a2c9b4f1d8_worker_identity_registration.py"
    )
    ddl = migration.read_text(encoding="utf-8").lower()
    for token in (
        "certificate",
        "private_key",
        " csr",
        " ca ",
        "secret",
        "credential",
        "endpoint",
        "base_url",
        "token",
        "hostname",
        "public_key",
        "anchor_material",
    ):
        assert token not in ddl, f"migration references `{token.strip()}`"
    # The immutable anchor field stores only a FINGERPRINT (a hash), never anchor material.
    assert "verification_anchor_fingerprint" in ddl


def test_contract_version_parity_between_api_and_worker():
    from secp_api.worker_identity_contract import (
        WORKER_IDENTITY_CONTRACT_VERSION as api_version,
    )
    from secp_worker.preflight.worker_identity_attestation import (
        WORKER_IDENTITY_CONTRACT_VERSION as worker_version,
    )

    assert api_version == worker_version


def test_verification_anchor_fingerprint_is_deterministic_and_hashed():
    from secp_api.worker_identity_contract import compute_verification_anchor_fingerprint

    a = compute_verification_anchor_fingerprint("public-anchor-v1")
    b = compute_verification_anchor_fingerprint("public-anchor-v1")
    c = compute_verification_anchor_fingerprint("public-anchor-v2")
    assert a == b and a != c
    assert a.startswith("sha256:") and len(a) == len("sha256:") + 64
    # The fingerprint never reveals the anchor value.
    assert "public-anchor-v1" not in a


def test_shipped_worker_runtime_remains_deny_by_default():
    # The consumer/orchestration/runtime must NOT construct the registered verifier or the
    # attestation source: the shipped default identity verifier remains the denying one.
    for name in ("consumer.py", "orchestration.py", "runtime.py"):
        src = (PREFLIGHT / name).read_text(encoding="utf-8")
        assert "RegisteredWorkerIdentityVerifier" not in src, (
            f"{name} must not wire the registered worker-identity verifier"
        )
        assert "worker_identity_attestation" not in src, (
            f"{name} must not import the attestation seam"
        )
    orch = (PREFLIGHT / "orchestration.py").read_text(encoding="utf-8")
    assert "identity_verifier or DenyingWorkerIdentityVerifier()" in orch


def test_attestation_module_has_no_network_cert_or_subprocess_code():
    forbidden = (
        "import httpx",
        "from httpx",
        "import requests",
        "import aiohttp",
        "import socket",
        "from socket",
        "import subprocess",
        "from subprocess",
        "import ssl",
        "import hvac",
        "openbao",
        "cryptography",
        "OpenSSL",
        "paramiko",
        "os.environ",
        "os.getenv",
        "getpass",
        "open(",
        "subprocess",
        "secp_plugin_proxmox",
        "load_pem",
        "x509",
        "sign(",
        "private_key",
    )
    src = ATTESTATION.read_text(encoding="utf-8")
    for token in forbidden:
        assert token not in src, f"attestation module must not reference `{token}`"


def test_attestation_and_contract_define_no_orm_or_persistence():
    forbidden = ("mapped_column", "Column(", "Table(", "declarative_base", "__tablename__")
    for path in (ATTESTATION, API_PKG / "worker_identity_contract.py"):
        src = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{path.name} must not define persistence (`{token}`)"


def test_no_concrete_infrastructure_values_in_new_sources():
    import re

    new_sources = [
        API_PKG / "worker_identity_contract.py",
        API_PKG / "schemas_worker_identity.py",
        API_PKG / "services" / "worker_identity.py",
        API_PKG / "routers" / "worker_identity.py",
        ATTESTATION,
        REPO_ROOT / "apps/api/migrations/versions/e7a2c9b4f1d8_worker_identity_registration.py",
    ]
    forbidden = re.compile(
        r"(?:\d{1,3}\.){3}\d{1,3}"  # IPv4
        r"|https?://[a-z0-9]"  # URL with host
        r"|:\d{4,5}\b"  # port
        r"|PVEAPIToken|@pam|@pve|-----BEGIN|vault:[a-z]",
        re.IGNORECASE,
    )
    for path in new_sources:
        text = path.read_text(encoding="utf-8")
        m = forbidden.search(text)
        assert m is None, f"{path.name} contains a concrete value: {m.group(0)!r}"
