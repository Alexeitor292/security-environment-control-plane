"""SECP-B2-4.1 — static/architecture guardrails for resolver-activation (secret-free, sealed).

Proves: the API cannot import/invoke the worker-only activation-capability verifier or the resolver/
Proves: the API cannot import/invoke the worker-only activation-capability verifier or the
durable schema stores no secret/reference/endpoint; the shipped worker defaults still stop before
lease acquisition; and the API-bound contract-version + operation-fingerprint match the worker's
(no drift).
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
API_PKG = REPO_ROOT / "apps" / "api" / "secp_api"
WEB_SRC = REPO_ROOT / "apps" / "web" / "src"


def _py(pkg: Path) -> list[Path]:
    return [p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts]


# The API must never import worker-only resolution/activation/identity/backend internals.
_API_FORBIDDEN_IMPORT_PREFIXES = (
    "secp_plugin_proxmox",
    "secp_worker.preflight",
)
_API_FORBIDDEN_SYMBOLS = frozenset(
    {
        "load_and_verify_activation_capability",
        "ResolverActivationCapability",
        "ActivationAuthorizationRefused",
        "OpenBaoWorkerSecretResolver",
        "OpenBaoHttpClient",
        "DbAuthoritativeReverifier",
        "SealedActivationGate",
        "DenyingWorkerIdentityVerifier",
    }
)


def test_api_cannot_import_worker_activation_or_resolver_code():
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


def test_resolver_activation_schema_has_no_secret_reference_or_endpoint_storage():
    from secp_api.models import ResolverActivationAuthorization, ResolverActivationEvidence

    cols = set(ResolverActivationAuthorization.__table__.columns.keys()) | set(
        ResolverActivationEvidence.__table__.columns.keys()
    )
    forbidden = {
        "secret",
        "secret_ref",
        "credential",
        "credential_ref",
        "token",
        "endpoint",
        "base_url",
        "url",
        "host",
        "port",
        "vault",
        "vault_path",
        "mount",
        "unseal",
        "policy",
        "backend_config",
        "worker_identity",
        "reference",
    }
    assert not (cols & forbidden), (
        f"resolver-activation schema exposes forbidden columns: {cols & forbidden}"
    )


def test_migration_ddl_is_secret_free():
    mig = (
        (
            REPO_ROOT
            / "apps/api/migrations/versions/d1f4a8b6c3e2_resolver_activation_authorization.py"
        )
        .read_text(encoding="utf-8")
        .lower()
    )
    for token in (
        "secret",
        "credential",
        "endpoint",
        "base_url",
        "token",
        "vault",
        "unseal",
        "openbao",
        "mount",
        "policy",
    ):
        assert token not in mig, f"migration references `{token}`"


def test_contract_version_and_fingerprint_do_not_drift_from_the_worker():
    from secp_api.resolver_activation_contract import (
        RESOLVER_ADAPTER_CONTRACT_VERSION as api_version,
    )
    from secp_api.resolver_activation_contract import (
        compute_operation_fingerprint as api_fp,
    )
    from secp_worker.preflight.backends.openbao_resolver import (
        RESOLVER_ADAPTER_CONTRACT_VERSION as worker_version,
    )
    from secp_worker.preflight.fingerprint import compute_operation_fingerprint as worker_fp

    assert api_version == worker_version

    class _PF:
        id = "11111111-1111-1111-1111-111111111111"
        organization_id = "22222222-2222-2222-2222-222222222222"
        execution_target_id = "33333333-3333-3333-3333-333333333333"
        onboarding_id = "44444444-4444-4444-4444-444444444444"
        live_read_authorization_id = "55555555-5555-5555-5555-555555555555"
        authorization_version = 3

    assert api_fp(_PF()) == worker_fp(_PF())


def test_shipped_worker_defaults_still_stop_before_lease_acquisition():
    # The shipped consumer default resolver is still the sealed resolver; the orchestration defaults
    # to the denying identity + sealed gate BEFORE lease acquisition. This PR wires nothing new into
    # the shipped resolution path.
    consumer = (REPO_ROOT / "apps/worker/secp_worker/preflight/consumer.py").read_text(
        encoding="utf-8"
    )
    assert "SealedSecretResolver()" in consumer
    orch = (REPO_ROOT / "apps/worker/secp_worker/preflight/orchestration.py").read_text(
        encoding="utf-8"
    )
    assert "identity_verifier or DenyingWorkerIdentityVerifier()" in orch
    assert "activation_gate or SealedActivationGate()" in orch
    # The activation-capability verifier is NOT wired into the orchestration/consumer default path.
    for name in ("orchestration.py", "consumer.py"):
        src = (REPO_ROOT / "apps/worker/secp_worker/preflight" / name).read_text(encoding="utf-8")
        assert "load_and_verify_activation_capability" not in src, (
            f"{name} must not wire the activation verifier into shipped runtime"
        )


def test_frontend_has_no_secret_backend_or_activation_toggle_field():
    forbidden = (
        'type="password"',
        "type='password'",
        "vault_path",
        "backend_endpoint",
        "backend_url",
        "worker_credential",
        "unseal",
        "activateResolver",
        "enableResolver",
        "/secrets",
        "readSecret",
    )
    scanned = 0
    for path in list(WEB_SRC.rglob("*.ts")) + list(WEB_SRC.rglob("*.tsx")):
        if ".mypy_cache" in path.parts or "node_modules" in path.parts:
            continue
        scanned += 1
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"frontend {path.name} references `{token}`"
    assert scanned >= 5


def test_frontend_states_the_sealed_until_evidence_wording():
    src = (WEB_SRC / "pages" / "resolver-activation.ts").read_text(encoding="utf-8").lower()
    assert "resolver activation remains sealed until separate staging trust" in src
    assert "worker-side activation" in src
