"""Cross-cutting OIDC-C security-boundary guardrails (ADR-019).

Static + behavioral proofs that the production deployment guardrails hold: no production client
secret / Keycloak bundle / default credentials, no wildcard or credentialed CORS, no wildcard Host,
no HTTP or localhost production origin, the preflight obtains no token and mutates no DB/audit and
imports no worker/provider code, liveness/startup never contact the IdP, no dev fallback /
provisioning activation in production, and the docs/reference artifacts never claim the platform is
production-ready or unseal infrastructure.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError
from secp_api.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[3]
PROD_ENV = REPO_ROOT / "infra" / "production" / "oidc.env.example"
PROD_README = REPO_ROOT / "infra" / "production" / "README.md"
PREFLIGHT_SRC = REPO_ROOT / "apps" / "api" / "secp_api" / "oidc_preflight.py"
MAIN_SRC = REPO_ROOT / "apps" / "api" / "secp_api" / "main.py"
README = REPO_ROOT / "README.md"
STATUS = REPO_ROOT / "docs" / "STATUS.md"

_PROD = dict(
    app_env="production",
    auth_dev_mode=False,
    workflow_dispatch_mode="temporal",
    oidc_issuer="https://idp.example.test/realms/secp",
    oidc_audience="secp-api",
    oidc_web_client_id="secp-web",
    public_origin="https://secp.example.test",
    cors_allow_origins=[],
)


def _prod(**overrides) -> Settings:
    return Settings(**{**_PROD, **overrides})


# --- production Settings guardrails --------------------------------------------------------------


def test_no_wildcard_or_credentialed_cors_in_production():
    # Production requires empty CORS (no wildcard, no origin at all).
    assert _prod().cors_allow_origins == []
    with pytest.raises(ValidationError):
        _prod(cors_allow_origins=["*"])
    with pytest.raises(ValidationError):
        _prod(cors_allow_origins=["https://secp.example.test"])
    # The app never configures credentialed / wildcard CORS.
    main_src = MAIN_SRC.read_text(encoding="utf-8")
    assert "allow_credentials=True" not in main_src
    assert 'allow_methods=["*"]' not in main_src
    assert 'allow_headers=["*"]' not in main_src


def test_no_wildcard_host_in_production():
    assert "*" not in _prod().trusted_hosts()
    with pytest.raises(ValidationError):
        _prod(internal_health_host="*")


def test_no_http_or_localhost_production_origin():
    with pytest.raises(ValidationError):
        _prod(public_origin="http://secp.example.test")  # not https
    for loopback in ("https://localhost", "https://127.0.0.1", "https://[::1]"):
        with pytest.raises(ValidationError):
            _prod(public_origin=loopback)


def test_no_dev_fallback_or_provisioning_activation_in_production():
    s = _prod()
    assert s.dev_auth_enabled is False
    assert s.enable_fake_provisioning is False
    assert s.enable_real_provisioning is False
    assert s.enable_opentofu_subprocess is False
    # Arming the dev fallback, the fake runner, or the OpenTofu subprocess in production is refused
    # at construction. (The real-provisioning path is additionally sealed by a code constant
    # regardless of the flag; the reference env pins it false — asserted in the reference-env test.)
    for override in (
        {"auth_dev_mode": True},
        {"enable_fake_provisioning": True},
        {"enable_opentofu_subprocess": True},
    ):
        with pytest.raises(ValidationError):
            _prod(**override)


# --- reference production configuration ----------------------------------------------------------


def test_production_reference_files_exist():
    assert PROD_ENV.is_file()
    assert PROD_README.is_file()


def test_production_env_example_has_no_credentials_or_secret():
    text = PROD_ENV.read_text(encoding="utf-8")
    lowered = text.lower()
    # No PEM key/cert material and no dev credentials anywhere in the file.
    assert "-----begin" not in lowered
    assert "dev-admin" not in lowered
    assert "dev-only" not in lowered
    # No NON-COMMENT line assigns a secret-shaped variable (comment prose may mention the words).
    assignments = {
        ln.split("=", 1)[0].strip().upper(): ln.split("=", 1)[1].strip()
        for ln in text.splitlines()
        if "=" in ln and not ln.lstrip().startswith("#")
    }
    for key, value in assignments.items():
        if any(tok in key for tok in ("SECRET", "PASSWORD", "PRIVATE", "TOKEN", "CREDENTIAL")):
            assert not value, f"reference env assigns a secret-shaped variable {key}={value!r}"
    # And no client secret / admin credential keys appear at all.
    for key in assignments:
        assert "CLIENT_SECRET" not in key
        assert "KEYCLOAK_ADMIN" not in key


def test_production_env_example_sets_required_sealed_flags():
    lines = {
        ln.split("=", 1)[0].strip(): ln.split("=", 1)[1].strip()
        for ln in PROD_ENV.read_text(encoding="utf-8").splitlines()
        if "=" in ln and not ln.lstrip().startswith("#")
    }
    assert lines["SECP_APP_ENV"] == "production"
    assert lines["SECP_AUTH_DEV_MODE"] == "false"
    assert lines["SECP_WORKFLOW_DISPATCH_MODE"] == "temporal"
    assert lines["SECP_ENABLE_FAKE_PROVISIONING"] == "false"
    assert lines["SECP_ENABLE_REAL_PROVISIONING"] == "false"
    assert lines["SECP_ENABLE_OPENTOFU_SUBPROCESS"] == "false"
    assert lines["SECP_CORS_ALLOW_ORIGINS"] == ""  # same-origin => CORS disabled
    assert lines["SECP_PUBLIC_ORIGIN"].startswith("https://")
    assert lines["SECP_OIDC_ISSUER"].startswith("https://")
    assert lines["SECP_OIDC_WEB_CLIENT_ID"] == "secp-web"
    # placeholder hostnames only (no real host)
    assert "example.com" in lines["SECP_PUBLIC_ORIGIN"]
    assert "example.com" in lines["SECP_OIDC_ISSUER"]


def test_no_production_keycloak_bundle():
    # No production Compose/Kubernetes stack and no bundled Keycloak container image.
    prod_dir = REPO_ROOT / "infra" / "production"
    for path in prod_dir.rglob("*"):
        if not path.is_file():
            continue
        assert not path.name.startswith("docker-compose"), f"unexpected prod stack: {path}"
        text = path.read_text(encoding="utf-8").lower()
        assert "quay.io/keycloak" not in text
        assert "image: keycloak" not in text


def test_production_artifacts_do_not_claim_to_unseal_infrastructure():
    for path in (PROD_ENV, PROD_README):
        lowered = path.read_text(encoding="utf-8").lower()
        for claim in (
            "enable_real_provisioning=true",
            "enable_opentofu_subprocess=true",
            "unseal the",
            "activate real provisioning",
        ):
            assert claim not in lowered


# --- preflight import + behavior boundary --------------------------------------------------------


def test_preflight_imports_no_worker_provider_or_db_code():
    src = PREFLIGHT_SRC.read_text(encoding="utf-8")
    for forbidden in (
        "secp_worker",
        "opentofu",
        "OpenTofu",
        "subprocess",
        "secp_api.db",
        "secp_api.models",
        "secp_api.deps",
        "AuditEvent",
        "session_scope",
        "get_sessionmaker",
    ):
        assert forbidden not in src, f"preflight must not reference {forbidden!r}"


def test_preflight_performs_no_token_acquisition_in_source():
    src = PREFLIGHT_SRC.read_text(encoding="utf-8")
    for forbidden in ("grant_type", "code_verifier", "client_secret", "jwt.encode", "jwt.decode"):
        assert forbidden not in src, f"preflight must not perform {forbidden!r}"


# --- liveness / startup never contact the IdP ----------------------------------------------------


def test_app_construction_never_contacts_the_idp(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("app construction must not open an HTTP client (no discovery/JWKS)")

    monkeypatch.setattr(httpx.Client, "__init__", _boom)
    import secp_api.main as main_mod

    app = main_mod.create_app()  # must not construct any httpx client
    assert app is not None


def test_liveness_probe_never_contacts_the_idp(monkeypatch):
    import secp_api.main as main_mod
    from fastapi.testclient import TestClient

    app = main_mod.create_app()
    app.router.on_startup.clear()
    client = TestClient(app)  # constructs its transport BEFORE we forbid new clients
    monkeypatch.setattr(
        httpx.Client,
        "__init__",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("liveness must not contact the IdP")),
    )
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


# --- docs do not overclaim production readiness --------------------------------------------------


def test_docs_do_not_claim_the_platform_is_production_ready():
    readme = README.read_text(encoding="utf-8").lower()
    status = STATUS.read_text(encoding="utf-8").lower()
    overclaims = (
        "the platform is production-ready",
        "the platform is production ready",
        "fully production-ready",
        "production-ready platform",
        "secp is production-ready",
    )
    for doc_name, text in (("README", readme), ("STATUS", status)):
        for claim in overclaims:
            assert claim not in text, f"{doc_name} overclaims: {claim!r}"
    # The honest caveat is present in the README status banner.
    assert "does not make the whole" in readme and "production-ready" in readme


def _doc_text(path: Path) -> str:
    raw = path.read_text(encoding="utf-8").lower()
    return re.sub(r"\s+", " ", raw.replace("*", "").replace("`", ""))


def test_docs_state_identity_provisioning_gap_truthfully():
    """A direct DBA subject binding must NOT be described as the supported/SECP-audited path; the
    identity-lifecycle gap + a pre-rollout verification gate must be stated (ADR-019 amendment)."""
    runbook = _doc_text(REPO_ROOT / "docs" / "runbooks" / "oidc-production.md")
    adr = _doc_text(REPO_ROOT / "docs" / "adr" / "ADR-019-production-oidc-deployment-operations.md")
    status = _doc_text(STATUS)
    for text in (runbook, adr, status):
        assert "no first-class production identity-lifecycle" in text
        assert (
            "not secp-audited" in text
            or "not automatically protected by secp's application audit" in text
        )
        assert "remains future work" in text
    assert "independently verified" in runbook
    assert "outside the supported secp application mutation path" in runbook
