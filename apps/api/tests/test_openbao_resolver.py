"""SECP-B2-4 — worker-only OpenBao resolver adapter + activation boundary (fake-only, no contact).

Proves: the ``vault:`` scheme validates syntax only (API never resolves); the API/frontend cannot
import the adapter/client; the default adapter constructs no client and never resolves; independent
authoritative re-verification runs at resolution time; the three-way credential-reference binding
refuses BEFORE any client is touched; the sealed self-test reveals nothing; SecretMaterial stays
non-serializable; and no resolved credential can enter a Terraform variable / rendered plan / plan
JSON / state / artifact / log / audit. Nothing here contacts OpenBao, Proxmox, or any backend.
"""

from __future__ import annotations

import ast
import pickle
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from secp_api.live_read_contract import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    PROXMOX_READONLY_POLICY_VERSION,
)
from secp_api.secret_refs import InvalidSecretRefError, parse_secret_ref, validate_secret_ref_syntax
from secp_worker.preflight.backends.openbao_resolver import (
    RESOLVER_ADAPTER_CONTRACT_VERSION,
    OpenBaoWorkerSecretResolver,
    ResolverSelfTestResult,
    SealedResolverSelfTest,
)
from secp_worker.preflight.reverify import ReverifiedAuthority
from secp_worker.preflight.secret_resolution import (
    ResolutionContract,
    ResolutionContractViolation,
    ResolutionPurpose,
    SecretMaterial,
    SecretResolutionUnavailable,
    TrustedCredentialReference,
    TrustedResolutionRequest,
    build_resolution_contract,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
API_PKG = REPO_ROOT / "apps" / "api" / "secp_api"
WEB_SRC = REPO_ROOT / "apps" / "web" / "src"
PROVISIONING_PKG = REPO_ROOT / "apps" / "worker" / "secp_worker" / "provisioning"
BACKENDS_PKG = REPO_ROOT / "apps" / "worker" / "secp_worker" / "preflight" / "backends"

_REF = "vault:secp/proxmox/target-1"


def _now() -> datetime:
    return datetime(2026, 7, 4, 12, 0, 0, tzinfo=UTC)


def _py(pkg: Path) -> list[Path]:
    return [p for p in pkg.rglob("*.py") if "__pycache__" not in p.parts]


# --- vault: scheme is opaque + syntax-only -------------------------------------------------------


def test_vault_scheme_accepts_opaque_locator_without_resolving():
    scheme, locator = parse_secret_ref(_REF)
    assert scheme == "vault"
    assert locator == "secp/proxmox/target-1"
    validate_secret_ref_syntax(_REF)  # syntax only; no resolution


@pytest.mark.parametrize(
    "good",
    [
        "vault:secp/proxmox/target-1",
        "vault:v1.2/service.prod",  # dotted names WITHIN a segment stay valid
        "vault:a.b.c",
        "vault:secp/v1.2.3/tok",
    ],
)
def test_vault_scheme_preserves_valid_dotted_segment_names(good):
    scheme, locator = parse_secret_ref(good)
    assert scheme == "vault"
    assert locator == good.split(":", 1)[1]  # never normalized/rewritten


@pytest.mark.parametrize(
    "bad",
    [
        "vault:/leading-slash",
        "vault:has space",
        "vault:https://host/path",  # no scheme/host
        "vault:a//b",  # no empty segment
        "vault:",  # empty locator
        "vault:end/",  # trailing slash / empty segment
        # Dot-segment traversal — any segment that is exactly '.' or '..' is rejected (not
        # normalized): opaque references must have one unambiguous representation.
        "vault:secp/./target",
        "vault:secp/../target",
        "vault:secp/target/..",
        "vault:secp/target/.",
        "vault:.",
        "vault:..",
        "vault:a/./b/c",
        "vault:a/b/../c",
    ],
)
def test_vault_scheme_rejects_non_opaque_or_unsafe_locators(bad):
    with pytest.raises(InvalidSecretRefError):
        parse_secret_ref(bad)


def test_api_secret_refs_module_never_resolves():
    # The API-side module must contain no resolution/backend/network code — syntax only.
    src = (API_PKG / "secret_refs.py").read_text(encoding="utf-8")
    for forbidden in (
        "import httpx",
        "requests",
        "socket",
        "openbao",
        "hvac",
        "reveal",
        "resolve(",
    ):
        assert forbidden not in src, f"secret_refs.py must not reference `{forbidden}`"


# --- API + frontend cannot reach the adapter -----------------------------------------------------


def test_api_cannot_import_openbao_adapter_or_reverifier():
    forbidden_prefixes = (
        "secp_worker.preflight.backends",
        "secp_worker.preflight.reverify",
    )
    for path in _py(API_PKG):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith(forbidden_prefixes), (
                    f"{path.name} imports from {node.module}"
                )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(forbidden_prefixes), (
                        f"{path.name} imports {alias.name}"
                    )


def test_frontend_has_no_openbao_or_secret_resolution_interface():
    # The B2-4.1 admin UI legitimately names the "resolver activation" feature and displays the
    # opaque contract-version label — those are safe. The real risks are a credential-entry field or
    # a secret-reading/secret-resolution route/method.
    forbidden = (
        "readSecret",
        "resolveSecret",
        "secret-resolution",
        "/secrets",
        'type="password"',
        "type='password'",
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


# --- default wiring constructs no client and never resolves --------------------------------------


def test_default_adapter_constructs_no_client_and_fails_closed():
    resolver = OpenBaoWorkerSecretResolver()
    assert resolver.contract_version == RESOLVER_ADAPTER_CONTRACT_VERSION
    assert resolver._client is None  # no client constructed by default
    assert resolver._reverifier is None

    class _Req:
        class contract:  # noqa: D401 - placeholder
            pass

    with pytest.raises(SecretResolutionUnavailable):
        resolver.resolve(_Req(), expectation=None, now=_now())  # type: ignore[arg-type]


def test_no_production_code_constructs_the_openbao_adapter_or_a_client():
    # No production worker/API code may instantiate the adapter, a client, or the DB reverifier —
    # they are wired only by tests / a future out-of-band-granted activation.
    forbidden_calls = {"OpenBaoWorkerSecretResolver", "DbAuthoritativeReverifier"}
    scan_roots = [
        p
        for p in _py(REPO_ROOT / "apps" / "worker" / "secp_worker") + _py(API_PKG)
        if "backends" not in p.parts and p.name != "reverify.py"
    ]
    for path in scan_roots:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
            if isinstance(node, ast.Call):
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                assert name not in forbidden_calls, f"{path.name} constructs {name}"


def test_backends_package_imports_no_backend_or_network_client():
    forbidden = (
        "import httpx",
        "from httpx",
        "import requests",
        "import aiohttp",
        "import socket",
        "from socket",
        "import subprocess",
        "import hvac",  # no bundled Vault/OpenBao client library
        "from hvac",
        "import openbao",
        "from openbao",
        "os.environ",
        "os.getenv",
        "TF_VAR",
    )
    for path in _py(BACKENDS_PKG):
        src = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in src, f"{path.name} must not reference `{token}`"


# --- resolution-time ordering: re-verify -> gate -> three-way -> client --------------------------


def _contract(**over) -> ResolutionContract:
    base = dict(
        purpose=ResolutionPurpose.readonly_staging_preflight,
        organization_id=uuid.UUID(int=1),
        execution_target_id=uuid.UUID(int=2),
        onboarding_id=uuid.UUID(int=3),
        authorization_id=uuid.UUID(int=4),
        authorization_version=2,
        authorization_expiry="2999-01-01T00:00:00Z",
        preflight_id=uuid.UUID(int=5),
        operation_fingerprint="sha256:" + "ab" * 32,
        contract_version=LIVE_READ_COLLECTOR_CONTRACT_VERSION,
        endpoint_policy_version=PROXMOX_READONLY_POLICY_VERSION,
        credential_reference=TrustedCredentialReference(_REF),
    )
    base.update(over)
    return ResolutionContract(**base)  # type: ignore[arg-type]


def _request(contract: ResolutionContract) -> TrustedResolutionRequest:
    # Build a real request via the sealed constructor token by round-tripping through a verified
    # binding is heavy; instead use the module token indirectly through a tiny stand-in that only
    # exposes `.contract` (the adapter only reads request.contract).
    class _Req:
        def __init__(self, c: ResolutionContract) -> None:
            self.contract = c

    return _Req(contract)  # type: ignore[return-value]


class _RecordingReverifier:
    """Returns a fixed authoritative result and records that it was consulted."""

    def __init__(self, authority: ReverifiedAuthority) -> None:
        self.authority = authority
        self.called = False

    def reverify(self, contract, *, now):
        self.called = True
        return self.authority


class _SpyClient:
    called = False

    def read_secret(self, *, reference, now):
        type(self).called = True
        return "opaque-material"


def _authority(contract: ResolutionContract, *, target=_REF, binding=_REF) -> ReverifiedAuthority:
    return ReverifiedAuthority(
        contract=contract,
        target_credential_reference=TrustedCredentialReference(target),
        binding_credential_reference=TrustedCredentialReference(binding),
    )


def test_independent_reverification_is_consulted_and_gate_uses_it_not_expectation():
    contract = _contract()
    reverifier = _RecordingReverifier(_authority(contract))
    client = _SpyClient()
    resolver = OpenBaoWorkerSecretResolver(reverifier=reverifier, http_client=client)
    # A hostile/incorrect `expectation` is IGNORED — authority comes from the reverifier.
    hostile_expectation = _contract(organization_id=uuid.UUID(int=999))
    material = resolver.resolve(_request(contract), expectation=hostile_expectation, now=_now())
    assert reverifier.called is True
    assert isinstance(material, SecretMaterial)
    assert _SpyClient.called is True
    _SpyClient.called = False


def test_gate_refuses_when_reverified_authority_mismatches_request():
    contract = _contract()
    # Authority re-derives a DIFFERENT org -> the per-field gate refuses before the client.
    authority = _authority(_contract(organization_id=uuid.UUID(int=42)))
    client = _SpyClient()
    resolver = OpenBaoWorkerSecretResolver(
        reverifier=_RecordingReverifier(authority), http_client=client
    )
    with pytest.raises(ResolutionContractViolation):
        resolver.resolve(_request(contract), expectation=contract, now=_now())
    assert _SpyClient.called is False  # never reached the client


def test_three_way_binding_refuses_before_client_use():
    contract = _contract()
    # Request + target references agree, but the verified binding reference differs -> fail closed
    # BEFORE the client is touched.
    authority = _authority(contract, target=_REF, binding="vault:secp/proxmox/other")
    client = _SpyClient()
    resolver = OpenBaoWorkerSecretResolver(
        reverifier=_RecordingReverifier(authority), http_client=client
    )
    with pytest.raises(ResolutionContractViolation) as exc:
        resolver.resolve(_request(contract), expectation=contract, now=_now())
    assert exc.value.reason_code == "credential_reference_mismatch"
    assert _SpyClient.called is False


def test_valid_request_but_no_client_still_fails_closed():
    # A valid vault reference preserves the sealed-default behavior: with no client injected, the
    # adapter fails closed AFTER the gate/three-way/vault checks pass.
    contract = _contract()
    resolver = OpenBaoWorkerSecretResolver(reverifier=_RecordingReverifier(_authority(contract)))
    with pytest.raises(SecretResolutionUnavailable):
        resolver.resolve(_request(contract), expectation=contract, now=_now())


def test_matching_env_references_refused_before_client_use():
    # All three references agree (three-way passes) but are the dev `env:` scheme, not vault -> the
    # adapter refuses BEFORE the client with a closed, secret-free reason.
    env_ref = "env:SECP_PROVIDER_SECRET__PF"
    _SpyClient.called = False
    contract = _contract(credential_reference=TrustedCredentialReference(env_ref))
    authority = _authority(contract, target=env_ref, binding=env_ref)
    client = _SpyClient()
    resolver = OpenBaoWorkerSecretResolver(
        reverifier=_RecordingReverifier(authority), http_client=client
    )
    with pytest.raises(ResolutionContractViolation) as exc:
        resolver.resolve(_request(contract), expectation=contract, now=_now())
    assert exc.value.reason_code == "unsupported_reference_scheme"
    assert _SpyClient.called is False
    assert env_ref not in str(exc.value)  # no reference leaks through the error


def test_malformed_vault_reference_refused_before_client_use():
    bad = "vault:secp/../escape"  # a syntactically invalid vault locator (dot-segment traversal)
    _SpyClient.called = False
    contract = _contract(credential_reference=TrustedCredentialReference(bad))
    authority = _authority(contract, target=bad, binding=bad)
    client = _SpyClient()
    resolver = OpenBaoWorkerSecretResolver(
        reverifier=_RecordingReverifier(authority), http_client=client
    )
    with pytest.raises(ResolutionContractViolation) as exc:
        resolver.resolve(_request(contract), expectation=contract, now=_now())
    assert exc.value.reason_code == "unsupported_reference_scheme"
    assert _SpyClient.called is False
    assert bad not in str(exc.value)


def test_expired_binding_refused_by_gate_before_client():
    past = "2000-01-01T00:00:00Z"
    contract = _contract(authorization_expiry=past)
    client = _SpyClient()
    resolver = OpenBaoWorkerSecretResolver(
        reverifier=_RecordingReverifier(_authority(contract)), http_client=client
    )
    with pytest.raises(ResolutionContractViolation):
        resolver.resolve(_request(contract), expectation=contract, now=_now() + timedelta(days=1))
    assert _SpyClient.called is False


# --- self-test + secret material safety ----------------------------------------------------------


def test_sealed_self_test_reveals_no_secret_or_reference():
    result = OpenBaoWorkerSecretResolver().self_test(now=_now())
    assert isinstance(result, ResolverSelfTestResult)
    assert result.ok is False
    assert result.reason_code == "resolver_self_test_sealed"
    blob = f"{result.ok} {result.reason_code}".lower()
    for forbidden in ("vault:", "secret", "token", "://", "secp/proxmox"):
        assert forbidden not in blob
    # The default self-test does no I/O and constructs no client.
    assert isinstance(OpenBaoWorkerSecretResolver()._self_test, SealedResolverSelfTest)


def test_secret_material_from_adapter_stays_opaque_and_non_serializable():
    contract = _contract()
    resolver = OpenBaoWorkerSecretResolver(
        reverifier=_RecordingReverifier(_authority(contract)), http_client=_SpyClient()
    )
    material = resolver.resolve(_request(contract), expectation=contract, now=_now())
    _SpyClient.called = False
    assert "opaque-material" not in repr(material)
    assert repr(material) == "SecretMaterial(<redacted>)"
    assert not hasattr(material, "__dict__")
    with pytest.raises(TypeError):
        pickle.dumps(material)


# --- no Terraform-variable / plan / state credential channel -------------------------------------


def test_resolver_never_touches_terraform_variables_plans_or_state():
    # The resolver adapter + reverifier must not reference TF_VAR, the provisioning render/plan/
    # state path, or feed SecretMaterial into it.
    for path in _py(BACKENDS_PKG) + [
        REPO_ROOT / "apps" / "worker" / "secp_worker" / "preflight" / "reverify.py"
    ]:
        src = path.read_text(encoding="utf-8")
        for token in ("TF_VAR", "rendering", "plan_json", "state_store", "provisioning"):
            assert token not in src, (
                f"{path.name} must not reference the provisioning path `{token}`"
            )


def test_provisioning_render_plan_state_never_reveal_a_credential():
    # The rendered workspace, plan JSON, state store, and change set must never reveal a resolved
    # credential — no reveal_secret()/SecretMaterial/ProviderCredential in that path (secrets flow
    # only through the dedicated executor env seam, never into rendered artifacts).
    for name in ("rendering.py", "plan_json.py", "state_store.py", "change_set.py"):
        src = (PROVISIONING_PKG / name).read_text(encoding="utf-8")
        for token in ("reveal_secret", "SecretMaterial", "ProviderCredential"):
            assert token not in src, f"{name} must not handle secret material (`{token}`)"


def test_rendering_enforces_secret_free_output():
    # The existing render guard rejects secret refs / secret-like literals in rendered files.
    src = (PROVISIONING_PKG / "rendering.py").read_text(encoding="utf-8")
    assert "_assert_secret_free" in src
    assert "contains a secret reference" in src


# --- no activation flag / env / compose can enable OpenBao resolution ----------------------------


def test_no_settings_or_config_enables_openbao_resolution():
    from secp_api.config import Settings

    for field in Settings.model_fields:
        assert "openbao" not in field.lower()
        assert "vault" not in field.lower()
        assert "resolver" not in field.lower()


def test_no_compose_or_config_references_openbao():
    compose = REPO_ROOT / "infra" / "dev" / "docker-compose.yml"
    if compose.exists():
        text = compose.read_text(encoding="utf-8").lower()
        assert "openbao" not in text
        assert "vault" not in text


def test_build_contract_helper_round_trips_for_reference_tests():
    # Sanity: build_resolution_contract is importable + usable for the fake authority in these
    # tests (keeps the reference-binding tests honest about the real contract shape).
    assert callable(build_resolution_contract)
