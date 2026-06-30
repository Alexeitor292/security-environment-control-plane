"""Slice 7 — worker-only secret resolution + API-side syntax validation (ADR-007)."""

from __future__ import annotations

import pytest
from secp_api.secret_refs import (
    InvalidSecretRefError,
    looks_like_plaintext_secret,
    parse_secret_ref,
    validate_secret_ref_syntax,
)
from secp_worker.secrets import (
    EnvSecretResolver,
    FakeSecretResolver,
    SecretResolutionError,
)

VALID_REF = "env:SECP_PROVIDER_SECRET__TARGET_ABC"


# --- API-side syntax validation (never resolves) ------------------------------


def test_valid_env_reference_parses():
    scheme, locator = parse_secret_ref(VALID_REF)
    assert scheme == "env"
    assert locator == "SECP_PROVIDER_SECRET__TARGET_ABC"
    validate_secret_ref_syntax(VALID_REF)  # no raise


@pytest.mark.parametrize(
    "ref",
    [
        "PVEAPIToken=root@pam!x=secret",  # looks like a raw token
        "just-a-plain-secret",
        "env:HOME",  # not namespaced -> refused (cannot read arbitrary env)
        "env:PATH",
        "vault:secret/data/x",  # unsupported scheme in SECP-002A
        "",
    ],
)
def test_invalid_or_unsafe_references_rejected(ref):
    with pytest.raises(InvalidSecretRefError):
        validate_secret_ref_syntax(ref)


def test_plaintext_detection():
    assert looks_like_plaintext_secret("raw-token-value") is True
    assert looks_like_plaintext_secret(VALID_REF) is False


# --- worker-side resolution ---------------------------------------------------


def test_env_resolver_reads_namespaced_env(monkeypatch):
    monkeypatch.setenv("SECP_PROVIDER_SECRET__TARGET_ABC", "tok-123")
    cred = EnvSecretResolver().resolve(VALID_REF)
    assert cred.secret == "tok-123"


def test_env_resolver_missing_value_is_redacted(monkeypatch):
    monkeypatch.delenv("SECP_PROVIDER_SECRET__TARGET_ABC", raising=False)
    with pytest.raises(SecretResolutionError) as exc:
        EnvSecretResolver().resolve(VALID_REF)
    # error must not leak the locator value beyond the scheme, and never a secret
    assert "tok" not in str(exc.value)


def test_fake_resolver_for_tests():
    resolver = FakeSecretResolver({VALID_REF: "fake-token"})
    assert resolver.resolve(VALID_REF).secret == "fake-token"
    with pytest.raises(SecretResolutionError):
        resolver.resolve("env:SECP_PROVIDER_SECRET__MISSING")


def test_resolved_secret_never_in_credential_repr():
    resolver = FakeSecretResolver({VALID_REF: "leak-me"})
    cred = resolver.resolve(VALID_REF)
    assert "leak-me" not in repr(cred)
