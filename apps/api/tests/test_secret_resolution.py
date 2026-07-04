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
        "vault:/leading-slash",  # vault locators are opaque relative paths only
        "vault:has space",
        # Dot-segment traversal: any segment exactly '.' or '..' is rejected (not normalized).
        "vault:secp/./target",
        "vault:secp/../target",
        "vault:secp/target/..",
        "vault:.",
        "vault:..",
        "aws-sm:whatever",  # still an unsupported scheme
        "",
    ],
)
def test_invalid_or_unsafe_references_rejected(ref):
    with pytest.raises(InvalidSecretRefError):
        validate_secret_ref_syntax(ref)


def test_vault_scheme_is_supported_syntax_only():
    # SECP-B2-4: the 'vault' scheme is an opaque reference the API validates syntactically but never
    # resolves (worker-only resolution behind the sealed OpenBao adapter).
    scheme, locator = parse_secret_ref("vault:secret/data/x")
    assert scheme == "vault"
    assert locator == "secret/data/x"
    validate_secret_ref_syntax("vault:secp/proxmox/target-1")  # no raise
    # Dotted names WITHIN a segment remain valid and are never normalized/rewritten.
    assert parse_secret_ref("vault:v1.2/service.prod") == ("vault", "v1.2/service.prod")
    assert parse_secret_ref("vault:a.b.c") == ("vault", "a.b.c")


def test_plaintext_detection():
    assert looks_like_plaintext_secret("raw-token-value") is True
    assert looks_like_plaintext_secret(VALID_REF) is False


# --- worker-side resolution ---------------------------------------------------


def test_env_resolver_reads_namespaced_env(monkeypatch):
    monkeypatch.setenv("SECP_PROVIDER_SECRET__TARGET_ABC", "tok-123")
    cred = EnvSecretResolver().resolve(VALID_REF)
    assert cred.reveal_secret() == "tok-123"


def test_env_resolver_missing_value_is_redacted(monkeypatch):
    monkeypatch.delenv("SECP_PROVIDER_SECRET__TARGET_ABC", raising=False)
    with pytest.raises(SecretResolutionError) as exc:
        EnvSecretResolver().resolve(VALID_REF)
    # error must not leak the locator value beyond the scheme, and never a secret
    assert "tok" not in str(exc.value)


def test_fake_resolver_for_tests():
    resolver = FakeSecretResolver({VALID_REF: "fake-token"})
    assert resolver.resolve(VALID_REF).reveal_secret() == "fake-token"
    with pytest.raises(SecretResolutionError):
        resolver.resolve("env:SECP_PROVIDER_SECRET__MISSING")


def test_resolved_secret_never_in_credential_repr():
    resolver = FakeSecretResolver({VALID_REF: "leak-me"})
    cred = resolver.resolve(VALID_REF)
    assert "leak-me" not in repr(cred)
