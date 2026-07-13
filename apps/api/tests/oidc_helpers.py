"""Shared OIDC test helpers (ADR-017): ephemeral RSA keys, token minting, and an injected
``httpx.MockTransport``-backed fake IdP. No network access; nothing here is a real credential.

This module is intentionally NOT named ``test_*`` / ``*_test`` so pytest never collects it.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from jwt.algorithms import RSAAlgorithm
from secp_api.oidc import OidcVerifier, OidcVerifierConfig

ISSUER = "https://issuer.test/realms/secp"
AUDIENCE = "secp-api"
JWKS_URI = "https://issuer.test/realms/secp/protocol/openid-connect/certs"


def gen_rsa() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def public_jwk(
    private_key: RSAPrivateKey, *, kid: str, alg: str | None = "RS256"
) -> dict[str, Any]:
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk["kid"] = kid
    jwk["use"] = "sig"
    if alg is not None:
        jwk["alg"] = alg
    return jwk


def sign(
    private_key: Any,
    claims: dict[str, Any],
    *,
    kid: str | None = "k1",
    alg: str = "RS256",
) -> str:
    headers = {"kid": kid} if kid is not None else {}
    return jwt.encode(claims, private_key, algorithm=alg, headers=headers)


def claims(
    *,
    sub: Any = "user-sub-1",
    iss: Any = ISSUER,
    aud: Any = AUDIENCE,
    exp_delta: int = 3600,
    iat_delta: int = 0,
    nbf_delta: int | None = None,
    include: tuple[str, ...] = ("iss", "aud", "sub", "iat", "exp"),
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    now = int(time.time())
    full = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "iat": now + iat_delta,
        "exp": now + exp_delta,
    }
    result = {k: full[k] for k in include}
    if nbf_delta is not None:
        result["nbf"] = now + nbf_delta
    if extra:
        result.update(extra)
    return result


class FakeIdp:
    """A configurable fake OIDC provider served over ``httpx.MockTransport``.

    Attributes mutate provider behavior for adversarial cases: outage (``fail``), redirect, non-2xx
    status, oversized body, raw malformed body, discovery issuer substitution, missing keys, etc.
    ``calls`` records every requested URL so tests can assert cache hits / bounded refresh.
    """

    def __init__(self, *, issuer: str = ISSUER, jwks_uri: str = JWKS_URI) -> None:
        self.issuer = issuer
        self.jwks_uri = jwks_uri
        self.discovery: dict[str, Any] = {"issuer": issuer, "jwks_uri": jwks_uri}
        self.jwks: dict[str, Any] = {"keys": []}
        self.calls: list[str] = []
        self.discovery_calls = 0
        self.jwks_calls = 0
        self.fail = False
        self.redirect = False
        self.discovery_status = 200
        self.jwks_status = 200
        self.discovery_raw: bytes | None = None
        self.jwks_raw: bytes | None = None
        self.oversized = False

    def set_keys(self, *jwks: dict[str, Any]) -> None:
        self.jwks = {"keys": list(jwks)}

    def _handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(url)
        if self.fail:
            raise httpx.ConnectError("simulated provider outage")
        if url.endswith("/.well-known/openid-configuration"):
            self.discovery_calls += 1
            if self.redirect:
                return httpx.Response(302, headers={"location": self.jwks_uri})
            if self.discovery_raw is not None:
                return httpx.Response(self.discovery_status, content=self.discovery_raw)
            return httpx.Response(self.discovery_status, json=self.discovery)
        if url == self.jwks_uri:
            self.jwks_calls += 1
            if self.oversized:
                return httpx.Response(200, content=b"{" + b" " * (2 * 1024 * 1024) + b"}")
            if self.jwks_raw is not None:
                return httpx.Response(self.jwks_status, content=self.jwks_raw)
            return httpx.Response(self.jwks_status, json=self.jwks)
        return httpx.Response(404)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handler)


def build_verifier(
    idp: FakeIdp,
    *,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    require_https: bool = False,
    monotonic: Any = time.monotonic,
    now_epoch: Any = time.time,
    **config_overrides: Any,
) -> OidcVerifier:
    transport = idp.transport()

    def client_factory() -> httpx.Client:
        # Mirror the production client posture: no redirects, no ambient proxy/env.
        return httpx.Client(
            transport=transport, follow_redirects=False, trust_env=False, timeout=5.0
        )

    base: dict[str, Any] = {
        "issuer": issuer,
        "audience": audience,
        "require_https": require_https,
        "http_timeout_seconds": 5.0,
        "discovery_cache_seconds": 300,
        "jwks_cache_seconds": 300,
        "clock_skew_seconds": 60,
        "max_token_bytes": 8192,
        "max_document_bytes": 1_048_576,
    }
    base.update(config_overrides)
    config = OidcVerifierConfig(**base)
    return OidcVerifier(
        config, client_factory=client_factory, monotonic=monotonic, now_epoch=now_epoch
    )
