"""Strict OIDC access-token verification (ADR-017 / OIDC-A).

A single, deployment-configured OIDC issuer is the sole root of trust. This module fetches that
issuer's discovery document and JWKS, verifies an access token's signature and registered claims
with an explicit fixed algorithm allowlist, and returns the verified claims. It maps NO identity to
an internal user (that is :func:`secp_api.auth.principal_from_oidc_claims`) and grants nothing —
authentication is not authorization.

Trust boundary rules enforced here:

* Discovery + JWKS are derived ONLY from the configured issuer — never caller- or database-provided.
* No network access happens at import time; discovery/JWKS are fetched lazily and only from
  :meth:`OidcVerifier.verify` (i.e. only when a request actually presents a bearer token).
* The accepted algorithm is a fixed ``["RS256"]`` allowlist — never derived from the JWT header or
  the JWK. ``none``, symmetric algorithms, and algorithm-confusion are refused before any key work.
* HTTP is bounded: no redirects, no ambient proxy/env, bounded timeouts, 2xx required, response size
  capped before JSON parsing, and resource URLs must be HTTP(S) with no userinfo (HTTPS in prod).
* Discovery ``issuer`` must exactly equal the configured issuer; a mismatch or malformed/unavailable
  trust metadata fails closed as :class:`OidcUnavailableError` (a retryable 503), NOT a 401.
* Caches (discovery + JWKS) are bounded, single-entry, monotonic-expiry — never unbounded global
  dicts. Raw tokens and decoded claims are never cached; JWKS is never persisted to the database.

The verifier never logs tokens, claims, subjects, JWK material, or provider response bodies. It
raises category-tagged exceptions; the dependency layer logs only the bounded category.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

if TYPE_CHECKING:
    from secp_api.config import Settings

# The ONLY accepted signing algorithm (ADR-017). Fixed allowlist — never read from the token or JWK.
ALLOWED_ALGORITHMS: tuple[str, ...] = ("RS256",)

# Bounded, content-free reason categories for server-side logging. The external HTTP response never
# distinguishes these — each maps to the same closed 401 (or 503 for provider_unavailable).
CATEGORY_HEADER_INVALID = "header_invalid"
CATEGORY_TOKEN_MALFORMED = "token_malformed"
CATEGORY_ALGORITHM_REFUSED = "algorithm_refused"
CATEGORY_KEY_UNKNOWN = "key_unknown"
CATEGORY_SIGNATURE_INVALID = "signature_invalid"
CATEGORY_CLAIMS_INVALID = "claims_invalid"
CATEGORY_SUBJECT_UNKNOWN = "subject_unknown"
CATEGORY_PROVIDER_UNAVAILABLE = "provider_unavailable"


class OidcError(Exception):
    """Base for OIDC verification failures. Carries only a bounded ``category`` (never token/claim/
    subject/provider content), suitable for server-side logging."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


class OidcVerificationError(OidcError):
    """A definitive token/claim/key/subject refusal → closed HTTP 401 ``unauthenticated``."""


class OidcUnavailableError(OidcError):
    """A temporary trust-infrastructure failure (discovery/JWKS unavailable or malformed) — the
    token could not be checked → closed, retryable HTTP 503 ``authentication_unavailable``."""

    def __init__(self, category: str = CATEGORY_PROVIDER_UNAVAILABLE) -> None:
        super().__init__(category)


@dataclass(frozen=True)
class OidcVerifierConfig:
    """Immutable, bounded verifier configuration snapshot (built from :class:`Settings`)."""

    issuer: str  # normalized: a single trailing slash removed
    audience: str
    require_https: bool  # True in production
    http_timeout_seconds: float
    discovery_cache_seconds: int
    jwks_cache_seconds: int
    clock_skew_seconds: int
    max_token_bytes: int
    max_document_bytes: int
    max_subject_length: int = 255  # matches app_user.subject String(255)


@dataclass(frozen=True)
class _CacheEntry:
    expiry_monotonic: float
    value: Any


def _default_client_factory(timeout_seconds: float) -> Callable[[], httpx.Client]:
    """A bounded, redirect-disabled, proxy/env-disabled synchronous client factory (production
    default). ``trust_env=False`` disables ambient proxy and environment configuration; the
    repository ships no reviewed proxy configuration, so ambient proxying stays off."""
    timeout = httpx.Timeout(
        timeout_seconds,
        connect=timeout_seconds,
        read=timeout_seconds,
        write=timeout_seconds,
        pool=timeout_seconds,
    )

    def factory() -> httpx.Client:
        return httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False)

    return factory


class OidcVerifier:
    """Verifies OIDC access tokens against one configured issuer. Thread-safe; bounded caches."""

    def __init__(
        self,
        config: OidcVerifierConfig,
        *,
        client_factory: Callable[[], httpx.Client] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        now_epoch: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self._client_factory = client_factory or _default_client_factory(
            config.http_timeout_seconds
        )
        self._monotonic = monotonic
        self._now_epoch = now_epoch
        self._lock = threading.Lock()
        self._discovery_cache: _CacheEntry | None = None  # value: dict (issuer + jwks_uri)
        self._jwks_cache: _CacheEntry | None = None  # value: dict[kid -> jwk]

    @classmethod
    def from_settings(cls, settings: Settings) -> OidcVerifier:
        issuer = settings.oidc_issuer.strip()
        # Normalize by removing exactly one trailing slash (the only permitted normalization).
        normalized = issuer[:-1] if issuer.endswith("/") else issuer
        config = OidcVerifierConfig(
            issuer=normalized,
            audience=settings.oidc_audience,
            require_https=settings.is_production,
            http_timeout_seconds=settings.oidc_http_timeout_seconds,
            discovery_cache_seconds=settings.oidc_discovery_cache_seconds,
            jwks_cache_seconds=settings.oidc_jwks_cache_seconds,
            clock_skew_seconds=settings.oidc_clock_skew_seconds,
            max_token_bytes=settings.oidc_max_token_bytes,
            max_document_bytes=settings.oidc_max_document_bytes,
        )
        return cls(config)

    @property
    def issuer(self) -> str:
        return self.config.issuer

    @property
    def max_token_bytes(self) -> int:
        return self.config.max_token_bytes

    # --- public entry point ---------------------------------------------------------------------

    def verify(self, token: str) -> tuple[str, Mapping[str, Any]]:
        """Verify a bearer access token. Returns ``(issuer, claims)`` on success.

        Raises :class:`OidcVerificationError` (→ 401) for any token/claim/key problem, or
        :class:`OidcUnavailableError` (→ 503) when the trust metadata cannot be obtained.
        """
        # 1. bounded size (before any parsing).
        if len(token) > self.config.max_token_bytes:
            raise OidcVerificationError(CATEGORY_TOKEN_MALFORMED)
        # 2. exactly three non-empty segments.
        segments = token.split(".")
        if len(segments) != 3 or not all(segments):
            raise OidcVerificationError(CATEGORY_TOKEN_MALFORMED)
        # 3. unverified header (used ONLY to reject; never to choose the algorithm).
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise OidcVerificationError(CATEGORY_TOKEN_MALFORMED) from None
        alg = header.get("alg")
        if alg not in ALLOWED_ALGORITHMS:
            raise OidcVerificationError(CATEGORY_ALGORITHM_REFUSED)
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise OidcVerificationError(CATEGORY_TOKEN_MALFORMED)
        # 4. resolve the signing key (one bounded JWKS refresh on unknown kid).
        jwk = self._signing_jwk(kid)
        public_key = self._public_key_from_jwk(jwk)
        # 5. signature + registered-claim verification with a fixed RS256 allowlist.
        try:
            claims = jwt.decode(
                token,
                key=public_key,
                algorithms=list(ALLOWED_ALGORITHMS),
                audience=self.config.audience,
                issuer=self.config.issuer,
                leeway=self.config.clock_skew_seconds,
                options={
                    "require": ["exp", "iat", "sub", "aud", "iss"],
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                },
            )
        except jwt.InvalidSignatureError:
            raise OidcVerificationError(CATEGORY_SIGNATURE_INVALID) from None
        except jwt.InvalidAlgorithmError:
            raise OidcVerificationError(CATEGORY_ALGORITHM_REFUSED) from None
        except (
            jwt.ExpiredSignatureError,
            jwt.ImmatureSignatureError,
            jwt.InvalidAudienceError,
            jwt.InvalidIssuerError,
            jwt.InvalidIssuedAtError,
            jwt.MissingRequiredClaimError,
        ):
            raise OidcVerificationError(CATEGORY_CLAIMS_INVALID) from None
        except jwt.DecodeError:
            raise OidcVerificationError(CATEGORY_TOKEN_MALFORMED) from None
        except jwt.PyJWTError:
            raise OidcVerificationError(CATEGORY_CLAIMS_INVALID) from None
        # 6. explicit subject validation — string, non-empty, bounded, NO transformation.
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub or len(sub) > self.config.max_subject_length:
            raise OidcVerificationError(CATEGORY_CLAIMS_INVALID)
        # 7. Defense-in-depth iat bound. PyJWT (2.13) already rejects a future iat via verify_iat,
        #    but we also reject it explicitly here — and reject a bool/non-numeric iat that an int
        #    coercion elsewhere could otherwise mask. Reject an iat beyond now + the skew.
        iat = claims.get("iat")
        if not isinstance(iat, (int, float)) or isinstance(iat, bool):
            raise OidcVerificationError(CATEGORY_CLAIMS_INVALID)
        if float(iat) > self._now_epoch() + self.config.clock_skew_seconds:
            raise OidcVerificationError(CATEGORY_CLAIMS_INVALID)
        return self.config.issuer, claims

    # --- key resolution -------------------------------------------------------------------------

    def _signing_jwk(self, kid: str) -> Mapping[str, Any]:
        keys = self._get_jwks(force_refresh=False)
        jwk = keys.get(kid)
        if jwk is None:
            # Unknown kid: refresh the JWKS EXACTLY once (bounded — supports key rotation without a
            # refresh loop). A still-unknown kid is a definitive 401.
            keys = self._get_jwks(force_refresh=True)
            jwk = keys.get(kid)
        if jwk is None:
            raise OidcVerificationError(CATEGORY_KEY_UNKNOWN)
        return jwk

    def _public_key_from_jwk(self, jwk: Mapping[str, Any]) -> Any:
        if jwk.get("kty") != "RSA":
            raise OidcVerificationError(CATEGORY_ALGORITHM_REFUSED)
        jwk_alg = jwk.get("alg")
        if jwk_alg is not None and jwk_alg != "RS256":
            raise OidcVerificationError(CATEGORY_ALGORITHM_REFUSED)
        try:
            return RSAAlgorithm.from_jwk(json.dumps(jwk))
        except Exception:
            raise OidcVerificationError(CATEGORY_ALGORITHM_REFUSED) from None

    # --- bounded caches (discovery + JWKS) ------------------------------------------------------

    def _get_jwks(self, *, force_refresh: bool) -> dict[str, Mapping[str, Any]]:
        with self._lock:
            now = self._monotonic()
            cache = self._jwks_cache
            if not force_refresh and cache is not None and now < cache.expiry_monotonic:
                return cache.value
            metadata = self._get_discovery_locked(now)
            keys = self._fetch_jwks(metadata["jwks_uri"])
            self._jwks_cache = _CacheEntry(
                expiry_monotonic=self._monotonic() + self.config.jwks_cache_seconds, value=keys
            )
            return keys

    def _get_discovery_locked(self, now: float) -> dict[str, Any]:
        cache = self._discovery_cache
        if cache is not None and now < cache.expiry_monotonic:
            return cache.value
        metadata = self._fetch_discovery()
        self._discovery_cache = _CacheEntry(
            expiry_monotonic=self._monotonic() + self.config.discovery_cache_seconds, value=metadata
        )
        return metadata

    # --- bounded network retrieval --------------------------------------------------------------

    def _fetch_discovery(self) -> dict[str, Any]:
        url = self.config.issuer + "/.well-known/openid-configuration"
        data = self._fetch_json(url)
        # Discovery issuer MUST exactly equal the configured issuer (no substitution).
        if data.get("issuer") != self.config.issuer:
            raise OidcUnavailableError()
        jwks_uri = data.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise OidcUnavailableError()
        self._require_safe_url(jwks_uri)
        return {"issuer": self.config.issuer, "jwks_uri": jwks_uri}

    def _fetch_jwks(self, jwks_uri: str) -> dict[str, Mapping[str, Any]]:
        data = self._fetch_json(jwks_uri)
        keys = data.get("keys")
        if not isinstance(keys, list):
            raise OidcUnavailableError()
        result: dict[str, Mapping[str, Any]] = {}
        for key in keys:
            if isinstance(key, dict):
                kid = key.get("kid")
                if isinstance(kid, str) and kid:
                    result[kid] = key
        return result

    def _fetch_json(self, url: str) -> dict[str, Any]:
        self._require_safe_url(url)
        body = bytearray()
        try:
            with self._client_factory() as client, client.stream("GET", url) as response:
                if response.status_code // 100 != 2:
                    raise OidcUnavailableError()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > self.config.max_document_bytes:
                        raise OidcUnavailableError()
        except OidcUnavailableError:
            raise
        except Exception:
            # Never surface provider/network/exception detail — one closed category.
            raise OidcUnavailableError() from None
        try:
            parsed = json.loads(bytes(body))
        except (ValueError, UnicodeDecodeError):
            raise OidcUnavailableError() from None
        if not isinstance(parsed, dict):
            raise OidcUnavailableError()
        return parsed

    def _require_safe_url(self, url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise OidcUnavailableError()
        if self.config.require_https and parsed.scheme != "https":
            raise OidcUnavailableError()
        if parsed.username or parsed.password or "@" in parsed.netloc:
            raise OidcUnavailableError()
        if not parsed.hostname:
            raise OidcUnavailableError()


# --- process-wide singleton (rebindable for tests) ---------------------------------------------

_verifier_singleton: OidcVerifier | None = None
_singleton_lock = threading.Lock()


def get_oidc_verifier() -> OidcVerifier:
    """FastAPI dependency: the process-wide verifier, built lazily from settings (no network at
    import). Tests override this dependency or call :func:`reset_oidc_verifier` with a seam-injected
    verifier."""
    global _verifier_singleton
    with _singleton_lock:
        if _verifier_singleton is None:
            from secp_api.config import get_settings

            _verifier_singleton = OidcVerifier.from_settings(get_settings())
        return _verifier_singleton


def reset_oidc_verifier(verifier: OidcVerifier | None = None) -> None:
    """Test helper: replace (or clear) the process-wide verifier singleton."""
    global _verifier_singleton
    with _singleton_lock:
        _verifier_singleton = verifier
