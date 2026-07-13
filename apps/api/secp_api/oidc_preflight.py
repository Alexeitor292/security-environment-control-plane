"""Token-free production OIDC deployment preflight (ADR-019 / OIDC-C).

An operator diagnostic — ``python -m secp_api.oidc_preflight`` — that actively checks the configured
OIDC provider is deployable BEFORE going live, WITHOUT performing a login, obtaining or verifying a
user token, or requiring a username / password / client secret.

It reuses the OIDC-A hardened HTTP seam (:func:`secp_api.oidc.fetch_document_bytes`,
:func:`secp_api.oidc.require_safe_url`, :func:`secp_api.oidc.build_client_factory`): bounded timeout
and response-size caps, no redirects, and ``trust_env=False`` (no ambient proxy/env). It performs NO
database access, NO audit event, and NO provider mutation, and it never prints a discovery body, JWK
material, or any token-shaped value — only bounded booleans/categories and values derived from
SECP's OWN configuration (the issuer hostname and the computed callback/logout URLs). No network
call happens at import time.

Exit codes (stable):

* ``0`` success — the provider metadata is deployable.
* ``1`` local configuration invalid — SECP's own config is unsafe/incomplete.
* ``2`` provider unavailable — discovery/JWKS could not be retrieved within the bounds.
* ``3`` provider metadata invalid — retrieved metadata is malformed or disagrees with configuration.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx
from jwt.algorithms import RSAAlgorithm

from secp_api.config import Settings, _public_origin_problems, get_settings
from secp_api.oidc import (
    OidcUnavailableError,
    OidcVerifier,
    build_client_factory,
    fetch_document_bytes,
    require_safe_url,
)

EXIT_OK = 0
EXIT_CONFIG_INVALID = 1
EXIT_PROVIDER_UNAVAILABLE = 2
EXIT_PROVIDER_METADATA_INVALID = 3

_CATEGORY_EXIT = {
    "ok": EXIT_OK,
    "config_invalid": EXIT_CONFIG_INVALID,
    "provider_unavailable": EXIT_PROVIDER_UNAVAILABLE,
    "provider_metadata_invalid": EXIT_PROVIDER_METADATA_INVALID,
}


# --- control-flow signals (carry only preflight-authored, provider-content-free messages) ---------


class _ConfigInvalid(Exception):
    pass


class _ProviderUnavailable(Exception):
    pass


class _MetadataInvalid(Exception):
    pass


@dataclass
class Check:
    """One bounded, non-secret preflight check. ``detail`` is preflight-authored (never provider
    content), and ``fatal=False`` marks an advisory check (e.g. S256 advertisement) that does not by
    itself fail the preflight."""

    name: str
    passed: bool
    detail: str = ""
    fatal: bool = True


@dataclass
class PreflightReport:
    category: str
    checks: list[Check] = field(default_factory=list)
    issuer_host: str | None = None
    callback_url: str | None = None
    logout_url: str | None = None
    s256_advertised: bool | None = None
    usable_rsa_keys: int | None = None

    @property
    def exit_code(self) -> int:
        return _CATEGORY_EXIT[self.category]

    def to_json(self) -> dict[str, Any]:
        """Safe JSON: categories/booleans/counts and SECP-derived (non-provider) URLs only."""
        return {
            "category": self.category,
            "exit_code": self.exit_code,
            "issuer_host": self.issuer_host,
            "callback_url": self.callback_url,
            "logout_url": self.logout_url,
            "s256_advertised": self.s256_advertised,
            "usable_rsa_keys": self.usable_rsa_keys,
            "checks": [
                {"name": c.name, "passed": c.passed, "fatal": c.fatal, "detail": c.detail}
                for c in self.checks
            ],
        }

    def render(self) -> str:
        lines = [f"OIDC deployment preflight: {self.category.upper()} (exit {self.exit_code})"]
        for c in self.checks:
            if c.passed:
                mark = "PASS"
            else:
                mark = "FAIL" if c.fatal else "WARN"
            suffix = f" — {c.detail}" if c.detail else ""
            lines.append(f"  [{mark}] {c.name}{suffix}")
        if self.issuer_host:
            lines.append(f"  issuer host: {self.issuer_host}")
        if self.callback_url:
            lines.append(f"  expected callback URL: {self.callback_url}")
        if self.logout_url:
            lines.append(f"  expected logout URL:   {self.logout_url}")
        if self.usable_rsa_keys is not None:
            lines.append(f"  usable RSA signing keys: {self.usable_rsa_keys}")
        if self.s256_advertised is not None:
            lines.append(f"  PKCE S256 advertised in discovery: {self.s256_advertised}")
        return "\n".join(lines)


def _issuer_problems(issuer: str, *, require_https: bool) -> list[str]:
    raw = issuer.strip()
    if not raw:
        return ["issuer is not set"]
    problems: list[str] = []
    parsed = urlsplit(raw)
    if require_https:
        if parsed.scheme != "https":
            problems.append("issuer must use https")
    elif parsed.scheme not in ("http", "https"):
        problems.append("issuer must be an http(s) url")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        problems.append("issuer must not contain userinfo")
    if parsed.query or parsed.fragment:
        problems.append("issuer must not contain a query or fragment")
    if not parsed.hostname:
        problems.append("issuer must contain a host")
    return problems


def _count_usable_rsa_keys(keys: list[Any]) -> int:
    """Count RSA signing keys with a non-empty kid whose material parses. Raises
    ``_MetadataInvalid`` on a duplicate kid. Never returns or logs any key material."""
    usable = 0
    seen_kids: set[str] = set()
    for key in keys:
        if not isinstance(key, dict):
            continue
        kid = key.get("kid")
        if not isinstance(kid, str) or not kid:
            continue  # missing/empty kid -> not a usable, addressable signing key
        if kid in seen_kids:
            raise _MetadataInvalid("jwks contains a duplicate kid")
        seen_kids.add(kid)
        if key.get("kty") != "RSA":
            continue
        use = key.get("use")
        if use is not None and use != "sig":
            continue
        alg = key.get("alg")
        if alg is not None and alg != "RS256":
            continue
        try:
            RSAAlgorithm.from_jwk(json.dumps(key))
        except Exception:
            continue  # malformed RSA material -> not usable
        usable += 1
    return usable


def _load_json_document(
    url: str,
    *,
    client_factory: Callable[[], httpx.Client],
    max_document_bytes: int,
    require_https: bool,
    what: str,
) -> dict[str, Any]:
    """Retrieve + parse a JSON object via the shared hardened seam. A transport failure is
    ``provider_unavailable``; a parse/non-object failure is ``provider_metadata_invalid``."""
    try:
        raw = fetch_document_bytes(
            url,
            client_factory=client_factory,
            max_document_bytes=max_document_bytes,
            require_https=require_https,
        )
    except OidcUnavailableError:
        raise _ProviderUnavailable(what) from None
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise _MetadataInvalid(f"{what} is not valid JSON") from None
    if not isinstance(parsed, dict):
        raise _MetadataInvalid(f"{what} is not a JSON object")
    return parsed


def run_preflight(
    settings: Settings,
    *,
    client_factory: Callable[[], httpx.Client] | None = None,
) -> PreflightReport:
    """Run the token-free preflight against ``settings``. Never performs a login, obtains a token,
    touches the database, or writes an audit event."""
    checks: list[Check] = []
    issuer_host: str | None = None
    callback_url: str | None = None
    logout_url: str | None = None
    s256: bool | None = None
    usable: int | None = None
    try:
        # 1. Local configuration: public origin + issuer must be safe and complete.
        origin_problems = _public_origin_problems(
            settings.public_origin, require_https=settings.is_production
        )
        checks.append(
            Check(
                "public_origin_valid",
                not origin_problems,
                "" if not origin_problems else "public origin is invalid for this environment",
            )
        )
        if origin_problems:
            raise _ConfigInvalid()
        callback_url = settings.oidc_callback_url
        logout_url = settings.oidc_logout_url

        config = OidcVerifier.from_settings(settings).config
        issuer_problems = _issuer_problems(config.issuer, require_https=config.require_https)
        checks.append(
            Check(
                "issuer_valid",
                not issuer_problems,
                "" if not issuer_problems else "issuer is invalid for this environment",
            )
        )
        if issuer_problems:
            raise _ConfigInvalid()
        issuer_host = urlsplit(config.issuer).hostname

        factory = client_factory or build_client_factory(config.http_timeout_seconds)

        # 2. Discovery — retrieved via the hardened seam, issuer must EXACTLY match configuration.
        discovery = _load_json_document(
            config.issuer + "/.well-known/openid-configuration",
            client_factory=factory,
            max_document_bytes=config.max_document_bytes,
            require_https=config.require_https,
            what="discovery",
        )
        checks.append(Check("discovery_retrieved", True, "fetched within bounds"))
        if discovery.get("issuer") != config.issuer:
            raise _MetadataInvalid("discovery issuer does not exactly match configuration")
        checks.append(Check("discovery_issuer_matches", True))

        # 3. Endpoint URLs must be safe (https in production, no userinfo).
        jwks_uri = discovery.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri:
            raise _MetadataInvalid("discovery has no jwks_uri")
        endpoints: list[tuple[str, Any]] = [
            ("authorization_endpoint", discovery.get("authorization_endpoint")),
            ("token_endpoint", discovery.get("token_endpoint")),
            ("jwks_uri", jwks_uri),
        ]
        end_session = discovery.get("end_session_endpoint")
        if end_session is not None:
            endpoints.append(("end_session_endpoint", end_session))
        for name, endpoint in endpoints:
            if not isinstance(endpoint, str) or not endpoint:
                raise _MetadataInvalid(f"discovery {name} is missing")
            try:
                require_safe_url(endpoint, require_https=config.require_https)
            except OidcUnavailableError:
                raise _MetadataInvalid(f"discovery {name} is not a safe url") from None
        checks.append(Check("endpoints_safe_https", True, "authorization/token/jwks[/logout] safe"))

        # 4. PKCE S256 advertisement — reported, but NOT proof; absence is advisory (see ADR-019).
        methods = discovery.get("code_challenge_methods_supported")
        s256 = isinstance(methods, list) and "S256" in methods
        checks.append(
            Check(
                "pkce_s256_advertised",
                s256,
                "advertised"
                if s256
                else "not advertised — confirm PKCE S256 is enforced on the IdP client",
                fatal=False,
            )
        )

        # 5. JWKS — at least one usable RSA signing key with a non-empty kid.
        jwks = _load_json_document(
            jwks_uri,
            client_factory=factory,
            max_document_bytes=config.max_document_bytes,
            require_https=config.require_https,
            what="jwks",
        )
        keys = jwks.get("keys")
        if not isinstance(keys, list) or not keys:
            raise _MetadataInvalid("jwks has no keys")
        usable = _count_usable_rsa_keys(keys)
        checks.append(
            Check("usable_rsa_signing_key", usable >= 1, f"{usable} usable RSA signing key(s)")
        )
        if usable < 1:
            raise _MetadataInvalid("jwks has no usable RSA signing key")

        return PreflightReport("ok", checks, issuer_host, callback_url, logout_url, s256, usable)
    except _ConfigInvalid:
        return PreflightReport(
            "config_invalid", checks, issuer_host, callback_url, logout_url, s256, usable
        )
    except _ProviderUnavailable:
        checks.append(Check("provider_reachable", False, "discovery/JWKS could not be retrieved"))
        return PreflightReport(
            "provider_unavailable", checks, issuer_host, callback_url, logout_url, s256, usable
        )
    except _MetadataInvalid as exc:
        # ``str(exc)`` is a preflight-authored, provider-content-free message.
        checks.append(Check("provider_metadata_valid", False, str(exc)))
        return PreflightReport(
            "provider_metadata_invalid", checks, issuer_host, callback_url, logout_url, s256, usable
        )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m secp_api.oidc_preflight",
        description=(
            "Token-free OIDC deployment preflight (ADR-019). Validates the configured provider's "
            "discovery + JWKS without logging in, obtaining a token, or touching the database."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit safe JSON (categories/booleans/counts only) instead of human-readable text",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        settings = get_settings()
    except Exception:
        # The local configuration itself is invalid (e.g. an unsafe production config was refused at
        # construction). Never print the exception — it could echo configuration detail.
        report = PreflightReport(
            "config_invalid", [Check("settings_load", False, "settings failed to load")]
        )
        _emit(report, as_json=args.json)
        return report.exit_code
    report = run_preflight(settings)
    _emit(report, as_json=args.json)
    return report.exit_code


def _emit(report: PreflightReport, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report.to_json(), indent=2, sort_keys=True))
    else:
        print(report.render())


if __name__ == "__main__":
    raise SystemExit(main())
