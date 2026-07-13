"""FastAPI dependencies: DB session and authenticated principal (ADR-017)."""

from __future__ import annotations

import logging
from collections.abc import Iterator

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from secp_api.auth import Principal, dev_principal, principal_from_oidc_claims
from secp_api.config import Settings, get_settings
from secp_api.db import get_db
from secp_api.errors import AuthenticationError, AuthenticationUnavailableError
from secp_api.oidc import (
    CATEGORY_HEADER_INVALID,
    OidcUnavailableError,
    OidcVerificationError,
    OidcVerifier,
    get_oidc_verifier,
)

logger = logging.getLogger("secp.api")

# Advertise an HTTP Bearer security scheme in OpenAPI. ``auto_error=False`` means this NEVER raises
# or parses — the strict raw-header detection in ``resolve_principal`` governs. Every route that
# depends on ``current_principal`` is thereby marked Bearer-secured in the schema; the public
# ``/health`` route does not depend on it and stays unsecured.
_bearer_scheme = HTTPBearer(auto_error=False, description="OIDC access token (ADR-017)")


def db_session() -> Iterator[Session]:
    yield from get_db()


def settings_dep() -> Settings:
    return get_settings()


def _refuse(category: str) -> AuthenticationError:
    """Log ONE bounded reason category (never the header/token/claims/subject) and return the
    closed, redacted 401. The caller raises it."""
    logger.info("authentication refused: %s", category)
    return AuthenticationError(f"authentication refused ({category})")


def _parse_bearer(authorization: str, *, max_len: int) -> str:
    """Strictly parse exactly ONE Bearer credential from a raw Authorization header value.

    Returns the raw token unchanged, or raises the closed 401. The scheme is case-insensitive (HTTP
    semantics: ``Bearer``/``bearer``/``BEARER``); the token is never transformed. A non-Bearer
    header (e.g. ``Basic``) is an ERROR — it must NOT be treated as "header absent" and must never
    fall back. Multiple / comma-combined / whitespace-split credentials and an empty token are
    refused.
    """
    if len(authorization) > max_len + 32:  # bound the raw header (token bound enforced in verify)
        raise _refuse(CATEGORY_HEADER_INVALID)
    scheme, sep, rest = authorization.partition(" ")
    if not sep or scheme.lower() != "bearer":
        raise _refuse(CATEGORY_HEADER_INVALID)
    token = rest
    if not token or any(ch.isspace() for ch in token) or "," in token:
        raise _refuse(CATEGORY_HEADER_INVALID)
    return token


def resolve_principal(
    *,
    session: Session,
    settings: Settings,
    verifier: OidcVerifier,
    authorization: str | None,
) -> Principal:
    """Core precedence logic (ADR-017), independent of FastAPI plumbing so it is directly testable.

    An Authorization header is ALWAYS evaluated first; a presented bearer token is strictly parsed,
    cryptographically verified, and mapped to a pre-provisioned internal user — it NEVER falls back
    to the dev principal on any failure. Only a request with NO Authorization header may use the dev
    fallback, and only when it is enabled (which is impossible in production).
    """
    if authorization is not None:
        token = _parse_bearer(authorization, max_len=verifier.max_token_bytes)
        try:
            issuer, claims = verifier.verify(token)
            return principal_from_oidc_claims(session, issuer=issuer, claims=claims)
        except OidcUnavailableError as exc:
            logger.warning("authentication unavailable: %s", exc.category)
            raise AuthenticationUnavailableError() from None
        except OidcVerificationError as exc:
            raise _refuse(exc.category) from None

    if settings.dev_auth_enabled:
        return dev_principal(session)

    raise _refuse("no_credential")


def current_principal(
    request: Request,
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
    verifier: OidcVerifier = Depends(get_oidc_verifier),
    _scheme: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> Principal:
    """Resolve the request principal. The raw ``Authorization`` header is read directly (so strict
    detection is not weakened by the lenient OpenAPI scheme); the security scheme only documents
    Bearer auth in the schema."""
    return resolve_principal(
        session=session,
        settings=settings,
        verifier=verifier,
        authorization=request.headers.get("Authorization"),
    )
