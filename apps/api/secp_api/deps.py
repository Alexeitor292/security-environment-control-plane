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
from secp_api.enrollment_signer_binding import build_runtime_binding
from secp_api.enrollment_signer_client import (
    EnrollmentOfferSignerClient,
    build_enrollment_offer_signer,
)
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


# THE COMMIT BOUNDARY. Every route resolves its session through THIS ONE MARKER, never through a
# bare ``Depends(db_session)``.
#
# ``scope="function"`` is what makes the request's transaction commit BEFORE the response is written
# to the socket. Without it FastAPI defaults a generator dependency to ``computed_scope="request"``
# (``fastapi/dependencies/models.py``), which puts the teardown on the exit stack that
# ``fastapi/routing.py`` closes AFTER ``await response(scope, receive, send)`` — so ``get_db``'s
# ``session.commit()`` ran after the client already held its 2xx. Measured on fastapi 0.138.2: a
# teardown commit that FAILS at request scope still returns ``200`` with a complete body; the same
# failure at function scope returns ``500``. That is the whole defect and the whole fix.
#
# Why a shared marker rather than a per-site ``Depends(db_session, scope="function")``: one named
# seam means a new route cannot silently opt back into the defect by writing the obvious thing. The
# object is a frozen dataclass (``fastapi.params.Depends``), so sharing one instance across every
# signature is safe. The ``Annotated`` form FastAPI documents was rejected only because it removes
# the parameter default, which is a SyntaxError at 7 of the call sites here (a defaulted parameter
# already precedes the session); nothing else about it was unsuitable.
#
# THIS CANNOT BE DONE STRUCTURALLY IN THIS FastAPI VERSION — do not "improve" it into a router-level
# or composition-level seam. Both were built and measured, and both are MIRAGES:
#   * ``route_class`` does NOT propagate through ``include_router`` (``routing.py``:
#     ``route_class = route_class_override or self.route_class``), so an app-level route class never
#     reaches the composed routes.
#   * Rewriting the composed app's dependant tree DOES set all 349 resolutions to "function" and
#     changes NOTHING at request time: ``_populate_api_route_state`` rebuilds
#     ``route.dependant = get_dependant(call=route.endpoint, ...)`` for every served operation, so
#     0 of 187 served operations use the object a composition-time walk can reach. Driven over a
#     real socket with that seam applied, the response still preceded the commit.
# The ``Depends(...)`` marker in the endpoint SIGNATURE is the only thing that survives that
# rebuild. ``tests/test_api_commit_boundary.py`` walks the SERVED trees and fails on exactly that
# disagreement, so this comment cannot quietly become false.
#
# THE ONE REAL CONSTRAINT THIS IMPOSES: DO NOT STREAM ORM INSTANCES.
# Function scope closes the session after the endpoint returns and after the response model is
# serialized, but BEFORE ``await response(scope, receive, send)``. An ordinary JSON response is
# therefore unaffected — serialization has already finished, so ``expire_on_commit`` cannot bite. A
# ``StreamingResponse`` is different: its body is produced DURING the send, by which point the
# session is closed, so touching an ORM attribute inside the generator raises
# ``DetachedInstanceError``. Measured on fastapi 0.138.2:
#     streaming ORM instances @ scope="request"   -> 200, complete body
#     streaming ORM instances @ scope="function"  -> headers already sent, then the connection
#                                                    closes mid-body (truncated chunked read)
#     streaming plain data / raw SQL @ "function" -> 200, complete body
# The truncation is the nasty part: the status line is already on the wire, so the client sees a
# 200 with a short body rather than an error. Materialise rows into plain data BEFORE returning a
# StreamingResponse. There is no streaming route in this application today, and the commit-boundary
# guard does NOT detect this — it has no notion of response classes.
#
# WEBSOCKET ROUTES ARE ALSO NOT COVERED. ``@router.websocket(...)`` produces an
# ``APIWebSocketRoute``, which is neither an ``_IncludedRouter`` nor an ``APIRoute``, so the
# commit-boundary guard's walk does not reach it and a request-scoped session generator behind one
# would go unreported. Left as documentation rather than detection on purpose: none exist in this
# application, and "commit before the response" does not map cleanly onto a socket that has no
# single response to be ordered against. If a WebSocket route is ever added, its session lifetime
# needs deciding on its own terms — not by assuming this guard covered it.
DB_SESSION = Depends(db_session, scope="function")


def settings_dep() -> Settings:
    return get_settings()


def get_enrollment_offer_signer(
    settings: Settings = Depends(settings_dep),
    session: Session = DB_SESSION,
) -> EnrollmentOfferSignerClient:
    """The injected controller-enrollment offer signer client (SECP-PR5H-B1 Phase 3). Sealed by
    default (fails closed); the production composition returns the fixed-UDS broker client only when
    the root-owned enablement marker's COMPLETE binding exactly matches the authoritative runtime
    binding built read-only from the verified ACTIVE controller identity + the running process + the
    fixed contracts + the CA bundle (SECP-PR5H-B2 C1) — never from settings/env for identity facts.
    Overridden in tests. The non-root API only ever holds this pure client seam — never the concrete
    root signer, the filesystem reader, or the enrollment private key."""
    binding = (
        build_runtime_binding(session) if bool(getattr(settings, "is_production", False)) else None
    )
    return build_enrollment_offer_signer(settings, runtime_binding=binding)


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
    session: Session = DB_SESSION,
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
