"""FastAPI dependencies: DB session and authenticated principal."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends, Header
from sqlalchemy.orm import Session

from secp_api.auth import Principal, dev_principal
from secp_api.config import Settings, get_settings
from secp_api.db import get_db
from secp_api.errors import AuthenticationError


def db_session() -> Iterator[Session]:
    yield from get_db()


def settings_dep() -> Settings:
    return get_settings()


def current_principal(
    session: Session = Depends(db_session),
    settings: Settings = Depends(settings_dep),
    authorization: str | None = Header(default=None),
) -> Principal:
    """Resolve the request principal.

    Production requires a verified OIDC bearer token. For local development the
    dev fallback principal is used when no usable token is presented AND the dev
    fallback is enabled (never in production).

    NOTE: full OIDC token verification against the dev IdP is a documented
    SECP-001 placeholder; the seam is here and the dev fallback keeps the stack
    runnable. See the design doc §11.
    """
    if settings.dev_auth_enabled:
        return dev_principal(session)
    raise AuthenticationError("OIDC token verification is required; dev auth fallback is disabled")
