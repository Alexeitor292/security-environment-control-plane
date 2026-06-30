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

    SECP-001 authentication behaviour
    -----------------------------------
    * **Dev fallback** (``SECP_AUTH_DEV_MODE=true``, ``APP_ENV != production``):
      the bootstrapped development admin principal is returned unconditionally.
      This is the only working authentication path in SECP-001.

    * **Bearer token presented**: OIDC bearer-token validation is **not
      implemented** in SECP-001.  Any ``Authorization: Bearer …`` header is
      explicitly rejected with an ``AuthenticationError`` explaining that OIDC
      token verification is a SECP-002+ milestone item.  We do not silently
      ignore the token or fall back to the dev principal, so callers are never
      misled into thinking their token was verified.

    * **No token + dev fallback disabled**: ``AuthenticationError`` is raised
      explaining that no usable authentication method is available.

    NOTE: The production startup guard (``Settings`` validator) ensures
    ``dev_auth_enabled`` is always ``False`` in production, so the dev fallback
    can never activate there regardless of this function's logic.
    """
    if settings.dev_auth_enabled:
        return dev_principal(session)

    if authorization is not None:
        raise AuthenticationError(
            "OIDC bearer-token verification is not implemented in SECP-001; "
            "tokens cannot be validated in this milestone. "
            "Bearer authentication will be available in SECP-002+."
        )

    raise AuthenticationError(
        "No authentication method is available: "
        "dev auth fallback is disabled and OIDC token verification is not "
        "implemented in SECP-001."
    )
