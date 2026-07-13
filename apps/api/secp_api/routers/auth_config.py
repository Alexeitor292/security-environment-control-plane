"""Public browser-authentication configuration endpoint (ADR-018 / OIDC-B).

``GET /api/v1/auth/config`` is deliberately PUBLIC (no ``current_principal`` dependency): the
browser must read it before it can authenticate. It returns only non-secret, server-owned values the
OIDC client needs to begin an Authorization Code + PKCE flow. It performs NO discovery/JWKS network
call, NO database mutation, and NO audit event, and it exposes NO client secret, token, password,
key, certificate, endpoint credential, or internal database detail. The backend remains the
authoritative token verifier (OIDC-A / ADR-017); nothing here weakens that boundary.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from secp_api.config import Settings
from secp_api.deps import settings_dep
from secp_api.schemas import AuthConfigOut

router = APIRouter(prefix="/api/v1", tags=["auth"])

# Fixed, server-owned values. The scope EXCLUDES ``offline_access`` (no long-lived refresh session
# in this slice); the paths are fixed same-origin relative application routes.
_OIDC_SCOPE = "openid profile email"
_REDIRECT_PATH = "/auth/callback"
_POST_LOGOUT_REDIRECT_PATH = "/login"


@router.get("/auth/config", response_model=AuthConfigOut)
def auth_config(settings: Settings = Depends(settings_dep)) -> AuthConfigOut:
    """Public authentication configuration for the browser client.

    ``mode`` is server-derived: ``dev_fallback`` ONLY when the safe dev fallback is actually enabled
    (non-production + ``auth_dev_mode``), otherwise ``oidc``. Production therefore always reports
    ``oidc`` and can never silently become dev-fallback.
    """
    mode = "dev_fallback" if settings.dev_auth_enabled else "oidc"
    return AuthConfigOut(
        mode=mode,
        issuer=settings.oidc_issuer,
        client_id=settings.oidc_web_client_id,
        audience=settings.oidc_audience,
        scope=_OIDC_SCOPE,
        redirect_path=_REDIRECT_PATH,
        post_logout_redirect_path=_POST_LOGOUT_REDIRECT_PATH,
    )
