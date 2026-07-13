"""FastAPI application factory for the control-plane API.

Registers routers, maps domain errors to HTTP responses, configures CORS, and —
in development — ensures the schema exists and seeds the dev org/admin and the
Web Breach 101 sample. The API never executes privileged infrastructure actions
(Charter Invariants 6, 7); execution is dispatched to the worker boundary.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from secp_api import immutability  # noqa: F401  (registers ORM immutability guards)
from secp_api.config import get_settings
from secp_api.db import get_engine, session_scope
from secp_api.errors import DomainError, ValidationFailedError
from secp_api.models import Base
from secp_api.routers import bootstrap_discovery as bootstrap_discovery_router
from secp_api.routers import (
    catalog,
    exercises,
    observability,
    plans,
    providers,
    system,
)
from secp_api.routers import environment_publication as environment_publication_router
from secp_api.routers import onboarding as onboarding_router
from secp_api.routers import provisioning as provisioning_router
from secp_api.routers import readonly_preflight as readonly_preflight_router
from secp_api.routers import resolver_activation as resolver_activation_router
from secp_api.routers import staging_deployments as staging_deployments_router
from secp_api.routers import staging_labs as staging_labs_router
from secp_api.routers import target_discovery as target_discovery_router
from secp_api.routers import topology_authoring as topology_authoring_router
from secp_api.routers import worker_admission as worker_admission_router
from secp_api.routers import worker_identity as worker_identity_router
from secp_api.routers import worker_nodes as worker_nodes_router

logger = logging.getLogger("secp.api")

# Feature routes that must NEVER echo a rejected caller value in a validation error body.
# FastAPI's default RequestValidationError body reflects Pydantic's ``input``/``ctx``; for these
# routes we return only a safe generic code. Keyed by a SEGMENT-AWARE base path (exact base or
# base + "/") -> the safe code — a broad accidental-prefix match (e.g. "-labsX") never matches.
_REDACTED_VALIDATION_ROUTES: tuple[tuple[str, str], ...] = (
    ("/api/v1/staging-labs", "invalid_staging_lab_input"),
    ("/api/v1/staging-deployments", "invalid_staging_deployment_input"),
    ("/api/v1/target-discovery", "invalid_target_discovery_input"),
    ("/api/v1/readonly-preflight", "invalid_readonly_preflight_input"),
    ("/api/v1/resolver-activation", "invalid_resolver_activation_input"),
    ("/api/v1/worker-identity", "invalid_worker_identity_input"),
    # PR C: the publication route is the only /api/v1/environment-versions endpoint; a malformed
    # request (bad UUID/hash, unknown/missing field, caller idempotency key) returns only this code.
    ("/api/v1/environment-versions/publish", "invalid_environment_publication_input"),
)


def _path_under(path: str, base: str) -> bool:
    """Segment-aware match: the path is exactly ``base`` or a child ``base/...`` route."""
    return path == base or path.startswith(base + "/")


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def _domain_error(_: Request, exc: DomainError) -> JSONResponse:
        # Authentication errors add a WWW-Authenticate challenge (ADR-017); all others set none.
        challenge = getattr(exc, "www_authenticate", None)
        headers = {"WWW-Authenticate": challenge} if challenge else None
        # Redacted errors (e.g. authentication, read-only preflight) serialize ONLY the closed
        # code — no message, details, or rejected input.
        if getattr(exc, "redacted", False):
            return JSONResponse(
                status_code=exc.http_status,
                content={"error": {"code": exc.code}},
                headers=headers,
            )
        payload: dict = {"error": {"code": exc.code, "message": exc.message}}
        if isinstance(exc, ValidationFailedError) and exc.errors:
            payload["error"]["details"] = exc.errors
        return JSONResponse(status_code=exc.http_status, content=payload, headers=headers)

    @app.exception_handler(RequestValidationError)
    async def _request_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Redacted-validation routes: return ONLY a safe generic code — no rejected input, ctx,
        # url, detail, request body, or user-supplied text.
        for base, code in _REDACTED_VALIDATION_ROUTES:
            if _path_under(request.url.path, base):
                return JSONResponse(status_code=422, content={"error": {"code": code}})
        # All other routes keep FastAPI's default behavior (backward compatible).
        return await request_validation_exception_handler(request, exc)


def _bootstrap_dev() -> None:
    """Create the schema and seed dev data — DEVELOPMENT/TEST ONLY.

    In production the schema is managed exclusively by Alembic migrations and NO
    bootstrap administrator is ever seeded (assignment hardening §2). Auto-creating
    tables or seeding an admin in production is refused here as defense in depth.
    """
    settings = get_settings()
    if settings.app_env not in ("dev", "test"):
        logger.info(
            "production startup: skipping schema auto-create and dev seed "
            "(use 'alembic upgrade head'); env=%s",
            settings.app_env,
        )
        return

    Base.metadata.create_all(bind=get_engine())
    from secp_api.seed import bootstrap_dev, seed_sample_environment

    with session_scope() as session:
        principal = bootstrap_dev(session)
        try:
            seed_sample_environment(session, principal)
        except FileNotFoundError:
            logger.warning("sample environment file not found; skipping seed")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description=(
            "Security Environment Control Platform control plane for governed environment "
            "authoring, simulated execution, and controlled provider integration. The API "
            "performs no privileged infrastructure actions; execution is dispatched to the "
            "worker boundary. Real provisioning and live discovery remain sealed by default. "
            "See docs/STATUS.md for the current-capability ledger."
        ),
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allow_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    _install_error_handlers(app)

    app.include_router(system.router)
    app.include_router(catalog.router)
    app.include_router(environment_publication_router.router)
    app.include_router(exercises.router)
    app.include_router(plans.router)
    app.include_router(observability.router)
    app.include_router(providers.router)
    app.include_router(provisioning_router.router)
    app.include_router(onboarding_router.router)
    app.include_router(staging_labs_router.router)
    app.include_router(staging_deployments_router.router)
    app.include_router(target_discovery_router.router)
    app.include_router(topology_authoring_router.router)
    app.include_router(bootstrap_discovery_router.router)
    app.include_router(worker_nodes_router.router)
    app.include_router(readonly_preflight_router.router)
    app.include_router(resolver_activation_router.router)
    app.include_router(worker_identity_router.router)
    # Internal worker-only admission route (SECP-B6 MB-1) — NOT under /api/v1; inert unless the
    # deployment-local controlled-integration profile is enabled. Worker admission uses CA-validated
    # internal HTTPS for server identity and transport security, plus an Ed25519 signed-nonce
    # proof-of-possession handshake for worker authentication — NOT X.509 client-certificate mTLS.
    app.include_router(worker_admission_router.router)

    @app.on_event("startup")
    def _startup() -> None:
        _bootstrap_dev()
        logger.info(
            "control-plane API started (env=%s, dispatch=%s, dev_auth=%s)",
            settings.app_env,
            settings.workflow_dispatch_mode,
            settings.dev_auth_enabled,
        )

    return app


app = create_app()
