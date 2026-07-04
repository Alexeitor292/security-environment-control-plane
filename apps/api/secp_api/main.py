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
from secp_api.routers import (
    catalog,
    exercises,
    observability,
    plans,
    providers,
    system,
)
from secp_api.routers import onboarding as onboarding_router
from secp_api.routers import provisioning as provisioning_router
from secp_api.routers import staging_labs as staging_labs_router

logger = logging.getLogger("secp.api")

# Staging-lab routes accept one optional caller string (``logical_name``). FastAPI's default
# RequestValidationError body echoes the rejected ``input`` value; for these routes that could
# reflect a token-shaped value back to the caller. They therefore return a safe generic code and
# NEVER echo the submitted value, request body, or raw validation details.
_STAGING_LAB_PATH_PREFIX = "/api/v1/staging-labs"


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def _domain_error(_: Request, exc: DomainError) -> JSONResponse:
        payload: dict = {"error": {"code": exc.code, "message": exc.message}}
        if isinstance(exc, ValidationFailedError) and exc.errors:
            payload["error"]["details"] = exc.errors
        return JSONResponse(status_code=exc.http_status, content=payload)

    @app.exception_handler(RequestValidationError)
    async def _request_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Staging-lab routes: return ONLY a safe generic code — no rejected input, ctx, raw
        # details, request body, or user-supplied text.
        if request.url.path.startswith(_STAGING_LAB_PATH_PREFIX):
            return JSONResponse(
                status_code=422, content={"error": {"code": "invalid_staging_lab_input"}}
            )
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
        description="SECP-001 Control Plane Foundation (simulated execution only).",
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
    app.include_router(exercises.router)
    app.include_router(plans.router)
    app.include_router(observability.router)
    app.include_router(providers.router)
    app.include_router(provisioning_router.router)
    app.include_router(onboarding_router.router)
    app.include_router(staging_labs_router.router)

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
