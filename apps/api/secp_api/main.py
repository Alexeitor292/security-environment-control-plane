"""FastAPI application factory for the control-plane API.

Registers routers, maps domain errors to HTTP responses, configures CORS, and —
in development — ensures the schema exists and seeds the dev org/admin and the
Web Breach 101 sample. The API never executes privileged infrastructure actions
(Charter Invariants 6, 7); execution is dispatched to the worker boundary.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from secp_api import immutability  # noqa: F401  (registers ORM immutability guards)
from secp_api.config import get_settings
from secp_api.db import get_engine, session_scope
from secp_api.errors import DomainError, ValidationFailedError
from secp_api.models import Base
from secp_api.routers import catalog, exercises, observability, plans, system

logger = logging.getLogger("secp.api")


def _install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(DomainError)
    async def _domain_error(_: Request, exc: DomainError) -> JSONResponse:
        payload: dict = {"error": {"code": exc.code, "message": exc.message}}
        if isinstance(exc, ValidationFailedError) and exc.errors:
            payload["error"]["details"] = exc.errors
        return JSONResponse(status_code=exc.http_status, content=payload)


def _bootstrap_dev() -> None:
    """Create the schema and seed dev data (development/test only)."""
    settings = get_settings()
    Base.metadata.create_all(bind=get_engine())
    if settings.app_env in ("dev", "test"):
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

    @app.on_event("startup")
    def _startup() -> None:
        _bootstrap_dev()
        logger.info("control-plane API started (env=%s)", settings.app_env)

    return app


app = create_app()
