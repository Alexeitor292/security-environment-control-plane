"""Application configuration.

All values come from the environment / ``.env`` (git-ignored). ``.env.example``
documents every key with development-only placeholders. No real secrets are ever
committed (Charter §13).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SECP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: Literal["dev", "test", "production"] = "dev"
    app_name: str = "Security Environment Control Platform"

    # Database. Defaults to a local SQLite file so the app/tests run with zero
    # external services; the dev Docker stack overrides this with PostgreSQL.
    database_url: str = "sqlite+pysqlite:///./secp_dev.db"

    # Workflow dispatch mode (ADR-005). 'inline' runs orchestration in-process
    # (dev/test default); 'temporal' enqueues to the durable worker.
    workflow_dispatch_mode: Literal["inline", "temporal"] = "inline"
    temporal_host: str = "localhost:7233"
    temporal_namespace: str = "default"
    temporal_task_queue: str = "secp-orchestration"

    # Auth. The dev fallback principal is ONLY honored when auth_dev_mode is true
    # AND app_env != production (enforced below). Production requires real OIDC.
    auth_dev_mode: bool = True
    oidc_issuer: str = "http://localhost:8081/realms/secp"
    oidc_audience: str = "secp-api"

    # Object storage (MinIO in dev). Wired for artifacts; lightly used in SECP-001.
    s3_endpoint: str = "http://localhost:9000"
    s3_bucket: str = "secp-artifacts"

    cors_allow_origins: list[str] = ["http://localhost:5173"]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def dev_auth_enabled(self) -> bool:
        # Defense in depth: never allow the dev auth fallback in production.
        return self.auth_dev_mode and not self.is_production


@lru_cache
def get_settings() -> Settings:
    return Settings()
