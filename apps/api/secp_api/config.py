"""Application configuration.

All values come from the environment / ``.env`` (git-ignored). ``.env.example``
documents every key with development-only placeholders. No real secrets are ever
committed (Charter §13).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import model_validator
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

    # SECP-002B-1B-9: bounded poll interval (seconds) for the worker-side, fake-only
    # staging-lab work-item consumer loop. The consumer runs ONLY in the worker process.
    staging_lab_poll_interval_seconds: float = 2.0

    # SECP-B6: worker-local, deployment-controlled read-only discovery enablement. Both are
    # DEPLOYMENT-LOCAL only (set in the worker container's deploy manifest) — never API/UI/DB
    # controlled, and they carry NO SSH/credential material. When the profile is disabled OR the
    # mount is absent/invalid, discovery stays sealed (the shipped default). The bundle FIELDS
    # (host/account/port/key/known_hosts/fingerprint) NEVER come from config/env — only from the
    # fixed mounted bundle directory below. These are read ONLY by the worker discovery composition.
    discovery_controlled_integration_enabled: bool = False
    discovery_bootstrap_mount: str = "/var/run/secp/discovery-bundle"

    # SECP-B6 MB-1: worker discovery ADMISSION over the internal control-plane endpoint. These are
    # DEPLOYMENT-LOCAL worker settings (an internal HTTPS URL + file paths) — never API/UI/DB
    # controlled. Worker AUTHENTICATION is the Ed25519 signed-nonce proof-of-possession handshake
    # (NOT X.509 client-certificate mTLS): the worker signs the server-issued nonce with its
    # deployment-local Ed25519 PRIVATE key, and the control plane verifies the signature against the
    # PUBLIC anchor whose fingerprint is pinned in the approved worker registration. The TLS layer
    # the endpoint is validated against ``discovery_admission_ca`` (server-cert validation, never
    # disabled). No secret material lives in config: the Ed25519 private key + public anchor live
    # ONLY on the worker's deployment-local filesystem at the paths below. When the endpoint or the
    # identity material is unset/invalid/unreachable, live discovery fails closed (sealed).
    discovery_admission_endpoint: str = ""
    # Path to the worker's deployment-local Ed25519 identity PRIVATE key (hex). Signs the nonce.
    discovery_worker_identity_key: str = ""
    # Path to the worker's deployment-local Ed25519 PUBLIC anchor (hex). Presented + pinned by fp.
    discovery_worker_identity_anchor: str = ""
    # Path to the CA bundle that validates the internal admission endpoint's server TLS certificate.
    discovery_admission_ca: str = ""

    # Auth. The dev fallback principal is ONLY honored when auth_dev_mode is true
    # AND app_env != production (enforced below). Production requires real OIDC.
    auth_dev_mode: bool = True
    oidc_issuer: str = "http://localhost:8081/realms/secp"
    oidc_audience: str = "secp-api"

    # Object storage (MinIO in dev). Wired for artifacts; lightly used in SECP-001.
    s3_endpoint: str = "http://localhost:9000"
    s3_bucket: str = "secp-artifacts"

    # SECP-002B-0: explicit dev/test gate for the FakeOpenTofuRunner. Never enabled
    # in production (enforced below). Even when true it only reaches the FAKE runner,
    # and only when every provisioning precondition is met (ADR-012).
    enable_fake_provisioning: bool = False

    # SECP-002B-1A: real, worker-only OpenTofu provisioning path (ADR-013).
    #
    # ``provisioning_application_mode`` selects the path: 'simulator' (unchanged
    # default) vs 'isolated_lab' (the ONLY mode eligible for the real path, and only
    # behind the full activation gate). ``enable_real_provisioning`` is the explicit
    # real-provisioning setting. ``enable_opentofu_subprocess`` ARMS the real
    # worker-side subprocess executor — it is disabled by default, refused in production
    # in B1-A, and is NOT armed anywhere in the B1-A slice (all tests / verification use
    # the fake process executor).
    provisioning_application_mode: Literal["simulator", "isolated_lab"] = "simulator"
    enable_real_provisioning: bool = False
    enable_opentofu_subprocess: bool = False

    cors_allow_origins: list[str] = ["http://localhost:5173"]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def dev_auth_enabled(self) -> bool:
        # The dev fallback principal requires BOTH a non-production environment AND
        # explicit dev-auth mode. Production can never enable it (see validator).
        return self.auth_dev_mode and not self.is_production

    @model_validator(mode="after")
    def _reject_unsafe_production_config(self) -> Settings:
        """Refuse to construct an unsafe production configuration.

        Production must not silently fall back to the bootstrap administrator or
        run privileged work through the inline dispatcher. These are hard errors
        (not silent disables), so a misconfigured production deployment fails fast
        rather than booting in an unsafe state (assignment hardening §1, §2).
        """
        if self.app_env != "production":
            return self
        problems: list[str] = []
        if self.auth_dev_mode:
            problems.append(
                "SECP_AUTH_DEV_MODE must be false in production "
                "(the dev auth fallback / bootstrap admin is forbidden)"
            )
        if self.workflow_dispatch_mode == "inline":
            problems.append(
                "SECP_WORKFLOW_DISPATCH_MODE must be 'temporal' in production "
                "(inline execution is for local development/tests only)"
            )
        if self.enable_fake_provisioning:
            problems.append(
                "SECP_ENABLE_FAKE_PROVISIONING must be false in production "
                "(the fake provisioning runner is for local development/tests only)"
            )
        if self.enable_opentofu_subprocess:
            problems.append(
                "SECP_ENABLE_OPENTOFU_SUBPROCESS must be false in production "
                "(the real OpenTofu subprocess executor is not cleared for production "
                "in SECP-002B-1A; it is armed only for a reviewed disposable lab in B1-B)"
            )
        if problems:
            raise ValueError("unsafe production configuration refused: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
