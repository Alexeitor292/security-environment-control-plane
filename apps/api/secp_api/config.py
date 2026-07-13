"""Application configuration.

All values come from the environment / ``.env`` (git-ignored). ``.env.example``
documents every key with development-only placeholders. No real secrets are ever
committed (Charter §13).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator
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

    # SECP-B8: worker-OWNED bundle automation. When enabled, a worker startup task generates + owns
    # the SSH + Ed25519 admission keypairs under ``discovery_worker_key_dir`` (private halves never
    # leave the worker), publishes ONLY the PUBLIC material to the control plane so the UI can
    # auto-populate the bootstrap wizard, and — once a target's bootstrap is completed + bound + the
    # host public key is captured — assembles the mounted bundle at ``discovery_bootstrap_mount``
    # from the control plane's SECRET-FREE bundle descriptor. All DEPLOYMENT-LOCAL; no SSH/cred
    # material lives in config. When disabled the worker never generates keys or writes a bundle.
    discovery_worker_managed_bundle: bool = False
    # Worker-private, persistent directory holding the worker-owned keypairs (0700; keys 0600). The
    # admission key/anchor here should be the same files ``discovery_worker_identity_key`` /
    # ``discovery_worker_identity_anchor`` point at, so the generated identity drives admission.
    discovery_worker_key_dir: str = "/var/run/secp/worker-keys"
    # Optional explicit organization id the self-publishing worker writes its PUBLIC node into. When
    # empty and exactly ONE organization exists (first-time/single-tenant), that org is used; with
    # multiple orgs and no explicit id, publication is skipped (never guess across tenants).
    discovery_worker_node_organization: str = ""
    # Stable label for this worker's published discovery node (unique per organization).
    discovery_worker_node_label: str = "default-worker"
    # Bounded poll interval (seconds) for the worker bundle-prep loop.
    discovery_worker_bundle_poll_seconds: float = 15.0

    # Auth. The dev fallback principal is ONLY honored when auth_dev_mode is true
    # AND app_env != production (enforced below). Production requires real OIDC.
    auth_dev_mode: bool = True
    oidc_issuer: str = "http://localhost:8081/realms/secp"
    oidc_audience: str = "secp-api"

    # OIDC-B (ADR-018): the PUBLIC browser client id used by the Authorization Code + PKCE flow.
    # It is NOT a secret (a public client has none); it is surfaced by GET /api/v1/auth/config so
    # the browser can start the flow. Bounded length; production requires a non-empty value.
    oidc_web_client_id: str = Field(default="secp-web", max_length=200)

    # --- Strict OIDC bearer verification (ADR-017) -------------------------------------------
    # Discovery + JWKS are DEPLOYMENT-CONFIGURED trust infrastructure derived only from
    # ``oidc_issuer`` — never caller- or database-provided. The numeric bounds below are
    # validated ALWAYS (a negative/zero/excessive value is refused in every environment); the
    # issuer-shape, HTTPS, and non-empty-audience requirements are enforced only in production
    # (non-production may use the HTTP dev Keycloak service). No secret/URL here is ever
    # controlled by an API request or a database row.
    oidc_discovery_cache_seconds: int = Field(default=300, ge=0, le=86400)
    oidc_jwks_cache_seconds: int = Field(default=300, ge=0, le=86400)
    oidc_http_timeout_seconds: float = Field(default=5.0, gt=0.0, le=30.0)
    oidc_clock_skew_seconds: int = Field(default=60, ge=0, le=300)
    oidc_max_token_bytes: int = Field(default=8192, ge=256, le=65536)
    oidc_max_document_bytes: int = Field(default=1_048_576, ge=1024, le=5_242_880)

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
        # --- OIDC bearer verification must be safely configured in production (ADR-017) -------
        # The issuer is the sole root of trust: it must be a bare HTTPS origin+path with no
        # embedded credentials, query, or fragment; the audience must be non-empty. (The bounded
        # numeric verifier settings are Field-validated in every environment.)
        issuer = self.oidc_issuer.strip()
        if not issuer:
            problems.append("SECP_OIDC_ISSUER must be set in production")
        else:
            parsed = urlsplit(issuer)
            if parsed.scheme != "https":
                problems.append("SECP_OIDC_ISSUER must use https:// in production")
            if parsed.username or parsed.password or "@" in parsed.netloc:
                problems.append("SECP_OIDC_ISSUER must not contain credentials (userinfo)")
            if parsed.query or parsed.fragment:
                problems.append("SECP_OIDC_ISSUER must not contain a query or fragment")
            if not parsed.hostname:
                problems.append("SECP_OIDC_ISSUER must contain a host")
        if not self.oidc_audience.strip():
            problems.append("SECP_OIDC_AUDIENCE must be non-empty in production")
        # OIDC-B (ADR-018): the public browser client id must be present in production (it is not a
        # secret; a public client has none). Its length bound is Field-validated in every env.
        if not self.oidc_web_client_id.strip():
            problems.append(
                "SECP_OIDC_WEB_CLIENT_ID must be a non-empty public client id in production"
            )
        if problems:
            raise ValueError("unsafe production configuration refused: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
