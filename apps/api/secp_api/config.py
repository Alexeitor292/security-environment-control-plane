"""Application configuration.

All values come from the environment / ``.env`` (git-ignored). ``.env.example``
documents every key with development-only placeholders. No real secrets are ever
committed (Charter §13).
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# OIDC-C (ADR-019): the canonical public application origin is bounded and never path-bearing.
_PUBLIC_ORIGIN_MAX_LENGTH = 255


def _canonicalize_origin(value: str) -> tuple[str, str]:
    """Normalize an origin to ``(canonical_origin_without_trailing_slash, host_without_port)``.

    Pure normalization — no validation (callers validate separately). Only the host is lowercased
    (hostnames are case-insensitive by spec); a scheme://host[:port] form is rebuilt with any
    trailing slash removed. No path is ever carried (a valid public origin has none).
    """
    parsed = urlsplit(value.strip())
    host = parsed.hostname or ""
    netloc = f"{host}:{parsed.port}" if parsed.port is not None else host
    if parsed.scheme and netloc:
        return f"{parsed.scheme}://{netloc}", host
    # Malformed (validated elsewhere): best-effort trailing-slash strip, no other transformation.
    return value.strip().rstrip("/"), host


def _loopback_or_ambiguous_problem(hostname: str) -> str | None:
    """Return a problem for a host that must never be a PRODUCTION public origin: ``localhost`` /
    any ``*.localhost`` / any IP loopback (all IPv4 ``127.0.0.0/8``, and compressed, expanded, and
    IPv4-mapped IPv6 loopback) / a trailing-dot host. IP detection uses the stdlib ``ipaddress``
    parser (not a literal list). Performs NO DNS resolution and never rejects an ordinary private
    enterprise DNS name merely because it might resolve internally."""
    host = hostname.lower()
    if host.endswith("."):
        return "SECP_PUBLIC_ORIGIN host must not end with '.' in production"
    if host == "localhost" or host.endswith(".localhost"):
        return "SECP_PUBLIC_ORIGIN must not be a localhost host in production"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None  # a DNS name (possibly private-enterprise) — allowed; never resolved here
    if ip.is_loopback:
        return "SECP_PUBLIC_ORIGIN must not be a loopback IP in production"
    mapped = getattr(ip, "ipv4_mapped", None)  # IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1)
    if mapped is not None and mapped.is_loopback:
        return "SECP_PUBLIC_ORIGIN must not be an IPv4-mapped loopback IP in production"
    return None


def _public_origin_problems(
    value: str, *, require_https: bool, forbid_loopback: bool = False
) -> list[str]:
    """Validate a public application origin (ADR-019). Empty == valid. No DNS/network access."""
    raw = value.strip()
    if not raw:
        return ["SECP_PUBLIC_ORIGIN must be set"]
    problems: list[str] = []
    if len(raw) > _PUBLIC_ORIGIN_MAX_LENGTH:
        problems.append(
            f"SECP_PUBLIC_ORIGIN must be at most {_PUBLIC_ORIGIN_MAX_LENGTH} characters"
        )
    if "*" in raw:
        problems.append("SECP_PUBLIC_ORIGIN must not contain a wildcard")
    parsed = urlsplit(raw)
    try:
        hostname = parsed.hostname
        _ = parsed.port  # a malformed port / malformed bracketed IPv6 raises here
    except ValueError:
        problems.append("SECP_PUBLIC_ORIGIN is malformed")
        return problems  # cannot reason further about a malformed authority — fail closed
    if require_https:
        if parsed.scheme != "https":
            problems.append("SECP_PUBLIC_ORIGIN must use https:// in production")
    elif parsed.scheme not in ("http", "https"):
        problems.append("SECP_PUBLIC_ORIGIN must be an http(s) origin")
    if parsed.username or parsed.password or "@" in parsed.netloc:
        problems.append("SECP_PUBLIC_ORIGIN must not contain credentials (userinfo)")
    if parsed.query or parsed.fragment:
        problems.append("SECP_PUBLIC_ORIGIN must not contain a query or fragment")
    if parsed.path not in ("", "/"):
        problems.append("SECP_PUBLIC_ORIGIN must not contain a path")
    if not hostname:
        problems.append("SECP_PUBLIC_ORIGIN must contain a host")
    else:
        # A bracketed IPv6 literal (the netloc has '[') must be a syntactically valid IPv6 address.
        if "[" in parsed.netloc and ":" in hostname:
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                problems.append("SECP_PUBLIC_ORIGIN has a malformed IPv6 host")
        if forbid_loopback:
            loopback_problem = _loopback_or_ambiguous_problem(hostname)
            if loopback_problem:
                problems.append(loopback_problem)
    return problems


def _cors_origin_problems(origins: list[str]) -> list[str]:
    """Validate CORS allow-origins in any environment (ADR-019). Each must be an exact,
    wildcard-free http(s) origin: no ``*``, protocol-relative, path/query/fragment, or userinfo."""
    problems: list[str] = []
    for origin in origins:
        raw = origin.strip()
        if "*" in raw:  # reject "*" AND any wildcard-bearing origin (e.g. https://*.evil.test)
            problems.append(f"must not contain a wildcard: {origin!r}")
            continue
        if raw.startswith("//"):
            problems.append(f"protocol-relative origin is forbidden: {origin!r}")
            continue
        parsed = urlsplit(raw)
        if parsed.scheme not in ("http", "https"):
            problems.append(f"origin must be an http(s) origin: {origin!r}")
        if parsed.username or parsed.password or "@" in parsed.netloc:
            problems.append(f"origin must not contain userinfo: {origin!r}")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            problems.append(f"origin must not contain a path/query/fragment: {origin!r}")
        if not parsed.hostname:
            problems.append(f"origin must contain a host: {origin!r}")
    return problems


def _internal_health_host_problems(value: str) -> list[str]:
    """Validate the optional production internal health host (ADR-019): a bare hostname only."""
    raw = value.strip()
    if not raw:
        return ["SECP_INTERNAL_HEALTH_HOST must be non-empty when set"]
    problems: list[str] = []
    if "*" in raw:
        problems.append("SECP_INTERNAL_HEALTH_HOST must not contain a wildcard")
    if any(ch in raw for ch in ("/", "@", ":")) or "://" in raw:
        problems.append("SECP_INTERNAL_HEALTH_HOST must be a bare hostname (no scheme/port/path)")
    return problems


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

    # OIDC-C (ADR-019): the ONE canonical public application origin. In production the web app and
    # the SECP API are served from this SAME origin (so CORS is disabled) and the browser
    # callback/logout URLs derive from it. Production requires an exact HTTPS origin (scheme https,
    # a host, no userinfo/query/fragment, no path beyond '/', no wildcard, bounded length).
    # Development may use the Vite dev origin. It is NOT returned to the browser (which knows its
    # own origin); it drives the production Host allowlist and operator preflight only.
    public_origin: str = "http://localhost:5173"
    # OIDC-C (ADR-019): an OPTIONAL additional internal hostname the production edge/load balancer
    # uses for liveness (e.g. a cluster-internal service name). Empty by default; a bare hostname
    # when set (never '*'). It only widens the Host allowlist; it never relaxes token verification.
    internal_health_host: str = ""

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def public_origin_canonical(self) -> str:
        """The canonical public origin (scheme://host[:port], no trailing slash)."""
        return _canonicalize_origin(self.public_origin)[0]

    @property
    def public_origin_host(self) -> str:
        """The public origin's host (no port) — the production Host allowlist entry."""
        return _canonicalize_origin(self.public_origin)[1]

    @property
    def oidc_callback_url(self) -> str:
        """The exact browser Authorization Code callback URL derived from the public origin."""
        return self.public_origin_canonical + "/auth/callback"

    @property
    def oidc_logout_url(self) -> str:
        """The exact browser post-logout URL derived from the public origin."""
        return self.public_origin_canonical + "/login"

    def trusted_hosts(self) -> list[str] | None:
        """Allowed Host-header values for the production TrustedHost middleware, or ``None`` to skip
        the middleware entirely (development/test convenience). Never contains '*'."""
        if not self.is_production:
            return None
        hosts = [self.public_origin_host]
        internal = self.internal_health_host.strip()
        if internal:
            hosts.append(internal)
        return hosts

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
        # --- OIDC-C (ADR-019): same-origin production deployment guardrails -----------------------
        # The canonical public origin must be a safe exact HTTPS origin (callback/logout/Host derive
        # from it). CORS is disabled because the browser and API are same-origin — any configured
        # origin is refused (fail closed, never silently emptied). The optional internal health
        # host, when set, must be a bare hostname so it never widens Host trust arbitrarily.
        problems.extend(
            _public_origin_problems(self.public_origin, require_https=True, forbid_loopback=True)
        )
        if self.cors_allow_origins:
            problems.append(
                "SECP_CORS_ALLOW_ORIGINS must be empty in production "
                "(the browser and API are same-origin; no CORS is used)"
            )
        if self.internal_health_host.strip():
            problems.extend(_internal_health_host_problems(self.internal_health_host))
        if problems:
            raise ValueError("unsafe production configuration refused: " + "; ".join(problems))
        return self

    @model_validator(mode="after")
    def _validate_cors_origin_shape(self) -> Settings:
        """CORS allow-origins (in EVERY environment) must be exact, wildcard-free http(s) origins —
        never '*', protocol-relative, or path/query/fragment/userinfo-bearing. Fails closed; unsafe
        values are refused, never silently rewritten."""
        problems = _cors_origin_problems(self.cors_allow_origins)
        if problems:
            raise ValueError("invalid SECP_CORS_ALLOW_ORIGINS: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
