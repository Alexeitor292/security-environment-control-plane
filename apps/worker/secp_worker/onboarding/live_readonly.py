"""Dormant, default-disabled live read-only collection orchestration (SECP-002B-1B-4).

Worker-only. This is the ONLY entry point that can reach the plugin's
``LiveReadOnlyProxmoxCollector``, and it is **not wired to the API, dispatcher, UI, environment
variables, Compose, or the normal onboarding-preflight lifecycle**. It enforces, in order:

1. a **default-disabled** gate — refused before anything else;
2. an **immutable binding** — validated (complete, unexpired, internally consistent, matching
   the current collector-contract + endpoint-allowlist versions) before any secret resolution
   or transport construction;

only then does it resolve an opaque ``secret_ref`` via an injected worker ``SecretResolver`` and
build a transport via an injected factory, and run the collector. It returns an **in-memory**
provider-neutral observed dict — it NEVER persists evidence, creates a ``TargetEvidenceRecord``,
adds a live evidence source to any persistence flow, or unseals
``SealedProviderTargetEvidenceCollector``. No real target/endpoint/credential/secret backend is
introduced. A later, separately-authorized activation PR is required to reach this outside unit
tests.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from secp_api.enums import VerificationLevel
from secp_plugin_proxmox.live_collector import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    LiveReadOnlyProxmoxCollector,
)
from secp_plugin_proxmox.readonly_policy import PROXMOX_READONLY_POLICY_VERSION
from secp_plugin_proxmox.transport import ReadOnlyHttpTransport

from secp_worker.secrets import SecretResolver

# A transport factory receives the just-resolved token and returns a read-only transport.
TransportFactory = Callable[[str], ReadOnlyHttpTransport]

_STRING_FIELDS = (
    "execution_target_id",
    "target_config_hash",
    "onboarding_id",
    "boundary_hash",
    "authorization_id",
    "authorization_expiry",
    "evidence_source",
    "verification_level",
    "collector_contract_version",
    "endpoint_allowlist_version",
)


class LiveReadCollectionDisabled(Exception):
    """Raised when the default-disabled live read-only gate is not explicitly enabled."""


class InvalidLiveReadBinding(Exception):
    """Raised when the immutable live-read binding is missing, expired, malformed, or
    internally inconsistent — before any secret resolution or transport construction."""


@dataclass(frozen=True)
class LiveReadCollectionGate:
    """Default-**disabled** gate. Not wired to env/Compose/API settings/UI/runtime endpoint in
    this PR. Tests may construct an explicitly enabled gate through direct injection only."""

    enabled: bool = False


@dataclass(frozen=True)
class LiveReadCollectionBinding:
    """Immutable live-read collection context. All fields are required; the collector refuses a
    binding that is incomplete, expired, malformed, or internally inconsistent."""

    execution_target_id: str
    target_config_hash: str
    onboarding_id: str
    boundary_hash: str
    authorization_id: str
    authorization_version: int
    authorization_expiry: str  # canonical ISO-8601 UTC, e.g. "2026-07-02T00:00:00Z"
    evidence_source: str
    verification_level: str
    collector_contract_version: str
    endpoint_allowlist_version: str

    def assert_valid(self, *, now: datetime) -> None:
        missing = [f for f in _STRING_FIELDS if not str(getattr(self, f, "")).strip()]
        if missing:
            raise InvalidLiveReadBinding(f"missing binding fields: {sorted(missing)}")
        if not isinstance(self.authorization_version, int) or self.authorization_version < 1:
            raise InvalidLiveReadBinding("authorization_version must be a positive integer")
        expiry = _parse_canonical_utc(self.authorization_expiry)
        if expiry <= now:
            raise InvalidLiveReadBinding("authorization has expired")
        # Internal consistency: this is the LIVE path with the current contract + allowlist.
        if self.verification_level != VerificationLevel.live_verified.value:
            raise InvalidLiveReadBinding(
                "live read binding requires verification_level=live_verified"
            )
        if self.evidence_source != LIVE_READ_EVIDENCE_SOURCE:
            raise InvalidLiveReadBinding("evidence_source is not the live read-only Proxmox source")
        if self.collector_contract_version != LIVE_READ_COLLECTOR_CONTRACT_VERSION:
            raise InvalidLiveReadBinding("collector contract version mismatch")
        if self.endpoint_allowlist_version != PROXMOX_READONLY_POLICY_VERSION:
            raise InvalidLiveReadBinding("endpoint allowlist version mismatch")


def _parse_canonical_utc(value: str) -> datetime:
    try:
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ValueError
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError) as exc:
        raise InvalidLiveReadBinding(
            "authorization_expiry must be a canonical ISO-8601 UTC timestamp ending in 'Z'"
        ) from exc
    if parsed.tzinfo is None:
        raise InvalidLiveReadBinding("authorization_expiry must be timezone-aware UTC")
    return parsed


def run_live_readonly_collection(
    *,
    gate: LiveReadCollectionGate,
    binding: LiveReadCollectionBinding,
    secret_ref: str,
    secret_resolver: SecretResolver,
    transport_factory: TransportFactory,
    declared_boundary: dict,
    now: datetime | None = None,
) -> dict:
    """Run the dormant live read-only collection. Returns an in-memory observed dict.

    Fails closed on a disabled gate (before anything) and on an invalid/expired/inconsistent
    binding (before secret resolution or transport construction). Never persists evidence.
    """
    now = now or datetime.now(UTC)
    # 1. Default-disabled gate — refuse before resolver, transport, endpoint, request, evidence.
    if not gate.enabled:
        raise LiveReadCollectionDisabled(
            "live read-only collection is disabled by default (SECP-002B-1B-4); a separately "
            "authorized activation is required before it can be reached outside unit tests"
        )
    # 2. Immutable binding — refuse before secret resolution or transport construction.
    binding.assert_valid(now=now)
    # 3. Only now: resolve the opaque secret (transient; never stored/logged/hashed/audited).
    credential = secret_resolver.resolve(secret_ref)
    # 4. Build the transport (injected fake in tests) and run the plugin collector.
    transport = transport_factory(credential.reveal_secret())
    return LiveReadOnlyProxmoxCollector().collect(transport, declared_boundary=declared_boundary)
