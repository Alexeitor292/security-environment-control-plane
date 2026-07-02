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

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from secp_api.enums import VerificationLevel
from secp_plugin_proxmox.live_collector import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
    LiveReadOnlyProxmoxCollector,
)
from secp_plugin_proxmox.readonly_policy import PROXMOX_READONLY_POLICY_VERSION
from secp_plugin_proxmox.target_config import (
    ProxmoxTargetConfigError,
    ValidatedProxmoxTargetConfig,
    parse_proxmox_target_config,
)
from secp_plugin_proxmox.transport import ReadOnlyHttpTransport

from secp_worker.secrets import SecretResolver

# A transport factory receives the VALIDATED target config (never a raw dict) + the just-resolved
# transient token, and returns a read-only transport. The validated config — not a separate
# factory choice — controls the destination the future transport connects to.
TransportFactory = Callable[[ValidatedProxmoxTargetConfig, str], ReadOnlyHttpTransport]

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


class LiveReadAuthorizationDenied(Exception):
    """Raised when the authorization verifier does not approve the binding."""


class CanonicalizationError(Exception):
    """Raised when an object cannot be canonicalized (NaN/inf/unsupported type)."""


_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical_json(obj: object) -> str:
    """Deterministic JSON: sorted keys, compact separators, UTF-8, no NaN/inf, no unsupported
    types (``json.dumps`` raises ``ValueError`` on NaN/inf and ``TypeError`` on unknown types)."""
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def canonical_sha256(obj: object) -> str:
    """``sha256:<hex>`` over the canonical JSON encoding of ``obj``."""
    try:
        encoded = canonical_json(obj).encode("utf-8")
    except (ValueError, TypeError) as exc:
        raise CanonicalizationError(
            "object is not canonicalizable (NaN/inf or unsupported type)"
        ) from exc
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@runtime_checkable
class LiveReadAuthorizationVerifier(Protocol):
    """Worker-only seam that must approve the immutable binding before secret resolution.

    Only fake test implementations exist in this PR — there is no real authorization backend.
    """

    def verify(self, binding: LiveReadCollectionBinding, *, now: datetime) -> bool: ...


def _assert_hash_matches(obj: object, expected: str, label: str) -> None:
    if not isinstance(expected, str) or not _DIGEST_RE.match(expected):
        raise InvalidLiveReadBinding(f"{label} hash is malformed")
    try:
        actual = canonical_sha256(obj)
    except CanonicalizationError as exc:
        raise InvalidLiveReadBinding(f"{label} could not be canonicalized: {exc}") from exc
    if actual != expected:
        raise InvalidLiveReadBinding(f"{label} hash mismatch")


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
    target_config: dict,
    declared_boundary: dict,
    secret_ref: str,
    secret_resolver: SecretResolver,
    transport_factory: TransportFactory,
    authorization_verifier: LiveReadAuthorizationVerifier,
    now: datetime | None = None,
) -> dict:
    """Run the dormant live read-only collection. Returns an in-memory observed dict.

    Fail-closed sequence (each step must pass before the next runs):

    a. **gate** — a disabled gate refuses before parse, hashes, the verifier, resolver, transport
       factory, collector, or any persistence code is touched;
    b. **binding structure** — completeness/expiry/internal-consistency;
    c. **parse/validate config** — the raw ``target_config`` is parsed into the plugin-owned,
       secret-free ``ValidatedProxmoxTargetConfig`` (rejects unknown/secret/nested/typed fields);
    d-e. **target-config hash** — canonical hash of the validated model's binding representation,
       compared to ``binding.target_config_hash``;
    f. **boundary hash** — recomputed from ``declared_boundary`` and compared to
       ``binding.boundary_hash``;
    g. **credential reference** — the validated ``credential_ref`` must equal the supplied
       ``secret_ref`` by exact in-memory equality (never logged/hashed);
    h. **authorization** — the verifier must approve the binding (before secret resolution);
    i. **secret resolution** — transient credential via the injected resolver;
    j-k. **transport + collect** — transport built from the VALIDATED config (never a raw dict)
       + transient token; returns in-memory observed data only.

    It never persists evidence, creates a ``TargetEvidenceRecord``, or unseals live evidence.
    """
    now = now or datetime.now(UTC)
    # a. Default-disabled gate — before parse / hashes / verifier / resolver / transport.
    if not gate.enabled:
        raise LiveReadCollectionDisabled(
            "live read-only collection is disabled by default (SECP-002B-1B-4); a separately "
            "authorized activation is required before it can be reached outside unit tests"
        )
    # b. Immutable binding structure.
    binding.assert_valid(now=now)
    # c. Parse/validate the target config into the plugin-owned secret-free model BEFORE any
    #    hashing. Rejected raw values are never logged, hashed, or returned.
    try:
        validated_config = parse_proxmox_target_config(target_config)
    except ProxmoxTargetConfigError as exc:
        raise InvalidLiveReadBinding(f"invalid target configuration: {exc}") from exc
    # d-e. Canonical-hash ONLY the validated model's secret-free binding representation and match.
    _assert_hash_matches(
        validated_config.binding_representation(),
        binding.target_config_hash,
        "target configuration",
    )
    # f. Recompute + match the declared-boundary hash.
    _assert_hash_matches(declared_boundary, binding.boundary_hash, "declared boundary")
    # g. Opaque credential-reference binding — exact in-memory equality only (ref never hashed).
    if secret_ref != validated_config.credential_ref:
        raise InvalidLiveReadBinding(
            "supplied secret reference does not match the target credential reference"
        )
    # h. Authorization verification — must approve before any secret resolution.
    if not authorization_verifier.verify(binding, now=now):
        raise LiveReadAuthorizationDenied("authorization was not verified for this binding")
    # i. Resolve the opaque secret (transient; never stored/logged/hashed/audited/returned).
    credential = secret_resolver.resolve(secret_ref)
    # j. Build the transport bound to the VALIDATED config (never a raw dict) + transient token.
    transport = transport_factory(validated_config, credential.reveal_secret())
    # k. Run the plugin collector; return in-memory observed data only.
    return LiveReadOnlyProxmoxCollector().collect(transport, declared_boundary=declared_boundary)
