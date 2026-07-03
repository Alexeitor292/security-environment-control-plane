"""Dormant, default-disabled live read-only collection orchestration (SECP-002B-1B-4/1B-5).

Worker-only. This is the ONLY entry point that can reach the plugin's
``LiveReadOnlyProxmoxCollector``, and it is **not wired to the API, dispatcher, UI, environment
variables, Compose, or the normal onboarding-preflight lifecycle**. It enforces, in order:

1. a **default-disabled** gate — refused before anything else;
2. an **immutable binding** — validated (complete, unexpired, internally consistent, matching
   the current collector-contract + endpoint-allowlist versions);
3. **trusted-record identity** — the binding must name, and the ``ExecutionTarget`` /
   ``TargetOnboarding`` records must agree on, one authoritative identity+relationship
   (SECP-002B-1B-5). The target configuration, declared boundary, and opaque credential reference
   are derived **exclusively** from those two authoritative records — a caller cannot supply them
   independently — before any secret resolution or transport construction.

only then does it resolve the target's own opaque ``secret_ref`` via an injected worker
``SecretResolver`` and build a transport via an injected factory, and run the collector. It
returns an **in-memory** provider-neutral observed dict — it NEVER persists evidence, creates a
``TargetEvidenceRecord``, adds a live evidence source to any persistence flow, or unseals
``SealedProviderTargetEvidenceCollector``. It never queries the database itself. No real
target/endpoint/credential/secret backend is introduced. A later, separately-authorized
activation PR is required to reach this outside unit tests.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from secp_api.enums import VerificationLevel
from secp_plugin_proxmox.live_collector import (
    LIVE_READ_COLLECTOR_CONTRACT_VERSION,
    LIVE_READ_EVIDENCE_SOURCE,
)
from secp_plugin_proxmox.readonly_policy import PROXMOX_READONLY_POLICY_VERSION
from secp_plugin_proxmox.target_config import (
    ProxmoxTargetConfigError,
    ValidatedProxmoxTargetConfig,
    parse_proxmox_target_config,
)
from secp_plugin_proxmox.transport import ReadOnlyHttpTransport

from secp_worker.secrets import SecretResolver

if TYPE_CHECKING:  # imported only for type hints — the runner never queries the database itself
    from secp_api.models import ExecutionTarget, TargetOnboarding

# The only provider plugin whose live read-only collector exists. A target bound to any other
# plugin is refused before any sensitive step.
PROXMOX_PLUGIN_NAME = "proxmox"

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
    "credential_ref",
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


class UntrustedRecordBinding(InvalidLiveReadBinding):
    """Raised when the binding's identity, or the target↔onboarding relationship, does not match
    the authoritative ``ExecutionTarget`` / ``TargetOnboarding`` records.

    A subclass of :class:`InvalidLiveReadBinding` so existing fail-closed handling still catches
    it. Its messages are deliberately generic — they never expose secret references, credential
    references, configuration values, or record contents.
    """


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


@runtime_checkable
class LiveReadTargetCollector(Protocol):
    """Injected collector seam. Production code must not instantiate collectors directly."""

    def collect(self, transport: ReadOnlyHttpTransport, *, declared_boundary: dict) -> dict: ...


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


@dataclass(frozen=True, repr=False)
class LiveReadCollectionBinding:
    """Immutable live-read collection context. All fields are required; the collector refuses a
    binding that is incomplete, expired, malformed, or internally inconsistent."""

    execution_target_id: str
    # Canonical hash of the VALIDATED Proxmox connection representation (base_url + verify_tls
    # only) — NOT necessarily the persisted ``ExecutionTarget.config_hash`` format. The opaque
    # credential reference is never part of this hash.
    target_config_hash: str
    onboarding_id: str
    boundary_hash: str
    authorization_id: str
    authorization_version: int
    authorization_expiry: str  # canonical ISO-8601 UTC, e.g. "2026-07-02T00:00:00Z"
    # Opaque credential reference — bound ONLY by exact in-memory equality, NEVER hashed/logged.
    credential_ref: str
    evidence_source: str
    verification_level: str
    collector_contract_version: str
    endpoint_allowlist_version: str

    def __repr__(self) -> str:
        return (
            "LiveReadCollectionBinding("
            f"execution_target_id={self.execution_target_id!r}, "
            f"target_config_hash={self.target_config_hash!r}, "
            f"onboarding_id={self.onboarding_id!r}, "
            f"boundary_hash={self.boundary_hash!r}, "
            f"authorization_id={self.authorization_id!r}, "
            f"authorization_version={self.authorization_version!r}, "
            f"authorization_expiry={self.authorization_expiry!r}, "
            "credential_ref=<redacted>, "
            f"evidence_source={self.evidence_source!r}, "
            f"verification_level={self.verification_level!r}, "
            f"collector_contract_version={self.collector_contract_version!r}, "
            f"endpoint_allowlist_version={self.endpoint_allowlist_version!r})"
        )

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


def _assert_trusted_records(
    binding: LiveReadCollectionBinding,
    execution_target: ExecutionTarget,
    onboarding: TargetOnboarding,
) -> None:
    """Fail closed unless the binding names, and the two records agree on, one authoritative
    identity. Runs BEFORE config parsing, hashing, authorization, secret resolution, transport
    construction, collection, and any persistence. Errors are generic — no reference/value leaks.
    """
    # The binding must name the exact authoritative records it was issued for.
    if str(binding.execution_target_id) != str(execution_target.id):
        raise UntrustedRecordBinding("binding execution target does not match the trusted record")
    if str(binding.onboarding_id) != str(onboarding.id):
        raise UntrustedRecordBinding("binding onboarding does not match the trusted record")
    # The onboarding must belong to this execution target, within the same organization.
    if onboarding.execution_target_id != execution_target.id:
        raise UntrustedRecordBinding("onboarding does not belong to the execution target")
    if onboarding.organization_id != execution_target.organization_id:
        raise UntrustedRecordBinding("onboarding and execution target organizations differ")
    # Only the Proxmox live collector exists; any other plugin is refused.
    if execution_target.plugin_name != PROXMOX_PLUGIN_NAME:
        raise UntrustedRecordBinding("execution target is not a proxmox target")
    # The target must carry an opaque credential reference (never a secret value).
    secret_ref = execution_target.secret_ref
    if not (isinstance(secret_ref, str) and secret_ref.strip()):
        raise UntrustedRecordBinding("execution target has no usable credential reference")


def _derive_parser_input(execution_target: ExecutionTarget) -> dict:
    """Build the plugin parser input in worker memory only, from the authoritative record:
    the secret-free stored ``config`` plus a ``credential_ref`` derived from the target's opaque
    ``secret_ref``. The stored config must remain connection-only — it must NOT itself carry a
    credential reference. Never mutates the ORM record."""
    raw_config = execution_target.config
    if not isinstance(raw_config, dict):
        raise InvalidLiveReadBinding("execution target configuration is not an object")
    if "credential_ref" in raw_config:
        # The credential reference must come ONLY from the target's secret_ref, never the config.
        raise InvalidLiveReadBinding(
            "execution target configuration must not carry a credential reference"
        )
    return {**raw_config, "credential_ref": execution_target.secret_ref}


def run_live_readonly_collection(
    *,
    gate: LiveReadCollectionGate,
    binding: LiveReadCollectionBinding,
    execution_target: ExecutionTarget,
    onboarding: TargetOnboarding,
    secret_resolver: SecretResolver,
    transport_factory: TransportFactory,
    collector: LiveReadTargetCollector,
    authorization_verifier: LiveReadAuthorizationVerifier,
    now: datetime | None = None,
) -> dict:
    """Run the dormant live read-only collection. Returns an in-memory observed dict.

    The target configuration, declared boundary, and opaque credential reference are derived
    **exclusively** from the authoritative ``execution_target`` (:class:`ExecutionTarget`) and
    ``onboarding`` (:class:`TargetOnboarding`) records — a caller cannot supply them
    independently. This runner never queries the database itself; a future, separately-authorized
    activation workflow is responsible for loading those trusted ORM records before calling it.

    Fail-closed sequence (each step must pass before the next runs):

    a. **gate** — a disabled gate refuses before identity checks, parse, hashes, the verifier,
       resolver, transport factory, collector, or any persistence code is touched;
    b. **binding structure** — completeness/expiry/internal-consistency;
    c. **trusted records** — the binding identity and the target↔onboarding relationship must
       match the authoritative records (:func:`_assert_trusted_records`);
    d. **derive inputs** — the config, boundary, and credential reference are taken ONLY from the
       trusted records (in worker memory; the ORM records are never mutated);
    e. **parse/validate config** — the derived config is parsed into the plugin-owned,
       secret-free ``ValidatedProxmoxTargetConfig`` (rejects unknown/secret/nested/typed fields);
    f. **connection hash** — canonical hash of the validated model's connection representation
       (ONLY ``base_url`` + ``verify_tls``; ``credential_ref`` is never hashed), compared to
       ``binding.target_config_hash``;
    g. **boundary hash** — recomputed from ``onboarding.declared_boundary`` and compared to
       ``binding.boundary_hash``;
    h. **credential reference** — exact three-way in-memory equality
       ``binding.credential_ref == validated_config.credential_ref == execution_target.secret_ref``
       (never hashed/logged; the mismatch error never echoes the reference);
    i. **authorization** — the verifier must approve the binding (before secret resolution);
    j. **secret resolution** — transient credential via the injected resolver, keyed by the
       target's own ``secret_ref``;
    k-l. **transport + collect** — transport built from the VALIDATED config (never a raw dict)
       + transient token; an injected collector returns in-memory observed data only.

    It never persists evidence, creates a ``TargetEvidenceRecord``, or unseals live evidence.
    """
    now = now or datetime.now(UTC)
    # a. Default-disabled gate — before identity / parse / hashes / verifier / resolver / transport.
    if not gate.enabled:
        raise LiveReadCollectionDisabled(
            "live read-only collection is disabled by default (SECP-002B-1B-4); a separately "
            "authorized activation is required before it can be reached outside unit tests"
        )
    # b. Immutable binding structure.
    binding.assert_valid(now=now)
    # c. Authoritative identity + relationship validation — before any sensitive step.
    _assert_trusted_records(binding, execution_target, onboarding)
    # d. Derive the config / boundary / credential reference ONLY from the trusted records.
    parser_input = _derive_parser_input(execution_target)
    declared_boundary = onboarding.declared_boundary
    # e. Parse/validate the derived config into the plugin-owned secret-free model BEFORE any
    #    hashing. Rejected values are never logged, hashed, or returned; the error stays generic.
    try:
        validated_config = parse_proxmox_target_config(parser_input)
    except ProxmoxTargetConfigError as exc:
        raise InvalidLiveReadBinding("invalid target configuration") from exc
    # f. Canonical-hash ONLY the connection identity (base_url + verify_tls). The opaque
    #    credential_ref is deliberately NOT part of this hash.
    _assert_hash_matches(
        validated_config.connection_representation(),
        binding.target_config_hash,
        "target configuration",
    )
    # g. Recompute + match the declared-boundary hash from the onboarding record.
    _assert_hash_matches(declared_boundary, binding.boundary_hash, "declared boundary")
    # h. Opaque credential reference — bound ONLY by exact three-way in-memory equality
    #    (binding == validated config == the target's own secret_ref). Never hashed/logged; the
    #    error never echoes the reference value.
    if not (
        binding.credential_ref == validated_config.credential_ref == execution_target.secret_ref
    ):
        raise InvalidLiveReadBinding(
            "credential reference mismatch (binding / validated config / trusted target record)"
        )
    # i. Authorization verification — must approve before any secret resolution.
    if not authorization_verifier.verify(binding, now=now):
        raise LiveReadAuthorizationDenied("authorization was not verified for this binding")
    # j. Resolve the opaque secret (transient; never stored/logged/hashed/audited/returned),
    #    keyed by the trusted target's own secret_ref.
    credential = secret_resolver.resolve(execution_target.secret_ref)
    # k. Build the transport bound to the VALIDATED config (never a raw dict) + transient token.
    transport = transport_factory(validated_config, credential.reveal_secret())
    # l. Run the plugin collector; return in-memory observed data only.
    return collector.collect(transport, declared_boundary=declared_boundary)
