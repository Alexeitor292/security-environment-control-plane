"""Pure, versioned, secret-free readiness contract (SECP-002B-1B, B1B-PR4 / ADR-021).

The shared vocabulary for the two SEPARATE durable readiness operations — remote-state readiness
and plan-secret readiness. It is consumed by the control-plane API (enqueue + read models) and by
the worker (which owns every external contact), so both derive the SAME authoritative binding,
operation fingerprint, and evidence hash.

This module performs NO I/O. It imports no worker, plugin, transport, HTTP, subprocess, adapter,
resolver, or secret code. It never sees — and can never persist — a backend URL, endpoint, bucket /
container / object name, state key or path, TLS fingerprint, token, credential, or secret reference.

**No durable value is a direct digest of an enumerable backend locator.** (An unsalted digest of a
low-entropy locator is a confirmation oracle: an actor who guesses the bucket/URL can confirm the
guess from the read model.) The remote-state backend is therefore represented ONLY as:

* a bounded ``backend_class`` (``remote`` / ``local`` / ``unknown``);
* the **exact immutable `ToolchainProfile` content hash** — the already-approved, high-entropy hash
  over the whole pinned profile — as the backend BINDING anchor; and
* an opaque, deterministic, collision-resistant ``state_namespace_identity`` derived only from
  server-owned **UUIDs and content hashes** — never from a backend reference, a caller-selected key,
  or a mutable display name.

External proof ids are required to be **UUIDs**, so a proof id can never *be* (nor be a digest of) a
bucket name, hostname, or state-file name.

Readiness is a DECISION-FREE VALIDATION POSTURE. Nothing here plans, applies, destroys, renders,
resolves, or advances a phase; a ``ready`` outcome authorizes no execution.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from secp_api.enums import (
    PlanSecretPurpose,
    PlanSecretReadinessFacet,
    ReadinessOperationKind,
    RemoteStateReadinessFacet,
)

# ---------------------------------------------------------------------------------------------
# Versions. Bump any of these on ANY change to the corresponding contract; each is folded into the
# operation fingerprint, so a bump correctly invalidates every prior readiness record (a new
# fingerprint => a new operation => a new immutable evidence row; history is never mutated).
# ---------------------------------------------------------------------------------------------

READINESS_POLICY_VERSION = "secp-002b-1b-pr4/readiness-policy/v1"

# The provider-neutral remote-state readiness adapter contract. The worker refuses any adapter whose
# ``contract_version`` differs; a deployment-local adapter is NEVER discovered from an environment
# variable, backend kind, PATH, installed SDK, URL string, or caller data — it is injected.
REMOTE_STATE_ADAPTER_CONTRACT_VERSION = "secp-002b-1b-pr4/remote-state-readiness-adapter/v1"

# The plan-secret resolver contract an authorization binds. Deliberately DISTINCT from the read-only
# preflight resolver contract (``RESOLVER_ADAPTER_CONTRACT_VERSION``): a live-read resolver
# authorization can never satisfy a provisioning-secret readiness gate.
PLAN_SECRET_RESOLVER_CONTRACT_VERSION = "secp-002b-1b-pr4/plan-secret-resolver/v1"

# The reviewed secret-backend self-test policy. The self-test proves the worker can AUTHENTICATE to
# the configured backend; it returns no target credential and no backend response body.
PLAN_SECRET_SELF_TEST_POLICY_VERSION = "secp-002b-1b-pr4/plan-secret-self-test/v1"

# The JIT child-process environment projection contract (see ``build_plan_secret_env``).
PLAN_SECRET_ENV_CONTRACT_VERSION = "secp-002b-1b-pr4/plan-secret-env/v1"

# Conservative bounded TTLs. Both are pinned to the eligibility TTL (6h) ON PURPOSE: a readiness
# record is collected AFTER its eligibility evidence, so the eligibility evidence always expires
# FIRST. An expired readiness record therefore always implies an expired (or drifted) eligibility
# binding, which REFUSES — and re-establishing eligibility yields a new evidence hash, hence a NEW
# operation fingerprint and a NEW readiness record. A shorter readiness TTL would strand an
# operation: its record would expire while its binding was still valid, and the exact-once success
# constraint would block a fresh `ready` row for the same fingerprint.
REMOTE_STATE_READINESS_TTL = timedelta(hours=6)
PLAN_SECRET_READINESS_TTL = timedelta(hours=6)

# Proof freshness windows. External backup / restore / encryption / lock proofs are VALIDATED, never
# invented: PR4 performs no backup and no restore against real state.
STATE_PROOF_MAX_AGE = timedelta(days=30)

# The durable, worker-owned, filesystem-only toolchain ATTESTATION record TTL. Pinned to the
# eligibility TTL for the same reason the readiness TTLs are: a readiness record is always collected
# AFTER its attestation, so an expired attestation always refuses the binding first.
TOOLCHAIN_ATTESTATION_TTL = timedelta(hours=6)

# The activation-dossier placeholder SENTINEL. **It FAILS CLOSED.** No deployment-local dossier is
# modelled yet, so this is the value the binding carries until a reviewed dossier supplies a real
# hash through the adapter activation. It can NEVER satisfy readiness:
#
#   * a controlled-live adapter capability cannot be issued with it;
#   * remote-state readiness cannot return ``ready`` with it;
#   * plan-secret readiness cannot return ``ready`` with it;
#   * ``ProvisioningReadinessStatus`` can never be current/ready with it;
#   * an audit record never represents it as approved deployment evidence.
#
# A real, reviewed, deployment-local dossier remains REQUIRED before controlled-live readiness can
# succeed.
READINESS_ACTIVATION_DOSSIER_PLACEHOLDER = "no-activation-dossier/b1b-pr4"


def is_placeholder_dossier(activation_dossier_hash: str) -> bool:
    """True when the dossier hash is the fail-closed placeholder (or empty/unset)."""
    return (
        not activation_dossier_hash
        or activation_dossier_hash == READINESS_ACTIVATION_DOSSIER_PLACEHOLDER
    )


# The exact allowlisted plan-read child-process environment variable(s). This is the COMPLETE set:
# ``build_plan_secret_env`` refuses any other key, and it never reads or mutates ``os.environ``.
PLAN_SECRET_ENV_ALLOWLIST: tuple[str, ...] = ("TF_VAR_pm_api_token",)

# Hard bounds on the durable evidence payload (defence against an adapter smuggling a state body,
# provider output, or backend response into evidence).
MAX_EVIDENCE_FACETS = 32
MAX_EVIDENCE_REASONS = 32
MAX_EVIDENCE_BYTES = 8 * 1024
MAX_ENV_VALUE_BYTES = 4096

# Every MANDATORY facet must pass explicitly for an operation to be ``ready``.
REQUIRED_REMOTE_STATE_FACETS: tuple[str, ...] = tuple(f.value for f in RemoteStateReadinessFacet)
REQUIRED_PLAN_SECRET_FACETS: tuple[str, ...] = tuple(f.value for f in PlanSecretReadinessFacet)

# Bounded backend classes. Anything that is not provably ``remote`` fails closed.
BACKEND_CLASS_REMOTE = "remote"
BACKEND_CLASS_LOCAL = "local"
BACKEND_CLASS_UNKNOWN = "unknown"

# Backend-kind tokens that are a local/file/disk state backend (or an empty kind). Kept byte-equal
# to the control-plane profile validator + the worker toolchain verifier so a local backend cannot
# slip past one layer.
LOCAL_STATE_TOKENS = frozenset({"local", "local-state", "localfs", "file", "disk", ""})

# Reviewed TLS posture. ``verify_tls=false`` is refused; there is no "insecure" mode.
TLS_MODE_VERIFIED = "verified"
TLS_MODE_DISABLED = "disabled"
TLS_MODE_UNKNOWN = "unknown"

# Reviewed trusted-identity policies for the state backend transport.
TRUSTED_IDENTITY_POLICIES = frozenset({"system_trust_store", "pinned_ca_bundle"})

# The exact backend actions a PLAN-ONLY operation may hold on the state namespace. Deletion and
# force-unlock are NOT here: a plan does not remove state, and force-unlock steals another owner's
# lock. Any additional action (or a wildcard / bucket-wide / administrative grant) is excessive.
PLAN_ALLOWED_STATE_ACTIONS = frozenset({"read", "write", "lock", "unlock_own"})
FORBIDDEN_STATE_ACTIONS = frozenset({"delete", "force_unlock", "admin", "list_all", "*"})

# Method names a state adapter may NEVER expose. The readiness contract has no state-body surface at
# all: there is no interface through which a state payload could be read, written, or returned.
FORBIDDEN_STATE_ADAPTER_METHODS: frozenset[str] = frozenset(
    {
        "get_state",
        "read_state",
        "download_state",
        "upload_state",
        "write_state",
        "put_state",
        "restore_state",
        "delete_state",
        "force_unlock",
    }
)

_FINGERPRINT_PREFIX = "secp-002b-1b-pr4/readiness-operation/v2"
_NAMESPACE_PREFIX = "secp-002b-1b-pr4/state-namespace/v2"
_NAMESPACE_MARKER_PREFIX = "secp-002b-1b-pr4/state-namespace-marker/v2"
_ATTESTATION_PREFIX = "secp-002b-1b-pr4/toolchain-attestation-operation/v1"


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def is_opaque_proof_id(value: object) -> bool:
    """External proof ids MUST be UUIDs — never a free label.

    A shape-bounded label (``[A-Za-z0-9._-]{1,120}``) is exactly the alphabet of a DNS hostname, an
    S3/GCS bucket name, a Vault mount, or a state-file name. Persisting it — **or a digest of it** —
    would put an enumerable backend locator (or a confirmation oracle for one) into durable
    evidence, the evidence hash, the audit log, and the API response. Requiring a UUID removes the
    leak AND the oracle: a UUID cannot *be* a locator, and its digest confirms nothing.
    """
    import uuid as _uuid

    if isinstance(value, _uuid.UUID):
        return True
    if not isinstance(value, str):
        return False
    try:
        _uuid.UUID(value)
    except ValueError:
        return False
    return True


def state_namespace_marker(namespace_identity: str) -> str:
    """The ONLY marker that may excuse an ALREADY-OCCUPIED state namespace (ADR-021 §D.9).

    It is derived SERVER-SIDE from the server-derived namespace identity, so an adapter cannot
    self-attest its way past an occupied namespace with a marker of its own choosing: it must
    present
    exactly this value, which it can only know if it is bound to exactly this operation's namespace.
    """
    return _sha256("|".join((_NAMESPACE_MARKER_PREFIX, namespace_identity)))


def toolchain_attestation_fingerprint(
    *,
    organization_id: str,
    execution_target_id: str,
    toolchain_profile_id: str,
    toolchain_profile_hash: str,
    worker_identity_registration_id: str,
    worker_identity_version: int,
    verifier_policy_version: str,
) -> str:
    """Exact-once fingerprint for ONE worker-local toolchain attestation attempt.

    It binds only server-owned identity + the immutable profile hash + the verifier policy version.
    It contains no path, no filename, no digest of on-disk content, and no environment value.
    """
    return _sha256(
        "|".join(
            (
                _ATTESTATION_PREFIX,
                organization_id,
                execution_target_id,
                toolchain_profile_id,
                toolchain_profile_hash,
                worker_identity_registration_id,
                str(worker_identity_version),
                verifier_policy_version,
            )
        )
    )


def state_namespace_identity(
    *,
    organization_id: str,
    execution_target_id: str,
    onboarding_id: str,
    manifest_id: str,
    manifest_content_hash: str,
    deployment_plan_id: str,
) -> str:
    """Deterministic, opaque, collision-resistant state-namespace identity (ADR-021 §D.3).

    Derived SOLELY from server-owned authoritative identity. It is never caller-selected, never
    derived from a mutable display name, and never reused across organizations (the organization id
    is part of the digest, so a cross-organization namespace produces a different identity and the
    ``namespace_identity`` facet fails closed).
    """
    return _sha256(
        "|".join(
            (
                _NAMESPACE_PREFIX,
                organization_id,
                execution_target_id,
                onboarding_id,
                manifest_id,
                manifest_content_hash,
                deployment_plan_id,
            )
        )
    )


def canonical_utc(value: datetime | None) -> str:
    """Canonical UTC ISO-8601 rendering so the API and a worker in another local timezone fold the
    same bytes into a fingerprint. A naive value is treated as UTC (SQLite drops tzinfo)."""
    if value is None:
        return ""
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def as_utc(value: datetime) -> datetime:
    """Treat a naive stored datetime as UTC (SQLite drops tzinfo; PostgreSQL preserves it)."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@dataclass(frozen=True, repr=False)
class ReadinessBinding:
    """The strict, immutable, authoritative readiness binding (ADR-021 §C).

    EVERY field is DERIVED from authoritative control-plane records by
    :func:`secp_api.readiness_binding.load_readiness_binding` — none is ever accepted from a caller,
    a request body, a Temporal argument, or an adapter. It is secret-free and endpoint-free: the
    remote-state backend appears only as the exact immutable ``toolchain_profile_hash`` (the backend
    BINDING anchor) plus a deterministic ``state_namespace_identity`` derived from server-owned
    UUIDs
    and content hashes. **No field is a digest of a backend reference or a secret reference.** The
    credential appears only as an OPAQUE ``credential_binding_id`` + version.

    ``__repr__`` is redacted so a binding can never leak into a log, exception, or test artefact.
    """

    # organization + immutable environment lineage
    organization_id: str
    environment_version_id: str
    environment_version_content_hash: str
    # plan / manifest
    deployment_plan_id: str
    deployment_plan_content_hash: str
    provisioning_manifest_id: str
    provisioning_manifest_content_hash: str
    # target + onboarding
    execution_target_id: str
    target_config_hash: str
    target_onboarding_id: str
    onboarding_boundary_hash: str
    effective_boundary_hash: str
    # exact current live eligibility evidence (B1B-PR3)
    eligibility_preflight_id: str
    eligibility_evidence_hash: str
    eligibility_policy_version: str
    eligibility_expires_at: str
    # exact toolchain profile + the DURABLE, worker-produced attestation record (B1B-PR2/PR4)
    toolchain_profile_id: str
    toolchain_profile_hash: str
    toolchain_attestation_policy_version: str
    toolchain_attestation_id: str
    toolchain_attestation_hash: str
    # remote state: the profile hash IS the backend binding anchor; the namespace is UUID-derived
    state_namespace_identity: str
    # OPAQUE credential binding — never a reference, never a hash of one
    credential_binding_id: str
    credential_binding_version: int
    # activation dossier + worker identity
    activation_dossier_hash: str
    worker_identity_registration_id: str
    worker_identity_version: int
    # operation + policy identity
    operation_kind: str
    readiness_policy_version: str
    adapter_contract_version: str
    # authorization (plan-secret readiness only; empty for remote-state readiness)
    authorization_id: str = ""
    authorization_version: int = 0
    authorization_expiry: str = ""
    # prior state readiness (plan-secret readiness only; empty for remote-state readiness)
    state_readiness_record_id: str = ""
    state_readiness_evidence_hash: str = ""

    def __repr__(self) -> str:
        return f"ReadinessBinding(operation_kind={self.operation_kind!r}, <redacted>)"

    def operation_fingerprint(self) -> str:
        """Deterministic, secret-free exact-once fingerprint over the COMPLETE binding (ADR-021 §J).

        A change to ANY security-relevant bound fact — environment version, plan, manifest, target
        config, onboarding boundary, eligibility evidence or expiry, eligibility policy, toolchain
        profile, attestation policy, **durable attestation record id/hash**, namespace identity,
        **opaque credential-binding id/version**, dossier hash, worker identity or version,
        authorization id / version / expiry, prior state-readiness record, resolver / adapter
        contract, or the readiness policy — yields a NEW operation and
        therefore a NEW immutable evidence row. An exact retry yields the same fingerprint and is
        idempotent (the durable terminal record is returned with no second external contact).
        """
        canonical = "|".join(
            (
                _FINGERPRINT_PREFIX,
                self.operation_kind,
                self.organization_id,
                self.environment_version_id,
                self.environment_version_content_hash,
                self.deployment_plan_id,
                self.deployment_plan_content_hash,
                self.provisioning_manifest_id,
                self.provisioning_manifest_content_hash,
                self.execution_target_id,
                self.target_config_hash,
                self.target_onboarding_id,
                self.onboarding_boundary_hash,
                self.effective_boundary_hash,
                self.eligibility_preflight_id,
                self.eligibility_evidence_hash,
                self.eligibility_policy_version,
                self.eligibility_expires_at,
                self.toolchain_profile_id,
                self.toolchain_profile_hash,
                self.toolchain_attestation_policy_version,
                self.toolchain_attestation_id,
                self.toolchain_attestation_hash,
                self.state_namespace_identity,
                self.credential_binding_id,
                str(self.credential_binding_version),
                self.activation_dossier_hash,
                self.worker_identity_registration_id,
                str(self.worker_identity_version),
                self.readiness_policy_version,
                self.adapter_contract_version,
                self.authorization_id,
                str(self.authorization_version),
                self.authorization_expiry,
                self.state_readiness_record_id,
                self.state_readiness_evidence_hash,
            )
        )
        return _sha256(canonical)

    def operation_identity_fingerprint(self) -> str:
        """The fingerprint of the OPERATION ITSELF, independent of which authorization approves it.

        Identical to :meth:`operation_fingerprint` with the authorization id / version / expiry
        blanked. A plan-secret authorization binds THIS value at creation (it cannot bind a
        fingerprint that already contains its own id), and the worker re-derives it and requires
        exact agreement — so an authorization minted for a different manifest, plan, target,
        onboarding, eligibility evidence, state-readiness record, toolchain profile, dossier,
        worker identity, secret purpose, resolver contract, or readiness policy can never authorize
        this operation.
        """
        from dataclasses import replace

        return replace(
            self, authorization_id="", authorization_version=0, authorization_expiry=""
        ).operation_fingerprint()


def readiness_evidence_hash(payload: dict) -> str:
    """Canonical ``sha256:`` hash over the bounded, secret-free readiness evidence payload."""
    from secp_scenario_schema import content_hash

    return content_hash(payload)


def required_facets(operation_kind: ReadinessOperationKind | str) -> tuple[str, ...]:
    kind = getattr(operation_kind, "value", operation_kind)
    if kind == ReadinessOperationKind.remote_state_readiness.value:
        return REQUIRED_REMOTE_STATE_FACETS
    if kind == ReadinessOperationKind.plan_secret_readiness.value:
        return REQUIRED_PLAN_SECRET_FACETS
    raise ValueError("unknown readiness operation kind")


def assert_plan_only_purpose(purpose: object) -> PlanSecretPurpose:
    """Refuse any secret purpose other than ``plan_read``.

    PR4 permits ONLY future plan-readiness. ``apply`` and ``destroy`` purposes are unrepresentable
    (absent from :class:`~secp_api.enums.PlanSecretPurpose`) AND explicitly refused here, so a
    string smuggled in through a request body, an ORM row, or a migration cannot create an
    apply/destroy secret authorization. There is no generic "all operations" credential readiness.
    """
    value = getattr(purpose, "value", purpose)
    if value != PlanSecretPurpose.plan_read.value:
        raise PurposeNotPermitted(
            "only the plan-read secret purpose is permitted in B1B-PR4; apply and destroy secret "
            "purposes remain sealed and belong to their own separately reviewed phases"
        )
    return PlanSecretPurpose.plan_read


class PurposeNotPermitted(ValueError):
    """A secret purpose other than ``plan_read`` was supplied. Never echoes the rejected value."""
