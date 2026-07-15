"""Durable readiness records (SECP-002B-1B, B1B-PR4 / ADR-021) — kept in a dedicated module.

Five append-only / CAS-guarded tables:

* :class:`RemoteStateReadinessRecord` — immutable, hash-bound, expiry-bound remote-state readiness
  evidence. It deliberately does NOT overload ``TargetEvidenceRecord`` (whose semantics are bound to
  live read-only target evidence).
* :class:`PlanSecretReadinessAuthorization` + :class:`PlanSecretReadinessEvidence` — the SEPARATE,
  explicit, time-bounded, revocable human authorization for plan-secret readiness. It deliberately
  does NOT reuse ``ResolverActivationAuthorization``, whose ``preflight_id`` /
  ``live_read_authorization_id`` foreign keys and ``readonly_staging_preflight`` purpose are bound
  to live READ-ONLY staging preflight and would be FALSE semantics here (ADR-021 §G).
* :class:`PlanSecretResolutionLease` — the durable single-use lease + bounded retry budget for one
  plan-secret readiness operation. It mirrors the B2-3 ``ResolutionLease`` CAS/retry contract but is
  keyed on the plan-secret authorization, because ``ResolutionLease.live_read_authorization_id`` is
  a NOT-NULL foreign key to ``live_read_authorization`` and its uniqueness key is built from it.
* :class:`PlanSecretReadinessRecord` — immutable plan-secret readiness evidence.

NOTHING here stores a secret, a secret reference, a hash of a secret reference, a backend locator,
endpoint, URL, bucket / container / object name, state key or path, namespace name, token, response
body, environment variable value, or exception text. Every security-critical binding is a TYPED
COLUMN; the single bounded JSON column per evidence table holds only typed facet results.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from secp_api.enums import (
    CredentialBindingSource,
    CredentialBindingStatus,
    CredentialPurposeClass,
    PlanSecretAuthorizationStatus,
    PlanSecretEvidenceKind,
    PlanSecretEvidenceStatus,
    PlanSecretReadinessOutcome,
    ReadinessCapabilityClass,
    RemoteStateReadinessOutcome,
    ResolutionLeaseStatus,
    ToolchainAttestationOutcome,
)
from secp_api.models import Base, TimestampMixin, _utcnow, _uuid
from secp_api.types import EnumType


class ToolchainAttestationRecord(Base, TimestampMixin):
    """Immutable, worker-produced, READINESS-ONLY toolchain attestation evidence (B1B-PR4 §1).

    A matching ``ToolchainProfile`` id/hash and a verifier-policy version are **NOT an
    attestation**. This record exists only when the worker ran the real ``RealToolchainVerifier``
    against an explicit, deployment-local, immutable ``ToolchainFilesystemLayout`` and every
    required facet was verified against the ACTUAL ON-DISK toolchain.

    It stores ONLY: organization; worker identity id + version; toolchain profile id + hash; the
    verifier policy version; the verified FACET NAMES; bounded reason codes; collection time; an
    expiry; an evidence hash; and the operation fingerprint.

    It stores **no path, no filename, no executable content, no provider content, no CLI content,
    and no raw expected/observed digest** beyond the already-approved safe profile hash + evidence
    projection.
    """

    __tablename__ = "toolchain_attestation_record"
    __table_args__ = (
        # Exact-once for the TERMINAL (``attested``) outcome only; failed attempts append as
        # immutable attempt history so a retry after a fixed layout is possible.
        Index(
            "uq_toolchain_attestation_operation",
            "toolchain_profile_id",
            "operation_fingerprint",
            unique=True,
            sqlite_where=text("outcome = 'attested'"),
            postgresql_where=text("outcome = 'attested'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    toolchain_profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("toolchain_profile.id"), nullable=False, index=True
    )
    toolchain_profile_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    worker_identity_registration_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("worker_identity_registration.id"), nullable=False, index=True
    )
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)
    verifier_policy_version: Mapped[str] = mapped_column(String(120), nullable=False)

    outcome: Mapped[ToolchainAttestationOutcome] = mapped_column(
        EnumType(ToolchainAttestationOutcome, length=40), nullable=False
    )
    # Bounded FACET NAMES only (e.g. "executable", "binary_digest") — never a path, a filename, or a
    # digest value.
    verified_facets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reason_codes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)


class CredentialBinding(Base, TimestampMixin):
    """An OPAQUE, versioned identity for a target's credential SELECTION (B1B-PR4 §2).

    It exists to close the post-approval ``secret_ref`` substitution gap **without** storing the
    reference or any hash of it. There is deliberately NO column that could hold a secret, a secret
    reference, a hash of a reference, a locator, a backend path, or a credential value: the
    binding is a bare opaque id + a monotonic version.

    **Rotation is unavoidable.** Any change to ``ExecutionTarget.secret_ref`` rotates the active
    binding and creates the next version — enforced by an ORM ``before_flush`` hook (the portable
    SQLite + PostgreSQL layer) AND by a PostgreSQL trigger (which also covers a raw/Core UPDATE that
    bypasses the ORM). Because the binding id + version are folded into the readiness operation
    fingerprint, a rotation invalidates every prior authorization and readiness record **without
    modifying any historical evidence**.
    """

    __tablename__ = "credential_binding"
    __table_args__ = (
        UniqueConstraint(
            "execution_target_id",
            "purpose_class",
            "binding_version",
            name="uq_credential_binding_target_purpose_version",
        ),
        # Exactly ONE active binding per (target, purpose class).
        Index(
            "uq_credential_binding_active",
            "execution_target_id",
            "purpose_class",
            unique=True,
            sqlite_where=text("status = 'active'"),
            postgresql_where=text("status = 'active'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    purpose_class: Mapped[CredentialPurposeClass] = mapped_column(
        EnumType(CredentialPurposeClass, length=40), nullable=False
    )
    binding_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[CredentialBindingStatus] = mapped_column(
        EnumType(CredentialBindingStatus, length=20),
        default=CredentialBindingStatus.active,
        nullable=False,
    )
    # B1B-PR5A amendment §1: which authoritative reference sourced this binding. A binding sourced
    # from the generic ``secret_ref`` (``legacy_generic``) can NEVER satisfy a real-plan gate; only
    # ``dedicated_operation`` can. It is part of the binding's immutable identity. PR4 rows backfill
    # to ``legacy_generic`` (the only source that existed then).
    binding_source: Mapped[CredentialBindingSource] = mapped_column(
        EnumType(CredentialBindingSource, length=40),
        default=CredentialBindingSource.legacy_generic,
        nullable=False,
    )
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"CredentialBinding(id={self.id!s}, version={self.binding_version!r}, "
            f"status={getattr(self.status, 'value', self.status)!r})"
        )


class RemoteStateReadinessRecord(Base, TimestampMixin):
    """Immutable, redacted, expiry-bound remote-state readiness evidence (ADR-021 §F).

    Safe content only: a bounded backend CLASS, an opaque backend BINDING HASH, an opaque NAMESPACE
    identity, opaque external proof ids, bounded facet results, bounded reason codes, policy /
    adapter versions, timestamps, an expiry, and an evidence hash. There is no column that can hold
    a state body, object key, backend URL, bucket name, account id, access key, token, provider
    body, or lock payload — and no readiness code path that could produce one.
    """

    __tablename__ = "remote_state_readiness_record"
    __table_args__ = (
        # Exact-once for the TERMINAL (``ready``) outcome ONLY. An exact retry of the same binding
        # returns the durable ``ready`` record with no second backend contact; a changed binding is
        # a
        # different fingerprint (a new row). NON-ready attempts append freely as immutable attempt
        # history — otherwise one transient backend blip would permanently poison the operation.
        Index(
            "uq_remote_state_readiness_operation",
            "provisioning_manifest_id",
            "operation_fingerprint",
            unique=True,
            sqlite_where=text("outcome = 'ready'"),
            postgresql_where=text("outcome = 'ready'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    target_onboarding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=False, index=True
    )
    deployment_plan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("deployment_plan.id"), nullable=False, index=True
    )
    provisioning_manifest_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("provisioning_manifest.id"), nullable=False, index=True
    )
    toolchain_profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("toolchain_profile.id"), nullable=False, index=True
    )
    eligibility_preflight_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_preflight.id"), nullable=False, index=True
    )
    # The DURABLE, worker-produced toolchain attestation this readiness is bound to (B1B-PR4 §1).
    toolchain_attestation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("toolchain_attestation_record.id"), nullable=False, index=True
    )
    worker_identity_registration_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("worker_identity_registration.id"), nullable=False, index=True
    )
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)

    # --- immutable binding hashes (typed columns, never a JSON blob) -----------------------------
    provisioning_manifest_content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    target_config_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    onboarding_boundary_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    eligibility_evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    eligibility_policy_version: Mapped[str] = mapped_column(String(120), nullable=False)
    toolchain_profile_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    toolchain_attestation_policy_version: Mapped[str] = mapped_column(String(120), nullable=False)
    toolchain_attestation_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    # The REVIEWED deployment-local dossier hash, taken from the controlled-live adapter capability.
    # The fail-closed placeholder can never produce a ``ready`` record.
    activation_dossier_hash: Mapped[str] = mapped_column(String(120), nullable=False)

    # --- backend identity: a bounded CLASS + the immutable PROFILE hash + a UUID-derived namespace.
    # There is deliberately NO digest of the backend reference/URL/bucket/key here: an unsalted
    # digest of an enumerable locator is a confirmation oracle.
    state_backend_class: Mapped[str] = mapped_column(String(20), nullable=False)
    state_namespace_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)

    # --- external proof ids: UUIDs ONLY (a UUID can never BE a bucket/host/state-file name) ------
    encryption_proof_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    lock_proof_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    backup_proof_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    restore_proof_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    # --- controlled-live adapter provenance (B1B-PR4 §3) ------------------------------------------
    capability_class: Mapped[ReadinessCapabilityClass] = mapped_column(
        EnumType(ReadinessCapabilityClass, length=20), nullable=False
    )
    adapter_registration_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # --- operation + policy identity --------------------------------------------------------------
    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    readiness_policy_version: Mapped[str] = mapped_column(String(120), nullable=False)
    adapter_contract_version: Mapped[str] = mapped_column(String(120), nullable=False)

    # --- typed outcome + bounded typed facets / reason codes -------------------------------------
    outcome: Mapped[RemoteStateReadinessOutcome] = mapped_column(
        EnumType(RemoteStateReadinessOutcome, length=40), nullable=False
    )
    facets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reason_codes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"RemoteStateReadinessRecord(id={self.id!s}, outcome="
            f"{getattr(self.outcome, 'value', self.outcome)!r}, "
            f"evidence_hash={self.evidence_hash!r})"
        )


class PlanSecretReadinessAuthorization(Base, TimestampMixin):
    """The SEPARATE, explicit, time-bounded, revocable human authorization for plan-secret
    readiness.

    It is NEVER inferred from topology approval, environment publication, deployment-plan approval,
    onboarding approval, a live-read authorization, eligibility success, toolchain attestation, or
    state readiness. Creating it does not run readiness; approving it does not run readiness.
    Revocation immediately invalidates future use.

    ``purpose`` is server-forced to ``plan_read``. Apply and destroy purposes are unrepresentable
    (absent from :class:`~secp_api.enums.PlanSecretPurpose`) and additionally refused by
    :func:`~secp_api.readiness_contract.assert_plan_only_purpose`.

    NOTE: it carries the credential-reference SCHEME (a bounded ``vault`` / ``env`` token reviewed
    by a human) but NEVER the reference itself and never a hash of it.
    """

    __tablename__ = "plan_secret_readiness_authorization"
    __table_args__ = (
        UniqueConstraint(
            "provisioning_manifest_id",
            "authorization_version",
            name="uq_plan_secret_authorization_manifest_version",
        ),
        # At most ONE active (draft/approved) authorization per manifest.
        Index(
            "uq_plan_secret_authorization_active",
            "provisioning_manifest_id",
            unique=True,
            sqlite_where=text("status in ('draft','approved')"),
            postgresql_where=text("status in ('draft','approved')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    target_onboarding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=False, index=True
    )
    deployment_plan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("deployment_plan.id"), nullable=False, index=True
    )
    provisioning_manifest_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("provisioning_manifest.id"), nullable=False, index=True
    )
    toolchain_profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("toolchain_profile.id"), nullable=False, index=True
    )
    eligibility_preflight_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_preflight.id"), nullable=False, index=True
    )
    remote_state_readiness_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("remote_state_readiness_record.id"), nullable=False, index=True
    )
    toolchain_attestation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("toolchain_attestation_record.id"), nullable=False, index=True
    )
    # The OPAQUE credential binding this authorization approves. Rotating the target's secret_ref
    # rotates the binding, which invalidates this authorization through the operation fingerprint.
    credential_binding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("credential_binding.id"), nullable=False, index=True
    )
    credential_binding_version: Mapped[int] = mapped_column(Integer, nullable=False)
    worker_identity_registration_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("worker_identity_registration.id"), nullable=False, index=True
    )
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)

    # --- immutable binding hashes -----------------------------------------------------------------
    provisioning_manifest_content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    target_config_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    onboarding_boundary_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    eligibility_evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    toolchain_profile_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    toolchain_attestation_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    remote_state_evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    activation_dossier_hash: Mapped[str] = mapped_column(String(120), nullable=False)

    # --- purpose + contract identity -------------------------------------------------------------
    purpose: Mapped[str] = mapped_column(String(40), nullable=False)
    credential_reference_scheme: Mapped[str] = mapped_column(String(20), nullable=False)
    resolver_contract_version: Mapped[str] = mapped_column(String(120), nullable=False)
    readiness_policy_version: Mapped[str] = mapped_column(String(120), nullable=False)
    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, index=True)

    # --- lifecycle -------------------------------------------------------------------------------
    authorization_expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    status: Mapped[PlanSecretAuthorizationStatus] = mapped_column(
        EnumType(PlanSecretAuthorizationStatus, length=40),
        default=PlanSecretAuthorizationStatus.draft,
        nullable=False,
    )
    authorization_version: Mapped[int] = mapped_column(Integer, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason_code: Mapped[str] = mapped_column(String(80), nullable=False, default="")

    evidence: Mapped[list[PlanSecretReadinessEvidence]] = relationship(
        back_populates="authorization",
        cascade="all, delete-orphan",
        order_by="PlanSecretReadinessEvidence.kind",
    )

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"PlanSecretReadinessAuthorization(id={self.id!s}, purpose={self.purpose!r}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            f"evidence_fingerprint={self.evidence_fingerprint!r})"
        )


class PlanSecretReadinessEvidence(Base, TimestampMixin):
    """One closed, secret-free human-review evidence item on a DRAFT plan-secret authorization."""

    __tablename__ = "plan_secret_readiness_evidence"
    __table_args__ = (
        UniqueConstraint("authorization_id", "kind", name="uq_plan_secret_evidence_kind"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("plan_secret_readiness_authorization.id"),
        nullable=False,
        index=True,
    )
    kind: Mapped[PlanSecretEvidenceKind] = mapped_column(
        EnumType(PlanSecretEvidenceKind, length=60), nullable=False
    )
    status: Mapped[PlanSecretEvidenceStatus] = mapped_column(
        EnumType(PlanSecretEvidenceStatus, length=20),
        default=PlanSecretEvidenceStatus.pending,
        nullable=False,
    )
    proof_id: Mapped[str] = mapped_column(String(120), nullable=False)
    issuer: Mapped[str] = mapped_column(String(120), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    authorization: Mapped[PlanSecretReadinessAuthorization] = relationship(
        back_populates="evidence"
    )


class PlanSecretResolutionLease(Base, TimestampMixin):
    """Durable single-use lease + bounded retry budget for ONE plan-secret readiness operation.

    Uniqueness (the budget / single-use key) is
    ``(authorization_id, authorization_version, operation_fingerprint)`` — and the operation
    fingerprint itself already folds in EVERY other security-relevant fact (organization, target,
    onboarding, manifest, plan, eligibility evidence, state-readiness record, toolchain profile,
    worker identity + version, dossier hash, secret purpose, resolver contract, readiness policy,
    authorization expiry). Worker identity is recorded for evidence only and is deliberately NOT
    part of the key, so a second worker identity can never open an independent duplicate budget for
    the same operation.

    It stores NO credential, secret reference, hash of a reference, endpoint, backend response, or
    target configuration.
    """

    __tablename__ = "plan_secret_resolution_lease"
    __table_args__ = (
        UniqueConstraint(
            "authorization_id",
            "authorization_version",
            "operation_fingerprint",
            name="uq_plan_secret_lease_operation",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("plan_secret_readiness_authorization.id"),
        nullable=False,
        index=True,
    )
    authorization_version: Mapped[int] = mapped_column(Integer, nullable=False)
    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    lease_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, default=_uuid)
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[ResolutionLeaseStatus] = mapped_column(
        EnumType(ResolutionLeaseStatus, length=40),
        default=ResolutionLeaseStatus.active,
        nullable=False,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    worker_identity_id: Mapped[str] = mapped_column(String(120), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PlanSecretReadinessRecord(Base, TimestampMixin):
    """Immutable, redacted, expiry-bound plan-secret readiness evidence (ADR-021 §L).

    It persists ONLY: bounded facet names + statuses, bounded reason codes, the resolver contract
    version, an opaque self-test proof id, the lease id, policy versions, safe hashes, timestamps,
    and an expiry. It NEVER persists a secret, a secret reference, a hash of a secret reference, a
    backend locator, an endpoint, a namespace name, a token, a backend response body, an environment
    variable name-value pair, or exception detail.
    """

    __tablename__ = "plan_secret_readiness_record"
    __table_args__ = (
        # Exact-once for the TERMINAL (``ready``) outcome ONLY — see RemoteStateReadinessRecord. A
        # NON-ready attempt appends, so the durable N=3 lease retry budget is actually reachable.
        Index(
            "uq_plan_secret_readiness_operation",
            "provisioning_manifest_id",
            "operation_fingerprint",
            unique=True,
            sqlite_where=text("outcome = 'ready'"),
            postgresql_where=text("outcome = 'ready'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("plan_secret_readiness_authorization.id"),
        nullable=False,
        index=True,
    )
    authorization_version: Mapped[int] = mapped_column(Integer, nullable=False)
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    target_onboarding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=False, index=True
    )
    deployment_plan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("deployment_plan.id"), nullable=False, index=True
    )
    provisioning_manifest_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("provisioning_manifest.id"), nullable=False, index=True
    )
    toolchain_profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("toolchain_profile.id"), nullable=False, index=True
    )
    eligibility_preflight_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_preflight.id"), nullable=False, index=True
    )
    remote_state_readiness_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("remote_state_readiness_record.id"), nullable=False, index=True
    )
    toolchain_attestation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("toolchain_attestation_record.id"), nullable=False, index=True
    )
    credential_binding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("credential_binding.id"), nullable=False, index=True
    )
    credential_binding_version: Mapped[int] = mapped_column(Integer, nullable=False)
    worker_identity_registration_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("worker_identity_registration.id"), nullable=False, index=True
    )
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)
    lease_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    # --- controlled-live adapter provenance (B1B-PR4 §3) ---
    capability_class: Mapped[ReadinessCapabilityClass] = mapped_column(
        EnumType(ReadinessCapabilityClass, length=20), nullable=False
    )
    adapter_registration_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    # --- immutable binding hashes -----------------------------------------------------------------
    provisioning_manifest_content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    target_config_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    onboarding_boundary_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    eligibility_evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    toolchain_profile_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    toolchain_attestation_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    remote_state_evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    activation_dossier_hash: Mapped[str] = mapped_column(String(120), nullable=False)
    authorization_evidence_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)

    # --- purpose / contract / policy -------------------------------------------------------------
    secret_purpose: Mapped[str] = mapped_column(String(40), nullable=False)
    resolver_contract_version: Mapped[str] = mapped_column(String(120), nullable=False)
    self_test_policy_version: Mapped[str] = mapped_column(String(120), nullable=False)
    env_contract_version: Mapped[str] = mapped_column(String(120), nullable=False)
    readiness_policy_version: Mapped[str] = mapped_column(String(120), nullable=False)
    # A UUID, never a free label (a label could BE a Vault mount / hostname / bucket).
    self_test_proof_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, index=True)

    # --- typed outcome + bounded typed facets / reason codes -------------------------------------
    outcome: Mapped[PlanSecretReadinessOutcome] = mapped_column(
        EnumType(PlanSecretReadinessOutcome, length=40), nullable=False
    )
    facets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reason_codes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"PlanSecretReadinessRecord(id={self.id!s}, secret_purpose={self.secret_purpose!r}, "
            f"outcome={getattr(self.outcome, 'value', self.outcome)!r}, "
            f"evidence_hash={self.evidence_hash!r})"
        )
