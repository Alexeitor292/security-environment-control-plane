"""Durable B1B-PR5A plan-activation records (ADR-022) — kept in a dedicated module.

Four tables close the remaining real-plan prerequisites **without ever storing a real deployment
value**:

* :class:`RealLabActivationDossier` + :class:`RealLabActivationDossierEvidence` — the durable,
  human-reviewed activation-dossier lifecycle (draft → evidence → approved → revoked/expired/
  superseded). The DETAILED dossier stays deployment-local and outside source control; only safe
  bindings and proof metadata are persisted.
* :class:`RealPlanGenerationAuthorization` — the SEPARATE, explicit, dedicated-permission
  authorization to GENERATE a real plan (``plan_generation`` only). It authorizes no apply/destroy.
* :class:`RealPlanGenerationAttempt` — the durable enqueue-only workflow attempt record. In PR5A it
  never reaches ``completed`` (no plan executes; the worker refuses at the sealed plan-only
  boundary).

NOTHING here stores a secret, a secret reference, a hash of a secret reference, a backend locator,
endpoint, URL, bucket/container/object name, state key or path, namespace name, token, response
body, environment value, hostname, IP, CIDR, node/storage/bridge name, VLAN, certificate, host key,
or raw proof text. Every security-critical binding is a TYPED column; credential identity is an
OPAQUE binding id + version; dimensional review evidence is an opaque UUID proof id + bounded
issuer.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
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
    ActivationDossierEvidenceKind,
    ActivationDossierEvidenceStatus,
    ActivationDossierStatus,
    PlanGenerationAttemptStatus,
    PlanGenerationAuthorizationStatus,
)
from secp_api.models import Base, TimestampMixin, _utcnow, _uuid
from secp_api.types import EnumType

# CLOSED revocation reason codes (B1B-PR5A amendment §4). The empty string is the unset default. A
# CHECK constraint (below) enforces this set at the DATABASE level for EVERY write — the ORM path, a
# raw/Core UPDATE, and even under ``session_replication_role = replica`` (a CHECK is not a trigger,
# so replica mode never disables it). No arbitrary free text can ever reach the durable column.
REVOCATION_REASON_CODES: tuple[str, ...] = (
    "operator",
    "superseded",
    "credential_rotated",
    "preflight_invalidated",
    "readiness_drift",
    "policy_change",
    "security_review",
    "expired",
)
_REVOCATION_REASON_CHECK = (
    "revocation_reason_code IN ('', " + ", ".join(f"'{c}'" for c in REVOCATION_REASON_CODES) + ")"
)
# The reason may be non-empty ONLY on a revoked row. A CHECK fires on INSERT and UPDATE, on every
# path, and under replica mode — so even a hand-built INSERT cannot pre-set a reason on a
# non-revoked row (closing the INSERT-path caveat the UPDATE-only trigger/ORM guard left open).
_REVOCATION_REQUIRES_REVOKED = "revocation_reason_code = '' OR status = 'revoked'"

_ACTIVE_DOSSIER = text("status in ('draft','approved')")
_ACTIVE_PLAN_AUTHORIZATION = text("status in ('draft','approved')")


class RealLabActivationDossier(Base, TimestampMixin):
    """The durable, human-reviewed activation dossier (B1B-PR5A, ADR-022 §3; ADR-020 §D).

    It binds the reviewed deployment package for ONE real-plan operation. The detailed dossier (real
    endpoints, credentials, node/storage/bridge names, CIDRs, state keys) stays deployment-local and
    outside source control; this row keeps only safe ids, opaque hashes, bounded categories, and
    opaque proof metadata. The fail-closed placeholder sentinel can never appear as
    ``dossier_hash``.

    Creating or approving a dossier executes nothing, enqueues nothing, contacts nothing, constructs
    no adapter, resolves no secret, and mints no activation grant.
    """

    __tablename__ = "real_lab_activation_dossier"
    __table_args__ = (
        UniqueConstraint(
            "provisioning_manifest_id",
            "dossier_revision",
            name="uq_activation_dossier_manifest_revision",
        ),
        # At most ONE active (draft/approved) dossier per manifest.
        Index(
            "uq_activation_dossier_active",
            "provisioning_manifest_id",
            unique=True,
            sqlite_where=_ACTIVE_DOSSIER,
            postgresql_where=_ACTIVE_DOSSIER,
        ),
        CheckConstraint(
            _REVOCATION_REASON_CHECK, name="ck_activation_dossier_revocation_reason_code"
        ),
        CheckConstraint(
            _REVOCATION_REQUIRES_REVOKED, name="ck_activation_dossier_revocation_requires_revoked"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    # --- upstream authoritative bindings (all set at creation, immutable) ------------------------
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    target_onboarding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=False, index=True
    )
    deployment_plan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("deployment_plan.id"), nullable=False, index=True
    )
    environment_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("environment_version.id"), nullable=False, index=True
    )
    provisioning_manifest_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("provisioning_manifest.id"), nullable=False, index=True
    )
    toolchain_profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("toolchain_profile.id"), nullable=False, index=True
    )
    toolchain_attestation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("toolchain_attestation_record.id"), nullable=False, index=True
    )
    worker_identity_registration_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("worker_identity_registration.id"), nullable=False, index=True
    )
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # OPAQUE operation-specific credential bindings (id + version only; never a reference or a
    # hash).
    provider_credential_binding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("credential_binding.id"), nullable=False, index=True
    )
    provider_credential_binding_version: Mapped[int] = mapped_column(Integer, nullable=False)
    state_credential_binding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("credential_binding.id"), nullable=False, index=True
    )
    state_credential_binding_version: Mapped[int] = mapped_column(Integer, nullable=False)

    # --- immutable binding hashes ----------------------------------------------------------------
    environment_version_content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    deployment_plan_content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    provisioning_manifest_content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    target_config_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    onboarding_boundary_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    toolchain_profile_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    toolchain_attestation_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    toolchain_attestation_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # The server-derived state namespace identity (opaque; never a namespace name).
    state_namespace_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)

    # --- downstream snapshots (bound if current at approval; the combined readiness re-verifies) --
    eligibility_preflight_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    eligibility_evidence_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    remote_state_readiness_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    remote_state_evidence_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    plan_secret_readiness_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    plan_secret_evidence_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)

    # --- reviewed operator responsibilities (OPAQUE proofs only) ----------------------------------
    recovery_owner_proof: Mapped[str] = mapped_column(String(120), nullable=False)
    emergency_stop_owner_proof: Mapped[str] = mapped_column(String(120), nullable=False)

    # --- identity / lifecycle ---------------------------------------------------------------------
    operation_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    dossier_revision: Mapped[int] = mapped_column(Integer, nullable=False)
    # The OPAQUE dossier hash readiness folds into its operation fingerprint. It is derived
    # server-side from the safe bindings + the complete evidence fingerprint; the placeholder
    # sentinel can never equal it.
    dossier_hash: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    evidence_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    authorization_expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[ActivationDossierStatus] = mapped_column(
        EnumType(ActivationDossierStatus, length=40),
        default=ActivationDossierStatus.draft,
        nullable=False,
    )
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    superseded_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason_code: Mapped[str] = mapped_column(String(80), nullable=False, default="")

    evidence: Mapped[list[RealLabActivationDossierEvidence]] = relationship(
        back_populates="dossier",
        cascade="all, delete-orphan",
        order_by="RealLabActivationDossierEvidence.kind",
    )

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"RealLabActivationDossier(id={self.id!s}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            f"dossier_hash={self.dossier_hash!r})"
        )


class RealLabActivationDossierEvidence(Base, TimestampMixin):
    """One closed, secret-free human-review evidence item on a DRAFT activation dossier."""

    __tablename__ = "real_lab_activation_dossier_evidence"
    __table_args__ = (
        UniqueConstraint("dossier_id", "kind", name="uq_activation_dossier_evidence_kind"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    dossier_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("real_lab_activation_dossier.id"), nullable=False, index=True
    )
    kind: Mapped[ActivationDossierEvidenceKind] = mapped_column(
        EnumType(ActivationDossierEvidenceKind, length=60), nullable=False
    )
    status: Mapped[ActivationDossierEvidenceStatus] = mapped_column(
        EnumType(ActivationDossierEvidenceStatus, length=20),
        default=ActivationDossierEvidenceStatus.pending,
        nullable=False,
    )
    proof_id: Mapped[str] = mapped_column(String(120), nullable=False)
    issuer: Mapped[str] = mapped_column(String(120), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    dossier: Mapped[RealLabActivationDossier] = relationship(back_populates="evidence")


class RealPlanGenerationAuthorization(Base, TimestampMixin):
    """The SEPARATE, explicit authorization to GENERATE a real plan (B1B-PR5A, ADR-022 §7).

    ``purpose`` is server-forced to ``plan_generation``. It authorizes NO apply, destroy, provider
    mutation, state mutation, credential rotation, or dossier approval. Creating it does not run
    anything; approving it (a DEDICATED permission) does not run anything; consumption occurs only
    in
    PR5B after a durable plan result — which does not exist in PR5A.
    """

    __tablename__ = "real_plan_generation_authorization"
    __table_args__ = (
        UniqueConstraint(
            "provisioning_manifest_id",
            "authorization_version",
            name="uq_plan_generation_authorization_manifest_version",
        ),
        Index(
            "uq_plan_generation_authorization_active",
            "provisioning_manifest_id",
            unique=True,
            sqlite_where=_ACTIVE_PLAN_AUTHORIZATION,
            postgresql_where=_ACTIVE_PLAN_AUTHORIZATION,
        ),
        CheckConstraint(
            _REVOCATION_REASON_CHECK, name="ck_plan_generation_authorization_revocation_reason_code"
        ),
        CheckConstraint(
            _REVOCATION_REQUIRES_REVOKED,
            name="ck_plan_generation_authorization_revocation_requires_revoked",
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
    activation_dossier_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("real_lab_activation_dossier.id"), nullable=False, index=True
    )
    eligibility_preflight_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_preflight.id"), nullable=False, index=True
    )
    toolchain_attestation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("toolchain_attestation_record.id"), nullable=False, index=True
    )
    remote_state_readiness_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("remote_state_readiness_record.id"), nullable=False, index=True
    )
    plan_secret_readiness_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("plan_secret_readiness_record.id"), nullable=False, index=True
    )
    provider_credential_binding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("credential_binding.id"), nullable=False, index=True
    )
    provider_credential_binding_version: Mapped[int] = mapped_column(Integer, nullable=False)
    state_credential_binding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("credential_binding.id"), nullable=False, index=True
    )
    state_credential_binding_version: Mapped[int] = mapped_column(Integer, nullable=False)
    worker_identity_registration_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("worker_identity_registration.id"), nullable=False, index=True
    )
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)

    # --- immutable binding hashes ----------------------------------------------------------------
    provisioning_manifest_content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    target_config_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    onboarding_boundary_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    eligibility_evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    toolchain_profile_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    toolchain_attestation_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    remote_state_evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    plan_secret_evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    activation_dossier_hash: Mapped[str] = mapped_column(String(120), nullable=False)
    dossier_evidence_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)

    # --- purpose / capability / policy ------------------------------------------------------------
    purpose: Mapped[str] = mapped_column(String(40), nullable=False)
    plan_only_capability_contract_version: Mapped[str] = mapped_column(String(120), nullable=False)
    readiness_policy_version: Mapped[str] = mapped_column(String(120), nullable=False)
    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, index=True)

    # --- lifecycle --------------------------------------------------------------------------------
    authorization_expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    status: Mapped[PlanGenerationAuthorizationStatus] = mapped_column(
        EnumType(PlanGenerationAuthorizationStatus, length=40),
        default=PlanGenerationAuthorizationStatus.draft,
        nullable=False,
    )
    authorization_version: Mapped[int] = mapped_column(Integer, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason_code: Mapped[str] = mapped_column(String(80), nullable=False, default="")

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"RealPlanGenerationAuthorization(id={self.id!s}, purpose={self.purpose!r}, "
            f"status={getattr(self.status, 'value', self.status)!r})"
        )


class RealPlanGenerationAttempt(Base, TimestampMixin):
    """A durable, secret-free real-plan-generation ATTEMPT record (B1B-PR5A workflow state).

    It exists only for idempotency + workflow state. It carries NO command, argv, cwd, path, secret,
    secret reference, environment, provider output, state content, raw plan JSON, binary plan, or
    stack trace. In PR5A its outcome is only ``requested`` or ``refused`` — never ``completed``,
    because no plan executes (the worker refuses at the sealed plan-only boundary).
    """

    __tablename__ = "real_plan_generation_attempt"
    __table_args__ = (
        # Exact-once for a terminal REFUSED per operation fingerprint (append-only history).
        Index(
            "uq_plan_generation_attempt_operation",
            "provisioning_manifest_id",
            "operation_fingerprint",
            unique=True,
            sqlite_where=text("status = 'refused'"),
            postgresql_where=text("status = 'refused'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("real_plan_generation_authorization.id"), nullable=True, index=True
    )
    authorization_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    deployment_plan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("deployment_plan.id"), nullable=False, index=True
    )
    provisioning_manifest_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("provisioning_manifest.id"), nullable=False, index=True
    )
    target_onboarding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=True
    )
    activation_dossier_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("real_lab_activation_dossier.id"), nullable=True
    )
    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    status: Mapped[PlanGenerationAttemptStatus] = mapped_column(
        EnumType(PlanGenerationAttemptStatus, length=40), nullable=False
    )
    refusal_reason_code: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"RealPlanGenerationAttempt(id={self.id!s}, "
            f"status={getattr(self.status, 'value', self.status)!r})"
        )
