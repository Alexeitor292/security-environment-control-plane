"""Durable ORM models for the real staging-lab deployment engine (SECP-B4).

These records are the app-owned spine of the deployment lifecycle. They store ONLY safe logical
intent, generated/ownership-bound identifiers, closed status/failure codes, pinned version labels,
and deterministic hashes. They NEVER store an endpoint, host, IP, real bridge/VMID/storage name,
certificate, secret, token, or credential reference. Plans and approvals are content-addressed and
immutable after insert (enforced by the ORM immutability guard). Every created resource carries the
exact SECP ownership tag and a typed inverse (rollback) operation.

They live in a dedicated module (imported by ``secp_api.models``) purely to keep the SECP-B4 diff
focused; they register on the shared ``Base`` exactly like every other model.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from secp_api.enums import (
    DeploymentInverseOp,
    DeploymentOperationKind,
    DeploymentOperationStatus,
    DeploymentResourceKind,
    DeploymentResourceState,
    DeploymentVerificationCode,
    DeploymentVerificationStatus,
    StagingDeploymentDecisionCode,
    StagingDeploymentStatus,
)
from secp_api.models import Base, TimestampMixin, _uuid
from secp_api.types import EnumType


class StagingDeployment(Base, TimestampMixin):
    """Durable desired-state + lifecycle root for a REAL staging-lab deployment (SECP-B4).

    Optimistic-concurrency ``revision``; every lifecycle mutation is a compare-and-swap on
    (status, revision). Sealed by default: no transition past ``approved`` performs a real host
    action unless a worker-local bootstrap bundle is injected AND an exact plan is approved.
    """

    __tablename__ = "staging_deployment"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    onboarding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=False, index=True
    )
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    ownership_label: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    resource_profile: Mapped[str] = mapped_column(String(60), default="small_lab", nullable=False)
    status: Mapped[StagingDeploymentStatus] = mapped_column(
        EnumType(StagingDeploymentStatus, length=40),
        default=StagingDeploymentStatus.draft,
        nullable=False,
    )
    decision_code: Mapped[StagingDeploymentDecisionCode] = mapped_column(
        EnumType(StagingDeploymentDecisionCode, length=40),
        default=StagingDeploymentDecisionCode.pending,
        nullable=False,
    )
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    plan_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    plan_hash: Mapped[str] = mapped_column(String(80), default="", nullable=False, index=True)
    approved_plan_hash: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    def __repr__(self) -> str:
        return (
            "StagingDeployment("
            f"id={self.id!s}, ownership_label={self.ownership_label!r}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            f"plan_hash={self.plan_hash!r})"
        )


class StagingDeploymentPlan(Base, TimestampMixin):
    """Immutable, content-addressed deployment plan (SECP-B4). ``plan_document`` lists ONLY safe
    resource categories/counts/labels/hashes. Immutable after insert."""

    __tablename__ = "staging_deployment_plan"
    __table_args__ = (
        UniqueConstraint("deployment_id", "plan_hash", name="uq_staging_deploy_plan_hash"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    deployment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("staging_deployment.id"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False)
    plan_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    ownership_tag: Mapped[str] = mapped_column(String(120), nullable=False)
    capacity_assessment_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    artifact_manifest_id: Mapped[str] = mapped_column(String(120), nullable=False)
    plan_document: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    def __repr__(self) -> str:
        return f"StagingDeploymentPlan(id={self.id!s}, plan_hash={self.plan_hash!r})"


class StagingDeploymentApproval(Base, TimestampMixin):
    """Immutable explicit approval binding one EXACT plan hash + target enrollment + ownership tag +
    capacity assessment + artifact manifest identity + worker identity version (SECP-B4)."""

    __tablename__ = "staging_deployment_approval"
    __table_args__ = (
        UniqueConstraint("deployment_id", "approved_plan_hash", name="uq_staging_deploy_approval"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    deployment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("staging_deployment.id"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    approved_plan_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False)
    onboarding_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    ownership_tag: Mapped[str] = mapped_column(String(120), nullable=False)
    capacity_assessment_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    artifact_manifest_id: Mapped[str] = mapped_column(String(120), nullable=False)
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)
    approved_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    def __repr__(self) -> str:
        return f"StagingDeploymentApproval(id={self.id!s}, plan_hash={self.approved_plan_hash!r})"


class StagingDeploymentOperation(Base, TimestampMixin):
    """Durable, resumable, idempotent, concurrency-safe deployment operation attempt (SECP-B4).

    ``operation_fingerprint`` is a deterministic server key over (deployment, kind, plan hash) so a
    retry after a worker restart resolves to the SAME row (no duplicate work). A partial unique
    permits at most one in-flight (queued/claimed/running) operation per deployment.
    """

    __tablename__ = "staging_deployment_operation"
    __table_args__ = (
        UniqueConstraint("operation_fingerprint", name="uq_staging_deploy_op_fingerprint"),
        Index(
            "uq_staging_deploy_op_inflight",
            "deployment_id",
            unique=True,
            sqlite_where=text("status IN ('queued','claimed','running')"),
            postgresql_where=text("status IN ('queued','claimed','running')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    deployment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("staging_deployment.id"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    operation_kind: Mapped[DeploymentOperationKind] = mapped_column(
        EnumType(DeploymentOperationKind, length=40), nullable=False
    )
    operation_fingerprint: Mapped[str] = mapped_column(String(90), nullable=False)
    plan_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[DeploymentOperationStatus] = mapped_column(
        EnumType(DeploymentOperationStatus, length=40),
        default=DeploymentOperationStatus.queued,
        nullable=False,
    )
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    phase: Mapped[str | None] = mapped_column(String(60), nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    def __repr__(self) -> str:
        return (
            "StagingDeploymentOperation("
            f"id={self.id!s}, kind={getattr(self.operation_kind, 'value', self.operation_kind)!r}, "
            f"status={getattr(self.status, 'value', self.status)!r})"
        )


class StagingDeploymentResource(Base, TimestampMixin):
    """Durable inventory of a resource the engine created, ownership-bound with a typed inverse op
    (SECP-B4). Rollback/teardown may remove ONLY resources proven owned by this exact lab."""

    __tablename__ = "staging_deployment_resource"
    __table_args__ = (
        UniqueConstraint(
            "deployment_id", "resource_kind", "resource_ref", name="uq_staging_deploy_resource"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    deployment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("staging_deployment.id"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    resource_kind: Mapped[DeploymentResourceKind] = mapped_column(
        EnumType(DeploymentResourceKind, length=40), nullable=False
    )
    ownership_tag: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    resource_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    # The EXACT observed provider locator (typed, with a discriminator) captured after a fresh read
    # confirmed our marker. Rollback/teardown fresh-reads THIS locator before deleting — it is never
    # a
    # generic generated label. Null only for a record created before any observation (never
    # mutated).
    observed_locator: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # The unique per-resource ownership marker stamped into the provider-visible field and re-read
    # to
    # prove ownership before any mutation/inverse.
    ownership_marker: Mapped[str | None] = mapped_column(String(200), nullable=True)
    inverse_op: Mapped[DeploymentInverseOp] = mapped_column(
        EnumType(DeploymentInverseOp, length=40), nullable=False
    )
    state: Mapped[DeploymentResourceState] = mapped_column(
        EnumType(DeploymentResourceState, length=40),
        default=DeploymentResourceState.created,
        nullable=False,
    )
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    def __repr__(self) -> str:
        return (
            "StagingDeploymentResource("
            f"id={self.id!s}, kind={getattr(self.resource_kind, 'value', self.resource_kind)!r}, "
            f"state={getattr(self.state, 'value', self.state)!r})"
        )


class StagingDeploymentVerification(Base, TimestampMixin):
    """Immutable verification result for one deployment check (SECP-B4). Closed check code + status
    only; never an endpoint/host/value. Immutable after insert."""

    __tablename__ = "staging_deployment_verification"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    deployment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("staging_deployment.id"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    operation_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("staging_deployment_operation.id"), nullable=False, index=True
    )
    check_code: Mapped[DeploymentVerificationCode] = mapped_column(
        EnumType(DeploymentVerificationCode, length=60), nullable=False
    )
    status: Mapped[DeploymentVerificationStatus] = mapped_column(
        EnumType(DeploymentVerificationStatus, length=20), nullable=False
    )

    def __repr__(self) -> str:
        return (
            "StagingDeploymentVerification("
            f"check={getattr(self.check_code, 'value', self.check_code)!r}, "
            f"status={getattr(self.status, 'value', self.status)!r})"
        )


class StagingDeploymentPoPChallenge(Base, TimestampMixin):
    """Durable, atomic, single-use remote-PoP challenge nonce (SECP-B4 corrective).

    The verifier issues a nonce and persists it here; consumption is an atomic conditional UPDATE
    (``consumed`` False -> True), so a replayed nonce is refused even across a worker/verifier
    restart. Bindings are stored for audit/defense; forgery is additionally prevented by the Ed25519
    signature over the full binding. Stores no key, anchor, or signature.
    """

    __tablename__ = "staging_deployment_pop_challenge"
    __table_args__ = (UniqueConstraint("nonce", name="uq_staging_deploy_pop_nonce"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    nonce: Mapped[str] = mapped_column(String(96), nullable=False, index=True)
    # Binding evidence (indexed for lookup/scoping). This is an operational single-use nonce ledger;
    # its integrity is the unique nonce + atomic consume, and the bindings are additionally enforced
    # cryptographically by the Ed25519 signature — so these are plain UUID columns, not FK children.
    deployment_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, index=True)
    operation_fingerprint: Mapped[str] = mapped_column(String(90), nullable=False)
    worker_registration_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)
    plan_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    def __repr__(self) -> str:
        return f"StagingDeploymentPoPChallenge(consumed={self.consumed})"
