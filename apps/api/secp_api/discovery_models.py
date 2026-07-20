"""Durable ORM models for worker-owned read-only target discovery (SECP-B5).

The app-owned spine of the discovery lifecycle. Records store ONLY typed, bounded, secret-free
discovery evidence, safe provider LABELS (node id, storage id, candidate VMIDs, generated ownership
names), closed status/reason codes, deterministic hashes, and pinned version labels. They NEVER
store
a host/IP/endpoint/port, SSH host/account/key path/known_hosts path/fingerprint, credential, token,
certificate, raw command output, or network address. The discovery snapshot, candidate plan, and its
approval are content-addressed and immutable + undeletable after insert (ORM immutability guard).

They live in a dedicated module (imported by ``secp_api.models``) to keep the SECP-B5 diff focused;
they register on the shared ``Base`` exactly like every other model.
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
    DiscoveryCandidatePlanStatus,
    DiscoveryContactState,
    DiscoveryDecisionCode,
    DiscoveryEligibility,
    DiscoveryJobStatus,
    TargetDiscoveryStatus,
)
from secp_api.models import Base, UpdatedTimestampMixin, _uuid
from secp_api.types import EnumType


class TargetDiscoveryEnrollment(Base, UpdatedTimestampMixin):
    """The app-owned target-discovery enrollment the operator drives (SECP-B5). All labels are
    server-generated; it binds an active onboarding of an execution target. Lifecycle is mutable via
    compare-and-swap; live apply of any derived plan remains sealed in this PR."""

    __tablename__ = "target_discovery_enrollment"

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
    status: Mapped[TargetDiscoveryStatus] = mapped_column(
        EnumType(TargetDiscoveryStatus, length=40),
        default=TargetDiscoveryStatus.requested,
        nullable=False,
    )
    decision_code: Mapped[DiscoveryDecisionCode] = mapped_column(
        EnumType(DiscoveryDecisionCode, length=40),
        default=DiscoveryDecisionCode.pending,
        nullable=False,
    )
    enrollment_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    active_plan_hash: Mapped[str] = mapped_column(
        String(80), default="", nullable=False, index=True
    )
    approved_plan_hash: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failure_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    def __repr__(self) -> str:
        return (
            "TargetDiscoveryEnrollment("
            f"id={self.id!s}, ownership_label={self.ownership_label!r}, "
            f"status={getattr(self.status, 'value', self.status)!r})"
        )


class DiscoveryJob(Base, UpdatedTimestampMixin):
    """Durable, resumable, idempotent, concurrency-safe read-only discovery operation (SECP-B5).

    ``operation_fingerprint`` is a deterministic key over (enrollment, version), so a retry after a
    worker restart resolves to the SAME row. A partial unique permits at most one in-flight
    (queued/claimed/running) job per enrollment.
    """

    __tablename__ = "discovery_job"
    __table_args__ = (
        UniqueConstraint("operation_fingerprint", name="uq_discovery_job_fingerprint"),
        Index(
            "uq_discovery_job_inflight",
            "enrollment_id",
            unique=True,
            sqlite_where=text("status IN ('queued','claimed','running')"),
            postgresql_where=text("status IN ('queued','claimed','running')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    enrollment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_discovery_enrollment.id"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    operation_fingerprint: Mapped[str] = mapped_column(String(90), nullable=False)
    enrollment_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[DiscoveryJobStatus] = mapped_column(
        EnumType(DiscoveryJobStatus, length=40),
        default=DiscoveryJobStatus.queued,
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
            f"DiscoveryJob(id={self.id!s}, status={getattr(self.status, 'value', self.status)!r})"
        )


class DiscoverySnapshot(Base, UpdatedTimestampMixin):
    """Immutable typed discovery evidence (SECP-B5). ``evidence`` is a bounded, secret-free JSON of
    booleans/bounded ints/safe tokens only. Immutable + undeletable after insert."""

    __tablename__ = "discovery_snapshot"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    enrollment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_discovery_enrollment.id"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    job_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("discovery_job.id"), nullable=False, index=True
    )
    enrollment_version: Mapped[int] = mapped_column(Integer, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    capacity_snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    eligibility: Mapped[DiscoveryEligibility] = mapped_column(
        EnumType(DiscoveryEligibility, length=20), nullable=False
    )
    reason_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)
    bundle_available: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Durable truth from the worker outcome. Never derive target contact from enablement flags or
    # bundle presence.
    contact_state: Mapped[DiscoveryContactState] = mapped_column(
        EnumType(DiscoveryContactState, length=40),
        default=DiscoveryContactState.unverifiable,
        nullable=False,
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    def __repr__(self) -> str:
        return (
            "DiscoverySnapshot("
            f"id={self.id!s}, eligibility={getattr(self.eligibility, 'value', self.eligibility)!r})"
        )


class DiscoveryCandidatePlan(Base, UpdatedTimestampMixin):
    """Immutable, content-addressed discovery-derived candidate plan (SECP-B5). Binds the exact
    discovered node/storage identity, bounded candidate VMIDs, generated ownership names + markers,
    and every drift anchor. ``executable`` is False — live apply is sealed. Immutable +
    undeletable."""

    __tablename__ = "discovery_candidate_plan"
    __table_args__ = (
        UniqueConstraint("enrollment_id", "plan_hash", name="uq_discovery_candidate_plan_hash"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    enrollment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_discovery_enrollment.id"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("discovery_snapshot.id"), nullable=False, index=True
    )
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False)
    plan_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    plan_document: Mapped[dict] = mapped_column(JSON, nullable=False)
    node: Mapped[str] = mapped_column(String(64), nullable=False)
    storage: Mapped[str] = mapped_column(String(64), nullable=False)
    ownership_tag: Mapped[str] = mapped_column(String(120), nullable=False)
    capacity_snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)
    enrollment_version: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[DiscoveryCandidatePlanStatus] = mapped_column(
        EnumType(DiscoveryCandidatePlanStatus, length=20),
        default=DiscoveryCandidatePlanStatus.draft,
        nullable=False,
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    def __repr__(self) -> str:
        return f"DiscoveryCandidatePlan(id={self.id!s}, plan_hash={self.plan_hash!r})"


class DiscoveryCandidatePlanApproval(Base, UpdatedTimestampMixin):
    """Immutable explicit approval binding one EXACT candidate-plan hash + every drift anchor
    (enrollment version, evidence hash, capacity snapshot hash, worker identity version, expiry).
    Immutable + undeletable after insert."""

    __tablename__ = "discovery_candidate_plan_approval"
    __table_args__ = (
        UniqueConstraint("enrollment_id", "plan_hash", name="uq_discovery_candidate_plan_approval"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    enrollment_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_discovery_enrollment.id"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    plan_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    ownership_tag: Mapped[str] = mapped_column(String(120), nullable=False)
    capacity_snapshot_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)
    enrollment_version: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)

    def __repr__(self) -> str:
        return f"DiscoveryCandidatePlanApproval(id={self.id!s}, plan_hash={self.plan_hash!r})"
