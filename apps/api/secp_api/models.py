"""SQLAlchemy ORM models — the control-plane system of record (Charter §7, §14).

Design notes
------------
* All tenant resources carry ``organization_id`` and are authorization-scoped.
* ``EnvironmentVersion`` and ``AuditEvent`` are immutable; enforcement lives in
  :mod:`secp_api.immutability` (ORM-level guard) plus the service layer
  (no update path) and, for PostgreSQL, a migration-installed trigger.
* The ``simulated_*`` tables are the normalized inventory/topology projection.
  In SECP-001 only the Simulator writes them; the ``provider`` column anticipates
  additional producers, so the core has no provider-specific columns
  (Charter Invariant 9).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from secp_api.enums import (
    ChangeSetApprovalStatus,
    EvidenceStatus,
    IsolationModel,
    LifecycleState,
    LivePreflightEvidenceStatus,
    LiveReadAuthorizationStatus,
    OnboardingMode,
    OnboardingStatus,
    PlanStatus,
    ProvisioningOperationKind,
    ProvisioningStatus,
    ReadonlyPreflightOutcome,
    ReadonlyPreflightStatus,
    ReservationStatus,
    ResolutionLeaseStatus,
    ResolverActivationEvidenceKind,
    ResolverActivationEvidenceStatus,
    ResolverActivationStatus,
    SnapshotStatus,
    StagingBootstrapArtifactProfile,
    StagingLabDecisionCode,
    StagingLabProfile,
    StagingLabPurpose,
    StagingLabStatus,
    StagingNetworkIntent,
    StagingResourceClass,
    StagingRollbackPolicy,
    StagingSubstrateEligibilityStatus,
    StagingWorkFailureCode,
    StagingWorkOperation,
    StagingWorkStatus,
    TargetStatus,
    ToolchainProfileStatus,
    WorkerIdentityEvidenceKind,
    WorkerIdentityEvidenceStatus,
    WorkerIdentityMechanism,
    WorkerIdentityStatus,
    WorkflowKind,
    WorkflowStatus,
)
from secp_api.types import EnumType


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


# --- Tenancy & identity -------------------------------------------------------


class Organization(Base, TimestampMixin):
    __tablename__ = "organization"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), unique=True, nullable=False)


class User(Base, TimestampMixin):
    __tablename__ = "app_user"
    __table_args__ = (UniqueConstraint("organization_id", "email"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True)


class Role(Base, TimestampMixin):
    __tablename__ = "role"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(500), default="")
    # List[str] of Permission values.
    permissions: Mapped[list] = mapped_column(JSON, default=list)


class UserRoleAssignment(Base, TimestampMixin):
    __tablename__ = "user_role_assignment"
    __table_args__ = (UniqueConstraint("user_id", "role_id", "organization_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("app_user.id"), nullable=False, index=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("role.id"), nullable=False)


class Team(Base, TimestampMixin):
    __tablename__ = "team"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), nullable=False)


# --- Templates & immutable versions ------------------------------------------


class EnvironmentTemplate(Base, TimestampMixin):
    __tablename__ = "environment_template"
    __table_args__ = (UniqueConstraint("organization_id", "slug"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    versions: Mapped[list[EnvironmentVersion]] = relationship(
        back_populates="template", cascade="all, delete-orphan"
    )


class EnvironmentVersion(Base, TimestampMixin):
    """Immutable snapshot of a template's declarative spec (Charter Invariant 2).

    Protected columns (``spec``, ``content_hash``, ``version_number``,
    ``api_version``) must never change after creation. See
    :mod:`secp_api.immutability`.
    """

    __tablename__ = "environment_version"
    __table_args__ = (UniqueConstraint("template_id", "version_number"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    template_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("environment_template.id"), nullable=False, index=True
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    api_version: Mapped[str] = mapped_column(String(100), nullable=False)
    spec: Mapped[dict] = mapped_column(JSON, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    template: Mapped[EnvironmentTemplate] = relationship(back_populates="versions")


# --- Exercises & instances ----------------------------------------------------


class Exercise(Base, TimestampMixin):
    __tablename__ = "exercise"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    template_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("environment_template.id"), nullable=False
    )
    environment_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("environment_version.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    lifecycle_state: Mapped[LifecycleState] = mapped_column(
        EnumType(LifecycleState), default=LifecycleState.draft, nullable=False
    )
    team_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    # Optional approved destination (ADR-006). None => the safe inline Simulator
    # path (unchanged behavior). SECP-002A does not allow deploying to a real
    # (e.g. Proxmox) target; that is deferred to SECP-002B.
    execution_target_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=True, index=True
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    instances: Mapped[list[EnvironmentInstance]] = relationship(
        back_populates="exercise", cascade="all, delete-orphan"
    )


class EnvironmentInstance(Base, TimestampMixin):
    """One isolated environment assigned to one team (Charter Invariant 5)."""

    __tablename__ = "environment_instance"
    __table_args__ = (UniqueConstraint("exercise_id", "team_index"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    exercise_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("exercise.id"), nullable=False, index=True
    )
    team_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("team.id"), nullable=True)
    team_index: Mapped[int] = mapped_column(Integer, nullable=False)
    instance_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    team_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    lifecycle_state: Mapped[LifecycleState] = mapped_column(
        EnumType(LifecycleState), default=LifecycleState.deploying, nullable=False
    )
    provider: Mapped[str] = mapped_column(String(60), default="simulator")

    exercise: Mapped[Exercise] = relationship(back_populates="instances")
    networks: Mapped[list[EnvironmentNetwork]] = relationship(
        back_populates="instance", cascade="all, delete-orphan"
    )
    nodes: Mapped[list[EnvironmentNode]] = relationship(
        back_populates="instance", cascade="all, delete-orphan"
    )
    edges: Mapped[list[EnvironmentTopologyEdge]] = relationship(
        back_populates="instance", cascade="all, delete-orphan"
    )


# --- Deployment plan, workflows, plugins, artifacts --------------------------


class DeploymentPlan(Base, TimestampMixin):
    __tablename__ = "deployment_plan"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    exercise_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("exercise.id"), nullable=False, index=True
    )
    environment_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("environment_version.id"), nullable=False
    )
    version_content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    # Pin the execution target + its config hash when one is selected (ADR-006), so
    # approval covers the exact destination. Null for the Simulator path.
    execution_target_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=True
    )
    target_config_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # Hash of scope_policy["provisioning"] at plan-generation time (SECP-002B-0).
    # Nullable for pre-migration rows; manifest generation fails closed when None.
    target_scope_policy_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # Pinned toolchain profile for the real OpenTofu path (SECP-002B-1A, ADR-013).
    # Null for the Simulator path and for fake-runner (B0) targets with no profile;
    # the real-lab activation gate fails closed when either is None.
    toolchain_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("toolchain_profile.id"), nullable=True
    )
    toolchain_profile_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # Enforceable onboarding binding (SECP-002B-1B-0, ADR-014). Null for the Simulator
    # path; required for target-bound plans (bound to the single active onboarding).
    target_onboarding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=True
    )
    onboarding_boundary_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    approved_preflight_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_preflight_evidence_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    onboarding_verification_level: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # Effective execution boundary = declared onboarding boundary ∩ target scope policy
    # (SECP-002B-1B-0 correction pass, ADR-014 §2). Immutable; recomputed + required to
    # agree at manifest generation and the worker gate. Null for the Simulator path.
    effective_boundary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    effective_boundary_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    status: Mapped[PlanStatus] = mapped_column(
        EnumType(PlanStatus), default=PlanStatus.generated, nullable=False
    )
    plan: Mapped[dict] = mapped_column(JSON, nullable=False)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    generated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_content_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    decision_reason: Mapped[str] = mapped_column(Text, default="")


class WorkflowRun(Base, TimestampMixin):
    __tablename__ = "workflow_run"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    # Nullable: discovery workflows are target-scoped, not exercise-scoped.
    exercise_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("exercise.id"), nullable=True, index=True
    )
    execution_target_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=True, index=True
    )
    snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("provider_inventory_snapshot.id"), nullable=True, index=True
    )
    kind: Mapped[WorkflowKind] = mapped_column(EnumType(WorkflowKind), nullable=False)
    status: Mapped[WorkflowStatus] = mapped_column(
        EnumType(WorkflowStatus), default=WorkflowStatus.running, nullable=False
    )
    dispatch_mode: Mapped[str] = mapped_column(String(20), default="inline")
    correlation_id: Mapped[str] = mapped_column(String(80), nullable=False)
    # Durable workflow identifier (Temporal workflow id) when dispatched durably.
    workflow_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_instance_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    snapshot: Mapped[ProviderInventorySnapshot | None] = relationship(
        back_populates="workflow_runs"
    )
    outbox: Mapped[WorkflowDispatchOutbox | None] = relationship(
        back_populates="workflow_run", cascade="all, delete-orphan"
    )


class WorkflowDispatchOutbox(Base, TimestampMixin):
    """Durable post-commit workflow submission request (ADR-010 correction)."""

    __tablename__ = "workflow_dispatch_outbox"
    __table_args__ = (
        UniqueConstraint("workflow_run_id"),
        UniqueConstraint("workflow_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    workflow_run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("workflow_run.id"), nullable=False, index=True
    )
    workflow: Mapped[str] = mapped_column(String(120), nullable=False)
    workflow_id: Mapped[str] = mapped_column(String(255), nullable=False)
    task_queue: Mapped[str] = mapped_column(String(255), nullable=False)
    args: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="pending", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    workflow_run: Mapped[WorkflowRun] = relationship(back_populates="outbox")


class Plugin(Base, TimestampMixin):
    __tablename__ = "plugin"
    __table_args__ = (UniqueConstraint("name", "version"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    contract_version: Mapped[str] = mapped_column(String(20), nullable=False)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)
    simulated: Mapped[bool] = mapped_column(Boolean, default=False)
    healthy: Mapped[bool] = mapped_column(Boolean, default=True)


class Artifact(Base, TimestampMixin):
    __tablename__ = "artifact"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    exercise_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("exercise.id"), nullable=True, index=True
    )
    kind: Mapped[str] = mapped_column(String(60), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    uri: Mapped[str] = mapped_column(String(500), default="")
    sha256: Mapped[str | None] = mapped_column(String(80), nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


class AuditEvent(Base, TimestampMixin):
    """Immutable audit record. Every mutation creates one (Charter Invariant 10)."""

    __tablename__ = "audit_event"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=True, index=True
    )
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    outcome: Mapped[str] = mapped_column(String(40), default="success")
    data: Mapped[dict] = mapped_column(JSON, default=dict)


# --- Generic observed inventory / topology projection (ADR-008) --------------
# Provider-neutral: every provider (the Simulator today; real providers later)
# populates the SAME tables. No provider-specific columns (Charter Invariant 9).
# Provenance columns (`provider`, `source`, `simulated`, `observed_at`,
# `provider_resource_id`, `provider_resource_type`) describe where a row came from.


class EnvironmentNetwork(Base, TimestampMixin):
    __tablename__ = "environment_network"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    instance_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("environment_instance.id"), nullable=False, index=True
    )
    ref: Mapped[str] = mapped_column(String(120), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    team_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    isolated: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(40), default="up")
    # Generic provenance / provider linkage.
    provider: Mapped[str] = mapped_column(String(60), default="simulator")
    provider_resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    provider_resource_type: Mapped[str] = mapped_column(String(60), default="network")
    source: Mapped[str] = mapped_column(String(60), default="simulator")
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)

    instance: Mapped[EnvironmentInstance] = relationship(back_populates="networks")


class EnvironmentNode(Base, TimestampMixin):
    __tablename__ = "environment_node"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    instance_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("environment_instance.id"), nullable=False, index=True
    )
    ref: Mapped[str] = mapped_column(String(120), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    role: Mapped[str] = mapped_column(String(120), nullable=False)
    image: Mapped[str] = mapped_column(String(200), nullable=False)
    network_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(40), default="up")
    # Generic provenance / provider linkage.
    provider: Mapped[str] = mapped_column(String(60), default="simulator")
    provider_resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    provider_resource_type: Mapped[str] = mapped_column(String(60), default="node")
    source: Mapped[str] = mapped_column(String(60), default="simulator")
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)

    instance: Mapped[EnvironmentInstance] = relationship(back_populates="nodes")


class EnvironmentTopologyEdge(Base, TimestampMixin):
    __tablename__ = "environment_topology_edge"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    instance_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("environment_instance.id"), nullable=False, index=True
    )
    source_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    provider: Mapped[str] = mapped_column(String(60), default="simulator")
    source: Mapped[str] = mapped_column(String(60), default="simulator")
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)

    instance: Mapped[EnvironmentInstance] = relationship(back_populates="edges")


# --- Execution targets and provider discovery (SECP-002A) --------------------


class ExecutionTarget(Base, TimestampMixin):
    """Approved, organization-scoped destination for a deployment (ADR-006).

    Provider-neutral. ``config`` is immutable non-secret JSON; ``secret_ref`` is an
    opaque pointer (NEVER a secret). ``config``/``config_hash``/``plugin_name`` are
    immutable after creation — new configuration requires a new target record.
    """

    __tablename__ = "execution_target"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    plugin_name: Mapped[str] = mapped_column(String(100), nullable=False)
    config: Mapped[dict] = mapped_column(JSON, nullable=False)
    config_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    secret_ref: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status: Mapped[TargetStatus] = mapped_column(
        EnumType(TargetStatus), default=TargetStatus.active, nullable=False
    )
    scope_policy: Mapped[dict] = mapped_column(JSON, default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    address_spaces: Mapped[list[AddressSpacePolicy]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    onboardings: Mapped[list[TargetOnboarding]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    live_read_authorizations: Mapped[list[LiveReadAuthorization]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    staging_labs: Mapped[list[StagingLab]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )
    staging_substrate_eligibilities: Mapped[list[StagingSubstrateEligibility]] = relationship(
        back_populates="target", cascade="all, delete-orphan"
    )


# --- Target onboarding + automated deployment contract (SECP-002B-1B-0) -------


class TargetOnboarding(Base, TimestampMixin):
    """Provider-neutral onboarding record for an execution target (ADR-014).

    Captures the onboarding mode (clean vs existing environment), the isolation model
    (physical vs logical), the immutable declared boundary + its hash, and the human
    approval. A target is cleared for real provisioning only when an onboarding reaches
    ``active`` with no config/scope drift since approval. ``declared_boundary``,
    ``boundary_hash``, ``onboarding_mode``, ``isolation_model``, ``execution_target_id``,
    and ``organization_id`` are immutable after creation (see
    :mod:`secp_api.immutability`). Secret-free.
    """

    __tablename__ = "target_onboarding"
    # At most ONE active onboarding per execution target (fail-closed ambiguity control).
    __table_args__ = (
        Index(
            "uq_target_onboarding_active",
            "execution_target_id",
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
    onboarding_mode: Mapped[OnboardingMode] = mapped_column(
        EnumType(OnboardingMode), nullable=False
    )
    isolation_model: Mapped[IsolationModel] = mapped_column(
        EnumType(IsolationModel), nullable=False
    )
    status: Mapped[OnboardingStatus] = mapped_column(
        EnumType(OnboardingStatus, length=40), default=OnboardingStatus.draft, nullable=False
    )
    declared_boundary: Mapped[dict] = mapped_column(JSON, nullable=False)
    boundary_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    # Pinned at approval so config/scope drift invalidates the approval (checked at activation).
    approved_target_config_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    approved_scope_policy_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # The exact approved preflight evidence package (SECP-002B-1B-0, ADR-014 §3). Pinned at
    # approval; later preflights cannot silently replace it. Plain Uuid (no DB-level FK) to
    # avoid a circular FK with target_preflight; integrity is enforced in the service layer.
    approved_preflight_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_preflight_evidence_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    approved_boundary_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    approved_verification_level: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_reason: Mapped[str] = mapped_column(Text, default="")
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    target: Mapped[ExecutionTarget] = relationship(back_populates="onboardings")
    preflights: Mapped[list[TargetPreflight]] = relationship(
        back_populates="onboarding", cascade="all, delete-orphan"
    )
    evidence_records: Mapped[list[TargetEvidenceRecord]] = relationship(back_populates="onboarding")
    live_read_authorizations: Mapped[list[LiveReadAuthorization]] = relationship(
        back_populates="onboarding", cascade="all, delete-orphan"
    )


class TargetEvidenceRecord(Base, TimestampMixin):
    """Append-only provider-neutral read-only target evidence (SECP-002B-1B-1).

    Stores a canonical, secret-free observed-target evidence payload plus structured
    comparison findings against one onboarding's declared boundary. In this release the
    only accepted source is simulated evidence; live collector support remains sealed.
    """

    __tablename__ = "target_evidence_record"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    onboarding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    evidence_source: Mapped[str] = mapped_column(String(80), nullable=False)
    verification_level: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[EvidenceStatus] = mapped_column(
        EnumType(EvidenceStatus, length=40), nullable=False
    )
    evidence_payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    findings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    onboarding: Mapped[TargetOnboarding] = relationship(back_populates="evidence_records")
    preflights: Mapped[list[TargetPreflight]] = relationship(back_populates="target_evidence")


class TargetPreflight(Base, TimestampMixin):
    """Immutable, redacted, structured onboarding preflight evidence (ADR-014).

    Provider-neutral. ``checks`` holds only redacted, review-safe entries; ``evidence_hash``
    binds them. ``collector`` names the seam that produced the evidence (``fake`` in
    SECP-002B-1B-0). No real target is inspected. Append-only: immutable after creation.
    """

    __tablename__ = "target_preflight"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    onboarding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=False, index=True
    )
    collector: Mapped[str] = mapped_column(String(60), default="fake", nullable=False)
    # Trusted-provenance model (SECP-002B-1B-0, ADR-014 §2): only ``live_verified`` evidence
    # from the ``provider_worker`` collector can unlock future live provisioning.
    verification_level: Mapped[str] = mapped_column(String(40), nullable=False, default="simulated")
    collector_kind: Mapped[str] = mapped_column(
        String(60), nullable=False, default="fake_declared_boundary"
    )
    collector_identity: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    evidence_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Provenance snapshot at collection time (part of the evidence hash).
    target_config_hash: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    scope_policy_hash: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    boundary_hash: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    toolchain_profile_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    toolchain_profile_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    passed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    checks: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    target_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("target_evidence_record.id"), nullable=True, index=True
    )
    target_evidence_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    onboarding: Mapped[TargetOnboarding] = relationship(back_populates="preflights")
    target_evidence: Mapped[TargetEvidenceRecord | None] = relationship(back_populates="preflights")


class LiveReadAuthorization(Base, TimestampMixin):
    """Secret-free durable authorization contract for future live read-only collection.

    Provider-neutral and dormant: this row records only safe binding facts and lifecycle
    state. It never stores endpoints, raw target configuration, declared boundary contents,
    credential/secret references, tokens, observations, or evidence payloads.
    """

    __tablename__ = "live_read_authorization"
    __table_args__ = (
        UniqueConstraint(
            "execution_target_id",
            "onboarding_id",
            "authorization_version",
            name="uq_live_read_authorization_target_onboarding_version",
        ),
    )

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
    connection_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    boundary_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    authorization_version: Mapped[int] = mapped_column(Integer, nullable=False)
    authorization_expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    collector_contract_version: Mapped[str] = mapped_column(String(120), nullable=False)
    endpoint_allowlist_version: Mapped[str] = mapped_column(String(120), nullable=False)
    evidence_source: Mapped[str] = mapped_column(String(80), nullable=False)
    verification_level: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[LiveReadAuthorizationStatus] = mapped_column(
        EnumType(LiveReadAuthorizationStatus, length=40),
        default=LiveReadAuthorizationStatus.draft,
        nullable=False,
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason_code: Mapped[str] = mapped_column(String(80), default="", nullable=False)

    target: Mapped[ExecutionTarget] = relationship(back_populates="live_read_authorizations")
    onboarding: Mapped[TargetOnboarding] = relationship(back_populates="live_read_authorizations")

    def __repr__(self) -> str:
        return (
            "LiveReadAuthorization("
            f"id={self.id!s}, "
            f"organization_id={self.organization_id!s}, "
            f"execution_target_id={self.execution_target_id!s}, "
            f"onboarding_id={self.onboarding_id!s}, "
            f"authorization_version={self.authorization_version!r}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            "connection_hash=<sha256>, "
            "boundary_hash=<sha256>)"
        )


class StagingLab(Base, TimestampMixin):
    """Application-owned declarative disposable staging lab (SECP-002B-1B-9).

    Fake-only and provider-neutral. This row is the durable desired-state + lifecycle record for
    a disposable read-only staging lab. It stores only safe logical intent: purpose, the approved
    substrate target id, profile, network intent, a bounded logical resource class, an approved
    bootstrap-artifact *profile id* (never paths/URLs/checksums), rollback policy, an immutable
    ownership label, lifecycle state, an immutable desired-state plan + its version + hash,
    approval metadata, and a fake simulated-observed-state.

    It NEVER stores endpoints, hostnames, IPs, bridge/VNet names, VMIDs, storage ids, certificate
    data, secrets/tokens/credential references/secret hashes, raw artifact paths/URLs/checksums,
    or actual provider observations. Reaching ``simulated_ready`` creates no infrastructure and is
    not live read-only collection. A staging-lab approval is separate from and never substitutes
    for a :class:`LiveReadAuthorization`.
    """

    __tablename__ = "staging_lab"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    ownership_label: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    purpose: Mapped[StagingLabPurpose] = mapped_column(
        EnumType(StagingLabPurpose, length=60),
        default=StagingLabPurpose.disposable_readonly_staging,
        nullable=False,
    )
    profile: Mapped[StagingLabProfile] = mapped_column(
        EnumType(StagingLabProfile, length=60),
        default=StagingLabProfile.nested_proxmox,
        nullable=False,
    )
    network_intent: Mapped[StagingNetworkIntent] = mapped_column(
        EnumType(StagingNetworkIntent, length=60),
        default=StagingNetworkIntent.host_only_no_uplink,
        nullable=False,
    )
    resource_class: Mapped[StagingResourceClass] = mapped_column(
        EnumType(StagingResourceClass, length=40),
        default=StagingResourceClass.small_lab,
        nullable=False,
    )
    rollback_policy: Mapped[StagingRollbackPolicy] = mapped_column(
        EnumType(StagingRollbackPolicy, length=60),
        default=StagingRollbackPolicy.revert_to_known_clean_checkpoint,
        nullable=False,
    )
    # Approved offline bootstrap-artifact profile — a closed backend catalog enum, never a
    # caller-supplied artifact id/path/URL/checksum. Stored as its enum value.
    bootstrap_artifact_profile: Mapped[StagingBootstrapArtifactProfile] = mapped_column(
        EnumType(StagingBootstrapArtifactProfile, length=60),
        default=StagingBootstrapArtifactProfile.nested_proxmox_offline_base,
        nullable=False,
    )
    status: Mapped[StagingLabStatus] = mapped_column(
        EnumType(StagingLabStatus, length=40),
        default=StagingLabStatus.draft,
        nullable=False,
    )
    # Optimistic-concurrency revision. Every lifecycle mutation performs a compare-and-swap on
    # (status, revision); a stale writer's conditional UPDATE affects zero rows and fails closed.
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Immutable desired-state plan (logical resources only) + version + hash. Set once at plan
    # generation; the plan cannot change after approval.
    plan_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    plan_hash: Mapped[str] = mapped_column(String(80), default="", nullable=False, index=True)
    desired_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Fake simulated observed-state (logical only); reconciled idempotently on retry.
    simulated_observed_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    # Approval binding (set once at approval): approver, time, and the exact approved plan.
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_plan_hash: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    approved_plan_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Closed decision/outcome code — never free text.
    decision_code: Mapped[StagingLabDecisionCode] = mapped_column(
        EnumType(StagingLabDecisionCode, length=40),
        default=StagingLabDecisionCode.pending,
        nullable=False,
    )

    target: Mapped[ExecutionTarget] = relationship(back_populates="staging_labs")
    work_items: Mapped[list[StagingLabWorkItem]] = relationship(
        back_populates="staging_lab", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            "StagingLab("
            f"id={self.id!s}, "
            f"organization_id={self.organization_id!s}, "
            f"execution_target_id={self.execution_target_id!s}, "
            f"ownership_label={self.ownership_label!r}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            f"plan_version={self.plan_version!r}, "
            f"plan_hash={self.plan_hash!r})"
        )


class StagingLabWorkItem(Base, TimestampMixin):
    """Durable, secret-free staging-lab work item (SECP-002B-1B-9).

    The API commits a ``queued`` item and returns; only the worker claims and processes it. It
    records only safe logical values (ids, immutable plan hash/version, operation kind, a
    server-generated operation fingerprint, lifecycle state, revision, timestamps, and a closed
    failure code) and NEVER an endpoint, host, IP, network, VMID, storage, certificate, token,
    credential, secret ref, artifact path/URL/checksum, or any provider observation.

    The ``operation_fingerprint`` is a deterministic server-generated key over
    (staging_lab_id, operation_kind, plan_hash, plan_version); it is unique, and the same
    (lab, operation, plan) scope is additionally enforced by ``uq_staging_work_scope`` so a retry
    for the identical operation and plan resolves to the original work item.
    """

    __tablename__ = "staging_lab_work_item"
    __table_args__ = (
        UniqueConstraint("operation_fingerprint", name="uq_staging_work_fingerprint"),
        # Uniqueness over the full intended scope (lab + operation + immutable plan hash/version).
        UniqueConstraint(
            "staging_lab_id",
            "operation_kind",
            "plan_hash",
            "plan_version",
            name="uq_staging_work_scope",
        ),
        # At most ONE active (queued or claimed) work item per lab+operation (fail-closed).
        Index(
            "uq_staging_work_active",
            "staging_lab_id",
            "operation_kind",
            unique=True,
            sqlite_where=text("status in ('queued','claimed')"),
            postgresql_where=text("status in ('queued','claimed')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    staging_lab_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("staging_lab.id"), nullable=False, index=True
    )
    operation_kind: Mapped[StagingWorkOperation] = mapped_column(
        EnumType(StagingWorkOperation, length=40), nullable=False
    )
    plan_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # Deterministic server-generated key over (lab, operation, plan_hash, plan_version).
    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[StagingWorkStatus] = mapped_column(
        EnumType(StagingWorkStatus, length=40),
        default=StagingWorkStatus.queued,
        nullable=False,
    )
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Closed failure/refusal code — never a free-text string.
    failure_code: Mapped[StagingWorkFailureCode | None] = mapped_column(
        EnumType(StagingWorkFailureCode, length=40), nullable=True
    )
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    staging_lab: Mapped[StagingLab] = relationship(back_populates="work_items")

    def __repr__(self) -> str:
        return (
            "StagingLabWorkItem("
            f"id={self.id!s}, staging_lab_id={self.staging_lab_id!s}, "
            f"operation_kind={getattr(self.operation_kind, 'value', self.operation_kind)!r}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            f"plan_version={self.plan_version!r})"
        )


class StagingSubstrateEligibility(Base, TimestampMixin):
    """Durable marker: a target is approved as a disposable staging substrate (SECP-002B-1B-9).

    A target does NOT become a staging substrate merely by being active with an active onboarding;
    a target admin must additionally issue this eligibility record. Secret-free.
    """

    __tablename__ = "staging_substrate_eligibility"
    __table_args__ = (
        Index(
            "uq_staging_substrate_active",
            "execution_target_id",
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
    plugin_type: Mapped[str] = mapped_column(String(40), nullable=False)
    allowed_profile: Mapped[StagingLabProfile] = mapped_column(
        EnumType(StagingLabProfile, length=60), nullable=False
    )
    status: Mapped[StagingSubstrateEligibilityStatus] = mapped_column(
        EnumType(StagingSubstrateEligibilityStatus, length=40),
        default=StagingSubstrateEligibilityStatus.active,
        nullable=False,
    )
    issued_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    target: Mapped[ExecutionTarget] = relationship(back_populates="staging_substrate_eligibilities")


class ReadonlyStagingPreflight(Base, TimestampMixin):
    """Durable, secret-free app-owned read-only staging-preflight intent (SECP-B2-0).

    The API commits a ``queued`` intent bound immutably to one authoritative
    (organization, execution target, onboarding, live-read authorization + version) tuple; only
    the worker claims and processes it, records a closed outcome code, and stores only safe
    readiness facts (booleans/counts). It NEVER stores endpoints, hosts, IPs, ports, paths,
    bridge/VNet/VLAN/VMID/storage identifiers, certificate data, tokens, credentials, secret
    references, target config values, or raw provider observations.

    The ``operation_fingerprint`` is a deterministic server-generated key over
    (organization, target, onboarding, authorization id, authorization version).
    """

    __tablename__ = "readonly_staging_preflight"
    __table_args__ = (
        UniqueConstraint("operation_fingerprint", name="uq_readonly_preflight_fingerprint"),
        UniqueConstraint(
            "execution_target_id",
            "onboarding_id",
            "live_read_authorization_id",
            "authorization_version",
            name="uq_readonly_preflight_scope",
        ),
        # At most ONE active (queued/claimed/running) preflight per target+onboarding+authorization.
        Index(
            "uq_readonly_preflight_active",
            "execution_target_id",
            "onboarding_id",
            "live_read_authorization_id",
            unique=True,
            sqlite_where=text("status in ('queued','claimed','running')"),
            postgresql_where=text("status in ('queued','claimed','running')"),
        ),
    )

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
    live_read_authorization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("live_read_authorization.id"), nullable=False, index=True
    )
    authorization_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # Pinned contract labels (immutable) — must match the authorization + worker/plugin.
    collector_contract_version: Mapped[str] = mapped_column(String(120), nullable=False)
    endpoint_allowlist_version: Mapped[str] = mapped_column(String(120), nullable=False)
    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[ReadonlyPreflightStatus] = mapped_column(
        EnumType(ReadonlyPreflightStatus, length=40),
        default=ReadonlyPreflightStatus.queued,
        nullable=False,
    )
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Closed outcome code (set once by the worker at terminal); never free text.
    outcome_code: Mapped[ReadonlyPreflightOutcome | None] = mapped_column(
        EnumType(ReadonlyPreflightOutcome, length=40), nullable=True
    )
    # Safe readiness facts only (booleans/counts); never endpoints/config/observations.
    readiness_facts: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    target: Mapped[ExecutionTarget] = relationship()

    def __repr__(self) -> str:
        return (
            "ReadonlyStagingPreflight("
            f"id={self.id!s}, execution_target_id={self.execution_target_id!s}, "
            f"onboarding_id={self.onboarding_id!s}, "
            f"live_read_authorization_id={self.live_read_authorization_id!s}, "
            f"authorization_version={self.authorization_version!r}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            f"outcome_code={getattr(self.outcome_code, 'value', self.outcome_code)!r})"
        )


class ResolutionLease(Base, TimestampMixin):
    """Durable, secret-free resolution-operation + short-lived lease state (SECP-B2-3).

    One row per **global operation uniqueness key**
    ``(live_read_authorization_id, authorization_version, operation_fingerprint)``. It carries the
    durable retry budget (``attempt_count``, fixed cap N=3) that is shared across every lease
    instance and every worker identity for that key, the current pre-success lease instance, and a
    closed refusal ``reason_code``. ``worker_identity_id`` is a secret-free identifier recorded for
    audit/evidence only and is deliberately **not** part of the uniqueness key.

    It NEVER stores a credential value, a credential/secret reference, an endpoint, target
    configuration, a certificate, a backend response, or a hash of any secret/reference. It contacts
    nothing and cannot resolve a secret; the shipped worker never creates a row (it fails closed at
    the sealed worker-identity/activation gate before lease acquisition).
    """

    __tablename__ = "resolution_lease"
    __table_args__ = (
        # Global operation uniqueness boundary — exactly the B2-2 key; NO worker identity.
        UniqueConstraint(
            "live_read_authorization_id",
            "authorization_version",
            "operation_fingerprint",
            name="uq_resolution_lease_operation",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    live_read_authorization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("live_read_authorization.id"), nullable=False, index=True
    )
    authorization_version: Mapped[int] = mapped_column(Integer, nullable=False)
    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    # Current lease instance id (rotates on re-acquisition after a lease expires).
    lease_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, default=_uuid)
    # Compare-and-swap guard for every durable transition.
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[ResolutionLeaseStatus] = mapped_column(
        EnumType(ResolutionLeaseStatus, length=40),
        default=ResolutionLeaseStatus.active,
        nullable=False,
    )
    # Durable attempt budget (cap N=3), preserved across lease instances and worker identities.
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # Short lease-instance expiry; always <= the authorization expiry.
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Secret-free worker identity that currently holds / last held the lease (evidence only).
    worker_identity_id: Mapped[str] = mapped_column(String(120), nullable=False)
    # Closed refusal reason code on a terminal transition; never free text, never a value.
    reason_code: Mapped[str] = mapped_column(String(60), default="", nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return (
            "ResolutionLease("
            f"id={self.id!s}, "
            f"live_read_authorization_id={self.live_read_authorization_id!s}, "
            f"authorization_version={self.authorization_version!r}, "
            f"operation_fingerprint={self.operation_fingerprint!r}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            f"attempt_count={self.attempt_count!r}, "
            f"revision={self.revision!r})"
        )


class ResolverActivationAuthorization(Base, TimestampMixin):
    """Durable, provider-neutral, secret-free authorization to *consider* resolver activation
    exact operation context (SECP-B2-4.1).

    This app-owned control-plane record is the SEPARATE, explicit, time-bounded, audited, revocable
    authorization that must exist (and be independently re-verified by the worker) before any future
    isolated-staging OpenBao activation can be considered. It grants **no** infrastructure
    performs **no** resolution, and is **never** auto-created from a ``LiveReadAuthorization`` or a
    staging-lab approval. It stores ONLY safe binding facts + hashes + lifecycle state — never an
    endpoint, hostname, port, token, policy, mount, unseal material, credential, backend
    configuration, vault path, or plaintext reference.
    """

    __tablename__ = "resolver_activation_authorization"
    __table_args__ = (
        # Server-derived monotonic version per (target, onboarding) — no caller-supplied version.
        UniqueConstraint(
            "execution_target_id",
            "onboarding_id",
            "authorization_version",
            name="uq_resolver_activation_target_onboarding_version",
        ),
        # At most ONE non-terminal (draft/approved) authorization per bound operation (work item).
        Index(
            "uq_resolver_activation_active_operation",
            "preflight_id",
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
    onboarding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=False, index=True
    )
    live_read_authorization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("live_read_authorization.id"), nullable=False, index=True
    )
    live_read_authorization_version: Mapped[int] = mapped_column(Integer, nullable=False)
    # Work-item identity + operation fingerprint the activation is bound to (secret-free).
    preflight_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("readonly_staging_preflight.id"), nullable=False, index=True
    )
    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    # Pinned resolver-adapter contract version + closed purpose (labels only, no backend detail).
    resolver_adapter_contract_version: Mapped[str] = mapped_column(String(120), nullable=False)
    purpose: Mapped[str] = mapped_column(String(60), nullable=False)
    authorization_expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Secret-free fingerprint over the complete evidence set; bound at approval time. Empty until
    # approved. NEVER an evidence value — only a sha256 over closed metadata.
    evidence_fingerprint: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    status: Mapped[ResolverActivationStatus] = mapped_column(
        EnumType(ResolverActivationStatus, length=40),
        default=ResolverActivationStatus.draft,
        nullable=False,
    )
    authorization_version: Mapped[int] = mapped_column(Integer, nullable=False)
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason_code: Mapped[str] = mapped_column(String(80), default="", nullable=False)

    evidence: Mapped[list[ResolverActivationEvidence]] = relationship(
        back_populates="authorization",
        cascade="all, delete-orphan",
        order_by="ResolverActivationEvidence.kind",
    )

    def __repr__(self) -> str:
        return (
            "ResolverActivationAuthorization("
            f"id={self.id!s}, "
            f"execution_target_id={self.execution_target_id!s}, "
            f"onboarding_id={self.onboarding_id!s}, "
            f"live_read_authorization_id={self.live_read_authorization_id!s}, "
            f"authorization_version={self.authorization_version!r}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            f"revision={self.revision!r}, "
            "evidence_fingerprint=<sha256>)"
        )


class ResolverActivationEvidence(Base, TimestampMixin):
    """One provider-neutral, secret-free activation-evidence item (SECP-B2-4.1 / B2-2 §8).

    Records proof METADATA only: a closed ``kind``, a closed ``status``, an opaque non-sensitive
    ``proof_id``, an issuer label, and a verification timestamp. It NEVER stores an endpoint,
    config, vault path, reference, worker credential, token, policy, or secret, and it is NOT a
    free-form operator text field (the service validates every value against a safe closed shape).
    """

    __tablename__ = "resolver_activation_evidence"
    __table_args__ = (
        UniqueConstraint("authorization_id", "kind", name="uq_resolver_activation_evidence_kind"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("resolver_activation_authorization.id"), nullable=False, index=True
    )
    kind: Mapped[ResolverActivationEvidenceKind] = mapped_column(
        EnumType(ResolverActivationEvidenceKind, length=60), nullable=False
    )
    status: Mapped[ResolverActivationEvidenceStatus] = mapped_column(
        EnumType(ResolverActivationEvidenceStatus, length=20),
        default=ResolverActivationEvidenceStatus.pending,
        nullable=False,
    )
    # Opaque, non-sensitive proof identifier (e.g. a review ticket id). Validated to a safe pattern.
    proof_id: Mapped[str] = mapped_column(String(120), nullable=False)
    issuer: Mapped[str] = mapped_column(String(120), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    authorization: Mapped[ResolverActivationAuthorization] = relationship(back_populates="evidence")

    def __repr__(self) -> str:
        return (
            "ResolverActivationEvidence("
            f"authorization_id={self.authorization_id!s}, "
            f"kind={getattr(self.kind, 'value', self.kind)!r}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            f"proof_id={self.proof_id!r})"
        )


class WorkerIdentityRegistration(Base, TimestampMixin):
    """Durable, secret-free trust anchor for an approved isolated-staging worker identity (B2-4.3).

    This app-owned control-plane record is the SEPARATE, explicit, time-bounded, audited, revocable
    registration that must exist (and be independently re-verified by a worker) before a future
    isolated staging worker can be trusted. It authenticates NO worker, performs NO mTLS, and stores
    ONLY safe metadata: an opaque identity label, an opaque deployment binding, and the sha256
    FINGERPRINT of a PUBLIC verification anchor. It NEVER stores a certificate, key, CSR, CA name,
    hostname, endpoint, port, token, secret reference, backend configuration, or free-form text.
    """

    __tablename__ = "worker_identity_registration"
    __table_args__ = (
        # Server-derived monotonic version per (org, identity label) — no caller-supplied version.
        UniqueConstraint(
            "organization_id",
            "identity_label",
            "identity_version",
            name="uq_worker_identity_org_label_version",
        ),
        # At most ONE non-terminal (draft/approved) registration per (org, identity label).
        Index(
            "uq_worker_identity_active",
            "organization_id",
            "identity_label",
            unique=True,
            sqlite_where=text("status in ('draft','approved')"),
            postgresql_where=text("status in ('draft','approved')"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    mechanism: Mapped[WorkerIdentityMechanism] = mapped_column(
        EnumType(WorkerIdentityMechanism, length=40), nullable=False
    )
    # Opaque, grammar-validated identity label + deployment binding (secret-free).
    identity_label: Mapped[str] = mapped_column(String(120), nullable=False)
    deployment_binding: Mapped[str] = mapped_column(String(120), nullable=False)
    # sha256:<hex> fingerprint of the PUBLIC verification anchor — never the anchor material itself.
    verification_anchor_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    identity_version: Mapped[int] = mapped_column(Integer, nullable=False)
    expiry: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Secret-free fingerprint over the complete evidence set; bound at approval time. Empty until
    # approved. NEVER an evidence value — only a sha256 over closed metadata.
    evidence_fingerprint: Mapped[str] = mapped_column(String(80), default="", nullable=False)
    status: Mapped[WorkerIdentityStatus] = mapped_column(
        EnumType(WorkerIdentityStatus, length=40),
        default=WorkerIdentityStatus.draft,
        nullable=False,
    )
    revision: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason_code: Mapped[str] = mapped_column(String(80), default="", nullable=False)

    evidence: Mapped[list[WorkerIdentityEvidence]] = relationship(
        back_populates="registration",
        cascade="all, delete-orphan",
        order_by="WorkerIdentityEvidence.kind",
    )

    def __repr__(self) -> str:
        return (
            "WorkerIdentityRegistration("
            f"id={self.id!s}, "
            f"organization_id={self.organization_id!s}, "
            f"identity_label={self.identity_label!r}, "
            f"identity_version={self.identity_version!r}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            f"revision={self.revision!r}, "
            "verification_anchor_fingerprint=<sha256>, "
            "evidence_fingerprint=<sha256>)"
        )


class WorkerIdentityEvidence(Base, TimestampMixin):
    """One secret-free worker-identity evidence item (SECP-B2-4.3).

    Records proof METADATA only: a closed ``kind``, a closed ``status``, an opaque non-sensitive
    ``proof_id``, an issuer label, and a verification timestamp. It NEVER stores a certificate, key,
    CSR, CA, endpoint, token, reference, or secret, and is NOT a free-form text field.
    """

    __tablename__ = "worker_identity_evidence"
    __table_args__ = (
        UniqueConstraint("registration_id", "kind", name="uq_worker_identity_evidence_kind"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    registration_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("worker_identity_registration.id"), nullable=False, index=True
    )
    kind: Mapped[WorkerIdentityEvidenceKind] = mapped_column(
        EnumType(WorkerIdentityEvidenceKind, length=60), nullable=False
    )
    status: Mapped[WorkerIdentityEvidenceStatus] = mapped_column(
        EnumType(WorkerIdentityEvidenceStatus, length=20),
        default=WorkerIdentityEvidenceStatus.pending,
        nullable=False,
    )
    proof_id: Mapped[str] = mapped_column(String(120), nullable=False)
    issuer: Mapped[str] = mapped_column(String(120), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    registration: Mapped[WorkerIdentityRegistration] = relationship(back_populates="evidence")

    def __repr__(self) -> str:
        return (
            "WorkerIdentityEvidence("
            f"registration_id={self.registration_id!s}, "
            f"kind={getattr(self.kind, 'value', self.kind)!r}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            f"proof_id={self.proof_id!r})"
        )


class LivePreflightEvidence(Base, TimestampMixin):
    """Durable, immutable, secret-free evidence of a completed live read-only staging preflight
    (SECP-B2-4.5). Worker-only: written ONLY by the sealed ``LivePreflightEvidenceWriter`` seam
    behind the governed collection handoff — never by the API/UI and never in shipped runtime.

    It binds the COMPLETE authoritative operation context (org, preflight, target, onboarding,
    live-read auth id+version, resolver-activation auth id+version, worker-identity registration
    id+version, lease identity, pinned contract/allowlist/schema versions, operation fingerprint)
    stores a strict closed ``payload`` (closed status, safe booleans, bounded counts, closed check/
    finding codes, approved labels) plus a deterministic ``evidence_hash``. It NEVER stores an
    endpoint, host, IP, port, node/storage/network name, raw provider response/error, certificate,
    credential, token, secret reference, or free text. It is immutable after insert (no update, no
    delete) and exact-once per completed preflight operation.
    """

    __tablename__ = "live_preflight_evidence"
    __table_args__ = (
        # Exact-once per completed preflight operation (idempotency boundary).
        UniqueConstraint(
            "preflight_id", "operation_fingerprint", name="uq_live_preflight_evidence_operation"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    preflight_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("readonly_staging_preflight.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    onboarding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=False, index=True
    )
    live_read_authorization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("live_read_authorization.id"), nullable=False, index=True
    )
    live_read_authorization_version: Mapped[int] = mapped_column(Integer, nullable=False)
    resolver_activation_authorization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("resolver_activation_authorization.id"), nullable=False, index=True
    )
    resolver_activation_authorization_version: Mapped[int] = mapped_column(Integer, nullable=False)
    worker_identity_registration_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("worker_identity_registration.id"), nullable=False, index=True
    )
    worker_identity_version: Mapped[int] = mapped_column(Integer, nullable=False)
    resolution_lease_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("resolution_lease.id"), nullable=False, index=True
    )
    operation_fingerprint: Mapped[str] = mapped_column(String(80), nullable=False)
    collector_contract_version: Mapped[str] = mapped_column(String(120), nullable=False)
    endpoint_allowlist_version: Mapped[str] = mapped_column(String(120), nullable=False)
    resolver_contract_version: Mapped[str] = mapped_column(String(120), nullable=False)
    evidence_schema_version: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[LivePreflightEvidenceStatus] = mapped_column(
        EnumType(LivePreflightEvidenceStatus, length=40), nullable=False
    )
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    # A strict, closed, secret-free canonical payload (validated by the live-evidence schema).
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    def __repr__(self) -> str:
        return (
            "LivePreflightEvidence("
            f"id={self.id!s}, "
            f"preflight_id={self.preflight_id!s}, "
            f"status={getattr(self.status, 'value', self.status)!r}, "
            "evidence_hash=<sha256>)"
        )


class ProviderInventorySnapshot(Base, TimestampMixin):
    """Immutable-after-completion provider inventory snapshot (ADR-008)."""

    __tablename__ = "provider_inventory_snapshot"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    plugin_name: Mapped[str] = mapped_column(String(100), nullable=False)
    plugin_version: Mapped[str] = mapped_column(String(40), default="")
    target_config_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    status: Mapped[SnapshotStatus] = mapped_column(
        EnumType(SnapshotStatus), default=SnapshotStatus.queued, nullable=False
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Once True the snapshot is immutable (enforced in secp_api.immutability).
    finalized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    resources: Mapped[list[ProviderInventoryResource]] = relationship(
        back_populates="snapshot", cascade="all, delete-orphan"
    )
    workflow_runs: Mapped[list[WorkflowRun]] = relationship(back_populates="snapshot")

    @property
    def workflow_run_id(self) -> uuid.UUID | None:
        return self.workflow_runs[0].id if self.workflow_runs else None


class ProviderInventoryResource(Base, TimestampMixin):
    """A normalized, provider-neutral inventory resource (no secrets, no Proxmox
    columns)."""

    __tablename__ = "provider_inventory_resource"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    snapshot_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("provider_inventory_snapshot.id"), nullable=False, index=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    resource_type: Mapped[str] = mapped_column(String(60), nullable=False)
    provider_external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    parent_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(40), default="unknown")
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)

    snapshot: Mapped[ProviderInventorySnapshot] = relationship(back_populates="resources")


class AddressSpacePolicy(Base, TimestampMixin):
    """An approved address space (CIDR block + per-team subnet prefix) for a
    target (ADR-009)."""

    __tablename__ = "address_space_policy"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    cidr_block: Mapped[str] = mapped_column(String(64), nullable=False)
    subnet_prefix: Mapped[int] = mapped_column(Integer, nullable=False)

    target: Mapped[ExecutionTarget] = relationship(back_populates="address_spaces")


class NetworkReservation(Base, TimestampMixin):
    """A reserved CIDR for a team within an exercise on a target (ADR-009).

    Unique on ``(execution_target_id, cidr)`` so a reserved block is never
    duplicated; releasing flips status and the block can be re-reserved by reusing
    the row.
    """

    __tablename__ = "network_reservation"
    __table_args__ = (UniqueConstraint("execution_target_id", "cidr"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    exercise_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("exercise.id"), nullable=True, index=True
    )
    team_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[ReservationStatus] = mapped_column(
        EnumType(ReservationStatus), default=ReservationStatus.reserved, nullable=False
    )


# --- Sealed OpenTofu runtime provenance (SECP-002B-1A) -----------------------


class ToolchainProfile(Base, TimestampMixin):
    """Immutable, secret-free, provider-neutral toolchain profile (ADR-013).

    Binds an ``ExecutionTarget`` to a worker-side IaC runtime. ``content`` holds the
    full validated provenance (pinned OpenTofu version + binary integrity + adapter/
    module-bundle hash + provider lockfile hash + renderer version + remote state-backend
    reference + offline provider-mirror identity + activation class). ``content``,
    ``content_hash``, ``runner_kind``, ``activation_class``, and ``execution_target_id``
    are immutable after creation (see :mod:`secp_api.immutability`). Contains NO secrets.
    """

    __tablename__ = "toolchain_profile"
    __table_args__ = (UniqueConstraint("execution_target_id", "version"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    runner_kind: Mapped[str] = mapped_column(String(60), nullable=False)
    activation_class: Mapped[str] = mapped_column(String(60), nullable=False)
    renderer_version: Mapped[str] = mapped_column(String(60), nullable=False)
    content: Mapped[dict] = mapped_column(JSON, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    status: Mapped[ToolchainProfileStatus] = mapped_column(
        EnumType(ToolchainProfileStatus), default=ToolchainProfileStatus.active, nullable=False
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)


# --- Provisioning safety harness (SECP-002B-0) -------------------------------


class ProvisioningManifest(Base, TimestampMixin):
    """Immutable, secret-free provisioning manifest (ADR-011).

    Generated only from an approved plan + pinned target/hash + finalized
    reservations + validated scope policy. ``content``/``content_hash`` and the
    binding columns are immutable after creation (see :mod:`secp_api.immutability`).
    Contains NO secrets, secret references, credentials, or endpoint auth material.
    """

    __tablename__ = "provisioning_manifest"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    deployment_plan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("deployment_plan.id"), nullable=False, index=True
    )
    execution_target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("execution_target.id"), nullable=False, index=True
    )
    target_config_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    # Scope-policy hash binding (SECP-002B-0): immutable once set.
    target_scope_policy_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # Toolchain-profile binding (SECP-002B-1A): copied from the plan, immutable once set.
    toolchain_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("toolchain_profile.id"), nullable=True
    )
    toolchain_profile_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    # Onboarding binding (SECP-002B-1B-0): copied from the plan, echoed into immutable
    # ``content`` (and therefore ``content_hash``), and re-verified at generation + gate.
    target_onboarding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("target_onboarding.id"), nullable=True
    )
    onboarding_boundary_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    approved_preflight_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_preflight_evidence_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    onboarding_verification_level: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # Effective execution boundary (declared boundary ∩ scope): copied from the plan, echoed
    # into immutable ``content``/``content_hash``, and re-verified at the worker gate.
    effective_boundary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    effective_boundary_hash: Mapped[str | None] = mapped_column(String(80), nullable=True)
    content: Mapped[dict] = mapped_column(JSON, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    operations: Mapped[list[ProvisioningOperation]] = relationship(
        back_populates="manifest", cascade="all, delete-orphan"
    )
    change_set_approvals: Mapped[list[ProvisioningChangeSetApproval]] = relationship(
        back_populates="manifest", cascade="all, delete-orphan"
    )


class ProvisioningOperation(Base, TimestampMixin):
    """Durable provisioning-operation record with an idempotency key (ADR-011/012).

    ``idempotency_key`` = sha256(manifest content hash + operation kind); a duplicate
    request maps to the same operation, so retries are safe.
    """

    __tablename__ = "provisioning_operation"
    __table_args__ = (UniqueConstraint("idempotency_key"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    manifest_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("provisioning_manifest.id"), nullable=False, index=True
    )
    kind: Mapped[ProvisioningOperationKind] = mapped_column(
        EnumType(ProvisioningOperationKind), nullable=False
    )
    status: Mapped[ProvisioningStatus] = mapped_column(
        EnumType(ProvisioningStatus, length=40),
        default=ProvisioningStatus.manifest_generated,
        nullable=False,
    )
    idempotency_key: Mapped[str] = mapped_column(String(120), nullable=False)
    # Deterministic runner operation id (fake runner); no secrets.
    runner: Mapped[str] = mapped_column(String(60), default="")
    operation_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    manifest: Mapped[ProvisioningManifest] = relationship(back_populates="operations")


class ProvisioningChangeSetApproval(Base, TimestampMixin):
    """Durable human approval of an exact dry-run change set (SECP-002B-1A, ADR-013).

    Apply/destroy on the real OpenTofu path are permitted only when a *freshly
    regenerated* dry run reproduces the exact ``change_set_hash`` this row approved AND
    every binding (manifest content hash, toolchain profile hash, scope-policy hash,
    reservations hash) still matches. Secret-free: stores only canonical, redacted
    hashes and a change-set summary — never a raw OpenTofu binary plan, endpoint, or
    credential.
    """

    __tablename__ = "provisioning_change_set_approval"
    __table_args__ = (UniqueConstraint("manifest_id", "authorizes_kind", "change_set_hash"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    manifest_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("provisioning_manifest.id"), nullable=False, index=True
    )
    toolchain_profile_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("toolchain_profile.id"), nullable=False, index=True
    )
    # The operation kind this approval authorizes: apply or destroy.
    authorizes_kind: Mapped[ProvisioningOperationKind] = mapped_column(
        EnumType(ProvisioningOperationKind), nullable=False
    )
    change_set_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    rendered_workspace_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    manifest_content_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    toolchain_profile_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    target_scope_policy_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    reservations_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    renderer_version: Mapped[str] = mapped_column(String(60), nullable=False)
    module_bundle_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[ChangeSetApprovalStatus] = mapped_column(
        EnumType(ChangeSetApprovalStatus),
        default=ChangeSetApprovalStatus.pending,
        nullable=False,
    )
    decided_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_reason: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    manifest: Mapped[ProvisioningManifest] = relationship(back_populates="change_set_approvals")


# SECP-B4 deployment engine models (kept in a dedicated module for a focused diff).
from secp_api.deployment_models import (  # noqa: E402,F401
    StagingDeployment,
    StagingDeploymentApproval,
    StagingDeploymentOperation,
    StagingDeploymentPlan,
    StagingDeploymentResource,
    StagingDeploymentVerification,
)
