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
    IsolationModel,
    LifecycleState,
    OnboardingMode,
    OnboardingStatus,
    PlanStatus,
    ProvisioningOperationKind,
    ProvisioningStatus,
    ReservationStatus,
    SnapshotStatus,
    TargetStatus,
    ToolchainProfileStatus,
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
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    onboarding: Mapped[TargetOnboarding] = relationship(back_populates="preflights")


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
