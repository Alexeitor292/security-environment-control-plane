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
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from secp_api.enums import LifecycleState, PlanStatus, WorkflowKind, WorkflowStatus
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
    networks: Mapped[list[SimulatedNetwork]] = relationship(
        back_populates="instance", cascade="all, delete-orphan"
    )
    nodes: Mapped[list[SimulatedNode]] = relationship(
        back_populates="instance", cascade="all, delete-orphan"
    )
    edges: Mapped[list[SimulatedTopologyEdge]] = relationship(
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
    exercise_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("exercise.id"), nullable=False, index=True
    )
    kind: Mapped[WorkflowKind] = mapped_column(EnumType(WorkflowKind), nullable=False)
    status: Mapped[WorkflowStatus] = mapped_column(
        EnumType(WorkflowStatus), default=WorkflowStatus.running, nullable=False
    )
    dispatch_mode: Mapped[str] = mapped_column(String(20), default="inline")
    correlation_id: Mapped[str] = mapped_column(String(80), nullable=False)
    target_instance_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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


# --- Simulated inventory / topology projection -------------------------------


class SimulatedNetwork(Base, TimestampMixin):
    __tablename__ = "simulated_network"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    instance_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("environment_instance.id"), nullable=False, index=True
    )
    ref: Mapped[str] = mapped_column(String(120), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    team_ref: Mapped[str | None] = mapped_column(String(120), nullable=True)
    isolated: Mapped[bool] = mapped_column(Boolean, default=True)
    provider: Mapped[str] = mapped_column(String(60), default="simulator")
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)

    instance: Mapped[EnvironmentInstance] = relationship(back_populates="networks")


class SimulatedNode(Base, TimestampMixin):
    __tablename__ = "simulated_node"

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
    provider: Mapped[str] = mapped_column(String(60), default="simulator")
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict)

    instance: Mapped[EnvironmentInstance] = relationship(back_populates="nodes")


class SimulatedTopologyEdge(Base, TimestampMixin):
    __tablename__ = "simulated_topology_edge"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    instance_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("environment_instance.id"), nullable=False, index=True
    )
    source_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(120), nullable=False)
    kind: Mapped[str] = mapped_column(String(40), nullable=False)

    instance: Mapped[EnvironmentInstance] = relationship(back_populates="edges")
