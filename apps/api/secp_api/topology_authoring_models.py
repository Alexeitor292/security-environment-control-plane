"""Durable topology draft authoring models (SECP-B9).

A dedicated module (mirroring deployment_models / discovery_models) for a
focused diff. Three aggregates:

* :class:`TopologyAuthoringDocument` — the authoring aggregate. Holds server-
  owned identity, org scope, optional source binding, lifecycle state, and
  pointers to the current / validated / submitted / approved revisions.
* :class:`TopologyRevision` — an IMMUTABLE revision. Content + content hash are
  frozen at creation; only ``status`` advances. A new edit is a new revision.
* :class:`TopologyValidationResult` — an IMMUTABLE validation result, pinned to
  an exact revision id + content hash. Never mutates the revision.

Control-plane only: no worker, no infrastructure contact, no secret material.
Immutability is enforced at the ORM layer in ``immutability.py`` and (for
Postgres) by DB triggers in the migration.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import Mapped, mapped_column, relationship

from secp_api.enums import (
    TopologyAuthoringStatus,
    TopologyRevisionStatus,
    TopologyValidationStatus,
)
from secp_api.models import Base, UpdatedTimestampMixin


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _now() -> datetime:
    return datetime.now(UTC)


class TopologyAuthoringDocument(Base, UpdatedTimestampMixin):
    """The authoring aggregate. Server-owned identity, org-scoped.

    The aggregate's mutable fields are its lifecycle ``status`` and the revision
    pointers; the source binding and organization are fixed at creation.
    """

    __tablename__ = "topology_authoring_document"
    __table_args__ = (UniqueConstraint("organization_id", "id", name="uq_topology_doc_org_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    # Optional provenance: the immutable environment version this draft started
    # from (never mutated; a draft can diverge freely). Nullable for the
    # explicitly-empty draft case.
    source_environment_version_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("environment_version.id"), nullable=True, index=True
    )
    exercise_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True, index=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[TopologyAuthoringStatus] = mapped_column(
        String(32), nullable=False, default=TopologyAuthoringStatus.draft
    )
    # Revision pointers (server-owned; advanced only by the service).
    current_revision_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    validated_revision_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    submitted_revision_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    approved_revision_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    revision_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    revisions: Mapped[list[TopologyRevision]] = relationship(
        back_populates="document", order_by="TopologyRevision.revision_number"
    )


class TopologyRevision(Base, UpdatedTimestampMixin):
    """An immutable topology revision. Content + content hash never change.

    Protected columns (``document``, ``organization_id``, ``revision_number``,
    ``parent_revision_id``, ``document_content``, ``content_hash``,
    ``schema_version``, ``source_environment_version_id``, ``created_by``,
    ``change_note``) must never change after creation (see immutability.py).
    ``status`` is the sole mutable field.
    """

    __tablename__ = "topology_revision"
    __table_args__ = (
        UniqueConstraint("document_id", "revision_number", name="uq_topology_revision_number"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("topology_authoring_document.id"), nullable=False, index=True
    )
    revision_number: Mapped[int] = mapped_column(Integer, nullable=False)
    parent_revision_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    # The canonicalized topology document (secret-free, schema-validated).
    # MutableDict so an in-place mutation dirties the row and the before_flush
    # immutability guard catches it (defense in depth with the PG trigger).
    document_content: Mapped[dict] = mapped_column(MutableDict.as_mutable(JSON), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    source_environment_version_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    change_note: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status: Mapped[TopologyRevisionStatus] = mapped_column(
        String(32), nullable=False, default=TopologyRevisionStatus.draft
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    # Decision fields (set-once when a submitted revision is decided).
    decided_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    document: Mapped[TopologyAuthoringDocument] = relationship(back_populates="revisions")


class TopologyValidationResult(Base, UpdatedTimestampMixin):
    """An immutable validation result pinned to an exact revision + hash.

    Recording a result never mutates the revision. Every field is frozen at
    creation. Findings are a bounded list of closed-code dicts (never a backend
    message).
    """

    __tablename__ = "topology_validation_result"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("topology_authoring_document.id"), nullable=False, index=True
    )
    revision_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("topology_revision.id"), nullable=False, index=True
    )
    # The exact content hash this result validated — the pinning anchor.
    content_hash: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    status: Mapped[TopologyValidationStatus] = mapped_column(String(32), nullable=False)
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    warning_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    findings: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    result_hash: Mapped[str] = mapped_column(String(80), nullable=False)
    validated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    validated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_now
    )
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
