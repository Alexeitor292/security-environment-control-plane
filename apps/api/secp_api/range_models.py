"""ORM models for the range lifecycle, provider resources, and the competition core.

These are real system-of-record rows, not a projection: a range's state, the provider resources it
owns, every operation run against it, its lifecycle timeline, and every scoring fact all live here.
Nothing in this module is written speculatively — in particular no row reaches a "success" state
except from an observation made by the provider layer and passed back through the service.

Two shapes are worth reading closely:

* :class:`RangeProviderResource` carries the provider's own identity for the resource
  (``external_id``) alongside the ownership label the provider stamped on it. Teardown matches on
  BOTH, so a resource this control plane did not create can never be selected for removal.
* :class:`RangeTeardownEvidence` records the residue verdict AND whether the probe that produced
  it was itself working (``probe_reachable``). Those are separate columns on purpose: a verdict is
  only meaningful in the company of the probe's own health.
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
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from secp_api.models import Base
from secp_api.range_enums import (
    CompetitionState,
    RangeEventLevel,
    RangeOperationKind,
    RangeOperationStatus,
    RangeResourceKind,
    RangeResourceState,
    RangeState,
    ResidueVerdict,
    SubmissionVerdict,
)
from secp_api.types import EnumType


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


# --- Range templates, instances, resources -----------------------------------


class RangeTemplate(Base):
    """A deployable range definition.

    The catalog ships as code (:mod:`secp_api.range_catalog`) and is synchronised into this table so
    that a deployed range keeps a durable foreign key to the exact definition it was built from,
    even if the shipped catalog later changes. ``spec`` is the frozen component/challenge document.
    """

    __tablename__ = "range_template"
    __table_args__ = (UniqueConstraint("slug"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    slug: Mapped[str] = mapped_column(String(63), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(String(500), default="")
    description: Mapped[str] = mapped_column(Text, default="")
    provider: Mapped[str] = mapped_column(String(60), nullable=False)
    difficulty: Mapped[str] = mapped_column(String(40), default="beginner")
    estimated_deploy_seconds: Mapped[int] = mapped_column(Integer, default=180, nullable=False)
    warning: Mapped[str] = mapped_column(Text, default="")
    #: The frozen definition: ``{"components": [...], "challenges": [...]}``.
    spec: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class RangeInstance(Base):
    """One deployed (or deployable) range owned by one organization."""

    __tablename__ = "range_instance"
    __table_args__ = (Index("ix_range_instance_org_state", "organization_id", "state"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    template_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("range_template.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    provider: Mapped[str] = mapped_column(String(60), nullable=False)
    state: Mapped[RangeState] = mapped_column(
        EnumType(RangeState), default=RangeState.draft, nullable=False
    )
    #: Free-text explanation for an off-path state. Always set for ``failed`` and
    #: ``recovery_required`` so the UI never has to invent one.
    state_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Short slug embedded in every provider resource name, e.g. ``0f2c9b``. Unique per range.
    resource_prefix: Mapped[str] = mapped_column(String(40), nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Set only by a teardown. ``None`` means "never torn down", which is not the same as ``clean``.
    residue_verdict: Mapped[ResidueVerdict | None] = mapped_column(
        EnumType(ResidueVerdict), nullable=True
    )
    #: Monotonic counter backing ``RangeLifecycleEvent.sequence`` for incremental UI fetch.
    event_sequence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    template: Mapped[RangeTemplate] = relationship()
    resources: Mapped[list[RangeProviderResource]] = relationship(
        back_populates="range_instance", cascade="all, delete-orphan"
    )
    operations: Mapped[list[RangeDeploymentOperation]] = relationship(
        back_populates="range_instance", cascade="all, delete-orphan"
    )


class RangeProviderResource(Base):
    """One concrete resource the provider created for a range.

    ``external_id`` is the provider's own identifier (a Docker container/network id), and
    ``owner_label`` records the ownership stamp the provider applied at creation. Teardown selects
    a resource only when the recorded ``external_id`` still carries the recorded ``owner_label`` —
    matching on either alone would let a name collision or a recycled id put an unrelated resource
    in scope.
    """

    __tablename__ = "range_provider_resource"
    __table_args__ = (Index("ix_range_provider_resource_range_kind", "range_instance_id", "kind"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    range_instance_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("range_instance.id"), nullable=False, index=True
    )
    kind: Mapped[RangeResourceKind] = mapped_column(EnumType(RangeResourceKind), nullable=False)
    provider: Mapped[str] = mapped_column(String(60), nullable=False)
    #: Which template component this resource realises. ``None`` for the shared network.
    component_key: Mapped[str | None] = mapped_column(String(80), nullable=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    image: Mapped[str | None] = mapped_column(String(300), nullable=True)
    #: The resolved image digest observed at deploy time — real evidence of what actually ran,
    #: as distinct from the tag the catalog asked for.
    image_digest: Mapped[str | None] = mapped_column(String(120), nullable=True)
    owner_label: Mapped[str] = mapped_column(String(200), nullable=False)
    state: Mapped[RangeResourceState] = mapped_column(
        EnumType(RangeResourceState), default=RangeResourceState.pending, nullable=False
    )
    host_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    range_instance: Mapped[RangeInstance] = relationship(back_populates="resources")


class RangeDeploymentOperation(Base):
    """A deploy / reset / destroy run, with its per-step progress."""

    __tablename__ = "range_deployment_operation"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    range_instance_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("range_instance.id"), nullable=False, index=True
    )
    kind: Mapped[RangeOperationKind] = mapped_column(EnumType(RangeOperationKind), nullable=False)
    status: Mapped[RangeOperationStatus] = mapped_column(
        EnumType(RangeOperationStatus), default=RangeOperationStatus.pending, nullable=False
    )
    phase: Mapped[str | None] = mapped_column(String(60), nullable=True)
    completed_steps: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_steps: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: ``[{"key","label","status","detail","at"}]`` in declaration order.
    steps: Mapped[list] = mapped_column(JSON, default=list)
    failure_code: Mapped[str | None] = mapped_column(String(80), nullable=True)
    failure_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    range_instance: Mapped[RangeInstance] = relationship(back_populates="operations")


class RangeLifecycleEvent(Base):
    """Append-only timeline. ``sequence`` is per-range and dense, so the UI can fetch increments."""

    __tablename__ = "range_lifecycle_event"
    __table_args__ = (UniqueConstraint("range_instance_id", "sequence"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    range_instance_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("range_instance.id"), nullable=False, index=True
    )
    operation_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(String(80), nullable=False)
    level: Mapped[RangeEventLevel] = mapped_column(
        EnumType(RangeEventLevel), default=RangeEventLevel.info, nullable=False
    )
    message: Mapped[str] = mapped_column(Text, nullable=False)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class RangeTeardownEvidence(Base):
    """What a teardown actually proved.

    ``probe_reachable`` is stored beside ``verdict`` because the verdict is only interpretable with
    it. When the probe could not run, ``verdict`` is ``unproven`` and ``reason`` says why absence
    was not established — never ``clean``.
    """

    __tablename__ = "range_teardown_evidence"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    range_instance_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("range_instance.id"), nullable=False, index=True
    )
    operation_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    verdict: Mapped[ResidueVerdict] = mapped_column(EnumType(ResidueVerdict), nullable=False)
    #: Whether the existence probe itself was demonstrably working at check time.
    probe_reachable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    expected_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    removed_confirmed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    still_present: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    unproven_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: ``[{"kind","name","external_id","verdict"}]``.
    resources: Mapped[list] = mapped_column(JSON, default=list)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


# --- Competition core ---------------------------------------------------------


class Competition(Base):
    __tablename__ = "competition"
    __table_args__ = (UniqueConstraint("range_instance_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    range_instance_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("range_instance.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    state: Mapped[CompetitionState] = mapped_column(
        EnumType(CompetitionState), default=CompetitionState.draft, nullable=False
    )
    #: Random per-competition salt for ``CompetitionSubmission.value_fingerprint``. Without it the
    #: fingerprint of a CORRECT submission would be a cheap offline oracle for the flag it matched,
    #: which would undo the hashing done on ``CompetitionFlag``.
    fingerprint_salt: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    teams: Mapped[list[CompetitionTeam]] = relationship(
        back_populates="competition", cascade="all, delete-orphan"
    )
    challenges: Mapped[list[CompetitionChallenge]] = relationship(
        back_populates="competition", cascade="all, delete-orphan"
    )


class CompetitionTeam(Base):
    __tablename__ = "competition_team"
    __table_args__ = (UniqueConstraint("competition_id", "slug"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    competition_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("competition.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), nullable=False)
    join_code: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    competition: Mapped[Competition] = relationship(back_populates="teams")
    members: Mapped[list[CompetitionTeamMember]] = relationship(
        back_populates="team", cascade="all, delete-orphan"
    )


class CompetitionTeamMember(Base):
    """One competitor on one team.

    A competitor is identified by a DISPLAY NAME, not by an ``app_user`` foreign key, and that is
    deliberate. Competitors at a training event are usually not provisioned SECP users — they are
    students, or visitors, or a rotating cast on a workshop day — and requiring a real user row to
    put someone on a scoreboard would either block the common case or push the platform into
    creating throwaway accounts. ``user_id`` is therefore optional, for the case where a competitor
    IS a known user and the link is worth keeping.

    Membership carries no authorization whatsoever. It never grants a permission, never affects
    which organization anything belongs to, and is not consulted when judging a submission — a
    submission is attributed to a TEAM, and the authenticated principal is what authorizes it. This
    table is a roster, and treating it as anything more would make display data load-bearing for
    access control.
    """

    __tablename__ = "competition_team_member"
    #: One display name per team. Two "Alex"es on the same team cannot be told apart on a
    #: scoreboard, so the constraint forces the disambiguation to happen at entry time rather than
    #: leaving an unreadable roster. The same name on a DIFFERENT team is fine.
    __table_args__ = (UniqueConstraint("team_id", "display_name"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    competition_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("competition.id"), nullable=False, index=True
    )
    team_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("competition_team.id"), nullable=False, index=True
    )
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    #: Set only when the competitor is a provisioned SECP user. Never required.
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("app_user.id"), nullable=True
    )
    added_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    team: Mapped[CompetitionTeam] = relationship(back_populates="members")


class CompetitionChallenge(Base):
    __tablename__ = "competition_challenge"
    __table_args__ = (UniqueConstraint("competition_id", "key"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    competition_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("competition.id"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(80), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(60), default="web")
    points: Mapped[int] = mapped_column(Integer, nullable=False)
    component_key: Mapped[str | None] = mapped_column(String(80), nullable=True)
    hint: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Bounded attempts per team. Keeps a flag from being brute-forced from the browser.
    max_attempts: Mapped[int] = mapped_column(Integer, default=25, nullable=False)
    display_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    competition: Mapped[Competition] = relationship(back_populates="challenges")
    flags: Mapped[list[CompetitionFlag]] = relationship(
        back_populates="challenge", cascade="all, delete-orphan"
    )


class CompetitionFlag(Base):
    """A bounded flag. The plaintext value is NEVER stored and NEVER leaves the server.

    Only ``value_hash`` (salted PBKDF2 over the normalised value) is persisted, so a database read
    does not hand out solutions and no response can accidentally serialise the answer.
    """

    __tablename__ = "competition_flag"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("competition_challenge.id"), nullable=False, index=True
    )
    label: Mapped[str] = mapped_column(String(120), default="")
    salt: Mapped[str] = mapped_column(String(64), nullable=False)
    value_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    case_sensitive: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    challenge: Mapped[CompetitionChallenge] = relationship(back_populates="flags")


class CompetitionSubmission(Base):
    """Every attempt, correct or not. ``value_fingerprint`` is a salted hash used only to detect a
    team re-submitting the identical value; the submitted text itself is never persisted."""

    __tablename__ = "competition_submission"
    __table_args__ = (Index("ix_competition_submission_team_challenge", "team_id", "challenge_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    competition_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("competition.id"), nullable=False, index=True
    )
    team_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("competition_team.id"), nullable=False, index=True
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("competition_challenge.id"), nullable=False, index=True
    )
    verdict: Mapped[SubmissionVerdict] = mapped_column(EnumType(SubmissionVerdict), nullable=False)
    points_awarded: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    value_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    submitted_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    submitted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class CompetitionScore(Base):
    """The authoritative award ledger: at most ONE row per (team, challenge).

    The unique constraint is what makes duplicate credit structurally impossible rather than merely
    checked — a concurrent double-submit loses at the database, not at an ``if`` statement.
    """

    __tablename__ = "competition_score"
    __table_args__ = (UniqueConstraint("team_id", "challenge_id"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_uuid)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("organization.id"), nullable=False, index=True
    )
    competition_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("competition.id"), nullable=False, index=True
    )
    team_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("competition_team.id"), nullable=False, index=True
    )
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("competition_challenge.id"), nullable=False, index=True
    )
    points: Mapped[int] = mapped_column(Integer, nullable=False)
    submission_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    awarded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
