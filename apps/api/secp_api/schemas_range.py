"""Request/response schemas for the range and competition API.

These are the shapes published in ``program-state/shared/range-api-contract.md`` and frozen for
``owner-range-ui``. Two omissions are deliberate and load-bearing:

* **No schema anywhere carries a flag value.** ``ChallengeOut`` has no such field, so there is no
  serialisation path — accidental or otherwise — by which a solution reaches a client.
* **No schema accepts an ``organization_id``.** Tenancy comes from the authenticated principal
  only; a caller cannot name the organization it wants to act in.

Every response is an ordinary JSON body built from plain data. Nothing here is streamed: the
request session closes before the response is written to the socket (see :mod:`secp_api.deps`), so
a ``StreamingResponse`` over ORM instances would send a 200 and then truncate.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

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


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- requests -----------------------------------------------------------------


class RangeCreate(BaseModel):
    template_slug: str = Field(pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    name: str | None = Field(default=None, max_length=200)


class CompetitionCreate(BaseModel):
    name: str | None = Field(default=None, max_length=200)


class TeamCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class TeamMemberCreate(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)
    #: Optional link to a provisioned SECP user. Competitors at a training event usually are not
    #: users, so this is never required; when given it must be in the caller's own organization.
    user_id: uuid.UUID | None = None


class SubmissionCreate(BaseModel):
    team_id: uuid.UUID
    challenge_id: uuid.UUID
    value: str = Field(min_length=1, max_length=512)


# --- catalog ------------------------------------------------------------------


class RangeComponentOut(BaseModel):
    key: str
    name: str
    role: str
    image: str
    container_port: int | None = None
    protocol: str = "http"
    path: str = "/"


class RangeTemplateOut(BaseModel):
    slug: str
    name: str
    summary: str
    description: str
    provider: str
    difficulty: str
    estimated_deploy_seconds: int
    warning: str
    components: list[RangeComponentOut]
    challenge_count: int
    total_points: int


# --- lifecycle ----------------------------------------------------------------


class RangeOperationStepOut(BaseModel):
    key: str
    label: str
    status: str
    detail: str | None = None
    at: str | None = None


class RangeOperationSummaryOut(BaseModel):
    id: uuid.UUID
    kind: RangeOperationKind
    status: RangeOperationStatus
    phase: str | None = None
    completed_steps: int
    total_steps: int
    percent: int


class RangeOperationOut(BaseModel):
    id: uuid.UUID
    range_id: uuid.UUID
    kind: RangeOperationKind
    status: RangeOperationStatus
    phase: str | None = None
    completed_steps: int
    total_steps: int
    percent: int
    failure_code: str | None = None
    failure_message: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    steps: list[RangeOperationStepOut]


class AccessTargetOut(BaseModel):
    component_key: str
    name: str
    url: str
    host: str
    port: int
    protocol: str
    #: True only where an actual response was observed from the component.
    reachable: bool
    observed_at: datetime | None = None


class RangeOut(BaseModel):
    id: uuid.UUID
    name: str
    template_slug: str
    template_name: str
    provider: str
    state: RangeState
    state_reason: str | None = None
    created_at: datetime
    updated_at: datetime
    deployed_at: datetime | None = None
    destroyed_at: datetime | None = None
    competition_id: uuid.UUID | None = None
    current_operation: RangeOperationSummaryOut | None = None
    residue_verdict: ResidueVerdict | None = None
    access: list[AccessTargetOut] = Field(default_factory=list)


class RangeResourceOut(BaseModel):
    id: uuid.UUID
    kind: RangeResourceKind
    provider: str
    component_key: str | None = None
    name: str
    external_id: str | None = None
    image: str | None = None
    image_digest: str | None = None
    state: RangeResourceState
    host_port: int | None = None
    created_at: datetime
    removed_at: datetime | None = None
    detail: dict


class RangeEventOut(BaseModel):
    id: uuid.UUID
    range_id: uuid.UUID
    sequence: int
    kind: str
    level: RangeEventLevel
    message: str
    data: dict
    occurred_at: datetime


class TeardownResourceOut(BaseModel):
    kind: str
    name: str
    external_id: str | None = None
    verdict: str
    detail: str | None = None


class TeardownEvidenceOut(BaseModel):
    id: uuid.UUID
    range_id: uuid.UUID
    operation_id: uuid.UUID | None = None
    verdict: ResidueVerdict
    probe_reachable: bool
    expected_count: int
    removed_confirmed: int
    still_present: int
    unproven_count: int
    reason: str | None = None
    observed_at: datetime
    resources: list[TeardownResourceOut]


# --- competition --------------------------------------------------------------


class CompetitionOut(BaseModel):
    id: uuid.UUID
    range_id: uuid.UUID
    name: str
    state: CompetitionState
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    team_count: int
    challenge_count: int
    total_points: int
    created_at: datetime


class TeamOut(BaseModel):
    id: uuid.UUID
    competition_id: uuid.UUID
    name: str
    slug: str
    join_code: str
    score: int
    solved_count: int
    created_at: datetime


class TeamMemberOut(BaseModel):
    """A roster entry. Carries no permission and never affects scoring or authorization."""

    id: uuid.UUID
    competition_id: uuid.UUID
    team_id: uuid.UUID
    display_name: str
    user_id: uuid.UUID | None = None
    created_at: datetime


class ChallengeOut(BaseModel):
    """NOTE: there is deliberately no flag field. Adding one would leak solutions."""

    id: uuid.UUID
    competition_id: uuid.UUID
    key: str
    title: str
    description: str
    category: str
    points: int
    component_key: str | None = None
    hint: str | None = None
    max_attempts: int
    solve_count: int
    solved_by_team_ids: list[uuid.UUID]


class SubmissionOut(BaseModel):
    id: uuid.UUID
    competition_id: uuid.UUID
    team_id: uuid.UUID
    team_name: str
    challenge_id: uuid.UUID
    challenge_title: str
    verdict: SubmissionVerdict
    #: What the server RECORDED. Never an instruction to the client to add points locally.
    points_awarded: int
    attempts_remaining: int
    submitted_at: datetime


class ScoreboardEntryOut(BaseModel):
    rank: int
    team_id: uuid.UUID
    team_name: str
    score: int
    solved_count: int
    last_solve_at: datetime | None = None
    solved_challenge_ids: list[uuid.UUID]


class ScoreboardOut(BaseModel):
    competition_id: uuid.UUID
    state: CompetitionState
    generated_at: datetime
    total_points: int
    entries: list[ScoreboardEntryOut]
