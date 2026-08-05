"""ORM rows -> response schemas.

Kept out of the routers so both range and competition routes project a ``CompetitionOut`` the same
way, and out of the services so the services stay free of presentation concerns.

Everything here materialises plain data before returning. That is not stylistic: the request
session closes before the response body is written (see :mod:`secp_api.deps`), so a projection that
handed back lazy ORM attributes for something to touch later would be reading a detached instance.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secp_api.range_catalog import CatalogTemplate
from secp_api.range_enums import RangeResourceKind, RangeResourceState, RangeState
from secp_api.range_models import (
    Competition,
    CompetitionChallenge,
    CompetitionScore,
    CompetitionSubmission,
    CompetitionTeam,
    RangeDeploymentOperation,
    RangeInstance,
    RangeLifecycleEvent,
    RangeProviderResource,
    RangeTeardownEvidence,
    RangeTemplate,
)
from secp_api.range_providers.local_docker import BIND_HOST
from secp_api.schemas_range import (
    AccessTargetOut,
    ChallengeOut,
    CompetitionOut,
    RangeComponentOut,
    RangeEventOut,
    RangeOperationOut,
    RangeOperationStepOut,
    RangeOperationSummaryOut,
    RangeOut,
    RangeResourceOut,
    RangeTemplateOut,
    ScoreboardEntryOut,
    ScoreboardOut,
    SubmissionOut,
    TeamOut,
    TeardownEvidenceOut,
    TeardownResourceOut,
)

#: The states in which access targets are meaningful. In any other state the range either has no
#: containers or has containers whose reachability was never established.
_ACCESSIBLE_STATES = frozenset({RangeState.ready, RangeState.active})


def _percent(completed: int, total: int) -> int:
    if total <= 0:
        return 0
    return max(0, min(100, round(completed * 100 / total)))


def template_out(row: RangeTemplate) -> RangeTemplateOut:
    spec = row.spec or {}
    challenges = spec.get("challenges", [])
    return RangeTemplateOut(
        slug=row.slug,
        name=row.name,
        summary=row.summary,
        description=row.description,
        provider=row.provider,
        difficulty=row.difficulty,
        estimated_deploy_seconds=row.estimated_deploy_seconds,
        warning=row.warning,
        components=[
            RangeComponentOut(
                key=component["key"],
                name=component["name"],
                role=component.get("role", "target"),
                image=component["image"],
                container_port=component.get("container_port"),
                protocol=component.get("protocol", "http"),
                path=component.get("path", "/"),
            )
            for component in spec.get("components", [])
        ],
        challenge_count=len(challenges),
        total_points=sum(int(challenge.get("points", 0)) for challenge in challenges),
    )


def catalog_template_out(template: CatalogTemplate) -> RangeTemplateOut:
    return RangeTemplateOut(
        slug=template.slug,
        name=template.name,
        summary=template.summary,
        description=template.description,
        provider=template.provider,
        difficulty=template.difficulty,
        estimated_deploy_seconds=template.estimated_deploy_seconds,
        warning=template.warning,
        components=[
            RangeComponentOut(
                key=component.key,
                name=component.name,
                role=component.role.value,
                image=component.image,
                container_port=component.container_port,
                protocol=component.protocol,
                path=component.path,
            )
            for component in template.components
        ],
        challenge_count=len(template.challenges),
        total_points=template.total_points,
    )


def operation_summary(operation: RangeDeploymentOperation) -> RangeOperationSummaryOut:
    return RangeOperationSummaryOut(
        id=operation.id,
        kind=operation.kind,
        status=operation.status,
        phase=operation.phase,
        completed_steps=operation.completed_steps,
        total_steps=operation.total_steps,
        percent=_percent(operation.completed_steps, operation.total_steps),
    )


def operation_out(operation: RangeDeploymentOperation) -> RangeOperationOut:
    return RangeOperationOut(
        id=operation.id,
        range_id=operation.range_instance_id,
        kind=operation.kind,
        status=operation.status,
        phase=operation.phase,
        completed_steps=operation.completed_steps,
        total_steps=operation.total_steps,
        percent=_percent(operation.completed_steps, operation.total_steps),
        failure_code=operation.failure_code,
        failure_message=operation.failure_message,
        started_at=operation.started_at,
        finished_at=operation.finished_at,
        steps=[
            RangeOperationStepOut(
                key=step.get("key", ""),
                label=step.get("label", ""),
                status=step.get("status", "pending"),
                detail=step.get("detail"),
                at=step.get("at"),
            )
            for step in (operation.steps or [])
        ],
    )


def access_targets(
    session: Session, instance: RangeInstance, template: RangeTemplate | None
) -> list[AccessTargetOut]:
    """Access URLs for a range, built ONLY from resources that were observed responding.

    A container in ``created`` (started but never answered) contributes nothing: offering an
    operator a link to something we never saw respond would be exactly the invented success this
    codebase refuses elsewhere.
    """
    if instance.state not in _ACCESSIBLE_STATES:
        return []
    names = {
        component["key"]: component
        for component in ((template.spec if template else None) or {}).get("components", [])
    }
    rows = (
        session.execute(
            select(RangeProviderResource).where(
                RangeProviderResource.range_instance_id == instance.id,
                RangeProviderResource.kind == RangeResourceKind.container,
                RangeProviderResource.removed_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    targets: list[AccessTargetOut] = []
    for row in rows:
        if row.host_port is None or row.state is not RangeResourceState.verified:
            continue
        component = names.get(row.component_key or "", {})
        protocol = component.get("protocol", "http")
        path = component.get("path", "/")
        targets.append(
            AccessTargetOut(
                component_key=row.component_key or row.name,
                name=component.get("name", row.name),
                url=f"{protocol}://{BIND_HOST}:{row.host_port}{path}",
                host=BIND_HOST,
                port=row.host_port,
                protocol=protocol,
                reachable=True,
                observed_at=row.created_at,
            )
        )
    return targets


def range_out(session: Session, instance: RangeInstance) -> RangeOut:
    template = session.get(RangeTemplate, instance.template_id)
    operation = session.execute(
        select(RangeDeploymentOperation)
        .where(RangeDeploymentOperation.range_instance_id == instance.id)
        .order_by(RangeDeploymentOperation.started_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    competition = session.execute(
        select(Competition.id).where(Competition.range_instance_id == instance.id)
    ).scalar_one_or_none()
    return RangeOut(
        id=instance.id,
        name=instance.name,
        template_slug=template.slug if template else "",
        template_name=template.name if template else "",
        provider=instance.provider,
        state=instance.state,
        state_reason=instance.state_reason,
        created_at=instance.created_at,
        updated_at=instance.updated_at,
        deployed_at=instance.deployed_at,
        destroyed_at=instance.destroyed_at,
        competition_id=competition,
        current_operation=operation_summary(operation) if operation else None,
        residue_verdict=instance.residue_verdict,
        access=access_targets(session, instance, template),
    )


def resource_out(row: RangeProviderResource) -> RangeResourceOut:
    return RangeResourceOut(
        id=row.id,
        kind=row.kind,
        provider=row.provider,
        component_key=row.component_key,
        name=row.name,
        external_id=row.external_id,
        image=row.image,
        image_digest=row.image_digest,
        state=row.state,
        host_port=row.host_port,
        created_at=row.created_at,
        removed_at=row.removed_at,
        detail=dict(row.detail or {}),
    )


def event_out(row: RangeLifecycleEvent) -> RangeEventOut:
    return RangeEventOut(
        id=row.id,
        range_id=row.range_instance_id,
        sequence=row.sequence,
        kind=row.kind,
        level=row.level,
        message=row.message,
        data=dict(row.data or {}),
        occurred_at=row.occurred_at,
    )


def teardown_evidence_out(row: RangeTeardownEvidence) -> TeardownEvidenceOut:
    return TeardownEvidenceOut(
        id=row.id,
        range_id=row.range_instance_id,
        operation_id=row.operation_id,
        verdict=row.verdict,
        probe_reachable=row.probe_reachable,
        expected_count=row.expected_count,
        removed_confirmed=row.removed_confirmed,
        still_present=row.still_present,
        unproven_count=row.unproven_count,
        reason=row.reason,
        observed_at=row.observed_at,
        resources=[
            TeardownResourceOut(
                kind=item.get("kind", ""),
                name=item.get("name", ""),
                external_id=item.get("external_id"),
                verdict=item.get("verdict", "unproven"),
                detail=item.get("detail"),
            )
            for item in (row.resources or [])
        ],
    )


def competition_out(session: Session, competition: Competition) -> CompetitionOut:
    team_count = session.execute(
        select(func.count(CompetitionTeam.id)).where(
            CompetitionTeam.competition_id == competition.id
        )
    ).scalar_one()
    challenge_count, total_points = session.execute(
        select(
            func.count(CompetitionChallenge.id),
            func.coalesce(func.sum(CompetitionChallenge.points), 0),
        ).where(CompetitionChallenge.competition_id == competition.id)
    ).one()
    return CompetitionOut(
        id=competition.id,
        range_id=competition.range_instance_id,
        name=competition.name,
        state=competition.state,
        started_at=competition.started_at,
        stopped_at=competition.stopped_at,
        team_count=int(team_count),
        challenge_count=int(challenge_count),
        total_points=int(total_points),
        created_at=competition.created_at,
    )


def team_out(session: Session, team: CompetitionTeam) -> TeamOut:
    score, solved = session.execute(
        select(
            func.coalesce(func.sum(CompetitionScore.points), 0),
            func.count(CompetitionScore.id),
        ).where(CompetitionScore.team_id == team.id)
    ).one()
    return TeamOut(
        id=team.id,
        competition_id=team.competition_id,
        name=team.name,
        slug=team.slug,
        join_code=team.join_code,
        score=int(score),
        solved_count=int(solved),
        created_at=team.created_at,
    )


def challenge_out(
    row: CompetitionChallenge, solvers: dict[uuid.UUID, list[uuid.UUID]]
) -> ChallengeOut:
    solved_by = solvers.get(row.id, [])
    return ChallengeOut(
        id=row.id,
        competition_id=row.competition_id,
        key=row.key,
        title=row.title,
        description=row.description,
        category=row.category,
        points=row.points,
        component_key=row.component_key,
        hint=row.hint,
        max_attempts=row.max_attempts,
        solve_count=len(solved_by),
        solved_by_team_ids=solved_by,
    )


def submission_out(
    row: CompetitionSubmission,
    *,
    team_name: str,
    challenge_title: str,
    attempts_remaining: int,
) -> SubmissionOut:
    return SubmissionOut(
        id=row.id,
        competition_id=row.competition_id,
        team_id=row.team_id,
        team_name=team_name,
        challenge_id=row.challenge_id,
        challenge_title=challenge_title,
        verdict=row.verdict,
        points_awarded=row.points_awarded,
        attempts_remaining=attempts_remaining,
        submitted_at=row.submitted_at,
    )


def scoreboard_out(competition: Competition, entries, total_points: int) -> ScoreboardOut:
    return ScoreboardOut(
        competition_id=competition.id,
        state=competition.state,
        generated_at=datetime.now(UTC),
        total_points=total_points,
        entries=[
            ScoreboardEntryOut(
                rank=entry.rank,
                team_id=entry.team_id,
                team_name=entry.team_name,
                score=entry.score,
                solved_count=entry.solved_count,
                last_solve_at=entry.last_solve_at,
                solved_challenge_ids=entry.solved_challenge_ids,
            )
            for entry in entries
        ],
    )
