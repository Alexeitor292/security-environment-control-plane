"""The native competition core.

Teams, challenges, bounded flags, submissions, scores, scoreboard, reset. It sits behind a clean
service boundary so that an external scoring engine (CTFd or similar) could replace it later
without touching the range lifecycle, the provider, or the HTTP contract — the routes call only
this module.

THE THREE PROPERTIES THAT MUST HOLD
-----------------------------------
1. **Flags never leave the server.** Only a salted PBKDF2 digest is stored, and no schema in
   :mod:`secp_api.schemas_range` has a field that could serialise one. Comparison is constant-time.
2. **No duplicate credit.** :class:`~secp_api.range_models.CompetitionScore` has a unique
   constraint on ``(team_id, challenge_id)``. The award is attempted inside a savepoint and an
   IntegrityError is treated as "someone else already scored it" — so two concurrent correct
   submissions produce one award, decided by the database rather than by a check-then-act race.
3. **The browser is never authoritative.** Every point in every response is read back from the
   score table after the write. The client supplies a candidate string and nothing else.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.enums import Permission
from secp_api.errors import DomainError, NotFoundError, ValidationFailedError
from secp_api.models import User
from secp_api.range_catalog import get_template
from secp_api.range_enums import CompetitionState, RangeState, SubmissionVerdict
from secp_api.range_models import (
    Competition,
    CompetitionChallenge,
    CompetitionFlag,
    CompetitionScore,
    CompetitionSubmission,
    CompetitionTeam,
    CompetitionTeamMember,
    RangeInstance,
    RangeTemplate,
)
from secp_api.services.ranges import RangeInvalidTransitionError, get_range, record_event

logger = logging.getLogger("secp.api.range.competition")

#: PBKDF2 work factor for flags and submission fingerprints. High enough that a database leak does
#: not hand over the flag set for free; low enough that a busy scoreboard is not gated on it.
_PBKDF2_ITERATIONS = 100_000
_MAX_FLAG_LENGTH = 512


class CompetitionNotOpenError(DomainError):
    http_status = 409
    code = "competition_not_open"


class SubmissionRejectedError(ValidationFailedError):
    http_status = 422
    code = "submission_rejected"


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (slug or "team")[:63]


def _normalise(value: str, *, case_sensitive: bool) -> str:
    normalised = value.strip()
    return normalised if case_sensitive else normalised.lower()


def _digest(value: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", value.encode("utf-8"), bytes.fromhex(salt), _PBKDF2_ITERATIONS
    ).hex()


# --- competition lifecycle ----------------------------------------------------


def create_competition(
    session: Session,
    principal: Principal,
    range_id: uuid.UUID,
    *,
    name: str | None = None,
) -> Competition:
    """Create the competition for a range and seed its challenges and flags from the template."""
    principal.require(Permission.exercise_operate)
    instance = get_range(session, principal, range_id)
    existing = session.execute(
        select(Competition).where(Competition.range_instance_id == instance.id)
    ).scalar_one_or_none()
    if existing is not None:
        raise RangeInvalidTransitionError("this range already has a competition")

    template_row = session.get(RangeTemplate, instance.template_id)
    catalog_template = get_template(template_row.slug) if template_row is not None else None
    if catalog_template is None:
        raise NotFoundError("the range's template is not in the shipped catalog")

    competition = Competition(
        organization_id=instance.organization_id,
        range_instance_id=instance.id,
        name=(name or f"{instance.name} competition").strip()[:200],
        state=CompetitionState.draft,
        fingerprint_salt=secrets.token_hex(16),
        created_by=principal.user_id,
    )
    session.add(competition)
    session.flush()

    for order, challenge in enumerate(catalog_template.challenges):
        row = CompetitionChallenge(
            organization_id=instance.organization_id,
            competition_id=competition.id,
            key=challenge.key,
            title=challenge.title,
            description=challenge.description,
            category=challenge.category,
            points=challenge.points,
            component_key=challenge.component_key,
            hint=challenge.hint,
            max_attempts=challenge.max_attempts,
            display_order=order,
        )
        session.add(row)
        session.flush()
        for flag in challenge.flags:
            salt = secrets.token_hex(16)
            session.add(
                CompetitionFlag(
                    organization_id=instance.organization_id,
                    challenge_id=row.id,
                    label=flag.label,
                    salt=salt,
                    value_hash=_digest(
                        _normalise(flag.value, case_sensitive=flag.case_sensitive), salt
                    ),
                    case_sensitive=flag.case_sensitive,
                )
            )
    session.flush()
    record_event(
        session,
        instance,
        kind="competition_created",
        message=(
            f"Competition '{competition.name}' created with "
            f"{len(catalog_template.challenges)} challenges"
        ),
    )
    return competition


def get_competition_for_range(
    session: Session, principal: Principal, range_id: uuid.UUID
) -> Competition:
    instance = get_range(session, principal, range_id)
    competition = session.execute(
        select(Competition).where(Competition.range_instance_id == instance.id)
    ).scalar_one_or_none()
    if competition is None:
        raise NotFoundError("this range has no competition")
    return competition


def get_competition(
    session: Session, principal: Principal, competition_id: uuid.UUID
) -> Competition:
    principal.require(Permission.exercise_operate)
    competition = session.get(Competition, competition_id)
    if competition is None:
        raise NotFoundError("competition not found")
    principal.require_org(competition.organization_id)
    return competition


def start_competition(
    session: Session, principal: Principal, competition_id: uuid.UUID
) -> Competition:
    competition = get_competition(session, principal, competition_id)
    principal.require(Permission.exercise_operate)
    if competition.state is CompetitionState.running:
        return competition
    instance = session.get(RangeInstance, competition.range_instance_id)
    if instance is None or instance.state not in (RangeState.ready, RangeState.active):
        raise RangeInvalidTransitionError(
            "the range must be ready before its competition can start"
        )
    team_count = session.execute(
        select(func.count(CompetitionTeam.id)).where(
            CompetitionTeam.competition_id == competition.id
        )
    ).scalar_one()
    if not team_count:
        raise RangeInvalidTransitionError("a competition needs at least one team to start")

    competition.state = CompetitionState.running
    competition.started_at = competition.started_at or _utcnow()
    competition.stopped_at = None
    instance.state = RangeState.active
    record_event(
        session,
        instance,
        kind="competition_started",
        message=f"Competition '{competition.name}' started with {team_count} team(s)",
    )
    return competition


def stop_competition(
    session: Session, principal: Principal, competition_id: uuid.UUID
) -> Competition:
    competition = get_competition(session, principal, competition_id)
    principal.require(Permission.exercise_operate)
    if competition.state is not CompetitionState.running:
        return competition
    competition.state = CompetitionState.stopped
    competition.stopped_at = _utcnow()
    instance = session.get(RangeInstance, competition.range_instance_id)
    if instance is not None and instance.state is RangeState.active:
        instance.state = RangeState.ready
        record_event(
            session,
            instance,
            kind="competition_stopped",
            message=f"Competition '{competition.name}' stopped",
        )
    return competition


# --- teams --------------------------------------------------------------------


def create_team(
    session: Session, principal: Principal, competition_id: uuid.UUID, *, name: str
) -> CompetitionTeam:
    competition = get_competition(session, principal, competition_id)
    principal.require(Permission.exercise_operate)
    cleaned = name.strip()
    if not cleaned:
        raise ValidationFailedError("a team needs a name")
    slug = _slugify(cleaned)
    clash = session.execute(
        select(CompetitionTeam).where(
            CompetitionTeam.competition_id == competition.id,
            CompetitionTeam.slug == slug,
        )
    ).scalar_one_or_none()
    if clash is not None:
        raise ValidationFailedError(f"a team named '{cleaned}' already exists")
    team = CompetitionTeam(
        organization_id=competition.organization_id,
        competition_id=competition.id,
        name=cleaned[:120],
        slug=slug,
        join_code=secrets.token_hex(3).upper(),
    )
    session.add(team)
    session.flush()
    return team


def list_teams(
    session: Session, principal: Principal, competition_id: uuid.UUID
) -> list[CompetitionTeam]:
    competition = get_competition(session, principal, competition_id)
    return list(
        session.execute(
            select(CompetitionTeam)
            .where(CompetitionTeam.competition_id == competition.id)
            .order_by(CompetitionTeam.created_at)
        )
        .scalars()
        .all()
    )


def _team_in(session: Session, competition: Competition, team_id: uuid.UUID) -> CompetitionTeam:
    team = session.get(CompetitionTeam, team_id)
    if team is None or team.competition_id != competition.id:
        raise NotFoundError("team not found")
    return team


def add_team_member(
    session: Session,
    principal: Principal,
    competition_id: uuid.UUID,
    team_id: uuid.UUID,
    *,
    display_name: str,
    user_id: uuid.UUID | None = None,
) -> CompetitionTeamMember:
    """Put one competitor on one team.

    Roster data only — see :class:`~secp_api.range_models.CompetitionTeamMember`. Adding someone
    grants them nothing; submissions are attributed to the team and authorized by the authenticated
    principal.

    Members may be added while the competition is RUNNING, unlike teams. A team appearing mid-event
    changes what the scoreboard means; a latecomer joining an existing team does not.
    """
    competition = get_competition(session, principal, competition_id)
    principal.require(Permission.exercise_operate)
    team = _team_in(session, competition, team_id)

    cleaned = display_name.strip()
    if not cleaned:
        raise ValidationFailedError("a team member needs a display name")
    clash = session.execute(
        select(CompetitionTeamMember).where(
            CompetitionTeamMember.team_id == team.id,
            CompetitionTeamMember.display_name == cleaned[:120],
        )
    ).scalar_one_or_none()
    if clash is not None:
        raise ValidationFailedError(f"'{cleaned}' is already on this team")

    if user_id is not None:
        # A named user must belong to the SAME organization. Accepting an arbitrary user id here
        # would let a roster entry quietly reference someone outside the tenant.
        user = session.get(User, user_id)
        if user is None or user.organization_id != competition.organization_id:
            raise ValidationFailedError("that user is not in this organization")

    member = CompetitionTeamMember(
        organization_id=competition.organization_id,
        competition_id=competition.id,
        team_id=team.id,
        display_name=cleaned[:120],
        user_id=user_id,
        added_by=principal.user_id,
    )
    session.add(member)
    session.flush()
    return member


def list_team_members(
    session: Session,
    principal: Principal,
    competition_id: uuid.UUID,
    team_id: uuid.UUID,
) -> list[CompetitionTeamMember]:
    competition = get_competition(session, principal, competition_id)
    team = _team_in(session, competition, team_id)
    return list(
        session.execute(
            select(CompetitionTeamMember)
            .where(CompetitionTeamMember.team_id == team.id)
            .order_by(CompetitionTeamMember.created_at)
        )
        .scalars()
        .all()
    )


def remove_team_member(
    session: Session,
    principal: Principal,
    competition_id: uuid.UUID,
    team_id: uuid.UUID,
    member_id: uuid.UUID,
) -> None:
    competition = get_competition(session, principal, competition_id)
    principal.require(Permission.exercise_operate)
    team = _team_in(session, competition, team_id)
    member = session.get(CompetitionTeamMember, member_id)
    if member is None or member.team_id != team.id:
        raise NotFoundError("team member not found")
    # Removing a competitor does NOT retract their team's solves. The team earned them, the
    # scoreboard is a record of what happened, and silently restating history because a roster
    # changed would make the scoreboard unreliable.
    session.delete(member)
    session.flush()


def delete_team(
    session: Session, principal: Principal, competition_id: uuid.UUID, team_id: uuid.UUID
) -> None:
    competition = get_competition(session, principal, competition_id)
    principal.require(Permission.exercise_operate)
    if competition.state is not CompetitionState.draft:
        raise RangeInvalidTransitionError(
            "teams cannot be removed once the competition has started"
        )
    team = session.get(CompetitionTeam, team_id)
    if team is None or team.competition_id != competition.id:
        raise NotFoundError("team not found")
    session.execute(delete(CompetitionSubmission).where(CompetitionSubmission.team_id == team.id))
    session.execute(delete(CompetitionScore).where(CompetitionScore.team_id == team.id))
    session.delete(team)
    session.flush()


# --- challenges ---------------------------------------------------------------


def list_challenges(
    session: Session, principal: Principal, competition_id: uuid.UUID
) -> list[CompetitionChallenge]:
    competition = get_competition(session, principal, competition_id)
    return list(
        session.execute(
            select(CompetitionChallenge)
            .where(CompetitionChallenge.competition_id == competition.id)
            .order_by(CompetitionChallenge.display_order)
        )
        .scalars()
        .all()
    )


def solvers_by_challenge(
    session: Session, competition_id: uuid.UUID
) -> dict[uuid.UUID, list[uuid.UUID]]:
    rows = session.execute(
        select(CompetitionScore.challenge_id, CompetitionScore.team_id)
        .where(CompetitionScore.competition_id == competition_id)
        .order_by(CompetitionScore.awarded_at)
    ).all()
    solvers: dict[uuid.UUID, list[uuid.UUID]] = {}
    for challenge_id, team_id in rows:
        solvers.setdefault(challenge_id, []).append(team_id)
    return solvers


# --- submissions --------------------------------------------------------------


@dataclass(frozen=True)
class SubmissionOutcome:
    submission: CompetitionSubmission
    team: CompetitionTeam
    challenge: CompetitionChallenge
    attempts_remaining: int


def submit_flag(
    session: Session,
    principal: Principal,
    competition_id: uuid.UUID,
    *,
    team_id: uuid.UUID,
    challenge_id: uuid.UUID,
    value: str,
) -> SubmissionOutcome:
    """Judge one submission and persist the outcome.

    Every path records a submission row — a wrong answer is data, not an error — and only the
    ``accepted`` path writes a score.
    """
    competition = get_competition(session, principal, competition_id)
    principal.require(Permission.exercise_operate)

    if len(value) > _MAX_FLAG_LENGTH:
        raise SubmissionRejectedError("the submitted value is too long")

    team = session.get(CompetitionTeam, team_id)
    if team is None or team.competition_id != competition.id:
        raise SubmissionRejectedError("that team is not in this competition")
    challenge = session.get(CompetitionChallenge, challenge_id)
    if challenge is None or challenge.competition_id != competition.id:
        raise SubmissionRejectedError("that challenge is not in this competition")

    fingerprint = _digest(value.strip().lower(), competition.fingerprint_salt)

    def record(verdict: SubmissionVerdict, points: int = 0) -> CompetitionSubmission:
        submission = CompetitionSubmission(
            organization_id=competition.organization_id,
            competition_id=competition.id,
            team_id=team.id,
            challenge_id=challenge.id,
            verdict=verdict,
            points_awarded=points,
            value_fingerprint=fingerprint,
            submitted_by=principal.user_id,
        )
        session.add(submission)
        session.flush()
        return submission

    attempts_used = session.execute(
        select(func.count(CompetitionSubmission.id)).where(
            CompetitionSubmission.team_id == team.id,
            CompetitionSubmission.challenge_id == challenge.id,
        )
    ).scalar_one()

    if competition.state is not CompetitionState.running:
        return SubmissionOutcome(
            record(SubmissionVerdict.not_open),
            team,
            challenge,
            max(challenge.max_attempts - attempts_used, 0),
        )

    already = session.execute(
        select(CompetitionScore).where(
            CompetitionScore.team_id == team.id,
            CompetitionScore.challenge_id == challenge.id,
        )
    ).scalar_one_or_none()
    if already is not None:
        # Correct or not, this team already holds the solve. NO further credit, ever.
        return SubmissionOutcome(
            record(SubmissionVerdict.already_solved),
            team,
            challenge,
            max(challenge.max_attempts - attempts_used, 0),
        )

    duplicate = (
        session.execute(
            select(CompetitionSubmission).where(
                CompetitionSubmission.team_id == team.id,
                CompetitionSubmission.challenge_id == challenge.id,
                CompetitionSubmission.value_fingerprint == fingerprint,
            )
        )
        .scalars()
        .first()
    )
    if duplicate is not None:
        # A repeat of a value this team already tried does not consume a fresh attempt's worth of
        # credit and cannot become correct; record it plainly.
        return SubmissionOutcome(
            record(SubmissionVerdict.duplicate),
            team,
            challenge,
            max(challenge.max_attempts - attempts_used, 0),
        )

    if attempts_used >= challenge.max_attempts:
        return SubmissionOutcome(record(SubmissionVerdict.attempts_exhausted), team, challenge, 0)

    flags = list(
        session.execute(select(CompetitionFlag).where(CompetitionFlag.challenge_id == challenge.id))
        .scalars()
        .all()
    )
    correct = False
    for flag in flags:
        candidate = _normalise(value, case_sensitive=flag.case_sensitive)
        if hmac.compare_digest(_digest(candidate, flag.salt), flag.value_hash):
            correct = True
            break

    if not correct:
        return SubmissionOutcome(
            record(SubmissionVerdict.incorrect),
            team,
            challenge,
            max(challenge.max_attempts - attempts_used - 1, 0),
        )

    submission = record(SubmissionVerdict.accepted, challenge.points)
    try:
        with session.begin_nested():
            session.add(
                CompetitionScore(
                    organization_id=competition.organization_id,
                    competition_id=competition.id,
                    team_id=team.id,
                    challenge_id=challenge.id,
                    points=challenge.points,
                    submission_id=submission.id,
                )
            )
    except IntegrityError:
        # The unique constraint fired: a concurrent submission won the race. The database — not an
        # `if` — is what makes double credit impossible, so downgrade this one honestly.
        session.rollback()
        submission = record(SubmissionVerdict.already_solved)
        return SubmissionOutcome(
            submission, team, challenge, max(challenge.max_attempts - attempts_used - 1, 0)
        )

    session.flush()
    instance = session.get(RangeInstance, competition.range_instance_id)
    if instance is not None:
        record_event(
            session,
            instance,
            kind="challenge_solved",
            message=f"{team.name} solved '{challenge.title}' for {challenge.points} points",
            data={"team_id": str(team.id), "challenge_id": str(challenge.id)},
        )
    return SubmissionOutcome(
        submission, team, challenge, max(challenge.max_attempts - attempts_used - 1, 0)
    )


def list_submissions(
    session: Session,
    principal: Principal,
    competition_id: uuid.UUID,
    *,
    team_id: uuid.UUID | None = None,
    challenge_id: uuid.UUID | None = None,
    limit: int = 100,
) -> list[CompetitionSubmission]:
    competition = get_competition(session, principal, competition_id)
    stmt = select(CompetitionSubmission).where(
        CompetitionSubmission.competition_id == competition.id
    )
    if team_id is not None:
        stmt = stmt.where(CompetitionSubmission.team_id == team_id)
    if challenge_id is not None:
        stmt = stmt.where(CompetitionSubmission.challenge_id == challenge_id)
    stmt = stmt.order_by(CompetitionSubmission.submitted_at.desc()).limit(max(1, min(limit, 500)))
    return list(session.execute(stmt).scalars().all())


# --- scoreboard ---------------------------------------------------------------


@dataclass(frozen=True)
class _StandingRow:
    """One team's aggregate, before ranking.

    A typed row rather than a dict: the values are genuinely heterogeneous, so a dict makes every
    field ``object`` to a type checker and the ranking arithmetic below stops being verified at all.
    """

    team: CompetitionTeam
    score: int
    solved: int
    last: datetime | None
    challenges: list[uuid.UUID]


@dataclass(frozen=True)
class ScoreboardEntry:
    rank: int
    team_id: uuid.UUID
    team_name: str
    score: int
    solved_count: int
    last_solve_at: datetime | None
    solved_challenge_ids: list[uuid.UUID]


def scoreboard(
    session: Session, principal: Principal, competition_id: uuid.UUID
) -> tuple[Competition, list[ScoreboardEntry], int]:
    """Compute the scoreboard from the award ledger. Nothing here trusts a client-supplied total."""
    competition = get_competition(session, principal, competition_id)
    teams = list_teams(session, principal, competition_id)
    awards = (
        session.execute(
            select(CompetitionScore).where(CompetitionScore.competition_id == competition.id)
        )
        .scalars()
        .all()
    )
    total_points = session.execute(
        select(func.coalesce(func.sum(CompetitionChallenge.points), 0)).where(
            CompetitionChallenge.competition_id == competition.id
        )
    ).scalar_one()

    by_team: dict[uuid.UUID, list[CompetitionScore]] = {team.id: [] for team in teams}
    for award in awards:
        by_team.setdefault(award.team_id, []).append(award)

    rows = [
        _StandingRow(
            team=team,
            score=sum(award.points for award in by_team.get(team.id, [])),
            solved=len(by_team.get(team.id, [])),
            last=max((award.awarded_at for award in by_team.get(team.id, [])), default=None),
            challenges=[award.challenge_id for award in by_team.get(team.id, [])],
        )
        for team in teams
    ]

    # Highest score first; a tie is broken by whoever reached it first. Tied teams SHARE a rank.
    rows.sort(
        key=lambda row: (
            -row.score,
            row.last or datetime.max.replace(tzinfo=UTC),
            row.team.created_at,
        )
    )
    entries: list[ScoreboardEntry] = []
    previous_key: tuple[int, datetime | None] | None = None
    rank = 0
    for index, row in enumerate(rows, start=1):
        key = (row.score, row.last)
        if key != previous_key:
            rank = index
            previous_key = key
        entries.append(
            ScoreboardEntry(
                rank=rank,
                team_id=row.team.id,
                team_name=row.team.name,
                score=row.score,
                solved_count=row.solved,
                last_solve_at=row.last,
                solved_challenge_ids=row.challenges,
            )
        )
    return competition, entries, int(total_points)


def reset_scores(session: Session, principal: Principal, competition_id: uuid.UUID) -> Competition:
    """Clear submissions and awards; keep teams and challenges."""
    competition = get_competition(session, principal, competition_id)
    principal.require(Permission.exercise_reset)
    session.execute(
        delete(CompetitionScore).where(CompetitionScore.competition_id == competition.id)
    )
    session.execute(
        delete(CompetitionSubmission).where(CompetitionSubmission.competition_id == competition.id)
    )
    session.flush()
    instance = session.get(RangeInstance, competition.range_instance_id)
    if instance is not None:
        record_event(
            session,
            instance,
            kind="scores_reset",
            message=f"Scores reset for competition '{competition.name}'",
        )
    return competition


def reset_scores_for_range(session: Session, instance: RangeInstance) -> None:
    """Score half of a range reset. Called by the lifecycle, so it takes no principal."""
    competition = session.execute(
        select(Competition).where(Competition.range_instance_id == instance.id)
    ).scalar_one_or_none()
    if competition is None:
        return
    session.execute(
        delete(CompetitionScore).where(CompetitionScore.competition_id == competition.id)
    )
    session.execute(
        delete(CompetitionSubmission).where(CompetitionSubmission.competition_id == competition.id)
    )
    session.flush()
