"""Competition routes: teams, challenges, submissions, scoreboard.

A submission always returns ``200`` with a verdict. A wrong flag is a normal outcome of playing,
not an HTTP error — only a malformed body or a team/challenge that does not belong to this
competition produces a 4xx.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secp_api.auth import Principal
from secp_api.deps import DB_SESSION, current_principal
from secp_api.range_models import CompetitionChallenge, CompetitionSubmission, CompetitionTeam
from secp_api.range_projection import (
    challenge_out,
    competition_out,
    scoreboard_out,
    submission_out,
    team_member_out,
    team_out,
)
from secp_api.schemas_range import (
    ChallengeOut,
    CompetitionCreate,
    CompetitionOut,
    ScoreboardOut,
    SubmissionCreate,
    SubmissionOut,
    TeamCreate,
    TeamMemberCreate,
    TeamMemberOut,
    TeamOut,
)
from secp_api.services import competitions

router = APIRouter(prefix="/api/v1", tags=["competitions"])


@router.post("/ranges/{range_id}/competition", response_model=CompetitionOut, status_code=201)
def create_competition(
    range_id: uuid.UUID,
    body: CompetitionCreate,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> CompetitionOut:
    competition = competitions.create_competition(session, principal, range_id, name=body.name)
    return competition_out(session, competition)


@router.get("/ranges/{range_id}/competition", response_model=CompetitionOut)
def get_competition_for_range(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> CompetitionOut:
    competition = competitions.get_competition_for_range(session, principal, range_id)
    return competition_out(session, competition)


# --- range-scoped aliases -----------------------------------------------------
#
# A range has exactly ONE competition (unique constraint on
# ``competition.range_instance_id``), so every competition-scoped read has an unambiguous
# range-scoped spelling. These three exist because the shipped UI addresses them that way: an
# operator holds a range id, not a competition id, and making the client fetch the competition
# first only to fetch its teams is a round trip that buys nothing.
#
# They are ALIASES, not a second implementation. Each resolves the range's competition and calls
# the same service function as its ``/competitions/{id}/...`` twin, so there is no second code path
# to keep in step and no way for the two spellings to disagree. The competition-scoped routes are
# unchanged and are not deprecated — a client that already holds a competition id should keep
# using them.


@router.get("/ranges/{range_id}/teams", response_model=list[TeamOut])
def list_range_teams(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[TeamOut]:
    competition = competitions.get_competition_for_range(session, principal, range_id)
    return [
        team_out(session, team)
        for team in competitions.list_teams(session, principal, competition.id)
    ]


@router.post("/ranges/{range_id}/teams", response_model=TeamOut, status_code=201)
def create_range_team(
    range_id: uuid.UUID,
    body: TeamCreate,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> TeamOut:
    competition = competitions.get_competition_for_range(session, principal, range_id)
    team = competitions.create_team(session, principal, competition.id, name=body.name)
    return team_out(session, team)


@router.get("/ranges/{range_id}/teams/{team_id}/members", response_model=list[TeamMemberOut])
def list_range_team_members(
    range_id: uuid.UUID,
    team_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[TeamMemberOut]:
    competition = competitions.get_competition_for_range(session, principal, range_id)
    return [
        team_member_out(member)
        for member in competitions.list_team_members(
            session, principal, competition.id, team_id
        )
    ]


@router.post(
    "/ranges/{range_id}/teams/{team_id}/members",
    response_model=TeamMemberOut,
    status_code=201,
)
def add_range_team_member(
    range_id: uuid.UUID,
    team_id: uuid.UUID,
    body: TeamMemberCreate,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> TeamMemberOut:
    competition = competitions.get_competition_for_range(session, principal, range_id)
    member = competitions.add_team_member(
        session,
        principal,
        competition.id,
        team_id,
        display_name=body.display_name,
        user_id=body.user_id,
    )
    return team_member_out(member)


@router.delete(
    "/ranges/{range_id}/teams/{team_id}/members/{member_id}",
    status_code=204,
)
def remove_range_team_member(
    range_id: uuid.UUID,
    team_id: uuid.UUID,
    member_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> None:
    competition = competitions.get_competition_for_range(session, principal, range_id)
    competitions.remove_team_member(session, principal, competition.id, team_id, member_id)


@router.get("/ranges/{range_id}/challenges", response_model=list[ChallengeOut])
def list_range_challenges(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[ChallengeOut]:
    competition = competitions.get_competition_for_range(session, principal, range_id)
    rows = competitions.list_challenges(session, principal, competition.id)
    solvers = competitions.solvers_by_challenge(session, competition.id)
    return [challenge_out(row, solvers) for row in rows]


@router.get("/ranges/{range_id}/scoreboard", response_model=ScoreboardOut)
def get_range_scoreboard(
    range_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ScoreboardOut:
    competition = competitions.get_competition_for_range(session, principal, range_id)
    resolved, entries, total_points = competitions.scoreboard(
        session, principal, competition.id
    )
    return scoreboard_out(resolved, entries, total_points)


# --- competition-scoped routes ------------------------------------------------


@router.get("/competitions/{competition_id}", response_model=CompetitionOut)
def get_competition(
    competition_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> CompetitionOut:
    competition = competitions.get_competition(session, principal, competition_id)
    return competition_out(session, competition)


@router.post("/competitions/{competition_id}/start", response_model=CompetitionOut)
def start_competition(
    competition_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> CompetitionOut:
    competition = competitions.start_competition(session, principal, competition_id)
    return competition_out(session, competition)


@router.post("/competitions/{competition_id}/stop", response_model=CompetitionOut)
def stop_competition(
    competition_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> CompetitionOut:
    competition = competitions.stop_competition(session, principal, competition_id)
    return competition_out(session, competition)


@router.post("/competitions/{competition_id}/reset-scores", response_model=CompetitionOut)
def reset_scores(
    competition_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> CompetitionOut:
    competition = competitions.reset_scores(session, principal, competition_id)
    return competition_out(session, competition)


@router.post("/competitions/{competition_id}/teams", response_model=TeamOut, status_code=201)
def create_team(
    competition_id: uuid.UUID,
    body: TeamCreate,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> TeamOut:
    team = competitions.create_team(session, principal, competition_id, name=body.name)
    return team_out(session, team)


@router.get("/competitions/{competition_id}/teams", response_model=list[TeamOut])
def list_teams(
    competition_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[TeamOut]:
    return [
        team_out(session, team)
        for team in competitions.list_teams(session, principal, competition_id)
    ]


@router.get(
    "/competitions/{competition_id}/teams/{team_id}/members",
    response_model=list[TeamMemberOut],
)
def list_team_members(
    competition_id: uuid.UUID,
    team_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[TeamMemberOut]:
    return [
        team_member_out(member)
        for member in competitions.list_team_members(
            session, principal, competition_id, team_id
        )
    ]


@router.post(
    "/competitions/{competition_id}/teams/{team_id}/members",
    response_model=TeamMemberOut,
    status_code=201,
)
def add_team_member(
    competition_id: uuid.UUID,
    team_id: uuid.UUID,
    body: TeamMemberCreate,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> TeamMemberOut:
    member = competitions.add_team_member(
        session,
        principal,
        competition_id,
        team_id,
        display_name=body.display_name,
        user_id=body.user_id,
    )
    return team_member_out(member)


@router.delete(
    "/competitions/{competition_id}/teams/{team_id}/members/{member_id}",
    status_code=204,
)
def remove_team_member(
    competition_id: uuid.UUID,
    team_id: uuid.UUID,
    member_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> None:
    competitions.remove_team_member(session, principal, competition_id, team_id, member_id)


@router.delete("/competitions/{competition_id}/teams/{team_id}", status_code=204)
def delete_team(
    competition_id: uuid.UUID,
    team_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> None:
    competitions.delete_team(session, principal, competition_id, team_id)


@router.get("/competitions/{competition_id}/challenges", response_model=list[ChallengeOut])
def list_challenges(
    competition_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[ChallengeOut]:
    rows = competitions.list_challenges(session, principal, competition_id)
    solvers = competitions.solvers_by_challenge(session, competition_id)
    return [challenge_out(row, solvers) for row in rows]


@router.post("/competitions/{competition_id}/submissions", response_model=SubmissionOut)
def submit_flag(
    competition_id: uuid.UUID,
    body: SubmissionCreate,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> SubmissionOut:
    outcome = competitions.submit_flag(
        session,
        principal,
        competition_id,
        team_id=body.team_id,
        challenge_id=body.challenge_id,
        value=body.value,
    )
    return submission_out(
        outcome.submission,
        team_name=outcome.team.name,
        challenge_title=outcome.challenge.title,
        attempts_remaining=outcome.attempts_remaining,
    )


@router.get("/competitions/{competition_id}/submissions", response_model=list[SubmissionOut])
def list_submissions(
    competition_id: uuid.UUID,
    team_id: uuid.UUID | None = Query(default=None),
    challenge_id: uuid.UUID | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> list[SubmissionOut]:
    rows = competitions.list_submissions(
        session,
        principal,
        competition_id,
        team_id=team_id,
        challenge_id=challenge_id,
        limit=limit,
    )
    teams = {
        team.id: team.name
        for team in session.execute(
            select(CompetitionTeam).where(CompetitionTeam.competition_id == competition_id)
        )
        .scalars()
        .all()
    }
    challenges = {
        challenge.id: (challenge.title, challenge.max_attempts)
        for challenge in session.execute(
            select(CompetitionChallenge).where(
                CompetitionChallenge.competition_id == competition_id
            )
        )
        .scalars()
        .all()
    }
    # ``attempts_remaining`` is the CURRENT budget for that (team, challenge) pair, not a
    # reconstruction of what it was when the row was written — the UI uses it to decide whether the
    # submit box is still live, so a historical value would be actively wrong.
    used = {
        (team_id, challenge_id): count
        for team_id, challenge_id, count in session.execute(
            select(
                CompetitionSubmission.team_id,
                CompetitionSubmission.challenge_id,
                func.count(CompetitionSubmission.id),
            )
            .where(CompetitionSubmission.competition_id == competition_id)
            .group_by(CompetitionSubmission.team_id, CompetitionSubmission.challenge_id)
        ).all()
    }
    return [
        submission_out(
            row,
            team_name=teams.get(row.team_id, "(removed team)"),
            challenge_title=challenges.get(row.challenge_id, ("(removed challenge)", 0))[0],
            attempts_remaining=max(
                challenges.get(row.challenge_id, ("", 0))[1]
                - used.get((row.team_id, row.challenge_id), 0),
                0,
            ),
        )
        for row in rows
    ]


@router.get("/competitions/{competition_id}/scoreboard", response_model=ScoreboardOut)
def get_scoreboard(
    competition_id: uuid.UUID,
    session: Session = DB_SESSION,
    principal: Principal = Depends(current_principal),
) -> ScoreboardOut:
    competition, entries, total_points = competitions.scoreboard(session, principal, competition_id)
    return scoreboard_out(competition, entries, total_points)
