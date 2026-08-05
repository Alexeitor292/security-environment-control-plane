"""Competition core: flag secrecy, no duplicate credit, bounded attempts, server-side scoring."""

from __future__ import annotations

import pytest
import secp_api.range_models  # noqa: F401  (registers the range tables on Base before create_all)
from secp_api.range_enums import CompetitionState, RangeState, SubmissionVerdict
from secp_api.range_models import CompetitionFlag, CompetitionScore
from secp_api.services import competitions, ranges

#: The catalog's first challenge and its correct flag. Kept here so a catalog change that breaks
#: the seeding contract fails loudly rather than silently making these tests vacuous.
FIRST_CHALLENGE_KEY = "dvwa-default-credentials"
FIRST_FLAG = "password"


@pytest.fixture
def ready_range(session, principal):
    instance = ranges.create_range(session, principal, template_slug="web-breach-lab")
    instance.state = RangeState.ready
    session.commit()
    return instance


@pytest.fixture
def competition(session, principal, ready_range):
    comp = competitions.create_competition(session, principal, ready_range.id, name="Test CTF")
    session.commit()
    return comp


@pytest.fixture
def started(session, principal, competition):
    team = competitions.create_team(session, principal, competition.id, name="Red Team")
    session.commit()
    competitions.start_competition(session, principal, competition.id)
    session.commit()
    return competition, team


def _challenge(session, principal, competition, key=FIRST_CHALLENGE_KEY):
    return next(
        challenge
        for challenge in competitions.list_challenges(session, principal, competition.id)
        if challenge.key == key
    )


def test_creating_a_competition_seeds_challenges_and_flags(session, principal, competition):
    challenges = competitions.list_challenges(session, principal, competition.id)
    assert len(challenges) == 6
    assert sum(challenge.points for challenge in challenges) == 600
    flags = session.query(CompetitionFlag).all()
    assert len(flags) == 6


def test_flag_values_are_never_stored_in_plaintext(session, principal, competition):
    """A database read must not hand out solutions."""
    for flag in session.query(CompetitionFlag).all():
        assert flag.value_hash != FIRST_FLAG
        assert FIRST_FLAG not in flag.value_hash
        assert len(flag.value_hash) == 64  # sha256 hex from PBKDF2
        assert len(flag.salt) == 32
    # Every seeded flag has its OWN salt, so identical values would not collide.
    salts = {flag.salt for flag in session.query(CompetitionFlag).all()}
    assert len(salts) == 6


def test_no_response_schema_can_carry_a_flag(session, principal, competition):
    """Structural, not textual.

    A substring search for the flag would be worthless here: this challenge's flag is the English
    word "password", which legitimately appears in its own description. So assert the SHAPE instead
    — ``ChallengeOut``'s fields are pinned, and no schema in the module exposes a flag-bearing
    field. Adding one fails this test; prose is free to say whatever it likes.
    """
    import inspect as _inspect

    from pydantic import BaseModel
    from secp_api import schemas_range
    from secp_api.schemas_range import ChallengeOut

    assert set(ChallengeOut.model_fields) == {
        "id",
        "competition_id",
        "key",
        "title",
        "description",
        "category",
        "points",
        "component_key",
        "hint",
        "max_attempts",
        "solve_count",
        "solved_by_team_ids",
    }

    forbidden = {"flag", "flags", "value", "value_hash", "salt", "answer", "solution"}
    for _, model in _inspect.getmembers(schemas_range, _inspect.isclass):
        if issubclass(model, BaseModel) and model.__module__ == schemas_range.__name__:
            leaked = forbidden & set(model.model_fields)
            # ``SubmissionCreate.value`` is the one legitimate 'value': it is INBOUND, the
            # candidate the player types. No OUTBOUND model may carry any of these.
            if model.__name__ == "SubmissionCreate":
                assert leaked == {"value"}
                continue
            assert not leaked, f"{model.__name__} exposes {leaked}"


def test_the_stored_flag_digest_never_reaches_a_projected_payload(session, principal, competition):
    """The salt and digest are random hex, so searching for them cannot produce a false positive."""
    from secp_api.range_projection import challenge_out

    solvers = competitions.solvers_by_challenge(session, competition.id)
    rendered = " ".join(
        str(challenge_out(challenge, solvers).model_dump())
        for challenge in competitions.list_challenges(session, principal, competition.id)
    )
    for flag in session.query(CompetitionFlag).all():
        assert flag.value_hash not in rendered
        assert flag.salt not in rendered


def test_a_correct_flag_scores_once_and_never_again(session, principal, started):
    competition, team = started
    challenge = _challenge(session, principal, competition)

    first = competitions.submit_flag(
        session,
        principal,
        competition.id,
        team_id=team.id,
        challenge_id=challenge.id,
        value=FIRST_FLAG,
    )
    session.commit()
    assert first.submission.verdict is SubmissionVerdict.accepted
    assert first.submission.points_awarded == challenge.points

    # The same team submitting the same correct flag again gets NO further credit.
    second = competitions.submit_flag(
        session,
        principal,
        competition.id,
        team_id=team.id,
        challenge_id=challenge.id,
        value=FIRST_FLAG,
    )
    session.commit()
    assert second.submission.verdict is SubmissionVerdict.already_solved
    assert second.submission.points_awarded == 0

    awards = (
        session.query(CompetitionScore)
        .filter(CompetitionScore.team_id == team.id, CompetitionScore.challenge_id == challenge.id)
        .all()
    )
    assert len(awards) == 1, "exactly one award row may exist per (team, challenge)"

    _, entries, total = competitions.scoreboard(session, principal, competition.id)
    assert entries[0].score == challenge.points
    assert entries[0].solved_count == 1
    assert total == 600


def test_the_award_ledger_makes_double_credit_structurally_impossible(session, principal, started):
    """Not an ``if`` — a unique constraint. A second award row cannot be inserted at all."""
    competition, team = started
    challenge = _challenge(session, principal, competition)
    competitions.submit_flag(
        session,
        principal,
        competition.id,
        team_id=team.id,
        challenge_id=challenge.id,
        value=FIRST_FLAG,
    )
    session.commit()

    from sqlalchemy.exc import IntegrityError

    session.add(
        CompetitionScore(
            organization_id=competition.organization_id,
            competition_id=competition.id,
            team_id=team.id,
            challenge_id=challenge.id,
            points=challenge.points,
        )
    )
    with pytest.raises(IntegrityError):
        session.flush()
    session.rollback()


def test_an_incorrect_flag_is_a_normal_outcome(session, principal, started):
    competition, team = started
    challenge = _challenge(session, principal, competition)
    outcome = competitions.submit_flag(
        session,
        principal,
        competition.id,
        team_id=team.id,
        challenge_id=challenge.id,
        value="definitely-not-it",
    )
    session.commit()
    assert outcome.submission.verdict is SubmissionVerdict.incorrect
    assert outcome.submission.points_awarded == 0
    assert outcome.attempts_remaining == challenge.max_attempts - 1


def test_flag_comparison_ignores_surrounding_whitespace_and_case(session, principal, started):
    competition, team = started
    challenge = _challenge(session, principal, competition)
    outcome = competitions.submit_flag(
        session,
        principal,
        competition.id,
        team_id=team.id,
        challenge_id=challenge.id,
        value="  PASSWORD  ",
    )
    session.commit()
    assert outcome.submission.verdict is SubmissionVerdict.accepted


def test_repeating_a_value_is_recorded_as_a_duplicate(session, principal, started):
    competition, team = started
    challenge = _challenge(session, principal, competition)
    for _ in range(2):
        outcome = competitions.submit_flag(
            session,
            principal,
            competition.id,
            team_id=team.id,
            challenge_id=challenge.id,
            value="same-wrong-guess",
        )
        session.commit()
    assert outcome.submission.verdict is SubmissionVerdict.duplicate


def test_attempts_are_bounded(session, principal, started):
    competition, team = started
    challenge = _challenge(session, principal, competition)
    for index in range(challenge.max_attempts):
        outcome = competitions.submit_flag(
            session,
            principal,
            competition.id,
            team_id=team.id,
            challenge_id=challenge.id,
            value=f"guess-{index}",
        )
        session.commit()
    assert outcome.attempts_remaining == 0

    # Budget exhausted: even the CORRECT flag no longer scores.
    exhausted = competitions.submit_flag(
        session,
        principal,
        competition.id,
        team_id=team.id,
        challenge_id=challenge.id,
        value=FIRST_FLAG,
    )
    session.commit()
    assert exhausted.submission.verdict is SubmissionVerdict.attempts_exhausted
    assert exhausted.submission.points_awarded == 0
    assert not session.query(CompetitionScore).filter(CompetitionScore.team_id == team.id).all()


def test_submissions_are_refused_when_the_competition_is_not_running(
    session, principal, competition
):
    team = competitions.create_team(session, principal, competition.id, name="Blue")
    session.commit()
    challenge = _challenge(session, principal, competition)
    outcome = competitions.submit_flag(
        session,
        principal,
        competition.id,
        team_id=team.id,
        challenge_id=challenge.id,
        value=FIRST_FLAG,
    )
    session.commit()
    assert outcome.submission.verdict is SubmissionVerdict.not_open
    assert outcome.submission.points_awarded == 0


def test_starting_a_competition_requires_a_ready_range_and_a_team(session, principal, competition):
    with pytest.raises(ranges.RangeInvalidTransitionError):
        competitions.start_competition(session, principal, competition.id)

    competitions.create_team(session, principal, competition.id, name="Red")
    instance = session.get(type(competition).__mro__[0], competition.range_instance_id)
    del instance
    from secp_api.range_models import RangeInstance

    row = session.get(RangeInstance, competition.range_instance_id)
    row.state = RangeState.draft
    session.commit()
    with pytest.raises(ranges.RangeInvalidTransitionError):
        competitions.start_competition(session, principal, competition.id)


def test_starting_moves_the_range_to_active_and_stopping_returns_it(session, principal, started):
    from secp_api.range_models import RangeInstance

    competition, _ = started
    row = session.get(RangeInstance, competition.range_instance_id)
    assert row.state is RangeState.active
    assert competition.state is CompetitionState.running

    competitions.stop_competition(session, principal, competition.id)
    session.commit()
    session.refresh(row)
    assert row.state is RangeState.ready
    assert competition.state is CompetitionState.stopped


def test_scoreboard_ranks_by_score_then_by_who_got_there_first(session, principal, started):
    competition, red = started
    blue = competitions.create_team(session, principal, competition.id, name="Blue Team")
    session.commit()
    challenges = competitions.list_challenges(session, principal, competition.id)
    first, second = challenges[0], challenges[1]

    # Blue solves the cheap one; Red solves the expensive one.
    competitions.submit_flag(
        session,
        principal,
        competition.id,
        team_id=blue.id,
        challenge_id=first.id,
        value=FIRST_FLAG,
    )
    session.commit()
    competitions.submit_flag(
        session,
        principal,
        competition.id,
        team_id=red.id,
        challenge_id=second.id,
        value="e99a18c428cb38d5f260853678922e03",
    )
    session.commit()

    _, entries, _ = competitions.scoreboard(session, principal, competition.id)
    assert [entry.team_name for entry in entries] == ["Red Team", "Blue Team"]
    assert entries[0].rank == 1
    assert entries[0].score == second.points
    assert entries[1].score == first.points


def test_tied_teams_share_a_rank(session, principal, started):
    competition, red = started
    blue = competitions.create_team(session, principal, competition.id, name="Blue Team")
    session.commit()
    _, entries, _ = competitions.scoreboard(session, principal, competition.id)
    assert {entry.rank for entry in entries} == {1}
    assert len(entries) == 2
    del blue, red


def test_reset_scores_keeps_teams_and_challenges(session, principal, started):
    competition, team = started
    challenge = _challenge(session, principal, competition)
    competitions.submit_flag(
        session,
        principal,
        competition.id,
        team_id=team.id,
        challenge_id=challenge.id,
        value=FIRST_FLAG,
    )
    session.commit()

    competitions.reset_scores(session, principal, competition.id)
    session.commit()

    assert len(competitions.list_teams(session, principal, competition.id)) == 1
    assert len(competitions.list_challenges(session, principal, competition.id)) == 6
    _, entries, _ = competitions.scoreboard(session, principal, competition.id)
    assert entries[0].score == 0
    assert competitions.list_submissions(session, principal, competition.id) == []


def test_a_team_from_another_competition_is_rejected(session, principal, started, ready_range):
    competition, _ = started
    other_range = ranges.create_range(session, principal, template_slug="web-breach-lab")
    other_range.state = RangeState.ready
    session.commit()
    other = competitions.create_competition(session, principal, other_range.id)
    foreign_team = competitions.create_team(session, principal, other.id, name="Outsiders")
    session.commit()
    challenge = _challenge(session, principal, competition)

    with pytest.raises(competitions.SubmissionRejectedError):
        competitions.submit_flag(
            session,
            principal,
            competition.id,
            team_id=foreign_team.id,
            challenge_id=challenge.id,
            value=FIRST_FLAG,
        )


def test_one_competition_per_range(session, principal, competition):
    with pytest.raises(ranges.RangeInvalidTransitionError):
        competitions.create_competition(session, principal, competition.range_instance_id)


def test_competitions_are_organization_scoped(session, principal, other_org_principal, competition):
    from secp_api.errors import AuthorizationError

    with pytest.raises(AuthorizationError):
        competitions.get_competition(session, other_org_principal, competition.id)
