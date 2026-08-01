"""Proofs that keep the commit-exposure survey's instrument honest.

The survey's output is a number that feeds an operator decision, so what must be defended is not the
number — it is the instrument's ability to produce one. Every test here fails in the direction of
"this tool can no longer see what it claims to see".

What is deliberately NOT pinned: the survey's headline counts, and in particular "no dependency
declares an explicit scope". Those are facts about the corpus **today**, not invariants of the
design. The whole point of the survey is to inform a decision about changing them, and a guard
asserting today's counts would go red on the very branch that acts on the survey — a false red,
aimed at someone who did nothing wrong. Re-run the survey instead; it prints its own numbers.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "apps/api") not in sys.path:
    sys.path.insert(0, str(REPO / "apps/api"))

os.environ.setdefault("SECP_APP_ENV", "test")
os.environ.setdefault("SECP_WORKFLOW_DISPATCH_MODE", "inline")


@pytest.fixture(scope="module")
def app():
    from secp_api.main import create_app

    application = create_app()
    application.router.on_startup.clear()
    return application


# --- the route census must have a population to count -------------------------------------------


def test_route_enumeration_reaches_the_nested_included_routers(app):
    """The obvious enumeration returns ZERO on this app, and zero is a plausible-looking answer.

    FastAPI 0.138 keeps each included router as one ``_IncludedRouter`` entry rather than
    flattening its routes into ``app.routes``, so ``[r for r in app.routes if isinstance(r,
    APIRoute)]`` finds nothing at all. A survey built on that would have reported an exposure of 0
    and been entirely wrong.
    """
    from commit_exposure_survey.census import iter_api_routes
    from fastapi.routing import APIRoute

    naive = [route for route in app.routes if isinstance(route, APIRoute)]
    walked = iter_api_routes(app)
    assert naive == [], (
        "the naive enumeration now works, so this regression's premise has changed; re-check "
        "whether the descending walk is still required"
    )
    assert len(walked) > 100, f"the descending walk found only {len(walked)} routes"


def test_route_census_is_non_vacuous_and_agrees_with_the_openapi_schema(app):
    from commit_exposure_survey.census import census_routes, verify_route_census

    facts = census_routes(app)
    assert verify_route_census(facts, app) == []
    assert any(fact.uses_db_session for fact in facts)


def test_the_session_dependency_is_matched_by_identity_not_by_name(app):
    """A same-named helper elsewhere must not be counted as the real session dependency."""
    import secp_api.deps as deps
    from commit_exposure_survey.census import DB_SESSION_DEPENDENCY

    assert DB_SESSION_DEPENDENCY is deps.db_session


# --- the commit census must be able to see a commit ---------------------------------------------


def test_commit_census_finds_the_known_commits_and_classifies_them(app):
    from commit_exposure_survey.census import census_commit_sites, verify_commit_census

    census = census_commit_sites()
    assert verify_commit_census(census) == []
    # The positive control: secp_api.db's two commits, neither of them in an except handler.
    db_sites = [site for site in census.sites if site.module == "secp_api.db"]
    assert len(db_sites) == 2
    assert all(site.protects_success_path for site in db_sites)


def test_an_except_only_commit_is_not_counted_as_success_path_protection():
    """Four routers commit inside an ``except`` handler to persist a durable refusal audit.

    Read as source text those look like "already protected". They are not: the success path never
    reaches them. Counting them would understate the exposure by four routers' worth of endpoints.
    """
    from commit_exposure_survey.census import census_commit_sites

    census = census_commit_sites()
    error_only = census.error_path_sites()
    assert error_only, "the except-handler classifier found nothing, so it is not discriminating"
    assert not any(site.protects_success_path for site in error_only)


def test_a_savepoint_release_is_not_counted_as_protection():
    """``session.begin_nested().commit()`` RELEASEs a savepoint and makes nothing durable."""
    from commit_exposure_survey.census import census_commit_sites

    census = census_commit_sites()
    savepoints = census.savepoint_sites()
    assert savepoints, "the savepoint rule found nothing, so a non-durable commit could count"
    assert not any(site.protects_success_path for site in savepoints)


# --- the runtime instrument must tell a real commit from a savepoint release ---------------------


def test_the_recorder_distinguishes_a_real_commit_from_a_savepoint_release():
    """The single most dangerous way this instrument can regress.

    The ORM's ``after_commit`` fires for a SAVEPOINT release as well as a real transaction commit.
    Keying on it would make any endpoint whose in-request work is a savepoint report as NOT_EXPOSED
    — understating the blast radius, which is the direction that gets acted on. The check re-derives
    the divergence at runtime rather than trusting a comment.
    """
    from commit_exposure_survey.measure import CommitRecorder, verify_savepoint_discrimination

    ok, note = verify_savepoint_discrimination(CommitRecorder())
    assert ok, note
    assert "0 recorded commits" in note


def test_an_undrivable_endpoint_is_never_reported_as_safe():
    """``NOT_MEASURED`` and ``NOT_EXPOSED`` must stay distinct outcomes.

    An endpoint that could not be driven is not an endpoint shown to be safe, and collapsing the
    two is how a survey turns silence into a reassuring number.
    """
    from commit_exposure_survey.measure import CommitEvent, RequestObservation

    undriven = RequestObservation(label="x", method="POST", path="/x", status=422)
    assert undriven.verdict() == "NOT_MEASURED"

    no_timestamp = RequestObservation(label="x", method="POST", path="/x", status=201)
    assert no_timestamp.verdict() == "NOT_MEASURED"

    exposed = RequestObservation(label="x", method="POST", path="/x", status=201)
    exposed.response_completed_at = 100.0
    exposed.commits = [CommitEvent(at=100.5, wrote=True, in_dependency_teardown=True)]
    assert exposed.verdict() == "EXPOSED"

    safe = RequestObservation(label="x", method="POST", path="/x", status=201)
    safe.response_completed_at = 100.0
    safe.commits = [CommitEvent(at=99.5, wrote=True, in_dependency_teardown=False)]
    assert safe.verdict() == "NOT_EXPOSED"

    read_only = RequestObservation(label="x", method="GET", path="/x", status=200)
    read_only.response_completed_at = 100.0
    read_only.commits = [CommitEvent(at=100.5, wrote=False, in_dependency_teardown=True)]
    assert read_only.verdict() == "NO_WRITE"


def test_the_survey_never_imports_into_production():
    """A survey that changed the thing it measures would be worthless."""
    import secp_api.deps
    import secp_api.main

    for module in (secp_api.main, secp_api.deps):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "commit_exposure_survey" not in source
