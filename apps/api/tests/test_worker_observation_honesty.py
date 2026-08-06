"""Liveness must never be manufactured from enrollment state, and must not survive a restart.

Two failure modes drive every test here, and both are failures of honesty rather than of logic:

1. **Substitution.** ``WorkerEnrollmentStateName.healthy`` is a terminal enrollment transition that
   stays true forever. Rendering it as "online" is the single most likely defect in this area
   precisely because the state is called ``healthy``.
2. **Reconstruction.** An in-memory observation that reappears after a controller restart — derived
   from a durable row that carries no timing — would read as fresh while proving nothing.
"""

from __future__ import annotations

import pathlib
from datetime import UTC, datetime, timedelta

import pytest
from secp_api.worker_observation import (
    DEFAULT_FRESHNESS_THRESHOLD,
    OBSERVATION_ERROR,
    OBSERVATION_FRESH,
    OBSERVATION_STALE,
    OBSERVATION_UNOBSERVED,
    SOURCE_ENROLLMENT_EXCHANGE,
    WorkerObservation,
    WorkerObservationRegistry,
    project_liveness,
)

NOW = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)
WORKER = "wk-installation-0001"


def _observation(**overrides) -> WorkerObservation:
    base = dict(
        worker_installation_id=WORKER,
        worker_key_fingerprint="sha256:" + "a" * 64,
        worker_role="proxmox_privileged",
        release_fingerprint="sha256:" + "b" * 64,
        observed_task_queue="secp-ordinary",
        observation_source=SOURCE_ENROLLMENT_EXCHANGE,
        observed_at=NOW,
    )
    base.update(overrides)
    return WorkerObservation(**base)


# --- the words this module may never say ----------------------------------------------------------

FORBIDDEN_LIVENESS_WORDS = ("online", "offline", "healthy")


def test_the_vocabulary_contains_no_current_state_claim():
    """``online``/``offline``/``healthy`` assert a state of the world right now.

    What the control plane has is a timestamp and an age. The strongest true statement available is
    "it was there at T", so the vocabulary is four values that all carry their own qualification.
    """
    for value in (
        OBSERVATION_UNOBSERVED,
        OBSERVATION_FRESH,
        OBSERVATION_STALE,
        OBSERVATION_ERROR,
    ):
        assert value not in FORBIDDEN_LIVENESS_WORDS


def test_no_forbidden_word_can_be_emitted_by_the_projection():
    """Scans the whole projection, not only ``state``.

    A field added later — a summary string, a badge label — is exactly where one of these words
    would reappear, and it would not be caught by checking ``state`` alone.
    """
    import dataclasses

    projection = project_liveness(_observation(), now=NOW)
    for field in dataclasses.fields(projection):
        value = getattr(projection, field.name)
        if isinstance(value, str):
            lowered = value.lower()
            for word in FORBIDDEN_LIVENESS_WORDS:
                assert word not in lowered, f"{field.name} says {value!r}"


def _module_source() -> str:
    return (
        pathlib.Path(__file__).resolve().parents[1] / "secp_api" / "worker_observation.py"
    ).read_text(encoding="utf-8")


def _imported_names() -> set[str]:
    """Every module and symbol ``worker_observation`` imports, via AST.

    Deliberately NOT a substring scan of the source. The first version of this guard was one, and
    it failed on its own explanatory docstring — which names ``WorkerEnrollmentStateName`` in order
    to explain why it must not be imported. A text scan cannot tell the difference between a
    dependency and a sentence about a dependency; the import table can.
    """
    import ast

    names: set[str] = set()
    for node in ast.walk(ast.parse(_module_source())):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names.add(module)
            names.update(f"{module}.{alias.name}" for alias in node.names)
            names.update(alias.name for alias in node.names)
    return names


def test_the_module_does_not_import_enrollment_state():
    """Structural, not stylistic: liveness cannot be derived from enrollment if it cannot see it.

    A projection that imported ``WorkerEnrollmentStateName`` could map ``healthy`` to ``fresh`` in
    one line, and that line would look reasonable in review. Removing the import removes the
    temptation and makes the substitution a visible architectural change instead.
    """
    imported = _imported_names()
    assert "WorkerEnrollmentStateName" not in imported
    assert not any(
        name.startswith("secp_api.enums") or name.startswith("secp_api.worker_enrollment")
        for name in imported
    ), sorted(imported)


# --- the readings ---------------------------------------------------------------------------------


def test_never_heard_from_is_unobserved():
    projection = project_liveness(None, now=NOW)
    assert projection.state == OBSERVATION_UNOBSERVED
    assert projection.is_observed is False
    assert projection.observed_at is None
    assert projection.age_seconds is None
    # The threshold is still reported. An operator asking "why does it say unobserved" is owed the
    # number it would have been compared against.
    assert projection.freshness_threshold_seconds == DEFAULT_FRESHNESS_THRESHOLD.total_seconds()


@pytest.mark.parametrize(
    "elapsed,expected",
    [
        (0, OBSERVATION_FRESH),
        (89, OBSERVATION_FRESH),
        (90, OBSERVATION_FRESH),  # the boundary is inclusive
        (91, OBSERVATION_STALE),
        (3600, OBSERVATION_STALE),
    ],
)
def test_freshness_is_an_age_compared_to_a_threshold(elapsed, expected):
    projection = project_liveness(_observation(), now=NOW + timedelta(seconds=elapsed))
    assert projection.state == expected
    assert projection.age_seconds == float(elapsed)


def test_a_stale_reading_still_reports_its_exact_age_and_identity():
    """ "Stale" alone is nearly useless. Last seen 40 minutes ago, on this queue, at this release,
    is actionable."""
    projection = project_liveness(_observation(), now=NOW + timedelta(minutes=40))
    assert projection.state == OBSERVATION_STALE
    assert projection.age_seconds == 2400.0
    assert projection.observed_at == NOW
    assert projection.worker_installation_id == WORKER
    assert projection.worker_role == "proxmox_privileged"
    assert projection.release_fingerprint == "sha256:" + "b" * 64
    assert projection.observed_task_queue == "secp-ordinary"
    assert projection.observation_source == SOURCE_ENROLLMENT_EXCHANGE


def test_a_future_stamped_observation_is_an_error_not_freshness():
    """Clock skew must not become a liveness guarantee.

    An observation stamped ahead of ``now`` would otherwise compute a negative age, sail under the
    threshold, and report ``fresh`` — turning a broken clock into proof the worker is up.
    """
    projection = project_liveness(_observation(), now=NOW - timedelta(seconds=30))
    assert projection.state == OBSERVATION_ERROR
    assert projection.age_seconds == -30.0
    assert "clock skew" in projection.error


def test_a_recorded_error_is_still_an_observation():
    """Contact happened even though the report was unusable, so the timestamp is real and kept."""
    projection = project_liveness(
        _observation(error="worker reported no task queue"), now=NOW + timedelta(seconds=5)
    )
    assert projection.state == OBSERVATION_ERROR
    assert projection.observed_at == NOW
    assert projection.age_seconds == 5.0
    assert projection.is_observed is True


# --- the registry, and the restart property -------------------------------------------------------


def test_a_fresh_registry_reports_unobserved_for_everyone():
    """THE restart property. A new controller process has heard from nobody, and says so."""
    assert WorkerObservationRegistry().project(WORKER, now=NOW).state == OBSERVATION_UNOBSERVED


def test_an_observation_does_not_survive_a_simulated_restart():
    """Simulated by dropping the state a process would lose, not by patching the projection.

    The point is that the reading reverts to ``unobserved`` — NOT to ``stale``. Stale would imply
    the control plane still knows when it last heard from the worker, and after a restart it does
    not know that at all.
    """
    registry = WorkerObservationRegistry()
    registry.record(_observation())
    assert registry.project(WORKER, now=NOW).state == OBSERVATION_FRESH

    registry.clear()  # what a restart actually does to a process-local dict

    after = registry.project(WORKER, now=NOW)
    assert after.state == OBSERVATION_UNOBSERVED
    assert after.state != OBSERVATION_STALE
    assert after.observed_at is None


def test_a_newer_observation_replaces_an_older_one():
    registry = WorkerObservationRegistry()
    registry.record(_observation())
    later = NOW + timedelta(seconds=60)
    registry.record(_observation(observed_at=later, observed_task_queue="secp-ordinary-2"))

    projection = registry.project(WORKER, now=later)
    assert projection.observed_at == later
    assert projection.observed_task_queue == "secp-ordinary-2"


def test_an_out_of_order_observation_is_dropped():
    """Two authenticated calls can be handled by different threads and land out of order.

    Letting the older one win would make a live worker look staler than it is — a false negative
    rather than a false positive, but still a wrong answer produced by the plumbing.
    """
    registry = WorkerObservationRegistry()
    later = NOW + timedelta(seconds=60)
    registry.record(_observation(observed_at=later))
    registry.record(_observation(observed_at=NOW))  # arrives second, is older

    assert registry.project(WORKER, now=later).observed_at == later


def test_workers_are_tracked_independently():
    registry = WorkerObservationRegistry()
    registry.record(_observation())
    assert registry.project("wk-installation-0002", now=NOW).state == OBSERVATION_UNOBSERVED
    assert registry.project(WORKER, now=NOW).state == OBSERVATION_FRESH


def test_the_registry_reaches_no_database():
    """Non-durability is the contract.

    A registry that quietly grew a session would become the permanent data model without the
    migration and review that change is supposed to require. Checked through the import table for
    the same reason as above — the module's own prose says the word "durable" repeatedly, and a
    text scan would either trip on that or be watered down until it caught nothing.
    """
    imported = _imported_names()
    forbidden = {"sqlalchemy", "sqlalchemy.orm", "secp_api.models", "secp_api.db", "Session"}
    assert not (imported & forbidden), sorted(imported & forbidden)
    assert not any(name.startswith("sqlalchemy") for name in imported), sorted(imported)
