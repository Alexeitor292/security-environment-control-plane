"""Tier gating for the acceptance suite, and the session-scoped acceptance run.

``pytest_collection_modifyitems``
    When the container tier was NOT declared, container-tier tests are DESELECTED, not skipped. A
    deselected test is absent from the report; a skipped one is a green tick with a footnote, and a
    reader scanning a CI summary sees the tick.

``acceptance_run`` (session fixture)
    THE run: one recorder, one fleet, one document, shared by every stage. Session-scoped because
    four streams produce the nine evidence stages, and a per-module recorder would yield four
    partial documents that cannot be reconciled — see :mod:`secp_acceptance.run` for the four-line
    contract a stage is written against.

``pytest_sessionfinish``
    Two jobs, in this order. First it seals and writes the run's evidence, on EVERY path including
    failure — a failed run's evidence is the record of what was and was not established, and writing
    it only on success would mean it exists exactly when nobody needs it. Then, when the container
    tier WAS declared, it fails the session unless the tier left a complete witness. That second
    half is what a skip cannot satisfy and what mechanism 1 cannot catch: a container body that
    never executed at all — deselected by a stray ``-k``, renamed, or lost to a collection error —
    leaves every collected test passing and the run green. Here it does not.

All of this is scoped to ``apps/acceptance/tests`` so the ordinary CI shards, which collect this
directory for its hermetic contract tests, are unaffected except for the deselection. A hermetic
shard opens no stage, so it seals and writes nothing.
"""

from __future__ import annotations

import os
import pathlib

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.run import AcceptanceRun
from secp_acceptance.tier import (
    ENV_TIER,
    TIERS,
    assert_tier_witnessed,
    container_tier_required,
    declared_tier,
    missing_witnesses,
)

#: Enables the ``pytester`` fixture. The tier gate's whole value is in two pytest HOOKS, and a hook
#: can only be proven by running a real pytest session over a real conftest — asserting on the hook
#: functions directly would test the bodies while leaving "is this hook actually wired up?"
#: unmeasured, which is the half that silently breaks.
pytest_plugins = ["pytester"]

#: Applied to every test that needs a real container runtime.
CONTAINER_MARKER = "container_tier"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        f"{CONTAINER_MARKER}: needs a real container runtime; deselected unless the container "
        f"tier is declared, and REFUSED (never skipped) when it is declared and Docker is absent",
    )
    # Fail immediately on a malformed tier declaration rather than at the first container test: a
    # typo in the acceptance workflow must not present as "no container tests were collected".
    # Reported as a UsageError so it exits as a clean, attributable configuration failure rather
    # than an INTERNALERROR traceback that a reader has to decode.
    try:
        declared_tier()
    except AcceptanceError as exc:
        raise pytest.UsageError(
            f"{exc.reason_code}: {ENV_TIER}={os.environ.get(ENV_TIER)!r} is not a known "
            f"acceptance tier. Use one of: {', '.join(sorted(TIERS))}."
        ) from None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if container_tier_required():
        return
    keep: list[pytest.Item] = []
    drop: list[pytest.Item] = []
    for item in items:
        (drop if item.get_closest_marker(CONTAINER_MARKER) else keep).append(item)
    if drop:
        config.hook.pytest_deselected(items=drop)
        items[:] = keep


#: Where the session's run is parked so ``pytest_sessionfinish`` can seal it. A hook cannot request
#: a fixture, and the document MUST be written on the failure paths — which is exactly when a run's
#: evidence is worth the most — so the run is reachable from the config rather than from the fixture
#: graph.
_RUN_ATTRIBUTE = "_secp_acceptance_run"


@pytest.fixture(scope="session")
def acceptance_run(request: pytest.FixtureRequest) -> AcceptanceRun:
    """THE run. One recorder, one fleet, one document, for the whole session.

    Session-scoped on purpose: four streams produce the nine stages, and a per-module recorder would
    give four partial documents that cannot be reconciled. Stages are handed this; they never build
    their own.

    Not gated on the container tier. A hermetic session may hold one and never open a stage, which
    seals nothing — the document is written only when a stage was actually opened.
    """
    run = AcceptanceRun()
    setattr(request.config, _RUN_ATTRIBUTE, run)
    return run


def _seal_the_run(session: pytest.Session) -> None:
    """Seal and write the evidence document for a session that actually opened a stage.

    Runs on EVERY path including failure. A failed run's evidence is the most valuable evidence the
    harness produces — it is the record of what was and was not established — and writing it only on
    success would mean the document exists exactly when nobody needs to consult it.

    A session that opened no stage writes nothing. That is not a silent skip: there is no run to
    describe, and an empty document would be a claim rather than an absence.
    """
    run = getattr(session.config, _RUN_ATTRIBUTE, None)
    if run is None or not run.stages:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    try:
        # pytest's own rootpath, not a search for the repo root: it is always defined, it is where
        # the acceptance workflow's upload step looks, and a search would raise inside any session
        # whose working tree does not look like this repository.
        path = run.write(pathlib.Path(session.config.rootpath))
    except AcceptanceError as exc:
        # Stages ran but the document could not be sealed — most likely no fleet was ever recorded.
        # That is a harness failure and must fail the session: a run that produced observations and
        # then could not say what it observed them ABOUT is not an acceptance result.
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        if reporter is not None:
            reporter.write_sep("=", "ACCEPTANCE EVIDENCE NOT SEALED", red=True, bold=True)
            reporter.write_line(
                f"{exc.reason_code}: {len(run.stages)} stage(s) recorded checks, but the evidence "
                f"document could not be sealed. This run is NOT an acceptance result."
            )
        return
    if reporter is not None:
        document = run.sealed
        assert document is not None  # write() sealed it or raised
        reporter.write_sep("=", "ACCEPTANCE EVIDENCE", bold=True)
        reporter.write_line(
            f"outcome={document.outcome} stages={len(document.stages_attempted)}/9 "
            f"checks={len(document.checks)} violated={len(document.violated())} "
            f"unproven={len(document.unproven())} missing={len(document.missing_checks())}"
        )
        reporter.write_line(f"written to {path.name} (digest {document.digest()[:19]}...)")


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Seal the run's evidence, then fail a declared container tier that did not actually execute.

    Deliberately runs even when ``exitstatus`` is already non-zero: an incomplete tier is worth
    reporting alongside whatever else failed, and suppressing it on an already-failing run would
    hide it exactly when the run is most confusing.

    Sealing happens FIRST, so the document survives even when the witness check is about to fail the
    session — those are the runs whose evidence a reader most needs.
    """
    _seal_the_run(session)
    if not container_tier_required():
        return
    try:
        assert_tier_witnessed()
    except AcceptanceError as exc:
        missing = ", ".join(missing_witnesses())
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_sep("=", "ACCEPTANCE TIER NOT EXECUTED", red=True, bold=True)
            reporter.write_line(
                f"{exc.reason_code}: the container tier was declared "
                f"(SECP_ACCEPTANCE_TIER=container) but these stages left no witness: {missing}.\n"
                "Every collected test may have passed; this run is NOT an acceptance result."
            )
