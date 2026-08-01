"""Tier gating for the acceptance suite.

Two hooks, doing the two halves of one job:

``pytest_collection_modifyitems``
    When the container tier was NOT declared, container-tier tests are DESELECTED, not skipped. A
    deselected test is absent from the report; a skipped one is a green tick with a footnote, and a
    reader scanning a CI summary sees the tick.

``pytest_sessionfinish``
    When the container tier WAS declared, the session fails unless the tier left a complete witness.
    This is the half that a skip cannot satisfy and that mechanism 1 cannot catch: a container body
    that never executed at all — deselected by a stray ``-k``, renamed, or lost to a collection
    error — leaves every collected test passing and the run green. Here it does not.

The hooks are scoped to ``apps/acceptance/tests`` so the ordinary CI shards, which collect this
directory for its hermetic contract tests, are unaffected except for the deselection.
"""

from __future__ import annotations

import os

import pytest
from secp_acceptance import AcceptanceError
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
    keep, drop = [], []
    for item in items:
        (drop if item.get_closest_marker(CONTAINER_MARKER) else keep).append(item)
    if drop:
        config.hook.pytest_deselected(items=drop)
        items[:] = keep


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail a declared container tier that did not actually execute.

    Deliberately runs even when ``exitstatus`` is already non-zero: an incomplete tier is worth
    reporting alongside whatever else failed, and suppressing it on an already-failing run would
    hide it exactly when the run is most confusing.
    """
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
