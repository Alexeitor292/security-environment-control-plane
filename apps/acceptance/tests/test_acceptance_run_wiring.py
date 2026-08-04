"""The run FIXTURE and the session-final seal, proven through real pytest sessions.

Why ``pytester`` and not direct calls: :mod:`test_acceptance_run` already tests
:class:`~secp_acceptance.run.AcceptanceRun` as an object, and every one of those tests would still
pass if the fixture were never declared and ``pytest_sessionfinish`` never sealed anything. The half
that silently breaks is the WIRING — an unrequested fixture, a hook that returns early, a document
nobody writes — and it can only be measured by running a session over the real conftest.

This is the same reasoning ``test_acceptance_tier_gate.py`` gives for testing its two hooks through
``runpytest_subprocess`` rather than by calling the hook functions.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from secp_acceptance.run import EVIDENCE_FILENAME

pytest_plugins = ["pytester"]


def _acceptance_package_root() -> str:
    """``apps/acceptance`` — importable so the subprocess can reach ``secp_acceptance``."""
    return str(pathlib.Path(__file__).resolve().parents[1])


def _install_real_conftest(pytester: pytest.Pytester, monkeypatch) -> None:
    """Copy the REAL conftest into the scratch suite, read from disk rather than restated.

    Restating it would let this file drift from the wiring it is supposed to prove — the exact
    failure mode that makes a wiring test worthless.
    """
    monkeypatch.setenv("PYTHONPATH", _acceptance_package_root())
    real = pathlib.Path(__file__).parent / "conftest.py"
    pytester.makeconftest(real.read_text(encoding="utf-8"))


#: A stage body that takes the session fixture, records a real fleet record, and covers the fleet
#: stage. Written as source for the subprocess.
_STAGE_SUITE = """
    from secp_acceptance.evidence import FleetRecord
    from secp_acceptance.reasons import CHECKS_BY_STAGE, STAGE_FLEET

    FLEET = FleetRecord(
        host_image_identity="sha256:" + "1" * 64,
        controller_host_identity="sha256:" + "2" * 64,
        worker_host_identity="sha256:" + "3" * 64,
        network_identity="sha256:" + "4" * 64,
        hosts_created=2,
        hosts_destroyed=2,
        nested_container_runtime=True,
        real_service_manager=True,
    )

    def test_a_stage_records_through_the_session_run(acceptance_run):
        acceptance_run.set_fleet(FLEET)
        acceptance_run.open_stage(STAGE_FLEET)
        for check in CHECKS_BY_STAGE[STAGE_FLEET]:
            acceptance_run.observe(check, STAGE_FLEET, {"check": check})
"""


def test_the_session_seals_and_writes_a_document(pytester, monkeypatch):
    """THE wiring test. A stage that used the fixture leaves a real document on disk."""
    _install_real_conftest(pytester, monkeypatch)
    pytester.makepyfile(test_stage=_STAGE_SUITE)

    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(passed=1, failed=0, errors=0)

    written = pytester.path / EVIDENCE_FILENAME
    assert written.is_file(), "the session finished without writing an evidence document"
    document = json.loads(written.read_text(encoding="utf-8"))
    assert document["stages_attempted"] == ["fleet"]
    assert len(document["checks"]) == 6
    # one stage is not nine, so it must NOT claim the word
    assert document["outcome"] == "failed"


def test_the_document_is_written_even_when_the_session_FAILS(pytester, monkeypatch):
    """The point of sealing on every path.

    A failed run's evidence is the record of what was and was not established. Writing it only on
    success would mean the document exists precisely when nobody needs to consult it.
    """
    _install_real_conftest(pytester, monkeypatch)
    pytester.makepyfile(
        test_stage=_STAGE_SUITE
        + """
    def test_something_else_blows_up():
        raise AssertionError("the stage after the recording failed")
"""
    )

    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(passed=1, failed=1)
    assert result.ret != 0

    written = pytester.path / EVIDENCE_FILENAME
    assert written.is_file(), "a FAILED session must still leave its evidence behind"
    assert json.loads(written.read_text(encoding="utf-8"))["stages_attempted"] == ["fleet"]


def test_a_session_that_opened_no_stage_writes_nothing(pytester, monkeypatch):
    """An empty document would be a CLAIM about a run that did not happen.

    The hermetic contract tests are collected by the ordinary CI shards on every PR; they must not
    litter the repository root with a document describing nothing.
    """
    _install_real_conftest(pytester, monkeypatch)
    pytester.makepyfile(
        test_plain="""
        def test_hermetic_only():
            assert True
        """
    )

    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(passed=1)
    assert not (pytester.path / EVIDENCE_FILENAME).exists()


def test_a_stage_that_recorded_without_a_fleet_FAILS_the_session(pytester, monkeypatch):
    """A run that produced observations and then could not say what it observed them ABOUT is not
    an acceptance result, and must not exit green having written nothing."""
    _install_real_conftest(pytester, monkeypatch)
    pytester.makepyfile(
        test_stage="""
        from secp_acceptance.reasons import STAGE_FLEET

        def test_records_but_never_sets_a_fleet(acceptance_run):
            acceptance_run.open_stage(STAGE_FLEET)
            acceptance_run.observe("hosts_are_distinct", STAGE_FLEET, {})
        """
    )

    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(passed=1, failed=0, errors=0)  # the collected test passed...
    assert result.ret != 0, "...and the session must still fail"
    result.stdout.fnmatch_lines(["*ACCEPTANCE EVIDENCE NOT SEALED*"])
    result.stdout.fnmatch_lines(["*acceptance_run_fleet_not_recorded*"])
    assert not (pytester.path / EVIDENCE_FILENAME).exists()


def test_the_run_is_one_object_across_modules(pytester, monkeypatch):
    """THE reason the fixture is session-scoped.

    Two stage modules, as the four streams will be. They must land in ONE document with both stages,
    not two documents or a document with the last writer's stage only.
    """
    _install_real_conftest(pytester, monkeypatch)
    pytester.makepyfile(test_stage_one=_STAGE_SUITE)
    pytester.makepyfile(
        test_stage_two="""
        from secp_acceptance.reasons import CHECKS_BY_STAGE, STAGE_QUEUES

        def test_a_second_stage_shares_the_same_run(acceptance_run):
            acceptance_run.open_stage(STAGE_QUEUES)
            for check in CHECKS_BY_STAGE[STAGE_QUEUES]:
                acceptance_run.observe(check, STAGE_QUEUES, {"check": check})
        """
    )

    result = pytester.runpytest_subprocess("-q")
    result.assert_outcomes(passed=2, failed=0, errors=0)

    document = json.loads((pytester.path / EVIDENCE_FILENAME).read_text(encoding="utf-8"))
    assert sorted(document["stages_attempted"]) == ["fleet", "queues"]
    assert len(document["checks"]) == 12, "both stages' checks must be in ONE document"
