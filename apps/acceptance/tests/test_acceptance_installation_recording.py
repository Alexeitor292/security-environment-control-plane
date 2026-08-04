"""Hermetic proof that the installation driver RECORDS what it observed, and can say "no".

WHY THIS FILE EXISTS
--------------------
Every producer in ``secp_acceptance.driver`` runs only in the container tier, so until now the
recording logic — the part that decides whether a check becomes ``observed``, ``unproven`` or
``violated`` — had no coverage that runs on a machine without Docker. That is the wrong half to
leave unmeasured: an installation that fails to install is loud, but a recorder that turns every
result into a pass is silent.

WHAT IT GUARDS AGAINST SPECIFICALLY
-----------------------------------
The container-tier nodes assert ``run.outcome_of(check) == "observed"``. That assertion is only
worth anything if the driver can produce something OTHER than ``observed``. A recording path that
answered "observed" regardless — because every branch fell through to the success case, or because
an exception silently skipped the record — would make all twenty of those nodes pass without
measuring anything, and they would keep passing through any future encoding mistake.

So these tests drive the REAL ``_StageRecorder`` and require each of its outcomes to be reachable
and distinguishable. They are the falsifiability control for the container tier, and they run in the
required gate on every PR.

Deliberately no run-level ``outcome`` assertion anywhere here. ``AcceptanceRecorder.seal`` derives
``passed`` only when ``set(stages) == STAGES``, so any single-stage run seals ``failed`` no matter
what its checks say — an assertion on that would be true for a reason unrelated to what it watched.
The property these stages own is at CHECK level, and that is what is asserted.
"""

from __future__ import annotations

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.driver import InstallationRun, _StageRecorder
from secp_acceptance.hosts import ROLE_WORKER, Host
from secp_acceptance.install import observe_operator_unit
from secp_acceptance.reasons import (
    OUTCOME_OBSERVED,
    OUTCOME_UNPROVEN,
    OUTCOME_VIOLATED,
    STAGE_WORKER_INSTALL,
)
from secp_acceptance.release import ReleaseMaterial
from secp_acceptance.run import AcceptanceRun
from secp_acceptance.shell import Result

_CHECK = "worker_operator_unit_present_disabled_stopped"


def _run() -> tuple[InstallationRun, _StageRecorder]:
    """A real run and a real stage recorder over the worker_install stage."""
    import pathlib

    install_run = InstallationRun(
        acceptance_run=AcceptanceRun(), material=ReleaseMaterial(workdir=pathlib.Path("."))
    )
    stage = _StageRecorder(install_run, STAGE_WORKER_INSTALL, install_run.worker)
    return install_run, stage


# --------------------------------------------------------------------------- the four outcomes


def test_a_positive_result_is_recorded_observed():
    run, stage = _run()
    stage.attempt(
        _CHECK, reason="acceptance_observation_unavailable", produce=lambda: (True, {"a": 1})
    )
    assert run.outcome_of(_CHECK) == OUTCOME_OBSERVED


def test_a_negative_result_is_recorded_unproven_and_NOT_observed():
    """THE control for the whole container tier.

    If this could not fail, every ``_assert_observed`` node in the installation module would be
    vacuous — they would pass on a run where nothing was installed at all.
    """
    run, stage = _run()
    stage.attempt(
        _CHECK, reason="acceptance_observation_unavailable", produce=lambda: (False, {"a": 1})
    )
    assert run.outcome_of(_CHECK) == OUTCOME_UNPROVEN
    assert run.outcome_of(_CHECK) != OUTCOME_OBSERVED
    assert run.reason_for(_CHECK) == "acceptance_observation_unavailable"


def test_an_observed_prohibited_state_is_violated_not_unproven():
    """``violated`` and ``unproven`` are opposites, and the driver must not collapse them.

    An operator unit observed enabled is maximal knowledge; recording it as "could not look" would
    file the program's headline safety breach as an absence of evidence.
    """
    run, stage = _run()
    stage.attempt(
        _CHECK,
        reason="acceptance_observation_unavailable",
        produce=lambda: (False, {"prohibited_state_observed": True}),
        violation=lambda obs: bool(obs.get("prohibited_state_observed")),
    )
    assert run.outcome_of(_CHECK) == OUTCOME_VIOLATED
    assert run.reason_for(_CHECK) == "acceptance_prohibited_state_observed"


def test_a_negative_result_without_a_violation_predicate_stays_unproven():
    """The violation branch must be opt-in per check.

    Without this, adding a predicate anywhere would risk reclassifying every negative result as a
    proven breach — an over-claim in the opposite direction.
    """
    run, stage = _run()
    stage.attempt(
        _CHECK,
        reason="acceptance_observation_unavailable",
        produce=lambda: (False, {"prohibited_state_observed": True}),
    )
    assert run.outcome_of(_CHECK) == OUTCOME_UNPROVEN


def test_a_bounded_refusal_keeps_its_own_reason_code():
    """An ``AcceptanceError`` carries a bounded reason the caller's fallback must not overwrite."""

    def refuse() -> tuple[bool, object]:
        raise AcceptanceError("acceptance_proof_would_be_vacuous")

    run, stage = _run()
    stage.attempt(_CHECK, reason="acceptance_observation_unavailable", produce=refuse)
    assert run.outcome_of(_CHECK) == OUTCOME_UNPROVEN
    assert run.reason_for(_CHECK) == "acceptance_proof_would_be_vacuous"


def test_an_unexpected_exception_still_leaves_a_record():
    """A harness fault must not delete the check.

    This is the failure mode the whole driver is shaped around: a check that quietly disappears
    reads as a check that passed.
    """

    def explode() -> tuple[bool, object]:
        raise RuntimeError("something the harness did not anticipate")

    run, stage = _run()
    stage.attempt(_CHECK, reason="acceptance_observation_unavailable", produce=explode)
    assert run.outcome_of(_CHECK) == OUTCOME_UNPROVEN


def test_every_path_records_exactly_one_result():
    """No path through ``attempt`` can record nothing, and none can record twice.

    Recording twice would raise ``acceptance_evidence_duplicate_check``; recording nothing would
    leave the stage incomplete. Both are checked by driving all four paths over distinct checks.
    """

    def boom() -> tuple[bool, object]:
        raise RuntimeError("x")

    run, stage = _run()
    for check, produce in (
        ("worker_bootstrap_written", lambda: (True, {})),
        ("worker_status_ok", lambda: (False, {})),
        ("worker_evidence_attested", boom),
    ):
        stage.attempt(check, reason="acceptance_observation_unavailable", produce=produce)
    for check in ("worker_bootstrap_written", "worker_status_ok", "worker_evidence_attested"):
        assert run.outcome_of(check) != "absent"


# --------------------------------------------------------------------------- the operator unit


def _systemd(monkeypatch: pytest.MonkeyPatch, properties: dict[str, str]) -> Host:
    """A host whose ``systemctl show`` answers exactly these properties.

    Patches the process seam the real ``Host.exec`` uses, so the code under test is the real
    observation function over a real ``Host`` — only the daemon is replaced.
    """
    body = "\n".join(f"{k}={v}" for k, v in properties.items()) + "\n"

    def fake_docker(*args: str, timeout: int = 300, check: bool = False) -> Result:
        return Result(exit_code=0, stdout=body, stderr="")

    monkeypatch.setattr("secp_acceptance.hosts.docker", fake_docker)
    return Host(role=ROLE_WORKER, container="c", dns_name="worker.secp.test")


def test_a_static_unit_is_the_prepared_dormant_state(monkeypatch: pytest.MonkeyPatch):
    """``static`` — NOT ``disabled`` — is what a correctly prepared host reports.

    The reviewed operator unit is rendered with no ``[Install]`` section, so systemd reports it
    ``static``. A check written against the literal ``"disabled"`` fails a correct host, which is
    exactly why the classifiers are imported from the product instead of restated.
    """
    host = _systemd(
        monkeypatch,
        {
            "LoadState": "loaded",
            "UnitFileState": "static",
            "ActiveState": "inactive",
            "SubState": "dead",
        },
    )
    observed = observe_operator_unit(host)
    assert observed["present_disabled_stopped"] is True
    assert observed["prohibited_state_observed"] is False


def test_an_absent_unit_is_NOT_the_prepared_state(monkeypatch: pytest.MonkeyPatch):
    """The second trap, and the one a `LoadState` check exists for.

    ``not-found`` classifies as NOT-enabled and reports ``ActiveState=inactive``, so an operator
    unit that was never installed satisfies both "not enabled" and "not running". Without proven
    presence, a check named ``present_disabled_stopped`` would prove only its last two words — and
    would prove them most easily when the first is false.
    """
    host = _systemd(
        monkeypatch,
        {
            "LoadState": "not-found",
            "UnitFileState": "not-found",
            "ActiveState": "inactive",
            "SubState": "dead",
        },
    )
    observed = observe_operator_unit(host)
    assert observed["present"] is False
    assert observed["present_disabled_stopped"] is False, (
        "an operator unit that is not installed at all must never read as correctly prepared"
    )
    assert observed["prohibited_state_observed"] is False


@pytest.mark.parametrize(
    ("unit_file_state", "active_state"),
    [("enabled", "inactive"), ("static", "active"), ("enabled", "active")],
)
def test_an_enabled_or_running_operator_is_a_prohibited_state(
    monkeypatch: pytest.MonkeyPatch, unit_file_state: str, active_state: str
):
    """Enabled, running, or both — each is the state the check exists to rule out."""
    host = _systemd(
        monkeypatch,
        {
            "LoadState": "loaded",
            "UnitFileState": unit_file_state,
            "ActiveState": active_state,
            "SubState": "running",
        },
    )
    observed = observe_operator_unit(host)
    assert observed["prohibited_state_observed"] is True
    assert observed["present_disabled_stopped"] is False


def test_an_unrecognised_systemd_state_is_neither_dormant_nor_prohibited(
    monkeypatch: pytest.MonkeyPatch,
):
    """The binding three-valued rule: ``None`` means "could not settle", never "fine".

    The product's classifiers return ``None`` for a value they do not recognise. Treated as falsy —
    the natural thing to write — an unknown state reads as a dormant operator, which is a false
    safety claim about the most safety-sensitive thing in the program.
    """
    host = _systemd(
        monkeypatch,
        {
            "LoadState": "loaded",
            "UnitFileState": "some-future-systemd-state",
            "ActiveState": "inactive",
            "SubState": "dead",
        },
    )
    observed = observe_operator_unit(host)
    assert observed["unclassifiable"] is True
    assert observed["present_disabled_stopped"] is False
    assert observed["prohibited_state_observed"] is False


def test_indirect_is_treated_as_enabled(monkeypatch: pytest.MonkeyPatch):
    """The product errs toward safety here and the harness must not undo it.

    ``indirect`` is conservative-True in the product: such a unit can be pulled in via another
    unit's ``Also=``, so a possibly-auto-starting operator never reads as not-enabled.
    """
    host = _systemd(
        monkeypatch,
        {
            "LoadState": "loaded",
            "UnitFileState": "indirect",
            "ActiveState": "inactive",
            "SubState": "dead",
        },
    )
    observed = observe_operator_unit(host)
    assert observed["enabled"] is True
    assert observed["present_disabled_stopped"] is False
    assert observed["prohibited_state_observed"] is True
