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
from secp_acceptance.install import host_untouched, probe_paths, read_operator_unit_properties
from secp_acceptance.queues import (
    OPERATOR_UNIT_PROPERTIES,
    encode_verdict,
    resolve_operator_unit_dormant,
)
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
#
# Dormancy itself is resolved by ``queues.resolve_operator_unit_dormant``, which the queues stage
# owns and this stage reuses; C tests the resolver. What is tested HERE is the INTEGRATION — that
# the reader this stage actually calls produces the shape that resolver requires, and that the two
# traps survive end to end through the seam worker_install really uses. A reader that dropped a
# property, or truncated one, would make every dormancy verdict `unprovable` while both sides
# looked correct in isolation.


def _systemd(monkeypatch: pytest.MonkeyPatch, properties: dict[str, str]) -> Host:
    """A host whose ``systemctl show`` answers exactly these properties.

    Patches the process seam the real ``Host.exec`` uses, so the code under test is the real reader
    over a real ``Host`` — only the daemon is replaced.
    """
    body = "\n".join(f"{k}={v}" for k, v in properties.items()) + "\n"

    def fake_docker(*args: str, timeout: int = 300, check: bool = False) -> Result:
        return Result(exit_code=0, stdout=body, stderr="")

    monkeypatch.setattr("secp_acceptance.hosts.docker", fake_docker)
    return Host(role=ROLE_WORKER, container="c", dns_name="worker.secp.test")


def _prepared() -> dict[str, str]:
    """What a correctly prepared host reports: static, loaded, never started."""
    return {
        "LoadState": "loaded",
        "ActiveState": "inactive",
        "UnitFileState": "static",
        "InvocationID": "",
        "StateChangeTimestampMonotonic": "123456",
        "NRestarts": "0",
    }


def test_the_reader_supplies_every_property_the_resolver_requires(monkeypatch: pytest.MonkeyPatch):
    """The contract between this stage's reader and the shared resolver.

    The property list is taken from ``queues.OPERATOR_UNIT_PROPERTIES`` rather than restated, so a
    property the resolver starts requiring cannot go unread. This asserts that actually holds.
    """
    host = _systemd(monkeypatch, _prepared())
    reading = read_operator_unit_properties(host)
    assert set(reading) == set(OPERATOR_UNIT_PROPERTIES)
    assert all(isinstance(v, str) for v in reading.values())


def test_a_static_never_started_unit_resolves_as_dormant(monkeypatch: pytest.MonkeyPatch):
    """``static`` — NOT ``disabled`` — is what a correctly prepared host reports.

    The reviewed operator unit is rendered with no ``[Install]`` section, so systemd reports it
    ``static``. A check written against the literal ``"disabled"`` would fail a correct host, which
    is why the classifiers live in the product and the resolver is shared.
    """
    host = _systemd(monkeypatch, _prepared())
    reading = read_operator_unit_properties(host)
    verdict = resolve_operator_unit_dormant(reading, reading)
    assert encode_verdict(verdict)[0] == OUTCOME_OBSERVED


def test_an_absent_unit_does_NOT_resolve_as_dormant(monkeypatch: pytest.MonkeyPatch):
    """The second trap, reached from the opposite direction to the ``static`` one.

    ``not-found`` classifies as NOT-enabled and reports ``ActiveState=inactive``, so an operator
    unit that was never installed satisfies both "not enabled" and "not running". A check named
    ``present_disabled_stopped`` would then prove only its last two words — and would prove them
    most easily when the first is false.
    """
    absent = _prepared() | {"LoadState": "not-found", "UnitFileState": "not-found"}
    host = _systemd(monkeypatch, absent)
    reading = read_operator_unit_properties(host)
    verdict = resolve_operator_unit_dormant(reading, reading)
    assert encode_verdict(verdict)[0] != OUTCOME_OBSERVED, (
        "an operator unit that is not installed at all must never read as correctly prepared"
    )


@pytest.mark.parametrize(
    "prohibited",
    [
        {"UnitFileState": "enabled"},
        {"ActiveState": "active"},
        {"InvocationID": "9f3a2b1c"},
        {"NRestarts": "2"},
    ],
)
def test_an_activated_operator_unit_is_a_violation_not_an_absence(
    monkeypatch: pytest.MonkeyPatch, prohibited: dict[str, str]
):
    """Enabled, running, or evidence of having ever run — each is a positive finding.

    ``InvocationID`` is the sharpest of them: systemd leaves it EMPTY until the first start, so a
    non-empty value is a positive statement that the unit HAS run, not a missing observation.
    """
    host = _systemd(monkeypatch, _prepared() | prohibited)
    reading = read_operator_unit_properties(host)
    verdict = resolve_operator_unit_dormant(reading, reading)
    outcome, _ = encode_verdict(verdict)
    assert outcome == OUTCOME_VIOLATED


def test_a_unit_that_moved_between_readings_is_not_dormant(monkeypatch: pytest.MonkeyPatch):
    """Why this stage takes TWO readings rather than one.

    A single snapshot is satisfied by a unit started and stopped again inside the window. The
    generation stamp changing between the two readings is what refuses that, and it is the reason
    worker_install reads once after the bootstrap commits and again at the end of the stage rather
    than passing one reading twice.
    """
    before = _prepared()
    after = _prepared() | {"StateChangeTimestampMonotonic": "999999"}
    verdict = resolve_operator_unit_dormant(before, after)
    assert encode_verdict(verdict)[0] != OUTCOME_OBSERVED


def test_an_unrecognised_systemd_state_is_not_dormant(monkeypatch: pytest.MonkeyPatch):
    """The binding three-valued rule: ``None`` means "could not settle", never "fine"."""
    host = _systemd(monkeypatch, _prepared() | {"UnitFileState": "some-future-systemd-state"})
    reading = read_operator_unit_properties(host)
    verdict = resolve_operator_unit_dormant(reading, reading)
    assert encode_verdict(verdict)[0] != OUTCOME_OBSERVED


# --------------------------------------------------------------------------- the path probe
#
# `host_untouched`'s consumer treats "every path absent" as the PASS condition for
# `worker_bootstrap_plan_is_dry_run`. So a probe that reports absence when it could not look turns
# an outage into a pass -- HostFleet.destroy's original defect in a different function. These pin
# the discrimination in both directions.


def _probe_host(monkeypatch: pytest.MonkeyPatch, result: Result) -> Host:
    def fake_docker(*args: str, timeout: int = 300, check: bool = False) -> Result:
        return result

    monkeypatch.setattr("secp_acceptance.hosts.docker", fake_docker)
    return Host(role=ROLE_WORKER, container="c", dns_name="worker.secp.test")


_PATHS = ("/etc/secp/worker/compose.yml", "/etc/systemd/system/secp-operator-worker.service")


def _lines(*entries: tuple[str, str], sentinel: bool = False) -> str:
    """Build probe stdout exactly as the host would print it."""
    out = [f"{verdict} {path}" for verdict, path in entries]
    if sentinel:
        out.append("__secp_probe_complete__")
    return "\n".join(out) + "\n"


def test_the_probe_reports_absence_the_host_actually_stated(monkeypatch: pytest.MonkeyPatch):
    body = _lines(("ABSENT", _PATHS[0]), ("ABSENT", _PATHS[1]), sentinel=True)
    host = _probe_host(monkeypatch, Result(exit_code=0, stdout=body, stderr=""))
    assert probe_paths(host, _PATHS) == {_PATHS[0]: False, _PATHS[1]: False}
    untouched = host_untouched(host, _PATHS)
    assert untouched["absent"] == untouched["probed"]


def test_the_probe_distinguishes_present_from_absent(monkeypatch: pytest.MonkeyPatch):
    """The control. A probe answering the same for everything would make both directions
    unfalsifiable, whichever way it leaned."""
    body = _lines(("PRESENT", _PATHS[0]), ("ABSENT", _PATHS[1]), sentinel=True)
    host = _probe_host(monkeypatch, Result(exit_code=0, stdout=body, stderr=""))
    assert probe_paths(host, _PATHS) == {_PATHS[0]: True, _PATHS[1]: False}


def test_an_unreachable_host_REFUSES_rather_than_reporting_everything_absent(
    monkeypatch: pytest.MonkeyPatch,
):
    """THE defect this probe exists to prevent.

    With ``test -e`` in a loop, an unreachable host failed every probe and reported every path
    absent -- which is the dry-run check's PASS condition. Here it refuses.
    """
    host = _probe_host(monkeypatch, Result(exit_code=1, stdout="", stderr="cannot connect"))
    with pytest.raises(AcceptanceError) as caught:
        probe_paths(host, _PATHS)
    assert caught.value.reason_code == "acceptance_observation_unavailable"


def test_a_PARTIAL_probe_failure_also_refuses(monkeypatch: pytest.MonkeyPatch):
    """The case a top-level reachability check alone would miss.

    The host answered and the program ran, but it did not speak about every path -- an
    untraversable parent, say. An incomplete answer is not absence.
    """
    body = _lines(("ABSENT", _PATHS[0]), sentinel=True)
    host = _probe_host(monkeypatch, Result(exit_code=0, stdout=body, stderr=""))
    with pytest.raises(AcceptanceError) as caught:
        probe_paths(host, _PATHS)
    assert caught.value.reason_code == "acceptance_observation_unavailable"


def test_output_without_the_completion_sentinel_refuses(monkeypatch: pytest.MonkeyPatch):
    """The sentinel proves the program ran to COMPLETION -- a fact no exit status supplies for a
    program killed midway."""
    body = _lines(("ABSENT", _PATHS[0]), ("ABSENT", _PATHS[1]))
    host = _probe_host(monkeypatch, Result(exit_code=0, stdout=body, stderr=""))
    with pytest.raises(AcceptanceError) as caught:
        probe_paths(host, _PATHS)
    assert caught.value.reason_code == "acceptance_observation_unavailable"
