"""A stage represented only by literals is detectable. Nothing else in the document detects it.

THE PREMISE THESE TESTS ESTABLISH FIRST
---------------------------------------
:func:`test_a_literal_only_run_produces_a_perfect_passing_document` is the reason this whole
mechanism exists, and it is deliberately the first test in the file: a stage that invents every
observation produces a document that is complete, entirely ``observed``, ``passed``, and accepted by
every rule in the loader. Nothing is wrong with it. It is a correct record of a claim that was never
measured.

Everything below only means something because that test passes.
"""

from __future__ import annotations

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.evidence import (
    FleetRecord,
    ReleaseRecord,
    canonical_bytes,
    evidence_from_bytes,
    evidence_from_dict,
)
from secp_acceptance.provenance import (
    PROVENANCE_OBSERVED,
    PROVENANCE_REFUSED,
    PROVENANCE_UNPROVEN,
    assert_stages_derived_from_execution,
    stage_provenance,
)
from secp_acceptance.reasons import CHECKS_BY_STAGE, RUN_PASSED, STAGE_FLEET, STAGES
from secp_acceptance.recorder import AcceptanceRecorder
from secp_acceptance.shell import Result, reset_seam, run, seam_position

_FLEET = FleetRecord(
    host_image_identity="sha256:" + "1" * 64,
    controller_host_identity="sha256:" + "2" * 64,
    worker_host_identity="sha256:" + "3" * 64,
    network_identity="sha256:" + "4" * 64,
    hosts_created=2,
    hosts_destroyed=2,
    nested_container_runtime=True,
    real_service_manager=True,
)
_RELEASE = ReleaseRecord(
    role="worker",
    baseline_aggregate="sha256:" + "5" * 64,
    baseline_source_sha="a" * 40,
    signing_anchor_id="sha256:" + "7" * 64,
    test_only_anchor=True,
)


@pytest.fixture(autouse=True)
def _clean_seam():
    """The seam counter is process-global by design. Isolate each test."""
    reset_seam()
    yield
    reset_seam()


def _literal_only_run() -> AcceptanceRecorder:
    """Nine stages, every check invented. No host is touched."""
    rec = AcceptanceRecorder()
    for stage in sorted(STAGES):
        rec.open_stage(stage)
        for check in CHECKS_BY_STAGE[stage]:
            rec.observe(check, stage, {"check": check})
    return rec


class _FakeCommand:
    """A stand-in for a real host command, so a stage can 'execute' hermetically.

    Patched over ``subprocess.run`` INSIDE the seam rather than over the seam itself: the point is
    to advance the real counter through the real code path. Patching ``shell.run`` would bypass the
    very thing under test.
    """

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1

        class _Completed:
            returncode = 0
            stdout = b"ok\n"
            stderr = b""

        return _Completed()


# --------------------------------------------------------------------------- the premise


def test_a_literal_only_run_produces_a_perfect_passing_document():
    """THE reason this mechanism exists. Read this before anything else in the file.

    Every check invented, nothing observed, nothing executed — and the document is complete,
    entirely ``observed``, ``passed``, and survives the loader in full. No validation rule can catch
    it, because there is nothing malformed about it.
    """
    sealed = _literal_only_run().seal(fleet=_FLEET, release=_RELEASE)

    assert sealed.outcome == RUN_PASSED
    assert sealed.coverage_complete()
    assert sealed.not_passing() == ()
    assert set(sealed.stages_attempted) == STAGES
    # ...and it round-trips through the loader untouched
    assert evidence_from_bytes(canonical_bytes(sealed)).digest() == sealed.digest()


def test_the_provenance_field_is_the_only_thing_that_exposes_it():
    """Same document, and every stage reports zero execution."""
    sealed = _literal_only_run().seal(fleet=_FLEET, release=_RELEASE)
    assert {record.seam_calls for record in sealed.provenance} == {0}

    verdict = stage_provenance(sealed)
    assert verdict.outcome == PROVENANCE_REFUSED
    assert verdict.passed is False
    assert verdict.reason_code == "acceptance_stage_not_derived_from_execution"
    assert set(verdict.literal_only_stages) == STAGES


def test_the_gate_clause_refuses_a_literal_only_run():
    with pytest.raises(AcceptanceError) as exc:
        assert_stages_derived_from_execution(
            _literal_only_run().seal(fleet=_FLEET, release=_RELEASE)
        )
    assert exc.value.reason_code == "acceptance_stage_not_derived_from_execution"


# --------------------------------------------------------------------------- the counter itself


def test_the_seam_counts_every_command_and_nothing_else(monkeypatch):
    """The counter advances once per command through :func:`run`, and only there."""
    fake = _FakeCommand()
    monkeypatch.setattr("secp_acceptance.shell.subprocess.run", fake)

    assert seam_position()[0] == 0
    run(("docker", "version"))
    run(("docker", "info", "--format", "{{.ID}}"))
    assert seam_position()[0] == 2
    assert fake.calls == 2


def test_a_FAILED_command_still_counts(monkeypatch):
    """The question is whether the stage reached a host, not whether the command worked.

    A stage whose every command failed still executed; its checks will say so as ``unproven`` or
    ``violated``. Not counting failures would make a stage that tried and failed indistinguishable
    from one that invented its results — which is the exact confusion this exists to remove.
    """

    def _failing(*args, **kwargs):
        class _Completed:
            returncode = 1
            stdout = b""
            stderr = b"boom\n"

        return _Completed()

    monkeypatch.setattr("secp_acceptance.shell.subprocess.run", _failing)
    run(("docker", "version"))
    assert seam_position()[0] == 1


def test_the_chain_carries_no_argument_material(monkeypatch):
    """The chain covers argv[0] and the ARITY only.

    The harness composes argv from real host output, so the arguments routinely carry container
    names, absolute paths and origins. Chaining over them would put exactly that material into a
    digest the evidence document publishes.
    """
    monkeypatch.setattr("secp_acceptance.shell.subprocess.run", _FakeCommand())

    run(("docker", "exec", "secp-acc-abcdef-worker", "systemctl", "is-system-running"))
    first = seam_position()[1]

    reset_seam()
    run(("docker", "exec", "secp-acc-999999-controller", "systemctl", "is-system-running"))
    second = seam_position()[1]

    assert first == second, "the chain differs between runs, so it is carrying the arguments"


def test_the_chain_does_move_on_a_different_command_shape(monkeypatch):
    """CONTROL for the test above. A chain insensitive to everything would satisfy it trivially."""
    monkeypatch.setattr("secp_acceptance.shell.subprocess.run", _FakeCommand())

    run(("docker", "version"))
    short = seam_position()[1]
    reset_seam()
    run(("docker", "info", "--format", "{{.ID}}"))
    assert seam_position()[1] != short


# --------------------------------------------------------------------------- a real stage passes


def test_a_stage_that_ACTUALLY_EXECUTED_is_accepted(monkeypatch):
    """The control that stops the clause from being satisfied by refusing everything."""
    monkeypatch.setattr("secp_acceptance.shell.subprocess.run", _FakeCommand())

    rec = AcceptanceRecorder()
    for stage in sorted(STAGES):
        rec.open_stage(stage)
        for check in CHECKS_BY_STAGE[stage]:
            run(("docker", "inspect", "thing"))  # the stage does real work through the seam
            rec.observe(check, stage, {"check": check})
    sealed = rec.seal(fleet=_FLEET, release=_RELEASE)

    assert all(record.seam_calls > 0 for record in sealed.provenance)
    verdict = stage_provenance(sealed)
    assert verdict.outcome == PROVENANCE_OBSERVED
    assert verdict.passed is True
    assert_stages_derived_from_execution(sealed)  # does not raise


def test_ONE_literal_stage_among_real_ones_is_caught(monkeypatch):
    """The realistic case: eight stages did real work and the ninth was stubbed out."""
    monkeypatch.setattr("secp_acceptance.shell.subprocess.run", _FakeCommand())

    rec = AcceptanceRecorder()
    for stage in sorted(STAGES):
        rec.open_stage(stage)
        for check in CHECKS_BY_STAGE[stage]:
            if stage != STAGE_FLEET:
                run(("docker", "inspect", "thing"))
            rec.observe(check, stage, {"check": check})
    sealed = rec.seal(fleet=_FLEET, release=_RELEASE)

    assert sealed.outcome == RUN_PASSED  # the document itself is perfectly happy
    verdict = stage_provenance(sealed)
    assert verdict.literal_only_stages == (STAGE_FLEET,)
    assert verdict.passed is False


# --------------------------------------------------------------------------- three-valued


def test_a_document_with_NO_provenance_is_unproven_not_refused():
    """Absent provenance and a stage proven to have done nothing are different facts.

    Collapsing them would repeat, inside the gate, the exact mistake this contract has now corrected
    four times elsewhere. ``unproven`` is still never a pass.
    """
    payload = _literal_only_run().seal(fleet=_FLEET, release=_RELEASE).canonical()
    payload["provenance"] = []
    stripped = evidence_from_dict(payload)

    verdict = stage_provenance(stripped)
    assert verdict.outcome == PROVENANCE_UNPROVEN
    assert verdict.reason_code == "acceptance_stage_provenance_absent"
    assert verdict.passed is False

    with pytest.raises(AcceptanceError) as exc:
        assert_stages_derived_from_execution(stripped)
    assert exc.value.reason_code == "acceptance_stage_provenance_absent"


def test_partial_provenance_is_refused_by_the_loader():
    """Eight entries for nine attempted stages would make a reader notice an ABSENCE to avoid
    reading the ninth as executed. Refused rather than left to the reader."""
    payload = _literal_only_run().seal(fleet=_FLEET, release=_RELEASE).canonical()
    payload["provenance"] = payload["provenance"][:-1]
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_incomplete"


def test_provenance_for_a_stage_that_was_never_attempted_is_refused():
    payload = _literal_only_run().seal(fleet=_FLEET, release=_RELEASE).canonical()
    payload["stages_attempted"] = [s for s in payload["stages_attempted"] if s != STAGE_FLEET]
    payload["checks"] = [c for c in payload["checks"] if c["stage"] != STAGE_FLEET]
    payload["outcome"] = "failed"
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_unknown_stage"


def test_the_chain_digest_must_be_a_digest():
    """The provenance field must not become another place a raw value reaches public evidence."""
    payload = _literal_only_run().seal(fleet=_FLEET, release=_RELEASE).canonical()
    payload["provenance"][0]["chain_digest"] = "/var/lib/secp/seam.log"
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_public_value_not_permitted"


def test_the_seam_result_is_still_returned_faithfully(monkeypatch):
    """Counting must not have changed what :func:`run` returns."""
    monkeypatch.setattr("secp_acceptance.shell.subprocess.run", _FakeCommand())
    result = run(("docker", "version"))
    assert isinstance(result, Result)
    assert result.ok is True
    assert result.stdout == "ok\n"
