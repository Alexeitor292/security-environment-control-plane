"""The ONE run: one recorder, one fleet, one sealed document, written on every path.

The properties a stage author and a reader of the evidence are entitled to rely on:

* the run is a single object — a stage cannot reach past it and open a second recorder;
* the verdict is DERIVED, and a run that never established a fleet cannot seal at all;
* the document is written on the FAILURE paths too, which is when it is worth the most;
* a parallelised session REFUSES rather than sealing one partial document per worker.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.evidence import FleetRecord, ReleaseRecord, evidence_from_bytes
from secp_acceptance.reasons import (
    CHECKS_BY_STAGE,
    RUN_FAILED,
    RUN_PASSED,
    STAGE_FLEET,
    STAGE_QUEUES,
    STAGES,
)
from secp_acceptance.run import EVIDENCE_FILENAME, AcceptanceRun, assert_single_process

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


def _cover(run: AcceptanceRun, stage: str) -> None:
    run.open_stage(stage)
    for check in CHECKS_BY_STAGE[stage]:
        run.observe(check, stage, {"check": check})


# --------------------------------------------------------------------------- single process


def test_a_parallelised_session_refuses_to_build_a_run(monkeypatch):
    """THE structural one. xdist would give every worker its own recorder, so each would seal a
    PARTIAL document and every one of them would look like a complete run."""
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw3")
    with pytest.raises(AcceptanceError) as exc:
        AcceptanceRun()
    assert exc.value.reason_code == "acceptance_run_not_single_process"


def test_the_single_process_check_is_keyed_on_the_variable_xdist_actually_sets(monkeypatch):
    """CONTROL, in both directions. An unset variable must permit the run, and an EMPTY one must
    too — xdist sets a worker id, and treating the mere presence of an empty string as parallel
    would refuse every ordinary session."""
    monkeypatch.delenv("PYTEST_XDIST_WORKER", raising=False)
    assert_single_process()  # does not raise
    monkeypatch.setenv("PYTEST_XDIST_WORKER", "")
    assert_single_process()  # does not raise


# --------------------------------------------------------------------------- sealing


def test_a_run_that_never_recorded_a_fleet_cannot_seal():
    """Every stage's claims are claims ABOUT a fleet. A document whose fleet record was invented
    would misdescribe the premise every other field depends on."""
    run = AcceptanceRun()
    _cover(run, STAGE_QUEUES)
    with pytest.raises(AcceptanceError) as exc:
        run.seal()
    assert exc.value.reason_code == "acceptance_run_fleet_not_recorded"


def test_a_second_DIFFERENT_fleet_in_one_session_is_refused():
    """Two fleets, one document. The evidence carries exactly one ``FleetRecord``, so a session that
    built two would describe one machine pair while carrying claims gathered against both — and
    nothing in the document would say which check belonged to which.

    This is the failure mode a MODULE-scoped fleet fixture produces as soon as a second stage module
    exists, which is why the fleet fixture must be session-scoped.
    """
    run = AcceptanceRun()
    run.set_fleet(_FLEET)
    second = _FLEET.model_copy(update={"controller_host_identity": "sha256:" + "9" * 64})
    with pytest.raises(AcceptanceError) as exc:
        run.set_fleet(second)
    assert exc.value.reason_code == "acceptance_run_fleet_conflict"


def test_recording_the_SAME_fleet_twice_is_allowed():
    """The control. A session-scoped fixture may legitimately hand over the same record more than
    once, and refusing that would push streams toward not recording it at all."""
    run = AcceptanceRun()
    run.set_fleet(_FLEET)
    run.set_fleet(_FLEET)  # does not raise
    _cover(run, STAGE_FLEET)
    assert run.seal().fleet == _FLEET


def test_a_fully_covered_run_seals_passed():
    run = AcceptanceRun()
    run.set_fleet(_FLEET)
    run.set_release(_RELEASE)
    for stage in sorted(STAGES):
        _cover(run, stage)
    document = run.seal()
    assert document.outcome == RUN_PASSED
    assert document.coverage_complete()
    assert len(document.stages_attempted) == 9


def test_sealing_is_idempotent_within_a_session():
    """``pytest_sessionfinish`` writes, and a stage may also have asked for the document. Two seals
    must not produce two different ``completed_at`` values and therefore two different documents."""
    run = AcceptanceRun()
    run.set_fleet(_FLEET)
    _cover(run, STAGE_FLEET)
    first = run.seal()
    assert run.seal() is first
    assert run.sealed is first


def test_a_run_missing_a_release_says_so_rather_than_inventing_a_lineage():
    """No stream has produced a release lineage yet, and a run without one must not carry a
    plausible-looking stand-in. Every field is a digest of the STATEMENT that none was established,
    and the run cannot pass anyway because the release-bearing stages are uncovered."""
    run = AcceptanceRun()
    run.set_fleet(_FLEET)
    _cover(run, STAGE_FLEET)
    document = run.seal()
    # NOTE: the outcome is deliberately NOT asserted here. A one-stage run always seals `failed`
    # because of the nine-stage rule, so `outcome == RUN_FAILED` would be true regardless of the
    # release record and would prove nothing about this test's actual subject.
    assert document.stages_attempted == (STAGE_FLEET,)
    # honest about the anchor: none was used, so the "test only" assertion is TRUE, not False
    assert document.release.test_only_anchor is True
    assert document.release.baseline_aggregate.startswith("sha256:")
    assert document.release.baseline_aggregate == document.release.signing_anchor_id


# --------------------------------------------------------------------------- writing


def test_the_written_document_survives_the_loader(tmp_path: pathlib.Path):
    """What is written must be exactly what a reader will re-derive. A run that emitted a document
    its own loader refuses would make every guarantee in the loader decorative."""
    run = AcceptanceRun()
    run.set_fleet(_FLEET)
    run.set_release(_RELEASE)
    for stage in sorted(STAGES):
        _cover(run, stage)
    path = run.write(tmp_path)

    assert path.name == EVIDENCE_FILENAME
    reloaded = evidence_from_bytes(path.read_bytes())
    assert reloaded.digest() == run.seal().digest()
    assert reloaded.outcome == RUN_PASSED


def test_a_FAILED_run_is_written_too(tmp_path: pathlib.Path):
    """The point of writing on every path. A failed run's evidence is the record of what was and
    was not established, and writing it only on success would mean it exists exactly when nobody
    needs to consult it."""
    run = AcceptanceRun()
    run.set_fleet(_FLEET)
    run.set_release(_RELEASE)
    # All nine stages, one violated — so `failed` is caused by the VIOLATION rather than by the
    # stage count, and this test would go red if `violated` ever stopped failing a run.
    for stage in sorted(STAGES):
        run.open_stage(stage)
        for check in CHECKS_BY_STAGE[stage]:
            if check != "operator_queue_has_zero_pollers":
                run.observe(check, stage, {"check": check})
    run.violated(
        "operator_queue_has_zero_pollers",
        STAGE_QUEUES,
        reason_code="acceptance_prohibited_state_observed",
        observation={"pollers": 1},
    )
    path = run.write(tmp_path)

    reloaded = evidence_from_bytes(path.read_bytes())
    assert reloaded.outcome == RUN_FAILED
    assert reloaded.violated() == ("operator_queue_has_zero_pollers",)
    assert reloaded.not_passing() == ("operator_queue_has_zero_pollers",)


def test_the_written_bytes_are_canonical_json(tmp_path: pathlib.Path):
    run = AcceptanceRun()
    run.set_fleet(_FLEET)
    _cover(run, STAGE_FLEET)
    raw = run.write(tmp_path).read_bytes()

    assert raw == raw.decode("utf-8").encode("utf-8")  # pure UTF-8
    parsed = json.loads(raw)
    assert list(parsed) == sorted(parsed), "canonical JSON must be key-sorted"
    assert b", " not in raw and b": " not in raw, "canonical JSON uses compact separators"


# --------------------------------------------------------------------------- delegation


def test_the_run_exposes_every_recording_verb_a_stage_needs():
    """The four-line stage contract is only satisfiable if the run actually carries these verbs.

    Checked against the RECORDER's public verbs rather than a restated list, so a verb added there
    and not surfaced here fails instead of silently forcing a stream to reach past the run.
    """
    from secp_acceptance.recorder import AcceptanceRecorder

    verbs = {
        name
        for name in vars(AcceptanceRecorder)
        if not name.startswith("_") and callable(getattr(AcceptanceRecorder, name))
    }
    # `seal` is deliberately not delegated: the run seals itself, with its own fleet and release.
    for verb in verbs - {"seal", "missing"}:
        assert hasattr(AcceptanceRun, verb), (
            f"AcceptanceRecorder.{verb} is not reachable through AcceptanceRun, so a stage would "
            f"have to reach past the run to use it"
        )


def test_a_stage_cannot_record_into_a_stage_it_never_opened():
    """Delegation must not have loosened the recorder's own discipline."""
    run = AcceptanceRun()
    with pytest.raises(AcceptanceError) as exc:
        run.observe("hosts_are_distinct", STAGE_FLEET, {})
    assert exc.value.reason_code == "acceptance_evidence_unknown_stage"
