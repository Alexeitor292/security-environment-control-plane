"""The specific tell survives into the document, without widening the reason vocabulary.

WHY THIS FIELD EXISTS
---------------------
``reason_code`` is deliberately coarse: ONE code — ``acceptance_prohibited_state_observed`` — covers
every "the harness saw the ruled-out state" case across all nine stages, because a code per check
would grow past review and the check id already names the property.

But within a check the tell varies. ``operator_unit_never_activated`` fires on an enabled unit, a
running unit, a populated ``InvocationID``, or a non-zero restart count — four findings with four
different remediations. Only the observation's DIGEST reaches the document, so without this field
the distinction is unrecoverable by a reader, for exactly the outcome where it matters most.

Raised by acc-C-queues, which had already adopted it inside the observation payload. This is the
document-level half: a bounded identifier, never free text, so it cannot become the back door
through which a path, a container id, a queue name or an origin reaches public evidence.
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
from secp_acceptance.reasons import CHECKS_BY_STAGE, RUN_PASSED, STAGE_QUEUES, STAGES
from secp_acceptance.recorder import AcceptanceRecorder

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

_VIOLATED_CHECK = "operator_unit_never_activated"


def _nine_stages(skip: str | None = None) -> AcceptanceRecorder:
    rec = AcceptanceRecorder()
    for stage in sorted(STAGES):
        rec.open_stage(stage)
        for check in CHECKS_BY_STAGE[stage]:
            if check != skip:
                rec.observe(check, stage, {"check": check})
    return rec


def _violated_with(cause: str | None):
    rec = _nine_stages(skip=_VIOLATED_CHECK)
    rec.violated(
        _VIOLATED_CHECK,
        STAGE_QUEUES,
        reason_code="acceptance_prohibited_state_observed",
        observation={"unit": "active"},
        observed_cause=cause,
    )
    return rec.seal(fleet=_FLEET, release=_RELEASE)


# --------------------------------------------------------------------------- it reaches the reader


def test_the_cause_survives_a_round_trip_through_canonical_bytes():
    """THE point of the field. A reader of the written document can tell which tell fired."""
    sealed = _violated_with("operator_unit_restart_count_nonzero")
    reloaded = evidence_from_bytes(canonical_bytes(sealed))
    record = reloaded.check_for(_VIOLATED_CHECK)
    assert record is not None
    assert record.observed_cause == "operator_unit_restart_count_nonzero"
    assert record.reason_code == "acceptance_prohibited_state_observed"


def test_two_violations_of_the_SAME_check_are_distinguishable():
    """Without this field both carry the identical coarse reason code and only a digest, so a reader
    triaging the document could not tell an enabled unit from a restarted one."""
    enabled = _violated_with("operator_unit_enabled")
    restarted = _violated_with("operator_unit_restart_count_nonzero")

    assert enabled.check_for(_VIOLATED_CHECK).reason_code == (
        restarted.check_for(_VIOLATED_CHECK).reason_code
    )
    assert enabled.check_for(_VIOLATED_CHECK).observed_cause != (
        restarted.check_for(_VIOLATED_CHECK).observed_cause
    )
    # and the documents are distinguishable by content address too
    assert enabled.digest() != restarted.digest()


def test_the_cause_is_optional():
    """A producer that cannot vary its tell must not be forced to invent one."""
    sealed = _violated_with(None)
    assert sealed.check_for(_VIOLATED_CHECK).observed_cause is None


# --------------------------------------------------------------------------- it stays bounded


@pytest.mark.parametrize(
    "leaky",
    [
        "/var/lib/secp/operator.service",
        "secp-controlled-live-v1",
        "https://controller.internal/health",
        "Operator Unit Was Enabled",
        "unit@host",
        "a" * 65,
    ],
    ids=["path", "queue-name", "origin", "prose", "address", "too-long"],
)
def test_a_cause_that_is_not_a_bounded_identifier_is_refused(leaky: str):
    """The field must never become the back door for the values the whole document forbids.

    The queue name is here deliberately: it is the single most likely thing a queues-stage producer
    would reach for when naming which queue was polled, and it is precisely what the public-evidence
    rule exists to keep out.
    """
    payload = _violated_with("operator_unit_enabled").canonical()
    for record in payload["checks"]:
        if record["check"] == _VIOLATED_CHECK:
            record["observed_cause"] = leaky

    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_invalid"


def test_the_leaky_cause_probe_is_not_vacuous():
    """CONTROL. If the mutation never reached the record — wrong check id, wrong key — every case
    above would 'refuse' for the baseline's own reasons and prove nothing."""
    payload = _violated_with("operator_unit_enabled").canonical()
    targeted = [r for r in payload["checks"] if r["check"] == _VIOLATED_CHECK]
    assert len(targeted) == 1, "the mutation target is not uniquely identifiable"
    assert targeted[0]["observed_cause"] == "operator_unit_enabled"
    # and the UNmutated document loads cleanly, so a refusal above is attributable to the mutation
    assert evidence_from_dict(payload).check_for(_VIOLATED_CHECK) is not None


def test_a_passing_check_may_not_carry_a_cause():
    """A positive observation has no cause of a bad thing to name.

    Forbidden for the same reason ``reason_code`` is: permitting it would let a producer file a
    finding somewhere the verdict never looks — the ``gaps`` failure mode in a different field.
    """
    payload = _nine_stages().seal(fleet=_FLEET, release=_RELEASE).canonical()
    assert payload["outcome"] == RUN_PASSED
    payload["checks"][0]["observed_cause"] = "something_went_wrong"
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_invalid"


def test_the_cause_passes_the_forbidden_secret_scan():
    """The document must still survive its own loader with the new field populated."""
    from secp_commissioning.descriptor import scan_forbidden

    scan_forbidden(_violated_with("operator_unit_enabled").canonical())
