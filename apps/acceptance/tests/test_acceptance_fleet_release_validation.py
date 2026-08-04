"""The fleet and release records are validated. They were not.

THE DEFECT THIS FILE CLOSES
---------------------------
``_assert_evidence_semantics`` re-asserted the four prohibitions, every closed vocabulary, and the
whole of ``checks`` — and never inspected ``ev.fleet`` or ``ev.release`` at all. Those two nested
records were reachable only through pydantic's ``_Str`` (any string, 1..200 characters).

Measured on the unmodified parent tree: **eleven single-field mutations were accepted on a document
still reporting ``passed``.** The two that matter most:

* ``release.test_only_anchor: False`` — a document asserting it used a PRODUCTION trust anchor,
  reading ``passed``. That is the boundary this whole program is built around.
* ``fleet.hosts_destroyed: 0`` against ``hosts_created: 2`` — a document stating it leaked both
  privileged hosts with nested Docker daemons, reading ``passed``.

The four prohibition booleans were re-asserted on load; the two most load-bearing honesty flags in
the document sat just outside that mechanism.

WHY AN ALLOWLIST OF SHAPES
--------------------------
Every identity in these records is a content address by construction, so requiring the DIGEST shape
refuses a host path, an origin, a container id, a queue name and a hostname without anyone having to
enumerate them. A denylist of forbidden substrings would have to predict what leaks; this cannot be
satisfied by anything except the thing it is supposed to be.
"""

from __future__ import annotations

import pytest
from secp_acceptance import AcceptanceError
from secp_acceptance.evidence import FleetRecord, ReleaseRecord, evidence_from_dict
from secp_acceptance.reasons import CHECKS_BY_STAGE, RUN_FAILED, RUN_PASSED, STAGES
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


def _passed_document() -> dict:
    rec = AcceptanceRecorder()
    for stage in sorted(STAGES):
        rec.open_stage(stage)
        for check in CHECKS_BY_STAGE[stage]:
            rec.observe(check, stage, {"check": check})
    sealed = rec.seal(fleet=_FLEET, release=_RELEASE)
    assert sealed.outcome == RUN_PASSED  # the premise every mutation below is applied to
    return sealed.canonical()


def _mutated(section: str, field: str, value: object) -> dict:
    payload = _passed_document()
    payload[section][field] = value
    return payload


#: The exact eleven mutations measured as ACCEPTED on the parent tree, each with the bounded code it
#: must now refuse with. Parametrised one-per-case so a regression names the field that reopened
#: rather than failing an opaque set comparison.
_MUTATIONS: tuple[tuple[str, str, object, str], ...] = (
    (
        "fleet",
        "network_identity",
        "secp-acc-9f3a-net",
        "acceptance_evidence_public_value_not_permitted",
    ),
    (
        "fleet",
        "controller_host_identity",
        "/var/lib/secp/controller.sock",
        "acceptance_evidence_public_value_not_permitted",
    ),
    (
        "fleet",
        "host_image_identity",
        "https://registry.internal.corp/secp/host:v1",
        "acceptance_evidence_public_value_not_permitted",
    ),
    ("fleet", "hosts_destroyed", 0, "acceptance_evidence_incomplete"),
    ("fleet", "nested_container_runtime", False, "acceptance_evidence_incomplete"),
    ("fleet", "real_service_manager", False, "acceptance_evidence_incomplete"),
    ("release", "role", "operator", "acceptance_evidence_public_value_not_permitted"),
    (
        "release",
        "signing_anchor_id",
        "secp-production-root-ca",
        "acceptance_evidence_public_value_not_permitted",
    ),
    ("release", "test_only_anchor", False, "acceptance_evidence_forbidden_value"),
    (
        "release",
        "baseline_aggregate",
        "the-baseline",
        "acceptance_evidence_public_value_not_permitted",
    ),
    (
        "release",
        "baseline_source_sha",
        "secp-operator-queue",
        "acceptance_evidence_public_value_not_permitted",
    ),
)


@pytest.mark.parametrize(
    ("section", "field", "value", "expected"),
    _MUTATIONS,
    ids=[f"{section}.{field}" for section, field, _, _ in _MUTATIONS],
)
def test_the_eleven_accepted_mutations_are_all_refused(
    section: str, field: str, value: object, expected: str
):
    """Every one of the eleven, with the reason code it refuses under."""
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(_mutated(section, field, value))
    assert exc.value.reason_code == expected


def test_the_baseline_document_really_does_pass():
    """CONTROL. If the baseline had stopped passing for an unrelated reason, all eleven cases above
    would refuse for that reason instead and this file would be measuring nothing."""
    assert evidence_from_dict(_passed_document()).outcome == RUN_PASSED


# --------------------------------------------------------------------------- the two headline ones


def test_a_document_claiming_a_PRODUCTION_anchor_is_refused_like_a_prohibition():
    """``test_only_anchor`` is a FIFTH prohibition, not an observation.

    The harness is never permitted to use a production signing anchor, so a document asserting it
    did describes a run this harness may not have made. Refused outright — and refused on a FAILED
    document too, because unlike the coverage rules a prohibition is not something a failing run
    gets to relax.
    """
    payload = _mutated("release", "test_only_anchor", False)
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_forbidden_value"

    payload["outcome"] = RUN_FAILED
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_forbidden_value"


def test_a_leaked_host_cannot_be_reported_as_a_passing_run():
    """``hosts_destroyed`` short of ``hosts_created`` is the most expensive residue this harness can
    leave behind, and it read as green."""
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(_mutated("fleet", "hosts_destroyed", 0))
    assert exc.value.reason_code == "acceptance_evidence_incomplete"

    # ...but a FAILED run may report the leak, which is exactly how a reader learns about it. A
    # rule that refused this document entirely would suppress the report it exists to carry.
    payload = _mutated("fleet", "hosts_destroyed", 0)
    payload["outcome"] = RUN_FAILED
    loaded = evidence_from_dict(payload)
    assert loaded.fleet.hosts_destroyed == 0
    assert loaded.fleet.hosts_created == 2


def test_destroying_more_hosts_than_were_created_is_refused_on_any_outcome():
    """Incoherent in either direction of the verdict: a run cannot tear down what it never built."""
    payload = _mutated("fleet", "hosts_created", 1)
    payload["outcome"] = RUN_FAILED
    with pytest.raises(AcceptanceError) as exc:
        evidence_from_dict(payload)
    assert exc.value.reason_code == "acceptance_evidence_invalid"


# ------------------------------------------------------------------- the premise, kept honest


def test_a_FAILED_run_may_report_a_fleet_that_never_built():
    """The direction a naive fix breaks.

    A fleet that never came up reports both nature booleans False, and that is the TRUE statement.
    Requiring them unconditionally would force every failed run to claim a fleet it did not have —
    the opposite of the honesty this document exists for. They are required only of a PASSING run.
    """
    payload = _passed_document()
    payload["outcome"] = RUN_FAILED
    payload["fleet"]["nested_container_runtime"] = False
    payload["fleet"]["real_service_manager"] = False
    loaded = evidence_from_dict(payload)
    assert loaded.fleet.nested_container_runtime is False


def test_the_optional_release_fields_are_validated_when_present():
    """``successor_*`` are absent on a baseline-only run and must be checked when they appear."""
    for field, value in (
        ("successor_aggregate", "not-a-digest"),
        ("successor_source_sha", "/var/lib/secp"),
        ("successor_parent_sha", "secp-controlled-live-v1"),
    ):
        with pytest.raises(AcceptanceError) as exc:
            evidence_from_dict(_mutated("release", field, value))
        assert exc.value.reason_code == "acceptance_evidence_public_value_not_permitted", field


def test_absent_optional_release_fields_are_still_accepted():
    """CONTROL for the test above — ``None`` must not be mistaken for a malformed value, or a
    baseline-only run could never seal."""
    payload = _passed_document()
    for field in ("successor_aggregate", "successor_source_sha", "successor_parent_sha"):
        payload["release"][field] = None
    assert evidence_from_dict(payload).release.successor_aggregate is None
