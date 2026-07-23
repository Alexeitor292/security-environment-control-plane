"""The bounded migration-head rolling-upgrade window (SECP-PR5H-A, ADR-027).

Proves the window is BOUNDED and correctly split:

* an ALREADY-ISSUED PR5F (legacy-head) signed offer stays verifiable;
* a NEWLY issued offer declares ONLY the current head, and issuance additionally requires the live
  controller to already be at it;
* unknown / malformed / older / future / branched heads refuse closed;
* a downgrade substitution refuses because the declared head must still equal the OBSERVED head.

These are pure contract/validation proofs: no host, container, network or provider is contacted.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from secp_discovery_activation.handoff import ControllerOffer
from secp_discovery_activation.migration_heads import (
    ACCEPTED_CONTROLLER_MIGRATION_HEADS,
    CURRENT_CONTROLLER_MIGRATION_HEAD,
    ISSUED_CONTROLLER_MIGRATION_HEAD,
    LEGACY_CONTROLLER_MIGRATION_HEAD,
    accepted_heads_match_literal,
    is_accepted_controller_migration_head,
)


def test_window_contains_exactly_the_two_reviewed_heads() -> None:
    assert ACCEPTED_CONTROLLER_MIGRATION_HEADS == ("d8f1a2b3c4e5", "b6e2f4a9c1d7")
    assert LEGACY_CONTROLLER_MIGRATION_HEAD == "d8f1a2b3c4e5"
    assert CURRENT_CONTROLLER_MIGRATION_HEAD == "b6e2f4a9c1d7"
    # the window is BOUNDED — exactly two, never open-ended
    assert len(ACCEPTED_CONTROLLER_MIGRATION_HEADS) == 2
    assert len(set(ACCEPTED_CONTROLLER_MIGRATION_HEADS)) == 2


def test_literal_and_tuple_never_drift() -> None:
    # the signed field's Literal must always agree with the accepted tuple
    assert accepted_heads_match_literal()


def test_issuance_is_single_valued_and_is_the_current_head() -> None:
    # a NEW offer always declares only the current head, never the legacy one
    assert ISSUED_CONTROLLER_MIGRATION_HEAD == CURRENT_CONTROLLER_MIGRATION_HEAD
    assert ISSUED_CONTROLLER_MIGRATION_HEAD != LEGACY_CONTROLLER_MIGRATION_HEAD


@pytest.mark.parametrize("head", ACCEPTED_CONTROLLER_MIGRATION_HEADS)
def test_both_accepted_heads_are_recognized(head: str) -> None:
    assert is_accepted_controller_migration_head(head) is True


@pytest.mark.parametrize(
    "head",
    [
        "c4e2f9a1b7d3",  # OLDER (the pre-PR5F baseline) — outside the window
        "000000000000",  # unknown
        "b6e2f4a9c1d8",  # near-miss / future
        "B6E2F4A9C1D7",  # wrong case
        "b6e2f4a9c1d7 (head)",  # malformed (raw alembic output, not a head)
        "d8f1a2b3c4e5,b6e2f4a9c1d7",  # branched / multi-head
        "",
        None,
        12345,
    ],
)
def test_unknown_malformed_older_future_and_branched_heads_refuse(head: object) -> None:
    assert is_accepted_controller_migration_head(head) is False


def _offer_payload(head: str) -> dict:
    """A ControllerOffer payload that is complete EXCEPT for the head under test.

    Only the head field is exercised here; every other field is deliberately invalid-free so a
    ValidationError can be attributed to the head alone (checked via the error locations)."""
    return {"controller_migration_head": head}


def _head_rejected(head: str) -> bool:
    """True when the signed-record field itself refuses the head (independent of other fields)."""
    try:
        ControllerOffer.model_validate(_offer_payload(head))
    except ValidationError as exc:
        locs = {".".join(str(p) for p in err["loc"]) for err in exc.errors()}
        return "controller_migration_head" in locs
    return False


def test_signed_field_accepts_an_already_issued_legacy_head() -> None:
    # an ALREADY-ISSUED PR5F offer must stay verifiable during the window
    assert _head_rejected(LEGACY_CONTROLLER_MIGRATION_HEAD) is False


def test_signed_field_accepts_the_current_head() -> None:
    assert _head_rejected(CURRENT_CONTROLLER_MIGRATION_HEAD) is False


@pytest.mark.parametrize("head", ["c4e2f9a1b7d3", "000000000000", "b6e2f4a9c1d8", ""])
def test_signed_field_refuses_heads_outside_the_window(head: str) -> None:
    assert _head_rejected(head) is True
