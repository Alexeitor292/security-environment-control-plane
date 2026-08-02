"""Pure OAuth 2.0 Token Revocation semantics (RFC 7009) — SECP-PR5H-B2, Workstream C.

The decision layer of ``secpctl auth logout``. These tests pin the response rules that decide
whether an operator is told their credential is dead, because getting them wrong in EITHER direction
is a real defect: reporting a success as a failure teaches operators to ignore the warning, and
reporting a failure as a success tells them a live token is dead.

The headline rule is RFC 7009 §2.2: **200 does not mean the token existed.** The server answers 200
both when it revoked the token and when the client submitted an invalid one, precisely so a client
cannot probe token validity here. A client that treats "invalid token" as a failure has misread it.
"""

from __future__ import annotations

import pytest
from secp_management import ManagementError
from secp_management.operator_token_revoke import (
    ERROR_UNSUPPORTED_TOKEN_TYPE,
    OUTCOME_CONCURRENT_REPLACEMENT,
    OUTCOME_NOT_REQUIRED,
    OUTCOME_PARTIAL,
    OUTCOME_REFUSED,
    OUTCOME_REVOKED,
    OUTCOME_UNAVAILABLE,
    OUTCOME_UNSUPPORTED,
    TOKEN_TYPE_HINT_ACCESS_TOKEN,
    RevocationOutcome,
    interpret_revocation_response,
    revocation_form,
    revocation_not_required,
    revocation_unsupported,
)

TOKEN = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2lnbmF0dXJl"
CLIENT_ID = "secp-cli"


# --- the request (RFC 7009 §2.1) ------------------------------------------------------------------


def test_the_revocation_form_carries_the_token_the_hint_and_the_public_client_id():
    form = revocation_form(token=TOKEN, client_id=CLIENT_ID)
    assert form == {
        "token": TOKEN,
        "token_type_hint": TOKEN_TYPE_HINT_ACCESS_TOKEN,
        "client_id": CLIENT_ID,
    }
    assert TOKEN_TYPE_HINT_ACCESS_TOKEN == "access_token"


def test_no_client_secret_is_ever_part_of_the_revocation_form():
    """secpctl is a PUBLIC client: §2.1 routes client authentication through RFC 6749 §2.3, under
    which a public client identifies itself by ``client_id`` alone. There is no secret to send."""
    form = revocation_form(token=TOKEN, client_id=CLIENT_ID)
    assert set(form) == {"token", "token_type_hint", "client_id"}
    assert not any("secret" in key for key in form)


@pytest.mark.parametrize("token", ["", None, 0, b"bytes", "x" * 8193])
def test_a_malformed_token_never_reaches_a_revocation_request(token):
    with pytest.raises(ManagementError) as ei:
        revocation_form(token=token, client_id=CLIENT_ID)
    assert ei.value.reason_code == "secpctl_revocation_token_invalid"


@pytest.mark.parametrize("client_id", ["", None, 0, "x" * 256])
def test_a_malformed_client_id_never_reaches_a_revocation_request(client_id):
    with pytest.raises(ManagementError) as ei:
        revocation_form(token=TOKEN, client_id=client_id)
    assert ei.value.reason_code == "secpctl_revocation_request_invalid"


def test_a_refused_request_never_echoes_the_token():
    with pytest.raises(ManagementError) as ei:
        revocation_form(token="x" * 9000, client_id=CLIENT_ID)
    assert "xxxx" not in f"{ei.value!r} {ei.value}"


# --- the response (RFC 7009 §2.2) -----------------------------------------------------------------


def test_exactly_200_is_a_successful_revocation():
    outcome = interpret_revocation_response(200)
    assert outcome.outcome == OUTCOME_REVOKED
    assert outcome.revoked is True
    assert outcome.token_still_live is False
    assert outcome.reason_code == ""


@pytest.mark.parametrize("status", [201, 202, 204, 299])
def test_an_undefined_2xx_is_a_conservative_refusal(status):
    outcome = interpret_revocation_response(status)
    assert outcome.outcome == OUTCOME_REFUSED
    assert outcome.revoked is False
    assert outcome.token_still_live is True
    assert outcome.reason_code == "secpctl_revocation_refused"


def test_a_200_for_an_invalid_token_is_a_success_and_not_an_error():
    """§2.2: 'The authorization server responds with HTTP status code 200 if the token has been
    revoked successfully OR IF THE CLIENT SUBMITTED AN INVALID TOKEN.' An already-expired or
    already-revoked token is therefore a complete logout — the credential is not usable, which is
    the property logout needed to be true."""
    assert interpret_revocation_response(200).revoked is True


def test_503_means_the_token_is_still_live():
    """§2.2.1: 'If the server responds with HTTP status code 503, the client must assume the token
    still exists and may retry after a reasonable delay.' This is the one outcome an operator
    genuinely needs to see, because their credential remains usable at the provider."""
    outcome = interpret_revocation_response(503)
    assert outcome.outcome == OUTCOME_UNAVAILABLE
    assert outcome.revoked is False
    assert outcome.token_still_live is True
    assert outcome.reason_code == "secpctl_revocation_provider_unavailable"


def test_unsupported_token_type_is_a_bounded_provider_limitation():
    outcome = interpret_revocation_response(400, error=ERROR_UNSUPPORTED_TOKEN_TYPE)
    assert outcome.outcome == OUTCOME_UNSUPPORTED
    assert outcome.token_still_live is True
    assert outcome.reason_code == "secpctl_revocation_unsupported_token_type"
    assert ERROR_UNSUPPORTED_TOKEN_TYPE == "unsupported_token_type"


@pytest.mark.parametrize(
    ("status", "error"),
    [(400, "invalid_request"), (401, "invalid_client"), (403, None), (500, None), (404, "")],
)
def test_any_other_failure_is_a_bounded_refusal_that_leaves_the_token_live(status, error):
    outcome = interpret_revocation_response(status, error=error)
    assert outcome.outcome == OUTCOME_REFUSED
    assert outcome.token_still_live is True
    assert outcome.reason_code == "secpctl_revocation_refused"


@pytest.mark.parametrize("status", [None, "200", 2.0, True, [200]])
def test_an_unusable_status_is_a_refusal_and_never_a_revocation(status):
    """A non-int status (including ``True``, which is an ``int`` subclass and must never be read as
    a 1) can only fail closed — reporting a revocation that did not happen is the dangerous
    direction."""
    outcome = interpret_revocation_response(status)
    assert outcome.outcome == OUTCOME_REFUSED
    assert outcome.token_still_live is True


def test_an_oversized_or_odd_error_member_does_not_become_an_unsupported_verdict():
    for error in ["x" * 65, 0, {"error": "unsupported_token_type"}, None]:
        assert interpret_revocation_response(400, error=error).outcome == OUTCOME_REFUSED


def test_interpreting_a_response_never_raises():
    """A logout must reach its LOCAL deletion whatever the provider said, so nothing on this path
    may raise. Every branch returns a bounded outcome instead."""
    for status in [200, 400, 503, None, "nonsense", -1, 0]:
        assert interpret_revocation_response(status, error=object()).outcome in {
            OUTCOME_REVOKED,
            OUTCOME_UNAVAILABLE,
            OUTCOME_UNSUPPORTED,
            OUTCOME_REFUSED,
        }


# --- the two outcomes reached without a request ---------------------------------------------------


def test_an_absent_revocation_endpoint_is_reported_and_never_treated_as_a_logout():
    """RFC 8414 §2 makes ``revocation_endpoint`` OPTIONAL, so a conforming provider may not offer
    one. The token then dies only when it expires, and the operator is told so."""
    outcome = revocation_unsupported()
    assert outcome.outcome == OUTCOME_UNSUPPORTED
    assert outcome.revoked is False
    assert outcome.token_still_live is True
    assert outcome.reason_code == "secpctl_revocation_endpoint_absent"


def test_nothing_to_revoke_is_a_complete_logout_not_a_shortfall():
    outcome = revocation_not_required()
    assert outcome.outcome == OUTCOME_NOT_REQUIRED
    assert outcome.revoked is False
    # nothing live to revoke, so nothing is left usable
    assert outcome.token_still_live is False


# --- the report -----------------------------------------------------------------------------------


def test_the_report_is_bounded_and_states_both_facts():
    assert interpret_revocation_response(200).to_report() == {
        "revoked": True,
        "revocation_outcome": OUTCOME_REVOKED,
        "token_still_live": False,
    }
    assert interpret_revocation_response(503).to_report() == {
        "revoked": False,
        "revocation_outcome": OUTCOME_UNAVAILABLE,
        "token_still_live": True,
    }


def test_token_still_live_is_not_merely_the_negation_of_revoked():
    """Only revoked/absent are known-dead; every other bounded outcome remains conservative."""
    not_live = {OUTCOME_REVOKED, OUTCOME_NOT_REQUIRED}
    for outcome in [
        interpret_revocation_response(200),
        revocation_not_required(),
        interpret_revocation_response(503),
        revocation_unsupported(),
        interpret_revocation_response(400),
        RevocationOutcome(OUTCOME_PARTIAL),
        RevocationOutcome(OUTCOME_CONCURRENT_REPLACEMENT),
    ]:
        assert outcome.token_still_live is (outcome.outcome not in not_live)
    assert revocation_not_required().revoked is False
    assert revocation_not_required().token_still_live is False
