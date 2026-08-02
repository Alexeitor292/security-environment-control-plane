"""Pure OAuth 2.0 Token Revocation protocol core (RFC 7009) — SECP-PR5H-B2, Workstream C.

This is the DECISION layer of ``secpctl auth logout``: it composes the revocation request and
interprets the authorization server's answer. It performs NO I/O — no socket, no sleep, no clock
read, no filesystem, no environment, no logging — so the semantics below are exercisable
deterministically. Retrieval is :mod:`secp_management.operator_device_auth`'s job.

The RFC 7009 rules pinned here are the ones implementations most often get wrong, and getting them
wrong in EITHER direction is a real defect: treating a success as a failure teaches operators to
ignore the warning, and treating a failure as a success tells them a live token is dead.

* **200 means "stop worrying", not "the token existed"** (§2.2). The server answers 200 both when it
  revoked the token AND when the client submitted an invalid one, precisely so the client cannot
  probe token validity here. An already-expired or already-revoked token is therefore a SUCCESSFUL
  logout, not an error, and must never be reported as one.
* **503 means the token IS STILL LIVE** (§2.2.1). The RFC is explicit that the client must assume
  the token still exists and may retry after a reasonable delay. This is the one outcome an operator
  genuinely needs to see, because their credential remains usable at the provider.
* **``unsupported_token_type`` is a bounded, non-retryable limitation** (§2.2.1) — the server does
  not revoke this kind of token. Retrying cannot help, and it is reported as a provider limitation
  rather than as a secpctl failure.
* **The revocation endpoint MUST be an HTTPS URL** (§2). It carries a bearer credential in the
  request body; the transport layer enforces this, and the reason code lives here.

One deliberate posture: secpctl revokes the ACCESS token, and ``token_type_hint`` says so (§2.1).
The hint is an optimization the server MAY ignore — §2.1 requires it to extend its search to other
token types if the hint does not find the token — so a wrong hint costs a lookup, never correctness.
There is no refresh token to revoke: the CLI is a public client that never requests
``offline_access``, so the access token is the entire credential and revoking it ends the session.

Nothing here returns, logs, or embeds the token, the endpoint, or a provider response body; every
failure is one bounded reason code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn

from secp_management import ManagementError

# --- RFC 7009 constants ---------------------------------------------------------------------------

#: RFC 7009 §2.1 — the hint that the submitted token is an access token.
TOKEN_TYPE_HINT_ACCESS_TOKEN = "access_token"

#: RFC 7009 §2.2.1 — the server does not support revoking the presented token type.
ERROR_UNSUPPORTED_TOKEN_TYPE = "unsupported_token_type"

#: RFC 7009 §2.2.1 — a 503 obliges the client to assume the token still exists.
_STATUS_SERVICE_UNAVAILABLE = 503

_MAX_TOKEN_BYTES = 8192
_MAX_ERROR_LEN = 64

# --- outcomes -------------------------------------------------------------------------------------

#: The provider accepted the revocation. Per §2.2 this ALSO covers an invalid/already-dead token —
#: the credential is not usable, which is exactly what logout needed to be true.
OUTCOME_REVOKED = "revoked"
#: There was no credential material to revoke. No request is made, and no token is known to remain
#: live, so this is a complete logout and not a shortfall. A merely LOCALLY expired credential does
#: not qualify: workstation clock skew can be ahead of the issuer, so logout still submits it.
OUTCOME_NOT_REQUIRED = "not_required"
#: The credential could not be READ, so it could not be revoked — a corrupt record, an entry minted
#: for another controller, or a locked/unreachable keystore. Critically this is NOT
#: :data:`OUTCOME_NOT_REQUIRED`: a perfectly live token may be sitting in that entry, and the logout
#: is about to delete it locally without ever revoking it.
OUTCOME_UNREADABLE = "credential_unreadable"
#: At least one readable token was proven dead while another known source was not.
OUTCOME_PARTIAL = "partial"
#: A newer OS-store generation replaced the one logout read; it was deliberately retained.
OUTCOME_CONCURRENT_REPLACEMENT = "concurrent_replacement"
#: The provider does not advertise a revocation endpoint at all (RFC 8414 makes it OPTIONAL).
OUTCOME_UNSUPPORTED = "unsupported"
#: RFC 7009 §2.2.1 — 503. The token MUST be assumed to still exist.
OUTCOME_UNAVAILABLE = "unavailable"
#: The provider refused the request (a 4xx other than the ones above, or an unusable answer).
OUTCOME_REFUSED = "refused"


class OperatorTokenRevocationError(ManagementError):
    """A bounded, closed revocation refusal — carries ONLY a reason code, never the token, the
    endpoint, a provider response body, or a raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise OperatorTokenRevocationError(reason_code)


@dataclass(frozen=True)
class RevocationOutcome:
    """One bounded revocation result.

    ``token_still_live`` is the operator-facing fact and is deliberately NOT simply
    ``not revoked``: an unsupported endpoint and a 503 both leave the token usable at the provider,
    and both must say so.
    """

    outcome: str
    reason_code: str = ""

    @property
    def revoked(self) -> bool:
        return self.outcome == OUTCOME_REVOKED

    @property
    def token_still_live(self) -> bool:
        """Whether the credential must be ASSUMED usable at the provider after this attempt.

        Both a successful revocation and "there was no credential material to revoke" leave no
        known usable token, so both are false. Every other outcome — unreadable, unsupported,
        unavailable, or refused — may leave one, and each says so rather than being folded into a
        single "logout failed".
        """
        return self.outcome not in (OUTCOME_REVOKED, OUTCOME_NOT_REQUIRED)

    def to_report(self) -> dict:
        return {
            "revoked": self.revoked,
            "revocation_outcome": self.outcome,
            "token_still_live": self.token_still_live,
        }


def revocation_form(*, token: object, client_id: str) -> dict[str, str]:
    """The RFC 7009 §2.1 revocation request body.

    ``token`` is REQUIRED. ``token_type_hint`` is OPTIONAL and set to ``access_token`` because that
    is the only token type secpctl ever holds. ``client_id`` is included because secpctl is a PUBLIC
    client: it has no secret to present, and §2.1 routes client authentication through RFC 6749
    §2.3, under which a public client identifies itself by ``client_id``. No secret is sent, and
    none exists to send.
    """
    if not isinstance(token, str) or not token or len(token) > _MAX_TOKEN_BYTES:
        _reject("secpctl_revocation_token_invalid")
    if not isinstance(client_id, str) or not client_id or len(client_id) > 255:
        _reject("secpctl_revocation_request_invalid")
    return {
        "token": token,
        "token_type_hint": TOKEN_TYPE_HINT_ACCESS_TOKEN,
        "client_id": client_id,
    }


def interpret_revocation_response(status: object, *, error: object = None) -> RevocationOutcome:
    """Interpret an RFC 7009 §2.2 revocation response.

    ``status`` is the HTTP status code; ``error`` is the OAuth ``error`` member when the body
    carried one. Returns a bounded :class:`RevocationOutcome` and NEVER raises on a provider answer
    — a logout must reach its local deletion whatever the provider said.
    """
    if not isinstance(status, int) or isinstance(status, bool):
        return RevocationOutcome(OUTCOME_REFUSED, reason_code="secpctl_revocation_response_invalid")

    # §2.2 specifies EXACTLY 200 on success AND on an invalid token. An undefined 2xx such as
    # 202 cannot be promoted to success: "accepted" may mean the revocation has not happened yet,
    # and logout's dangerous failure direction is claiming a still-live token is dead.
    if status == 200:
        return RevocationOutcome(OUTCOME_REVOKED)

    # §2.2.1: the client MUST assume the token still exists and MAY retry later.
    if status == _STATUS_SERVICE_UNAVAILABLE:
        return RevocationOutcome(
            OUTCOME_UNAVAILABLE, reason_code="secpctl_revocation_provider_unavailable"
        )

    if isinstance(error, str) and 0 < len(error) <= _MAX_ERROR_LEN:
        if error == ERROR_UNSUPPORTED_TOKEN_TYPE:
            return RevocationOutcome(
                OUTCOME_UNSUPPORTED, reason_code="secpctl_revocation_unsupported_token_type"
            )

    return RevocationOutcome(OUTCOME_REFUSED, reason_code="secpctl_revocation_refused")


def revocation_unsupported() -> RevocationOutcome:
    """The outcome when the issuer advertises NO ``revocation_endpoint``.

    RFC 8414 §2 makes ``revocation_endpoint`` OPTIONAL, so a conforming provider may simply not
    offer one. That is a provider limitation, not a secpctl failure — but the token stays live, so
    it is reported, never silently treated as a successful logout.
    """
    return RevocationOutcome(OUTCOME_UNSUPPORTED, reason_code="secpctl_revocation_endpoint_absent")


def revocation_credential_unreadable(reason_code: str) -> RevocationOutcome:
    """The outcome when the stored credential could not be READ, so it could not be revoked.

    This is deliberately NOT :func:`revocation_not_required`. "Absent" and "expired" mean no live
    token exists; "the record is corrupt", "this entry belongs to another controller" and "the
    keystore is locked" mean a live token may exist and simply cannot be reached. Collapsing the
    second group into the first would make logout affirmatively report ``token_still_live: false``.
    The caller also lacks a validated generation in this case, so it must not delete the OS record.
    """
    return RevocationOutcome(OUTCOME_UNREADABLE, reason_code=reason_code)


def revocation_not_required() -> RevocationOutcome:
    """The outcome when there is no live credential to revoke.

    Only confirmed absence reaches this outcome. A valid, bounded but locally expired OS record is
    still submitted conservatively because the workstation clock is not issuer truth; a malformed
    expiry is unreadable, never absence.
    """
    return RevocationOutcome(OUTCOME_NOT_REQUIRED)


__all__ = [
    "ERROR_UNSUPPORTED_TOKEN_TYPE",
    "OUTCOME_CONCURRENT_REPLACEMENT",
    "OUTCOME_NOT_REQUIRED",
    "OUTCOME_PARTIAL",
    "OUTCOME_REFUSED",
    "OUTCOME_REVOKED",
    "OUTCOME_UNAVAILABLE",
    "OUTCOME_UNREADABLE",
    "OUTCOME_UNSUPPORTED",
    "TOKEN_TYPE_HINT_ACCESS_TOKEN",
    "OperatorTokenRevocationError",
    "RevocationOutcome",
    "interpret_revocation_response",
    "revocation_credential_unreadable",
    "revocation_form",
    "revocation_not_required",
    "revocation_unsupported",
]
