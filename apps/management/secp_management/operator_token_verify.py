"""CLI-side verification of an operator access token — SECP-PR5H-B2, Workstream C.

ADR-028 §3 requires ``secpctl auth login`` to verify issuer / audience / signature / expiry and the
required claims BEFORE the token is persisted. The management plane may not import ``secp_api`` (per
``tests/test_pr5h_secpctl_boundary_guards.py`` and ``tests/test_management_plane_boundary.py``), so
this module is a DELIBERATE, reviewed re-statement of the ADR-017 verification rules on this side of
the plane boundary — the same pattern as the documented ``worker_enrollment_schema.py`` /
``migration_heads.py`` non-import pair, which hold the same literal and must agree without importing
each other.

It is PURE: the JWKS arrives as already-fetched data and the clock arrives as an argument, so it
performs no network, filesystem, environment or clock access and is fully unit-testable. Retrieval
is :mod:`secp_management.operator_device_auth`'s job.

Trust rules mirrored from ADR-017 (``secp_api/oidc.py``):

* the accepted algorithm is a fixed ``["RS256"]`` allowlist — NEVER read from the JWT header or the
  JWK, so ``none``, symmetric algorithms and algorithm confusion are refused before any key work;
* the signing key is selected by an exact ``kid`` match against the supplied JWKS;
* ``exp``, ``iat``, ``sub``, ``aud`` and ``iss`` are all REQUIRED, and ``iss`` must exactly equal
  the reviewed issuer;
* an ``iat`` beyond now + the permitted skew is refused explicitly, including a ``bool``/non-numeric
  ``iat`` that an int coercion elsewhere could otherwise mask.

Two further checks close the CLIENT and SCOPE halves of the brief, which signature/issuer/audience
verification alone does not cover:

* **client** — when the token carries ``azp`` (authorized party), it MUST equal the client id
  secpctl presented. OpenID Connect Core §3.1.3.7 step 5 states that a client SHOULD verify its own
  client id is the ``azp`` value when the claim is present, and Keycloak sets ``azp`` on every
  access token to the client that obtained it. This is what stops a token minted for a DIFFERENT
  client — but the same issuer and audience — from being accepted and stored as secpctl's operator
  credential. The claim is optional in the spec, so an absent ``azp`` is not a refusal; a present,
  mismatched one is.
* **scope** — the granted scope must carry the required floor and none of the refused set, so a
  provider that silently upgraded the grant to ``offline_access`` is refused rather than obeyed. The
  policy is stated once, in :mod:`secp_management.device_grant`, and applied both to the token
  response and to this claim.

Every failure is one bounded reason code. The token, its claims, the JWK material and any upstream
exception never enter a refusal, repr, log or report.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, NoReturn

from secp_management import ManagementError
from secp_management.device_grant import validate_granted_scope

#: The ONLY accepted signing algorithm (ADR-017). A fixed allowlist, never derived from input.
ALLOWED_ALGORITHMS: tuple[str, ...] = ("RS256",)

_MAX_TOKEN_BYTES = 8192
_MAX_SUBJECT_LENGTH = 255  # matches app_user.subject String(255)
_DEFAULT_CLOCK_SKEW_SECONDS = 60


class OperatorTokenVerificationError(ManagementError):
    """A bounded, closed token-verification refusal — carries ONLY a reason code, never the token,
    a claim value, JWK material, or a raw exception."""


def _reject(reason_code: str) -> NoReturn:
    raise OperatorTokenVerificationError(reason_code)


@dataclass(frozen=True)
class VerifiedOperatorToken:
    """The bounded, non-secret facts a verified operator token yields.

    It deliberately carries NO raw claims mapping and NOT the token itself — only the exact subject
    (needed to detect an unprovisioned operator), the expiry (needed for credential-store
    lifecycle), and the granted scope (a non-secret, already-validated set kept so a report can say
    what was actually granted). ``auth status`` still resolves the authoritative principal from
    ``/api/v1/me``; a token claim never determines organization, role or permission.
    """

    subject: str
    expires_at_epoch: int
    issued_at_epoch: int
    granted_scope: frozenset[str] = frozenset()


def _signing_key(jwks: Mapping[str, Any], kid: str) -> Any:
    """Resolve the RSA public key for ``kid`` from an already-fetched JWKS mapping."""
    from jwt.algorithms import RSAAlgorithm

    jwk = jwks.get(kid)
    if not isinstance(jwk, dict):
        _reject("secpctl_operator_token_key_unknown")
    if jwk.get("kty") != "RSA":
        _reject("secpctl_operator_token_algorithm_refused")
    jwk_alg = jwk.get("alg")
    if jwk_alg is not None and jwk_alg != "RS256":
        _reject("secpctl_operator_token_algorithm_refused")
    use = jwk.get("use")
    if use is not None and use != "sig":
        _reject("secpctl_operator_token_algorithm_refused")
    try:
        return RSAAlgorithm.from_jwk(json.dumps(jwk))
    except Exception:  # noqa: BLE001 - malformed key material is a bounded refusal
        _reject("secpctl_operator_token_algorithm_refused")


def verify_operator_token(
    token: str,
    *,
    jwks: Mapping[str, Any],
    issuer: str,
    audience: str,
    now_epoch: float,
    client_id: str = "",
    clock_skew_seconds: int = _DEFAULT_CLOCK_SKEW_SECONDS,
) -> VerifiedOperatorToken:
    """Verify a device-grant access token against the reviewed issuer's JWKS.

    ``jwks`` maps ``kid`` -> JWK dict (already retrieved and bounded by the caller). ``client_id``,
    when supplied, is the client secpctl presented, and a present ``azp`` claim must equal it.
    Returns the bounded :class:`VerifiedOperatorToken`, or raises
    :class:`OperatorTokenVerificationError` with a single bounded reason code.
    """
    import jwt

    if not isinstance(token, str) or not token or len(token) > _MAX_TOKEN_BYTES:
        _reject("secpctl_operator_token_invalid")
    segments = token.split(".")
    if len(segments) != 3 or not all(segments):
        _reject("secpctl_operator_token_invalid")

    # The unverified header is used ONLY to reject; never to choose the algorithm.
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        _reject("secpctl_operator_token_invalid")
    if header.get("alg") not in ALLOWED_ALGORITHMS:
        _reject("secpctl_operator_token_algorithm_refused")
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        _reject("secpctl_operator_token_invalid")

    public_key = _signing_key(jwks, kid)

    try:
        claims = jwt.decode(
            token,
            key=public_key,
            algorithms=list(ALLOWED_ALGORITHMS),
            audience=audience,
            issuer=issuer,
            leeway=clock_skew_seconds,
            options={
                "require": ["exp", "iat", "sub", "aud", "iss"],
                "verify_signature": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
                "verify_nbf": True,
            },
        )
    except jwt.InvalidSignatureError:
        _reject("secpctl_operator_token_signature_invalid")
    except jwt.InvalidAlgorithmError:
        _reject("secpctl_operator_token_algorithm_refused")
    except jwt.ExpiredSignatureError:
        _reject("secpctl_operator_token_expired")
    except (
        jwt.ImmatureSignatureError,
        jwt.InvalidAudienceError,
        jwt.InvalidIssuerError,
        jwt.InvalidIssuedAtError,
        jwt.MissingRequiredClaimError,
    ):
        _reject("secpctl_operator_token_claims_invalid")
    except jwt.PyJWTError:
        _reject("secpctl_operator_token_claims_invalid")

    # Defence in depth: `iss` must exactly equal the reviewed issuer (no substitution).
    if claims.get("iss") != issuer:
        _reject("secpctl_operator_token_claims_invalid")

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject or len(subject) > _MAX_SUBJECT_LENGTH:
        _reject("secpctl_operator_token_claims_invalid")

    issued_at = claims.get("iat")
    if not isinstance(issued_at, (int, float)) or isinstance(issued_at, bool):
        _reject("secpctl_operator_token_claims_invalid")
    if float(issued_at) > now_epoch + clock_skew_seconds:
        _reject("secpctl_operator_token_claims_invalid")

    expires_at = claims.get("exp")
    if not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool):
        _reject("secpctl_operator_token_claims_invalid")

    # CLIENT: a present `azp` must name the client secpctl actually presented (OIDC Core §3.1.3.7).
    # The claim is optional, so its ABSENCE is not a refusal — but a token minted for a different
    # client at the same issuer and audience is, which is the substitution this check exists for.
    authorized_party = claims.get("azp")
    if client_id and authorized_party is not None:
        if not isinstance(authorized_party, str) or authorized_party != client_id:
            _reject("secpctl_operator_token_client_invalid")

    # SCOPE: the same policy the token response was held to, applied to the claim. `scope` is absent
    # on providers that do not mirror it into the access token, which `validate_granted_scope`
    # reads as "exactly what was requested" rather than as a violation.
    granted_scope = validate_granted_scope(claims.get("scope"))

    return VerifiedOperatorToken(
        subject=subject,
        expires_at_epoch=int(expires_at),
        issued_at_epoch=int(issued_at),
        granted_scope=granted_scope,
    )


def jwks_by_kid(document: object) -> dict[str, Any]:
    """Project a retrieved JWKS document into a ``kid`` -> JWK mapping.

    Keys without a usable string ``kid`` are dropped (they are not addressable by a token header).
    A malformed document is a bounded refusal — the document body is never surfaced.
    """
    if not isinstance(document, dict):
        _reject("secpctl_operator_token_jwks_invalid")
    keys = document.get("keys")
    if not isinstance(keys, list) or not keys:
        _reject("secpctl_operator_token_jwks_invalid")
    result: dict[str, Any] = {}
    for key in keys:
        if isinstance(key, dict):
            kid = key.get("kid")
            if isinstance(kid, str) and kid:
                result[kid] = key
    if not result:
        _reject("secpctl_operator_token_jwks_invalid")
    return result


__all__ = [
    "ALLOWED_ALGORITHMS",
    "OperatorTokenVerificationError",
    "VerifiedOperatorToken",
    "jwks_by_kid",
    "verify_operator_token",
]
