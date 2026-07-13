"""Strict OIDC verifier unit tests (ADR-017 / OIDC-A) — no network; ephemeral RSA keys + a
MockTransport fake IdP. Covers valid tokens, algorithm/key attacks, claim validation, discovery/JWKS
retrieval + caching, bounded unknown-kid refresh, and error-category hygiene."""

from __future__ import annotations

import base64
import json

import jwt
import pytest
from secp_api.config import Settings
from secp_api.oidc import (
    ALLOWED_ALGORITHMS,
    OidcUnavailableError,
    OidcVerificationError,
    OidcVerifier,
)
from tests.oidc_helpers import (  # type: ignore
    AUDIENCE,
    ISSUER,
    FakeIdp,
    build_verifier,
    claims,
    gen_rsa,
    public_jwk,
    sign,
)

KID = "k1"

_KNOWN_CATEGORIES = {
    "header_invalid",
    "token_malformed",
    "algorithm_refused",
    "key_unknown",
    "signature_invalid",
    "claims_invalid",
    "provider_unavailable",
}


@pytest.fixture(scope="module")
def rsa_key():
    return gen_rsa()


@pytest.fixture
def idp(rsa_key):
    provider = FakeIdp()
    provider.set_keys(public_jwk(rsa_key, kid=KID))
    return provider


@pytest.fixture
def verifier(idp):
    return build_verifier(idp)


def _raw_token(header: dict, payload: dict, signature: str = "AAAA") -> str:
    def seg(data: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()

    return f"{seg(header)}.{seg(payload)}.{signature}"


# --- valid tokens ------------------------------------------------------------------------------


def test_valid_rs256_token_returns_issuer_and_claims(rsa_key, idp, verifier):
    token = sign(rsa_key, claims(sub="alice"), kid=KID)
    issuer, verified = verifier.verify(token)
    assert issuer == ISSUER
    assert verified["sub"] == "alice"
    assert idp.discovery_calls == 1 and idp.jwks_calls == 1


def test_valid_with_list_audience(rsa_key, verifier):
    token = sign(rsa_key, claims(aud=["other", AUDIENCE]), kid=KID)
    _, verified = verifier.verify(token)
    assert AUDIENCE in verified["aud"]


def test_valid_with_optional_nbf(rsa_key, verifier):
    token = sign(rsa_key, claims(nbf_delta=-30), kid=KID)
    _, verified = verifier.verify(token)
    assert "nbf" in verified


# --- algorithm / key attacks -------------------------------------------------------------------


def test_alg_none_is_refused(verifier):
    token = _raw_token({"alg": "none", "kid": KID}, claims())
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "algorithm_refused"


def test_hs256_is_refused_before_key_work(verifier, idp):
    # Algorithm confusion: an HS256 token must be rejected purely on the header allowlist, before
    # any key is fetched or used as an HMAC secret.
    token = jwt.encode(claims(), "x" * 40, algorithm="HS256", headers={"kid": KID})
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "algorithm_refused"


def test_wrong_asymmetric_algorithm_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(), kid=KID, alg="RS384")
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "algorithm_refused"


def test_missing_kid_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(), kid=None)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "token_malformed"


def test_unknown_kid_is_refused_and_refreshes_once(rsa_key, idp, verifier):
    # Warm the cache with a valid verify, then present an unknown kid.
    verifier.verify(sign(rsa_key, claims(), kid=KID))
    jwks_calls_before = idp.jwks_calls
    token = sign(rsa_key, claims(), kid="unknown-kid")
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "key_unknown"
    # exactly ONE bounded JWKS refresh on the unknown kid (no refresh loop).
    assert idp.jwks_calls == jwks_calls_before + 1


def test_key_rotation_succeeds_after_refresh(rsa_key, idp, verifier):
    # Warm the cache, then rotate the IdP to a brand-new key/kid and present a token signed by it.
    verifier.verify(sign(rsa_key, claims(), kid=KID))
    new_key = gen_rsa()
    idp.set_keys(public_jwk(new_key, kid="k2"))
    token = sign(new_key, claims(sub="rotated"), kid="k2")
    _, verified = verifier.verify(token)
    assert verified["sub"] == "rotated"


def test_forged_signature_is_refused(idp, verifier):
    # A token signed by a different key but claiming the known kid must fail signature verification.
    attacker_key = gen_rsa()
    token = sign(attacker_key, claims(), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "signature_invalid"


def test_jwk_kty_mismatch_is_refused(rsa_key, idp, verifier):
    # The JWKS key for the kid claims a symmetric type; a token signed RS256 must be refused.
    idp.set_keys({"kty": "oct", "kid": KID, "k": "AAAA", "alg": "HS256"})
    token = sign(rsa_key, claims(), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "algorithm_refused"


def test_jwk_alg_mismatch_is_refused(rsa_key, idp, verifier):
    jwk = public_jwk(rsa_key, kid=KID, alg="HS256")  # RSA key mislabeled HS256
    idp.set_keys(jwk)
    token = sign(rsa_key, claims(), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "algorithm_refused"


def test_allowed_algorithms_is_rs256_only():
    assert ALLOWED_ALGORITHMS == ("RS256",)


def test_from_settings_normalizes_single_trailing_slash():
    v = OidcVerifier.from_settings(
        Settings(app_env="test", oidc_issuer=ISSUER + "/", oidc_audience=AUDIENCE)
    )
    assert v.issuer == ISSUER  # exactly one trailing slash removed; no other transformation
    assert v.max_token_bytes == 8192


# --- claim validation --------------------------------------------------------------------------


def test_wrong_issuer_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(iss="https://evil.test/realms/secp"), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "claims_invalid"


def test_issuer_trailing_slash_mismatch_is_refused(rsa_key, verifier):
    # verifier issuer is ISSUER (no trailing slash); a token iss WITH a slash must not match.
    token = sign(rsa_key, claims(iss=ISSUER + "/"), kid=KID)
    with pytest.raises(OidcVerificationError):
        verifier.verify(token)


def test_wrong_audience_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(aud="some-other-api"), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "claims_invalid"


def test_missing_audience_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(include=("iss", "sub", "iat", "exp")), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "claims_invalid"


def test_expired_token_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(exp_delta=-3600, iat_delta=-7200), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "claims_invalid"


def test_future_nbf_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(nbf_delta=3600), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "claims_invalid"


def test_unacceptable_future_iat_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(iat_delta=3600), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "claims_invalid"


def test_missing_exp_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(include=("iss", "aud", "sub", "iat")), kid=KID)
    with pytest.raises(OidcVerificationError):
        verifier.verify(token)


def test_missing_iat_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(include=("iss", "aud", "sub", "exp")), kid=KID)
    with pytest.raises(OidcVerificationError):
        verifier.verify(token)


def test_missing_sub_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(include=("iss", "aud", "iat", "exp")), kid=KID)
    with pytest.raises(OidcVerificationError):
        verifier.verify(token)


def test_empty_sub_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(sub=""), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "claims_invalid"


def test_non_string_sub_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(sub=12345), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "claims_invalid"


def test_oversized_sub_is_refused(rsa_key, verifier):
    token = sign(rsa_key, claims(sub="x" * 300), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify(token)
    assert exc.value.category == "claims_invalid"


def test_oversized_token_is_refused(rsa_key, idp):
    small = build_verifier(idp, max_token_bytes=256)
    token = sign(rsa_key, claims(extra={"bloat": "y" * 4000}), kid=KID)
    with pytest.raises(OidcVerificationError) as exc:
        small.verify(token)
    assert exc.value.category == "token_malformed"


def test_malformed_token_is_refused(verifier):
    with pytest.raises(OidcVerificationError) as exc:
        verifier.verify("not-a-jwt")
    assert exc.value.category == "token_malformed"


# --- discovery / JWKS retrieval ----------------------------------------------------------------


def test_discovery_issuer_substitution_fails_closed(rsa_key, idp, verifier):
    idp.discovery = {"issuer": "https://evil.test/realms/secp", "jwks_uri": idp.jwks_uri}
    token = sign(rsa_key, claims(), kid=KID)
    with pytest.raises(OidcUnavailableError):
        verifier.verify(token)


def test_discovery_missing_issuer_fails_closed(rsa_key, idp, verifier):
    idp.discovery = {"jwks_uri": idp.jwks_uri}
    with pytest.raises(OidcUnavailableError):
        verifier.verify(sign(rsa_key, claims(), kid=KID))


def test_discovery_missing_jwks_uri_fails_closed(rsa_key, idp, verifier):
    idp.discovery = {"issuer": ISSUER}
    with pytest.raises(OidcUnavailableError):
        verifier.verify(sign(rsa_key, claims(), kid=KID))


def test_redirect_is_refused(rsa_key, idp, verifier):
    idp.redirect = True
    with pytest.raises(OidcUnavailableError):
        verifier.verify(sign(rsa_key, claims(), kid=KID))


def test_provider_outage_fails_closed(rsa_key, idp, verifier):
    idp.fail = True
    with pytest.raises(OidcUnavailableError) as exc:
        verifier.verify(sign(rsa_key, claims(), kid=KID))
    assert exc.value.category == "provider_unavailable"


def test_non_2xx_discovery_fails_closed(rsa_key, idp, verifier):
    idp.discovery_status = 500
    with pytest.raises(OidcUnavailableError):
        verifier.verify(sign(rsa_key, claims(), kid=KID))


def test_oversized_jwks_fails_closed(rsa_key, idp, verifier):
    idp.oversized = True
    with pytest.raises(OidcUnavailableError):
        verifier.verify(sign(rsa_key, claims(), kid=KID))


def test_invalid_discovery_json_fails_closed(rsa_key, idp, verifier):
    idp.discovery_raw = b"this is not json"
    with pytest.raises(OidcUnavailableError):
        verifier.verify(sign(rsa_key, claims(), kid=KID))


def test_invalid_jwks_structure_fails_closed(rsa_key, idp, verifier):
    idp.jwks_raw = b'{"keys": "not-a-list"}'
    with pytest.raises(OidcUnavailableError):
        verifier.verify(sign(rsa_key, claims(), kid=KID))


def test_userinfo_in_jwks_uri_is_refused(rsa_key, idp, verifier):
    idp.discovery = {"issuer": ISSUER, "jwks_uri": "https://user:pass@issuer.test/certs"}
    with pytest.raises(OidcUnavailableError):
        verifier.verify(sign(rsa_key, claims(), kid=KID))


# --- caching -----------------------------------------------------------------------------------


def test_cache_hit_avoids_network(rsa_key, idp, verifier):
    verifier.verify(sign(rsa_key, claims(), kid=KID))
    verifier.verify(sign(rsa_key, claims(), kid=KID))
    # both discovery and JWKS fetched exactly once across two verifications.
    assert idp.discovery_calls == 1
    assert idp.jwks_calls == 1


def test_cache_expiry_refreshes(rsa_key, idp):
    clock = {"t": 1000.0}
    v = build_verifier(
        idp,
        monotonic=lambda: clock["t"],
        discovery_cache_seconds=30,
        jwks_cache_seconds=30,
    )
    v.verify(sign(rsa_key, claims(), kid=KID))
    assert idp.jwks_calls == 1
    clock["t"] += 100  # past the cache lifetime
    v.verify(sign(rsa_key, claims(), kid=KID))
    assert idp.jwks_calls == 2
    assert idp.discovery_calls == 2


def test_no_network_at_construction(rsa_key, idp):
    v = build_verifier(idp)
    assert idp.calls == []  # constructing the verifier performs no network access
    v.verify(sign(rsa_key, claims(), kid=KID))
    assert idp.calls  # only verify() triggers fetches


# --- error-category hygiene --------------------------------------------------------------------


def test_error_categories_are_bounded_and_leak_nothing(rsa_key, idp, verifier):
    secret_sub = "SUPER-SECRET-SUBJECT-VALUE"
    cases = [
        sign(rsa_key, claims(sub=secret_sub, aud="wrong"), kid=KID),
        sign(gen_rsa(), claims(sub=secret_sub), kid=KID),  # forged
        "malformed",
    ]
    for token in cases:
        with pytest.raises(OidcVerificationError) as exc:
            verifier.verify(token)
        assert exc.value.category in _KNOWN_CATEGORIES
        # the exception carries ONLY the bounded category — never the token or a claim value.
        assert str(exc.value) == exc.value.category
        assert secret_sub not in str(exc.value)


def test_verify_returns_no_network_when_token_size_rejected(rsa_key, idp):
    v = build_verifier(idp, max_token_bytes=256)
    with pytest.raises(OidcVerificationError):
        v.verify("z" * 5000)
    assert idp.calls == []  # oversized token is rejected before any discovery/JWKS fetch
