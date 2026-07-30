"""CLI-side operator token verification (SECP-PR5H-B2, Workstream C).

ADR-028 §3 requires secpctl to verify a device-grant token itself before storing it. The management
plane may not import ``secp_api``, so these tests pin that the re-stated rules match ADR-017's
posture: a fixed RS256 allowlist that is never read from the token or the JWK, exact issuer and
audience, every required claim present, and a bounded subject.
"""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from secp_management import ManagementError
from secp_management.operator_token_verify import (
    ALLOWED_ALGORITHMS,
    jwks_by_kid,
    verify_operator_token,
)

ISSUER = "https://idp.invalid/realms/secp"
AUDIENCE = "secp-api"
SUBJECT = "5ec9ad00-0000-4000-8000-000000000001"
KID = "test-key-1"


@pytest.fixture(scope="module")
def keypair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, private.public_key()


@pytest.fixture(scope="module")
def jwks(keypair):
    _private, public = keypair
    jwk = json.loads(RSAAlgorithm.to_jwk(public))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


def _token(keypair, *, alg="RS256", kid=KID, **claim_overrides) -> str:
    private, _public = keypair
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": SUBJECT,
        "iat": now,
        "exp": now + 300,
    }
    claims.update(claim_overrides)
    for key in [k for k, v in claims.items() if v is None]:
        del claims[key]
    key = "secret" if alg.startswith("HS") else private
    headers = {"kid": kid} if kid else {}
    return jwt.encode(claims, key, algorithm=alg, headers=headers)


def _verify(token, jwks_doc, **kwargs):
    params = {
        "jwks": jwks_by_kid(jwks_doc),
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "now_epoch": time.time(),
    }
    params.update(kwargs)
    return verify_operator_token(token, **params)


def _reason(excinfo) -> str:
    return excinfo.value.reason_code


def test_only_rs256_is_allowed():
    assert ALLOWED_ALGORITHMS == ("RS256",)


def test_a_valid_token_verifies_and_yields_bounded_facts(keypair, jwks):
    verified = _verify(_token(keypair), jwks)
    assert verified.subject == SUBJECT
    assert verified.expires_at_epoch > verified.issued_at_epoch


def test_the_verified_result_carries_no_raw_claims_or_token(keypair, jwks):
    verified = _verify(_token(keypair), jwks)
    assert not hasattr(verified, "claims")
    assert not hasattr(verified, "token")
    assert "eyJ" not in repr(verified)


def test_hs256_token_is_refused_before_any_key_work(keypair, jwks):
    """Algorithm confusion: a symmetric token signed with the JWK's public modulus as the HMAC key
    must never verify. The allowlist is checked against the header before key resolution."""
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair, alg="HS256"), jwks)
    assert _reason(ei) == "secpctl_operator_token_algorithm_refused"


def test_alg_none_token_is_refused_at_the_structural_check(jwks):
    """An `alg=none` JWT has an EMPTY signature segment, so the "three non-empty segments" check
    refuses it before the header is even parsed — one layer earlier than the algorithm allowlist."""
    unsigned = jwt.encode({"iss": ISSUER, "sub": SUBJECT}, key="", algorithm="none")
    assert unsigned.endswith(".")
    with pytest.raises(ManagementError) as ei:
        _verify(unsigned, jwks)
    assert _reason(ei) == "secpctl_operator_token_invalid"


def test_alg_none_with_a_forged_signature_is_refused_by_the_algorithm_allowlist(jwks):
    """The second layer: a well-formed `alg=none` token carrying junk in the signature segment gets
    past the structural check and must then be refused because `none` is not on the allowlist."""
    unsigned = jwt.encode({"iss": ISSUER, "sub": SUBJECT}, key="", algorithm="none")
    with pytest.raises(ManagementError) as ei:
        _verify(unsigned + "Zm9yZ2Vk", jwks)
    assert _reason(ei) == "secpctl_operator_token_algorithm_refused"


def test_an_unknown_kid_is_refused(keypair, jwks):
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair, kid="rotated-away"), jwks)
    assert _reason(ei) == "secpctl_operator_token_key_unknown"


def test_a_token_with_no_kid_is_refused(keypair, jwks):
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair, kid=None), jwks)
    assert _reason(ei) == "secpctl_operator_token_invalid"


def test_a_signature_from_another_key_is_refused(jwks):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    forged = jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": SUBJECT, "iat": now, "exp": now + 300},
        other,
        algorithm="RS256",
        headers={"kid": KID},
    )
    with pytest.raises(ManagementError) as ei:
        _verify(forged, jwks)
    assert _reason(ei) == "secpctl_operator_token_signature_invalid"


def test_a_wrong_audience_is_refused(keypair, jwks):
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair, aud="some-other-api"), jwks)
    assert _reason(ei) == "secpctl_operator_token_claims_invalid"


def test_a_wrong_issuer_is_refused(keypair, jwks):
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair, iss="https://evil.invalid/realms/secp"), jwks)
    assert _reason(ei) == "secpctl_operator_token_claims_invalid"


def test_an_expired_token_is_refused(keypair, jwks):
    now = int(time.time())
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair, iat=now - 900, exp=now - 600), jwks)
    assert _reason(ei) == "secpctl_operator_token_expired"


@pytest.mark.parametrize("claim", ["exp", "iat", "sub", "aud", "iss"])
def test_every_required_claim_is_required(keypair, jwks, claim):
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair, **{claim: None}), jwks)
    assert _reason(ei) in {
        "secpctl_operator_token_claims_invalid",
        "secpctl_operator_token_expired",
    }


def test_a_future_issued_at_is_refused(keypair, jwks):
    future = int(time.time()) + 3600
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair, iat=future, exp=future + 300), jwks)
    assert _reason(ei) == "secpctl_operator_token_claims_invalid"


def test_an_oversized_subject_is_refused(keypair, jwks):
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair, sub="s" * 256), jwks)
    assert _reason(ei) == "secpctl_operator_token_claims_invalid"


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b", "a.b.c.d", "a..c", "x" * 9000, None, 7])
def test_malformed_tokens_are_refused(jwks, token):
    with pytest.raises(ManagementError) as ei:
        _verify(token, jwks)
    assert _reason(ei) in {
        "secpctl_operator_token_invalid",
        "secpctl_operator_token_algorithm_refused",
    }


def test_a_non_rsa_jwk_is_refused(keypair):
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair), {"keys": [{"kid": KID, "kty": "oct", "k": "AAAA"}]})
    assert _reason(ei) == "secpctl_operator_token_algorithm_refused"


def test_a_jwk_advertising_another_algorithm_is_refused(keypair, jwks):
    hostile = json.loads(json.dumps(jwks))
    hostile["keys"][0]["alg"] = "RS512"
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair), hostile)
    assert _reason(ei) == "secpctl_operator_token_algorithm_refused"


def test_an_encryption_only_jwk_is_refused(keypair, jwks):
    hostile = json.loads(json.dumps(jwks))
    hostile["keys"][0]["use"] = "enc"
    with pytest.raises(ManagementError) as ei:
        _verify(_token(keypair), hostile)
    assert _reason(ei) == "secpctl_operator_token_algorithm_refused"


@pytest.mark.parametrize(
    "document", [None, {}, {"keys": []}, {"keys": "nope"}, {"keys": [{"kty": "RSA"}]}, []]
)
def test_a_malformed_jwks_document_is_refused(document):
    with pytest.raises(ManagementError) as ei:
        jwks_by_kid(document)
    assert _reason(ei) == "secpctl_operator_token_jwks_invalid"


def test_keys_without_a_usable_kid_are_dropped(jwks):
    document = json.loads(json.dumps(jwks))
    document["keys"].append({"kty": "RSA", "n": "AAAA", "e": "AQAB"})  # no kid
    assert set(jwks_by_kid(document)) == {KID}


def test_a_refusal_never_echoes_the_token_or_claims(keypair, jwks):
    token = _token(keypair, aud="leaky-audience-value")
    with pytest.raises(ManagementError) as ei:
        _verify(token, jwks)
    rendered = f"{ei.value!r} {ei.value}"
    assert token not in rendered
    assert "leaky-audience-value" not in rendered


def test_verification_performs_no_network_or_filesystem_access():
    """The JWKS arrives as data; retrieval belongs to ``operator_device_auth``."""
    import ast
    import pathlib

    import secp_management.operator_token_verify as module

    source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [a.name for a in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for name in names:
                assert name.split(".")[0] not in {"httpx", "socket", "os", "pathlib", "requests"}
