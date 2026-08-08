"""The controller trust-anchor identity — the value that closes CA substitution.

One derivation, imported by both planes. The controller SIGNS it; the worker COMPUTES it from the
bundle it really built its TLS context from. These tests pin the properties that make that
comparison meaningful, because a derivation that differed between the two sides would fail in the
direction that looks like success.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from secp_commissioning.trust_anchor import (
    TRUST_ANCHOR_DOMAIN,
    TrustAnchorError,
    trust_anchor_id_for,
)


def _ca(common_name: str) -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def test_the_same_trust_set_has_the_same_identity_regardless_of_order_or_formatting():
    """Stability is what stops a re-wrapped bundle reading as a substituted one.

    A false MISMATCH here is not harmless: it would refuse legitimate enrollments, and the fix an
    operator reaches for under that pressure is to stop checking.
    """
    a, b = _ca("ca-a"), _ca("ca-b")
    assert trust_anchor_id_for(a + b) == trust_anchor_id_for(b + a)
    assert trust_anchor_id_for(a) == trust_anchor_id_for("# a comment\n" + a + "\n\n")
    assert trust_anchor_id_for(a) == trust_anchor_id_for(a.encode())


def test_a_different_trust_set_has_a_different_identity():
    """Including an APPENDED CA — the substitution a single-certificate fingerprint misses.

    Trusting a bundle means trusting every certificate in it, so an attacker who appends their own
    CA to a bundle containing the real one has changed what the worker trusts even though the real
    certificate is still present and its fingerprint unchanged.
    """
    a, b = _ca("ca-a"), _ca("ca-b")
    assert trust_anchor_id_for(a) != trust_anchor_id_for(b)
    assert trust_anchor_id_for(a) != trust_anchor_id_for(a + b)
    assert trust_anchor_id_for(a + b) != trust_anchor_id_for(b)


@pytest.mark.parametrize("bundle", ["", "   ", "\n", b"", "not a pem at all", "-----BEGIN X-----"])
def test_an_empty_or_unparseable_bundle_refuses_rather_than_yielding_an_identity(bundle):
    """An empty bundle must not produce the identity of "trust nothing".

    If it did, two workers with no CA would compare EQUAL and read as agreement — a mismatch check
    that passes precisely when there is nothing to check.
    """
    with pytest.raises(TrustAnchorError):
        trust_anchor_id_for(bundle)


def test_the_identity_is_domain_separated():
    """A bare `sha256:` says nothing about WHAT it identifies.

    Without the domain, a trust-anchor id is structurally interchangeable with a claim digest, a
    release digest or a worker key id — every one of which is also a bare sha256 of something.
    """
    import hashlib

    from secp_commissioning.canonical import sha256_digest

    a = _ca("ca-a")
    member = hashlib.sha256(
        x509.load_pem_x509_certificates(a.encode())[0].public_bytes(serialization.Encoding.DER)
    ).hexdigest()
    assert trust_anchor_id_for(a) == sha256_digest(
        {"domain": TRUST_ANCHOR_DOMAIN, "members": [member]}
    )
    # and NOT the undomained form, which is what a replay would rely on
    assert trust_anchor_id_for(a) != sha256_digest({"members": [member]})
    assert trust_anchor_id_for(a) != "sha256:" + member


def test_both_planes_import_the_same_derivation():
    """Structural: there is ONE implementation, in the package both planes already share.

    A second copy — even a correct one — reintroduces the failure this module exists to prevent,
    because the two sides would then be comparing values produced by different code.
    """
    import pathlib

    import secp_api
    import secp_worker

    for root in (pathlib.Path(secp_api.__file__).parent, pathlib.Path(secp_worker.__file__).parent):
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if "trust_anchor_id_for" in text:
                assert "from secp_commissioning" in text, path
            # nobody re-derives it locally
            assert "TRUST_ANCHOR_DOMAIN =" not in text, path


def test_the_derivation_reads_certificates_not_file_bytes():
    """Digesting the PEM text would make a comment or a line ending a different trust set."""
    import inspect

    from secp_commissioning import trust_anchor

    source = inspect.getsource(trust_anchor.trust_anchor_id_for)
    assert "load_pem_x509_certificates" in source
    assert "Encoding.DER" in source
