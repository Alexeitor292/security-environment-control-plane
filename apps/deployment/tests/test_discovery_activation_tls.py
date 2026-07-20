"""Hermetic in-memory TLS preparation for the PR5F admission listener."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from secp_discovery_activation.tls import (
    TLSValidationError,
    generate_tls_material,
    import_admission_ca,
    import_tls_material,
    import_tls_public_material,
)

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
IDENTITY = "admission.internal.test"


@pytest.fixture(scope="module")
def material():  # noqa: ANN201
    return generate_tls_material(dns_identity=IDENTITY, validity_days=30, now=NOW)


def test_generated_material_has_exact_identity_validity_and_safe_metadata(material) -> None:  # noqa: ANN001
    metadata = material.metadata
    assert metadata.server_dns_identity == IDENTITY
    assert metadata.server_dns_sans == (IDENTITY,)
    assert metadata.ca_certificate_fingerprint.startswith("sha256:")
    assert metadata.server_certificate_fingerprint.startswith("sha256:")
    assert metadata.server_public_key_fingerprint.startswith("sha256:")
    assert metadata.ca_private_key_present is True
    assert metadata.server_private_key_present is True

    certificate = x509.load_pem_x509_certificate(material.server_certificate_pem())
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == [IDENTITY]
    assert certificate.not_valid_before_utc <= NOW < certificate.not_valid_after_utc


def test_material_repr_never_contains_pem_or_private_material(material) -> None:  # noqa: ANN001
    rendered = repr(material)
    assert rendered == (
        "ValidatedTLSMaterial(<redacted>, "
        f"ca={material.metadata.ca_certificate_fingerprint}, "
        f"server={material.metadata.server_certificate_fingerprint}, "
        f"identity={material.metadata.server_dns_identity!r})"
    )
    safe_keys = set(material.metadata.canonical())
    assert "server_private_key_fingerprint" not in safe_keys
    assert "ca_private_key_fingerprint" not in safe_keys


def test_import_normalizes_and_revalidates_generated_material(material) -> None:  # noqa: ANN001
    imported = import_tls_material(
        ca_certificate_pem=b"\n" + material.ca_certificate_pem() + b"\n",
        server_certificate_pem=material.server_certificate_pem(),
        server_private_key_pem=material.server_private_key_pem(),
        expected_dns_identity=IDENTITY,
        now=NOW,
    )
    assert imported.metadata.ca_private_key_present is False
    assert imported.metadata.server_private_key_present is True
    assert imported.metadata.server_certificate_fingerprint == (
        material.metadata.server_certificate_fingerprint
    )


def test_worker_public_import_contains_no_server_private_key(material) -> None:  # noqa: ANN001
    public = import_tls_public_material(
        ca_certificate_pem=material.ca_certificate_pem(),
        server_certificate_pem=material.server_certificate_pem(),
        expected_dns_identity=IDENTITY,
        now=NOW,
    )

    assert public.metadata.ca_certificate_fingerprint == (
        material.metadata.ca_certificate_fingerprint
    )
    assert public.metadata.server_certificate_fingerprint == (
        material.metadata.server_certificate_fingerprint
    )
    assert public.metadata.server_private_key_present is False
    assert not hasattr(public, "server_private_key_pem")
    assert "PRIVATE KEY" not in repr(public)


def test_worker_ca_import_contains_only_the_validated_ca(material) -> None:  # noqa: ANN001
    authority = import_admission_ca(ca_certificate_pem=material.ca_certificate_pem(), now=NOW)

    assert authority.ca_certificate_fingerprint == (material.metadata.ca_certificate_fingerprint)
    assert authority.ca_certificate_content_digest.startswith("sha256:")
    assert x509.load_pem_x509_certificate(authority.ca_certificate_pem()).fingerprint(
        hashes.SHA256()
    ).hex() == authority.ca_certificate_fingerprint.removeprefix("sha256:")
    assert not hasattr(authority, "server_certificate_pem")
    assert not hasattr(authority, "server_private_key_pem")
    assert "BEGIN" not in repr(authority)


def test_worker_ca_import_refuses_malformed_or_expired_ca(material) -> None:  # noqa: ANN001
    with pytest.raises(TLSValidationError) as malformed:
        import_admission_ca(ca_certificate_pem=b"not a CA", now=NOW)
    assert malformed.value.reason_code == "ca_certificate_invalid"

    with pytest.raises(TLSValidationError) as expired:
        import_admission_ca(
            ca_certificate_pem=material.ca_certificate_pem(),
            now=NOW + timedelta(days=31),
        )
    assert expired.value.reason_code == "ca_not_current"


def test_wrong_certificate_identity_or_san_refuses(material) -> None:  # noqa: ANN001
    with pytest.raises(TLSValidationError) as exc:
        import_tls_material(
            ca_certificate_pem=material.ca_certificate_pem(),
            server_certificate_pem=material.server_certificate_pem(),
            server_private_key_pem=material.server_private_key_pem(),
            expected_dns_identity="other.internal.test",
            now=NOW,
        )
    assert exc.value.reason_code == "server_identity_mismatch"


def test_extra_san_refuses(material) -> None:  # noqa: ANN001
    ca_certificate = x509.load_pem_x509_certificate(material.ca_certificate_pem())
    ca_key = serialization.load_pem_private_key(material.ca_private_key_pem(), password=None)
    server_key = serialization.load_pem_private_key(
        material.server_private_key_pem(), password=None
    )
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, IDENTITY)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(minutes=1))
        .not_valid_after(NOW + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(IDENTITY), x509.DNSName("other.internal.test")]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA384())
    )
    with pytest.raises(TLSValidationError) as exc:
        import_tls_material(
            ca_certificate_pem=material.ca_certificate_pem(),
            server_certificate_pem=certificate.public_bytes(serialization.Encoding.PEM),
            server_private_key_pem=material.server_private_key_pem(),
            expected_dns_identity=IDENTITY,
            now=NOW,
        )
    assert exc.value.reason_code == "server_san_invalid"


def test_mismatched_server_private_key_refuses(material) -> None:  # noqa: ANN001
    other = generate_tls_material(dns_identity=IDENTITY, validity_days=30, now=NOW)
    with pytest.raises(TLSValidationError) as exc:
        import_tls_material(
            ca_certificate_pem=material.ca_certificate_pem(),
            server_certificate_pem=material.server_certificate_pem(),
            server_private_key_pem=other.server_private_key_pem(),
            expected_dns_identity=IDENTITY,
            now=NOW,
        )
    assert exc.value.reason_code == "server_private_key_mismatch"


def test_wrong_ca_refuses(material) -> None:  # noqa: ANN001
    other = generate_tls_material(dns_identity=IDENTITY, validity_days=30, now=NOW)
    with pytest.raises(TLSValidationError) as exc:
        import_tls_material(
            ca_certificate_pem=other.ca_certificate_pem(),
            server_certificate_pem=material.server_certificate_pem(),
            server_private_key_pem=material.server_private_key_pem(),
            expected_dns_identity=IDENTITY,
            now=NOW,
        )
    assert exc.value.reason_code in {"server_issuer_mismatch", "server_signature_invalid"}


def test_expired_server_certificate_refuses(material) -> None:  # noqa: ANN001
    with pytest.raises(TLSValidationError) as exc:
        import_tls_material(
            ca_certificate_pem=material.ca_certificate_pem(),
            server_certificate_pem=material.server_certificate_pem(),
            server_private_key_pem=material.server_private_key_pem(),
            expected_dns_identity=IDENTITY,
            now=NOW + timedelta(days=30, hours=12),
        )
    assert exc.value.reason_code == "server_certificate_not_current"


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("ca_certificate_pem", b"not a CA", "ca_certificate_invalid"),
        ("server_certificate_pem", b"not a cert", "server_certificate_invalid"),
        ("server_private_key_pem", b"not a key", "server_private_key_invalid"),
    ],
)
def test_malformed_material_refuses_with_closed_reason(
    material,
    field: str,
    value: bytes,
    reason: str,  # noqa: ANN001
) -> None:
    values = {
        "ca_certificate_pem": material.ca_certificate_pem(),
        "server_certificate_pem": material.server_certificate_pem(),
        "server_private_key_pem": material.server_private_key_pem(),
    }
    values[field] = value
    with pytest.raises(TLSValidationError) as exc:
        import_tls_material(**values, expected_dns_identity=IDENTITY, now=NOW)
    assert exc.value.reason_code == reason
    assert value.decode("ascii") not in repr(exc.value)


@pytest.mark.parametrize(
    ("identity", "days"),
    [
        ("*.internal.test", 30),
        ("10.20.30.40", 30),
        ("Admission.internal.test", 30),
        (IDENTITY, 0),
        (IDENTITY, 826),
        (IDENTITY, 1.0),
        (IDENTITY, True),
    ],
)
def test_generation_refuses_ambiguous_identity_or_validity(identity: str, days: int) -> None:
    with pytest.raises(TLSValidationError):
        generate_tls_material(dns_identity=identity, validity_days=days, now=NOW)


def test_tls_preparation_performs_no_filesystem_or_network_io(monkeypatch) -> None:  # noqa: ANN001
    def forbidden(*_args, **_kwargs):  # noqa: ANN002, ANN003, ANN202
        raise AssertionError("external I/O attempted")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr("socket.socket", forbidden)
    generated = generate_tls_material(dns_identity=IDENTITY, validity_days=1, now=NOW)
    assert generated.metadata.server_dns_identity == IDENTITY


def test_generation_refuses_invalid_or_overflowing_clock() -> None:
    with pytest.raises(TLSValidationError) as exc:
        generate_tls_material(
            dns_identity=IDENTITY,
            validity_days=1,
            now=datetime.max.replace(tzinfo=UTC),
        )
    assert exc.value.reason_code == "tls_validity_invalid"
