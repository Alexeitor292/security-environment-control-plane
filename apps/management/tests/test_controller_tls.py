"""Root-installer controller-API TLS producer (SECP-PR5H-B2, commit 2b-2).

Proves the producer honors the SIGNED ``ControllerTlsPolicy``: it generates a policy-conformant
local
CA + server identity (exact key + signature algorithm, DNS SAN == origin host, EKU serverAuth, CA
pathlen 0, validity within the ceiling), validates an imported enterprise set the same way, and
refuses every off-policy escape (unpermitted mode, IP origin, algorithm mismatch, over-long
validity,
a too-weak policy). Cryptography is cross-platform, so this runs everywhere (no POSIX gate).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from secp_management import ManagementError
from secp_management.controller_tls import (
    CONTROLLER_CA_BUNDLE_PATH,
    ControllerTlsError,
    produce_controller_tls,
)
from secp_management.release_bundle import ControllerTlsPolicy

_ORIGIN = "https://controller.secp.example:8443"
_IDENTITY = "controller.secp.example"


def _policy(**over) -> ControllerTlsPolicy:
    base = {
        "allowed_modes": ("generated_local_ca", "imported_enterprise_tls"),
        "key_algorithm": "ecdsa-p256",
        "signature_algorithm": "ecdsa-with-sha256",
        "max_validity_days": 825,
        "require_san": True,
        "server_auth_eku_required": True,
        "ca_pathlen_zero": True,
        "min_tls_version": "1.3",
        "allow_ip_origin": False,
        "allow_generated_local_ca": True,
    }
    base.update(over)
    return ControllerTlsPolicy(**base)


# --- generated_local_ca -----------------------------------------------------------------------


def test_generated_local_ca_is_policy_conformant():
    produced = produce_controller_tls(
        policy=_policy(), canonical_origin=_ORIGIN, mode="generated_local_ca"
    )
    assert produced.mode == "generated_local_ca"
    assert produced.dns_identity == _IDENTITY
    assert produced.key_algorithm == "ecdsa-p256"
    assert produced.signature_algorithm == "ecdsa-with-sha256"
    assert 1 <= produced.validity_days <= 825
    # the produced CA bundle is a single valid CA cert with pathlen 0 + serverAuth server chain
    ca = x509.load_pem_x509_certificate(produced.ca_bundle_pem())
    server = x509.load_pem_x509_certificate(produced.server_certificate_pem())
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0
    san = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [n.value for n in san] == [_IDENTITY]
    eku = server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert tuple(eku) == (ExtendedKeyUsageOID.SERVER_AUTH,)
    # the fixed CA-bundle path is exactly what the locator will trust
    assert CONTROLLER_CA_BUNDLE_PATH == "/etc/secp/controller/tls/ca-bundle.pem"


def test_generated_local_ca_honors_the_policy_algorithm_p384():
    produced = produce_controller_tls(
        policy=_policy(key_algorithm="ecdsa-p384", signature_algorithm="ecdsa-with-sha384"),
        canonical_origin=_ORIGIN,
        mode="generated_local_ca",
    )
    assert produced.key_algorithm == "ecdsa-p384"
    assert produced.signature_algorithm == "ecdsa-with-sha384"
    server = x509.load_pem_x509_certificate(produced.server_certificate_pem())
    assert server.public_key().curve.name == "secp384r1"


def test_generated_validity_is_clamped_to_the_policy_ceiling():
    produced = produce_controller_tls(
        policy=_policy(max_validity_days=30), canonical_origin=_ORIGIN, mode="generated_local_ca"
    )
    assert produced.validity_days == 30


@pytest.mark.parametrize(
    "over,mode,reason",
    [
        (
            {"allowed_modes": ("imported_enterprise_tls",)},
            "generated_local_ca",
            "controller_tls_mode_not_permitted",
        ),
        (
            {"allow_generated_local_ca": False, "allowed_modes": ("generated_local_ca",)},
            "generated_local_ca",
            "controller_tls_generated_ca_not_permitted",
        ),
    ],
)
def test_generated_refusals(over, mode, reason):
    with pytest.raises(ManagementError) as e:
        produce_controller_tls(policy=_policy(**over), canonical_origin=_ORIGIN, mode=mode)
    assert e.value.reason_code == reason


def test_ip_origin_is_refused_when_the_policy_forbids_it():
    with pytest.raises(ControllerTlsError) as e:
        produce_controller_tls(
            policy=_policy(), canonical_origin="https://10.0.0.5:8443", mode="generated_local_ca"
        )
    assert e.value.reason_code == "controller_tls_ip_origin_forbidden"


def test_unknown_mode_is_refused():
    with pytest.raises(ManagementError) as e:
        produce_controller_tls(policy=_policy(), canonical_origin=_ORIGIN, mode="acme_http_01")
    assert e.value.reason_code == "controller_tls_mode_unknown"


def test_a_too_weak_policy_is_refused():
    # a policy that (incorrectly) does not require SAN/EKU/pathlen is refused as too weak, even
    # though
    # the generator itself always emits the strong form.
    with pytest.raises(ManagementError) as e:
        produce_controller_tls(
            policy=_policy(require_san=False), canonical_origin=_ORIGIN, mode="generated_local_ca"
        )
    assert e.value.reason_code == "controller_tls_policy_too_weak"


# --- imported_enterprise_tls ------------------------------------------------------------------


def _mint_enterprise_set(identity: str, *, validity_days: int = 90):
    """A well-formed enterprise CA/server/key set (ECDSA P256 / SHA256) for the default policy."""
    now = datetime.now(UTC)
    not_before = now - timedelta(minutes=5)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Enterprise Root CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(now + timedelta(days=validity_days + 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    server = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity)]))
        .issuer_name(ca.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(now + timedelta(days=validity_days))
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
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(identity)]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return (
        ca.public_bytes(serialization.Encoding.PEM),
        server.public_bytes(serialization.Encoding.PEM),
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def test_imported_enterprise_tls_is_validated_against_the_policy():
    ca_pem, server_pem, key_pem = _mint_enterprise_set(_IDENTITY)
    produced = produce_controller_tls(
        policy=_policy(),
        canonical_origin=_ORIGIN,
        mode="imported_enterprise_tls",
        imported_ca_pem=ca_pem,
        imported_server_pem=server_pem,
        imported_key_pem=key_pem,
    )
    assert produced.mode == "imported_enterprise_tls"
    assert produced.dns_identity == _IDENTITY
    assert produced.key_algorithm == "ecdsa-p256"


def test_imported_material_is_required_for_the_import_mode():
    with pytest.raises(ManagementError) as e:
        produce_controller_tls(
            policy=_policy(), canonical_origin=_ORIGIN, mode="imported_enterprise_tls"
        )
    assert e.value.reason_code == "controller_tls_import_material_required"


def test_imported_material_for_the_wrong_identity_is_refused():
    ca_pem, server_pem, key_pem = _mint_enterprise_set("other.host.example")
    with pytest.raises(ControllerTlsError) as e:
        produce_controller_tls(
            policy=_policy(),
            canonical_origin=_ORIGIN,
            mode="imported_enterprise_tls",
            imported_ca_pem=ca_pem,
            imported_server_pem=server_pem,
            imported_key_pem=key_pem,
        )
    assert e.value.reason_code.startswith("controller_tls_import_invalid")


def test_imported_material_with_a_wrong_key_algorithm_is_refused():
    # policy demands p256; an imported p384 set is structurally valid but off-policy.
    ca_pem, server_pem, key_pem = _mint_enterprise_set(_IDENTITY)
    with pytest.raises(ControllerTlsError) as e:
        produce_controller_tls(
            policy=_policy(key_algorithm="ecdsa-p384", signature_algorithm="ecdsa-with-sha384"),
            canonical_origin=_ORIGIN,
            mode="imported_enterprise_tls",
            imported_ca_pem=ca_pem,
            imported_server_pem=server_pem,
            imported_key_pem=key_pem,
        )
    assert e.value.reason_code == "controller_tls_key_algorithm_mismatch"


def test_imported_validity_just_over_the_ceiling_is_refused():
    # span == ceiling days + 5 min: the earlier floored-.days check let this pass at ceiling=90; the
    # timedelta check must refuse a lifetime that exceeds the ceiling by any amount.
    ca_pem, server_pem, key_pem = _mint_enterprise_set(_IDENTITY, validity_days=90)
    with pytest.raises(ControllerTlsError) as e:
        produce_controller_tls(
            policy=_policy(max_validity_days=90),
            canonical_origin=_ORIGIN,
            mode="imported_enterprise_tls",
            imported_ca_pem=ca_pem,
            imported_server_pem=server_pem,
            imported_key_pem=key_pem,
        )
    assert e.value.reason_code == "controller_tls_validity_out_of_bounds"


def test_imported_validity_within_the_ceiling_passes():
    ca_pem, server_pem, key_pem = _mint_enterprise_set(_IDENTITY, validity_days=89)
    produced = produce_controller_tls(
        policy=_policy(max_validity_days=90),
        canonical_origin=_ORIGIN,
        mode="imported_enterprise_tls",
        imported_ca_pem=ca_pem,
        imported_server_pem=server_pem,
        imported_key_pem=key_pem,
    )
    assert produced.validity_days == 89


def test_private_material_never_appears_in_the_repr():
    produced = produce_controller_tls(
        policy=_policy(), canonical_origin=_ORIGIN, mode="generated_local_ca"
    )
    text = repr(produced)
    key_pem = produced.server_private_key_pem()
    assert b"PRIVATE KEY" in key_pem  # the accessor returns the real private material...
    assert "redacted" in text
    assert "PRIVATE KEY" not in text and "BEGIN" not in text  # ...but the repr never exposes it
