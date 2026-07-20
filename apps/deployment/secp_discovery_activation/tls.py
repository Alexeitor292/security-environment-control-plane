"""In-memory TLS import/generation and strict certificate validation.

No function in this module opens a path, resolves DNS, or contacts a peer.  Private material is
held only in a slots-based object whose ``repr``/``str`` are redacted.  Safe metadata contains
certificate and public-key fingerprints, exact identity/validity, and presence booleans; it never
contains a private-key fingerprint or raw PEM.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    padding,
    rsa,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from secp_discovery_activation import DiscoveryActivationError
from secp_discovery_activation.profile import validate_dns_identity

_MAX_CERTIFICATE_BYTES = 32 * 1024
_MAX_PRIVATE_KEY_BYTES = 64 * 1024
_MAX_GENERATED_VALIDITY_DAYS = 825
_MATERIAL_CONSTRUCTION_TOKEN = object()


class TLSValidationError(DiscoveryActivationError):
    """TLS material was refused with a closed reason code."""


def _fingerprint(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _iso8601(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class TLSMaterialMetadata:
    """Safe TLS facts suitable for plans, manifests, status, and evidence."""

    ca_certificate_fingerprint: str
    server_certificate_fingerprint: str
    server_public_key_fingerprint: str
    server_dns_identity: str
    server_dns_sans: tuple[str, ...]
    ca_not_before: str
    ca_not_after: str
    server_not_before: str
    server_not_after: str
    ca_certificate_present: bool = True
    server_certificate_present: bool = True
    server_private_key_present: bool = True
    ca_private_key_present: bool = False

    def canonical(self) -> dict[str, Any]:
        return {
            "ca_certificate_fingerprint": self.ca_certificate_fingerprint,
            "server_certificate_fingerprint": self.server_certificate_fingerprint,
            "server_public_key_fingerprint": self.server_public_key_fingerprint,
            "server_dns_identity": self.server_dns_identity,
            "server_dns_sans": list(self.server_dns_sans),
            "ca_not_before": self.ca_not_before,
            "ca_not_after": self.ca_not_after,
            "server_not_before": self.server_not_before,
            "server_not_after": self.server_not_after,
            "ca_certificate_present": self.ca_certificate_present,
            "server_certificate_present": self.server_certificate_present,
            "server_private_key_present": self.server_private_key_present,
            "ca_private_key_present": self.ca_private_key_present,
        }


class ValidatedTLSMaterial:
    """Validated normalized PEM held in memory with an intentionally redacted representation."""

    _ca_certificate_pem: bytes
    _server_certificate_pem: bytes
    _server_private_key_pem: bytes
    _ca_private_key_pem: bytes | None
    metadata: TLSMaterialMetadata

    __slots__ = (
        "_ca_certificate_pem",
        "_server_certificate_pem",
        "_server_private_key_pem",
        "_ca_private_key_pem",
        "metadata",
    )

    def __init__(
        self,
        *,
        ca_certificate_pem: bytes,
        server_certificate_pem: bytes,
        server_private_key_pem: bytes,
        ca_private_key_pem: bytes | None,
        metadata: TLSMaterialMetadata,
        _token: object | None = None,
    ) -> None:
        if _token is not _MATERIAL_CONSTRUCTION_TOKEN:
            raise TLSValidationError("tls_material_construction_forbidden")
        object.__setattr__(self, "_ca_certificate_pem", ca_certificate_pem)
        object.__setattr__(self, "_server_certificate_pem", server_certificate_pem)
        object.__setattr__(self, "_server_private_key_pem", server_private_key_pem)
        object.__setattr__(self, "_ca_private_key_pem", ca_private_key_pem)
        object.__setattr__(self, "metadata", metadata)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("validated TLS material is immutable")

    def __repr__(self) -> str:
        return (
            "ValidatedTLSMaterial(<redacted>, "
            f"ca={self.metadata.ca_certificate_fingerprint}, "
            f"server={self.metadata.server_certificate_fingerprint}, "
            f"identity={self.metadata.server_dns_identity!r})"
        )

    __str__ = __repr__

    # Explicit trusted-installer accessors.  These values are never used by render manifests or
    # representations; callers must opt in to handling secret bytes.
    def ca_certificate_pem(self) -> bytes:
        return self._ca_certificate_pem

    def server_certificate_pem(self) -> bytes:
        return self._server_certificate_pem

    def server_private_key_pem(self) -> bytes:
        return self._server_private_key_pem

    def ca_private_key_pem(self) -> bytes | None:
        return self._ca_private_key_pem


class ValidatedTLSPublicMaterial:
    """Validated CA/server certificates for the worker host; contains no private key."""

    _ca_certificate_pem: bytes
    _server_certificate_pem: bytes
    metadata: TLSMaterialMetadata

    __slots__ = ("_ca_certificate_pem", "_server_certificate_pem", "metadata")

    def __init__(
        self,
        *,
        ca_certificate_pem: bytes,
        server_certificate_pem: bytes,
        metadata: TLSMaterialMetadata,
        _token: object | None = None,
    ) -> None:
        if _token is not _MATERIAL_CONSTRUCTION_TOKEN:
            raise TLSValidationError("tls_material_construction_forbidden")
        object.__setattr__(self, "_ca_certificate_pem", ca_certificate_pem)
        object.__setattr__(self, "_server_certificate_pem", server_certificate_pem)
        object.__setattr__(self, "metadata", metadata)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("validated TLS public material is immutable")

    def __repr__(self) -> str:
        return (
            "ValidatedTLSPublicMaterial(<certificates-redacted>, "
            f"ca={self.metadata.ca_certificate_fingerprint}, "
            f"server={self.metadata.server_certificate_fingerprint}, "
            f"identity={self.metadata.server_dns_identity!r})"
        )

    __str__ = __repr__

    def ca_certificate_pem(self) -> bytes:
        return self._ca_certificate_pem

    def server_certificate_pem(self) -> bytes:
        return self._server_certificate_pem


class ValidatedAdmissionCA:
    """One validated CA certificate for the ordinary-worker host.

    This is the deliberately narrower production handoff type.  It has no server-certificate or
    private-key accessor: the independently signed controller offer supplies the expected server
    fingerprint/identity, and the worker proves those facts with a live pinned TLS handshake.
    """

    _ca_certificate_pem: bytes
    ca_certificate_content_digest: str
    ca_certificate_fingerprint: str
    ca_not_before: str
    ca_not_after: str

    __slots__ = (
        "_ca_certificate_pem",
        "ca_certificate_content_digest",
        "ca_certificate_fingerprint",
        "ca_not_before",
        "ca_not_after",
    )

    def __init__(
        self,
        *,
        ca_certificate_pem: bytes,
        ca_certificate_content_digest: str,
        ca_certificate_fingerprint: str,
        ca_not_before: str,
        ca_not_after: str,
        _token: object | None = None,
    ) -> None:
        if _token is not _MATERIAL_CONSTRUCTION_TOKEN:
            raise TLSValidationError("tls_material_construction_forbidden")
        object.__setattr__(self, "_ca_certificate_pem", ca_certificate_pem)
        object.__setattr__(self, "ca_certificate_content_digest", ca_certificate_content_digest)
        object.__setattr__(self, "ca_certificate_fingerprint", ca_certificate_fingerprint)
        object.__setattr__(self, "ca_not_before", ca_not_before)
        object.__setattr__(self, "ca_not_after", ca_not_after)

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("validated admission CA is immutable")

    def __repr__(self) -> str:
        return f"ValidatedAdmissionCA(<certificate-redacted>, ca={self.ca_certificate_fingerprint})"

    __str__ = __repr__

    def ca_certificate_pem(self) -> bytes:
        return self._ca_certificate_pem


def _now_utc(now: datetime | None) -> datetime:
    resolved = datetime.now(UTC) if now is None else now
    if (
        not isinstance(resolved, datetime)
        or resolved.tzinfo is None
        or resolved.utcoffset() is None
    ):
        raise TLSValidationError("tls_time_invalid")
    return resolved.astimezone(UTC)


def _load_one_certificate(raw: bytes, reason: str) -> x509.Certificate:
    if not isinstance(raw, bytes) or not (1 <= len(raw) <= _MAX_CERTIFICATE_BYTES):
        raise TLSValidationError(reason)
    stripped = raw.strip()
    if (
        stripped.count(b"-----BEGIN CERTIFICATE-----") != 1
        or stripped.count(b"-----END CERTIFICATE-----") != 1
        or not stripped.startswith(b"-----BEGIN CERTIFICATE-----")
        or not stripped.endswith(b"-----END CERTIFICATE-----")
    ):
        raise TLSValidationError(reason)
    try:
        certificates = x509.load_pem_x509_certificates(stripped + b"\n")
    except ValueError:
        raise TLSValidationError(reason) from None
    if len(certificates) != 1:
        raise TLSValidationError(reason)
    return certificates[0]


def _load_private_key(raw: bytes) -> Any:
    if not isinstance(raw, bytes) or not (1 <= len(raw) <= _MAX_PRIVATE_KEY_BYTES):
        raise TLSValidationError("server_private_key_invalid")
    stripped = raw.strip()
    if (
        stripped.count(b"-----BEGIN ") != 1
        or stripped.count(b"PRIVATE KEY-----") != 2
        or b"ENCRYPTED PRIVATE KEY" in stripped
        or not stripped.startswith(b"-----BEGIN ")
        or not stripped.endswith(b"PRIVATE KEY-----")
    ):
        raise TLSValidationError("server_private_key_invalid")
    try:
        key = serialization.load_pem_private_key(stripped + b"\n", password=None)
    except (TypeError, UnsupportedAlgorithm, ValueError):
        raise TLSValidationError("server_private_key_invalid") from None
    _validate_public_key(key.public_key(), "server_private_key_algorithm_invalid")
    return key


def _validate_public_key(key: Any, reason: str) -> None:
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            raise TLSValidationError(reason)
        return
    if isinstance(key, ec.EllipticCurvePublicKey):
        if key.curve.key_size < 256:
            raise TLSValidationError(reason)
        return
    if isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        return
    raise TLSValidationError(reason)


def _validate_signature_algorithm(certificate: x509.Certificate) -> None:
    try:
        algorithm = certificate.signature_hash_algorithm
    except UnsupportedAlgorithm:
        raise TLSValidationError("certificate_signature_algorithm_invalid") from None
    if algorithm is not None and algorithm.name not in {"sha256", "sha384", "sha512"}:
        raise TLSValidationError("certificate_signature_algorithm_invalid")


def _verify_signature(certificate: x509.Certificate, issuer: x509.Certificate, reason: str) -> None:
    _validate_signature_algorithm(certificate)
    public_key = issuer.public_key()
    try:
        hash_algorithm = certificate.signature_hash_algorithm
    except UnsupportedAlgorithm:
        raise TLSValidationError(reason) from None
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if hash_algorithm is None:
                raise TLSValidationError(reason)
            parameters = certificate.signature_algorithm_parameters
            rsa_padding = (
                parameters
                if isinstance(parameters, padding.AsymmetricPadding)
                else padding.PKCS1v15()
            )
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                rsa_padding,
                hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if hash_algorithm is None:
                raise TLSValidationError(reason)
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(hash_algorithm),
            )
        elif isinstance(public_key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
            public_key.verify(certificate.signature, certificate.tbs_certificate_bytes)
        else:
            raise TLSValidationError(reason)
    except TLSValidationError:
        raise
    except Exception:
        raise TLSValidationError(reason) from None


def _extension(
    certificate: x509.Certificate,
    extension_type: type[Any],
    reason: str,
    *,
    critical: bool | None = None,
) -> Any:
    try:
        extension = certificate.extensions.get_extension_for_class(extension_type)
    except x509.ExtensionNotFound:
        raise TLSValidationError(reason) from None
    if critical is not None and extension.critical is not critical:
        raise TLSValidationError(reason)
    return extension.value


def _validate_ca(certificate: x509.Certificate, now: datetime) -> None:
    if certificate.subject != certificate.issuer or not certificate.subject:
        raise TLSValidationError("ca_not_self_issued")
    _validate_public_key(certificate.public_key(), "ca_public_key_algorithm_invalid")
    constraints = _extension(
        certificate, x509.BasicConstraints, "ca_constraints_missing", critical=True
    )
    if not constraints.ca or constraints.path_length != 0:
        raise TLSValidationError("ca_constraints_invalid")
    usage = _extension(certificate, x509.KeyUsage, "ca_key_usage_missing", critical=True)
    if not usage.key_cert_sign or not usage.crl_sign:
        raise TLSValidationError("ca_key_usage_invalid")
    if not (certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc):
        raise TLSValidationError("ca_not_current")
    _verify_signature(certificate, certificate, "ca_signature_invalid")


def import_admission_ca(
    *, ca_certificate_pem: bytes, now: datetime | None = None
) -> ValidatedAdmissionCA:
    """Validate and normalize the sole TLS artifact transferred to the worker host."""

    resolved_now = _now_utc(now)
    certificate = _load_one_certificate(ca_certificate_pem, "ca_certificate_invalid")
    _validate_ca(certificate, resolved_now)
    normalized = certificate.public_bytes(serialization.Encoding.PEM)
    return ValidatedAdmissionCA(
        ca_certificate_pem=normalized,
        ca_certificate_content_digest=_fingerprint(normalized),
        ca_certificate_fingerprint=_fingerprint(
            certificate.public_bytes(serialization.Encoding.DER)
        ),
        ca_not_before=_iso8601(certificate.not_valid_before_utc),
        ca_not_after=_iso8601(certificate.not_valid_after_utc),
        _token=_MATERIAL_CONSTRUCTION_TOKEN,
    )


def _validate_server(
    certificate: x509.Certificate,
    *,
    ca_certificate: x509.Certificate,
    expected_dns_identity: str,
    now: datetime,
) -> tuple[str, ...]:
    _validate_public_key(certificate.public_key(), "server_public_key_algorithm_invalid")
    if certificate.issuer != ca_certificate.subject:
        raise TLSValidationError("server_issuer_mismatch")
    _verify_signature(certificate, ca_certificate, "server_signature_invalid")
    if not (certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc):
        raise TLSValidationError("server_certificate_not_current")
    if (
        certificate.not_valid_before_utc < ca_certificate.not_valid_before_utc
        or certificate.not_valid_after_utc > ca_certificate.not_valid_after_utc
    ):
        raise TLSValidationError("server_validity_outside_ca")

    constraints = _extension(
        certificate, x509.BasicConstraints, "server_constraints_missing", critical=True
    )
    if constraints.ca:
        raise TLSValidationError("server_constraints_invalid")
    usage = _extension(certificate, x509.KeyUsage, "server_key_usage_missing", critical=True)
    if not usage.digital_signature or usage.key_cert_sign or usage.crl_sign:
        raise TLSValidationError("server_key_usage_invalid")
    extended = _extension(certificate, x509.ExtendedKeyUsage, "server_eku_missing")
    if tuple(extended) != (ExtendedKeyUsageOID.SERVER_AUTH,):
        raise TLSValidationError("server_eku_invalid")

    san = _extension(certificate, x509.SubjectAlternativeName, "server_san_missing")
    names = tuple(san)
    if len(names) != 1 or not isinstance(names[0], x509.DNSName):
        raise TLSValidationError("server_san_invalid")
    dns_sans = (names[0].value,)
    if dns_sans != (expected_dns_identity,):
        raise TLSValidationError("server_identity_mismatch")
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != expected_dns_identity:
        raise TLSValidationError("server_common_name_mismatch")
    return dns_sans


def _validated_certificate_pair(
    *,
    ca_certificate_pem: bytes,
    server_certificate_pem: bytes,
    expected_dns_identity: str,
    now: datetime | None,
) -> tuple[x509.Certificate, x509.Certificate, str, tuple[str, ...], bytes]:
    try:
        identity = validate_dns_identity(expected_dns_identity)
    except ValueError:
        raise TLSValidationError("tls_identity_invalid") from None
    resolved_now = _now_utc(now)
    ca_certificate = _load_one_certificate(ca_certificate_pem, "ca_certificate_invalid")
    server_certificate = _load_one_certificate(server_certificate_pem, "server_certificate_invalid")
    _validate_ca(ca_certificate, resolved_now)
    dns_sans = _validate_server(
        server_certificate,
        ca_certificate=ca_certificate,
        expected_dns_identity=identity,
        now=resolved_now,
    )
    server_public_der = server_certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return ca_certificate, server_certificate, identity, dns_sans, server_public_der


def _certificate_metadata(
    *,
    ca_certificate: x509.Certificate,
    server_certificate: x509.Certificate,
    identity: str,
    dns_sans: tuple[str, ...],
    server_public_der: bytes,
    server_private_key_present: bool,
) -> TLSMaterialMetadata:
    return TLSMaterialMetadata(
        ca_certificate_fingerprint=_fingerprint(
            ca_certificate.public_bytes(serialization.Encoding.DER)
        ),
        server_certificate_fingerprint=_fingerprint(
            server_certificate.public_bytes(serialization.Encoding.DER)
        ),
        server_public_key_fingerprint=_fingerprint(server_public_der),
        server_dns_identity=identity,
        server_dns_sans=dns_sans,
        ca_not_before=_iso8601(ca_certificate.not_valid_before_utc),
        ca_not_after=_iso8601(ca_certificate.not_valid_after_utc),
        server_not_before=_iso8601(server_certificate.not_valid_before_utc),
        server_not_after=_iso8601(server_certificate.not_valid_after_utc),
        server_private_key_present=server_private_key_present,
    )


def import_tls_public_material(
    *,
    ca_certificate_pem: bytes,
    server_certificate_pem: bytes,
    expected_dns_identity: str,
    now: datetime | None = None,
) -> ValidatedTLSPublicMaterial:
    """Validate the exact public TLS pair transferred to the worker host.

    This parser has no private-key parameter by design.  The returned metadata truthfully marks
    ``server_private_key_present=False`` and its representation contains fingerprints only.
    """

    ca_certificate, server_certificate, identity, dns_sans, server_public_der = (
        _validated_certificate_pair(
            ca_certificate_pem=ca_certificate_pem,
            server_certificate_pem=server_certificate_pem,
            expected_dns_identity=expected_dns_identity,
            now=now,
        )
    )
    normalized_ca = ca_certificate.public_bytes(serialization.Encoding.PEM)
    normalized_server = server_certificate.public_bytes(serialization.Encoding.PEM)
    metadata = _certificate_metadata(
        ca_certificate=ca_certificate,
        server_certificate=server_certificate,
        identity=identity,
        dns_sans=dns_sans,
        server_public_der=server_public_der,
        server_private_key_present=False,
    )
    return ValidatedTLSPublicMaterial(
        ca_certificate_pem=normalized_ca,
        server_certificate_pem=normalized_server,
        metadata=metadata,
        _token=_MATERIAL_CONSTRUCTION_TOKEN,
    )


def import_tls_material(
    *,
    ca_certificate_pem: bytes,
    server_certificate_pem: bytes,
    server_private_key_pem: bytes,
    expected_dns_identity: str,
    now: datetime | None = None,
) -> ValidatedTLSMaterial:
    """Normalize and fully validate an imported CA/server-certificate/private-key set."""
    ca_certificate, server_certificate, identity, dns_sans, server_public_der = (
        _validated_certificate_pair(
            ca_certificate_pem=ca_certificate_pem,
            server_certificate_pem=server_certificate_pem,
            expected_dns_identity=expected_dns_identity,
            now=now,
        )
    )
    private_key = _load_private_key(server_private_key_pem)
    private_public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if server_public_der != private_public_der:
        raise TLSValidationError("server_private_key_mismatch")

    normalized_ca = ca_certificate.public_bytes(serialization.Encoding.PEM)
    normalized_server = server_certificate.public_bytes(serialization.Encoding.PEM)
    normalized_private_key = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    metadata = _certificate_metadata(
        ca_certificate=ca_certificate,
        server_certificate=server_certificate,
        identity=identity,
        dns_sans=dns_sans,
        server_public_der=server_public_der,
        server_private_key_present=True,
    )
    return ValidatedTLSMaterial(
        ca_certificate_pem=normalized_ca,
        server_certificate_pem=normalized_server,
        server_private_key_pem=normalized_private_key,
        ca_private_key_pem=None,
        metadata=metadata,
        _token=_MATERIAL_CONSTRUCTION_TOKEN,
    )


def generate_tls_material(
    *,
    dns_identity: str,
    validity_days: int = 365,
    now: datetime | None = None,
) -> ValidatedTLSMaterial:
    """Generate a local CA and exact-DNS-SAN server identity, entirely in memory."""
    try:
        identity = validate_dns_identity(dns_identity)
    except ValueError:
        raise TLSValidationError("tls_identity_invalid") from None
    if type(validity_days) is not int or not (1 <= validity_days <= _MAX_GENERATED_VALIDITY_DAYS):
        raise TLSValidationError("tls_validity_invalid")
    resolved_now = _now_utc(now)
    try:
        not_before = resolved_now - timedelta(minutes=5)
        server_not_after = resolved_now + timedelta(days=validity_days)
        ca_not_after = server_not_after + timedelta(days=1)
    except (OverflowError, ValueError):
        raise TLSValidationError("tls_validity_invalid") from None

    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SECP Discovery Local CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(ca_not_after)
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA384())
    )

    server_key = ec.generate_private_key(ec.SECP256R1())
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity)])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_certificate.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(server_not_after)
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
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA384())
    )

    ca_certificate_pem = ca_certificate.public_bytes(serialization.Encoding.PEM)
    server_certificate_pem = server_certificate.public_bytes(serialization.Encoding.PEM)
    server_private_key_pem = server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    validated = import_tls_material(
        ca_certificate_pem=ca_certificate_pem,
        server_certificate_pem=server_certificate_pem,
        server_private_key_pem=server_private_key_pem,
        expected_dns_identity=identity,
        now=resolved_now,
    )
    ca_private_key_pem = ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    metadata = TLSMaterialMetadata(
        **{
            **validated.metadata.canonical(),
            "server_dns_sans": validated.metadata.server_dns_sans,
            "ca_private_key_present": True,
        }
    )
    return ValidatedTLSMaterial(
        ca_certificate_pem=validated.ca_certificate_pem(),
        server_certificate_pem=validated.server_certificate_pem(),
        server_private_key_pem=validated.server_private_key_pem(),
        ca_private_key_pem=ca_private_key_pem,
        metadata=metadata,
        _token=_MATERIAL_CONSTRUCTION_TOKEN,
    )


__all__ = [
    "TLSValidationError",
    "TLSMaterialMetadata",
    "ValidatedTLSMaterial",
    "ValidatedTLSPublicMaterial",
    "ValidatedAdmissionCA",
    "import_admission_ca",
    "import_tls_material",
    "import_tls_public_material",
    "generate_tls_material",
]
