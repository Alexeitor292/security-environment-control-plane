"""Root-installer controller-API TLS producer honoring the SIGNED release TLS policy (SECP-PR5H-B2,
commit 2b-2).

The signed ``v1alpha2`` release binds a CLOSED
:class:`~secp_management.release_bundle.ControllerTlsPolicy`
(allowed modes, key/signature algorithm, validity ceiling, SAN/EKU/CA-pathlen requirements,
DNS-vs-IP
origin). At install time the root composition produces the controller-API server identity in ONE of
the two policy-permitted ways and PROVES the produced material conforms to the signed policy before
it
is ever written:

* ``generated_local_ca`` — mint a local CA + exact-DNS-SAN server certificate using the policy's own
  key + signature algorithm, then validate the pair and check every policy field;
* ``imported_enterprise_tls`` — validate an operator-supplied CA/server/key set against the policy.

Every certificate is validated through the mature, plane-shared
:mod:`secp_discovery_activation.tls` primitives (chain, self-issued CA, ``BasicConstraints``
pathlen 0,
``KeyUsage``, EKU == serverAuth, exactly-one-DNS-SAN == identity, validity windows, key/private-key
match), and this module adds the policy-conformance layer on top (key algorithm, signature
algorithm,
validity ceiling, DNS-vs-IP). This module is PURE: it generates/validates entirely in memory and
opens
no path, resolves no DNS, and contacts no peer — the fixed-path install write is a distinct step. It
imports no network / subprocess / API-plane capability.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from secp_discovery_activation.profile import validate_dns_identity
from secp_discovery_activation.tls import (
    TLSValidationError,
    ValidatedTLSMaterial,
    import_tls_material,
)

from secp_management import ManagementError
from secp_management.layout import ManagementLocations
from secp_management.release_bundle import (
    TLS_MODE_GENERATED_LOCAL_CA,
    TLS_MODE_IMPORTED_ENTERPRISE,
    ControllerTlsPolicy,
)

#: Fixed, code-owned controller-API TLS material paths (never descriptor-selected, never a CLI arg),
#: sourced from the authoritative :class:`ManagementLocations`. The CA bundle path is EXACTLY the
#: path
#: the controller-API locator records for secpctl to trust.
_LOCATIONS = ManagementLocations()
CONTROLLER_TLS_DIR = _LOCATIONS.controller_tls_dir()
CONTROLLER_CA_BUNDLE_PATH = _LOCATIONS.controller_ca_bundle_path()
CONTROLLER_SERVER_CERT_PATH = _LOCATIONS.controller_server_cert_path()
CONTROLLER_SERVER_KEY_PATH = _LOCATIONS.controller_server_key_path()

_HARD_MAX_VALIDITY_DAYS = (
    825  # the closed CA/Browser-Forum server-cert ceiling (belt-and-suspenders)
)

#: policy key-algorithm -> an in-memory key generator honoring EXACTLY that algorithm. The concrete
#: return types differ (EC / Ed25519 / RSA private keys) but all support the CertificateBuilder
#: signing surface, so the value type is surfaced as ``Any``.
_KEY_GENERATORS: dict[str, Callable[[], Any]] = {
    "ecdsa-p256": lambda: ec.generate_private_key(ec.SECP256R1()),
    "ecdsa-p384": lambda: ec.generate_private_key(ec.SECP384R1()),
    "ed25519": ed25519.Ed25519PrivateKey.generate,
    "rsa-3072": lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072),
    "rsa-4096": lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096),
}
#: policy signature-algorithm -> the signing hash (ed25519 signs with no external hash: None).
_SIGNATURE_HASHES = {
    "ecdsa-with-sha256": hashes.SHA256(),
    "ecdsa-with-sha384": hashes.SHA384(),
    "sha256-rsa": hashes.SHA256(),
    "sha384-rsa": hashes.SHA384(),
    "ed25519": None,
}


class ControllerTlsError(ManagementError):
    """A bounded, closed controller-TLS refusal — a reason code, never a key/cert/origin byte."""


def _reject(reason_code: str) -> NoReturn:
    raise ControllerTlsError(reason_code)


@dataclass(frozen=True)
class ProducedControllerTls:
    """The validated, policy-conformant controller-API TLS material + its safe facts. Its repr is
    redacted; the private material is reachable only through the explicit accessors."""

    _material: ValidatedTLSMaterial
    mode: str
    dns_identity: str
    key_algorithm: str
    signature_algorithm: str
    validity_days: int

    def __repr__(self) -> str:  # never the origin / certs / key
        return f"ProducedControllerTls(mode={self.mode!r}, <redacted>)"

    def ca_bundle_pem(self) -> bytes:
        return self._material.ca_certificate_pem()

    def server_certificate_pem(self) -> bytes:
        return self._material.server_certificate_pem()

    def server_private_key_pem(self) -> bytes:
        return self._material.server_private_key_pem()

    def safe_metadata(self) -> dict[str, object]:
        """Public certificate facts only (fingerprints, identity, validity) — no private key."""
        return {
            "mode": self.mode,
            "dns_identity": self.dns_identity,
            "key_algorithm": self.key_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "validity_days": self.validity_days,
            **self._material.metadata.canonical(),
        }


# --------------------------------------------------------------------------- identity / policy


def _origin_dns_identity(canonical_origin: str, *, allow_ip_origin: bool) -> str:
    """Extract the host from a canonical ``https://host[:port]`` origin and require it to be a valid
    DNS identity (never an IP unless the signed policy explicitly permits an IP origin)."""
    if not isinstance(canonical_origin, str) or not canonical_origin.startswith("https://"):
        _reject("controller_tls_origin_invalid")
    rest = canonical_origin[len("https://") :]
    host = rest.split("/", 1)[0].split(":", 1)[0]
    if not host:
        _reject("controller_tls_origin_invalid")
    if not allow_ip_origin and _looks_like_ip(host):
        _reject("controller_tls_ip_origin_forbidden")
    try:
        return validate_dns_identity(host)
    except ValueError:
        _reject("controller_tls_origin_invalid")


def _looks_like_ip(host: str) -> bool:
    # a conservative IPv4/IPv6 shape check (the signed policy forbids an IP origin by default).
    if ":" in host:
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _server_key_algorithm(cert: x509.Certificate) -> str:
    key = cert.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"secp256r1": "ecdsa-p256", "secp384r1": "ecdsa-p384"}.get(
            key.curve.name, "unsupported"
        )
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519"
    if isinstance(key, rsa.RSAPublicKey):
        return {3072: "rsa-3072", 4096: "rsa-4096"}.get(key.key_size, "unsupported")
    return "unsupported"


def _signature_algorithm(cert: x509.Certificate) -> str:
    key = cert.public_key()  # the SUBJECT key; for a self-consistent chain the issuer key matches
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519"
    try:
        algo = cert.signature_hash_algorithm
    except Exception:  # noqa: BLE001 - an unknown signature hash is a bounded refusal
        return "unsupported"
    name: str = getattr(algo, "name", "") or ""
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"sha256": "ecdsa-with-sha256", "sha384": "ecdsa-with-sha384"}.get(
            name, "unsupported"
        )
    if isinstance(key, rsa.RSAPublicKey):
        return {"sha256": "sha256-rsa", "sha384": "sha384-rsa"}.get(name, "unsupported")
    return "unsupported"


def _assert_policy_conformant(
    material: ValidatedTLSMaterial, policy: ControllerTlsPolicy, dns_identity: str
) -> tuple[str, str, int]:
    """Prove the produced/imported material conforms to EVERY field of the signed policy. The
    structural facts (self-issued CA pathlen 0, KeyUsage, EKU==serverAuth, exactly-one-DNS-SAN ==
    identity, chain, validity windows, key/private-key match) are already enforced by the shared
    :mod:`secp_discovery_activation.tls` validation; this adds the signed-policy layer."""
    ca = x509.load_pem_x509_certificate(material.ca_certificate_pem())
    server = x509.load_pem_x509_certificate(material.server_certificate_pem())

    # key algorithm: BOTH the CA and the server must use exactly the policy's key algorithm.
    server_alg = _server_key_algorithm(server)
    if server_alg != policy.key_algorithm or _server_key_algorithm(ca) != policy.key_algorithm:
        _reject("controller_tls_key_algorithm_mismatch")

    # signature algorithm: the CA-issued signatures must match the policy's signature algorithm, and
    # that algorithm must be compatible with the key algorithm (the signed policy already binds
    # this,
    # but re-checking closes a mismatched hand-rolled policy).
    sig_alg = _signature_algorithm(server)
    if (
        sig_alg != policy.signature_algorithm
        or _signature_algorithm(ca) != policy.signature_algorithm
    ):
        _reject("controller_tls_signature_algorithm_mismatch")

    # SAN / EKU / CA-pathlen are policy REQUIREMENTS; the shared validation already enforces the
    # strong form, so a policy that (incorrectly) does not require them is refused as too weak.
    if not (policy.require_san and policy.server_auth_eku_required and policy.ca_pathlen_zero):
        _reject("controller_tls_policy_too_weak")

    # validity: the produced server certificate's lifetime must not exceed the signed ceiling (nor
    # the absolute CA/Browser-Forum ceiling). Compare the ACTUAL timedelta, not the floored
    # ``.days`` — an imported cert with a sub-day fraction over the ceiling (e.g. ceiling + 23h)
    # must be refused, not rounded down under the bound.
    not_before = server.not_valid_before_utc
    not_after = server.not_valid_after_utc
    ceiling = min(policy.max_validity_days, _HARD_MAX_VALIDITY_DAYS)
    if not_after <= not_before or not_after > not_before + timedelta(days=ceiling):
        _reject("controller_tls_validity_out_of_bounds")
    validity_days = (not_after - not_before).days

    # the certificate identity must be exactly the origin host (the shared validation binds SAN/CN
    # to
    # the passed identity; assert the passed identity is what we resolved from the origin).
    san = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = [n.value for n in san if isinstance(n, x509.DNSName)]
    if names != [dns_identity]:
        _reject("controller_tls_identity_mismatch")
    return server_alg, sig_alg, validity_days


# --------------------------------------------------------------------------- producers


def _generate_conformant_material(
    policy: ControllerTlsPolicy, dns_identity: str, *, now: datetime
) -> ValidatedTLSMaterial:
    """Mint a local CA + server certificate honoring the policy's exact key + signature algorithm,
    then validate the pair through the shared strict validator."""
    if policy.key_algorithm not in _KEY_GENERATORS:
        _reject("controller_tls_key_algorithm_unsupported")
    if policy.signature_algorithm not in _SIGNATURE_HASHES:
        _reject("controller_tls_signature_algorithm_unsupported")
    validity_days = min(policy.max_validity_days, _HARD_MAX_VALIDITY_DAYS)
    sig_hash = _SIGNATURE_HASHES[policy.signature_algorithm]
    # backdate not_before 5 min for clock skew, and set not_after so the TOTAL span is EXACTLY
    # validity_days — so the strict timedelta ceiling check in _assert_policy_conformant passes for
    # the normal generated path (span == ceiling) while still bounding imports that run over.
    not_before = now - timedelta(minutes=5)
    server_not_after = not_before + timedelta(days=validity_days)
    ca_not_after = server_not_after + timedelta(days=1)

    ca_key = _KEY_GENERATORS[policy.key_algorithm]()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SECP Controller Local CA")])
    ca_cert = (
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
        .sign(ca_key, sig_hash)
    )

    server_key = _KEY_GENERATORS[policy.key_algorithm]()
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, dns_identity)])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(server_not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=isinstance(server_key, rsa.RSAPrivateKey),
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_identity)]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, sig_hash)
    )

    try:
        return import_tls_material(
            ca_certificate_pem=ca_cert.public_bytes(serialization.Encoding.PEM),
            server_certificate_pem=server_cert.public_bytes(serialization.Encoding.PEM),
            server_private_key_pem=server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            expected_dns_identity=dns_identity,
            now=now,
        )
    except TLSValidationError:
        _reject("controller_tls_generation_invalid")


def produce_controller_tls(
    *,
    policy: ControllerTlsPolicy,
    canonical_origin: str,
    mode: str,
    imported_ca_pem: bytes | None = None,
    imported_server_pem: bytes | None = None,
    imported_key_pem: bytes | None = None,
    now: datetime | None = None,
) -> ProducedControllerTls:
    """Produce the controller-API TLS material for ``mode`` (a policy-permitted mode), conformant to
    the signed policy. ``generated_local_ca`` mints locally; ``imported_enterprise_tls`` validates
    an
    operator-supplied set. Any non-conformant input keeps installation sealed (bounded reason)."""
    resolved_now = (datetime.now(UTC) if now is None else now).astimezone(UTC)
    if mode not in (TLS_MODE_GENERATED_LOCAL_CA, TLS_MODE_IMPORTED_ENTERPRISE):
        _reject("controller_tls_mode_unknown")
    if mode not in policy.allowed_modes:
        _reject("controller_tls_mode_not_permitted")
    dns_identity = _origin_dns_identity(canonical_origin, allow_ip_origin=policy.allow_ip_origin)

    if mode == TLS_MODE_GENERATED_LOCAL_CA:
        if not policy.allow_generated_local_ca:
            _reject("controller_tls_generated_ca_not_permitted")
        if imported_ca_pem or imported_server_pem or imported_key_pem:
            _reject("controller_tls_generated_takes_no_material")
        material = _generate_conformant_material(policy, dns_identity, now=resolved_now)
    else:
        if not (imported_ca_pem and imported_server_pem and imported_key_pem):
            _reject("controller_tls_import_material_required")
        try:
            material = import_tls_material(
                ca_certificate_pem=imported_ca_pem,
                server_certificate_pem=imported_server_pem,
                server_private_key_pem=imported_key_pem,
                expected_dns_identity=dns_identity,
                now=resolved_now,
            )
        except TLSValidationError as exc:
            raise ControllerTlsError(f"controller_tls_import_invalid:{exc.reason_code}") from None

    key_alg, sig_alg, validity_days = _assert_policy_conformant(material, policy, dns_identity)
    return ProducedControllerTls(
        _material=material,
        mode=mode,
        dns_identity=dns_identity,
        key_algorithm=key_alg,
        signature_algorithm=sig_alg,
        validity_days=validity_days,
    )


__all__ = [
    "CONTROLLER_CA_BUNDLE_PATH",
    "CONTROLLER_SERVER_CERT_PATH",
    "CONTROLLER_SERVER_KEY_PATH",
    "CONTROLLER_TLS_DIR",
    "ControllerTlsError",
    "ProducedControllerTls",
    "produce_controller_tls",
]
