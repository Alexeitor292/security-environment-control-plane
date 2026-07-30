"""Root-installer controller-API TLS producer honoring the SIGNED release TLS policy (SECP-PR5H-B2,
commit 2b-2).

The signed ``v1alpha2`` release binds a CLOSED
:class:`~secp_management.release_bundle.ControllerTlsPolicy` (allowed modes, key/signature
algorithm,
validity ceiling, SAN/EKU/CA-pathlen requirements, DNS-vs-IP origin). At install time the root
composition produces the controller-API server identity in ONE of the two policy-permitted ways and
PROVES the produced material conforms to the signed policy before it is ever written:

* ``generated_local_ca`` — mint a local CA + exact-DNS-SAN server certificate using the policy's own
  key + signature algorithm, then fully validate the pair and check every policy field;
* ``imported_enterprise_tls`` — validate an operator-supplied CA/server/key set against the policy.

The X.509 generation + strict validation (chain, self-issued CA, ``BasicConstraints`` pathlen 0,
``KeyUsage``, EKU == serverAuth, exactly-one-DNS-SAN == identity, key/private-key match, validity
windows) is implemented IN THIS MODULE with :mod:`cryptography` — the management plane may not
import
the PR5F deployment-authority ``secp_discovery_activation`` package (an enforced plane boundary).
This
module is PURE: it generates/validates entirely in memory and opens no path, resolves no DNS, and
contacts no peer — the fixed-path install write is a distinct step. It reaches no network /
subprocess
/ API-plane capability.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

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
_MAX_CERT_BYTES = 32 * 1024
_MAX_KEY_BYTES = 64 * 1024
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

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
_SIGNATURE_HASHES: dict[str, Any] = {
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

    _ca_bundle_pem: bytes
    _server_cert_pem: bytes
    _server_key_pem: bytes
    mode: str
    dns_identity: str
    key_algorithm: str
    signature_algorithm: str
    validity_days: int
    _facts: dict[str, str]

    def __repr__(self) -> str:  # never the origin / certs / key
        return f"ProducedControllerTls(mode={self.mode!r}, <redacted>)"

    def ca_bundle_pem(self) -> bytes:
        return self._ca_bundle_pem

    def server_certificate_pem(self) -> bytes:
        return self._server_cert_pem

    def server_private_key_pem(self) -> bytes:
        return self._server_key_pem

    def safe_metadata(self) -> dict[str, object]:
        """Public certificate facts only (fingerprints, identity, validity) — no private key."""
        return {
            "mode": self.mode,
            "dns_identity": self.dns_identity,
            "key_algorithm": self.key_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "validity_days": self.validity_days,
            **self._facts,
        }


# --------------------------------------------------------------------------- identity / origin


def _looks_like_ip(host: str) -> bool:
    # a conservative IPv4/IPv6 shape check (the signed policy forbids an IP origin by default).
    if ":" in host:
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def _validate_dns_identity(host: str) -> str:
    """A bounded DNS identity: 1..253 chars, non-empty labels of ``[a-z0-9-]`` not hyphen-edged,
    at least two labels, never all-numeric (an IP is handled separately)."""
    if not isinstance(host, str) or not (1 <= len(host) <= 253) or host.endswith("."):
        _reject("controller_tls_origin_invalid")
    labels = host.split(".")
    if len(labels) < 2 or not all(_DNS_LABEL.fullmatch(label) for label in labels):
        _reject("controller_tls_origin_invalid")
    return host


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
    return _validate_dns_identity(host)


# --------------------------------------------------------------------------- X.509 validation


def _load_cert(raw: bytes, reason: str) -> x509.Certificate:
    if not isinstance(raw, bytes) or not (1 <= len(raw) <= _MAX_CERT_BYTES):
        _reject(reason)
    stripped = raw.strip()
    if (
        stripped.count(b"-----BEGIN CERTIFICATE-----") != 1
        or stripped.count(b"-----END CERTIFICATE-----") != 1
        or not stripped.startswith(b"-----BEGIN CERTIFICATE-----")
        or not stripped.endswith(b"-----END CERTIFICATE-----")
    ):
        _reject(reason)
    try:
        certs = x509.load_pem_x509_certificates(stripped + b"\n")
    except ValueError:
        _reject(reason)
    if len(certs) != 1:
        _reject(reason)
    return certs[0]


def _load_key(raw: bytes) -> Any:
    if not isinstance(raw, bytes) or not (1 <= len(raw) <= _MAX_KEY_BYTES):
        _reject("server_private_key_invalid")
    stripped = raw.strip()
    if b"ENCRYPTED PRIVATE KEY" in stripped or b"PRIVATE KEY-----" not in stripped:
        _reject("server_private_key_invalid")
    try:
        key = serialization.load_pem_private_key(stripped + b"\n", password=None)
    except (TypeError, UnsupportedAlgorithm, ValueError):
        _reject("server_private_key_invalid")
    _validate_public_key(key.public_key(), "server_private_key_algorithm_invalid")
    return key


def _validate_public_key(key: Any, reason: str) -> None:
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            _reject(reason)
        return
    if isinstance(key, ec.EllipticCurvePublicKey):
        if key.curve.key_size < 256:
            _reject(reason)
        return
    if isinstance(key, ed25519.Ed25519PublicKey):
        return
    _reject(reason)


def _verify_signature(cert: x509.Certificate, issuer: x509.Certificate, reason: str) -> None:
    public_key = issuer.public_key()
    try:
        hash_algorithm = cert.signature_hash_algorithm
    except UnsupportedAlgorithm:
        _reject(reason)
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            if hash_algorithm is None:
                _reject(reason)
            params = cert.signature_algorithm_parameters
            rsa_padding = (
                params if isinstance(params, padding.AsymmetricPadding) else padding.PKCS1v15()
            )
            public_key.verify(
                cert.signature, cert.tbs_certificate_bytes, rsa_padding, hash_algorithm
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if hash_algorithm is None:
                _reject(reason)
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hash_algorithm))
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            _reject(reason)
    except ControllerTlsError:
        raise
    except Exception:  # noqa: BLE001 - a failed verify is a bounded refusal, never a raw exception
        _reject(reason)


def _extension(
    cert: x509.Certificate, cls: type[Any], reason: str, *, critical: bool | None
) -> Any:
    try:
        ext = cert.extensions.get_extension_for_class(cls)
    except x509.ExtensionNotFound:
        _reject(reason)
    if critical is not None and ext.critical is not critical:
        _reject(reason)
    return ext.value


def _validate_ca(cert: x509.Certificate, now: datetime) -> None:
    if cert.subject != cert.issuer or not cert.subject:
        _reject("ca_not_self_issued")
    _validate_public_key(cert.public_key(), "ca_public_key_algorithm_invalid")
    constraints = _extension(cert, x509.BasicConstraints, "ca_constraints_missing", critical=True)
    if not constraints.ca or constraints.path_length != 0:
        _reject("ca_constraints_invalid")
    usage = _extension(cert, x509.KeyUsage, "ca_key_usage_missing", critical=True)
    if not usage.key_cert_sign or not usage.crl_sign:
        _reject("ca_key_usage_invalid")
    if not (cert.not_valid_before_utc <= now < cert.not_valid_after_utc):
        _reject("ca_not_current")
    _verify_signature(cert, cert, "ca_signature_invalid")


def _validate_server(
    cert: x509.Certificate, *, ca: x509.Certificate, identity: str, now: datetime
) -> None:
    _validate_public_key(cert.public_key(), "server_public_key_algorithm_invalid")
    if cert.issuer != ca.subject:
        _reject("server_issuer_mismatch")
    _verify_signature(cert, ca, "server_signature_invalid")
    if not (cert.not_valid_before_utc <= now < cert.not_valid_after_utc):
        _reject("server_certificate_not_current")
    if (
        cert.not_valid_before_utc < ca.not_valid_before_utc
        or cert.not_valid_after_utc > ca.not_valid_after_utc
    ):
        _reject("server_validity_outside_ca")
    constraints = _extension(
        cert, x509.BasicConstraints, "server_constraints_missing", critical=True
    )
    if constraints.ca:
        _reject("server_constraints_invalid")
    usage = _extension(cert, x509.KeyUsage, "server_key_usage_missing", critical=True)
    if not usage.digital_signature or usage.key_cert_sign or usage.crl_sign:
        _reject("server_key_usage_invalid")
    eku = _extension(cert, x509.ExtendedKeyUsage, "server_eku_missing", critical=None)
    if tuple(eku) != (ExtendedKeyUsageOID.SERVER_AUTH,):
        _reject("server_eku_invalid")
    san = _extension(cert, x509.SubjectAlternativeName, "server_san_missing", critical=None)
    names = tuple(san)
    if len(names) != 1 or not isinstance(names[0], x509.DNSName) or names[0].value != identity:
        _reject("server_identity_mismatch")
    common = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(common) != 1 or common[0].value != identity:
        _reject("server_common_name_mismatch")


def _validate_material(
    *, ca_pem: bytes, server_pem: bytes, key_pem: bytes, identity: str, now: datetime
) -> tuple[x509.Certificate, x509.Certificate, bytes, bytes, bytes]:
    """Fully validate a CA + server + private-key set (chain, CA/server constraints, identity, key
    match) and return the parsed certs + normalized PEM bytes. Raises a bounded ControllerTlsError
    with a bare sub-reason on any defect (the caller wraps it per mode)."""
    ca = _load_cert(ca_pem, "ca_certificate_invalid")
    server = _load_cert(server_pem, "server_certificate_invalid")
    _validate_ca(ca, now)
    _validate_server(server, ca=ca, identity=identity, now=now)
    key = _load_key(key_pem)
    server_spki = server.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if server_spki != key_spki:
        _reject("server_private_key_mismatch")
    norm_ca = ca.public_bytes(serialization.Encoding.PEM)
    norm_server = server.public_bytes(serialization.Encoding.PEM)
    norm_key = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return ca, server, norm_ca, norm_server, norm_key


def _fingerprint(cert: x509.Certificate) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


# --------------------------------------------------------------------------- policy conformance


def _key_algorithm(cert: x509.Certificate) -> str:
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


def _signature_algorithm(cert: x509.Certificate, issuer: x509.Certificate) -> str:
    """The signature algorithm the ISSUER used to sign ``cert`` (mapped by the issuer key type)."""
    issuer_key = issuer.public_key()
    if isinstance(issuer_key, ed25519.Ed25519PublicKey):
        return "ed25519"
    try:
        algo = cert.signature_hash_algorithm
    except Exception:  # noqa: BLE001 - an unknown signature hash is a bounded refusal
        return "unsupported"
    name: str = getattr(algo, "name", "") or ""
    if isinstance(issuer_key, ec.EllipticCurvePublicKey):
        return {"sha256": "ecdsa-with-sha256", "sha384": "ecdsa-with-sha384"}.get(
            name, "unsupported"
        )
    if isinstance(issuer_key, rsa.RSAPublicKey):
        return {"sha256": "sha256-rsa", "sha384": "sha384-rsa"}.get(name, "unsupported")
    return "unsupported"


def _assert_policy_conformant(
    ca: x509.Certificate, server: x509.Certificate, policy: ControllerTlsPolicy, dns_identity: str
) -> tuple[str, str, int]:
    """Prove the validated material conforms to EVERY field of the signed policy. The structural
    facts (self-issued CA pathlen 0, KeyUsage, EKU==serverAuth, exactly-one-DNS-SAN == identity,
    chain, validity windows, key/private-key match) are already enforced by
    :func:`_validate_material`;
    this adds the signed-policy layer."""
    # key algorithm: BOTH the CA and the server must use exactly the policy's key algorithm.
    server_alg = _key_algorithm(server)
    if server_alg != policy.key_algorithm or _key_algorithm(ca) != policy.key_algorithm:
        _reject("controller_tls_key_algorithm_mismatch")

    # signature algorithm: the CA-issued signatures (CA self-signature + server signature) must both
    # match the policy's signature algorithm.
    sig_alg = _signature_algorithm(server, ca)
    if (
        sig_alg != policy.signature_algorithm
        or _signature_algorithm(ca, ca) != policy.signature_algorithm
    ):
        _reject("controller_tls_signature_algorithm_mismatch")

    # SAN / EKU / CA-pathlen are policy REQUIREMENTS; the structural validation already enforces the
    # strong form, so a policy that (incorrectly) does not require them is refused as too weak.
    if not (policy.require_san and policy.server_auth_eku_required and policy.ca_pathlen_zero):
        _reject("controller_tls_policy_too_weak")

    # validity: compare the ACTUAL timedelta, not the floored ``.days`` — an imported cert with a
    # sub-day fraction over the ceiling (e.g. ceiling + 23h) must be refused, not rounded under.
    not_before = server.not_valid_before_utc
    not_after = server.not_valid_after_utc
    ceiling = min(policy.max_validity_days, _HARD_MAX_VALIDITY_DAYS)
    if not_after <= not_before or not_after > not_before + timedelta(days=ceiling):
        _reject("controller_tls_validity_out_of_bounds")
    validity_days = (not_after - not_before).days

    # the certificate identity must be exactly the origin host (the structural validation binds
    # SAN/CN to the passed identity; assert it is what we resolved from the origin).
    san = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = [n.value for n in san if isinstance(n, x509.DNSName)]
    if names != [dns_identity]:
        _reject("controller_tls_identity_mismatch")
    return server_alg, sig_alg, validity_days


# --------------------------------------------------------------------------- producers


def _generate_pems(
    policy: ControllerTlsPolicy, dns_identity: str, *, now: datetime
) -> tuple[bytes, bytes, bytes]:
    """Mint a local CA + server certificate honoring the policy's exact key + signature algorithm.
    The total span is EXACTLY the (clamped) validity days so the strict ceiling check passes for the
    normal generated path while still bounding imports that run over."""
    if policy.key_algorithm not in _KEY_GENERATORS:
        _reject("controller_tls_key_algorithm_unsupported")
    if policy.signature_algorithm not in _SIGNATURE_HASHES:
        _reject("controller_tls_signature_algorithm_unsupported")
    validity_days = min(policy.max_validity_days, _HARD_MAX_VALIDITY_DAYS)
    sig_hash = _SIGNATURE_HASHES[policy.signature_algorithm]
    not_before = now - timedelta(minutes=5)  # clock-skew backdate
    server_not_after = not_before + timedelta(days=validity_days)  # span == validity_days exactly
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
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns_identity)]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, sig_hash)
    )
    return (
        ca_cert.public_bytes(serialization.Encoding.PEM),
        server_cert.public_bytes(serialization.Encoding.PEM),
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


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
        ca_pem, server_pem, key_pem = _generate_pems(policy, dns_identity, now=resolved_now)
        try:
            ca, server, norm_ca, norm_server, norm_key = _validate_material(
                ca_pem=ca_pem,
                server_pem=server_pem,
                key_pem=key_pem,
                identity=dns_identity,
                now=resolved_now,
            )
        except ControllerTlsError:
            _reject("controller_tls_generation_invalid")
    else:
        if not (imported_ca_pem and imported_server_pem and imported_key_pem):
            _reject("controller_tls_import_material_required")
        try:
            ca, server, norm_ca, norm_server, norm_key = _validate_material(
                ca_pem=imported_ca_pem,
                server_pem=imported_server_pem,
                key_pem=imported_key_pem,
                identity=dns_identity,
                now=resolved_now,
            )
        except ControllerTlsError as exc:
            raise ControllerTlsError(f"controller_tls_import_invalid:{exc.reason_code}") from None

    key_alg, sig_alg, validity_days = _assert_policy_conformant(ca, server, policy, dns_identity)
    facts = {
        "ca_certificate_fingerprint": _fingerprint(ca),
        "server_certificate_fingerprint": _fingerprint(server),
    }
    return ProducedControllerTls(
        _ca_bundle_pem=norm_ca,
        _server_cert_pem=norm_server,
        _server_key_pem=norm_key,
        mode=mode,
        dns_identity=dns_identity,
        key_algorithm=key_alg,
        signature_algorithm=sig_alg,
        validity_days=validity_days,
        _facts=facts,
    )


def validate_controller_tls_material(
    *,
    ca_pem: bytes,
    server_pem: bytes,
    key_pem: bytes,
    policy: ControllerTlsPolicy,
    canonical_origin: str,
    now: datetime | None = None,
) -> dict[str, object]:
    """Strict cryptographic validation of an ADOPTED controller-API TLS set against the signed
    policy — the exact chain / server-key pairing / SAN == canonical-origin / serverAuth EKU / key
    usage / current validity / policy-conformance (key + signature algorithm, validity ceiling,
    SAN + IP policy) checks ``produce_controller_tls`` applies to imported material, WITHOUT the
    mode-permitted gate (adoption is mode-agnostic: an existing set must be policy-conformant no
    matter how it was produced). Any mismatch raises :class:`ControllerTlsError`. Returns NON-SECRET
    facts (dns identity, algorithms, validity days) for the adoption receipt."""
    resolved_now = (datetime.now(UTC) if now is None else now).astimezone(UTC)
    dns_identity = _origin_dns_identity(canonical_origin, allow_ip_origin=policy.allow_ip_origin)
    ca, server, _norm_ca, _norm_server, _norm_key = _validate_material(
        ca_pem=ca_pem,
        server_pem=server_pem,
        key_pem=key_pem,
        identity=dns_identity,
        now=resolved_now,
    )
    key_alg, sig_alg, validity_days = _assert_policy_conformant(ca, server, policy, dns_identity)
    return {
        "dns_identity": dns_identity,
        "key_algorithm": key_alg,
        "signature_algorithm": sig_alg,
        "validity_days": validity_days,
    }


__all__ = [
    "CONTROLLER_CA_BUNDLE_PATH",
    "CONTROLLER_SERVER_CERT_PATH",
    "CONTROLLER_SERVER_KEY_PATH",
    "CONTROLLER_TLS_DIR",
    "ControllerTlsError",
    "ProducedControllerTls",
    "produce_controller_tls",
    "validate_controller_tls_material",
]
