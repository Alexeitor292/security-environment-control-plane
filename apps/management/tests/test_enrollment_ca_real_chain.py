"""The invitation CA chain, against REAL cryptography and the REAL ``ssl`` module (SECP WS-B).

Every other CA test in this branch monkeypatches ``ssl.create_default_context``. Those tests pin
*which bytes* the transport passes; none of them proves the bytes are *usable*. A chain that is
malformed, or valid PEM but not a certificate, would satisfy all of them and fail at the first live
enrollment — the exact failure shape of a mechanism that looks delivered and never fires.

So this module closes that gap and nothing else:

* it generates REAL certificates (a self-signed root, and a root + intermediate chain) with
  ``cryptography``, and additionally exercises the ACTUAL production producer,
  ``produce_controller_tls`` — the same call whose ``ca_bundle_pem`` is written to the path the
  bootstrap-recorded locator points at, so the bytes under test are the bytes an operator's
  controller really has;
* it feeds them to a GENUINE ``ssl.create_default_context(cadata=...)`` — never patched — and
  asserts on ``get_ca_certs()``, i.e. on what OpenSSL actually accepted rather than on what we
  handed it;
* it proves the negative: a value that passes our PEM grammar gate but is not a real certificate is
  refused by ``ssl``, so the two layers agree on what a chain is and the gate is not quietly wider
  than the thing it guards;
* it runs a real chain through EVERY stage of the invitation path — grammar gate, size bounds,
  ``_REQUIRED_INVITATION_KEYS`` projection, ``_inputs()`` mapping, transport construction — and
  lands it in a working context, byte-identical throughout.

MEASURED SIZES (this module is where the bounds stop being estimates)
---------------------------------------------------------------------
=====================================  ============  ====================
material                                   CA bytes   % of 8192 CA bound
=====================================  ============  ====================
production controller CA (ecdsa-p256)           599                   7%
root + intermediate (ecdsa-p256)          1023-1027                  12%
root + intermediate (RSA-4096)            3468-3480                  42%
=====================================  ============  ====================

The ranges are not sloppiness: a DER-encoded ECDSA signature is 1-2 bytes shorter whenever ``r`` or
``s`` has a leading zero byte, and the serial number varies likewise, so a freshly generated chain
lands anywhere in the range. Every assertion below is therefore a RATIO or an inequality with
headroom, never an equality against a byte count that would flake.

The largest realistic shape leaves more than half the CA budget unused. The whole invitation file
carrying the RSA-4096 chain is ~4110 bytes, 25% of the 16384 cap, measured with the exact
``_invitation()`` fixture below. (An earlier note recorded 4354 here; that figure came from a
scratch measurement that inflated ``controller_origin`` to near its 269-character cap rather than
the 31-character origin this module actually uses — a 232-byte difference, not jitter.)

Note that 16384 is required for CONSISTENCY with a CA field permitted to reach 8192 — a CA at its
own limit plus the remaining fields cannot fit in the old 8192 whole-file cap — and NOT because any
measured chain needs it. The longest non-CA field an invitation can carry is ``controller_origin``,
bounded at 269 by ``ControllerApiLocator``, so the 1024 per-field bound is ~3.8x the largest
permitted value.

The production controller CA bundle is exactly ONE certificate: ``controller_tls._load_cert``
refuses a CA PEM containing anything other than a single CERTIFICATE block, in BOTH TLS modes. The
multi-certificate support proven here is therefore forward-looking for that path, and immediately
real for any chain an operator supplies by another route.

No network, no real CA, no controller contact: every key and certificate is generated in-process
and discarded with the test.
"""

from __future__ import annotations

import datetime as _dt
import json
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from secp_management.controller_tls import ControllerTlsPolicy, produce_controller_tls
from secp_management.enrollment_cli import (
    _MAX_CA_BUNDLE_BYTES,
    _MAX_INVITATION_BYTES,
    _MAX_INVITATION_FIELD_BYTES,
    _REQUIRED_INVITATION_KEYS,
    WorkerCliError,
    load_invitation_file,
)
from secp_management.worker_enroller import DriverWorkerEnroller
from secp_worker.enrollment_http_transport import (
    HttpxWorkerEnrollmentTransport,
    WorkerEnrollmentSigner,
)

_NOW = _dt.datetime(2026, 7, 30, tzinfo=_dt.UTC)


def _issue(common_name: str, *, issuer=None, issuer_key=None, path_length: int | None = None):
    """One REAL EC certificate. Self-signed when no issuer is given, otherwise signed by it."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject if issuer is None else issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - _dt.timedelta(days=1))
        .not_valid_after(_NOW + _dt.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
    )
    cert = builder.sign(key if issuer_key is None else issuer_key, hashes.SHA256())
    return cert, key


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


@pytest.fixture(scope="module")
def root_only() -> str:
    cert, _key = _issue("secp-test-root", path_length=0)
    return _pem(cert)


@pytest.fixture(scope="module")
def root_and_intermediate() -> str:
    root, root_key = _issue("secp-test-root", path_length=1)
    inter, _ik = _issue("secp-test-intermediate", issuer=root, issuer_key=root_key, path_length=0)
    # operator convention: leaf-most first, root last
    return _pem(inter) + _pem(root)


@pytest.fixture(scope="module")
def rsa_root_and_intermediate() -> str:
    """The LARGEST realistic enterprise shape (RSA-4096 root + intermediate). Slower to generate,
    so it is module-scoped and used only where the size is the point."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    def _rsa_issue(cn, issuer=None, issuer_key=None, path_length=None):
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject if issuer is None else issuer.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOW - _dt.timedelta(days=1))
            .not_valid_after(_NOW + _dt.timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
            .sign(key if issuer_key is None else issuer_key, hashes.SHA256())
        )
        return cert, key

    root, rk = _rsa_issue("secp-rsa-root", path_length=1)
    inter, _ = _rsa_issue("secp-rsa-intermediate", issuer=root, issuer_key=rk, path_length=0)
    return _pem(inter) + _pem(root)


@pytest.fixture(scope="module")
def produced_controller_ca() -> str:
    """The ACTUAL production controller CA bundle — the bytes written to the path the locator
    records, and therefore the bytes ``LocatorControllerCaBundleProvider`` reads in production."""
    produced = produce_controller_tls(
        policy=ControllerTlsPolicy(
            allowed_modes=("generated_local_ca", "imported_enterprise_tls"),
            key_algorithm="ecdsa-p256",
            signature_algorithm="ecdsa-with-sha256",
            max_validity_days=825,
            require_san=True,
            server_auth_eku_required=True,
            ca_pathlen_zero=True,
            min_tls_version="1.3",
            allow_ip_origin=False,
            allow_generated_local_ca=True,
        ),
        canonical_origin="https://controller.example.test",
        mode="generated_local_ca",
    )
    return produced.ca_bundle_pem().decode("ascii")


# --- the real ssl module actually accepts what we hand it ----------------------------------------


def _real_context(pem: str) -> ssl.SSLContext:
    """A GENUINE ssl context. Nothing is patched here; if OpenSSL rejects the chain this raises."""
    return ssl.create_default_context(cadata=pem)


def test_the_production_controller_ca_bundle_loads_into_a_real_ssl_context(produced_controller_ca):
    """The strongest form of the claim: the real producer's output, into real OpenSSL."""
    ctx = _real_context(produced_controller_ca)

    loaded = ctx.get_ca_certs()
    assert len(loaded) == 1, "OpenSSL accepted a different number of certs than we supplied"
    # it is OUR certificate that OpenSSL retained, not something inherited from the host store.
    # (The DNS identity lives on the SERVER certificate's SAN, not on the CA; the CA carries the
    # producer's own issuer common name.)
    assert "SECP Controller Local CA" in str(loaded[0])
    assert isinstance(ctx, ssl.SSLContext)


def test_a_root_plus_intermediate_chain_loads_both_certificates(root_and_intermediate):
    """The multi-certificate case. ``get_ca_certs()`` is the assertion because it reports what
    OpenSSL parsed and retained, not what we passed in."""
    ctx = _real_context(root_and_intermediate)

    assert len(ctx.get_ca_certs()) == 2


def test_a_single_self_signed_root_loads(root_only):
    assert len(_real_context(root_only).get_ca_certs()) == 1


def test_supplying_cadata_does_not_silently_fall_back_to_the_system_trust_store(root_only):
    """If ``cadata`` were ignored the context would carry the host's whole trust store, and every
    assertion above would pass for the wrong reason.

    The premise is established FIRST. Asserting only ``== 1`` is byte-identical to the assertion
    above it, and on a host with an empty system trust store it would pass while proving nothing —
    exactly the vacuity this module exists to avoid. Requiring the default context to be
    substantially populated is what makes ``== 1`` below mean 'nothing was inherited'."""
    system = ssl.create_default_context().get_ca_certs()
    assert len(system) > 10, (
        f"this host's default trust store holds only {len(system)} certs — the assertion below "
        "cannot distinguish 'cadata was honoured' from 'there was nothing to inherit'"
    )

    ctx = _real_context(root_only)

    assert len(ctx.get_ca_certs()) == 1  # exactly ours, none of the system's inherited


# --- the grammar gate and ssl agree on what a chain is -------------------------------------------


@pytest.mark.parametrize(
    "label,body",
    [
        ("base64 that is not a certificate", "QUFBQUFBQUFBQUFBQUFBQUFBQUE="),
        ("empty body", ""),
    ],
)
def test_a_grammar_valid_pem_that_is_not_a_certificate_is_refused_by_ssl(label, body):
    """Our grammar gate is deliberately a SHAPE check, not a cryptographic one — it exists to give a
    bounded reason code in the right layer, not to replace ``ssl``. This is the handoff: a value the
    gate ACCEPTS, that only real parsing can reject, IS rejected by real parsing.

    Without this, "the CA is validated" would be true of the shape and false of the certificate."""
    forged = f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"

    # it passes OUR shape gate ...
    from secp_management.enrollment_cli import _validate_ca_bundle_pem

    _validate_ca_bundle_pem(forged)  # no raise: the shape is right

    # ... and is refused by the layer that actually parses it
    with pytest.raises(ssl.SSLError):
        _real_context(forged)


@pytest.mark.parametrize(
    "body",
    [
        "@@@@not-base64@@@@",  # characters outside the base64 + armour alphabet
        "AAAA\x00AAAA",  # embedded control character
    ],
)
def test_the_grammar_gate_is_tighter_than_ssl_where_it_can_be_cheaply(body):
    """Measured, not assumed: the gate rejects these BEFORE ``ssl`` ever sees them, so the bounded
    reason code names the field instead of surfacing an opaque OpenSSL error. This pins which side
    of the handoff each class of failure lands on."""
    from secp_management.enrollment_cli import _validate_ca_bundle_pem

    forged = f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"

    with pytest.raises(WorkerCliError) as ei:
        _validate_ca_bundle_pem(forged)
    assert ei.value.reason_code == "secpctl_invitation_ca_invalid"


def test_the_transport_refuses_a_value_ssl_would_also_refuse():
    """The worker-plane gate must not be wider than the management-plane one."""
    from secp_worker.enrollment_http_transport import EnrollmentTransportError

    with pytest.raises(EnrollmentTransportError) as ei:
        HttpxWorkerEnrollmentTransport(
            controller_origin="https://controller.example.test",
            ca_bundle_pem="-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            signer=_signer(),
        )

    assert ei.value.reason_code == "enrollment_ca_invalid"


def _signer() -> WorkerEnrollmentSigner:
    from secp_management.signing import generate_keypair

    private_hex, _public = generate_keypair()
    return WorkerEnrollmentSigner(private_hex)


# --- a real chain survives EVERY stage of the invitation path ------------------------------------


def _invitation(ca_pem: str) -> dict:
    return {
        "enrollment_id": "sha256:" + "a" * 64,
        "invitation_id": "sha256:" + "b" * 64,
        "controller_installation_id": "controller-dev0001",
        "controller_key_id": "sha256:" + "c" * 64,
        "controller_origin": "https://controller.example.test",
        "controller_ca_bundle_pem": ca_pem,
        "transaction_id": "txn-0001",
        "release_digest": "sha256:" + "d" * 64,
        "expires_at": "2999-07-27T01:00:00+00:00",
    }


def test_a_real_chain_survives_the_whole_invitation_path_into_a_working_context(
    tmp_path, produced_controller_ca
):
    """One test, every stage: file -> bounded read -> grammar gate -> required-key projection ->
    _inputs() mapping -> transport construction -> a REAL ssl context.

    Each stage is asserted byte-identical, so a stage that normalised, truncated, or re-encoded the
    chain fails here rather than at the first live enrollment."""
    path = tmp_path / "invitation.json"
    path.write_text(json.dumps(_invitation(produced_controller_ca)), encoding="utf-8")

    # stage 1: the bounded read + grammar gate + projection
    loaded = load_invitation_file(str(path))
    assert loaded["controller_ca_bundle_pem"] == produced_controller_ca
    assert "controller_ca_bundle_pem" in _REQUIRED_INVITATION_KEYS

    # stage 2: the management -> worker mapping
    inputs = DriverWorkerEnroller._inputs(loaded)
    assert inputs.controller_ca_bundle_pem == produced_controller_ca

    # stage 3: transport construction (runs the worker-plane grammar gate)
    transport = HttpxWorkerEnrollmentTransport(
        controller_origin=inputs.controller_origin,
        ca_bundle_pem=inputs.controller_ca_bundle_pem,
        signer=_signer(),
    )
    assert transport is not None

    # stage 4: the chain the transport would hand to ssl, in a REAL context
    ctx = _real_context(inputs.controller_ca_bundle_pem)
    assert len(ctx.get_ca_certs()) == 1


def test_a_root_plus_intermediate_also_survives_the_whole_path(tmp_path, root_and_intermediate):
    path = tmp_path / "invitation.json"
    path.write_text(json.dumps(_invitation(root_and_intermediate)), encoding="utf-8")

    inputs = DriverWorkerEnroller._inputs(load_invitation_file(str(path)))

    assert inputs.controller_ca_bundle_pem == root_and_intermediate
    assert len(_real_context(inputs.controller_ca_bundle_pem).get_ca_certs()) == 2


# --- the bounds, MEASURED against real material rather than estimated ----------------------------


def test_the_declared_bounds_fit_real_measured_chains(
    produced_controller_ca, root_and_intermediate, root_only
):
    """The CA bound and the whole-file bound were set from an estimate. These are the measurements.

    Recorded as an explicit ratio rather than a bare ``<``, so a future certificate profile change
    that pushes a real chain close to the bound shows up as a shrinking margin instead of passing
    silently until the day it does not."""
    produced_bytes = len(produced_controller_ca.encode("utf-8"))
    chain_bytes = len(root_and_intermediate.encode("utf-8"))
    root_bytes = len(root_only.encode("utf-8"))

    # the real production CA bundle is a SINGLE certificate: controller_tls._load_cert refuses a
    # CA pem containing anything other than exactly one CERTIFICATE block, in BOTH tls modes
    assert produced_bytes < _MAX_CA_BUNDLE_BYTES
    assert chain_bytes < _MAX_CA_BUNDLE_BYTES
    assert root_bytes < _MAX_CA_BUNDLE_BYTES
    # margin: every measured chain must leave at least half the CA budget unused
    assert max(produced_bytes, chain_bytes) * 2 < _MAX_CA_BUNDLE_BYTES, (
        f"measured chains {produced_bytes}/{chain_bytes}B are close to the "
        f"{_MAX_CA_BUNDLE_BYTES}B CA bound"
    )


def test_the_largest_realistic_enterprise_chain_parses_and_fits_every_bound(
    tmp_path, rsa_root_and_intermediate
):
    """RSA-4096 root + intermediate — the biggest shape an enterprise PKI realistically hands over.

    Enforced rather than documented: it must load in real OpenSSL as two certificates, survive the
    whole invitation path, and sit inside both bounds with margin. Measured at 3480B (42% of the
    8192 CA bound); the whole file is 4354B (26% of 16384)."""
    ca_bytes = len(rsa_root_and_intermediate.encode("utf-8"))
    assert ca_bytes > 3000, "fixture is not the large shape this test exists to measure"
    assert ca_bytes < _MAX_CA_BUNDLE_BYTES // 2, (
        f"the largest realistic chain ({ca_bytes}B) has less than 2x margin against the "
        f"{_MAX_CA_BUNDLE_BYTES}B CA bound"
    )

    path = tmp_path / "invitation.json"
    body = json.dumps(_invitation(rsa_root_and_intermediate))
    path.write_text(body, encoding="utf-8")
    assert len(body.encode("utf-8")) < _MAX_INVITATION_BYTES // 2

    inputs = DriverWorkerEnroller._inputs(load_invitation_file(str(path)))

    assert inputs.controller_ca_bundle_pem == rsa_root_and_intermediate
    assert len(_real_context(inputs.controller_ca_bundle_pem).get_ca_certs()) == 2


def test_a_whole_invitation_carrying_a_real_chain_fits_the_file_bound(
    tmp_path, root_and_intermediate
):
    """The whole-file cap was raised 8192 -> 16384 for exactly this payload. Measure it."""
    path = tmp_path / "invitation.json"
    body = json.dumps(_invitation(root_and_intermediate))
    path.write_text(body, encoding="utf-8")

    assert len(body.encode("utf-8")) < _MAX_INVITATION_BYTES
    assert load_invitation_file(str(path))["controller_ca_bundle_pem"] == root_and_intermediate


def test_every_non_ca_field_of_a_real_invitation_fits_the_per_field_bound(root_and_intermediate):
    """The 1024 per-field bound was a judgement call. It is bounded above by the field grammars:
    the longest non-CA field an invitation can carry is ``controller_origin``, capped at 269 by
    ``ControllerApiLocator._MAX_ORIGIN_LEN``; the digests are 71. So 1024 is ~3.8x the largest
    value the contract permits, and no real invitation can approach it."""
    invitation = _invitation(root_and_intermediate)

    for key in _REQUIRED_INVITATION_KEYS:
        if key == "controller_ca_bundle_pem":
            continue
        assert len(invitation[key].encode("utf-8")) <= _MAX_INVITATION_FIELD_BYTES
    assert (
        max(
            len(v.encode("utf-8")) for k, v in invitation.items() if k != "controller_ca_bundle_pem"
        )
        < _MAX_INVITATION_FIELD_BYTES // 3
    )


def test_an_oversized_real_chain_is_still_refused_by_the_ca_bound(tmp_path):
    """The bound is real, not decorative: a chain past it refuses with the CA-specific code even
    though every certificate in it is genuine."""
    root, root_key = _issue("secp-bulk-root", path_length=1)
    many = "".join(
        _pem(_issue(f"secp-bulk-{n}", issuer=root, issuer_key=root_key)[0]) for n in range(20)
    )
    assert len(many.encode("utf-8")) > _MAX_CA_BUNDLE_BYTES  # genuinely oversized

    path = tmp_path / "invitation.json"
    path.write_text(json.dumps(_invitation(many)), encoding="utf-8")

    with pytest.raises(WorkerCliError) as ei:
        load_invitation_file(str(path))
    assert ei.value.reason_code == "secpctl_invitation_ca_too_large"
