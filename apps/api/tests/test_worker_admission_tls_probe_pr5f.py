"""Hermetic contract tests for the no-argument in-container admission TLS probe."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from secp_discovery_activation.tls import generate_tls_material
from secp_worker import admission_tls_probe as probe

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
IDENTITY = "admission.internal.test"


def _settings(**updates):
    values = {
        "discovery_controlled_integration_enabled": True,
        "discovery_worker_managed_bundle": True,
        "discovery_admission_ca": probe.ADMISSION_CA_PATH,
        "discovery_admission_endpoint": f"https://{IDENTITY}:8443",
    }
    values.update(updates)
    return SimpleNamespace(**values)


def test_probe_reports_only_safe_fingerprints_from_worker_namespace() -> None:
    material = generate_tls_material(dns_identity=IDENTITY, validity_days=30, now=NOW)
    server_der = x509.load_pem_x509_certificate(material.server_certificate_pem()).public_bytes(
        serialization.Encoding.DER
    )
    observed: list[tuple[str, int, str, bytes]] = []

    def connect(host: str, port: int, identity: str, ca_pem: bytes):
        observed.append((host, port, identity, ca_pem))
        return server_der, "TLSv1.3"

    result = probe.run_probe(
        settings=_settings(),
        ca_reader=material.ca_certificate_pem,
        connector=connect,
    )
    encoded = probe._json_bytes(result)

    assert result == {
        "contract_version": probe.CONTRACT_VERSION,
        "ok": True,
        "reason_code": "ok",
        "ca_certificate_fingerprint": material.metadata.ca_certificate_fingerprint,
        "server_certificate_fingerprint": material.metadata.server_certificate_fingerprint,
        "server_dns_identity": IDENTITY,
        "tls_version": "TLSv1.3",
        "probe_effects": {
            "http_requested": False,
            "redirect_followed": False,
            "proxy_used": False,
        },
    }
    assert len(observed) == 1
    observed_host, observed_port, observed_identity, observed_ca = observed[0]
    assert (observed_host, observed_port, observed_identity) == (IDENTITY, 8443, IDENTITY)
    assert x509.load_pem_x509_certificate(observed_ca).fingerprint(hashes.SHA256()).hex() == (
        material.metadata.ca_certificate_fingerprint.removeprefix("sha256:")
    )
    assert b"BEGIN CERTIFICATE" not in encoded
    assert b"PRIVATE KEY" not in encoded
    assert b"https://" not in encoded


def test_configuration_refuses_before_ca_read_or_connection() -> None:
    calls: list[str] = []

    def forbidden():
        calls.append("ca")
        raise AssertionError

    result = probe.run_probe(
        settings=_settings(discovery_admission_ca="/tmp/untrusted"),
        ca_reader=forbidden,
        connector=lambda *_args: (_ for _ in ()).throw(AssertionError()),
    )

    assert result["reason_code"] == "activation_configuration_invalid"
    assert calls == []


def test_ca_or_handshake_failure_is_closed_and_suppresses_sensitive_text() -> None:
    failed_ca = probe.run_probe(
        settings=_settings(),
        ca_reader=lambda: b"database-password PRIVATE KEY",
        connector=lambda *_args: (_ for _ in ()).throw(AssertionError()),
    )
    assert failed_ca["reason_code"] == "tls_probe_failed"
    assert b"PRIVATE KEY" not in probe._json_bytes(failed_ca)

    material = generate_tls_material(dns_identity=IDENTITY, validity_days=30, now=NOW)

    def failed_connection(*_args):
        raise RuntimeError("https://credential@internal.example")

    failed_tls = probe.run_probe(
        settings=_settings(),
        ca_reader=material.ca_certificate_pem,
        connector=failed_connection,
    )
    encoded = probe._json_bytes(failed_tls)
    assert failed_tls["reason_code"] == "tls_probe_failed"
    assert b"credential" not in encoded and b"internal.example" not in encoded


def test_main_forbids_arguments_without_reading_settings(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        probe,
        "run_probe",
        lambda: (_ for _ in ()).throw(AssertionError("must remain inert")),
    )

    assert probe._main(["--endpoint", "https://untrusted.test"]) == 1
    assert b"arguments_forbidden" in capsys.readouterr().out.encode()
