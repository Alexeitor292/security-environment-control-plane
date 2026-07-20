"""Closed in-container TLS probe for the production worker admission boundary.

The probe accepts no argument and makes one TLS handshake (no HTTP request) from the ordinary
worker's own network namespace using only the exact mounted CA certificate.  Output contains safe
fingerprints/identity/protocol facts and fixed effect booleans; endpoint, PEM, exceptions, proxy
configuration, and credentials are never emitted.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import stat
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

CONTRACT_VERSION = "secp.worker.admission-tls-probe/v1"
ADMISSION_CA_PATH = "/etc/secp/admission-ca.pem"
_MAX_CA_BYTES = 32 * 1024
_TIMEOUT_SECONDS = 5
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

CAReader = Callable[[], bytes]
TLSConnector = Callable[[str, int, str, bytes], tuple[bytes, str]]


def _fingerprint(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _base() -> dict[str, Any]:
    return {
        "contract_version": CONTRACT_VERSION,
        "ok": False,
        "reason_code": "tls_probe_failed",
        "ca_certificate_fingerprint": None,
        "server_certificate_fingerprint": None,
        "server_dns_identity": None,
        "tls_version": None,
        "probe_effects": {
            "http_requested": False,
            "redirect_followed": False,
            "proxy_used": False,
        },
    }


def _closed(payload: dict[str, Any], reason: str) -> dict[str, Any]:
    payload["ok"] = False
    payload["reason_code"] = reason
    payload["ca_certificate_fingerprint"] = None
    payload["server_certificate_fingerprint"] = None
    payload["server_dns_identity"] = None
    payload["tls_version"] = None
    return payload


def _read_fixed_ca() -> bytes:
    fd: int | None = None
    try:
        before = os.lstat(ADMISSION_CA_PATH)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or stat.S_IMODE(before.st_mode) != 0o644
            or not (1 <= before.st_size <= _MAX_CA_BYTES)
        ):
            raise ValueError
        fd = os.open(ADMISSION_CA_PATH, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC)
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError
        chunks = bytearray()
        while len(chunks) <= _MAX_CA_BYTES:
            chunk = os.read(fd, min(8192, _MAX_CA_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) != before.st_size:
            raise ValueError
        return bytes(chunks)
    except Exception:
        raise RuntimeError("ca_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def _connect(host: str, port: int, identity: str, ca_pem: bytes) -> tuple[bytes, str]:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cadata=ca_pem.decode("ascii"))
        with socket.create_connection((host, port), timeout=_TIMEOUT_SECONDS) as raw:
            raw.settimeout(_TIMEOUT_SECONDS)
            with context.wrap_socket(raw, server_hostname=identity) as secured:
                peer = secured.getpeercert(binary_form=True)
                version = secured.version()
        if not peer or version not in {"TLSv1.2", "TLSv1.3"}:
            raise ValueError
        return peer, version
    except Exception:
        raise RuntimeError("tls_handshake_failed") from None


def run_probe(
    *,
    settings: object | None = None,
    ca_reader: CAReader | None = None,
    connector: TLSConnector | None = None,
) -> dict[str, Any]:
    payload = _base()
    try:
        if settings is None:
            from secp_api.config import get_settings

            settings = get_settings()
        if (
            getattr(settings, "discovery_controlled_integration_enabled", None) is not True
            or getattr(settings, "discovery_worker_managed_bundle", None) is not True
            or getattr(settings, "discovery_admission_ca", None) != ADMISSION_CA_PATH
        ):
            return _closed(payload, "activation_configuration_invalid")
        endpoint = getattr(settings, "discovery_admission_endpoint", None)
        if not isinstance(endpoint, str):
            return _closed(payload, "admission_endpoint_invalid")
        from secp_worker.admission_http_transport import _validate_admission_endpoint

        normalized = _validate_admission_endpoint(endpoint)
        parsed = urlsplit(normalized)
        identity = parsed.hostname
        if identity is None:
            return _closed(payload, "admission_endpoint_invalid")
        port = parsed.port or 443

        ca_pem = (ca_reader or _read_fixed_ca)()
        ca = x509.load_pem_x509_certificate(ca_pem)
        ca_fingerprint = _fingerprint(ca.public_bytes(serialization.Encoding.DER))
        peer_der, version = (connector or _connect)(identity, port, identity, ca_pem)
        # Parsing the peer again ensures the fingerprint covers one complete DER certificate.
        peer = x509.load_der_x509_certificate(peer_der)
        server_fingerprint = _fingerprint(peer.public_bytes(serialization.Encoding.DER))
        payload.update(
            {
                "ok": True,
                "reason_code": "ok",
                "ca_certificate_fingerprint": ca_fingerprint,
                "server_certificate_fingerprint": server_fingerprint,
                "server_dns_identity": identity,
                "tls_version": version,
            }
        )
        return payload
    except Exception:
        return _closed(payload, "tls_probe_failed")


def _json_bytes(payload: dict[str, Any]) -> bytes:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return raw if len(raw) <= 2048 else b'{"ok":false,"reason_code":"probe_output_invalid"}'


def _main(argv: list[str]) -> int:
    payload = _closed(_base(), "arguments_forbidden") if argv else run_probe()
    import sys

    sys.stdout.buffer.write(_json_bytes(payload) + b"\n")
    return 0 if payload["ok"] is True else 1


if __name__ == "__main__":  # pragma: no cover
    import sys

    raise SystemExit(_main(sys.argv[1:]))
