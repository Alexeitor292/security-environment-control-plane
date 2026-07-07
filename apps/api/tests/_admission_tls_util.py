"""Test-only TLS helpers for the SECP-B6 admission-transport hardening tests.

Provides an in-process CA + server certificate and a threaded fake admission endpoint (HTTP or
HTTPS) whose every response is caller-controlled. Used to prove that a plain-HTTP or wrong-CA fake
admission server — even one that would "admit" anything — can never cause SSH contact, and that the
client rejects generic ``200`` responses. NEVER imported by production code. Not a test module
itself (underscore prefix), so pytest does not collect it.
"""

from __future__ import annotations

import datetime
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _gen_cert(*, ca_cert=None, ca_key=None, common_name: str, is_ca: bool, san_dns: str | None):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = subject if ca_cert is None else ca_cert.subject
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san_dns)]), critical=False
        )
    cert = builder.sign(key if ca_key is None else ca_key, hashes.SHA256())
    return cert, key


def _cert_pem(cert) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return cert.public_bytes(serialization.Encoding.PEM)


def _key_pem(key) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


class IssuedTls:
    """A CA + a server cert/key it signed, materialized as files under ``tmp_path``."""

    def __init__(self, tmp_path, *, san_dns: str = "localhost", label: str = "a") -> None:
        ca_cert, ca_key = _gen_cert(common_name=f"secp-test-ca-{label}", is_ca=True, san_dns=None)
        server_cert, server_key = _gen_cert(
            ca_cert=ca_cert, ca_key=ca_key, common_name=san_dns, is_ca=False, san_dns=san_dns
        )
        self.ca_path = str(tmp_path / f"admission-ca-{label}.pem")
        self.server_cert_path = str(tmp_path / f"server-cert-{label}.pem")
        self.server_key_path = str(tmp_path / f"server-key-{label}.pem")
        (tmp_path / f"admission-ca-{label}.pem").write_bytes(_cert_pem(ca_cert))
        (tmp_path / f"server-cert-{label}.pem").write_bytes(_cert_pem(server_cert))
        (tmp_path / f"server-key-{label}.pem").write_bytes(_key_pem(server_key))


def write_ca_only(tmp_path, *, label: str = "trust") -> str:
    """Write a valid, standalone CA PEM (no server) and return its path — a usable trust anchor."""
    ca_cert, _ = _gen_cert(common_name=f"secp-test-ca-{label}", is_ca=True, san_dns=None)
    p = tmp_path / f"ca-only-{label}.pem"
    p.write_bytes(_cert_pem(ca_cert))
    return str(p)


class FakeAdmissionServer:
    """A threaded fake admission endpoint.

    ``responder(path, body) -> (status, dict)`` fully controls every response. ``request_count``
    records how many requests actually arrived — so a test can prove a rejected transport (plain
    HTTP, unparsable URL) never contacts the server at all, and that a redirect is not followed.
    Serves HTTPS when ``certfile``/``keyfile`` are given, else plain HTTP.
    """

    def __init__(self, *, responder, certfile: str | None = None, keyfile: str | None = None):
        self._responder = responder
        self._certfile = certfile
        self._keyfile = keyfile
        self.request_count = 0
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> FakeAdmissionServer:
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):  # silence access logging
                pass

            def do_POST(self):  # noqa: N802 (BaseHTTPRequestHandler API)
                length = int(self.headers.get("Content-Length", 0) or 0)
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    body = json.loads(raw.decode("utf-8"))
                except ValueError:
                    body = {}
                outer.request_count += 1
                status, payload = outer._responder(self.path, body)
                data = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                if status in (301, 302, 307, 308):
                    # A redirect target that WOULD admit — proves httpx does not follow it.
                    self.send_header("Location", "https://localhost/internal/would-admit")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = ThreadingHTTPServer(("localhost", 0), _Handler)
        if self._certfile is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=self._certfile, keyfile=self._keyfile)
            self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    @property
    def port(self) -> int:
        assert self._server is not None
        return self._server.server_address[1]

    @property
    def base_url(self) -> str:
        scheme = "https" if self._certfile is not None else "http"
        return f"{scheme}://localhost:{self.port}"
