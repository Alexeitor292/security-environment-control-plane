"""Worker-side discovery admission client (SECP-B6 MB-1).

Before any host contact the isolated worker must obtain a CONTROL-PLANE-VERIFIED, one-time admission
by proving possession of its deployment-local Ed25519 identity key to the control plane. This module
is the worker side of that boundary. It NEVER imports :mod:`secp_api.services.worker_admission` and
NEVER touches a DB ``Session``: the identity DECISION is made by the control plane behind the
internal admission endpoint, reached here over an injected :class:`AdmissionTransport` (the shipped
transport is CA-validated HTTPS). The client only (a) begins a challenge, (b) signs the
server-issued nonce with its deployment-local key, (c) completes, and later (d) asserts the exact
binding and (e) consumes the one-time admission — all as request/response over the transport.

The shipped default is :class:`SealedWorkerAdmissionClient`, which refuses and performs no signing.
A real :class:`HttpWorkerAdmissionClient` is constructed only on the isolated worker from
deployment-local key material + the internal endpoint. This module holds no private key beyond the
deployment-local signer, constructs no SSH/Proxmox/mutation code, and imports the shared
Ed25519 signing-message CONTRACT (a pure crypto/encoding library — never the admission service).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

_ADMISSION_BASE_PATH = "/internal/worker-discovery-admission"


class WorkerAdmissionUnavailable(Exception):
    """Fail-closed: no valid control-plane admission could be obtained. Closed reason code only."""

    def __init__(self, reason_code: str = "worker_admission_unavailable") -> None:
        super().__init__(f"worker discovery admission unavailable: {reason_code}")
        self.reason_code = reason_code


@dataclass(frozen=True)
class AdmissionGrant:
    """The authoritative registration id + version the control plane proved for an admission.

    Never a value the worker asserted — the control plane returns it after verifying the pinned
    anchor + re-running the authoritative verifier."""

    registration_id: uuid.UUID
    identity_version: int


@runtime_checkable
class AdmissionTransport(Protocol):
    """A request/response seam to the internal admission endpoint. Returns ``(status, body)``; the
    body is the parsed JSON object (already unwrapped from any ``{"detail": ...}`` envelope)."""

    def post(self, path: str, payload: dict) -> tuple[int, dict]: ...


@runtime_checkable
class WorkerAdmissionClient(Protocol):
    """Crosses the control-plane admission boundary for a discovery job. NO DB ``Session`` and NO
    caller-supplied clock: the control plane owns the identity decision and authoritative time."""

    def admit(
        self,
        *,
        discovery_job_id: uuid.UUID,
        authorization_id: uuid.UUID,
        authorization_version: int,
        endpoint_binding_hash: str,
    ) -> uuid.UUID: ...

    def assert_valid(
        self,
        *,
        admission_id: uuid.UUID,
        discovery_job_id: uuid.UUID,
        endpoint_binding_hash: str,
    ) -> AdmissionGrant: ...

    def consume(
        self,
        *,
        admission_id: uuid.UUID,
        discovery_job_id: uuid.UUID,
        endpoint_binding_hash: str,
    ) -> AdmissionGrant: ...


class SealedWorkerAdmissionClient:
    """Shipped default: refuses. No key material, no signing, no admission is ever obtained."""

    def admit(
        self,
        *,
        discovery_job_id: uuid.UUID,
        authorization_id: uuid.UUID,
        authorization_version: int,
        endpoint_binding_hash: str,
    ) -> uuid.UUID:
        raise WorkerAdmissionUnavailable("no worker admission client is configured")

    def assert_valid(
        self,
        *,
        admission_id: uuid.UUID,
        discovery_job_id: uuid.UUID,
        endpoint_binding_hash: str,
    ) -> AdmissionGrant:
        raise WorkerAdmissionUnavailable("no worker admission client is configured")

    def consume(
        self,
        *,
        admission_id: uuid.UUID,
        discovery_job_id: uuid.UUID,
        endpoint_binding_hash: str,
    ) -> AdmissionGrant:
        raise WorkerAdmissionUnavailable("no worker admission client is configured")


class HttpWorkerAdmissionClient:
    """Performs the control-plane-verified handshake over the internal admission endpoint.

    Constructed ONLY on the isolated worker from its deployment-local Ed25519 identity material + a
    transport to the internal endpoint. ``admit`` begins a challenge, signs the server-issued nonce
    with the deployment-local key, and completes; ``assert_valid``/``consume`` bind + one-time
    consume the admission. The client never verifies its own proof (that would be a self-check),
    never persists/logs the private key, and never talks to a DB or the admission service directly —
    only request/response JSON of NON-secret IDs (+ the signature) over the transport.
    """

    def __init__(
        self, *, transport: AdmissionTransport, private_key_hex: str, public_anchor_hex: str
    ) -> None:
        self._transport = transport
        self._private_key_hex = private_key_hex
        self._public_anchor_hex = public_anchor_hex

    def __repr__(self) -> str:  # never expose the private key
        return "HttpWorkerAdmissionClient(<redacted>)"

    def _post(self, path: str, payload: dict) -> dict:
        try:
            status, body = self._transport.post(_ADMISSION_BASE_PATH + path, payload)
        except Exception as exc:  # a transport/TLS failure fails closed with a closed reason
            raise WorkerAdmissionUnavailable("admission_endpoint_unreachable") from exc
        if status != 200:
            reason = "worker_admission_refused"
            if isinstance(body, dict):
                reason = str(body.get("reason_code") or body.get("code") or reason)
            raise WorkerAdmissionUnavailable(reason)
        if not isinstance(body, dict):
            raise WorkerAdmissionUnavailable("admission_response_malformed")
        return body

    def admit(
        self,
        *,
        discovery_job_id: uuid.UUID,
        authorization_id: uuid.UUID,
        authorization_version: int,
        endpoint_binding_hash: str,
    ) -> uuid.UUID:
        from secp_api.worker_admission_contract import admission_signing_message, ed25519_sign

        begin = self._post(
            "/begin",
            {
                "discovery_job_id": str(discovery_job_id),
                "authorization_id": str(authorization_id),
                "authorization_version": authorization_version,
                "endpoint_binding_hash": endpoint_binding_hash,
            },
        )
        try:
            message = admission_signing_message(
                nonce=str(begin["nonce"]),
                organization_id=str(begin["organization_id"]),
                discovery_job_id=str(begin["discovery_job_id"]),
                worker_registration_id=str(begin["worker_registration_id"]),
                identity_version=int(begin["identity_version"]),
                endpoint_binding_hash=str(begin["endpoint_binding_hash"]),
                expires_at=datetime.fromisoformat(str(begin["expires_at"])),
            )
            admission_id = uuid.UUID(str(begin["admission_id"]))
        except (KeyError, ValueError, TypeError) as exc:
            raise WorkerAdmissionUnavailable("admission_response_malformed") from exc
        signature = ed25519_sign(private_key_hex=self._private_key_hex, message=message)
        self._post(
            "/complete",
            {
                "admission_id": str(admission_id),
                "public_anchor": self._public_anchor_hex,
                "signature": signature,
            },
        )
        return admission_id

    def assert_valid(
        self,
        *,
        admission_id: uuid.UUID,
        discovery_job_id: uuid.UUID,
        endpoint_binding_hash: str,
    ) -> AdmissionGrant:
        body = self._post(
            "/assert",
            {
                "admission_id": str(admission_id),
                "discovery_job_id": str(discovery_job_id),
                "endpoint_binding_hash": endpoint_binding_hash,
            },
        )
        return self._grant(body)

    def consume(
        self,
        *,
        admission_id: uuid.UUID,
        discovery_job_id: uuid.UUID,
        endpoint_binding_hash: str,
    ) -> AdmissionGrant:
        body = self._post(
            "/consume",
            {
                "admission_id": str(admission_id),
                "discovery_job_id": str(discovery_job_id),
                "endpoint_binding_hash": endpoint_binding_hash,
            },
        )
        return self._grant(body)

    @staticmethod
    def _grant(body: dict) -> AdmissionGrant:
        try:
            return AdmissionGrant(
                registration_id=uuid.UUID(str(body["registration_id"])),
                identity_version=int(body["identity_version"]),
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise WorkerAdmissionUnavailable("admission_response_malformed") from exc


class HttpxAdmissionTransport:
    """The shipped production transport: CA-validated HTTPS to the internal admission endpoint.

    The base URL + CA bundle are deployment-local worker settings. TLS server-certificate validation
    uses the configured CA when provided, else the system trust store — it is NEVER disabled
    (``verify`` is provably never ``False``). ``httpx`` is imported lazily so this module — and the
    worker discovery package — carry no network/transport import at rest; the transport is
    constructed ONLY when the deployment-local live profile supplies an endpoint. Worker
    authentication is the Ed25519 signed-nonce proof carried in the request bodies, NOT a client
    certificate (this is not X.509 mTLS)."""

    def __init__(self, *, base_url: str, ca_path: str = "", timeout: float = 10.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._ca_path = ca_path
        self._timeout = timeout

    def __repr__(self) -> str:
        return f"HttpxAdmissionTransport(base_url={self._base_url!r})"

    @property
    def base_url(self) -> str:
        return self._base_url

    def post(self, path: str, payload: dict) -> tuple[int, dict]:
        import httpx

        verify: str | bool = self._ca_path if self._ca_path else True
        with httpx.Client(verify=verify, timeout=self._timeout) as client:
            resp = client.post(self._base_url + path, json=payload)
        try:
            body = resp.json()
        except ValueError:
            body = {}
        # Unwrap FastAPI's error envelope so callers see the closed reason code directly.
        if isinstance(body, dict) and isinstance(body.get("detail"), dict):
            body = body["detail"]
        if not isinstance(body, dict):
            body = {}
        return resp.status_code, body
