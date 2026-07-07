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
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

_ADMISSION_BASE_PATH = "/internal/worker-discovery-admission"


class WorkerAdmissionUnavailable(Exception):
    """Fail-closed: no valid control-plane admission could be obtained. Closed reason code only."""

    def __init__(self, reason_code: str = "worker_admission_unavailable") -> None:
        super().__init__(f"worker discovery admission unavailable: {reason_code}")
        self.reason_code = reason_code


# --- strict admission-response validators ------------------------------------
# A generic HTTP 200 is NOT sufficient: every field is validated for presence, type, consistency
# with the request, and the exact lifecycle status. Any deviation fails closed as
# ``admission_response_malformed`` — the worker never trusts a self-asserted or mismatched grant.


def _malformed() -> WorkerAdmissionUnavailable:
    return WorkerAdmissionUnavailable("admission_response_malformed")


def _req_uuid(body: dict, key: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(body[key]))
    except (KeyError, ValueError, TypeError, AttributeError):
        raise _malformed() from None


def _req_nonempty_str(body: dict, key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise _malformed()
    return value


def _req_positive_int(body: dict, key: str) -> int:
    value = body.get(key)
    # bool is an int subclass — reject it explicitly; require a strictly positive integer.
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise _malformed()
    return value


def _req_status(body: dict, expected: str) -> None:
    if body.get("status") != expected:
        raise _malformed()


def _req_echo(body: dict, key: str, expected: str) -> None:
    value = body.get(key)
    if not isinstance(value, str) or value != expected:
        raise _malformed()


def _req_future_datetime(body: dict, key: str) -> datetime:
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise _malformed()
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise _malformed() from None
    aware = parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    if aware <= datetime.now(UTC):
        raise _malformed()  # stale / already-expired admission
    return aware


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
        # Strict /begin validation: every field present + correctly typed, echoed consistently with
        # the request (job id + endpoint digest), a strictly-positive identity version, and a
        # genuinely FUTURE expiry. A generic 200 with missing/mismatched fields fails closed here —
        # before the private key ever signs anything.
        admission_id = _req_uuid(begin, "admission_id")
        nonce = _req_nonempty_str(begin, "nonce")
        organization_id = _req_uuid(begin, "organization_id")
        worker_registration_id = _req_uuid(begin, "worker_registration_id")
        identity_version = _req_positive_int(begin, "identity_version")
        if _req_uuid(begin, "discovery_job_id") != discovery_job_id:
            raise _malformed()  # response is for a different job than requested
        _req_echo(begin, "endpoint_binding_hash", endpoint_binding_hash)
        expires_at = _req_future_datetime(begin, "expires_at")

        message = admission_signing_message(
            nonce=nonce,
            organization_id=str(organization_id),
            discovery_job_id=str(discovery_job_id),
            worker_registration_id=str(worker_registration_id),
            identity_version=identity_version,
            endpoint_binding_hash=endpoint_binding_hash,
            expires_at=expires_at,
        )
        signature = ed25519_sign(private_key_hex=self._private_key_hex, message=message)
        complete = self._post(
            "/complete",
            {
                "admission_id": str(admission_id),
                "public_anchor": self._public_anchor_hex,
                "signature": signature,
            },
        )
        # /complete must be EXACTLY ``admitted`` for THIS admission id — nothing else counts.
        _req_status(complete, "admitted")
        _req_echo(complete, "admission_id", str(admission_id))
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
        # Exact phase (``valid``) for THIS admission id, then a validated grant.
        _req_status(body, "valid")
        _req_echo(body, "admission_id", str(admission_id))
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
        # Exact phase (``consumed``) for THIS admission id, then a validated grant.
        _req_status(body, "consumed")
        _req_echo(body, "admission_id", str(admission_id))
        return self._grant(body)

    @staticmethod
    def _grant(body: dict) -> AdmissionGrant:
        # The authoritative registration id + a strictly-positive identity version. A zero/negative
        # version (an unapprovable identity) or a malformed id fails closed.
        return AdmissionGrant(
            registration_id=_req_uuid(body, "registration_id"),
            identity_version=_req_positive_int(body, "identity_version"),
        )


# The shipped production transport (CA-validated HTTPS) lives in
# ``secp_worker.admission_http_transport`` — OUTSIDE the discovery package, which must stay
# transport-free (the SECP-B5 guard forbids ``httpx`` under ``secp_worker/target_discovery``). The
# composition wiring constructs that transport and injects it into this client.
