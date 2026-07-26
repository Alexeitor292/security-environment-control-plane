"""Worker-initiated hardened EnrollmentTransport for the supported worker-enrollment exchange
(SECP-PR5H-B1, T2).

The worker's OUTBOUND HTTPS client for the controller enrollment surface. The worker proves
possession of its locally-generated Ed25519 key by signing a domain-separated binding claim (bound
to the exact enrollment, invitation, controller identity, transaction, release and expiry) and
submitting the detached attestation; the controller VERIFIES that signature before it consumes the
single-use invitation. No private key ever leaves this process.

Transport posture (mirrors the reviewed admission transport, ``HttpxAdmissionTransport``):
server TLS is verified against the EXACT deployment-local CA bundle (``verify`` is provably never
``True``/``False`` — always an ``ssl.SSLContext`` over the configured CA path; never the public /
system trust store and never disabled); ambient environment networking is disabled
(``trust_env=False``); redirects are refused (``follow_redirects=False``); the outbound origin
is the EXACT ``controller_origin`` from the invitation, strictly validated (``https`` only, plain
host[:port], no userinfo/query/fragment/non-root path); request/response bodies are bounded; the
content type is strict; no cookies / credential forwarding; and a connect / TLS / timeout failure
fails closed with a bounded reason code — the ``httpx`` chain (which can carry the host) is dropped
with ``from None``.

This module lives at the worker TOP LEVEL on purpose (the ``httpx`` seam): the enrollment
subpackages stay transport-free. The shipped default is :class:`SealedEnrollmentTransport`, which
fails closed (``enrollment_transport_not_activated``) until a deployment-local profile builds the
real transport with an explicit controller origin + CA bundle + worker signer.
"""

from __future__ import annotations

import asyncio
import json
import math
import re
from dataclasses import dataclass
from typing import NoReturn
from urllib.parse import urlsplit

from secp_commissioning.enrollment_attestation import (
    ENROLLMENT_ATTESTATION_DOMAIN,
    POP_KIND,
    RESULT_KIND,
    DetachedAttestation,
    claim_digest,
    sign_detached,
    worker_binding_claim,
    worker_result_claim,
)

from secp_worker.hardened_http import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    HardenedTransportError,
    parse_bounded_json,
)

# A conservative host / IPv4 literal (no userinfo/ports/whitespace/path/scheme chars).
_SAFE_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-.]*[A-Za-z0-9])?$")
_DEFAULT_TIMEOUT = 10.0
_MAX_TIMEOUT = 30.0
# The bounded, allow-listed worker-facing enrollment paths (per enrollment id, filled at call time).
_BIND_PATH = "/api/v1/enrollment/{enrollment_id}/transport/bind"
_RESULT_PATH = "/api/v1/enrollment/{enrollment_id}/transport/result"


class EnrollmentTransportError(Exception):
    """A bounded, closed transport refusal — carries ONLY a reason code, never the origin, CA path,
    a private key, a raw handoff record or an httpx exception."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _validate_controller_origin(origin: str) -> str:
    if not isinstance(origin, str) or not origin.strip():
        raise EnrollmentTransportError("enrollment_origin_required")
    parts = urlsplit(origin.strip())
    if (
        parts.scheme != "https"
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in ("", "/")
        or not parts.hostname
        or not _SAFE_HOST_RE.fullmatch(parts.hostname)
    ):
        raise EnrollmentTransportError("enrollment_origin_invalid")
    if parts.port is not None and not (1 <= parts.port <= 65535):
        raise EnrollmentTransportError("enrollment_origin_invalid")
    host = parts.hostname + (f":{parts.port}" if parts.port is not None else "")
    return f"https://{host}"


class _NonSerializable:
    """A base that refuses every serialization/copy path so a signer holding a private key can never
    be pickled, copied, or asdict-ed into logs / plans / events."""

    def __reduce__(self) -> NoReturn:
        raise EnrollmentTransportError("enrollment_signer_not_serializable")

    def __getstate__(self) -> NoReturn:
        raise EnrollmentTransportError("enrollment_signer_not_serializable")


class WorkerEnrollmentSigner(_NonSerializable):
    """Holds the worker's locally-generated Ed25519 private key IN MEMORY and signs the enrollment
    binding-PoP + worker-result over the shared attestation primitive. The private key is never
    returned, represented, logged, serialized, or transported."""

    def __init__(self, private_key_hex: str) -> None:
        # derive + cache only the PUBLIC material; validate the key by deriving its public half now
        try:
            att = sign_detached(
                private_key_hex,
                domain=ENROLLMENT_ATTESTATION_DOMAIN,
                kind=POP_KIND,
                digest="sha256:" + "0" * 64,
            )
        except Exception:
            raise EnrollmentTransportError("enrollment_signer_invalid") from None
        self._private_key_hex = private_key_hex
        self._public_key_hex = att.public_key_hex
        self._key_id = att.key_id

    def __repr__(self) -> str:
        return f"WorkerEnrollmentSigner(key_id={self._key_id!r})"  # never the private key

    @property
    def worker_public_key_hex(self) -> str:
        return self._public_key_hex

    @property
    def worker_key_id(self) -> str:
        return self._key_id

    def sign_binding(self, digest: str) -> DetachedAttestation:
        return sign_detached(
            self._private_key_hex,
            domain=ENROLLMENT_ATTESTATION_DOMAIN,
            kind=POP_KIND,
            digest=digest,
        )

    def sign_result(self, digest: str) -> DetachedAttestation:
        return sign_detached(
            self._private_key_hex,
            domain=ENROLLMENT_ATTESTATION_DOMAIN,
            kind=RESULT_KIND,
            digest=digest,
        )


@dataclass(frozen=True)
class EnrollmentInvitationInputs:
    """The non-secret invitation fields the worker received out of band (from the create response).
    The worker echoes these EXACTLY into the binding claim; the controller re-derives them from its
    authoritative invitation and refuses any mismatch."""

    enrollment_id: str
    invitation_id: str
    controller_installation_id: str
    controller_key_id: str
    controller_origin: str
    controller_transaction_id: str
    release_digest: str
    expires_at: str


def _attestation_payload(att: DetachedAttestation) -> dict[str, str]:
    return {
        "algorithm": att.algorithm,
        "key_id": att.key_id,
        "public_key_hex": att.public_key_hex,
        "signature": att.signature,
    }


class HttpxWorkerEnrollmentTransport(_NonSerializable):
    """CA-pinned worker-initiated HTTPS transport to the controller enrollment surface.

    Auth is the Ed25519 signed binding-PoP in the request body, NOT an X.509 client certificate
    (this is not mTLS). The outbound origin is the EXACT ``controller_origin`` from the
    invitation."""

    def __init__(
        self,
        *,
        controller_origin: str,
        ca_path: str,
        signer: WorkerEnrollmentSigner,
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._origin = _validate_controller_origin(controller_origin)
        if not (isinstance(ca_path, str) and ca_path.strip()):
            raise EnrollmentTransportError("enrollment_ca_required")
        self._ca_path = ca_path
        if not isinstance(signer, WorkerEnrollmentSigner):
            raise EnrollmentTransportError("enrollment_signer_invalid")
        self._signer = signer
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int | float)
            or timeout <= 0
            or timeout > _MAX_TIMEOUT
            or not math.isfinite(float(timeout))
        ):
            raise EnrollmentTransportError("enrollment_timeout_invalid")
        self._timeout = float(timeout)

    def __repr__(self) -> str:  # never the origin / CA path / signer private material
        return "HttpxWorkerEnrollmentTransport(<redacted>)"

    def submit_binding(self, invitation: EnrollmentInvitationInputs) -> tuple[int, dict]:
        """Build + sign the worker proof-of-possession binding and submit it. The worker key id in
        the claim is the signer's own key id, so the claim is self-consistent and the controller can
        pin the presented key."""
        if invitation.controller_origin.strip().rstrip("/") != self._origin:
            # the invitation must point at the exact origin this transport is pinned to
            raise EnrollmentTransportError("enrollment_origin_mismatch")
        claim = worker_binding_claim(
            enrollment_id=invitation.enrollment_id,
            invitation_id=invitation.invitation_id,
            controller_installation_id=invitation.controller_installation_id,
            controller_key_id=invitation.controller_key_id,
            controller_transaction_id=invitation.controller_transaction_id,
            worker_installation_id=_installation_from_key(self._signer.worker_key_id),
            worker_key_id=self._signer.worker_key_id,
            release_digest=invitation.release_digest,
            expires_at=invitation.expires_at,
        )
        attestation = self._signer.sign_binding(claim_digest(claim))
        body = {"binding": claim, "attestation": _attestation_payload(attestation)}
        return self._post(_BIND_PATH.format(enrollment_id=invitation.enrollment_id), body)

    def submit_result(
        self, invitation: EnrollmentInvitationInputs, *, predecessor_digest: str, outcome: str
    ) -> tuple[int, dict]:
        claim = worker_result_claim(
            enrollment_id=invitation.enrollment_id,
            controller_transaction_id=invitation.controller_transaction_id,
            worker_key_id=self._signer.worker_key_id,
            predecessor_digest=predecessor_digest,
            release_digest=invitation.release_digest,
            outcome=outcome,
        )
        attestation = self._signer.sign_result(claim_digest(claim))
        body = {"result": claim, "attestation": _attestation_payload(attestation)}
        return self._post(_RESULT_PATH.format(enrollment_id=invitation.enrollment_id), body)

    # --- the hardened outbound POST (mirrors HttpxAdmissionTransport) -----------------------------

    async def _post_async(self, path: str, request_body: bytes) -> tuple[int, bytes]:
        import ssl

        import httpx

        ssl_context = ssl.create_default_context(cafile=self._ca_path)
        async with asyncio.timeout(self._timeout):
            async with httpx.AsyncClient(
                verify=ssl_context,  # EXACT deployment-local CA; never system trust, never disabled
                trust_env=False,  # ignore *_PROXY / SSL_CERT_* / ambient env networking
                follow_redirects=False,  # a redirect is never a valid enrollment response
                timeout=self._timeout,
            ) as client:
                async with client.stream(
                    "POST",
                    self._origin + path,
                    content=request_body,
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                        "Content-Type": "application/json",
                    },
                ) as resp:
                    if resp.is_redirect:
                        raise EnrollmentTransportError("enrollment_redirect_forbidden")
                    encodings = resp.headers.get_list("content-encoding")
                    if len(encodings) > 1 or any(
                        value.strip().lower() != "identity" for value in encodings
                    ):
                        raise EnrollmentTransportError("enrollment_response_invalid")
                    status = resp.status_code
                    response_body = bytearray()
                    async for chunk in resp.aiter_raw():
                        if len(chunk) > MAX_RESPONSE_BYTES - len(response_body):
                            raise HardenedTransportError("response_too_large")
                        response_body.extend(chunk)
                    return status, bytes(response_body)

    def _post(self, path: str, payload: dict) -> tuple[int, dict]:
        try:
            request_body = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            raise EnrollmentTransportError("enrollment_request_invalid") from None
        if len(request_body) > MAX_REQUEST_BYTES:
            raise EnrollmentTransportError("enrollment_request_too_large")
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise EnrollmentTransportError("enrollment_async_context_forbidden")
        try:
            status, raw = asyncio.run(self._post_async(path, request_body))
        except EnrollmentTransportError:
            raise
        except HardenedTransportError as exc:
            reason = (
                "enrollment_response_too_large"
                if exc.reason_code == "response_too_large"
                else "enrollment_response_invalid"
            )
            raise EnrollmentTransportError(reason) from None
        except Exception:
            # a connect / TLS / timeout failure fails closed WITHOUT leaking the origin or CA path
            raise EnrollmentTransportError("enrollment_transport_failed") from None
        try:
            body = parse_bounded_json(raw, max_bytes=MAX_RESPONSE_BYTES)
        except HardenedTransportError:
            raise EnrollmentTransportError("enrollment_response_invalid") from None
        if isinstance(body, dict) and isinstance(body.get("detail"), dict):
            body = body["detail"]
        if not isinstance(body, dict):
            body = {}
        return status, body


class SealedEnrollmentTransport(_NonSerializable):
    """The shipped default: no worker-initiated enrollment transport is activated. Every call fails
    closed (``enrollment_transport_not_activated``) until a deployment-local profile constructs the
    real :class:`HttpxWorkerEnrollmentTransport` with an explicit origin + CA bundle + signer."""

    def __repr__(self) -> str:
        return "SealedEnrollmentTransport(<sealed>)"

    def submit_binding(self, invitation: EnrollmentInvitationInputs) -> tuple[int, dict]:
        raise EnrollmentTransportError("enrollment_transport_not_activated")

    def submit_result(
        self, invitation: EnrollmentInvitationInputs, *, predecessor_digest: str, outcome: str
    ) -> tuple[int, dict]:
        raise EnrollmentTransportError("enrollment_transport_not_activated")


def _installation_from_key(worker_key_id: str) -> str:
    # a deterministic, bounded worker installation label derived from the pinned key id (lowercase
    # hex, grammar-valid); the authoritative worker identity is the key id, this is only a label
    return "worker-" + worker_key_id.split(":", 1)[-1][:16]


__all__ = [
    "EnrollmentInvitationInputs",
    "EnrollmentTransportError",
    "HttpxWorkerEnrollmentTransport",
    "SealedEnrollmentTransport",
    "WorkerEnrollmentSigner",
]
