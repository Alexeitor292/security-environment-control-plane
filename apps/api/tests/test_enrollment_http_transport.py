"""Worker-initiated hardened EnrollmentTransport (SECP-PR5H-B1, T2).

Proves the transport posture offline (no real network / TLS): the outbound origin is strictly
validated; the request goes out pinned to the CA chain CARRIED IN THE INVITATION (``verify`` is an
``ssl.SSLContext`` built with ``cadata``, never True/False and never a file), with
``trust_env=False`` and ``follow_redirects=False``; the worker proof-of-possession attestation in
the body verifies under the worker's own key over the exact binding claim; redirects and big
responses fail closed; the shipped default is sealed; and the signer/transport never serialize or
leak the private key / origin / CA chain.
"""

from __future__ import annotations

import pickle
import ssl

import httpx
import pytest
from secp_commissioning import enrollment_attestation as ea
from secp_management.signing import generate_keypair
from secp_worker.enrollment_http_transport import (
    EnrollmentInvitationInputs,
    EnrollmentTransportError,
    HttpxWorkerEnrollmentTransport,
    SealedEnrollmentTransport,
    WorkerEnrollmentSigner,
)

ORIGIN = "https://controller.example.test"


def _pem(body: str) -> str:
    """A grammar-valid CERTIFICATE chain. ``ssl.create_default_context`` is patched in these tests,
    so the base64 body never has to decode to a real certificate."""
    return f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"


CA_PEM = _pem("MIIBfakeCAforTESTS0000000000000==")
SECRET_CA_PEM = _pem("MIIBsecretCAvalue0000000000000==")


def _signer() -> WorkerEnrollmentSigner:
    priv, _pub = generate_keypair()
    return WorkerEnrollmentSigner(priv)


def _invitation(signer: WorkerEnrollmentSigner) -> EnrollmentInvitationInputs:
    return EnrollmentInvitationInputs(
        enrollment_id="sha256:" + "a" * 64,
        invitation_id="sha256:" + "b" * 64,
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id="sha256:" + "c" * 64,
        controller_origin=ORIGIN,
        controller_transaction_id="txn-0001",
        release_digest="sha256:" + "d" * 64,
        expires_at="2026-07-21T01:00:00+00:00",
        controller_ca_bundle_pem=CA_PEM,
    )


class _FakeResp:
    def __init__(
        self,
        *,
        status=200,
        body=b'{"detail":{"state":"worker_bound"}}',
        is_redirect=False,
        encoding=None,
    ):
        self.status_code = status
        self._body = body
        self.is_redirect = is_redirect
        self.headers = httpx.Headers({"content-encoding": encoding} if encoding else {})

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def aiter_raw(self):
        yield self._body


class _FakeClient:
    captured: dict = {}
    cadata: str | None = None
    resp = _FakeResp()

    def __init__(self, **kw):
        _FakeClient.captured = dict(kw)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def stream(self, method, url, *, content, headers):
        _FakeClient.captured["url"] = url
        _FakeClient.captured["content"] = content
        _FakeClient.captured["req_headers"] = headers
        return _FakeClient.resp


@pytest.fixture
def patched(monkeypatch):
    # keyword-only `cadata`, not `cafile`: the CA now arrives as PEM TEXT in the invitation, so the
    # transport builds its context with `cadata=` and never writes the chain to a file. Capturing it
    # lets the tests below assert the EXACT chain reached ssl.
    # kept off `captured`, which `_FakeClient.__init__` rebuilds after the context is created
    def _context(*, cadata):
        _FakeClient.cadata = cadata
        return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    monkeypatch.setattr(ssl, "create_default_context", _context)
    monkeypatch.setattr(httpx, "AsyncClient", _FakeClient)
    _FakeClient.resp = _FakeResp()
    return _FakeClient


@pytest.mark.parametrize(
    "origin",
    [
        "http://controller.example.test",  # plain HTTP
        "https://user:pass@controller.example.test",  # userinfo
        "https://controller.example.test?x=1",  # query
        "https://controller.example.test#f",  # fragment
        "https://controller.example.test/enroll",  # non-root path
        "https://:8443",  # missing host
        "ftp://controller.example.test",  # other scheme
        "",  # empty
    ],
)
def test_transport_rejects_non_strict_origins(origin):
    with pytest.raises(EnrollmentTransportError):
        HttpxWorkerEnrollmentTransport(
            controller_origin=origin, ca_bundle_pem=CA_PEM, signer=_signer()
        )


def test_the_exact_invitation_ca_chain_reaches_ssl_as_cadata(patched):
    """`cadata`, not `cafile`: the chain arrives as PEM TEXT in the invitation, so there is no file
    to create, no fixed path to reserve, and nothing to clean up. `verify` stays provably an
    SSLContext over exactly this chain — never system trust, never True/False."""
    signer = _signer()
    t = HttpxWorkerEnrollmentTransport(
        controller_origin=ORIGIN, ca_bundle_pem=SECRET_CA_PEM, signer=signer
    )

    t.submit_binding(_invitation(signer))

    assert patched.cadata == SECRET_CA_PEM
    assert isinstance(patched.captured["verify"], ssl.SSLContext)


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "not a pem",
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",  # never a private key
        "-----BEGIN CERTIFICATE-----\nAAAA\n",  # unterminated
    ],
)
def test_a_missing_or_malformed_ca_chain_refuses_at_construction(bad):
    """Refused HERE with a bounded reason code, not as an opaque ssl error at connect time."""
    with pytest.raises(EnrollmentTransportError) as ei:
        HttpxWorkerEnrollmentTransport(
            controller_origin=ORIGIN, ca_bundle_pem=bad, signer=_signer()
        )

    assert ei.value.reason_code in ("enrollment_ca_required", "enrollment_ca_invalid")


def test_the_production_factory_pins_the_transport_to_its_own_invitation(patched):
    from secp_worker.enrollment_http_transport import build_invitation_transport

    signer = _signer()
    invitation = _invitation(signer)

    build_invitation_transport(signer, invitation).submit_binding(invitation)

    assert patched.cadata == invitation.controller_ca_bundle_pem
    assert patched.captured["url"].startswith(invitation.controller_origin)


def test_binding_submit_is_ca_pinned_no_proxy_no_redirects(patched):
    signer = _signer()
    t = HttpxWorkerEnrollmentTransport(
        controller_origin=ORIGIN, ca_bundle_pem=CA_PEM, signer=signer
    )
    status, body = t.submit_binding(_invitation(signer))
    assert status == 200 and body == {"state": "worker_bound"}
    cap = patched.captured
    assert isinstance(cap["verify"], ssl.SSLContext)  # provably never True/False
    assert cap["trust_env"] is False
    assert cap["follow_redirects"] is False
    assert cap["timeout"] is not None
    assert cap["url"] == ORIGIN + "/api/v1/enrollment/sha256:" + "a" * 64 + "/exchange/bind"
    assert cap["req_headers"]["Content-Type"] == "application/json"
    assert cap["req_headers"]["Accept-Encoding"] == "identity"


def test_submitted_pop_attestation_verifies_over_the_binding_claim(patched):
    import json

    signer = _signer()
    t = HttpxWorkerEnrollmentTransport(
        controller_origin=ORIGIN, ca_bundle_pem=CA_PEM, signer=signer
    )
    t.submit_binding(_invitation(signer))
    sent = json.loads(patched.captured["content"])
    claim, att = sent["binding"], sent["attestation"]
    # the controller-side verification: pin the worker key, verify the detached POP over the claim
    assert claim["worker_key_id"] == signer.worker_key_id
    ea.verify_detached(
        ea.DetachedAttestation(**att),
        expected_key_id=signer.worker_key_id,
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.POP_KIND,
        digest=ea.claim_digest(claim),
    )
    # a tampered claim no longer matches the signed digest
    with pytest.raises(ea.AttestationError):
        ea.verify_detached(
            ea.DetachedAttestation(**att),
            expected_key_id=signer.worker_key_id,
            domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
            kind=ea.POP_KIND,
            digest=ea.claim_digest(claim | {"release_digest": "sha256:" + "9" * 64}),
        )


def test_result_submit_signs_a_worker_result(patched):
    import json

    signer = _signer()
    t = HttpxWorkerEnrollmentTransport(
        controller_origin=ORIGIN, ca_bundle_pem=CA_PEM, signer=signer
    )
    health_evidence = {"schema": "secp.worker-enrollment.health/v1", "all_checks_passed": True}
    t.submit_result(
        _invitation(signer),
        predecessor_digest="sha256:" + "e" * 64,
        outcome="ready",
        health_evidence=health_evidence,
        generation="2",
        challenge="sha256:" + "1" * 64,
    )
    sent = json.loads(patched.captured["content"])
    ea.verify_detached(
        ea.DetachedAttestation(**sent["attestation"]),
        expected_key_id=signer.worker_key_id,
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.RESULT_KIND,
        digest=ea.claim_digest(sent["result"]),
    )
    # the transported body carries the raw health-evidence structure, and the signed claim binds its
    # sha256 digest so the controller can recompute it and a swapped body fails verification
    assert sent["health_evidence"] == health_evidence
    assert sent["result"]["health_evidence_digest"] == ea.sha256_digest(health_evidence)
    assert sent["result"]["generation"] == "2"


def test_redirect_response_fails_closed(patched):
    patched.resp = _FakeResp(is_redirect=True)
    signer = _signer()
    t = HttpxWorkerEnrollmentTransport(
        controller_origin=ORIGIN, ca_bundle_pem=CA_PEM, signer=signer
    )
    with pytest.raises(EnrollmentTransportError) as ei:
        t.submit_binding(_invitation(signer))
    assert ei.value.reason_code == "enrollment_redirect_forbidden"


def test_non_identity_content_encoding_fails_closed(patched):
    patched.resp = _FakeResp(encoding="gzip")
    signer = _signer()
    t = HttpxWorkerEnrollmentTransport(
        controller_origin=ORIGIN, ca_bundle_pem=CA_PEM, signer=signer
    )
    with pytest.raises(EnrollmentTransportError) as ei:
        t.submit_binding(_invitation(signer))
    assert ei.value.reason_code == "enrollment_response_invalid"


def test_oversized_response_fails_closed(patched):
    patched.resp = _FakeResp(body=b"x" * (64 * 1024 + 1))
    signer = _signer()
    t = HttpxWorkerEnrollmentTransport(
        controller_origin=ORIGIN, ca_bundle_pem=CA_PEM, signer=signer
    )
    with pytest.raises(EnrollmentTransportError) as ei:
        t.submit_binding(_invitation(signer))
    assert ei.value.reason_code == "enrollment_response_too_large"


def test_sealed_default_fails_closed():
    signer = _signer()
    sealed = SealedEnrollmentTransport()
    with pytest.raises(EnrollmentTransportError) as ei:
        sealed.submit_binding(_invitation(signer))
    assert ei.value.reason_code == "enrollment_transport_not_activated"


def test_signer_and_transport_never_leak_or_serialize():
    priv, pub = generate_keypair()
    signer = WorkerEnrollmentSigner(priv)
    assert signer.worker_key_id == ea.key_id_for(pub)
    assert priv not in repr(signer)  # the private key is never represented
    t = HttpxWorkerEnrollmentTransport(
        controller_origin=ORIGIN, ca_bundle_pem=SECRET_CA_PEM, signer=signer
    )
    assert "controller.example.test" not in repr(t) and SECRET_CA_PEM not in repr(t)
    for obj in (signer, t):
        with pytest.raises(EnrollmentTransportError):
            pickle.dumps(obj)


def test_invitation_mismatch_between_transport_and_invitation_refuses(patched):
    """INTERNAL CONSISTENCY, not origin validation. The driver builds the transport from the
    same invitation it then submits, so this can never authenticate an origin against anything
    independent. It exists to catch a transport cached or reused ACROSS invitations."""
    signer = _signer()
    t = HttpxWorkerEnrollmentTransport(
        controller_origin=ORIGIN, ca_bundle_pem=CA_PEM, signer=signer
    )
    # A SECOND legitimate controller, not an attacker. The origin is deliberately not named
    # adversarially: this check cannot stop an attacker (both sides derive from the same
    # invitation), and an "evil" fixture would quietly re-imply the security meaning the rename
    # removed. What it catches is a transport reused across two honest enrollments.
    other = _invitation(signer)
    other = EnrollmentInvitationInputs(
        **{**other.__dict__, "controller_origin": "https://controller-two.example.test"}
    )
    with pytest.raises(EnrollmentTransportError) as ei:
        t.submit_binding(other)
    assert ei.value.reason_code == "enrollment_transport_invitation_mismatch"
