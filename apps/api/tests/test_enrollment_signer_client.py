"""API-side controller-enrollment offer signer client seam (SECP-PR5H-B1, Phase 3).

Proves the shipped default is sealed and fails closed; the production composition wires the
fixed-UDS client ONLY when a broker socket path is configured; the client is redacted +
non-serializable;
every broker error / malformed response / unreachable socket collapses to a single bounded
``enrollment_signer_unavailable`` (never a broker code or the socket path); and — on POSIX — a real
client<->broker round-trip over a Unix-domain socket yields a worker-verifiable offer.
"""

from __future__ import annotations

import os
import pickle
import socket
import threading

import pytest
from secp_api.config import Settings
from secp_api.enrollment_signer_client import (
    SealedEnrollmentOfferSignerClient,
    UnixSocketEnrollmentOfferSignerClient,
    _parse_offer_response,
    build_enrollment_offer_signer,
)
from secp_api.errors import WorkerEnrollmentError
from secp_commissioning import enrollment_attestation as ea
from secp_commissioning.controller_enrollment_signer import (
    AuthorizedControllerOfferContext,
    ControllerEnrollmentOfferSigner,
    SigningIdentityLease,
    prepare_controller_enrollment_key,
)
from secp_commissioning.runtime import InMemoryFilesystem

ORIGIN = "https://ctrl.example.test"
RELEASE = "sha256:" + "a" * 64
INSTALL = "controller-aaaaaaaa"
NOW = "2026-07-26T00:00:00+00:00"


def test_sealed_default_fails_closed_and_is_non_serializable():
    sealed = SealedEnrollmentOfferSignerClient()
    ctx = _context_stub()
    with pytest.raises(WorkerEnrollmentError) as ei:
        sealed.sign_offer(ctx, now=NOW)
    assert ei.value.code == "enrollment_signer_unavailable"
    assert "sealed" in repr(sealed).lower()
    with pytest.raises(WorkerEnrollmentError):
        pickle.dumps(sealed)


def test_build_returns_sealed_when_the_client_is_disabled():
    signer = build_enrollment_offer_signer(Settings(app_env="dev"))
    assert isinstance(signer, SealedEnrollmentOfferSignerClient)
    # disabled is the default; there is no socket-path setting to configure (C5)
    assert not hasattr(Settings(app_env="dev"), "enrollment_signer_socket_path")


def test_build_returns_the_uds_client_when_enabled():
    signer = build_enrollment_offer_signer(Settings(app_env="dev", enrollment_signer_enabled=True))
    assert isinstance(signer, UnixSocketEnrollmentOfferSignerClient)
    assert "redacted" in repr(signer).lower()
    assert "/run/secp" not in repr(signer)  # the socket path never leaks


def test_the_uds_client_is_pinned_to_the_fixed_code_owned_socket():
    """C5: the client takes NO socket/path argument and binds to the ONE code-owned constant."""
    import inspect

    from secp_commissioning.controller_enrollment_signer import ENROLLMENT_SIGNER_SOCKET_PATH

    params = inspect.signature(UnixSocketEnrollmentOfferSignerClient.__init__).parameters
    assert "socket_path" not in params, (
        "the production UDS client must expose no socket_path override"
    )
    client = UnixSocketEnrollmentOfferSignerClient()
    assert (
        client._socket_path == ENROLLMENT_SIGNER_SOCKET_PATH == "/run/secp/enrollment-signer.sock"
    )


def test_parse_offer_response_reconstructs_a_signed_offer():
    payload = {
        "offer": {
            "claim": {"schema": ea.OFFER_SCHEMA, "enrollment_id": "sha256:" + "1" * 64},
            "attestation": {
                "algorithm": "Ed25519",
                "key_id": "sha256:" + "c" * 64,
                "public_key_hex": "0" * 64,
                "signature": "0" * 128,
            },
        },
        "ownership": {
            "claim": {
                "schema": ea.OWNERSHIP_SCHEMA,
                "controller_key_id": "sha256:" + "c" * 64,
                "controller_trust_anchor_id": "sha256:" + "7" * 64,
            },
            "attestation": {
                "algorithm": "Ed25519",
                "key_id": "sha256:" + "c" * 64,
                "public_key_hex": "0" * 64,
                "signature": "0" * 128,
            },
        },
    }
    offer = _parse_offer_response(payload)
    assert offer.claim["schema"] == ea.OFFER_SCHEMA
    assert offer.attestation.algorithm == "Ed25519"
    assert offer.ownership_claim["schema"] == ea.OWNERSHIP_SCHEMA


@pytest.mark.parametrize(
    "payload",
    [
        {"error": "controller_enrollment_offer_cross_key"},  # a bounded broker error
        {"error": "enrollment_signer_peer_unauthorized"},
        {"offer": {"claim": {}}},  # missing attestation
        {"offer": {"claim": {}, "attestation": {}}, "ownership": {}},  # malformed ownership
        {"offer": {"attestation": {}, "claim": {}}},  # attestation missing fields
        "not-a-dict",
        {},
    ],
)
def test_parse_offer_response_fails_closed_on_any_non_offer(payload):
    with pytest.raises(WorkerEnrollmentError) as ei:
        _parse_offer_response(payload)
    assert ei.value.code == "enrollment_signer_unavailable"  # never surfaces the broker code


def test_an_unreachable_broker_socket_fails_closed(monkeypatch):
    # the location is a code constant; a test double may patch it, but no production surface can.
    import secp_api.enrollment_signer_client as client_mod

    monkeypatch.setattr(
        client_mod, "ENROLLMENT_SIGNER_SOCKET_PATH", "/nonexistent/secp/enroll.sock"
    )
    client = UnixSocketEnrollmentOfferSignerClient()
    with pytest.raises(WorkerEnrollmentError) as ei:
        client.sign_offer(_context_stub(), now=NOW)
    assert ei.value.code == "enrollment_signer_unavailable"


# --- POSIX end-to-end over a real Unix-domain socket ---------------------------------------------


def _context_stub(**over) -> AuthorizedControllerOfferContext:
    fields = dict(
        enrollment_id="sha256:" + "1" * 64,
        invitation_id="sha256:" + "2" * 64,
        organization_id="11111111-1111-1111-1111-111111111111",
        controller_installation_id=INSTALL,
        controller_key_id="sha256:" + "c" * 64,
        controller_origin=ORIGIN,
        controller_transaction_id="txn-0001",
        worker_installation_id="worker-bbbbbbbb",
        worker_key_id="sha256:" + "3" * 64,
        release_digest=RELEASE,
        expires_at="2999-01-01T00:00:00+00:00",
        predecessor_digest="sha256:" + "4" * 64,
    )
    fields.update(over)
    return AuthorizedControllerOfferContext(**fields)


@pytest.mark.skipif(
    os.name != "posix" or getattr(os, "geteuid", lambda: 1)() == 0,
    reason="AF_UNIX server bind + SO_PEERCRED allowlist requires POSIX non-root",
)
def test_client_and_broker_roundtrip_over_a_real_uds(tmp_path, monkeypatch):
    from contextlib import contextmanager

    from secp_management.enrollment_signer_broker import (
        EnrollmentSignerBroker,
        PeerCredentialPolicy,
    )

    fs = InMemoryFilesystem()
    for d in ("/var", "/var/lib", "/var/lib/secp", "/var/lib/secp/bootstrap"):
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    identity = prepare_controller_enrollment_key(fs, write=True, confirm=True)
    lease = SigningIdentityLease(
        row_id="row-1",
        activation_token="row-1|2026-07-01T00:00:00+00:00|gen-1",
        controller_installation_id=INSTALL,
        controller_key_id=identity["key_id"],
        controller_trust_anchor_hex=identity["public_key_hex"],
        controller_tls_trust_anchor_id="sha256:" + "7" * 64,
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        management_identity_digest="sha256:" + "e" * 64,
        bootstrap_evidence_digest="sha256:" + "f" * 64,
        enrollment_key_proof_id=identity["enrollment_key_proof_id"],
    )

    class _Provider:
        @contextmanager
        def lease(self):
            yield lease

    signer = ControllerEnrollmentOfferSigner(fs, _Provider())
    broker = EnrollmentSignerBroker(
        signer=signer,
        peer_policy=PeerCredentialPolicy(allowed_peers=((os.getuid(), os.getgid()),)),
    )
    sock_path = str(tmp_path / "s.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(sock_path)
    listener.listen(1)

    def _serve() -> None:
        conn, _ = listener.accept()
        try:
            broker.handle_connection(conn)
        finally:
            conn.close()

    server = threading.Thread(target=_serve)
    server.start()
    try:
        # the client binds the fixed code constant; a test double patches it to the temp socket.
        import secp_api.enrollment_signer_client as client_mod

        monkeypatch.setattr(client_mod, "ENROLLMENT_SIGNER_SOCKET_PATH", sock_path)
        client = UnixSocketEnrollmentOfferSignerClient()
        offer = client.sign_offer(_context_stub(controller_key_id=identity["key_id"]), now=NOW)
    finally:
        server.join(timeout=5)
        listener.close()
    ea.verify_detached(
        offer.attestation,
        expected_key_id=identity["key_id"],
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.OFFER_KIND,
        digest=ea.claim_digest(offer.claim),
    )
