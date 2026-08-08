"""Root-gated controller-enrollment offer signer broker (SECP-PR5H-B1, Phase 3).

Hermetic: an in-memory hardened filesystem signer + an injected peer-credential reader over a real
socketpair, so the full authorize -> request -> sign -> self-verify -> respond path runs with no
real root, socket file, or database. Covers the peer-credential allowlist, the single bounded
operation, request validation, self-verification of the minted offer, the sealed default, and the
production DB ACTIVE-identity lease provider.
"""

from __future__ import annotations

import json
import socket

import pytest
from secp_commissioning import enrollment_attestation as ea
from secp_commissioning.controller_enrollment_signer import (
    AuthorizedControllerOfferContext,
    ControllerEnrollmentOfferSigner,
    ControllerEnrollmentSignerError,
    SealedControllerEnrollmentSigner,
    SignedControllerOffer,
    SigningIdentityLease,
    prepare_controller_enrollment_key,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.enrollment_signer_broker import (
    EnrollmentSignerBroker,
    EnrollmentSignerBrokerError,
    PeerCredentialPolicy,
    PeerCredentials,
    read_peer_credentials,
)
from secp_management.enrollment_signer_identity import DbActiveControllerSigningIdentityProvider
from secp_management.signing import generate_keypair
from secp_management.systemd import render_enrollment_signer_broker_service
from sqlalchemy import create_engine, text

ORIGIN = "https://ctrl.example.test"
RELEASE = "sha256:" + "a" * 64
INSTALL = "controller-aaaaaaaa"
NOW = "2026-07-26T00:00:00+00:00"
_ANCESTORS = ("/var", "/var/lib", "/var/lib/secp", "/var/lib/secp/bootstrap")
_API_UID, _API_GID = 1000, 1000
from contextlib import contextmanager  # noqa: E402


class _Provider:
    def __init__(self, lease: SigningIdentityLease) -> None:
        self._lease = lease

    @contextmanager
    def lease(self):
        yield self._lease


def _prepared_signer():
    fs = InMemoryFilesystem()
    for d in _ANCESTORS:
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
    signer = ControllerEnrollmentOfferSigner(fs, _Provider(lease))
    return signer, identity


def _context(identity, **over) -> AuthorizedControllerOfferContext:
    fields = dict(
        enrollment_id="sha256:" + "1" * 64,
        invitation_id="sha256:" + "2" * 64,
        organization_id="11111111-1111-1111-1111-111111111111",
        controller_installation_id=INSTALL,
        controller_key_id=identity["key_id"],
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


def _request(context: AuthorizedControllerOfferContext) -> bytes:
    import dataclasses

    fields = {f.name: getattr(context, f.name) for f in dataclasses.fields(context)}
    return json.dumps({"op": "sign_offer", "now": NOW, "context": fields}).encode("utf-8")


def _roundtrip(broker: EnrollmentSignerBroker, request: bytes) -> dict:
    client, server = socket.socketpair()
    try:
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        broker.handle_connection(server)
        raw = client.recv(65536)
    finally:
        client.close()
        server.close()
    return json.loads(raw.decode("utf-8"))


def _broker(
    signer, *, peer_uid=_API_UID, peer_gid=_API_GID, allowed_peers=((_API_UID, _API_GID),)
) -> EnrollmentSignerBroker:
    return EnrollmentSignerBroker(
        signer=signer,
        peer_policy=PeerCredentialPolicy(allowed_peers=allowed_peers),
        peer_reader=lambda conn: PeerCredentials(pid=1, uid=peer_uid, gid=peer_gid),
    )


# --- happy path ----------------------------------------------------------------------------------


def test_broker_signs_a_worker_verifiable_offer_for_an_authorized_peer():
    signer, identity = _prepared_signer()
    ctx = _context(identity)
    resp = _roundtrip(_broker(signer), _request(ctx))
    assert "error" not in resp
    offer = resp["offer"]
    assert offer["claim"]["schema"] == ea.OFFER_SCHEMA
    # the returned offer verifies under the pinned controller key over its own claim
    ea.verify_detached(
        ea.DetachedAttestation(**offer["attestation"]),
        expected_key_id=identity["key_id"],
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.OFFER_KIND,
        digest=ea.claim_digest(offer["claim"]),
    )


# --- peer credential allowlist -------------------------------------------------------------------


def test_an_unauthorized_peer_uid_is_refused_closed():
    signer, _ = _prepared_signer()
    resp = _roundtrip(_broker(signer, peer_uid=4242), _request(_context(_prepared_signer()[1])))
    assert resp == {"error": "enrollment_signer_peer_unauthorized"}


def test_an_unauthorized_peer_gid_is_refused_closed():
    signer, identity = _prepared_signer()
    resp = _roundtrip(_broker(signer, peer_gid=4242), _request(_context(identity)))
    assert resp == {"error": "enrollment_signer_peer_unauthorized"}


def test_the_peer_policy_refuses_an_empty_or_root_allowlist():
    with pytest.raises(EnrollmentSignerBrokerError) as ei:
        PeerCredentialPolicy(allowed_peers=())
    assert ei.value.reason_code == "enrollment_signer_peer_policy_empty"
    with pytest.raises(EnrollmentSignerBrokerError) as ei2:
        PeerCredentialPolicy(allowed_peers=((0, 1000),))
    assert ei2.value.reason_code == "enrollment_signer_peer_policy_root_forbidden"
    with pytest.raises(EnrollmentSignerBrokerError) as ei3:
        PeerCredentialPolicy(allowed_peers=((1000, 0),))  # root gid is equally forbidden
    assert ei3.value.reason_code == "enrollment_signer_peer_policy_root_forbidden"


def test_a_crossed_uid_gid_pair_cannot_authenticate():
    """C5: authorization is by the EXACT (uid, gid) pair. A peer presenting an allowlisted uid with
    a DIFFERENT allowlisted gid (or vice versa) — a crossed combination that independent uid/gid
    allowlists would have wrongly admitted — is refused closed."""
    signer, identity = _prepared_signer()
    peers = ((1000, 1000), (2000, 2000))
    # crossed: uid 1000 (allowed in pair (1000,1000)) + gid 2000 (allowed in pair (2000,2000))
    resp = _roundtrip(
        _broker(signer, peer_uid=1000, peer_gid=2000, allowed_peers=peers),
        _request(_context(identity)),
    )
    assert resp == {"error": "enrollment_signer_peer_unauthorized"}
    # the exact pairs still authenticate
    ok = _roundtrip(
        _broker(signer, peer_uid=2000, peer_gid=2000, allowed_peers=peers),
        _request(_context(identity)),
    )
    assert "error" not in ok


def test_peer_credentials_unavailable_is_bounded():
    class _BadConn:
        def getsockopt(self, *a):
            raise OSError("no peercred")

    with pytest.raises(EnrollmentSignerBrokerError) as ei:
        read_peer_credentials(_BadConn())
    assert ei.value.reason_code == "enrollment_signer_peer_credentials_unavailable"


# --- one bounded operation only ------------------------------------------------------------------


def test_a_non_sign_operation_is_refused():
    signer, _ = _prepared_signer()
    resp = _roundtrip(_broker(signer), json.dumps({"op": "read_key"}).encode("utf-8"))
    assert resp == {"error": "enrollment_signer_request_invalid"}


def test_malformed_json_is_refused():
    signer, _ = _prepared_signer()
    resp = _roundtrip(_broker(signer), b"{not json")
    assert resp == {"error": "enrollment_signer_request_invalid"}


def test_an_oversized_request_is_refused():
    signer, _ = _prepared_signer()
    resp = _roundtrip(_broker(signer), b'{"op":"sign_offer","x":"' + b"z" * 9000 + b'"}')
    assert resp == {"error": "enrollment_signer_request_too_large"}


def test_a_malformed_context_field_is_refused_before_signing():
    signer, identity = _prepared_signer()
    ctx = _context(identity)
    import dataclasses

    fields = {f.name: getattr(ctx, f.name) for f in dataclasses.fields(ctx)}
    fields["controller_origin"] = "http://not-https"  # fails the strict origin grammar
    bad = json.dumps({"op": "sign_offer", "now": NOW, "context": fields}).encode("utf-8")
    resp = _roundtrip(_broker(signer), bad)
    assert resp == {"error": "controller_enrollment_offer_invalid"}


# --- sealed default + self-verification ----------------------------------------------------------


def test_a_sealed_signer_refuses_closed():
    resp = _roundtrip(
        _broker(SealedControllerEnrollmentSigner()), _request(_context(_prepared_signer()[1]))
    )
    assert resp == {"error": "controller_enrollment_signer_unavailable"}


def test_the_broker_refuses_an_offer_that_fails_self_verification():
    identity = _prepared_signer()[1]

    class _TamperingSigner:
        def sign_offer(self, context, *, now):
            claim = ea.controller_offer_claim(
                enrollment_id=context.enrollment_id,
                invitation_id=context.invitation_id,
                controller_installation_id=context.controller_installation_id,
                controller_key_id=context.controller_key_id,
                controller_origin=context.controller_origin,
                controller_transaction_id=context.controller_transaction_id,
                worker_installation_id=context.worker_installation_id,
                worker_key_id=context.worker_key_id,
                release_digest=context.release_digest,
                expires_at=context.expires_at,
                predecessor_digest=context.predecessor_digest,
            )
            # an attestation whose public key does not derive the pinned key id -> fails self-verify
            bad = ea.DetachedAttestation(
                algorithm="Ed25519",
                key_id=claim["controller_key_id"],
                public_key_hex="0" * 64,
                signature="0" * 128,
            )
            ownership_claim = ea.controller_ownership_claim(
                organization_id=context.organization_id,
                controller_installation_id=context.controller_installation_id,
                controller_key_id=context.controller_key_id,
                controller_origin=context.controller_origin,
                controller_trust_anchor_id="sha256:" + "7" * 64,
                worker_key_id=context.worker_key_id,
                enrollment_id=context.enrollment_id,
                invitation_id=context.invitation_id,
                controller_transaction_id=context.controller_transaction_id,
                release_digest=context.release_digest,
                predecessor_digest=context.predecessor_digest,
            )
            return SignedControllerOffer(
                claim=claim,
                attestation=bad,
                ownership_claim=ownership_claim,
                ownership_attestation=bad,
            )

    resp = _roundtrip(_broker(_TamperingSigner()), _request(_context(identity)))
    assert resp == {"error": "controller_enrollment_offer_self_verify_failed"}


# --- production DB ACTIVE-identity lease provider ------------------------------------------------


def _identity_db(tmp_path, *, status="active", verified=1, rows=1):
    url = f"sqlite+pysqlite:///{(tmp_path / 'identity.db').as_posix()}"
    engine = create_engine(url, future=True)
    _, pub = generate_keypair()
    with engine.begin() as conn:
        conn.exec_driver_sql(
            "CREATE TABLE controller_enrollment_identity ("
            "id TEXT PRIMARY KEY, status TEXT, controller_installation_id TEXT, "
            "controller_key_id TEXT, controller_trust_anchor_hex TEXT, controller_origin TEXT, "
            "release_digest TEXT, management_identity_digest TEXT, bootstrap_evidence_digest TEXT, "
            "enrollment_key_proof_id TEXT, verified INTEGER, activated_at TEXT)"
        )
        for i in range(rows):
            conn.execute(
                text(
                    "INSERT INTO controller_enrollment_identity VALUES (:id, :status, :inst, :kid, "
                    ":anchor, :origin, :rel, :mgmt, :boot, :proof, :verified, :activated)"
                ),
                {
                    "id": f"row-{i}",
                    "status": status,
                    "inst": INSTALL,
                    "kid": ea.key_id_for(pub),
                    "anchor": pub,
                    "origin": ORIGIN,
                    "rel": RELEASE,
                    "mgmt": "sha256:" + "e" * 64,
                    "boot": "sha256:" + "f" * 64,
                    "proof": ea.enrollment_key_proof_id_for(pub),
                    "verified": verified,
                    "activated": "2026-07-01T00:00:00+00:00",
                },
            )
    return engine


def test_db_provider_leases_the_single_verified_active_identity(tmp_path, monkeypatch):
    import secp_management.enrollment_signer_identity as signer_identity

    monkeypatch.setattr(
        signer_identity,
        "_observe_tls_trust_anchor_id",
        lambda: "sha256:" + "7" * 64,
    )
    provider = DbActiveControllerSigningIdentityProvider(_identity_db(tmp_path))
    with provider.lease() as lease:
        assert lease.controller_installation_id == INSTALL
        assert lease.controller_origin == ORIGIN
        assert lease.release_digest == RELEASE
        assert lease.controller_tls_trust_anchor_id == "sha256:" + "7" * 64
        assert lease.enrollment_key_proof_id.startswith("enrkp:")


def test_db_provider_refuses_when_no_active_identity(tmp_path):
    provider = DbActiveControllerSigningIdentityProvider(_identity_db(tmp_path, status="revoked"))
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        with provider.lease():
            pass
    assert ei.value.reason_code == "controller_enrollment_identity_unavailable"


def test_db_provider_refuses_an_unverified_identity(tmp_path):
    provider = DbActiveControllerSigningIdentityProvider(_identity_db(tmp_path, verified=0))
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        with provider.lease():
            pass
    assert ei.value.reason_code == "controller_enrollment_identity_unverified"


# --- systemd unit --------------------------------------------------------------------------------


def test_broker_systemd_unit_is_root_uds_only_and_disabled_by_default():
    unit = render_enrollment_signer_broker_service(
        exec_argv=("/usr/bin/python3", "-m", "secp_management.enrollment_signer_broker"),
    )
    assert "User=root" in unit
    assert "RestrictAddressFamilies=AF_UNIX\n" in unit or "RestrictAddressFamilies=AF_UNIX" in unit
    assert "AF_INET" not in unit  # no TCP family, ever
    assert "RuntimeDirectory=secp" in unit
    assert "ReadOnlyPaths=/var/lib/secp/bootstrap/controller-enrollment-signing.key" in unit
    assert "[Install]" not in unit  # present-but-disabled until an operator enables it
    assert "CapabilityBoundingSet=" in unit and "NoNewPrivileges=yes" in unit
