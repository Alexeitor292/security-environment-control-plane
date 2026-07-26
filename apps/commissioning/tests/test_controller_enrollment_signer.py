"""Root-gated controller enrollment offer signer (SECP-PR5H-B1, Phase 2).

Exercises the dedicated enrollment key's full lifecycle and refusal surface hermetically via the
in-memory hardened filesystem (no real root needed): a valid root-owned 0600 key signs a verifiable
offer, and every unsafe condition — missing / malformed / wrong-owner / wrong-mode / symlink /
hard-link / untrusted-ancestor key, pin mismatch, public/private mismatch, key-id / trust-anchor /
proof-id mismatch, evidence-/release-key reuse, superseded identity, cross-release/origin/
installation offer, expired offer — refuses closed with a bounded reason code before any signing,
and no private material ever appears in a repr, error, or serialization.
"""

from __future__ import annotations

import pytest
from secp_commissioning import enrollment_attestation as ea
from secp_commissioning.controller_enrollment_signer import (
    CONTROLLER_ENROLLMENT_KEY_PATH,
    CONTROLLER_ENROLLMENT_PUB_PATH,
    ControllerEnrollmentOfferSigner,
    ControllerEnrollmentSignerError,
    ControllerOfferRequest,
    ExpectedControllerIdentity,
    SealedControllerEnrollmentSigner,
    prepare_controller_enrollment_key,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.signing import generate_keypair

ORIGIN = "https://ctrl.example.test"
RELEASE = "sha256:" + "a" * 64
_ANCESTORS = ("/var", "/var/lib", "/var/lib/secp", "/var/lib/secp/bootstrap")


def _fs() -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    for d in _ANCESTORS:
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    return fs


def _expected(identity: dict[str, str], **over: str) -> ExpectedControllerIdentity:
    fields = dict(
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id=identity["key_id"],
        controller_trust_anchor_hex=identity["public_key_hex"],
        controller_origin=ORIGIN,
        release_digest=RELEASE,
        enrollment_key_proof_id=identity["enrollment_key_proof_id"],
    )
    fields.update(over)
    return ExpectedControllerIdentity(**fields)


def _request(**over: str) -> ControllerOfferRequest:
    fields = dict(
        enrollment_id="sha256:" + "1" * 64,
        invitation_id="sha256:" + "2" * 64,
        controller_installation_id="controller-aaaaaaaa",
        controller_key_id="",  # filled from identity by the caller
        controller_origin=ORIGIN,
        controller_transaction_id="txn-0001",
        worker_installation_id="worker-bbbbbbbb",
        worker_key_id="sha256:" + "3" * 64,
        release_digest=RELEASE,
        expires_at="2999-01-01T00:00:00+00:00",
        predecessor_digest="sha256:" + "4" * 64,
    )
    fields.update(over)
    return ControllerOfferRequest(**fields)


def _prepared() -> tuple[
    InMemoryFilesystem, dict[str, str], ControllerEnrollmentOfferSigner, ControllerOfferRequest
]:
    fs = _fs()
    identity = prepare_controller_enrollment_key(fs, write=True, confirm=True)
    exp = _expected(identity)
    signer = ControllerEnrollmentOfferSigner(fs, exp)
    req = _request(controller_key_id=identity["key_id"])
    return fs, identity, signer, req


NOW = "2026-07-26T00:00:00+00:00"


# --- happy path + verifier round-trip ------------------------------------------------------------


def test_valid_root_controlled_key_signs_a_verifiable_offer():
    _fs_, identity, signer, req = _prepared()
    signed = signer.sign_offer(req, now=NOW)
    assert signed.claim["schema"] == ea.OFFER_SCHEMA
    assert signed.claim["controller_key_id"] == identity["key_id"]
    assert signed.attestation.key_id == identity["key_id"]
    # the WORKER verifies through the SAME shared verifier, pinning the controller key id
    ea.verify_detached(
        signed.attestation,
        expected_key_id=identity["key_id"],
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.OFFER_KIND,
        digest=ea.claim_digest(signed.claim),
    )


def test_prepare_writes_a_root_owned_0600_key_and_a_pinned_sidecar():
    fs, identity, _signer, _req = _prepared()
    kst = fs.lstat(CONTROLLER_ENROLLMENT_KEY_PATH)
    assert kst is not None and kst.uid == 0 and kst.gid == 0 and (kst.mode & 0o777) == 0o600
    assert kst.nlink == 1 and not kst.is_symlink and kst.is_regular
    pst = fs.lstat(CONTROLLER_ENROLLMENT_PUB_PATH)
    assert pst is not None and (pst.mode & 0o777) == 0o640
    # the raw private key is 32 bytes; the pin exposes only public material
    assert fs.lstat(CONTROLLER_ENROLLMENT_KEY_PATH).size == 32
    import json

    pin = json.loads(fs.safe_read(CONTROLLER_ENROLLMENT_PUB_PATH, max_bytes=4096, expected_uid=0))
    assert set(pin) == {"key_id", "public_key_hex", "enrollment_key_proof_id"}
    assert pin == identity


# --- filesystem-security refusals ----------------------------------------------------------------


def test_missing_key_refuses():
    fs = _fs()  # ancestors exist, but no key was ever prepared
    exp = _expected(
        {
            "key_id": "sha256:" + "b" * 64,
            "public_key_hex": "b" * 64,
            "enrollment_key_proof_id": "enrkp:" + "b" * 64,
        }
    )
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        ControllerEnrollmentOfferSigner(fs, exp).sign_offer(
            _request(controller_key_id=exp.controller_key_id), now=NOW
        )
    assert ei.value.reason_code == "controller_enrollment_key_unsafe"


def test_wrong_owner_key_refuses():
    fs, _identity, signer, req = _prepared()
    fs._nodes[CONTROLLER_ENROLLMENT_KEY_PATH].uid = 1000
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(req, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_key_unsafe"


def test_wrong_mode_key_refuses():
    fs, _identity, signer, req = _prepared()
    fs._nodes[CONTROLLER_ENROLLMENT_KEY_PATH].mode = 0o644
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(req, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_key_unsafe"


def test_symlink_key_refuses():
    fs, _identity, signer, req = _prepared()
    fs.seed_symlink(CONTROLLER_ENROLLMENT_KEY_PATH)
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(req, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_key_unsafe"


def test_hardlinked_key_refuses():
    fs, _identity, signer, req = _prepared()
    fs._nodes[CONTROLLER_ENROLLMENT_KEY_PATH].nlink = 2
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(req, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_key_unsafe"


def test_untrusted_ancestor_refuses():
    fs, _identity, signer, req = _prepared()
    fs._nodes["/var/lib/secp/bootstrap"].uid = 1000  # attacker-owned parent
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(req, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_key_unsafe"


def test_malformed_key_length_refuses():
    fs = _fs()
    fs.seed_file(
        CONTROLLER_ENROLLMENT_KEY_PATH, b"\x01" * 16, uid=0, gid=0, mode=0o600
    )  # not 32 bytes
    exp = _expected(
        {
            "key_id": "sha256:" + "b" * 64,
            "public_key_hex": "b" * 64,
            "enrollment_key_proof_id": "enrkp:" + "b" * 64,
        }
    )
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        ControllerEnrollmentOfferSigner(fs, exp).sign_offer(
            _request(controller_key_id=exp.controller_key_id), now=NOW
        )
    assert ei.value.reason_code == "controller_enrollment_key_unsafe"


# --- pin + key<->identity mismatches -------------------------------------------------------------


def test_public_private_mismatch_pin_refuses():
    fs, _identity, signer, req = _prepared()
    # tamper the pinned public material so it no longer matches the on-disk private key
    import json

    fs._nodes[CONTROLLER_ENROLLMENT_PUB_PATH].data = json.dumps(
        {
            "key_id": "sha256:" + "c" * 64,
            "public_key_hex": "c" * 64,
            "enrollment_key_proof_id": "enrkp:" + "c" * 64,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(req, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_key_pin_mismatch"


def test_malformed_pin_refuses():
    fs, _identity, signer, req = _prepared()
    fs._nodes[CONTROLLER_ENROLLMENT_PUB_PATH].data = b"{not json"
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(req, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_pin_invalid"


def test_key_id_mismatch_against_active_identity_refuses():
    fs, identity, _signer, _req = _prepared()
    exp = _expected(identity, controller_key_id="sha256:" + "d" * 64)  # wrong active key id
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        ControllerEnrollmentOfferSigner(fs, exp).sign_offer(
            _request(controller_key_id=exp.controller_key_id), now=NOW
        )
    assert ei.value.reason_code == "controller_enrollment_key_id_mismatch"


def test_trust_anchor_mismatch_against_active_identity_refuses():
    fs, identity, _signer, req = _prepared()
    exp = _expected(identity, controller_trust_anchor_hex="e" * 64)  # wrong anchor
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        ControllerEnrollmentOfferSigner(fs, exp).sign_offer(req, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_trust_anchor_mismatch"


def test_proof_id_mismatch_against_active_identity_refuses():
    fs, identity, _signer, req = _prepared()
    exp = _expected(identity, enrollment_key_proof_id="enrkp:" + "f" * 64)  # wrong proof id
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        ControllerEnrollmentOfferSigner(fs, exp).sign_offer(req, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_proof_id_mismatch"


def test_a_reused_evidence_or_release_key_cannot_sign_enrollment_offers():
    # the on-disk key is a DIFFERENT key (e.g. the management-evidence / release-signing key), but
    # the active identity is the enrollment identity — the loaded key does not derive it, refuse.
    fs = _fs()
    other_priv, other_pub = generate_keypair()
    import json

    fs.seed_file(
        CONTROLLER_ENROLLMENT_KEY_PATH, bytes.fromhex(other_priv), uid=0, gid=0, mode=0o600
    )
    other_pin = {
        "key_id": ea.key_id_for(other_pub),
        "public_key_hex": other_pub,
        "enrollment_key_proof_id": ea.enrollment_key_proof_id_for(other_pub),
    }
    fs.seed_file(
        CONTROLLER_ENROLLMENT_PUB_PATH,
        json.dumps(other_pin, sort_keys=True, separators=(",", ":")).encode("ascii"),
        uid=0,
        gid=0,
        mode=0o640,
    )
    enrollment_priv, enrollment_pub = generate_keypair()
    exp = _expected(
        {
            "key_id": ea.key_id_for(enrollment_pub),
            "public_key_hex": enrollment_pub,
            "enrollment_key_proof_id": ea.enrollment_key_proof_id_for(enrollment_pub),
        }
    )
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        ControllerEnrollmentOfferSigner(fs, exp).sign_offer(
            _request(controller_key_id=exp.controller_key_id), now=NOW
        )
    assert ei.value.reason_code == "controller_enrollment_trust_anchor_mismatch"


# --- offer binding + expiry ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("controller_key_id", "controller_enrollment_offer_cross_key"),
        ("controller_installation_id", "controller_enrollment_offer_cross_installation"),
        ("controller_origin", "controller_enrollment_offer_cross_origin"),
        ("release_digest", "controller_enrollment_offer_cross_release"),
    ],
)
def test_offer_bound_to_a_different_identity_field_refuses(field, code):
    _fs_, identity, signer, _req = _prepared()
    bad = (
        "controller-zzzzzzzz"
        if field == "controller_installation_id"
        else "https://evil.example.test"
        if field == "controller_origin"
        else "sha256:" + "9" * 64
    )
    fields = {"controller_key_id": identity["key_id"], field: bad}  # the override field wins
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(_request(**fields), now=NOW)
    assert ei.value.reason_code == code


def test_expired_offer_refuses():
    _fs_, identity, signer, _req = _prepared()
    req = _request(controller_key_id=identity["key_id"], expires_at="2020-01-01T00:00:00+00:00")
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(req, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_offer_expired"


def test_malformed_offer_timestamp_refuses():
    _fs_, identity, signer, _req = _prepared()
    req = _request(controller_key_id=identity["key_id"], expires_at="not-a-time")
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(req, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_offer_invalid"


# --- restart + rotation --------------------------------------------------------------------------


def test_restart_reloads_the_same_identity_and_signs_identically():
    fs, identity, _signer, req = _prepared()
    exp = _expected(identity)
    a = ControllerEnrollmentOfferSigner(fs, exp).sign_offer(req, now=NOW)
    # a brand-new signer over the SAME persisted key + identity (a restart) signs the same claim
    b = ControllerEnrollmentOfferSigner(fs, exp).sign_offer(req, now=NOW)
    assert a.claim == b.claim and a.attestation.signature == b.attestation.signature


def test_rotation_makes_only_the_new_active_signer_usable():
    fs, old_identity, _signer, _req = _prepared()
    old_exp = _expected(old_identity)
    # rotate: remove the old key/pin and provision a NEW dedicated enrollment key in place
    fs.remove_file(CONTROLLER_ENROLLMENT_KEY_PATH)
    fs.remove_file(CONTROLLER_ENROLLMENT_PUB_PATH)
    new_identity = prepare_controller_enrollment_key(fs, write=True, confirm=True)
    assert new_identity["key_id"] != old_identity["key_id"]
    new_exp = _expected(new_identity)
    new_req = _request(controller_key_id=new_identity["key_id"])
    # the NEW active signer signs; the OLD (superseded) identity no longer matches the on-disk key
    ControllerEnrollmentOfferSigner(fs, new_exp).sign_offer(new_req, now=NOW)
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        ControllerEnrollmentOfferSigner(fs, old_exp).sign_offer(
            _request(controller_key_id=old_identity["key_id"]), now=NOW
        )
    assert ei.value.reason_code == "controller_enrollment_trust_anchor_mismatch"


# --- sealed default + non-serializable + no leakage ----------------------------------------------


def test_sealed_default_fails_closed():
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        SealedControllerEnrollmentSigner().sign_offer(_request(controller_key_id="x"), now=NOW)
    assert ei.value.reason_code == "controller_enrollment_signer_unavailable"


def test_prepare_requires_write_and_confirm():
    fs = _fs()
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        prepare_controller_enrollment_key(fs, write=True, confirm=False)
    assert ei.value.reason_code == "controller_enrollment_key_prepare_unconfirmed"
    assert fs.lstat(CONTROLLER_ENROLLMENT_KEY_PATH) is None  # nothing written on a dry run


def test_signer_never_leaks_key_material_and_is_not_serializable():
    import pickle

    fs, identity, signer, req = _prepared()
    signed = signer.sign_offer(req, now=NOW)
    raw_priv_hex = fs.safe_read(
        CONTROLLER_ENROLLMENT_KEY_PATH, max_bytes=1024, expected_uid=0
    ).hex()
    # the private key never appears in the signer repr, the signed offer, or its attestation
    blob = repr(signer) + repr(signed) + repr(signed.attestation)
    assert raw_priv_hex not in blob
    assert identity["key_id"] in repr(signer)  # only the public key id is shown
    with pytest.raises(ControllerEnrollmentSignerError):
        pickle.dumps(signer)
    with pytest.raises(ControllerEnrollmentSignerError):
        pickle.dumps(SealedControllerEnrollmentSigner())
