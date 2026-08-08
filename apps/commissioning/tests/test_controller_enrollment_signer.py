"""Root-gated controller enrollment offer signer + signer review S1-S4 (SECP-PR5H-B1, Phase 2).

Hermetic (in-memory hardened filesystem, no real root). Covers: a valid single-file root-owned 0600
key signs a worker-verifiable offer; every unsafe key condition refuses; S1 the strict validated
signing context refuses malformed / non-canonical / oversized / path-shaped / secret-like / control-
character input before the key is read; S2 the ACTIVE identity is proven at sign time through a held
lease (a superseded / revoked / unverified / ambiguous / changed identity refuses even when the old
matching key remains on disk); S3 key preparation is create-or-adopt with read-back + receipt-match
compensation and rotation is an atomic replace; S4 the signer repr is a constant ``<redacted>``.
"""

from __future__ import annotations

from contextlib import contextmanager

import pytest
from secp_commissioning import enrollment_attestation as ea
from secp_commissioning.controller_enrollment_signer import (
    CONTROLLER_ENROLLMENT_KEY_PATH,
    AuthorizedControllerOfferContext,
    ControllerEnrollmentOfferSigner,
    ControllerEnrollmentSignerError,
    SealedControllerEnrollmentSigner,
    SigningIdentityLease,
    prepare_controller_enrollment_key,
    rotate_controller_enrollment_key,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.signing import generate_keypair

ORIGIN = "https://ctrl.example.test"
RELEASE = "sha256:" + "a" * 64
INSTALL = "controller-aaaaaaaa"
NOW = "2026-07-26T00:00:00+00:00"
_ANCESTORS = ("/var", "/var/lib", "/var/lib/secp", "/var/lib/secp/bootstrap")


def _fs() -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    for d in _ANCESTORS:
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    return fs


def _lease(identity: dict[str, str], **over: str) -> SigningIdentityLease:
    fields = dict(
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
    fields.update(over)
    return SigningIdentityLease(**fields)  # type: ignore[arg-type]


class _Provider:
    """In-memory ActiveControllerSigningIdentityProvider double: yields the currently-configured
    live lease (a rotation is simulated by ``set``-ing a new lease) or raises a bounded refusal."""

    def __init__(self, lease: SigningIdentityLease | None = None, error: Exception | None = None):
        self._lease = lease
        self._error = error

    def set(self, *, lease: SigningIdentityLease | None = None, error: Exception | None = None):
        self._lease, self._error = lease, error

    @contextmanager
    def lease(self):
        if self._error is not None:
            raise self._error
        assert self._lease is not None
        yield self._lease


def _ctx_fields(**over: str) -> dict[str, str]:
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
    return fields


def _ctx(**over: str) -> AuthorizedControllerOfferContext:
    return AuthorizedControllerOfferContext(**_ctx_fields(**over))


def _prepared():
    fs = _fs()
    identity = prepare_controller_enrollment_key(fs, write=True, confirm=True)
    provider = _Provider(_lease(identity))
    signer = ControllerEnrollmentOfferSigner(fs, provider)
    ctx = _ctx(controller_key_id=identity["key_id"])
    return fs, identity, provider, signer, ctx


# --- happy path + verifier round-trip ------------------------------------------------------------


def test_valid_key_and_live_active_identity_signs_a_verifiable_offer():
    _fs_, identity, _provider, signer, ctx = _prepared()
    signed = signer.sign_offer(ctx, now=NOW)
    assert signed.claim["schema"] == ea.OFFER_SCHEMA
    assert signed.attestation.key_id == identity["key_id"]
    ea.verify_detached(
        signed.attestation,
        expected_key_id=identity["key_id"],
        domain=ea.ENROLLMENT_ATTESTATION_DOMAIN,
        kind=ea.OFFER_KIND,
        digest=ea.claim_digest(signed.claim),
    )


# --- S1: strict / canonical / bounded signing input (refused BEFORE the key is read) -------------


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("enrollment_id", "not-a-digest"),  # malformed enrollment id
        ("enrollment_id", "sha256:" + "z" * 64),  # cross/substituted, non-hex
        ("invitation_id", "sha256:" + "g" * 64),  # malformed invitation id
        ("controller_installation_id", "X"),  # bad installation grammar
        ("worker_installation_id", "WORKER"),  # bad installation grammar (uppercase)
        ("controller_key_id", "deadbeef"),  # not a sha256 digest
        ("worker_key_id", "sha256:short"),  # malformed worker key id
        ("release_digest", "release-1"),  # malformed release digest
        ("predecessor_digest", "/etc/passwd"),  # path-shaped predecessor
        ("controller_origin", "http://ctrl.example.test"),  # non-https origin
        ("controller_origin", "https://user:pw@ctrl.example.test"),  # userinfo in origin
        ("controller_transaction_id", "txn\x00bad"),  # control character
        ("controller_transaction_id", "t" * 513),  # oversized field
        ("expires_at", "2999-01-01T00:00:00"),  # non-UTC (naive) timestamp
        ("expires_at", "2999-01-01T00:00:00-05:00"),  # non-UTC offset
        ("expires_at", "2999-01-01T00:00:00.000000000000000000000000+00:00"),  # >40 chars
    ],
)
def test_strict_context_refuses_malformed_input_before_signing(field, value):
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        AuthorizedControllerOfferContext(**_ctx_fields(**{field: value}))
    assert ei.value.reason_code == "controller_enrollment_offer_invalid"


def test_strict_context_refuses_a_secret_like_value():
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        AuthorizedControllerOfferContext(
            **_ctx_fields(controller_transaction_id="-----BEGIN PRIVATE KEY-----")
        )
    assert ei.value.reason_code == "controller_enrollment_offer_invalid"


def test_a_malformed_context_never_reaches_the_key_read():
    # even with NO key on disk, a malformed context refuses at construction (before any fs access)
    with pytest.raises(ControllerEnrollmentSignerError):
        _ctx(worker_key_id="not-a-digest")


# --- S2: prove the CURRENT active identity at sign time ------------------------------------------


def test_a_superseded_identity_signer_refuses_even_though_its_key_remains_on_disk():
    fs, identity_a, provider, signer, _ctx0 = _prepared()
    ctx = _ctx(controller_key_id=identity_a["key_id"])
    assert signer.sign_offer(ctx, now=NOW).attestation.key_id == identity_a["key_id"]  # A signs
    # A is SUPERSEDED in the database while A's matching key still sits at the fixed path: the live
    # lease now yields identity B, so the SAME already-created signer refuses (key derives A,
    # live active identity is B) — it never keeps signing under the retired identity.
    _priv_b, pub_b = generate_keypair()
    identity_b = {
        "key_id": ea.key_id_for(pub_b),
        "public_key_hex": pub_b,
        "enrollment_key_proof_id": ea.enrollment_key_proof_id_for(pub_b),
    }
    provider.set(lease=_lease(identity_b, row_id="row-2", activation_token="row-2|gen-2"))
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(_ctx(controller_key_id=identity_a["key_id"]), now=NOW)
    assert ei.value.reason_code == "controller_enrollment_offer_cross_key"


def test_after_rotation_the_new_active_signer_signs_with_the_new_key():
    fs, _identity_a, provider, signer, _ctx0 = _prepared()
    identity_b = rotate_controller_enrollment_key(fs, write=True, confirm=True)  # new on-disk key
    provider.set(lease=_lease(identity_b, row_id="row-2", activation_token="row-2|gen-2"))
    signed = signer.sign_offer(_ctx(controller_key_id=identity_b["key_id"]), now=NOW)
    assert signed.attestation.key_id == identity_b["key_id"]


@pytest.mark.parametrize(
    "code",
    [
        "controller_enrollment_no_active_identity",
        "controller_enrollment_identity_ambiguous",
        "controller_enrollment_identity_superseded",
        "controller_enrollment_identity_revoked",
        "controller_enrollment_identity_unverified",
        "controller_enrollment_identity_bindings_malformed",
    ],
)
def test_a_lease_refusal_propagates_as_a_bounded_signing_refusal(code):
    fs, identity, provider, signer, ctx = _prepared()
    provider.set(error=ControllerEnrollmentSignerError(code))
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(_ctx(controller_key_id=identity["key_id"]), now=NOW)
    assert ei.value.reason_code == code


def test_an_unexpected_provider_failure_is_a_bounded_closed_refusal():
    fs, identity, provider, signer, _ctx0 = _prepared()
    provider.set(error=RuntimeError("db exploded with a host string"))
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(_ctx(controller_key_id=identity["key_id"]), now=NOW)
    assert ei.value.reason_code == "controller_enrollment_identity_unavailable"


def test_a_key_matching_a_historical_but_not_the_current_identity_refuses():
    # the on-disk key derives identity A, but the live lease is a DIFFERENT active identity whose
    # trust anchor / key id do not match the loaded key -> refuse (never sign under a stale key)
    fs, identity_a, provider, signer, _ctx0 = _prepared()
    _priv_c, pub_c = generate_keypair()
    live = _lease(
        {
            "key_id": ea.key_id_for(pub_c),
            "public_key_hex": pub_c,
            "enrollment_key_proof_id": ea.enrollment_key_proof_id_for(pub_c),
        },
        controller_key_id=identity_a["key_id"],  # lie: claim A's key id but a different anchor
    )
    provider.set(lease=live)
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(_ctx(controller_key_id=identity_a["key_id"]), now=NOW)
    assert ei.value.reason_code == "controller_enrollment_trust_anchor_mismatch"


# --- offer binding + expiry ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "bad", "code"),
    [
        (
            "controller_installation_id",
            "controller-zzzzzzzz",
            "controller_enrollment_offer_cross_installation",
        ),
        (
            "controller_origin",
            "https://evil.example.test",
            "controller_enrollment_offer_cross_origin",
        ),
        ("release_digest", "sha256:" + "9" * 64, "controller_enrollment_offer_cross_release"),
    ],
)
def test_offer_bound_to_a_different_identity_field_refuses(field, bad, code):
    _fs_, identity, _provider, signer, _ctx0 = _prepared()
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(_ctx(controller_key_id=identity["key_id"], **{field: bad}), now=NOW)
    assert ei.value.reason_code == code


def test_expired_offer_refuses():
    _fs_, identity, _provider, signer, _ctx0 = _prepared()
    ctx = _ctx(controller_key_id=identity["key_id"], expires_at="2020-01-01T00:00:00+00:00")
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(ctx, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_offer_expired"


def test_a_malformed_now_refuses():
    _fs_, identity, _provider, signer, _ctx0 = _prepared()
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(_ctx(controller_key_id=identity["key_id"]), now="not-a-time")
    assert ei.value.reason_code == "controller_enrollment_offer_invalid"


# --- filesystem-security refusals on the single key file -----------------------------------------


@pytest.mark.parametrize(
    "mutate",
    [
        "missing",
        "wrong_owner",
        "wrong_mode",
        "symlink",
        "hardlink",
        "untrusted_ancestor",
        "short",
    ],
)
def test_unsafe_key_file_refuses(mutate):
    fs, identity, provider, signer, _ctx0 = _prepared()
    ctx = _ctx(controller_key_id=identity["key_id"])
    if mutate == "missing":
        fs.remove_file(CONTROLLER_ENROLLMENT_KEY_PATH)
    elif mutate == "wrong_owner":
        fs._nodes[CONTROLLER_ENROLLMENT_KEY_PATH].uid = 1000
    elif mutate == "wrong_mode":
        fs._nodes[CONTROLLER_ENROLLMENT_KEY_PATH].mode = 0o644
    elif mutate == "symlink":
        fs.seed_symlink(CONTROLLER_ENROLLMENT_KEY_PATH)
    elif mutate == "hardlink":
        fs._nodes[CONTROLLER_ENROLLMENT_KEY_PATH].nlink = 2
    elif mutate == "untrusted_ancestor":
        fs._nodes["/var/lib/secp/bootstrap"].uid = 1000
    elif mutate == "short":
        fs._nodes[CONTROLLER_ENROLLMENT_KEY_PATH].data = b"\x01" * 16
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        signer.sign_offer(ctx, now=NOW)
    assert ei.value.reason_code == "controller_enrollment_key_unsafe"


# --- S3: crash-, retry- and race-safe key preparation --------------------------------------------


def test_prepare_creates_a_root_owned_single_file_and_reads_it_back():
    fs = _fs()
    identity = prepare_controller_enrollment_key(fs, write=True, confirm=True)
    st = fs.lstat(CONTROLLER_ENROLLMENT_KEY_PATH)
    assert st is not None and st.uid == 0 and st.gid == 0 and (st.mode & 0o777) == 0o600
    assert st.nlink == 1 and not st.is_symlink and st.is_regular and st.size == 32
    # the identity is fully derived from the single file (no separate sidecar exists)
    assert set(identity) == {"key_id", "public_key_hex", "enrollment_key_proof_id"}
    assert fs.list_dir("/var/lib/secp/bootstrap") == ("controller-enrollment-signing.key",)


def test_prepare_is_idempotent_and_adopts_an_existing_valid_key():
    fs = _fs()
    a = prepare_controller_enrollment_key(fs, write=True, confirm=True)
    b = prepare_controller_enrollment_key(
        fs, write=True, confirm=True
    )  # crash-after-create / retry
    assert a == b  # the same key is safely adopted, never replaced


def test_prepare_on_a_present_malformed_key_refuses():
    fs = _fs()
    fs.seed_file(CONTROLLER_ENROLLMENT_KEY_PATH, b"\x01" * 16, uid=0, gid=0, mode=0o600)  # not 32
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        prepare_controller_enrollment_key(fs, write=True, confirm=True)
    assert ei.value.reason_code == "controller_enrollment_key_unsafe"


def test_prepare_requires_write_and_confirm():
    fs = _fs()
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        prepare_controller_enrollment_key(fs, write=True, confirm=False)
    assert ei.value.reason_code == "controller_enrollment_key_prepare_unconfirmed"
    assert fs.lstat(CONTROLLER_ENROLLMENT_KEY_PATH) is None  # dry run writes nothing


class _ReadbackFailFs(InMemoryFilesystem):
    def created_file_matches(self, receipt):  # simulate a file changed after exclusive install
        return False


class _CompensationFailFs(_ReadbackFailFs):
    def remove_created_file(self, receipt):  # simulate compensation itself failing
        return False


def _seed_ancestors(fs: InMemoryFilesystem) -> InMemoryFilesystem:
    for d in _ANCESTORS:
        fs.seed_dir(d, uid=0, gid=0, mode=0o755)
    return fs


def test_prepare_read_back_failure_compensates_and_refuses():
    fs = _seed_ancestors(_ReadbackFailFs())
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        prepare_controller_enrollment_key(fs, write=True, confirm=True)
    assert ei.value.reason_code == "controller_enrollment_key_prepare_readback_failed"
    assert fs.lstat(CONTROLLER_ENROLLMENT_KEY_PATH) is None  # the created key was compensated away


def test_prepare_compensation_failure_raises_a_distinct_code():
    fs = _seed_ancestors(_CompensationFailFs())
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        prepare_controller_enrollment_key(fs, write=True, confirm=True)
    assert ei.value.reason_code == "controller_enrollment_key_compensation_failed"


def test_restart_after_a_completed_preparation_adopts_the_same_key():
    fs = _fs()
    a = prepare_controller_enrollment_key(fs, write=True, confirm=True)
    # a brand-new process (fresh objects) over the SAME persisted file adopts the identical key
    b = prepare_controller_enrollment_key(fs, write=True, confirm=True)
    assert a == b


# --- S3: rotation is a recoverable atomic replace ------------------------------------------------


def test_rotation_atomically_replaces_the_key_and_reads_it_back():
    fs = _fs()
    old = prepare_controller_enrollment_key(fs, write=True, confirm=True)
    new = rotate_controller_enrollment_key(fs, write=True, confirm=True)
    assert new["key_id"] != old["key_id"]
    assert _adopt_matches(fs, new)
    # still exactly one file (no delete-then-create window, no orphan)
    assert fs.list_dir("/var/lib/secp/bootstrap") == ("controller-enrollment-signing.key",)


def test_rotation_requires_a_present_valid_key():
    fs = _fs()  # nothing to rotate FROM
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        rotate_controller_enrollment_key(fs, write=True, confirm=True)
    assert ei.value.reason_code == "controller_enrollment_key_unsafe"


def test_rotation_requires_write_and_confirm():
    fs = _fs()
    prepare_controller_enrollment_key(fs, write=True, confirm=True)
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        rotate_controller_enrollment_key(fs, write=True, confirm=False)
    assert ei.value.reason_code == "controller_enrollment_key_prepare_unconfirmed"


def _adopt_matches(fs: InMemoryFilesystem, identity: dict[str, str]) -> bool:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    raw = fs.safe_read(CONTROLLER_ENROLLMENT_KEY_PATH, max_bytes=1024, expected_uid=0)
    pub_hex = (
        Ed25519PrivateKey.from_private_bytes(raw)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    return ea.key_id_for(pub_hex) == identity["key_id"]


# --- S4: fully redacted representation + non-serializable + sealed default ------------------------


def test_signer_repr_is_a_constant_redaction_with_no_sensitive_value():
    fs, identity, provider, signer, _ctx0 = _prepared()
    lease = _lease(identity)
    r = repr(signer)
    assert r == "ControllerEnrollmentOfferSigner(<redacted>)"
    for secret in (
        identity["key_id"],
        identity["public_key_hex"],
        identity["enrollment_key_proof_id"],
        lease.management_identity_digest,
        lease.bootstrap_evidence_digest,
        RELEASE,
        CONTROLLER_ENROLLMENT_KEY_PATH,
    ):
        assert secret not in r


def test_signer_never_leaks_private_material_and_is_not_serializable():
    import pickle

    fs, _identity, _provider, signer, ctx = _prepared()
    signed = signer.sign_offer(ctx, now=NOW)
    raw_priv_hex = fs.safe_read(
        CONTROLLER_ENROLLMENT_KEY_PATH, max_bytes=1024, expected_uid=0
    ).hex()
    assert raw_priv_hex not in (repr(signer) + repr(signed) + repr(signed.attestation))
    with pytest.raises(ControllerEnrollmentSignerError):
        pickle.dumps(signer)


def test_sealed_default_fails_closed():
    with pytest.raises(ControllerEnrollmentSignerError) as ei:
        SealedControllerEnrollmentSigner().sign_offer(_ctx(), now=NOW)
    assert ei.value.reason_code == "controller_enrollment_signer_unavailable"
