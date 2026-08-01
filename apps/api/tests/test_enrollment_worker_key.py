"""Fixed-path worker enrollment key seam (SECP WS-B, W1).

Hermetic: every case runs against the deterministic in-memory hardened filesystem, so the
ownership/mode/type refusals are exercised without touching a real host. Proves the write gates,
adoption of an already-provisioned pair, the refusal to repair an incomplete pair, the metadata and
pair-coherence refusals, the bounded host-local observation, and that private material is never
represented.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from secp_commissioning.enrollment_attestation import key_id_for
from secp_commissioning.runtime import InMemoryFilesystem
from secp_worker.enrollment_driver import WorkerEnrollmentDriverError
from secp_worker.enrollment_key import (
    WORKER_ENROLLMENT_KEY_PATH,
    WORKER_ENROLLMENT_PUBLIC_PATH,
    WORKER_ENROLLMENT_ROOT,
    LocalWorkerEnrollmentKeySeam,
    observe_local_worker_enrollment_key,
    prepare_local_worker_enrollment_key,
)


def _prepared() -> InMemoryFilesystem:
    fs = InMemoryFilesystem()
    prepare_local_worker_enrollment_key(fs, write=True, confirm=True)
    return fs


def _foreign_pair() -> tuple[str, str]:
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public = (
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).hex()
    return private, public


def test_preparation_creates_then_adopts_the_same_protected_identity():
    fs = InMemoryFilesystem()

    created = prepare_local_worker_enrollment_key(fs, write=True, confirm=True)
    adopted = prepare_local_worker_enrollment_key(fs, write=True, confirm=True)

    assert created.classification == "created"
    assert adopted.classification == "adopted"
    assert adopted.key_id == created.key_id
    assert created.key_id.startswith("sha256:")
    assert created.canonical() == {"key_id": created.key_id, "classification": "created"}
    assert fs.lstat(WORKER_ENROLLMENT_ROOT).mode == 0o700
    assert fs.lstat(WORKER_ENROLLMENT_KEY_PATH).mode == 0o600  # the private half is never readable
    assert fs.lstat(WORKER_ENROLLMENT_PUBLIC_PATH).mode == 0o644
    # the recorded key id derives from the public anchor actually on disk
    public_hex = fs.safe_read(WORKER_ENROLLMENT_PUBLIC_PATH, max_bytes=64, expected_uid=0)
    assert key_id_for(public_hex.decode("ascii")) == created.key_id


def test_preparation_requires_both_write_gates_without_mutation():
    for write, confirm, reason in (
        (False, True, "enrollment_worker_key_write_authority_required"),
        (True, False, "enrollment_worker_key_confirmation_required"),
    ):
        fs = InMemoryFilesystem()
        with pytest.raises(WorkerEnrollmentDriverError) as ei:
            prepare_local_worker_enrollment_key(fs, write=write, confirm=confirm)
        assert ei.value.reason_code == reason
        assert WORKER_ENROLLMENT_ROOT not in fs.paths()  # not even the root was created


def test_the_seam_loads_an_already_provisioned_key_without_write_authority():
    fs = _prepared()
    expected = observe_local_worker_enrollment_key(fs)

    signer = LocalWorkerEnrollmentKeySeam(fs).load_or_create()  # no write, no confirm

    assert signer.worker_key_id == expected
    assert key_id_for(signer.worker_public_key_hex) == expected


def test_the_seam_refuses_an_absent_key_without_write_authority():
    fs = InMemoryFilesystem()

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        LocalWorkerEnrollmentKeySeam(fs).load_or_create()

    assert ei.value.reason_code == "enrollment_worker_key_absent"
    assert WORKER_ENROLLMENT_ROOT not in fs.paths()  # an unauthorized call provisions nothing


def test_the_seam_provisions_on_first_use_with_explicit_write_authority():
    fs = InMemoryFilesystem()
    seam = LocalWorkerEnrollmentKeySeam(fs, write=True, confirm=True)

    first = seam.load_or_create()
    second = seam.load_or_create()  # the second call adopts, never re-generates

    assert first.worker_key_id == second.worker_key_id
    assert observe_local_worker_enrollment_key(fs) == first.worker_key_id


def test_an_incomplete_pair_is_never_repaired():
    private, _public = _foreign_pair()
    fs = InMemoryFilesystem()
    fs.seed_dir(WORKER_ENROLLMENT_ROOT, mode=0o700)
    fs.seed_file(WORKER_ENROLLMENT_KEY_PATH, private.encode("ascii"), mode=0o600)

    for call in (
        lambda: prepare_local_worker_enrollment_key(fs, write=True, confirm=True),
        lambda: LocalWorkerEnrollmentKeySeam(fs, write=True, confirm=True).load_or_create(),
    ):
        with pytest.raises(WorkerEnrollmentDriverError) as ei:
            call()
        assert ei.value.reason_code == "enrollment_worker_key_pair_incomplete"
    assert WORKER_ENROLLMENT_PUBLIC_PATH not in fs.paths()


def test_a_public_anchor_that_does_not_derive_from_the_private_half_is_refused():
    private, _public = _foreign_pair()
    _other_private, other_public = _foreign_pair()
    fs = InMemoryFilesystem()
    fs.seed_dir(WORKER_ENROLLMENT_ROOT, mode=0o700)
    fs.seed_file(WORKER_ENROLLMENT_KEY_PATH, private.encode("ascii"), mode=0o600)
    fs.seed_file(WORKER_ENROLLMENT_PUBLIC_PATH, other_public.encode("ascii"), mode=0o644)

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        LocalWorkerEnrollmentKeySeam(fs).load_or_create()

    assert ei.value.reason_code == "enrollment_worker_key_pair_mismatch"
    assert observe_local_worker_enrollment_key(fs) == ""


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (
            lambda fs, priv: fs.seed_file(
                WORKER_ENROLLMENT_KEY_PATH, priv.encode("ascii"), mode=0o644
            ),
            "enrollment_worker_key_metadata_invalid",
        ),
        (
            lambda fs, priv: fs.seed_file(
                WORKER_ENROLLMENT_KEY_PATH, priv.encode("ascii"), uid=1000, mode=0o600
            ),
            "enrollment_worker_key_metadata_invalid",
        ),
        (
            lambda fs, priv: fs.seed_file(
                WORKER_ENROLLMENT_KEY_PATH, priv.encode("ascii"), mode=0o600, nlink=2
            ),
            "enrollment_worker_key_hardlinked",
        ),
        (
            lambda fs, priv: fs.seed_symlink(WORKER_ENROLLMENT_KEY_PATH),
            "enrollment_worker_key_symlink",
        ),
        (
            lambda fs, priv: fs.seed_special(WORKER_ENROLLMENT_KEY_PATH),
            "enrollment_worker_key_not_regular",
        ),
        (
            lambda fs, priv: fs.seed_file(WORKER_ENROLLMENT_PUBLIC_PATH, b"x" * 64, mode=0o600),
            "enrollment_worker_key_anchor_metadata_invalid",
        ),
    ],
)
def test_drifted_on_disk_key_metadata_is_refused(mutate, reason):
    private, public = _foreign_pair()
    fs = InMemoryFilesystem()
    fs.seed_dir(WORKER_ENROLLMENT_ROOT, mode=0o700)
    fs.seed_file(WORKER_ENROLLMENT_KEY_PATH, private.encode("ascii"), mode=0o600)
    fs.seed_file(WORKER_ENROLLMENT_PUBLIC_PATH, public.encode("ascii"), mode=0o644)
    mutate(fs, private)

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        LocalWorkerEnrollmentKeySeam(fs).load_or_create()

    assert ei.value.reason_code == reason
    assert observe_local_worker_enrollment_key(fs) == ""  # and it observes as absent, never present


def test_a_non_hex_key_encoding_is_refused():
    _private, public = _foreign_pair()
    fs = InMemoryFilesystem()
    fs.seed_dir(WORKER_ENROLLMENT_ROOT, mode=0o700)
    fs.seed_file(WORKER_ENROLLMENT_KEY_PATH, b"Z" * 64, mode=0o600)
    fs.seed_file(WORKER_ENROLLMENT_PUBLIC_PATH, public.encode("ascii"), mode=0o644)

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        LocalWorkerEnrollmentKeySeam(fs).load_or_create()

    assert ei.value.reason_code == "enrollment_worker_key_encoding_invalid"


def test_a_foreign_owned_root_refuses_provisioning():
    fs = InMemoryFilesystem()
    fs.seed_dir(WORKER_ENROLLMENT_ROOT, uid=1000, gid=1000, mode=0o700)

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        prepare_local_worker_enrollment_key(fs, write=True, confirm=True)

    assert ei.value.reason_code == "enrollment_worker_key_root_unsafe"
    assert WORKER_ENROLLMENT_KEY_PATH not in fs.paths()


def test_a_destination_appearing_mid_install_is_never_overwritten_and_is_compensated():
    foreign = b"a" * 64

    class DestinationAppearanceFilesystem(InMemoryFilesystem):
        injected = False

        def exclusive_install(self, path, data, *, uid, gid, mode):  # noqa: ANN001, ANN201
            if path == WORKER_ENROLLMENT_PUBLIC_PATH and not self.injected:
                self.injected = True
                self.seed_file(path, foreign, uid=0, gid=0, mode=0o644)
            return super().exclusive_install(path, data, uid=uid, gid=gid, mode=mode)

    fs = DestinationAppearanceFilesystem()
    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        prepare_local_worker_enrollment_key(fs, write=True, confirm=True)

    assert ei.value.reason_code == "enrollment_worker_key_install_failed"
    # the foreign object is left untouched and the key we created is compensated away
    assert fs.safe_read(WORKER_ENROLLMENT_PUBLIC_PATH, max_bytes=64, expected_uid=0) == foreign
    assert WORKER_ENROLLMENT_KEY_PATH not in fs.paths()


def test_the_observation_is_bounded_and_never_raises():
    assert observe_local_worker_enrollment_key(InMemoryFilesystem()) == ""
    fs = _prepared()
    observed = observe_local_worker_enrollment_key(fs)
    assert observed.startswith("sha256:")
    assert observed == LocalWorkerEnrollmentKeySeam(fs).load_or_create().worker_key_id


def test_neither_the_seam_nor_the_signer_ever_represents_private_material():
    fs = _prepared()
    seam = LocalWorkerEnrollmentKeySeam(fs, write=True, confirm=True)
    private_hex = fs.safe_read(WORKER_ENROLLMENT_KEY_PATH, max_bytes=64, expected_uid=0).decode()

    signer = seam.load_or_create()

    assert repr(seam) == "LocalWorkerEnrollmentKeySeam(<redacted>)"
    assert private_hex not in repr(seam)
    assert private_hex not in repr(signer)
    assert signer.worker_key_id in repr(signer)
    assert not hasattr(seam, "__dict__")  # __slots__: no private material can be attached
