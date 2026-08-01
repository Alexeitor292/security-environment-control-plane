"""Durable worker-enrollment restart-step marker store (SECP WS-B, W4).

Hermetic, over the deterministic in-memory hardened filesystem. Proves durability across store
instances, that the caller-supplied enrollment id never reaches a path, the closed step vocabulary,
the hardened metadata contract on both the directories and the markers, that an untrusted or
malformed marker reads as ABSENT rather than as data, and that a filesystem fault degrades to the
shipped sealed default's (safe) behaviour instead of failing an enrollment.
"""

from __future__ import annotations

import hashlib

import pytest
from secp_commissioning.runtime import InMemoryFilesystem
from secp_worker import enrollment_driver
from secp_worker.enrollment_driver import WorkerEnrollmentDriverError
from secp_worker.enrollment_key import WORKER_ENROLLMENT_ROOT
from secp_worker.enrollment_state_store import (
    WORKER_ENROLLMENT_STATE_DIR,
    WORKER_ENROLLMENT_STEPS,
    DurableWorkerEnrollmentStateStore,
)

ENROLLMENT = "sha256:" + "1" * 64
OTHER_ENROLLMENT = "sha256:" + "2" * 64


def _marker_path(enrollment_id: str) -> str:
    digest = hashlib.sha256(enrollment_id.encode("utf-8")).hexdigest()
    return f"{WORKER_ENROLLMENT_STATE_DIR}/{digest}.step"


def test_the_step_vocabulary_byte_matches_the_drivers_own_constants():
    """The store must never accept a token the driver does not emit, or reject one it does."""
    assert WORKER_ENROLLMENT_STEPS == (
        enrollment_driver._STEP_OFFER_VERIFIED,
        enrollment_driver._STEP_HEALTHY,
    )


def test_a_recorded_step_survives_a_new_store_instance():
    fs = InMemoryFilesystem()

    DurableWorkerEnrollmentStateStore(fs).record(ENROLLMENT, "offer_verified")

    # a RESTARTED worker builds a fresh store over the same host filesystem
    assert DurableWorkerEnrollmentStateStore(fs).load(ENROLLMENT) == "offer_verified"
    DurableWorkerEnrollmentStateStore(fs).record(ENROLLMENT, "healthy")
    assert DurableWorkerEnrollmentStateStore(fs).load(ENROLLMENT) == "healthy"


def test_markers_are_per_enrollment_and_hardened():
    fs = InMemoryFilesystem()
    store = DurableWorkerEnrollmentStateStore(fs)

    store.record(ENROLLMENT, "healthy")

    assert store.load(OTHER_ENROLLMENT) is None  # another enrollment is never answered
    assert fs.lstat(WORKER_ENROLLMENT_ROOT).mode == 0o700
    assert fs.lstat(WORKER_ENROLLMENT_STATE_DIR).mode == 0o700
    marker = fs.lstat(_marker_path(ENROLLMENT))
    assert (marker.mode, marker.uid, marker.gid) == (0o600, 0, 0)


def test_the_enrollment_id_never_enters_the_marker_path():
    hostile = "../../../../etc/secp/planted"
    fs = InMemoryFilesystem()
    store = DurableWorkerEnrollmentStateStore(fs)

    store.record(hostile, "offer_verified")

    written = [p for p in fs.paths() if p.endswith(".step")]
    assert written == [_marker_path(hostile)]  # named by the id's SHA-256, never by the id
    assert written[0].startswith(WORKER_ENROLLMENT_STATE_DIR + "/")
    assert "etc" not in written[0]
    assert store.load(hostile) == "offer_verified"


def test_the_marker_carries_only_the_step_token():
    fs = InMemoryFilesystem()

    DurableWorkerEnrollmentStateStore(fs).record(ENROLLMENT, "offer_verified")

    raw = fs.safe_read(_marker_path(ENROLLMENT), max_bytes=64, expected_uid=0)
    assert raw == b"offer_verified\n"  # no key, offer, claim, attestation, origin or timestamp


@pytest.mark.parametrize("step", ["", "verified", "HEALTHY", "healthy\n../", "offer_verified "])
def test_an_unknown_step_is_refused_and_writes_nothing(step):
    fs = InMemoryFilesystem()

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        DurableWorkerEnrollmentStateStore(fs).record(ENROLLMENT, step)

    assert ei.value.reason_code == "enrollment_worker_state_step_invalid"
    assert WORKER_ENROLLMENT_STATE_DIR not in fs.paths()


@pytest.mark.parametrize("enrollment_id", ["", "x" * 257, None, 7])
def test_a_malformed_enrollment_id_is_refused_on_record_and_absent_on_load(enrollment_id):
    fs = InMemoryFilesystem()
    store = DurableWorkerEnrollmentStateStore(fs)

    with pytest.raises(WorkerEnrollmentDriverError) as ei:
        store.record(enrollment_id, "healthy")

    assert ei.value.reason_code == "enrollment_worker_state_enrollment_id_invalid"
    assert store.load(enrollment_id) is None


@pytest.mark.parametrize("content", [b"tampered", b"", b"offer_verified healthy", b"\xff\xfe"])
def test_a_malformed_marker_value_reads_as_absent(content):
    fs = InMemoryFilesystem()
    fs.seed_dir(WORKER_ENROLLMENT_ROOT, mode=0o700)
    fs.seed_dir(WORKER_ENROLLMENT_STATE_DIR, mode=0o700)
    fs.seed_file(_marker_path(ENROLLMENT), content, mode=0o600)

    assert DurableWorkerEnrollmentStateStore(fs).load(ENROLLMENT) is None


@pytest.mark.parametrize(
    "seed",
    [
        lambda fs, path: fs.seed_file(path, b"healthy\n", mode=0o644),
        lambda fs, path: fs.seed_file(path, b"healthy\n", uid=1000, mode=0o600),
        lambda fs, path: fs.seed_file(path, b"healthy\n", mode=0o600, nlink=2),
        lambda fs, path: fs.seed_symlink(path),
        lambda fs, path: fs.seed_special(path),
        lambda fs, path: fs.seed_dir(path, mode=0o600),
    ],
)
def test_an_untrusted_marker_object_reads_as_absent(seed):
    fs = InMemoryFilesystem()
    fs.seed_dir(WORKER_ENROLLMENT_ROOT, mode=0o700)
    fs.seed_dir(WORKER_ENROLLMENT_STATE_DIR, mode=0o700)
    seed(fs, _marker_path(ENROLLMENT))

    assert DurableWorkerEnrollmentStateStore(fs).load(ENROLLMENT) is None


def test_a_drifted_state_directory_records_nothing_and_stays_absent():
    fs = InMemoryFilesystem()
    fs.seed_dir(WORKER_ENROLLMENT_ROOT, mode=0o700)
    fs.seed_dir(WORKER_ENROLLMENT_STATE_DIR, uid=1000, gid=1000, mode=0o700)
    store = DurableWorkerEnrollmentStateStore(fs)

    # the write is best-effort (it does not raise into the exchange), but nothing is written into
    # an untrusted directory — the absent marker then fails the local health check, which is where
    # a drifted host is meant to be caught.
    assert store.record(ENROLLMENT, "healthy") is None
    assert store.load(ENROLLMENT) is None


def test_a_filesystem_fault_degrades_to_the_sealed_default_behaviour():
    class FaultingFilesystem(InMemoryFilesystem):
        def atomic_install(self, path, data, *, uid, gid, mode):  # noqa: ANN001, ANN201
            raise OSError("no space left on device")

    fs = FaultingFilesystem()
    store = DurableWorkerEnrollmentStateStore(fs)

    # the marker is only a retry HINT — an unpersistable hint must never fail an enrollment the
    # controller has already advanced; it degrades to "no marker", which is safe by design.
    assert store.record(ENROLLMENT, "offer_verified") is None
    assert store.load(ENROLLMENT) is None


def test_the_store_never_represents_a_path_or_a_marker_value():
    fs = InMemoryFilesystem()
    store = DurableWorkerEnrollmentStateStore(fs)
    store.record(ENROLLMENT, "healthy")

    assert repr(store) == "DurableWorkerEnrollmentStateStore(<redacted>)"
    assert not hasattr(store, "__dict__")  # __slots__
