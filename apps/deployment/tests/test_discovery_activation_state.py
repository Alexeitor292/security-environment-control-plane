"""Hermetic state-backend semantics for PR5F activation transactions."""

from __future__ import annotations

import pytest
from secp_discovery_activation.state import InMemoryWorkerStateFilesystem, WorkerStateError

UID = 1001
GID = 1001


def test_missing_state_prepares_exact_tree_and_empty_compensation_removes_only_created_state() -> (
    None
):
    state = InMemoryWorkerStateFilesystem()

    before = state.inspect(uid=UID, gid=GID)
    receipt = state.prepare(uid=UID, gid=GID)
    prepared = state.inspect(uid=UID, gid=GID)

    assert before.present is False
    assert receipt.classification == "created" and receipt.root_created is True
    assert prepared.present is True and prepared.prepared is True
    assert prepared.key_file_count == prepared.bundle_file_count == 0
    assert state.compensate(receipt, uid=UID, gid=GID) is True
    assert state.present is False and state.prepared is False


def test_adopted_state_is_never_deleted_by_compensation() -> None:
    state = InMemoryWorkerStateFilesystem()
    state.present = True
    state.prepared = True

    receipt = state.prepare(uid=UID, gid=GID)

    assert receipt.classification == "adopted" and receipt.root_created is False
    assert state.compensate(receipt, uid=UID, gid=GID) is True
    assert state.present is True and state.prepared is True


def test_generated_keys_and_bundle_survive_container_recreation_and_compensation() -> None:
    state = InMemoryWorkerStateFilesystem()
    receipt = state.prepare(uid=UID, gid=GID)
    state.keys_generated = True
    state.bundle_populated = True

    metadata = state.inspect(uid=UID, gid=GID)
    compensated = state.compensate(receipt, uid=UID, gid=GID)

    assert metadata.key_file_count == 4 and metadata.bundle_file_count == 4
    assert metadata.keys_generated is True and metadata.bundle_populated is True
    assert compensated is True
    assert state.present is True and state.prepared is True


def test_foreign_partial_tree_is_refused_without_overwrite_or_delete() -> None:
    state = InMemoryWorkerStateFilesystem()
    state.present = True
    state.prepared = False

    with pytest.raises(WorkerStateError) as exc:
        state.prepare(uid=UID, gid=GID)

    assert exc.value.reason_code == "worker_state_root_foreign_or_partial"
    assert state.present is True and state.prepared is False
    assert "compensate" not in state.operations


@pytest.mark.parametrize(
    "reason",
    [
        "worker_state_root_symlink",
        "worker_state_key_hardlink",
        "worker_state_bundle_special_file",
        "worker_state_root_owner_invalid",
        "worker_state_private_mode_invalid",
    ],
)
def test_unsafe_metadata_refuses_before_prepare_and_preserves_foreign_state(reason: str) -> None:
    state = InMemoryWorkerStateFilesystem()
    state.present = True
    state.unsafe_reason = reason

    with pytest.raises(WorkerStateError) as exc:
        state.prepare(uid=UID, gid=GID)

    assert exc.value.reason_code == reason
    assert state.operations == ["inspect"]
    assert state.present is True


def test_failed_compensation_is_reported_without_claiming_removal() -> None:
    state = InMemoryWorkerStateFilesystem()
    receipt = state.prepare(uid=UID, gid=GID)
    state.compensation_succeeds = False

    assert state.compensate(receipt, uid=UID, gid=GID) is False
    assert state.present is True and state.prepared is True


@pytest.mark.parametrize(("uid", "gid"), [(0, GID), (UID, 0), (True, GID), (UID, 65534)])
def test_runtime_identity_is_nonroot_and_bounded(uid: int, gid: int) -> None:
    state = InMemoryWorkerStateFilesystem()
    with pytest.raises(WorkerStateError) as exc:
        state.inspect(uid=uid, gid=gid)
    assert exc.value.reason_code == "worker_state_identity_invalid"
