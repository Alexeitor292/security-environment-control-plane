"""Role-dependent controller/worker transaction-journal schema (SECP-PR5F.1).

The controller transaction journals a private binding of the fixed environment file under the
``controller_env`` key.  ``_validate_journal`` therefore enforces an *exact*, role-dependent key
set: a controller journal MUST carry exactly one valid ``controller_env`` binding, a worker journal
MUST NOT carry it, and neither role admits any other key.

These platform-independent tests drive the production ``_validate_journal`` directly and run the
real ``_write_journal`` -> ``receipt``/``_load_journal`` cycle through the production store (backed
by in-memory journal bytes), so the schema contract cannot regress or hide behind Windows POSIX
skips.  The Linux-root gate additionally runs the same round trip against the real journal path.
"""

from __future__ import annotations

import json

import pytest
import secp_discovery_activation.local_adapter as la
from secp_discovery_activation.adapters import ActivationAdapterError
from secp_discovery_activation.layout import ORDINARY_TASK_QUEUE
from secp_discovery_activation.local_adapter import LocalHostRole

_SHA = "sha256:" + "a" * 64  # a syntactically valid sha256 digest (the schema requires the prefix)
_TXN = "7c9e6679-7425-40de-944b-e07fc1f90ae7"  # a valid version-4 UUID (round-trips canonically)
_ENV_SENTINEL = b"SECP_ADMIN_TOKEN=do-not-persist-these-bytes\n"

_WORKER_BOOL_KEYS = (
    "present",
    "running",
    "healthy",
    "controlled_integration_enabled",
    "worker_managed_bundle_enabled",
    "fixed_worker_paths",
    "state_mount_read_write_only_worker",
    "ca_mount_read_only_worker",
    "discovery_mount_absent_from_other_containers",
    "bundle_prep_loop_started",
    "operator_service_present",
    "operator_container_present",
    "operator_registration_present",
    "operator_queue_polled",
    "generic_activation_subprocess_sealed",
    "generic_executor_subprocess_sealed",
    "plan_only_process_sealed",
    "real_provisioning_enabled",
    "artifacts_prepared",
    "worker_config_installed",
    "worker_recreation_required",
    "worker_generation_changed",
)


def _env_binding(*, mode: int = 0o640, **overrides: object) -> dict[str, object]:
    binding: dict[str, object] = {"digest": _SHA, "uid": 0, "gid": 0, "mode": mode}
    binding.update(overrides)
    return binding


def _execution() -> dict[str, object]:
    return {
        "container_path": "/usr/bin/podman",
        "container_digest": _SHA,
        "compose_path": "/usr/bin/docker-compose",
        "compose_digest": _SHA,
    }


def _effects() -> dict[str, object]:
    return {
        "effects_started": False,
        "controller_changed": False,
        "controller_runtime_changed": False,
        "worker_config_changed": False,
        "worker_recreated": False,
        "evidence_committed": False,
    }


def _controller_journal() -> dict[str, object]:
    roles = la._roles_for(LocalHostRole.controller)
    return {
        "schema": la._JOURNAL_SCHEMA,
        "transaction_id": _TXN,
        "host_role": "controller",
        "status": "staged",
        "render_manifest_sha256": _SHA,
        "profile_content_digest": _SHA,
        "base_compose": {"digest": _SHA, "uid": 0, "gid": 0, "mode": 0o640},
        "before": {role: None for role in roles},
        "after": {role: None for role in roles},
        "effects": _effects(),
        "operation_count": 0,
        "state_receipt": None,
        "execution": _execution(),
        "before_worker": None,
        "before_controller": {
            "controller_config_installed": False,
            "proxy_running": False,
            "proxy_healthy": False,
            "private_listener_only": False,
            "tls_ready": False,
            "activation_route_enabled": False,
            "api_runtime": None,
            "proxy_runtime": None,
            "migration_head": None,
            "migration_head_ready": False,
            "configuration_artifact_digests": [],
        },
        "runtime_after": None,
        "worker_tls_proof": None,
        "controller_env": _env_binding(),
    }


def _worker_journal() -> dict[str, object]:
    roles = la._roles_for(LocalHostRole.worker)
    before_worker: dict[str, object] = {key: False for key in _WORKER_BOOL_KEYS}
    before_worker.update(
        {
            "image_digest": _SHA,
            "generation_digest": _SHA,
            "ordinary_queues": [ORDINARY_TASK_QUEUE],
            "configuration_artifact_digests": [],
            "runtime": None,
        }
    )
    return {
        "schema": la._JOURNAL_SCHEMA,
        "transaction_id": _TXN,
        "host_role": "worker",
        "status": "staged",
        "render_manifest_sha256": _SHA,
        "profile_content_digest": _SHA,
        "base_compose": {"digest": _SHA, "uid": 0, "gid": 0, "mode": 0o640},
        "before": {role: None for role in roles},
        "after": {role: None for role in roles},
        "effects": _effects(),
        "operation_count": 0,
        "state_receipt": {
            "classification": "created",
            "root_created": True,
            "keys_created": True,
            "bundle_created": True,
            "root_device": 1,
            "root_inode": 2,
            "keys_inode": 3,
            "bundle_inode": 4,
        },
        "execution": _execution(),
        "before_worker": before_worker,
        "before_controller": None,
        "runtime_after": None,
        "worker_tls_proof": None,
    }


def _refuses(journal: dict[str, object]) -> str:
    with pytest.raises(ActivationAdapterError) as caught:
        la._validate_journal(journal)
    return caught.value.reason_code


# --- 1: a structurally valid controller journal with exactly one controller_env binding passes ---


def test_valid_controller_journal_with_env_binding_passes() -> None:
    la._validate_journal(_controller_journal())  # no raise
    assert "controller_env" in _controller_journal()


# --- 2: the same controller journal without controller_env refuses (the shipped blocker) ---


def test_controller_journal_without_env_binding_refuses() -> None:
    journal = _controller_journal()
    del journal["controller_env"]
    assert _refuses(journal) == "transaction_journal_malformed"


# --- 3: a controller_env carrying content_b64 refuses (bytes must never be journaled) ---


def test_controller_env_with_content_b64_refuses() -> None:
    journal = _controller_journal()
    journal["controller_env"] = _env_binding(content_b64="Zm9v")
    assert _refuses(journal) == "transaction_journal_malformed"


# --- 4: a controller_env with world-readable mode 0644 refuses (secret-bearing: 0600/0640 only) ---


def test_controller_env_mode_0644_refuses() -> None:
    journal = _controller_journal()
    journal["controller_env"] = _env_binding(mode=0o644)
    assert _refuses(journal) == "transaction_journal_malformed"


# --- 5: malformed controller_env digest/uid/gid/mode/extra-key each refuse ---


@pytest.mark.parametrize(
    "binding",
    [
        {"digest": "not-a-sha", "uid": 0, "gid": 0, "mode": 0o640},  # bad digest
        {
            "digest": "a" * 64,
            "uid": 0,
            "gid": 0,
            "mode": 0o640,
        },  # 64 hex but missing sha256: prefix
        {"digest": _SHA, "uid": 1, "gid": 0, "mode": 0o640},  # non-root uid
        {"digest": _SHA, "uid": 0, "gid": -1, "mode": 0o640},  # negative gid
        {"digest": _SHA, "uid": 0, "gid": 0, "mode": "640"},  # non-int mode
        {"digest": _SHA, "uid": 0, "gid": 0, "mode": 0o640, "extra": 1},  # extra field
        {"digest": _SHA, "uid": 0, "gid": 0},  # missing mode
        None,  # not a binding
    ],
)
def test_controller_env_malformed_fields_refuse(binding: object) -> None:
    journal = _controller_journal()
    journal["controller_env"] = binding
    assert _refuses(journal) == "transaction_journal_malformed"


# --- 6: a valid worker journal without controller_env passes ---


def test_valid_worker_journal_without_env_passes() -> None:
    la._validate_journal(_worker_journal())  # no raise
    assert "controller_env" not in _worker_journal()


# --- 7: a worker journal carrying controller_env refuses (worker must never claim it) ---


def test_worker_journal_with_env_binding_refuses() -> None:
    journal = _worker_journal()
    journal["controller_env"] = _env_binding()
    assert _refuses(journal) == "transaction_journal_malformed"


# --- 8/9: real production write_journal -> receipt/load cycle succeeds, persists no env bytes ---


class _MemJournalStore(la.PosixActivationArtifactStore):
    """Production store with the real journal write/read/validate/receipt path, backed by an
    in-memory byte blob instead of the root-only filesystem — so the exact schema round trip runs
    on any platform without weakening any validation."""

    def __init__(self, host_role: LocalHostRole) -> None:
        super().__init__(host_role)
        self._blobs: dict[str, bytes] = {}

    def _read_absolute(  # type: ignore[override]
        self, path: str, *, allow_missing: bool, max_bytes: int = 0, journal: bool = False
    ) -> la._BoundFile | None:
        data = self._blobs.get(path)
        if data is None:
            if allow_missing:
                return None
            la._closed("activation_artifact_missing")
        return la._BoundFile(data, la._digest(data), 0, 0, 0o600)

    def _write_absolute(  # type: ignore[override]
        self,
        path: str,
        desired: la._BoundFile,
        *,
        expected: object = None,
        journal: bool = False,
        max_bytes: int = 0,
    ) -> None:
        self._blobs[path] = desired.content


def test_controller_stage_write_receipt_cycle_succeeds() -> None:
    store = _MemJournalStore(LocalHostRole.controller)
    store._write_journal(_controller_journal(), expected=None)  # real serialize + write
    receipt = store.receipt()  # real _load_journal -> _validate_journal -> receipt
    assert receipt.journal_present is True
    assert receipt.transaction_id == _TXN


def test_journal_persists_only_binding_never_env_bytes() -> None:
    store = _MemJournalStore(LocalHostRole.controller)
    store._write_journal(_controller_journal(), expected=None)
    raw = store._blobs[store._journal_path]
    loaded = json.loads(raw)
    assert set(loaded["controller_env"]) == {"digest", "uid", "gid", "mode"}
    assert "content" not in loaded["controller_env"]
    assert "content_b64" not in loaded["controller_env"]
    # no environment bytes of any kind are present in the serialized journal
    assert _ENV_SENTINEL not in raw
    assert b"do-not-persist" not in raw


def test_worker_stage_write_receipt_cycle_never_journals_controller_env() -> None:
    store = _MemJournalStore(LocalHostRole.worker)
    store._write_journal(_worker_journal(), expected=None)
    assert store.receipt().journal_present is True
    assert "controller_env" not in json.loads(store._blobs[store._journal_path])
