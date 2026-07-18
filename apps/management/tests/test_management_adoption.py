"""Adoption is a COMPLETE, non-dead-end state with a closed admission->commit TOCTOU (SECP-PR5E
round 4 blockers 1 + 4).

Worker/controller adoption refuses unless the host ALREADY matches the complete canonical prepared
end state (with images matched to the EXACT signed purpose mapping). After installing identity + the
signed release record it obtains a FINAL coherent observation, proves the ABA generation is
unchanged
since admission AND re-runs the complete end-state predicate, and only then writes evidence last —
compensating the newly created documents if the final observation fails.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from _mgmt_support import (
    CONTROLLER_COMPONENT_IMAGE,
    deps_for,
    ephemeral_trust_root,
    prepared_controller_world,
    prepared_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.cli import run

_WRONG = "sha256:" + "9" * 64
_ID = "/var/lib/secp/bootstrap/worker-identity.json"


def _worker(world_kwargs=None, *, write=True):
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, prepared_worker_world(**(world_kwargs or {})), trust)
    argv = ["adopt", "worker", "--bundle", bd] + (["--write", "--confirm"] if write else [])
    return run(argv, deps), deps, fs


def _controller(world_kwargs=None, *, write=True):
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/c"
    seed_signed_bundle(fs, bd, "controller", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, prepared_controller_world(**(world_kwargs or {})), trust)
    argv = ["adopt", "controller", "--bundle", bd] + (["--write", "--confirm"] if write else [])
    return run(argv, deps), deps, fs


def _no_evidence(fs):
    return not any(p.endswith("evidence.json") for p in fs.paths())


# --- success + transactional documents ---


def test_adopt_worker_full_prepared_writes_four_documents():
    (code, rep), deps, fs = _worker()
    assert code == 0 and rep["mode"] == "adopted"
    assert rep["restarted_anything"] is False and rep["loaded_image"] is False
    for name in (
        "worker-identity.json",
        "worker-installed-release.json",
        "worker-installed-release.sig.json",
        "worker-evidence.json",
    ):
        assert f"/var/lib/secp/bootstrap/{name}" in set(fs.paths())
    assert deps.worker_adapter._w.ops == []  # NO mutation adapter op


def test_adopted_worker_status_ok():
    (code, _rep), deps, _fs = _worker()
    assert code == 0
    code, st = run(["status", "worker"], deps)
    assert code == 0 and st["ok"] is True
    assert st["dimensions"]["management_identity"] is True


def test_adopt_dry_run_default():
    (code, rep), _deps, _fs = _worker(write=False)
    assert code == 0 and rep["mode"] == "dry_run"


def test_adopted_installation_is_not_rollback_owned():
    (code, _rep), deps, _fs = _worker()
    assert code == 0
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "rollback_refused_adopted_installation"


def test_controller_adopt_full_prepared_status_ok():
    (code, _rep), deps, _fs = _controller()
    assert code == 0
    code, st = run(["status", "controller"], deps)
    assert code == 0 and st["ok"] is True


# --- worker adoption refuses every incomplete condition ---


@pytest.mark.parametrize(
    "world_kwargs,tail",
    [
        ({"operator_present": False}, "worker_operator_not_disabled_stopped"),
        ({"operator_enabled": True}, "worker_operator_not_disabled_stopped"),
        ({"operator_running": True}, "worker_operator_not_disabled_stopped"),
        ({"package_trusted": False}, "worker_operator_package_untrusted"),
        ({"ordinary_polls_operator_queue": True}, "worker_ordinary_polls_operator_queue"),
        ({"commissioning_override": "not_prepared"}, "worker_commissioning_not_prepared"),
        ({"deployment_override": "not_prepared"}, "worker_deployment_not_sealed_prepared"),
        ({"ordinary_healthy": False}, "worker_ordinary_not_ready"),
        ({"image_digest": _WRONG}, "worker_ordinary_image_mismatch"),
        ({"operator_image_digest": _WRONG}, "worker_operator_image_mismatch"),
        ({"config_identity": _WRONG}, "worker_ordinary_config_mismatch"),
        ({"unit_identity_value": _WRONG}, "worker_operator_unit_mismatch"),
        ({"deployment_package_aggregate": _WRONG}, "worker_deployment_package_mismatch"),
        ({"coherent": False}, "worker_reobservation_incoherent"),
    ],
)
def test_worker_adoption_refuses_incomplete(world_kwargs, tail):
    (code, rep), _deps, fs = _worker(world_kwargs, write=False)
    assert code == 2 and rep["reason_code"] == "adoption_incomplete:" + tail
    assert _no_evidence(fs)


# --- controller adoption refuses every incomplete condition ---


def _swap(mapping):
    out = dict(mapping)
    out["api"], out["postgres"] = out["postgres"], out["api"]
    return out


@pytest.mark.parametrize(
    "world_kwargs,tail",
    [
        (
            {"containers": {"api": CONTROLLER_COMPONENT_IMAGE["api"]}},
            "controller_component_set_mismatch",
        ),
        ({"containers": _swap(CONTROLLER_COMPONENT_IMAGE)}, "controller_component_image_mismatch"),
        ({"all_running": False}, "controller_not_all_running"),
        ({"all_healthy": False}, "controller_not_all_healthy"),
        ({"migration_identity": "deadbeef0000"}, "controller_migration_mismatch"),
        ({"config_identity": _WRONG}, "controller_config_mismatch"),
        ({"unit_identity_value": _WRONG}, "controller_unit_mismatch"),
        ({"privileged": ("mystery-root-svc",)}, "controller_unknown_privileged_service"),
        ({"coherent": False}, "controller_reobservation_incoherent"),
    ],
)
def test_controller_adoption_refuses_incomplete(world_kwargs, tail):
    (code, rep), _deps, fs = _controller(world_kwargs, write=False)
    assert code == 2 and rep["reason_code"] == "adoption_incomplete:" + tail
    assert _no_evidence(fs)


# --- admission -> commit TOCTOU is closed (blocker 4) ---


def test_worker_restart_between_admission_and_commit_refuses():
    (code, rep), _deps, fs = _worker({"restart_before_final": True})
    assert code == 2 and rep["reason_code"] == "adoption_generation_changed"
    assert _no_evidence(fs)  # no evidence after a final-observation failure


def test_operator_start_between_admission_and_commit_refuses():
    (code, rep), _deps, fs = _worker({"operator_start_before_final": True})
    assert code == 2 and rep["reason_code"] == "adoption_generation_changed"
    assert _no_evidence(fs)


def test_worker_degraded_between_admission_and_commit_refuses():
    # a health degradation WITHOUT a restart keeps the generation marker, so the re-run end-state
    # predicate (not the generation check) catches it.
    (code, rep), _deps, fs = _worker({"unhealthy_before_final": True})
    assert code == 2 and rep["reason_code"] == "adoption_final:worker_ordinary_not_ready"
    assert _no_evidence(fs)


def test_controller_generation_change_during_adoption_refuses():
    (code, rep), _deps, fs = _controller({"controller_regen_before_final": True})
    assert code == 2 and rep["reason_code"] == "adoption_generation_changed"
    assert _no_evidence(fs)


def test_no_partial_adoption_after_final_observation_failure():
    (code, _rep), _deps, fs = _worker({"restart_before_final": True})
    assert code == 2
    for name in (
        "worker-identity.json",
        "worker-installed-release.json",
        "worker-installed-release.sig.json",
        "worker-evidence.json",
    ):
        assert f"/var/lib/secp/bootstrap/{name}" not in set(fs.paths())


def test_failed_idempotent_readoption_restores_original_documents():
    # a valid adopted install re-adopted at a LATER wall-clock time (different identity created_at)
    # whose final observation changes generation must RESTORE the original documents — never leave a
    # pre-existing document mutated (which would brick the install).
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    assert (
        run(
            ["adopt", "worker", "--bundle", bd, "--write", "--confirm"],
            deps_for(fs, prepared_worker_world(), trust),
        )[0]
        == 0
    )
    original = fs.safe_read(_ID, max_bytes=1 << 18, expected_uid=0)

    deps2 = replace(
        deps_for(fs, prepared_worker_world(restart_before_final=True), trust),
        clock=lambda: "2026-08-01T00:00:00+00:00",  # a later re-adoption → a different created_at
    )
    code, rep = run(["adopt", "worker", "--bundle", bd, "--write", "--confirm"], deps2)
    assert code == 2 and rep["reason_code"] == "adoption_generation_changed"
    # the original identity document is restored byte-for-byte (no partial/mutated adoption)
    assert fs.safe_read(_ID, max_bytes=1 << 18, expected_uid=0) == original
    # and a subsequent status over a clean prepared observation still passes (not bricked)
    code, st = run(["status", "worker"], deps_for(fs, prepared_worker_world(), trust))
    assert code == 0 and st["ok"] is True


# --- transactional adoption writes: compensate only newly created documents on failure ---


def test_adoption_partial_write_compensates_only_new_documents(monkeypatch):
    from secp_management import engine

    (_result, deps, fs) = _worker(write=False)
    real_install = engine._install_doc

    def _flaky(fs_, loc, path, data):
        if path.endswith("worker-evidence.json"):
            raise engine.ManagementError("fake_evidence_write_failure")
        return real_install(fs_, loc, path, data)

    monkeypatch.setattr(engine, "_install_doc", _flaky)
    code, rep = run(
        [
            "adopt",
            "worker",
            "--bundle",
            "/var/lib/secp/bootstrap/release/w",
            "--write",
            "--confirm",
        ],
        deps,
    )
    assert code == 2 and rep["reason_code"] == "fake_evidence_write_failure"
    for name in (
        "worker-identity.json",
        "worker-installed-release.json",
        "worker-installed-release.sig.json",
        "worker-evidence.json",
    ):
        assert f"/var/lib/secp/bootstrap/{name}" not in set(fs.paths())
