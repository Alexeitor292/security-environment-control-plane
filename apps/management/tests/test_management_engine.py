"""Engine core: roles, dry-run/write gate, typed ordered ops, reobservation gate, seals.

Round 3 (SECP-PR5E): the write path drives the CLOSED TYPED role adapter operations in order,
consuming exact verified artifacts, and commits evidence only after a FINAL coherent reobservation
of
the COMPLETE canonical end state; a sealed adapter or a failed reobservation can never yield a false
success. (Adoption, rollback, classification, and receipt/compensation have dedicated files.)
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from _mgmt_support import (
    CONTROLLER_COMPONENT_IMAGE as _CONTROLLER_COMPONENT_IMAGE,
)
from _mgmt_support import (
    WORKER_OPERATOR_IMAGE as _OPERATOR_IMG,
)
from _mgmt_support import (
    deps_for,
    ephemeral_trust_root,
    fresh_controller_world,
    fresh_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.adapters import (
    SealedControllerBootstrapAdapter,
    SealedWorkerBootstrapAdapter,
)
from secp_management.cli import run
from secp_management.planes import Plane, Role, may_mutate, parse_role
from secp_management.topology import OPERATOR_TASK_QUEUE, ORDINARY_TASK_QUEUE


def _fresh_worker(**overrides):
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/worker"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_worker_world(**overrides), trust)
    return deps, bd, fs


def _fresh_controller(**overrides):
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/controller"
    seed_signed_bundle(fs, bd, "controller", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_controller_world(**overrides), trust)
    return deps, bd, fs


def _op_names(world):
    return [o.split(":")[0] for o in world.ops]


def _assert_no_documents(fs):
    for suffix in ("evidence.json", "identity.json", "installed-release.json"):
        assert not any(p.endswith(suffix) for p in fs.paths())


# --- planes + roles ---


def test_plane_mutation_rules():
    assert may_mutate(Plane.MANAGEMENT, Plane.INFRASTRUCTURE)
    assert may_mutate(Plane.MANAGEMENT, Plane.SCENARIO)
    assert not may_mutate(Plane.SCENARIO, Plane.MANAGEMENT)
    assert not may_mutate(Plane.INFRASTRUCTURE, Plane.MANAGEMENT)


def test_unknown_role_refused():
    from secp_management import ManagementError

    with pytest.raises(ManagementError):
        parse_role("scenario")
    assert parse_role("controller") is Role.CONTROLLER


def test_management_is_not_a_scenario_target():
    from secp_management import ManagementError
    from secp_management.planes import assert_not_scenario_target

    with pytest.raises(ManagementError) as exc:
        assert_not_scenario_target(Plane.MANAGEMENT)
    assert exc.value.reason_code == "management_plane_not_a_scenario_target"
    assert_not_scenario_target(Plane.SCENARIO)


# --- role isolation ---


def test_worker_bundle_cannot_bootstrap_controller():
    deps, bd, _fs = _fresh_worker()
    code, rep = run(["bootstrap", "controller", "--bundle", bd], deps)
    assert code == 2 and rep["reason_code"] == "release_role_mismatch"


# --- dry-run + write/confirm gate ---


def test_dry_run_writes_nothing():
    deps, bd, fs = _fresh_worker()
    before = set(fs.paths())
    code, rep = run(["bootstrap", "worker", "--bundle", bd], deps)
    assert code == 0 and rep["mode"] == "dry_run"
    assert set(fs.paths()) == before
    assert deps.worker_adapter._w.ops == []  # no adapter op in a dry run


def test_write_without_confirm_refuses():
    deps, bd, _fs = _fresh_worker()
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write"], deps)
    assert code == 2 and rep["reason_code"] == "write_requires_confirm"


def test_confirm_without_write_refuses():
    deps, bd, _fs = _fresh_worker()
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "confirm_requires_write"


def test_write_requires_root():
    deps, bd, _fs = _fresh_worker(is_root=False)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "root_required_for_write"


# --- controller + worker bootstrap (typed ordered ops + reobservation gate) ---


def test_worker_bootstrap_write_then_status_ok():
    deps, bd, _fs = _fresh_worker()
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "written"
    assert rep["operator_started"] is False and rep["operator_enabled"] is False
    assert rep["reobserved_healthy"] is True
    code, st = run(["status", "worker"], deps)
    assert code == 0 and st["ok"] is True
    assert st["dimensions"]["ordinary_queue"] == ORDINARY_TASK_QUEUE
    assert st["dimensions"]["operator_queue"] == OPERATOR_TASK_QUEUE


def test_controller_bootstrap_write_then_status_ok():
    deps, bd, _fs = _fresh_controller()
    code, rep = run(["bootstrap", "controller", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "written"
    code, st = run(["status", "controller"], deps)
    assert code == 0 and st["ok"] is True


def test_worker_ops_execute_in_reviewed_order():
    deps, bd, _fs = _fresh_worker()
    world = deps.worker_adapter._w
    run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    names = _op_names(world)
    assert names[:2] == ["load_image", "load_image"]  # ordinary + operator images
    assert names[2:] == [
        "install_ordinary_config",
        "install_deployment_package",
        "install_operator_unit_disabled",
        "daemon_reload",
        "start_ordinary",  # ONLY the ordinary worker is started; the operator is never started
    ]


def test_controller_ops_execute_in_reviewed_order():
    deps, bd, _fs = _fresh_controller()
    world = deps.controller_adapter._w
    code, rep = run(["bootstrap", "controller", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "written"
    names = _op_names(world)
    n = len(names) - 5  # one load_image per controller component
    assert names[:n] == ["load_image"] * n and n == 8
    assert names[n:] == [
        "install_config",
        "install_unit",
        "daemon_reload",
        "run_migrations",
        "start_stack",
    ]


def test_adapter_receives_exact_verified_artifact_bytes():
    # the fake adapter calls artifact.read() (digest+size checked) on every load — a bare name or
    # abstract digest would not survive. Corrupting the seeded artifact makes the read fail closed.
    deps, bd, fs = _fresh_worker()
    fs.seed_file(f"{bd}/images/ordinary.tar", b"tampered-after-verification\n", mode=0o644)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    # release verification refuses the tampered artifact before the write is even reached
    assert code == 2 and rep["reason_code"] in (
        "release_artifact_digest_mismatch",
        "release_artifact_size_mismatch",
        "fs_read_size_invalid",
    )


def test_worker_plan_never_starts_or_enables_operator():
    deps, bd, _fs = _fresh_worker()
    _code, rep = run(["bootstrap", "worker", "--bundle", bd], deps)
    steps = rep["plan"]
    op = [s for s in steps if s.get("kind") == "operator_unit"]
    assert op and op[0]["state"] == "present_disabled_stopped" and op[0]["start"] is False
    assert not any(s.get("kind") == "operator_start" for s in steps)


def test_controller_bootstrap_dry_run_deterministic():
    deps, bd, _fs = _fresh_controller()
    _c1, r1 = run(["bootstrap", "controller", "--bundle", bd], deps)
    _c2, r2 = run(["bootstrap", "controller", "--bundle", bd], deps)
    assert r1["plan"] == r2["plan"]


def test_idempotent_exact_state_write_twice():
    deps, bd, _fs = _fresh_worker()
    run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "written"


def test_seals_reported_safe():
    deps, bd, _fs = _fresh_worker()
    _code, rep = run(["bootstrap", "worker", "--bundle", bd], deps)
    assert rep["code_seals"]["safe"] is True
    assert rep["code_seals"]["operator_activation_sealed"] is True
    assert rep["code_seals"]["plan_only_process_sealed"] is False


# --- sealed production adapters fail closed (no false written) ---


def test_sealed_worker_adapter_refuses_write():
    deps, bd, fs = _fresh_worker()
    sealed = replace(deps, worker_adapter=SealedWorkerBootstrapAdapter())
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], sealed)
    assert code == 2 and rep["reason_code"] == "worker_bootstrap_adapter_not_provisioned"
    _assert_no_documents(fs)


def test_sealed_controller_adapter_refuses_write():
    deps, bd, fs = _fresh_controller()
    sealed = replace(deps, controller_adapter=SealedControllerBootstrapAdapter())
    code, rep = run(["bootstrap", "controller", "--bundle", bd, "--write", "--confirm"], sealed)
    assert code == 2 and rep["reason_code"] == "controller_bootstrap_adapter_not_provisioned"
    _assert_no_documents(fs)


# --- FINAL reobservation gate: a bad or incomplete end state fails closed + compensates ---


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"start_healthy": False}, "worker_ordinary_not_ready"),
        ({"start_operator_running": True}, "worker_operator_not_disabled_stopped"),
        ({"start_operator_enabled": True}, "worker_operator_not_disabled_stopped"),
        ({"package_trusted_on_install": False}, "worker_operator_package_untrusted"),
        ({"start_image_digest": "sha256:" + "9" * 64}, "worker_ordinary_image_mismatch"),
        # the ordinary worker running the OPERATOR image is caught (never set membership)
        ({"start_image_digest": _OPERATOR_IMG}, "worker_ordinary_image_mismatch"),
        ({"start_operator_image": "sha256:" + "9" * 64}, "worker_operator_image_mismatch"),
        ({"start_polls_operator_queue": True}, "worker_ordinary_polls_operator_queue"),
        ({"bad_installed_config": True}, "worker_ordinary_config_mismatch"),
        ({"bad_installed_unit": True}, "worker_operator_unit_mismatch"),
        ({"bad_installed_package": True}, "worker_deployment_package_mismatch"),
        ({"stay_incoherent": True}, "worker_reobservation_incoherent"),
    ],
)
def test_worker_reobservation_incomplete_end_state_refuses(overrides, reason):
    deps, bd, fs = _fresh_worker(**overrides)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == reason
    _assert_no_documents(fs)  # identity/release-record compensated; evidence never written


def test_controller_image_swap_between_valid_release_images_refuses():
    # swap two components' images (both valid release images): exact signed mapping catches it
    swapped = dict(_CONTROLLER_COMPONENT_IMAGE)
    swapped["api"], swapped["postgres"] = swapped["postgres"], swapped["api"]
    deps, bd, fs = _fresh_controller(controller_start_images=swapped)
    code, rep = run(["bootstrap", "controller", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "controller_component_image_mismatch"
    _assert_no_documents(fs)


@pytest.mark.parametrize(
    "overrides,reason",
    [
        ({"controller_start_healthy": False}, "controller_not_all_healthy"),
        ({"controller_start_running": False}, "controller_not_all_running"),
        (
            {"controller_start_images": {"api": _CONTROLLER_COMPONENT_IMAGE["api"]}},
            "controller_component_set_mismatch",
        ),
        ({"controller_start_migration": "deadbeef0000"}, "controller_migration_mismatch"),
        ({"bad_installed_config": True}, "controller_config_mismatch"),
        ({"bad_installed_unit": True}, "controller_unit_mismatch"),
        ({"controller_start_privileged": ("mystery",)}, "controller_unknown_privileged_service"),
    ],
)
def test_controller_reobservation_incomplete_end_state_refuses(overrides, reason):
    deps, bd, fs = _fresh_controller(**overrides)
    code, rep = run(["bootstrap", "controller", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == reason
    _assert_no_documents(fs)
