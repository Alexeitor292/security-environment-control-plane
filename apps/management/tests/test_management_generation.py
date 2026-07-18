"""The raw generation TUPLE must be complete, not merely hashed (SECP-PR5E round 6 blocker 3).

A matching SHA-256 marker is insufficient when it was computed from incomplete generation facts. The
engine validates the raw tuple BEFORE deriving/comparing the marker: worker — a nonempty ordinary
container id, a nonnegative-integer restart count, a nonempty valid start timestamp, a nonzero
numeric
PID while running, and a defined operator InvocationID for a present operator; controller — per-
component container-id/restart-count/image maps whose keys EXACTLY equal the signed component set,
every container id nonempty, every restart count a nonnegative integer. In every case below the
observer returns a CORRECTLY-DERIVED marker over the incomplete tuple, yet status refuses.
"""

from __future__ import annotations

from _mgmt_support import (
    CONTROLLER_COMPONENT_IMAGE,
    deps_for,
    ephemeral_trust_root,
    fresh_controller_world,
    fresh_worker_world,
    prepared_controller_world,
    prepared_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.cli import run

_COMPS = sorted(CONTROLLER_COMPONENT_IMAGE)
_FULL_IDS = {c: "cid-" + c for c in _COMPS}
_FULL_RESTARTS = {c: "0" for c in _COMPS}


def _worker_status(world):
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    assert (
        run(
            ["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"],
            deps_for(fs, fresh_worker_world(), trust),
        )[0]
        == 0
    )
    return run(["status", "worker"], deps_for(fs, world, trust))


def _controller_status(world):
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/c"
    seed_signed_bundle(fs, bd, "controller", kid, priv)
    seed_write_ancestors(fs)
    assert (
        run(
            ["bootstrap", "controller", "--bundle", bd, "--write", "--confirm"],
            deps_for(fs, fresh_controller_world(), trust),
        )[0]
        == 0
    )
    return run(["status", "controller"], deps_for(fs, world, trust))


def _assert_worker_incomplete(**overrides):
    _code, st = _worker_status(prepared_worker_world(**overrides))
    assert st["dimensions"]["drift"] == "worker_generation_marker_invalid" and st["ok"] is False


def _assert_controller_incomplete(**overrides):
    _code, st = _controller_status(prepared_controller_world(**overrides))
    assert st["dimensions"]["drift"] == "controller_generation_marker_invalid" and st["ok"] is False


# --- worker incomplete tuples (correct marker over incomplete facts) ---


def test_worker_empty_container_id_refuses():
    _assert_worker_incomplete(worker_container_id_override="")


def test_worker_blank_pid_refuses():
    _assert_worker_incomplete(worker_pid_override="")


def test_worker_zero_pid_while_running_refuses():
    _assert_worker_incomplete(worker_pid_override="0")


def test_worker_nonnumeric_pid_refuses():
    _assert_worker_incomplete(worker_pid_override="not-a-pid")


def test_worker_blank_start_timestamp_refuses():
    _assert_worker_incomplete(worker_started_override="")


def test_worker_invalid_restart_count_refuses():
    _assert_worker_incomplete(restart_count="-1")


def test_worker_nonnumeric_restart_count_refuses():
    _assert_worker_incomplete(restart_count="x")


def test_worker_missing_operator_invocation_refuses():
    # a present (disabled+stopped) operator must expose a defined InvocationID generation fact
    _assert_worker_incomplete(invocation_id="")


# --- controller incomplete tuples (correct marker over incomplete maps; image map stays complete)
# ---


def test_controller_empty_generation_maps_refuse():
    _assert_controller_incomplete(
        controller_container_ids_override={}, controller_restart_counts_override={}
    )


def test_controller_missing_one_container_id_refuses():
    partial = {c: v for c, v in _FULL_IDS.items() if c != _COMPS[0]}
    _assert_controller_incomplete(controller_container_ids_override=partial)


def test_controller_missing_one_restart_count_refuses():
    partial = {c: v for c, v in _FULL_RESTARTS.items() if c != _COMPS[0]}
    _assert_controller_incomplete(controller_restart_counts_override=partial)


def test_controller_empty_container_id_value_refuses():
    ids = dict(_FULL_IDS)
    ids[_COMPS[0]] = ""  # a present component with an empty container id
    _assert_controller_incomplete(controller_container_ids_override=ids)


def test_controller_invalid_restart_count_value_refuses():
    restarts = dict(_FULL_RESTARTS)
    restarts[_COMPS[0]] = "-1"
    _assert_controller_incomplete(controller_restart_counts_override=restarts)
