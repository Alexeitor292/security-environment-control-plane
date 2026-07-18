"""Status revalidation (SECP-PR5E round 4): status independently reloads evidence, the management
identity, and the reverified installed-release record, runs the shared installed-document integrity
verifier, and revalidates the COMPLETE end state —
config/unit/component/migration/deployment-package
identities and the EXACT signed component/ordinary/operator image mapping — against a FRESH
observation. Expectations are derived from the SIGNED record, never from a (re-authorable) evidence.
"""

from __future__ import annotations

from dataclasses import replace

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
from secp_management.adapters import SealedHostObserver
from secp_management.cli import run
from secp_management.signing import ReleaseTrustRoot, TrustAnchor, generate_keypair

_WRONG = "sha256:" + "9" * 64


def _installed_worker():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_worker_world(), trust)
    assert run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)[0] == 0
    return fs, trust, kid


def _installed_controller():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/c"
    seed_signed_bundle(fs, bd, "controller", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_controller_world(), trust)
    assert run(["bootstrap", "controller", "--bundle", bd, "--write", "--confirm"], deps)[0] == 0
    return fs, trust, kid


def _worker_status(world):
    fs, trust, _kid = _installed_worker()
    return run(["status", "worker"], deps_for(fs, world, trust))


def _controller_status(world):
    fs, trust, _kid = _installed_controller()
    return run(["status", "controller"], deps_for(fs, world, trust))


# --- worker cross-status + prepared-state gates ---


def test_prepared_and_sealed_prepared_coexist():
    code, st = _worker_status(prepared_worker_world())
    dims = st["dimensions"]
    assert dims["commissioning"] == "prepared" and dims["deployment"] == "sealed_prepared"
    assert code == 0 and st["ok"] is True


def test_operator_absent_not_prepared():
    _code, st = _worker_status(prepared_worker_world(operator_present=False))
    assert st["dimensions"]["commissioning"] == "not_prepared"
    assert st["dimensions"]["deployment"] == "not_prepared" and st["ok"] is False


def test_operator_enabled_refuses():
    _code, st = _worker_status(prepared_worker_world(operator_enabled=True))
    assert st["dimensions"]["operator_disabled"] is False and st["ok"] is False


def test_operator_running_refuses():
    _code, st = _worker_status(prepared_worker_world(operator_running=True))
    assert st["dimensions"]["operator_stopped"] is False and st["ok"] is False


def test_ordinary_unhealthy_refuses():
    _code, st = _worker_status(prepared_worker_world(ordinary_healthy=False))
    assert st["dimensions"]["ordinary_health"] is False and st["ok"] is False


def test_restart_aba_refuses():
    _code, st = _worker_status(prepared_worker_world(coherent=False))
    assert st["dimensions"]["ordinary_container_generation"] is False and st["ok"] is False


def test_package_untrusted_blocks_sealed():
    _code, st = _worker_status(prepared_worker_world(package_trusted=False))
    assert st["dimensions"]["commissioning"] == "prepared"
    assert st["dimensions"]["deployment"] == "not_prepared" and st["ok"] is False


def test_ordinary_polls_operator_queue_refuses():
    _code, st = _worker_status(prepared_worker_world(ordinary_polls_operator_queue=True))
    assert st["dimensions"]["no_operator_queue_polling"] is False and st["ok"] is False


# --- worker installed-artifact identity drift refuses status (blocker 2) ---


def test_worker_config_drift_refuses():
    _code, st = _worker_status(prepared_worker_world(config_identity=_WRONG))
    assert st["dimensions"]["ordinary_config_binding"] is False
    assert st["dimensions"]["drift"] == "worker_ordinary_config_mismatch" and st["ok"] is False


def test_worker_unit_drift_refuses():
    _code, st = _worker_status(prepared_worker_world(unit_identity_value=_WRONG))
    assert st["dimensions"]["operator_unit_binding"] is False
    assert st["dimensions"]["drift"] == "worker_operator_unit_mismatch" and st["ok"] is False


def test_worker_deployment_package_drift_refuses():
    _code, st = _worker_status(prepared_worker_world(deployment_package_aggregate=_WRONG))
    assert st["dimensions"]["deployment_package_binding"] is False
    assert st["dimensions"]["drift"] == "worker_deployment_package_mismatch" and st["ok"] is False


def test_worker_health_command_drift_refuses():
    _code, st = _worker_status(prepared_worker_world(health_command_identity_value=_WRONG))
    assert st["dimensions"]["health_command_binding"] is False
    assert st["dimensions"]["drift"] == "worker_health_command_mismatch" and st["ok"] is False


def test_worker_ordinary_image_drift_refuses():
    _code, st = _worker_status(prepared_worker_world(image_digest=_WRONG))
    assert st["dimensions"]["ordinary_image_binding"] is False
    assert st["dimensions"]["drift"] == "worker_ordinary_image_mismatch" and st["ok"] is False


def test_worker_operator_image_drift_refuses():
    _code, st = _worker_status(prepared_worker_world(operator_image_digest=_WRONG))
    assert st["dimensions"]["operator_image_binding"] is False
    assert st["dimensions"]["drift"] == "worker_operator_image_mismatch" and st["ok"] is False


# --- controller identity + topology drift refuses status (blocker 2) ---


def test_controller_status_ok():
    _code, st = _controller_status(prepared_controller_world())
    assert st["ok"] is True


def test_controller_incoherent_refuses():
    _code, st = _controller_status(prepared_controller_world(coherent=False))
    assert st["ok"] is False


def test_controller_empty_stack_refuses():
    _code, st = _controller_status(prepared_controller_world(containers={}))
    assert st["dimensions"]["component_set"] is False and st["ok"] is False


def test_controller_component_set_drift_refuses():
    two = {
        "api": CONTROLLER_COMPONENT_IMAGE["api"],
        "postgres": CONTROLLER_COMPONENT_IMAGE["postgres"],
    }
    _code, st = _controller_status(prepared_controller_world(containers=two))
    assert st["dimensions"]["drift"] == "controller_component_set_mismatch" and st["ok"] is False


def test_controller_component_image_swap_drift_refuses():
    swapped = dict(CONTROLLER_COMPONENT_IMAGE)
    swapped["api"], swapped["postgres"] = swapped["postgres"], swapped["api"]
    _code, st = _controller_status(prepared_controller_world(containers=swapped))
    assert st["dimensions"]["image_identity"] is False
    assert st["dimensions"]["drift"] == "controller_component_image_mismatch" and st["ok"] is False


def test_controller_config_drift_refuses():
    _code, st = _controller_status(prepared_controller_world(config_identity=_WRONG))
    assert st["dimensions"]["config_binding"] is False
    assert st["dimensions"]["drift"] == "controller_config_mismatch" and st["ok"] is False


def test_controller_unit_drift_refuses():
    _code, st = _controller_status(prepared_controller_world(unit_identity_value=_WRONG))
    assert st["dimensions"]["unit_binding"] is False
    assert st["dimensions"]["drift"] == "controller_unit_mismatch" and st["ok"] is False


def test_controller_migration_drift_refuses():
    _code, st = _controller_status(prepared_controller_world(migration_identity="deadbeef0000"))
    assert st["dimensions"]["migration_identity_bound"] is False
    assert st["dimensions"]["drift"] == "controller_migration_mismatch" and st["ok"] is False


def test_controller_unhealthy_service_refuses():
    _code, st = _controller_status(prepared_controller_world(all_healthy=False))
    assert st["dimensions"]["service_health"] is False and st["ok"] is False


# --- parsed records alone never satisfy status without a live reobservation ---


def test_absent_evidence_refuses():
    trust, _kid, _priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    seed_write_ancestors(fs)
    _code, st = run(["status", "worker"], deps_for(fs, prepared_worker_world(), trust))
    assert st["ok"] is False and st["dimensions"]["drift"] in (
        "evidence_absent",
        "fs_read_not_regular",
    )


def test_missing_release_record_refuses():
    fs, trust, _kid = _installed_worker()
    fs.remove_file("/var/lib/secp/bootstrap/worker-installed-release.json")
    _code, st = run(["status", "worker"], deps_for(fs, prepared_worker_world(), trust))
    assert st["ok"] is False
    assert st["dimensions"]["drift"] in ("release_record_absent", "fs_read_not_regular")


def test_release_record_signature_untrusted_refuses():
    fs, _trust, kid = _installed_worker()
    _priv2, pub2 = generate_keypair()
    forged = ReleaseTrustRoot(anchors=(TrustAnchor(kid, pub2),), test_only=True)
    _code, st = run(["status", "worker"], deps_for(fs, prepared_worker_world(), forged))
    assert st["ok"] is False and st["dimensions"]["drift"] == "release_signature_untrusted"


def test_parsed_records_without_observation_cannot_satisfy():
    fs, trust, _kid = _installed_worker()
    blind = replace(deps_for(fs, prepared_worker_world(), trust), observer=SealedHostObserver())
    _code, st = run(["status", "worker"], blind)
    assert st["ok"] is False
    assert st["dimensions"]["observation_available"] is False
    assert st["dimensions"]["drift"] == "host_observer_not_available"


def test_identity_provenance_tamper_refuses():
    # every provenance field of the identity is authenticated against the SIGNED record; a
    # modified-but-parseable identity with a changed source_tree_sha refuses status.
    import json

    from secp_commissioning.canonical import canonical_json

    fs, trust, _kid = _installed_worker()
    ident_path = "/var/lib/secp/bootstrap/worker-identity.json"
    doc = json.loads(fs.safe_read(ident_path, max_bytes=1 << 18, expected_uid=0))
    doc["source_tree_sha"] = "f" * 40
    fs.seed_file(ident_path, canonical_json(doc).encode(), mode=0o640, uid=0)
    _code, st = run(["status", "worker"], deps_for(fs, prepared_worker_world(), trust))
    # the detached attestation binds the identity digest, so an altered identity fails it first
    assert st["ok"] is False and st["dimensions"]["drift"] in (
        "evidence_attestation_untrusted",
        "identity_record_tree_mismatch",
    )


# --- round 5 blocker 5: the observed generation marker is mandatory, strictly SHA-256, and MUST
#     equal the marker the engine recomputes from the complete observed generation tuple ---


def test_worker_empty_generation_marker_refuses():
    _code, st = _worker_status(prepared_worker_world(generation_marker_override=""))
    assert st["dimensions"]["drift"] == "worker_generation_marker_invalid" and st["ok"] is False


def test_worker_malformed_generation_marker_refuses():
    _code, st = _worker_status(prepared_worker_world(generation_marker_override="not-a-sha256"))
    assert st["dimensions"]["drift"] == "worker_generation_marker_invalid" and st["ok"] is False


def test_worker_constant_placeholder_marker_not_tracking_generation_refuses():
    # a well-formed but constant marker that does NOT derive from the observed generation tuple (an
    # observer that returns the same digest regardless of the real generation facts) is refused.
    _code, st = _worker_status(
        prepared_worker_world(generation_marker_override="sha256:" + "a" * 64)
    )
    assert st["dimensions"]["drift"] == "worker_generation_marker_invalid" and st["ok"] is False


def test_controller_empty_generation_marker_refuses():
    _code, st = _controller_status(prepared_controller_world(generation_marker_override=""))
    assert st["dimensions"]["drift"] == "controller_generation_marker_invalid" and st["ok"] is False


def test_controller_malformed_generation_marker_refuses():
    _code, st = _controller_status(prepared_controller_world(generation_marker_override="deadbeef"))
    assert st["dimensions"]["drift"] == "controller_generation_marker_invalid" and st["ok"] is False


def test_controller_constant_placeholder_marker_not_tracking_generation_refuses():
    _code, st = _controller_status(
        prepared_controller_world(generation_marker_override="sha256:" + "b" * 64)
    )
    assert st["dimensions"]["drift"] == "controller_generation_marker_invalid" and st["ok"] is False
