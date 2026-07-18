"""Pre-existing install classification BEFORE any host op (SECP-PR5E round 3 blocker 5).

A write classifies the four target documents FIRST and permits only ALL-ABSENT (fresh) or an EXACT,
fully revalidated idempotent same-release install; it refuses a partial, foreign, drifted,
changed-release, mode-crossed, or disagreeing pre-existing state — and does so WITHOUT running any
host operation.
"""

from __future__ import annotations

import json
from dataclasses import replace

from _mgmt_support import (
    default_artifacts,
    deps_for,
    ephemeral_trust_root,
    fresh_worker_world,
    prepared_worker_world,
    seed_signed_bundle,
    seed_write_ancestors,
)
from secp_commissioning.canonical import canonical_json
from secp_commissioning.runtime import InMemoryFilesystem
from secp_management.cli import run

_ID = "/var/lib/secp/bootstrap/worker-identity.json"
_EV = "/var/lib/secp/bootstrap/worker-evidence.json"
_RR = "/var/lib/secp/bootstrap/worker-installed-release.json"


def _installed():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_worker_world(), trust)
    assert run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)[0] == 0
    return trust, kid, priv, fs, bd


def _rebootstrap(trust, fs, bd):
    """Re-bootstrap over a FRESH world so any host op would be recorded, and assert none ran."""
    deps = deps_for(fs, fresh_worker_world(), trust)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    return code, rep, deps


def _read(fs, path):
    return fs.safe_read(path, max_bytes=1 << 20, expected_uid=0)


def test_idempotent_same_release_reinstall_permitted():
    trust, _kid, _priv, fs, bd = _installed()
    code, rep, _deps = _rebootstrap(trust, fs, bd)
    assert code == 0 and rep["mode"] == "written"


def test_failed_idempotent_rebootstrap_restores_original_documents():
    # a valid install re-bootstrapped at a LATER time (different identity created_at) whose final
    # reobservation fails must RESTORE the original documents — never leave one mutated (no brick).
    trust, _kid, _priv, fs, bd = _installed()
    original = fs.safe_read(_ID, max_bytes=1 << 18, expected_uid=0)
    deps2 = replace(
        deps_for(fs, fresh_worker_world(start_healthy=False), trust),
        clock=lambda: "2026-08-01T00:00:00+00:00",
    )
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps2)
    assert code == 2 and rep["reason_code"] == "worker_ordinary_not_ready"
    assert fs.safe_read(_ID, max_bytes=1 << 18, expected_uid=0) == original  # restored
    code, st = run(["status", "worker"], deps_for(fs, prepared_worker_world(), trust))
    assert code == 0 and st["ok"] is True  # not bricked


def test_partial_existing_refuses_before_any_host_op():
    trust, _kid, _priv, fs, bd = _installed()
    fs.remove_file(_EV)  # 3 of 4 documents remain
    code, rep, deps = _rebootstrap(trust, fs, bd)
    assert code == 2 and rep["reason_code"] == "preexisting_partial_install"
    assert deps.worker_adapter._w.ops == []  # classification precedes every host op


def test_changed_release_refuses():
    trust, kid, priv, fs, bd = _installed()
    alt = default_artifacts("worker")
    alt[1]["image_digest"] = "sha256:" + "b" * 64  # a different release → different aggregate
    bd2 = "/var/lib/secp/bootstrap/release/w2"
    seed_signed_bundle(fs, bd2, "worker", kid, priv, artifacts=alt)
    code, rep, deps = _rebootstrap(trust, fs, bd2)
    assert code == 2 and rep["reason_code"] == "preexisting_changed_release"
    assert deps.worker_adapter._w.ops == []


def test_bootstrap_over_adopted_refuses():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    adopt_deps = deps_for(fs, prepared_worker_world(), trust)
    assert run(["adopt", "worker", "--bundle", bd, "--write", "--confirm"], adopt_deps)[0] == 0
    code, rep, deps = _rebootstrap(trust, fs, bd)
    assert code == 2 and rep["reason_code"] == "bootstrap_over_adopted_refused"
    assert deps.worker_adapter._w.ops == []


def test_foreign_evidence_record_refuses():
    trust, _kid, _priv, fs, bd = _installed()
    fs.seed_file(_EV, b'{"not":"evidence"}\n', mode=0o640, uid=0)
    code, rep, deps = _rebootstrap(trust, fs, bd)
    assert code == 2 and rep["reason_code"] == "preexisting_foreign_record"
    assert deps.worker_adapter._w.ops == []


def test_identity_evidence_disagreement_refuses():
    trust, _kid, _priv, fs, bd = _installed()
    doc = json.loads(_read(fs, _ID))
    doc["installation_id"] = "secp-mgmt-forgeddiff"  # disagrees with the evidence installation_id
    fs.seed_file(_ID, canonical_json(doc).encode(), mode=0o640, uid=0)
    code, rep, deps = _rebootstrap(trust, fs, bd)
    assert code == 2 and rep["reason_code"] == "preexisting_identity_evidence_disagreement"
    assert deps.worker_adapter._w.ops == []


def test_drifted_install_refuses():
    trust, _kid, _priv, fs, bd = _installed()
    doc = json.loads(_read(fs, _ID))
    # keep installation_id + release_digest (so identity/evidence agree) but drift the artifact set
    doc["installed_artifact_digests"] = ["sha256:" + "7" * 64]
    fs.seed_file(_ID, canonical_json(doc).encode(), mode=0o640, uid=0)
    code, rep, deps = _rebootstrap(trust, fs, bd)
    # the attestation binds the identity digest → an altered identity fails attestation first
    assert code == 2 and rep["reason_code"] in (
        "preexisting_evidence_unauthenticated",
        "preexisting_drifted_install",
    )
    assert deps.worker_adapter._w.ops == []
