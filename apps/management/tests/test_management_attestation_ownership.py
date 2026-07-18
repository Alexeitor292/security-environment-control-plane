"""The detached evidence attestation is a fully-owned FIFTH managed document (SECP-PR5E round 6
blocker 1).

Pre-existing classification counts ALL FIVE paths (identity, release manifest, release signature,
evidence, evidence attestation) and permits only all-five-absent (fresh) or all-five-present-and-
authenticated (exact idempotent). An attestation-only/orphan state, the four core documents without
the attestation, or the attestation with only a subset of core documents is refused BEFORE any host
op. The attestation carries its own ManagedObjectRecord (binding/uid/gid/mode/classification), so
rollback removes it ONLY when its authenticated ownership record proves the transaction created it —
an orphan/foreign attestation is never overwritten or deleted.
"""

from __future__ import annotations

import json

from _mgmt_support import (
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
_RR = "/var/lib/secp/bootstrap/worker-installed-release.json"
_SIG = "/var/lib/secp/bootstrap/worker-installed-release.sig.json"
_EV = "/var/lib/secp/bootstrap/worker-evidence.json"
_ATT = "/var/lib/secp/bootstrap/worker-evidence.attestation.json"
_FIVE = (_ID, _RR, _SIG, _EV, _ATT)


def _installed():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    deps = deps_for(fs, fresh_worker_world(), trust)
    assert run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)[0] == 0
    return fs, trust, bd


def _read(fs, path):
    return fs.safe_read(path, max_bytes=1 << 18, expected_uid=0)


def _rebootstrap(fs, trust, bd):
    deps = deps_for(fs, fresh_worker_world(), trust)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    return code, rep, deps


# --- the fifth document is written + represented in the ownership model ---


def test_bootstrap_writes_all_five_documents():
    fs, _trust, _bd = _installed()
    assert all(p in set(fs.paths()) for p in _FIVE)


def test_evidence_ownership_records_cover_all_five_kinds():
    fs, _trust, _bd = _installed()
    ev = json.loads(_read(fs, _EV))
    kinds = sorted(r["kind"] for r in ev["object_records"])
    assert kinds == sorted(
        ["identity", "release_manifest", "release_signature", "evidence", "evidence_attestation"]
    )
    att_rec = next(r for r in ev["object_records"] if r["kind"] == "evidence_attestation")
    # the attestation record is self/independently-verified: no embedded content digest, created
    assert att_rec["content_sha256"] is None and att_rec["classification"] == "created"


# --- five-path classification refuses partial/orphan states before any host op ---


def test_orphan_attestation_refuses_fresh_bootstrap_and_is_not_overwritten():
    trust, kid, priv, _pub = ephemeral_trust_root()
    fs = InMemoryFilesystem()
    bd = "/var/lib/secp/bootstrap/release/w"
    seed_signed_bundle(fs, bd, "worker", kid, priv)
    seed_write_ancestors(fs)
    orphan = b'{"orphan":"attestation"}\n'
    fs.seed_file(_ATT, orphan, mode=0o640, uid=0)  # only the attestation exists
    deps = deps_for(fs, fresh_worker_world(), trust)
    code, rep = run(["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"], deps)
    assert code == 2 and rep["reason_code"] == "preexisting_partial_install"
    assert deps.worker_adapter._w.ops == []  # classification precedes every host op
    assert _read(fs, _ATT) == orphan  # the orphan attestation is never overwritten
    assert _ID not in set(fs.paths())  # nothing written


def test_four_core_without_attestation_refuses():
    fs, trust, bd = _installed()
    fs.remove_file(_ATT)  # the four core documents remain, attestation gone
    code, rep, deps = _rebootstrap(fs, trust, bd)
    assert code == 2 and rep["reason_code"] == "preexisting_partial_install"
    assert deps.worker_adapter._w.ops == []


def test_attestation_plus_subset_of_core_refuses():
    fs, trust, bd = _installed()
    fs.remove_file(_ID)  # attestation + 3 core docs (no identity)
    code, rep, deps = _rebootstrap(fs, trust, bd)
    assert code == 2 and rep["reason_code"] == "preexisting_partial_install"
    assert deps.worker_adapter._w.ops == []


def test_wrong_owner_attestation_refuses_before_any_host_op():
    fs, trust, bd = _installed()
    fs.seed_file(_ATT, _read(fs, _ATT), mode=0o640, uid=1000)  # same bytes, wrong owner
    code, rep, deps = _rebootstrap(fs, trust, bd)
    # the hardened read of the attestation rejects the untrusted owner before it can be
    # authenticated
    assert code == 2 and rep["reason_code"] in (
        "preexisting_evidence_unauthenticated",
        "preexisting_drifted_install",
    )
    assert deps.worker_adapter._w.ops == []


def test_symlinked_attestation_refuses_before_any_host_op():
    fs, trust, bd = _installed()
    fs.seed_symlink(_ATT)  # replace the attestation with a symlink
    code, rep, deps = _rebootstrap(fs, trust, bd)
    assert code == 2 and rep["reason_code"] in (
        "preexisting_evidence_unauthenticated",
        "preexisting_drifted_install",
    )
    assert deps.worker_adapter._w.ops == []


def test_foreign_attestation_refuses_reinstall_before_host_op():
    fs, trust, bd = _installed()
    # a foreign attestation from a DIFFERENT ephemeral signer: valid-shaped but does not verify
    other_trust, okid, opriv, _opub = ephemeral_trust_root()
    fs2 = InMemoryFilesystem()
    seed_signed_bundle(fs2, bd, "worker", okid, opriv)
    seed_write_ancestors(fs2)
    assert (
        run(
            ["bootstrap", "worker", "--bundle", bd, "--write", "--confirm"],
            deps_for(fs2, fresh_worker_world(), other_trust),
        )[0]
        == 0
    )
    fs.seed_file(_ATT, _read(fs2, _ATT), mode=0o640, uid=0)  # graft the foreign attestation
    code, rep, deps = _rebootstrap(fs, trust, bd)
    assert code == 2 and rep["reason_code"] == "preexisting_evidence_unauthenticated"
    assert deps.worker_adapter._w.ops == []


# --- rollback removes the attestation only via its created record; never a foreign one ---


def test_rollback_removes_the_attestation_via_its_created_record():
    fs, trust, bd = _installed()
    deps = deps_for(fs, fresh_worker_world(), trust)
    code, rep = run(["rollback", "worker"], deps)
    assert code == 0 and len(rep["removable_bindings"]) == 5  # all five created documents
    code, rep = run(["rollback", "worker", "--write", "--confirm"], deps)
    assert code == 0 and rep["mode"] == "written"
    assert not any(p in set(fs.paths()) for p in _FIVE)  # attestation removed too


def test_rollback_of_forged_attestation_deletes_nothing():
    fs, trust, bd = _installed()
    doc = json.loads(_read(fs, _EV))
    # re-author the (canonical) evidence — the detached attestation no longer matches it
    doc["transaction_timestamp"] = "2030-01-01T00:00:00+00:00"
    fs.seed_file(_EV, canonical_json(doc).encode(), mode=0o640, uid=0)
    code, rep = run(
        ["rollback", "worker", "--write", "--confirm"], deps_for(fs, prepared_worker_world(), trust)
    )
    assert code == 2 and rep["reason_code"] == "evidence_attestation_untrusted"
    assert all(p in set(fs.paths()) for p in _FIVE)  # nothing deleted (attestation preserved)
